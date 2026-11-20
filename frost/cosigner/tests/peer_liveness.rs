// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Peer liveness over the daemon's own mesh path (mTLS gRPC, `PeerDial`, tonic channels with
//! keepalive), on an in-memory network with injected faults, in paused tokio time: deadlines,
//! keepalives and probe intervals run in virtual time, so a 60 s partition costs nothing.
//!
//! - channel liveness: a blackholed peer fails within its round deadline and its dead connection
//!   is replaced (T1); a node back under a new address is reached again by tonic's own reconnect,
//!   no channel rebuild (T2);
//! - the breaker: one hit per blackholed member, not one per signature (T3); a stalled round 2 costs
//!   one deadline, never a second one for the abort (T4); a busy member that keeps making progress
//!   is never opened, a frozen one is (T5); refusals do not open, a falsely opened peer is still
//!   used, DKG ignores it (T7, T8, T9);
//! - fast refusal: an isolated leader refuses within a few seconds, then at once, and signs again
//!   right after the heal (T6);
//! - hosted writes: a member past its deadline is skipped as unreachable, never read as a conflict
//!   (T10);
//! - the member side: a definite I/O error in round 2 marks the store down at once, and a probe that
//!   finds it working brings it back with no restart (T11, T15);
//! - the client's deadline: it only shortens the leader's work (T12, T13, T4b);
//! - saturation: slow but progressing members open no breaker, and no signature makes more than two
//!   attempts (T14).
//!
//! Nonce and intent safety under abandoned attempts (T16) is in `signing_policy.rs`, next to the
//! journal helpers it needs.

// DaemonError wraps large frost/tonic types (as in the crate itself).
#![allow(clippy::result_large_err)]

#[path = "common/memnet.rs"]
mod memnet;

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use frost_ed25519::Identifier;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rutli_cosigner::config::TlsConfig;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::liveness::{DownReason, PeerHealth};
use rutli_cosigner::node::{Node, Round1Ctx};
use rutli_cosigner::orchestrator::{run_dkg, sign, Peers, DEFAULT_WRITE_QUORUM};
use rutli_cosigner::pb;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::pb::signer_client::SignerClient;
use rutli_cosigner::pb::signer_server::SignerServer;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi, ROUND1_DEADLINE, ROUND2_DEADLINE};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use rutli_cosigner::tls::Tls;
use rutli_cosigner::DaemonError;
use tokio::time::Instant;
use tonic::codegen::http;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

use memnet::{Fault, MemNet};

const N: u16 = 3;
const T: u16 = 2;
const KEY: &str = "frost-liveness";
const MASTER: &[u8] = b"hosted key cluster master secret for tests";
const CLUSTER: &str = "testcluster00000";

fn authority(id: u16) -> String {
    format!("cosigner{id}:{}", 9100 + id)
}

fn endpoint(id: u16) -> String {
    format!("https://{}", authority(id))
}

fn cn(id: u16) -> String {
    format!("cosigner{id}")
}

fn msg(tag: &str) -> [u8; 34] {
    rutli_frost_core::dealer::canton_test_message(tag.as_bytes())
}

struct Ca(rcgen::Certificate, KeyPair);

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "rutli test CA");
    Ca(params.self_signed(&key).unwrap(), key)
}

fn leaf(dir: &Path, ca: &Ca, cn: &str) -> TlsConfig {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.signed_by(&key, &ca.0, &ca.1).unwrap();
    let (cert_path, key_path, ca_path) = (
        dir.join(format!("{cn}.pem")),
        dir.join(format!("{cn}.key")),
        dir.join("ca.pem"),
    );
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca.0.pem()).unwrap();
    TlsConfig {
        ca_cert: ca_path,
        cert: cert_path,
        key: key_path,
        domain: None,
        allow_expired_ca: false,
        require_peer_pins: None,
    }
}

// ── a member that misbehaves on request ───────────────────────────────────────────────────────

/// What a member does with one Peer method, for one caller or all.
#[derive(Clone)]
enum Act {
    /// Hold the request this long before the handler sees it (a stalled or slow member).
    Delay(Duration),
    /// Answer with this status instead (an older member, a full member).
    Reply(Arc<dyn Fn() -> tonic::Status + Send + Sync>),
}

/// Per-node misbehaviour, set by the test while the node serves.
#[derive(Default)]
struct Control {
    /// (method name or "*", caller CN or None for anyone) → what to do.
    rules: Mutex<Vec<(String, Option<String>, Act)>>,
    /// A single-server queue in front of the sign rounds: (one permit, service time).
    queue: Mutex<Option<(Arc<tokio::sync::Semaphore>, Duration)>>,
    /// Requests seen per method.
    seen: Mutex<HashMap<String, usize>>,
}

impl Control {
    fn set(&self, method: &str, caller: Option<&str>, act: Act) {
        let mut rules = self.rules.lock().unwrap();
        rules.retain(|(m, c, _)| !(m == method && c.as_deref() == caller));
        rules.push((method.to_string(), caller.map(str::to_owned), act));
    }

    fn clear(&self) {
        self.rules.lock().unwrap().clear();
        *self.queue.lock().unwrap() = None;
    }

    fn act(&self, method: &str, caller: Option<&str>) -> Option<Act> {
        let rules = self.rules.lock().unwrap();
        rules
            .iter()
            .rev()
            .find(|(m, c, _)| (m == method || m == "*") && (c.is_none() || c.as_deref() == caller))
            .map(|(_, _, a)| a.clone())
    }

    fn seen(&self, method: &str) -> usize {
        self.seen.lock().unwrap().get(method).copied().unwrap_or(0)
    }
}

/// The Peer service behind a [`Control`].
#[derive(Clone)]
struct Faulty<S> {
    inner: S,
    control: Arc<Control>,
}

impl<S: tonic::server::NamedService> tonic::server::NamedService for Faulty<S> {
    const NAME: &'static str = S::NAME;
}

impl<S> tonic::codegen::Service<http::Request<tonic::body::BoxBody>> for Faulty<S>
where
    S: tonic::codegen::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
            Error = Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Infallible>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Infallible>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        let method = req
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let caller = req
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|i| i.peer_certs())
            .and_then(|certs| {
                certs
                    .first()
                    .and_then(|c| rutli_cosigner::service::cn_of(c.as_ref()))
            });
        let (control, mut inner) = (self.control.clone(), self.inner.clone());
        Box::pin(async move {
            *control
                .seen
                .lock()
                .unwrap()
                .entry(method.clone())
                .or_default() += 1;
            let queue = control.queue.lock().unwrap().clone();
            if let Some((permits, service)) = queue.filter(|_| method.starts_with("SignRound")) {
                let _one_at_a_time = permits.acquire_owned().await.unwrap();
                tokio::time::sleep(service).await;
            }
            match control.act(&method, caller.as_deref()) {
                Some(Act::Delay(d)) => tokio::time::sleep(d).await,
                Some(Act::Reply(status)) => return Ok(status().into_http()),
                None => {}
            }
            inner.call(req).await
        })
    }
}

// ── the mesh ──────────────────────────────────────────────────────────────────────────────────

struct Mesh {
    net: MemNet,
    nodes: Vec<Arc<Node>>,
    /// `peers[i]`: node i+1's view, itself as `LocalPeer`, the others over gRPC.
    peers: Vec<Peers>,
    controls: Vec<Arc<Control>>,
    tls: Vec<Tls>,
    driver: Tls,
    servers: Mutex<HashMap<u16, tokio::task::JoinHandle<()>>>,
    _tmp: tempfile::TempDir,
}

impl Drop for Mesh {
    fn drop(&mut self) {
        for (_, h) in self.servers.lock().unwrap().drain() {
            h.abort();
        }
    }
}

impl Mesh {
    /// Three nodes, mTLS mesh over memnet, the key `KEY` generated.
    async fn new() -> Self {
        let m = Self::build(false);
        run_dkg(&m.peers[0], KEY).await.unwrap();
        m
    }

    /// [`Mesh::new`] with hosted keys on every node.
    async fn hosted() -> Self {
        let m = Self::build(true);
        run_dkg(&m.peers[0], KEY).await.unwrap();
        m
    }

    fn build(hosted: bool) -> Self {
        let net = MemNet::new();
        let ca = ca();
        let tmp = tempfile::tempdir().unwrap();
        let tls: Vec<Tls> = (1..=N)
            .map(|i| rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, &cn(i))).unwrap())
            .collect();
        let driver = rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, "driver")).unwrap();
        let nodes: Vec<Arc<Node>> = (1..=N)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
                let node = Node::new(Identifier::try_from(i).unwrap(), N, T, ks);
                Arc::new(if hosted {
                    node.with_hosted_keys(MASTER, CLUSTER.to_string()).unwrap()
                } else {
                    node
                })
            })
            .collect();
        let mut peers = Vec::new();
        for (i, n) in nodes.iter().enumerate() {
            let me = i as u16 + 1;
            let view: Peers = (1..=N)
                .map(|j| {
                    if j == me {
                        Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>
                    } else {
                        let dial = tls[i].dial_as(&cn(j), None, j).unwrap();
                        let connector = dial.connector_over(net.dialer_from(&cn(me)));
                        Arc::new(
                            GrpcPeer::connect_lazy_over(
                                Identifier::try_from(j).unwrap(),
                                &endpoint(j),
                                &dial,
                                connector,
                            )
                            .unwrap(),
                        ) as Arc<dyn PeerApi>
                    }
                })
                .collect();
            n.set_mesh(view.clone()).unwrap();
            peers.push(view);
        }
        let m = Mesh {
            net,
            nodes,
            peers,
            controls: (0..N).map(|_| Arc::default()).collect(),
            tls,
            driver,
            servers: Mutex::new(HashMap::new()),
            _tmp: tmp,
        };
        for id in 1..=N {
            let incoming = m.net.listen(&authority(id));
            m.serve(id, incoming);
        }
        m
    }

    /// Serve node `id`'s Peer and Signer APIs on `incoming`.
    fn serve(
        &self,
        id: u16,
        incoming: tokio_stream::wrappers::UnboundedReceiverStream<std::io::Result<memnet::MemIo>>,
    ) {
        let i = id as usize - 1;
        let peer = PeerSvc {
            node: self.nodes[i].clone(),
            allowed_cns: Some(Arc::new((1..=N).map(cn).collect::<HashSet<_>>())),
            peer_ids: Some(Arc::new((1..=N).map(|j| (cn(j), j)).collect())),
            peer_pins: None,
        };
        let signer = SignerSvc {
            node: self.nodes[i].clone(),
            peers: self.peers[i].clone(),
            allowed_cns: Some(Arc::new(["driver".to_string()].into())),
            operator_cns: None,
            hosted_write_quorum: DEFAULT_WRITE_QUORUM,
            decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
            sign_guard: None,
            refresh_cns: None,
        };
        let server = tonic::transport::Server::builder()
            .tls_config(self.tls[i].server.clone())
            .unwrap()
            .add_service(Faulty {
                inner: PeerServer::new(peer),
                control: self.controls[i].clone(),
            })
            .add_service(SignerServer::new(signer))
            .serve_with_incoming(incoming);
        let handle = tokio::spawn(async move {
            let _ = server.await;
        });
        if let Some(old) = self.servers.lock().unwrap().insert(id, handle) {
            old.abort();
        }
    }

    /// Node `id` comes back under a new address (a replaced pod): connections to the old one stay
    /// blackholed, new dials reach the new server.
    fn restart_at_new_address(&self, id: u16) {
        let incoming = self.net.relisten(&authority(id));
        self.serve(id, incoming);
    }

    /// Node `leader`'s (1-based) view restricted to `members` (1-based, itself included).
    fn view(&self, leader: u16, members: &[u16]) -> Peers {
        self.peers[leader as usize - 1]
            .iter()
            .filter(|p| {
                members
                    .iter()
                    .any(|&m| Identifier::try_from(m).unwrap() == p.identifier())
            })
            .cloned()
            .collect()
    }

    /// Node `from`'s (1-based) health record of node `to`.
    fn health(&self, from: u16, to: u16) -> Arc<PeerHealth> {
        self.peers[from as usize - 1][to as usize - 1]
            .health()
            .expect("a gRPC peer keeps health")
            .clone()
    }

    fn node(&self, id: u16) -> &Arc<Node> {
        &self.nodes[id as usize - 1]
    }

    fn control(&self, id: u16) -> &Control {
        &self.controls[id as usize - 1]
    }

    async fn sign(&self, leader: u16, tag: &str) -> rutli_cosigner::Result<[u8; 64]> {
        sign(
            self.node(leader),
            &self.peers[leader as usize - 1],
            KEY,
            &msg(tag),
        )
        .await
    }

    /// The driver's Signer client of node `id`, over the same in-memory network.
    fn signer(&self, id: u16) -> SignerClient<tonic::transport::Channel> {
        let dial = self.driver.dial_as(&cn(id), None, id).unwrap();
        let channel = dial
            .endpoint(&endpoint(id))
            .unwrap()
            .connect_with_connector_lazy(dial.connector_over(self.net.dialer()));
        SignerClient::new(channel)
    }

    fn all_up(&self) -> bool {
        (1..=N).all(|from| {
            (1..=N)
                .filter(|&to| to != from)
                .all(|to| self.health(from, to).state_name() == "up")
        })
    }

    fn transitions(&self) -> u64 {
        (1..=N)
            .flat_map(|from| {
                (1..=N)
                    .filter(move |&to| to != from)
                    .map(move |to| (from, to))
            })
            .map(|(f, t)| self.health(f, t).transitions())
            .sum()
    }
}

fn delay(d: u64) -> Act {
    Act::Delay(Duration::from_secs(d))
}

fn close(a: Duration, b: Duration, slack_ms: u64) -> bool {
    a.max(b) - a.min(b) <= Duration::from_millis(slack_ms)
}

async fn settle(secs: f64) {
    tokio::time::sleep(Duration::from_secs_f64(secs)).await;
}

// ── T1, T2: channel liveness ──────────────────────────────────────────────────────────────────

/// T1. A peer that stops answering on an established connection: a sign round to it fails at its
/// 2 s deadline (not the 10 s backstop), keepalive drops the dead connection within 8 s of its last
/// read, and once the link heals a fresh connection carries the next call.
#[tokio::test(start_paused = true)]
async fn t01_a_blackholed_peer_fails_within_its_deadline_and_its_connection_is_replaced_after_heal()
{
    let m = Mesh::new().await;
    let to2 = m.peers[0][1].clone();
    to2.ceremony_protocol().await.unwrap();
    assert_eq!(m.net.live(&cn(1), &authority(2)), 1);
    let dials = m.net.dials(&cn(1), &authority(2));

    m.net.fault_link(&cn(1), &authority(2), Fault::Blackhole);
    let t0 = Instant::now();
    let err = to2
        .sign_round1_within(KEY, "t1", &Round1Ctx::default(), ROUND1_DEADLINE)
        .await
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::PeerDeadline { peer: 2, .. }),
        "{err:?}"
    );
    assert!(
        close(t0.elapsed(), ROUND1_DEADLINE, 50),
        "failed after {:?}",
        t0.elapsed()
    );

    tokio::time::sleep_until(t0 + Duration::from_secs(9)).await;
    assert_eq!(
        m.net.live(&cn(1), &authority(2)),
        0,
        "keepalive closed the dead connection within 8 s"
    );
    assert!(m.health(1, 2).is_unreachable(), "{:?}", m.health(1, 2));

    m.net.fault_link(&cn(1), &authority(2), Fault::Heal);
    settle(1.5).await;
    assert_eq!(
        m.health(1, 2).state_name(),
        "up",
        "the prober saw it answer"
    );
    let t1 = Instant::now();
    to2.ceremony_protocol().await.unwrap();
    assert!(t1.elapsed() < Duration::from_millis(100));
    assert!(
        m.net.dials(&cn(1), &authority(2)) > dials,
        "a new connection carries the call"
    );
}

/// T2. A node replaced under a new address (old connections stay blackholed): tonic's channel
/// re-dials once keepalive closes the dead connection — no rebuild — and signing through that node
/// is back within 9 s.
#[tokio::test(start_paused = true)]
async fn t02_a_node_back_under_a_new_address_is_reached_again_by_the_same_channel() {
    let m = Mesh::new().await;
    let pair = m.view(1, &[1, 2]);
    sign(m.node(1), &pair, KEY, &msg("warm")).await.unwrap();

    m.restart_at_new_address(2);
    let t0 = Instant::now();
    let mut back = None;
    for i in 0..30 {
        if sign(m.node(1), &pair, KEY, &msg(&format!("t2-{i}")))
            .await
            .is_ok()
        {
            back = Some(t0.elapsed());
            break;
        }
        settle(1.0).await;
    }
    let back = back.expect("signing through node 2 came back");
    assert!(back <= Duration::from_secs(10), "back after {back:?}");
    assert_eq!(m.health(1, 2).state_name(), "up");
}

// ── T3–T5: the breaker ────────────────────────────────────────────────────────────────────────

/// T3. A blackholed member: of 20 signatures in a row only the first pays its round-1 deadline;
/// the rest sign at once with the other member.
#[tokio::test(start_paused = true)]
async fn t03_a_blackholed_member_costs_one_signature_one_deadline_not_every_signature() {
    let m = Mesh::new().await;
    m.net.fault(&authority(2), Fault::Blackhole);
    let mut took = Vec::new();
    for i in 0..20 {
        let t = Instant::now();
        m.sign(1, &format!("t3-{i}")).await.unwrap();
        took.push(t.elapsed());
    }
    assert!(close(took[0], ROUND1_DEADLINE, 100), "{took:?}");
    assert!(
        took[1..].iter().all(|d| *d < Duration::from_millis(100)),
        "{took:?}"
    );
    settle(1.5).await; // the deadline's probe
    assert!(m.health(1, 2).is_unreachable());
    assert_eq!(
        m.health(1, 3).state_name(),
        "up",
        "a slow peer changes only its own entry"
    );
}

/// T4. A member whose round 2 stalls (and which does not answer the abort either): the signature
/// pays one round-2 deadline and signs with the other member — the abort to the stalled member is
/// detached, never a second wait. The member is then marked stalled (its progress counter did not
/// move), and only its own entry changes.
#[tokio::test(start_paused = true)]
async fn t04_a_stalled_round_2_costs_one_deadline_and_the_abort_is_not_waited_for() {
    let m = Mesh::new().await;
    m.control(2).set("SignRound2", None, delay(600));
    m.control(2).set("AbortSign", None, delay(600));
    let t0 = Instant::now();
    m.sign(1, "t4").await.unwrap();
    let took = t0.elapsed();
    assert!(
        took >= ROUND2_DEADLINE && took < ROUND2_DEADLINE + Duration::from_millis(200),
        "took {took:?}"
    );
    settle(2.0).await;
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Stalled));
    assert_eq!(m.health(1, 3).state_name(), "up");
    assert_eq!(m.health(1, 3).transitions(), 0);
    // The next signatures go around it at once.
    let t1 = Instant::now();
    m.sign(1, "t4-next").await.unwrap();
    assert!(t1.elapsed() < Duration::from_millis(100));
}

/// T5. A member slow for this leader but busy completing rounds for another leader is excluded
/// from the signature that missed its deadline, and its breaker stays shut; once its progress
/// counter freezes, the next deadline opens it.
#[tokio::test(start_paused = true)]
async fn t05_a_busy_member_is_not_marked_down_and_a_frozen_one_is() {
    let m = Arc::new(Mesh::new().await);
    m.control(3).set("SignRound2", Some(&cn(1)), delay(6));
    // Leader 2 keeps signing with node 3: node 3's round-2 counter moves.
    let busy = {
        let m = m.clone();
        tokio::spawn(async move {
            let pair = m.view(2, &[2, 3]);
            let mut i = 0u64;
            loop {
                let _ = sign(m.node(2), &pair, KEY, &msg(&format!("busy-{i}"))).await;
                settle(0.1).await;
                i += 1;
            }
        })
    };
    settle(1.0).await;
    let pair = m.view(1, &[1, 3]);
    let t0 = Instant::now();
    let err = sign(m.node(1), &pair, KEY, &msg("t5")).await.unwrap_err();
    assert!(
        close(t0.elapsed(), ROUND2_DEADLINE, 100),
        "{:?}",
        t0.elapsed()
    );
    assert!(
        matches!(err, DaemonError::ThresholdNotMet { .. }),
        "excluded from this signature: {err:?}"
    );
    settle(2.0).await;
    assert_eq!(m.health(1, 3).state_name(), "up", "busy is not dead");
    assert_eq!(m.health(1, 3).transitions(), 0);

    // Now nothing completes on node 3 any more: the next deadline opens it.
    busy.abort();
    m.control(3).set("SignRound2", Some(&cn(1)), delay(600));
    settle(8.0).await;
    let _ = sign(m.node(1), &pair, KEY, &msg("t5-frozen"))
        .await
        .unwrap_err();
    settle(2.0).await;
    assert_eq!(m.health(1, 3).down_reason(), Some(DownReason::Stalled));
}

// ── T6: fast refusal ──────────────────────────────────────────────────────────────────────────

/// T6. A leader cut off from both peers: its first signature refuses after two round-1 deadlines
/// (≈ 4 s), the next once the in-flight probe has answered (≤ 1.5 s), then at once with
/// `no-quorum`; after the heal it signs again within 3 s.
#[tokio::test(start_paused = true)]
async fn t06_an_isolated_leader_refuses_quickly_and_signs_again_after_the_heal() {
    let m = Mesh::new().await;
    for other in [2, 3] {
        m.net
            .fault_link(&cn(1), &authority(other), Fault::Blackhole);
        m.net
            .fault_link(&cn(other), &authority(1), Fault::Blackhole);
    }
    let t = Instant::now();
    let err = m.sign(1, "t6-first").await.unwrap_err();
    assert!(
        t.elapsed() <= Duration::from_millis(4500),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(tonic::Status::from(err).code(), tonic::Code::Unavailable);

    let t = Instant::now();
    let err = m.sign(1, "t6-second").await.unwrap_err();
    assert!(
        t.elapsed() <= Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
    assert!(
        matches!(err, DaemonError::NoQuorum { needed: 2, visible: 1, ref missing } if missing == &vec![2, 3]),
        "{err:?}"
    );
    for i in 0..5 {
        let t = Instant::now();
        let err = m.sign(1, &format!("t6-{i}")).await.unwrap_err();
        assert!(
            t.elapsed() < Duration::from_millis(100),
            "{:?}",
            t.elapsed()
        );
        let status = tonic::Status::from(err);
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(
            status
                .metadata()
                .get(rutli_cosigner::error::ERROR_TRAILER)
                .unwrap(),
            rutli_cosigner::error::NO_QUORUM
        );
    }
    // The other two leaders sign with each other throughout.
    m.sign(2, "t6-others").await.unwrap();

    for other in [2, 3] {
        m.net.fault_link(&cn(1), &authority(other), Fault::Heal);
        m.net.fault_link(&cn(other), &authority(1), Fault::Heal);
    }
    let healed = Instant::now();
    let mut ok = false;
    while healed.elapsed() < Duration::from_secs(3) {
        if m.sign(1, "t6-healed").await.is_ok() {
            ok = true;
            break;
        }
        settle(0.5).await;
    }
    assert!(ok, "signing again within 3 s of the heal");
}

// ── T7–T9: what opens and what does not ───────────────────────────────────────────────────────

/// T7. The `keystore-down` trailer survives the wire and opens the member as refusing; a plain
/// UNAVAILABLE (an older member) opens it as unreachable; UNAVAILABLE with another trailer
/// (`sessions-full`) never opens. A refusing member whose store works again is closed by the probe
/// (its self-reported store state), with no restart anywhere.
#[tokio::test(start_paused = true)]
async fn t07_the_keystore_down_trailer_is_typed_across_the_wire_and_other_unavailables_are_told_apart(
) {
    let m = Mesh::new().await;
    let ctx = Round1Ctx::default();
    m.node(2)
        .keystore_health()
        .report_definite("Input/output error (os error 5)");
    let err = m.peers[0][1]
        .sign_round1(KEY, "t7", &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::KeystoreDown(ref d) if d.contains("readiness probe")),
        "{err:?}"
    );
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Refusing));
    m.node(2).check_keystore().unwrap();
    settle(2.5).await;
    assert_eq!(
        m.health(1, 2).state_name(),
        "up",
        "its probe reports the store working again"
    );

    m.control(3).set(
        "SignRound1",
        None,
        Act::Reply(Arc::new(|| {
            tonic::Status::unavailable("not serving: an older member")
        })),
    );
    let err = m.peers[0][2]
        .sign_round1(KEY, "t7-old", &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::Status(ref s) if s.code() == tonic::Code::Unavailable),
        "{err:?}"
    );
    assert_eq!(m.health(1, 3).down_reason(), Some(DownReason::Unreachable));
    settle(1.5).await;
    assert_eq!(m.health(1, 3).state_name(), "up", "its NodeInfo answers");

    let full = || {
        tonic::Status::from(DaemonError::Core(
            rutli_frost_core::CoreError::SessionsFull {
                cap_kind: rutli_frost_core::session::PendingCap::Opener,
                open: 1,
                cap: 1,
            },
        ))
    };
    m.control(3)
        .set("SignRound1", None, Act::Reply(Arc::new(full)));
    let before = m.health(1, 3).transitions();
    m.peers[0][2]
        .sign_round1(KEY, "t7-full", &ctx)
        .await
        .unwrap_err();
    assert_eq!(
        (m.health(1, 3).state_name(), m.health(1, 3).transitions()),
        ("up", before)
    );
}

/// T8. Answered refusals never open a breaker (unknown key, unknown session, another sharing); a
/// peer falsely marked down is still tried — last, never skipped — and a success closes it.
#[tokio::test(start_paused = true)]
async fn t08_refusals_do_not_open_and_a_falsely_opened_peer_is_still_used() {
    let m = Mesh::new().await;
    let to2 = m.peers[0][1].clone();
    to2.sign_round1("frost-no-such-key", "t8", &Round1Ctx::default())
        .await
        .unwrap_err();
    to2.sign_round2(KEY, "never-opened", &msg("t8"), &Default::default(), None)
        .await
        .unwrap_err();
    let other_sharing = Round1Ctx {
        leader_view: Some((99, [7; 32])),
        ..Default::default()
    };
    let err = to2
        .sign_round1(KEY, "t8-epoch", &other_sharing)
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::EpochMismatch { .. }), "{err:?}");
    assert_eq!(
        (m.health(1, 2).state_name(), m.health(1, 2).transitions()),
        ("up", 0)
    );

    m.health(1, 2).open(DownReason::Stalled);
    m.health(1, 3).open(DownReason::Stalled);
    m.sign(1, "t8-false-open")
        .await
        .expect("down peers are tried last, not skipped");
    assert_eq!(m.health(1, 2).state_name(), "up", "its round 2 succeeded");
}

/// T9. DKG ignores the breaker: it runs over every node, whatever this leader thinks of them.
#[tokio::test(start_paused = true)]
async fn t09_dkg_succeeds_with_peers_falsely_marked_down() {
    let m = Mesh::new().await;
    m.health(1, 2).open(DownReason::Unreachable);
    m.health(1, 3).open(DownReason::Stalled);
    let group = run_dkg(&m.peers[0], "frost-liveness-second").await.unwrap();
    let sig = sign(m.node(2), &m.peers[1], "frost-liveness-second", &msg("t9"))
        .await
        .unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &group,
        &msg("t9"),
        &sig
    ));
}

// ── T10: hosted writes ────────────────────────────────────────────────────────────────────────

/// T10. A member that does not answer within the deadline is skipped as unreachable by a hosted
/// key generation — the write commits at its quorum — and is never read as a conflict.
#[tokio::test(start_paused = true)]
async fn t10_a_member_past_its_deadline_is_unreachable_for_a_hosted_write_not_a_conflict() {
    let m = Mesh::hosted().await;
    m.control(3).set("*", None, delay(600));
    let (_, created, replicas) = rutli_cosigner::orchestrator::generate_hosted_key(
        m.node(1),
        &m.peers[0],
        "rutli-liveness-aes",
        rutli_cosigner::hosted::HostedSpec::Aes256Gcm,
        DEFAULT_WRITE_QUORUM,
    )
    .await
    .unwrap();
    assert!(created);
    assert_eq!(replicas, 2);
}

// ── T11, T15: the member's key store ──────────────────────────────────────────────────────────

fn nonce_dir(m: &Mesh, id: u16) -> std::path::PathBuf {
    m._tmp
        .path()
        .join(format!("node-{id}"))
        .join(format!("{KEY}.nonces"))
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn root() -> bool {
    // SAFETY: geteuid has no preconditions and touches no memory.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        eprintln!("skipped: running as root, a read-only directory would still be writable");
    }
    root
}

/// T11. A definite I/O error in a member's round-2 store work (EACCES on its nonce markers, as an
/// EROFS or EIO would) marks its key store down at once — not at the next probe — and the leader
/// signs with the other member in the same call.
#[tokio::test(start_paused = true)]
async fn t11_a_definite_io_error_in_round_2_marks_the_store_down_at_once() {
    if root() {
        return;
    }
    let m = Mesh::new().await;
    m.sign(1, "t11-warm").await.unwrap();
    set_mode(&nonce_dir(&m, 2), 0o500);
    let t = Instant::now();
    m.sign(1, "t11").await.unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
    assert!(
        m.node(2).keystore_health().is_down(),
        "marked down by the failed round 2 itself"
    );
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Refusing));
    set_mode(&nonce_dir(&m, 2), 0o700);
}

/// T15. One I/O error does not take a node out until a restart: down at once, then the next
/// readiness probe that finds the store working clears it, leaders close their breaker from the
/// node's own report, and it signs again.
#[tokio::test(start_paused = true)]
async fn t15_a_single_io_error_is_cleared_by_the_next_probe_without_a_restart() {
    if root() {
        return;
    }
    let m = Mesh::new().await;
    m.sign(1, "t15-warm").await.unwrap();
    set_mode(&nonce_dir(&m, 2), 0o500);
    m.sign(1, "t15-eio").await.unwrap();
    assert!(m.node(2).keystore_health().is_down());
    // Down: it refuses round 1 with the trailer, so no leader includes it meanwhile.
    let err = m.peers[2][1]
        .sign_round1(KEY, "t15-refused", &Round1Ctx::default())
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::KeystoreDown(_)), "{err:?}");

    set_mode(&nonce_dir(&m, 2), 0o700);
    m.node(2).check_keystore().unwrap(); // the monitor's next tick
    assert!(!m.node(2).keystore_health().is_down());
    settle(2.5).await;
    assert_eq!(m.health(1, 2).state_name(), "up");
    sign(m.node(1), &m.view(1, &[1, 2]), KEY, &msg("t15-back"))
        .await
        .expect("node 2 signs again");
}

// ── T12, T13, T4b: the client's deadline ──────────────────────────────────────────────────────

fn sign_request(tag: &str, timeout: Option<Duration>) -> tonic::Request<pb::SignRequest> {
    let mut req = tonic::Request::new(pb::SignRequest {
        key_id: KEY.into(),
        message: msg(tag).to_vec(),
        intent: None,
    });
    if let Some(t) = timeout {
        req.set_timeout(t);
    }
    req
}

/// T12. A client deadline shorter than the leader's budget ends the leader's work by that deadline,
/// and the sessions it opened are aborted on every member.
#[tokio::test(start_paused = true)]
async fn t12_a_client_deadline_ends_the_leaders_work_and_its_sessions_are_aborted() {
    let m = Mesh::new().await;
    m.control(2).set("SignRound2", None, delay(600));
    m.control(3).set("SignRound2", None, delay(600));
    let t = Instant::now();
    let err = m
        .signer(1)
        .sign(sign_request("t12", Some(Duration::from_secs(3))))
        .await
        .unwrap_err();
    assert!(
        t.elapsed() <= Duration::from_secs(3),
        "{:?} ({err:?})",
        t.elapsed()
    );
    settle(1.5).await;
    assert_eq!(
        m.node(1).sign_load().leading(),
        0,
        "the leader is done with it"
    );
    for id in 1..=N {
        assert_eq!(
            m.node(id).pending_sign_count(KEY),
            0,
            "node {id} holds no session of it"
        );
    }
}

/// T13. No `grpc-timeout`: the leader's own budget and round deadlines apply (a stalled round 2
/// costs 5 s, then the other member signs). Under 1 s: refused at once, no round started. Huge:
/// capped by the round deadlines, never a longer wait. T4b: with the driver's 5 s attempt, a member
/// dying in round 2 costs ≈ 4 s and the signature still lands inside the attempt.
#[tokio::test(start_paused = true)]
async fn t13_the_client_deadline_only_ever_shortens_the_leaders_work() {
    let m = Mesh::new().await;
    let mut client = m.signer(1);
    client.sign(sign_request("t13-warm", None)).await.unwrap();
    m.control(2).set("SignRound2", None, delay(600));

    let t = Instant::now();
    client.sign(sign_request("t13-none", None)).await.unwrap();
    assert!(
        t.elapsed() >= ROUND2_DEADLINE
            && t.elapsed() < ROUND2_DEADLINE + Duration::from_millis(200),
        "{:?}",
        t.elapsed()
    );

    let before: Vec<_> = (1..=N).map(|id| m.node(id).load_now()).collect();
    let err = client
        .sign(sign_request("t13-short", Some(Duration::from_millis(500))))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::DeadlineExceeded, "{err:?}");
    assert!(err.message().contains("no round started"), "{err:?}");
    let after: Vec<_> = (1..=N).map(|id| m.node(id).load_now()).collect();
    assert_eq!(
        before.iter().map(|l| l.r1done).collect::<Vec<_>>(),
        after.iter().map(|l| l.r1done).collect::<Vec<_>>()
    );

    // A huge deadline: the round-2 deadline still bounds the wait on the stalled member.
    m.health(1, 2).close("call");
    let mut req = sign_request("t13-huge", None);
    req.metadata_mut()
        .insert("grpc-timeout", "99999999S".parse().unwrap());
    let t = Instant::now();
    client.sign(req).await.unwrap();
    assert!(
        t.elapsed() < ROUND2_DEADLINE + Duration::from_millis(200),
        "{:?}",
        t.elapsed()
    );

    // T4b: the driver's 5 s attempt. Round 2 gives up at min(5 s, left − 1 s) ≈ 4 s.
    m.health(1, 2).close("call");
    let t = Instant::now();
    client
        .sign(sign_request("t13-driver", Some(Duration::from_secs(5))))
        .await
        .unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(4200),
        "{:?}",
        t.elapsed()
    );
}

// ── T14: saturation ───────────────────────────────────────────────────────────────────────────

/// T14. Every member a single slow server (sign rounds queued, 150 ms each) under three leaders
/// signing at once: round deadlines are missed, but every member keeps making progress — no breaker
/// opens, no signature makes more than two attempts, and no member releases more than two shares for
/// one request (the per-request share cap is 8).
#[tokio::test(start_paused = true)]
async fn t14_saturated_but_progressing_members_open_no_breaker() {
    let m = Arc::new(Mesh::new().await);
    for id in 1..=N {
        *m.control(id).queue.lock().unwrap() = Some((
            Arc::new(tokio::sync::Semaphore::new(1)),
            Duration::from_millis(150),
        ));
    }
    let slow = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    let per_leader = 15;
    for leader in 1..=N {
        for i in 0..per_leader {
            let (m, slow) = (m.clone(), slow.clone());
            tasks.spawn(async move {
                let t = Instant::now();
                let r = m.sign(leader, &format!("t14-{leader}-{i}")).await;
                if t.elapsed() >= ROUND1_DEADLINE {
                    slow.fetch_add(1, Ordering::SeqCst);
                }
                r.is_ok()
            });
        }
    }
    let mut ok = 0;
    while let Some(r) = tasks.join_next().await {
        ok += usize::from(r.unwrap());
    }
    let signatures = N as usize * per_leader;
    assert!(
        slow.load(Ordering::SeqCst) > 0,
        "the members were saturated (some signature waited a deadline)"
    );
    assert!(ok > 0);
    settle(3.0).await;
    assert_eq!(m.transitions(), 0, "no breaker opened");
    assert!(m.all_up());
    // Each attempt sends one remote round 1 and at most one remote round 2 (t = 2, leader first).
    let r1: usize = (1..=N).map(|id| m.control(id).seen("SignRound1")).sum();
    let r2: usize = (1..=N).map(|id| m.control(id).seen("SignRound2")).sum();
    assert!(
        r1 <= 2 * signatures,
        "{r1} remote round 1s for {signatures} signatures"
    );
    assert!(
        r2 <= 2 * signatures,
        "{r2} remote round 2s for {signatures} signatures"
    );
    for id in 1..=N {
        m.control(id).clear();
    }
}

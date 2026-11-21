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
//!   used, DKG ignores it (T7, T8, T9); a member stalled once is back within one window through
//!   its trial while another member is up (T17); a control call that reads the store opens nothing
//!   past its deadline, `NodeInfo` does (T18); a signature that finds the trial taken still tries
//!   that subset in its own place (T21); a trial whose peer was never sent a round is given back
//!   at once (T22);
//! - fast refusal: an isolated leader refuses within a few seconds, then at once, and signs again
//!   right after the heal (T6);
//! - hosted writes: a member past its deadline is skipped as unreachable, never read as a conflict
//!   (T10);
//! - the member side: a definite I/O error in round 2 marks the store down at once, and a probe that
//!   finds it working brings it back with no restart (T11, T15); a round 2 still in its store work
//!   when the leader's deadline cancels the call over gRPC finishes once — one marker, one journal
//!   entry — and the leader's abort meanwhile finds nothing to drop (T20); a round 1 that waited
//!   past its caller's deadline for a blocking thread opens no session (T19);
//! - the client's deadline: it only shortens the leader's work (T12, T13, T4b);
//! - saturation: slow but progressing members open no breaker, and no signature makes more than
//!   `n − t + 1` attempts, counted at every member (T14).
//!
//! Nonce and intent safety under abandoned attempts (T16) is in `signing_policy.rs`, next to the
//! journal helpers it needs.

// DaemonError wraps large frost/tonic types (as in the crate itself).
#![allow(clippy::result_large_err)]

#[path = "common/memnet.rs"]
mod memnet;
#[path = "common/store_fault.rs"]
mod store_fault;

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use frost_ed25519::Identifier;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use async_trait::async_trait;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use rutli_cosigner::config::{SigningPolicyConfig, TlsConfig};
use rutli_cosigner::journal::{read_key_dir, JournalEntry, Retention, SignJournal};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::liveness::{DownReason, PeerHealth};
use rutli_cosigner::node::{Node, Round1Ctx};
use rutli_cosigner::orchestrator::{
    max_sign_attempts, run_dkg, sign, Peers, DEFAULT_WRITE_QUORUM,
};
use rutli_cosigner::pb;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::pb::signer_client::SignerClient;
use rutli_cosigner::pb::signer_server::SignerServer;
use rutli_cosigner::peer::{
    GrpcPeer, Liveness, LocalPeer, PeerApi, BREAKER_WINDOW, CONTROL_DEADLINE, ROUND1_DEADLINE,
    ROUND2_DEADLINE,
};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use rutli_cosigner::tls::Tls;
use rutli_cosigner::DaemonError;
use tokio::time::Instant;
use tonic::codegen::http;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

use memnet::{Fault, MemNet};
use store_fault::{Store, StoreFault};

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
    /// Each node's round-2 store work ([`StoreFault`]).
    stores: Vec<Arc<StoreFault>>,
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
        let m = Self::build(false, false);
        run_dkg(&m.peers[0], KEY).await.unwrap();
        m
    }

    /// [`Mesh::new`] with hosted keys on every node.
    async fn hosted() -> Self {
        let m = Self::build(true, false);
        run_dkg(&m.peers[0], KEY).await.unwrap();
        m
    }

    /// [`Mesh::new`] with a signing policy and sign journal on every node (no intents required, no
    /// rate limit): every released share is journaled with its session id and digest.
    async fn journaled() -> Self {
        let m = Self::build(false, true);
        run_dkg(&m.peers[0], KEY).await.unwrap();
        m
    }

    fn build(hosted: bool, journaled: bool) -> Self {
        let net = MemNet::new();
        let ca = ca();
        let tmp = tempfile::tempdir().unwrap();
        let tls: Vec<Tls> = (1..=N)
            .map(|i| rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, &cn(i))).unwrap())
            .collect();
        let driver = rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, "driver")).unwrap();
        let stores: Vec<Arc<StoreFault>> = (0..N).map(|_| StoreFault::new()).collect();
        let policy = SigningPolicyConfig {
            require_intent: Some(false),
            require_ceremony_intent: Some(false),
            sign_rate_limit_per_min: 0,
            sign_rate_limit_per_day: 0,
            ..Default::default()
        };
        let nodes: Vec<Arc<Node>> = (1..=N)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
                let mut node = Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
                    .with_sign_store_hook(stores[i as usize - 1].hook());
                if journaled {
                    let verifier = rutli_cosigner::intent::IntentVerifier::new(
                        ca.0.pem().into_bytes(),
                        false,
                        CLUSTER.into(),
                        ["driver".to_string()],
                        &policy,
                    )
                    .unwrap();
                    let journal = SignJournal::open(
                        tmp.path().join(format!("journal-{i}")),
                        i,
                        Retention {
                            days: 90,
                            max_bytes: 64 << 20,
                        },
                    )
                    .unwrap();
                    node = node.with_sign_guard(Arc::new(
                        rutli_cosigner::sign_policy::SignGuard::new(
                            Arc::new(verifier),
                            journal,
                            10,
                        ),
                    ));
                }
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
            stores,
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

    fn store(&self, id: u16) -> &StoreFault {
        &self.stores[id as usize - 1]
    }

    /// Node `id`'s sign journal for `KEY` ([`Mesh::journaled`]).
    fn journal(&self, id: u16) -> Vec<JournalEntry> {
        let dir = self._tmp.path().join(format!("journal-{id}")).join(KEY);
        if !dir.exists() {
            return Vec::new();
        }
        read_key_dir(&dir).unwrap().entries
    }

    /// Nonce markers node `id` has burnt for `KEY`.
    fn markers(&self, id: u16) -> usize {
        std::fs::read_dir(nonce_dir(self, id))
            .map(|d| d.count())
            .unwrap_or(0)
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
/// move), and only its own entry changes. One signature per window pays a deadline for its trial.
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
    settle(1.0).await;
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Stalled));
    assert_eq!(m.health(1, 3).state_name(), "up");
    assert_eq!(m.health(1, 3).transitions(), 0);
    // Inside its window the next signatures go around it at once.
    let t1 = Instant::now();
    m.sign(1, "t4-next").await.unwrap();
    assert!(t1.elapsed() < Duration::from_millis(100));
    // After the window one signature tries it first (its trial) and pays one round-2 deadline; the
    // window doubles, and the signatures after that go around it at once again.
    settle(1.5).await;
    let t2 = Instant::now();
    m.sign(1, "t4-trial").await.unwrap();
    assert!(
        t2.elapsed() >= ROUND2_DEADLINE
            && t2.elapsed() < ROUND2_DEADLINE + Duration::from_millis(200),
        "{:?}",
        t2.elapsed()
    );
    settle(1.0).await;
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Stalled));
    for i in 0..5 {
        let t = Instant::now();
        m.sign(1, &format!("t4-after-{i}")).await.unwrap();
        assert!(t.elapsed() < Duration::from_millis(100), "{:?}", t.elapsed());
        settle(0.5).await;
    }
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
        matches!(err, DaemonError::AttemptsExhausted { usable: 1, .. }),
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

/// T17. A member whose round 2 stalls once and then answers again is back up within one window
/// while the other member is up: the first signature after the window tries a subset with it first
/// (its trial), and that signature pays no deadline since the member answers. A trial is used up
/// only by an attempt that contacts the member.
#[tokio::test(start_paused = true)]
async fn t17_a_member_stalled_once_is_back_within_one_window_while_another_member_is_up() {
    let m = Mesh::new().await;
    m.sign(1, "t17-warm").await.unwrap();
    m.control(2).set("SignRound2", None, delay(600));
    m.sign(1, "t17-stall").await.unwrap();
    let opened = Instant::now();
    settle(0.1).await; // the deadline's probe
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Stalled));
    assert_eq!(m.health(1, 3).state_name(), "up");
    m.control(2).clear();
    let round2s = m.control(2).seen("SignRound2");

    let mut back = None;
    for i in 0..40 {
        let t = Instant::now();
        m.sign(1, &format!("t17-{i}")).await.unwrap();
        assert!(
            t.elapsed() < Duration::from_millis(100),
            "no signature pays a deadline: {:?}",
            t.elapsed()
        );
        if m.health(1, 2).state_name() == "up" {
            back = Some(opened.elapsed());
            break;
        }
        assert_eq!(
            m.control(2).seen("SignRound2"),
            round2s,
            "inside the window node 2 is not asked"
        );
        settle(0.2).await;
    }
    let back = back.expect("node 2 came back through its trial");
    assert!(
        back <= BREAKER_WINDOW + Duration::from_millis(500),
        "back after {back:?}"
    );
    assert_eq!(
        m.control(2).seen("SignRound2"),
        round2s + 1,
        "exactly one signature tried it"
    );
    assert_eq!(m.health(1, 3).transitions(), 0);
}

/// T21. Two signatures start together after a stalled member's window while the other member
/// refuses round 1: both see the trial due, one takes it and signs through it; the other finds it
/// taken, skips only that first try, and once the refusing member has failed signs with the same
/// subset in its tier's place — down peers are reordered, never skipped.
#[tokio::test(start_paused = true)]
async fn t21_a_signature_that_finds_the_trial_taken_still_tries_its_subset_in_place() {
    let m = Mesh::new().await;
    m.sign(1, "t21-warm").await.unwrap();
    m.control(2).set("SignRound2", None, delay(600));
    m.sign(1, "t21-stall").await.unwrap();
    settle(0.1).await; // the deadline's probe
    assert_eq!(m.health(1, 2).down_reason(), Some(DownReason::Stalled));
    // Node 2 has recovered (node 1 still holds it down); node 3 refuses every round 1.
    m.control(2).clear();
    m.control(3).set(
        "SignRound1",
        None,
        Act::Reply(Arc::new(|| {
            tonic::Status::failed_precondition("t21: refused")
        })),
    );
    settle(BREAKER_WINDOW.as_secs_f64()).await;
    assert!(m.health(1, 2).trial_due());
    let (to2, to3) = (
        m.control(2).seen("SignRound1"),
        m.control(3).seen("SignRound1"),
    );

    let (a, b) = tokio::join!(m.sign(1, "t21-a"), m.sign(1, "t21-b"));
    a.expect("the signature with the trial signs through {1,2}");
    b.expect("the other one signs through {1,2} after {1,3} failed");
    assert_eq!(
        m.control(2).seen("SignRound1"),
        to2 + 2,
        "both signatures sent node 2 a round 1"
    );
    assert_eq!(
        m.control(3).seen("SignRound1"),
        to3 + 1,
        "only the signature without the trial tried {{1,3}}"
    );
    assert_eq!(m.health(1, 2).state_name(), "up");
}

/// T22. 3-of-5: a stalled member's trial subset is {leader, best other, stalled}, and rounds go to
/// members in turn. When the middle member refuses round 1, the stalled one is never sent a round:
/// the trial is given back at once (published `down` again, due, its window not doubled) and the
/// next signature takes it.
#[tokio::test(start_paused = true)]
async fn t22_a_trial_whose_peer_was_never_sent_a_round_is_given_back() {
    let tmp = tempfile::tempdir().unwrap();
    let nodes: Vec<Arc<Node>> = (1..=5u16)
        .map(|i| {
            let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), 5, 3, ks))
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let plain: Peers = nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>)
        .collect();
    run_dkg(&plain, KEY).await.unwrap();
    let round1s: Round1Log = Arc::default();
    let refuse = Arc::new(AtomicBool::new(true));
    let stalled = Arc::new(PeerHealth::new(4, Liveness::default()));
    let view: Peers = plain
        .iter()
        .enumerate()
        .map(|(i, p)| {
            Arc::new(Counted {
                inner: p.clone(),
                round1s: round1s.clone(),
                health: (i == 3).then(|| stalled.clone()),
                refuse_round1: (i == 1).then(|| refuse.clone()),
            }) as Arc<dyn PeerApi>
        })
        .collect();
    stalled.open(DownReason::Stalled);
    settle(BREAKER_WINDOW.as_secs_f64()).await;
    assert!(stalled.trial_due());
    let before = stalled.transitions();
    let to = |member: u16| {
        round1s
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.member == member)
            .count()
    };

    // {1,2,4} (the trial) fails at node 2 before node 4 is asked; {1,3,5} signs.
    sign(&nodes[0], &view, KEY, &msg("t22-a"))
        .await
        .expect("the all-up subset signs");
    assert_eq!(to(2), 1);
    assert_eq!(to(4), 0, "node 4 was never sent a round");
    assert_eq!(
        (stalled.state_name(), stalled.down_reason()),
        ("down", Some(DownReason::Stalled)),
        "the trial is given back and published as down"
    );
    assert_eq!(stalled.transitions(), before + 2, "down → trial → down");
    assert!(stalled.trial_due(), "due again at once");

    // Node 2 answers again: the next signature takes the trial and sends node 4 its rounds.
    refuse.store(false, Ordering::SeqCst);
    sign(&nodes[0], &view, KEY, &msg("t22-b"))
        .await
        .expect("the trial subset signs");
    assert_eq!(to(4), 1, "the next signature took the trial");
    // In-process members feed no health: no verdict, the trial is held.
    assert_eq!(stalled.state_name(), "trial");
    // Its window was not doubled by the given-back trial: a failed trial now waits 2 × 2 s.
    stalled.open(DownReason::Stalled);
    settle(2.0 * BREAKER_WINDOW.as_secs_f64()).await;
    assert!(stalled.trial_due());
}

/// T18. A `KeyEpoch` or `CeremonyStatus` past its deadline (a slow store on the peer) opens no
/// breaker and signing goes on with that peer; a `NodeInfo` past its deadline opens it as
/// unreachable, and the prober brings it back once it answers.
#[tokio::test(start_paused = true)]
async fn t18_a_store_reading_control_call_past_its_deadline_opens_nothing_and_node_info_does() {
    let m = Mesh::new().await;
    let to2 = m.peers[0][1].clone();
    m.control(2).set("KeyEpoch", None, delay(600));
    m.control(2).set("CeremonyStatus", None, delay(600));
    let t = Instant::now();
    let err = to2.key_epoch(KEY).await.unwrap_err();
    assert!(
        matches!(err, DaemonError::PeerDeadline { peer: 2, .. }),
        "{err:?}"
    );
    assert!(close(t.elapsed(), CONTROL_DEADLINE, 50), "{:?}", t.elapsed());
    let err = to2.ceremony_status("t18").await.unwrap_err();
    assert!(
        matches!(err, DaemonError::PeerDeadline { peer: 2, .. }),
        "{err:?}"
    );
    settle(1.5).await;
    assert_eq!(
        (m.health(1, 2).state_name(), m.health(1, 2).transitions()),
        ("up", 0)
    );
    sign(m.node(1), &m.view(1, &[1, 2]), KEY, &msg("t18"))
        .await
        .expect("node 2 still signs");

    m.control(2).set("NodeInfo", None, delay(600));
    let err = to2.node_info().await.unwrap_err();
    assert!(
        matches!(err, DaemonError::PeerDeadline { peer: 2, .. }),
        "{err:?}"
    );
    assert!(m.health(1, 2).is_unreachable());
    m.control(2).clear();
    settle(1.5).await;
    assert_eq!(m.health(1, 2).state_name(), "up", "its probe answers again");
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

/// T11. A definite I/O error in a member's round-2 store work (an injected EIO, as an EROFS or
/// EACCES would be) marks its key store down at once — not at the next probe — and the leader signs
/// with the other member in the same call. The failed round 2 burns no marker.
#[tokio::test(start_paused = true)]
async fn t11_a_definite_io_error_in_round_2_marks_the_store_down_at_once() {
    let m = Mesh::new().await;
    m.sign(1, "t11-warm").await.unwrap();
    let markers = m.markers(2);
    m.store(2).set(Store::Fail(libc::EIO));
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
    assert_eq!(m.markers(2), markers, "no marker for the failed round 2");
    m.store(2).set(Store::Ok);
}

/// T15. One I/O error does not take a node out until a restart: down at once, then the next
/// readiness probe that finds the store working clears it, leaders close their breaker from the
/// node's own report, and it signs again.
#[tokio::test(start_paused = true)]
async fn t15_a_single_io_error_is_cleared_by_the_next_probe_without_a_restart() {
    let m = Mesh::new().await;
    m.sign(1, "t15-warm").await.unwrap();
    m.store(2).set(Store::Fail(libc::EIO));
    m.sign(1, "t15-eio").await.unwrap();
    assert!(m.node(2).keystore_health().is_down());
    // Down: it refuses round 1 with the trailer, so no leader includes it meanwhile.
    let err = m.peers[2][1]
        .sign_round1(KEY, "t15-refused", &Round1Ctx::default())
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::KeystoreDown(_)), "{err:?}");

    m.store(2).set(Store::Ok);
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

// ── T20: a late round 2 over gRPC ──────────────────────────────────────────────────────────────

/// Yield until `done`, moving no time (a held blocking thread stops paused time from advancing by
/// itself, and none is needed here).
async fn until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..100_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("never happened: {what}");
}

/// T20. The real cancel-while-blocking path: a member's round 2 is inside its store work (after it
/// took the session out of memory, before the journal entry and the marker) when the leader's
/// round-2 deadline passes. The leader's call is cancelled over gRPC and its abort reaches the
/// member, which finds nothing to drop; the leader signs with the other member. When the store
/// moves again the round 2 finishes once: exactly one marker and one journal entry for that
/// session, and the leader never resends it.
#[tokio::test(start_paused = true)]
async fn t20_a_round_2_cancelled_in_its_store_work_finishes_once() {
    let m = Arc::new(Mesh::journaled().await);
    m.sign(1, "t20-warm").await.unwrap();
    let (markers, journaled) = (m.markers(2), m.journal(2).len());
    let aborts = m.control(2).seen("AbortSign");
    m.store(2).set(Store::Hold);
    let signing = {
        let m = m.clone();
        tokio::spawn(async move { m.sign(1, "t20").await })
    };
    until("node 2's round 2 to reach its store work", || {
        m.stores[1].held() == 1
    })
    .await;
    assert_eq!(
        m.node(2).pending_sign_count(KEY),
        0,
        "its nonces are out of memory"
    );
    let t0 = Instant::now();
    tokio::time::advance(ROUND2_DEADLINE + Duration::from_millis(10)).await;
    signing
        .await
        .unwrap()
        .expect("signed with the other member");
    assert!(t0.elapsed() < ROUND2_DEADLINE + Duration::from_millis(200));
    until("the abort to reach node 2", || {
        m.control(2).seen("AbortSign") > aborts
    })
    .await;
    assert_eq!(
        (m.markers(2), m.journal(2).len()),
        (markers, journaled),
        "nothing released yet"
    );

    m.store(2).set(Store::Ok);
    until("node 2's round 2 to end", || {
        m.node(2).load_now().inflight == 0
    })
    .await;
    let late: Vec<_> = m.journal(2).into_iter().skip(journaled).collect();
    assert_eq!(
        late.len(),
        1,
        "the abandoned session released one share: {late:?}"
    );
    assert_eq!(m.markers(2), markers + 1, "and burnt one marker");
    let session = &late[0].session_id;
    let store =
        rutli_frost_core::nonce_store::NonceStore::open(nonce_dir(&m, 2)).unwrap();
    assert!(store.is_consumed(session).unwrap());
    assert_eq!(
        m.control(2).seen("SignRound2"),
        2,
        "warm-up plus the cancelled one: never resent"
    );
    m.sign(1, "t20-after").await.unwrap();
}

// ── T19: a round that waited past its caller's deadline ───────────────────────────────────────

/// T19. A sign round 1 queued behind a jammed blocking pool until its caller's deadline passed
/// opens no session when a thread frees up: the caller is gone and its abort may already have come
/// and gone, so nonces opened now would wait for the TTL. The same round within its deadline opens
/// one (the check is not vacuous).
#[test]
fn t19_a_round_1_queued_past_its_callers_deadline_opens_no_session() {
    use rutli_cosigner::pb::peer_server::Peer;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .max_blocking_threads(1)
        .build()
        .unwrap();
    rt.block_on(async {
        let m = Mesh::new().await;
        let node = m.node(2).clone();
        let svc = Arc::new(PeerSvc {
            node: node.clone(),
            allowed_cns: None,
            peer_ids: None,
            peer_pins: None,
        });
        let round1 = |session: &str| {
            let mut req = tonic::Request::new(pb::SignRound1Request {
                key_id: KEY.into(),
                session_id: session.into(),
                ..Default::default()
            });
            req.metadata_mut()
                .insert("grpc-timeout", "2000m".parse().unwrap());
            req
        };

        // The pool's one thread is busy (a hung store elsewhere); the round queues behind it.
        let (release, jammed) = std::sync::mpsc::channel::<()>();
        let jam = tokio::task::spawn_blocking(move || {
            let _ = jammed.recv();
        });
        let call = {
            let (svc, req) = (svc.clone(), round1("t19-late"));
            tokio::spawn(async move { svc.sign_round1(req).await })
        };
        while node.load_now().inflight == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        release.send(()).unwrap();
        jam.await.unwrap();
        let err = call.await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::DeadlineExceeded, "{err:?}");
        assert_eq!(node.pending_sign_count(KEY), 0, "no session opened");

        svc.sign_round1(round1("t19-in-time")).await.unwrap();
        assert_eq!(node.pending_sign_count(KEY), 1);
    });
}

// ── T14: saturation ───────────────────────────────────────────────────────────────────────────

/// One sign round 1 a leader sent.
struct Round1Sent {
    message: Vec<u8>,
    session: String,
    member: u16,
    /// The member is its attempt's first: an attempt sends its first member a round 1 before any
    /// other member, so these count attempts, whichever member is first.
    first: bool,
}

/// The sign round 1s leaders sent ([`Round1Sent`]).
type Round1Log = Arc<Mutex<Vec<Round1Sent>>>;

/// A leader's view of one member that logs the leader's sign round 1s ([`Round1Log`]) and forwards
/// everything, liveness included.
struct Counted {
    inner: Arc<dyn PeerApi>,
    round1s: Round1Log,
    /// Health kept here, for an in-process member (which keeps none): it is then a remote member to
    /// the leader.
    health: Option<Arc<PeerHealth>>,
    /// While set, round 1 is refused (an answered policy refusal) after it is logged.
    refuse_round1: Option<Arc<AtomicBool>>,
}

#[async_trait]
impl PeerApi for Counted {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    fn is_local(&self) -> bool {
        self.health.is_none() && self.inner.is_local()
    }
    fn health(&self) -> Option<&Arc<PeerHealth>> {
        self.health.as_ref().or_else(|| self.inner.health())
    }
    async fn reachable_within(&self, fresh: Duration, wait: Duration) -> bool {
        self.inner.reachable_within(fresh, wait).await
    }
    async fn sign_round1_within(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
        deadline: Duration,
    ) -> rutli_cosigner::Result<SigningCommitments> {
        let member = (1..=u16::MAX)
            .find(|&i| Identifier::try_from(i).ok() == Some(self.identifier()))
            .unwrap();
        self.round1s.lock().unwrap().push(Round1Sent {
            message: ctx.message.clone().unwrap_or_default(),
            session: session_id.to_owned(),
            member,
            first: ctx.signers.as_ref().and_then(|s| s.first()) == Some(&member),
        });
        if self
            .refuse_round1
            .as_ref()
            .is_some_and(|r| r.load(Ordering::SeqCst))
        {
            return Err(DaemonError::PolicyRefused(format!(
                "cosigner {member}: refused for the test"
            )));
        }
        self.inner
            .sign_round1_within(key_id, session_id, ctx, deadline)
            .await
    }
    async fn sign_round2_within(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &std::collections::BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
        deadline: Duration,
    ) -> rutli_cosigner::Result<SignatureShare> {
        self.inner
            .sign_round2_within(
                key_id,
                session_id,
                message,
                commitments,
                intent_digest,
                deadline,
            )
            .await
    }
    async fn abort_sign_within(
        &self,
        key_id: &str,
        session_id: &str,
        deadline: Duration,
    ) -> rutli_cosigner::Result<()> {
        self.inner
            .abort_sign_within(key_id, session_id, deadline)
            .await
    }
    async fn sign_round1(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
    ) -> rutli_cosigner::Result<SigningCommitments> {
        self.inner.sign_round1(key_id, session_id, ctx).await
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &std::collections::BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> rutli_cosigner::Result<SignatureShare> {
        self.inner
            .sign_round2(key_id, session_id, message, commitments, intent_digest)
            .await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> rutli_cosigner::Result<()> {
        self.inner.abort_sign(key_id, session_id).await
    }
    async fn ceremony_fence(
        &self,
        c: &str,
        k: &str,
        kind: &'static str,
    ) -> rutli_cosigner::Result<()> {
        self.inner.ceremony_fence(c, k, kind).await
    }
    async fn ceremony_release(&self, c: &str, k: &str) -> rutli_cosigner::Result<()> {
        self.inner.ceremony_release(c, k).await
    }
    async fn node_info(&self) -> rutli_cosigner::Result<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(
        &self,
        a: &str,
        b: &str,
        s: &str,
        d: &[u8],
        w: &rutli_cosigner::wrap::Wrapped,
    ) -> rutli_cosigner::Result<Vec<u8>> {
        self.inner.replicate_key(a, b, s, d, w).await
    }
    async fn fetch_key(
        &self,
        k: &str,
    ) -> rutli_cosigner::Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(k).await
    }
    async fn list_keys(&self) -> rutli_cosigner::Result<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, c: &str, k: &str) -> rutli_cosigner::Result<bool> {
        self.inner.purge_key(c, k).await
    }
}

/// T14. Every member a single slow server (sign rounds queued, 150 ms each) under three leaders
/// signing at once: round deadlines are missed, but every member keeps making progress. Counted
/// per signature, not in aggregate: no signature makes more than `n − t + 1` attempts (counted at
/// every member: one round-1 session at each attempt's first member, the leader's own node or
/// not), no member opens more round-1 sessions for one signature than that, nor journals more
/// shares for it (nor more than `max_shares_per_request`), and no breaker opens.
#[tokio::test(start_paused = true)]
async fn t14_saturated_but_progressing_members_open_no_breaker() {
    let m = Arc::new(Mesh::journaled().await);
    for id in 1..=N {
        *m.control(id).queue.lock().unwrap() = Some((
            Arc::new(tokio::sync::Semaphore::new(1)),
            Duration::from_millis(150),
        ));
    }
    let round1s: Round1Log = Arc::default();
    let views: Vec<Peers> = (0..N as usize)
        .map(|i| {
            m.peers[i]
                .iter()
                .map(|p| {
                    Arc::new(Counted {
                        inner: p.clone(),
                        round1s: round1s.clone(),
                        health: None,
                        refuse_round1: None,
                    }) as Arc<dyn PeerApi>
                })
                .collect()
        })
        .collect();
    let views = Arc::new(views);
    let slow = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    let per_leader = 15;
    for leader in 1..=N {
        for i in 0..per_leader {
            let (m, views, slow) = (m.clone(), views.clone(), slow.clone());
            tasks.spawn(async move {
                let t = Instant::now();
                let r = sign(
                    m.node(leader),
                    &views[leader as usize - 1],
                    KEY,
                    &msg(&format!("t14-{leader}-{i}")),
                )
                .await;
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
    assert!(
        slow.load(Ordering::SeqCst) > 0,
        "the members were saturated (some signature waited a deadline)"
    );
    assert!(ok > 0);
    settle(3.0).await;
    assert_eq!(m.transitions(), 0, "no breaker opened");
    assert!(m.all_up());

    let cap = max_sign_attempts(N as usize, T as usize);
    // Unique round-1 sessions per signature: at each attempt's first member (= attempts), and at
    // each member.
    let mut attempts: HashMap<Vec<u8>, HashSet<String>> = HashMap::new();
    let mut opened: HashMap<(Vec<u8>, u16), HashSet<String>> = HashMap::new();
    for r in round1s.lock().unwrap().iter() {
        if r.first {
            attempts
                .entry(r.message.clone())
                .or_default()
                .insert(r.session.clone());
        }
        opened
            .entry((r.message.clone(), r.member))
            .or_default()
            .insert(r.session.clone());
    }
    assert_eq!(attempts.len(), N as usize * per_leader, "every signature counted");
    assert!(
        attempts.values().all(|a| (1..=cap).contains(&a.len())),
        "attempts per signature: {attempts:?}"
    );
    assert!(
        opened.values().all(|s| s.len() <= cap),
        "round-1 sessions per member and signature: {opened:?}"
    );
    let max_shares = SigningPolicyConfig::default().max_shares_per_request as usize;
    for id in 1..=N {
        let mut shares: HashMap<String, usize> = HashMap::new();
        for e in m.journal(id) {
            *shares.entry(e.digest).or_default() += 1;
        }
        assert!(
            shares.values().all(|&n| n <= cap && n <= max_shares),
            "node {id}: shares per signature {shares:?}"
        );
    }
    for id in 1..=N {
        m.control(id).clear();
    }
}

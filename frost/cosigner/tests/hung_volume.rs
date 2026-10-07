// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! A *hung* data volume — a dead NFS/CSI mount, a snapshot hook's fsfreeze — must cost a parked
//! thread, not the node. A filesystem call on such a volume does not fail, it never returns; file
//! permissions cannot simulate that, so these tests park key-store calls through the store's
//! fault-injection seam ([`IoHook`]).
//!
//! The shipped CPU limit (500m) gives the cgroup-aware tokio runtime exactly one worker, so the
//! cluster test runs on exactly one: a single store call parked on it would freeze Health and every
//! peer RPC together.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use frost_ed25519::Identifier;
use rutli_cosigner::health::{spawn_monitor, PROBE_TIMEOUT};
use rutli_cosigner::keystore::{IoHook, KeyStore};
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, sign, Peers};
use rutli_cosigner::pb::peer_server::Peer;
use rutli_cosigner::pb::signer_server::Signer;
use rutli_cosigner::pb::{GroupKeyRequest, HealthRequest, SignRequest, SignRound1Request};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use tonic::Request;

/// Parks every key-store access to a path it was told to hang on, until released — a volume that
/// stopped answering.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    hang: Vec<PathBuf>,
    released: bool,
    parked: usize,
}

impl Gate {
    fn hang_on(&self, path: impl Into<PathBuf>) {
        self.state.lock().unwrap().hang.push(path.into());
    }

    fn hook(self: &Arc<Self>) -> IoHook {
        let gate = self.clone();
        Arc::new(move |path: &Path| gate.pass(path))
    }

    fn pass(&self, path: &Path) {
        let mut s = self.state.lock().unwrap();
        if s.released || !s.hang.iter().any(|h| h == path) {
            return;
        }
        s.parked += 1;
        self.changed.notify_all();
        while !s.released {
            s = self.changed.wait(s).unwrap();
        }
        s.parked -= 1;
    }

    fn parked_within(&self, n: usize, within: Duration) -> bool {
        let s = self.state.lock().unwrap();
        let (s, _) = self.changed.wait_timeout_while(s, within, |s| s.parked < n).unwrap();
        s.parked >= n
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
}

/// Un-hangs the volume however the test ends: a thread still parked would keep the runtime from
/// shutting down, turning a failed assertion into a hung test run.
struct ReleaseOnDrop(Arc<Gate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Run `fut` on the runtime's worker and wait for it from this (non-runtime) thread, so a wedged
/// worker fails the test instead of hanging it.
fn answers_within<T: Send + 'static>(
    rt: &tokio::runtime::Runtime,
    within: Duration,
    fut: impl Future<Output = T> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    rt.spawn(async move {
        let _ = tx.send(fut.await);
    });
    rx.recv_timeout(within).ok()
}

fn canton_digest() -> Vec<u8> {
    let mut m = vec![0x12u8, 0x20];
    m.extend([9u8; 32]);
    m
}

fn signer_svc(node: &Arc<Node>, peers: &Peers) -> Arc<SignerSvc> {
    Arc::new(SignerSvc {
        node: node.clone(),
        peers: peers.clone(),
        allowed_cns: None,
        hosted_write_quorum: 1,
        decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
    })
}

#[test]
fn a_store_call_parked_on_a_hung_volume_does_not_freeze_health_or_other_keys() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1) // what a 500m CPU limit gives the cgroup-aware runtime
        .enable_all()
        .build()
        .unwrap();
    let gate = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(gate.clone()); // after `rt`, so it runs before the runtime drops

    let tmp = tempfile::tempdir().unwrap();
    let keys1 = tmp.path().join("node-1");
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let mut ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
            if i != 1 {
                return Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks));
            }
            ks = ks.with_io_hook(gate.hook());
            // Probe on every Health call, and skip the unresponsive grace so this test does not
            // wait it out (the grace has its own unit test in health.rs).
            Arc::new(
                Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks)
                    .with_keystore_probe_freshness(Duration::ZERO)
                    .with_keystore_unresponsive_after(Duration::ZERO),
            )
        })
        .collect();
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    let group_a = rt.block_on(run_dkg(&peers, "a")).unwrap();
    rt.block_on(run_dkg(&peers, "b")).unwrap();

    let signer1 = signer_svc(&nodes[0], &peers);
    let peer1 = Arc::new(PeerSvc { node: nodes[0].clone(), allowed_cns: None });
    let health = |svc: &Arc<SignerSvc>| {
        let svc = svc.clone();
        async move { Signer::health(&*svc, Request::new(HealthRequest {})).await.unwrap().into_inner() }
    };
    let round1_b = |svc: &Arc<PeerSvc>, session: &'static str| {
        let svc = svc.clone();
        async move {
            Peer::sign_round1(
                &*svc,
                Request::new(SignRound1Request { key_id: "b".into(), session_id: session.into() }),
            )
            .await
        }
    };
    let answer = PROBE_TIMEOUT + Duration::from_secs(2);

    // 1. Key "a"'s share file stops answering. A GroupKey for "a" (share not cached since the DKG
    //    wrote it) reads it and parks.
    gate.hang_on(keys1.join("a.json"));
    let parked = {
        let svc = signer1.clone();
        rt.spawn(async move {
            Signer::group_key(&*svc, Request::new(GroupKeyRequest { key_id: "a".into() })).await
        })
    };
    assert!(gate.parked_within(1, Duration::from_secs(5)), "the GroupKey read must reach the store");

    // The single worker is still free: Health answers (the probe itself is fine), a peer sign
    // round on another key answers, and the node still LEADS a whole signature on that key.
    let h = answers_within(&rt, answer, health(&signer1)).expect("Health must answer");
    assert!(h.ok, "nothing is wrong with the store as a whole yet: {}", h.detail);
    let r1 = answers_within(&rt, answer, round1_b(&peer1, "s-1")).expect("SignRound1 must answer");
    assert!(r1.is_ok(), "a sign round on another key must succeed: {r1:?}");
    let led = answers_within(&rt, answer, {
        let svc = signer1.clone();
        async move {
            Signer::sign(&*svc, Request::new(SignRequest { key_id: "b".into(), message: canton_digest() }))
                .await
        }
    })
    .expect("Sign must answer");
    assert_eq!(led.expect("node 1 leads a signature on b").into_inner().signature.len(), 64);

    // 2. Now the whole volume hangs: the readiness probe parks too. Health still answers within the
    //    probe timeout — NOT_SERVING, unresponsive — and the node turns sign rounds away at once,
    //    before touching the store, so healthy leaders sign around it.
    gate.hang_on(&keys1);
    let started = Instant::now();
    let h = answers_within(&rt, answer, health(&signer1)).expect("Health must answer");
    assert!(started.elapsed() < answer, "Health took {:?}", started.elapsed());
    assert!(!h.ok, "a hung store must not report healthy");
    assert!(h.detail.contains("unresponsive"), "{}", h.detail);
    let refused = answers_within(&rt, Duration::from_secs(2), round1_b(&peer1, "s-2"))
        .expect("a refusal must be immediate, not another parked call");
    assert_eq!(refused.expect_err("refused while down").code(), tonic::Code::Unavailable);
    let around = answers_within(&rt, answer, {
        let (leader, peers) = (nodes[1].clone(), peers.clone());
        async move { sign(&leader, &peers, "b", &canton_digest()).await }
    })
    .expect("node 2's Sign must answer");
    assert!(around.is_ok(), "node 2 must sign around the hung node: {around:?}");

    // 3. The volume comes back: the parked read completes with the right answer, the hung probe's
    //    real result replaces "unresponsive", and the node serves again.
    gate.release();
    let got = rt
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), parked).await })
        .expect("the parked GroupKey completes once the volume answers")
        .unwrap()
        .expect("GroupKey for a");
    assert_eq!(got.into_inner().group_verifying_key, group_a.to_vec());
    let deadline = Instant::now() + Duration::from_secs(5);
    while nodes[0].keystore_health().is_down() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let h = answers_within(&rt, answer, health(&signer1)).expect("Health must answer");
    assert!(h.ok, "must recover on its own: {}", h.detail);
}

/// The readiness monitor is a plain thread: it flips a hung store to "down" — and back — with no
/// async runtime in the process at all, as when the runtime's only worker is the thing stuck.
#[test]
fn the_watchdog_flips_the_verdict_on_a_hung_store_without_any_async_runtime() {
    let gate = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(gate.clone());
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("keys");
    gate.hang_on(&dir);
    let ks = KeyStore::open(&dir).unwrap().with_io_hook(gate.hook());
    let node = Arc::new(
        Node::new(Identifier::try_from(1u16).unwrap(), 1, 1, ks)
            .with_keystore_unresponsive_after(Duration::ZERO),
    );
    let _watchdog = spawn_monitor(node.clone(), Duration::from_millis(20));

    assert!(gate.parked_within(1, Duration::from_secs(5)), "the watchdog's probe reaches the store");
    let deadline = Instant::now() + PROBE_TIMEOUT + Duration::from_secs(3);
    while !node.keystore_health().is_down() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(node.keystore_health().is_down(), "a hung probe must turn the node away from work");
    assert!(node.refuse_if_keystore_down().is_err());

    gate.release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while node.keystore_health().is_down() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!node.keystore_health().is_down(), "the probe's real result must clear the verdict");
}

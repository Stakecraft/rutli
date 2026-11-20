// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! A member of a signature cannot make the leader exclude an honest node, over in-process clusters
//! (LocalPeer): each member gets its own session id, so the one it learns names no other member's
//! session, and a session belongs to the caller that opened it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;

use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{Node, Round1Ctx};
use rutli_cosigner::orchestrator::{run_dkg, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::{DaemonError, Result};
use rutli_frost_core::CoreError;

const KEY: &str = "frost-owned-sessions";

/// A 3-of-5 in-process cluster, key `KEY` generated. Returns the nodes and node 1's view of the
/// cluster as the daemon builds it: itself in process, every other node as `cosigner1` calls it.
async fn cluster(dir: &std::path::Path) -> (Vec<Arc<Node>>, [u8; 32]) {
    cluster_of(dir, 5, 3).await
}

/// An in-process `t`-of-`n` cluster, key `KEY` generated.
async fn cluster_of(dir: &std::path::Path, n: u16, t: u16) -> (Vec<Arc<Node>>, [u8; 32]) {
    let nodes: Vec<Arc<Node>> = (1..=n)
        .map(|i| {
            let ks = KeyStore::open(dir.join(format!("node-{i}"))).unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), n, t, ks))
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    let group = run_dkg(&peers, KEY).await.unwrap();
    (nodes, group)
}

/// Node `of` as node `by` reaches it over the mesh (asks as `cosigner<by>`).
fn as_seen_by(nodes: &[Arc<Node>], of: usize, by: usize) -> LocalPeer {
    LocalPeer::new(nodes[of].clone()).on_behalf_of(nodes[by].clone())
}

/// (node, call, what it answered) for every call an [`Intruder`] made.
type Answers = Arc<Mutex<Vec<(u16, &'static str, String)>>>;

/// The ids a member can make from the session id it was given: that id and a few near it.
fn derived(own: &str) -> Vec<String> {
    let mut flipped = own.to_string();
    let last = flipped.pop().unwrap();
    flipped.push(if last == '0' { '1' } else { '0' });
    vec![own.to_string(), flipped, own.replace("sign-", "signtest-"), own.to_uppercase()]
}

/// A compromised member. At its round 1 it learns its own session id and at once, on every other
/// member, tries that id and the ids it can derive from it: a round 2, an abort, and then a round 1
/// of its own under each (to sit on the id before the leader gets there). What they answered is
/// kept. With `refuse_round2` it fails its own round 2, so the leader gives the attempt up and
/// aborts it everywhere.
struct Intruder {
    inner: LocalPeer,
    /// The other members, as the intruder reaches them.
    targets: Vec<(u16, LocalPeer)>,
    answers: Answers,
    round2s: AtomicUsize,
    refuse_round2: AtomicBool,
    /// The session ids it was given.
    own: Mutex<Vec<String>>,
}

#[async_trait]
impl PeerApi for Intruder {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        let mine = self.inner.sign_round1(key_id, session_id, ctx).await?;
        self.own.lock().unwrap().push(session_id.to_string());
        let forged = BTreeMap::from([(self.identifier(), mine)]);
        let msg = ctx.message.clone().unwrap_or_default();
        for (id, target) in &self.targets {
            for guess in derived(session_id) {
                let r2 = target.sign_round2(key_id, &guess, &msg, &forged, None).await;
                let abort = target.abort_sign(key_id, &guess).await;
                let squat = target.sign_round1(key_id, &guess, ctx).await;
                let mut answers = self.answers.lock().unwrap();
                answers.push((*id, "round2", r2.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "signed".into())));
                answers.push((*id, "abort", abort.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "ok".into())));
                answers.push((*id, "round1", squat.err().map(|e| format!("{e:?}")).unwrap_or_else(|| "opened".into())));
            }
        }
        Ok(mine)
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.round2s.fetch_add(1, Ordering::SeqCst);
        if self.refuse_round2.load(Ordering::SeqCst) {
            return Err(DaemonError::Status(tonic::Status::unavailable("transport error")));
        }
        self.inner.sign_round2(key_id, session_id, message, commitments, intent_digest).await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.inner.abort_sign(key_id, session_id).await
    }
    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.inner.ceremony_fence(ceremony_id, key_id, kind).await
    }
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        self.inner.ceremony_release(ceremony_id, key_id).await
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(
        &self,
        ceremony_id: &str,
        key_id: &str,
        spec: &str,
        public_key_der: &[u8],
        wrapped: &rutli_cosigner::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
        self.inner.replicate_key(ceremony_id, key_id, spec, public_key_der, wrapped).await
    }
    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(key_id).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        self.inner.purge_key(ceremony_id, key_id).await
    }
}

/// Node 1 leads; node 2 is the intruder, inside the first subset {1, 2, 3}. Its round 1 comes after
/// node 1's own share opened and before node 3's, so it can try both: what is already open on node
/// 1, and sitting on an id on node 3 before the leader gets there. Every id it can make from its
/// own names nothing of the leader's: round 2s find no session, aborts drop nothing, its round 1s
/// open sessions nobody else uses. The first attempt signs, and nobody honest is excluded.
#[tokio::test]
async fn a_member_that_tries_the_ids_it_can_derive_on_other_nodes_gains_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, group) = cluster(tmp.path()).await;
    let answers = Arc::new(Mutex::new(Vec::new()));
    let intruder = Arc::new(Intruder {
        inner: as_seen_by(&nodes, 1, 0),
        targets: vec![(1, as_seen_by(&nodes, 0, 1)), (3, as_seen_by(&nodes, 2, 1))],
        answers: answers.clone(),
        round2s: AtomicUsize::new(0),
        refuse_round2: AtomicBool::new(false),
        own: Default::default(),
    });
    let log: Log = Default::default();
    let honest = |p: LocalPeer| Arc::new(Scripted::new(p, Mode::Normal, &log)) as Arc<dyn PeerApi>;
    let peers: Peers = vec![
        honest(LocalPeer::new(nodes[0].clone())),
        intruder.clone(),
        honest(as_seen_by(&nodes, 2, 0)),
        honest(as_seen_by(&nodes, 3, 0)),
        honest(as_seen_by(&nodes, 4, 0)),
    ];

    let msg = rutli_frost_core::dealer::canton_test_message(b"through an intruder");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.expect("the honest members sign");
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
    assert_eq!(intruder.round2s.load(Ordering::SeqCst), 1, "one attempt: nobody was excluded");

    let answers = answers.lock().unwrap().clone();
    let guesses = derived("sign-x").len();
    assert_eq!(answers.len(), 2 * guesses * 3, "{answers:?}");
    for (node, call, answer) in &answers {
        let expected = match *call {
            "round2" => answer.contains("UnknownSession"),
            "abort" => answer == "ok",
            _ => answer == "opened",
        };
        assert!(expected, "node {node} {call}: {answer}");
    }
    // The ids of the attempt: one per member, all distinct, none of them one it could make.
    let own = intruder.own.lock().unwrap().clone();
    assert_eq!(own.len(), 1);
    let honest_ids: Vec<(u16, String)> =
        log.lock().unwrap().iter().filter(|(_, c, _)| *c == "round1").map(|(n, _, s)| (*n, s.clone())).collect();
    assert_eq!(honest_ids.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1, 3]);
    let mut all: Vec<&String> = honest_ids.iter().map(|(_, s)| s).chain(&own).collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 3, "one distinct id per member: {honest_ids:?} {own:?}");
    let guessed = derived(&own[0]);
    // The leader's sessions on nodes 1 and 3 lived through every try and signed: each burned its
    // own id there. The intruder's sessions sit under its guesses only, until the TTL.
    for (n, id) in &honest_ids {
        assert!(!guessed.contains(id), "node {n}: {id} was guessable");
        assert!(marker_exists(tmp.path(), *n, id), "node {n} signed under its own id");
        for g in &guessed {
            assert!(!marker_exists(tmp.path(), *n, g), "node {n} burned nothing under {g}");
        }
    }
    for (i, n) in nodes.iter().enumerate() {
        let squats = if i == 0 || i == 2 { guesses } else { 0 };
        assert_eq!(n.pending_sign_count(KEY), squats, "node {}", i + 1);
    }
}

/// The owner binding behind the ids: a member handed another member's id (as if it could learn
/// one) still cannot abort or advance that session, on the leader's own share or on a peer, with a
/// round 2 that would otherwise sign. The owners then sign.
#[tokio::test]
async fn a_member_that_knows_another_members_session_id_still_cannot_use_it() {
    use rutli_cosigner::node::SessionOwner;
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, group) = cluster_of(tmp.path(), 3, 2).await;
    let msg = rutli_frost_core::dealer::canton_test_message(b"known id");
    let ctx = Round1Ctx { message: Some(msg.to_vec()), signers: Some(vec![1, 2]), ..Default::default() };
    let leader = SessionOwner::Peer("cosigner1".into());
    let cs = BTreeMap::from([
        (nodes[0].identifier, nodes[0].sign_round1(KEY, "leaders-own", &ctx).unwrap()),
        (nodes[1].identifier, nodes[1].sign_round1_as(KEY, "for-cosigner1", &ctx, &leader).unwrap()),
    ]);
    for (node, session, owner) in [(0usize, "leaders-own", "this node's own leader"), (1, "for-cosigner1", "peer 'cosigner1'")] {
        let by3 = as_seen_by(&nodes, node, 2);
        for err in [
            by3.abort_sign(KEY, session).await.unwrap_err(),
            by3.sign_round2(KEY, session, &msg, &cs, None).await.unwrap_err(),
        ] {
            let text = format!("{err:?}");
            assert!(matches!(err, DaemonError::Core(CoreError::NotSessionOwner { .. })), "{text}");
            assert!(text.contains(owner) && text.contains("cosigner3"), "{text}");
        }
        assert_eq!(nodes[node].pending_sign_count(KEY), 1);
    }
    let shares = BTreeMap::from([
        (nodes[0].identifier, nodes[0].sign_round2(KEY, "leaders-own", &msg, &cs).unwrap()),
        (nodes[1].identifier, nodes[1].sign_round2_as(KEY, "for-cosigner1", &msg, &cs, None, &leader).unwrap()),
    ]);
    let sig = nodes[0].aggregate(KEY, &msg, &cs, &shares).unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

/// The opener still aborts its own sessions: when node 2 fails its round 2, node 3 still holds
/// live nonces for the attempt; the leader aborts it there as `cosigner1`, the nonces go, and the
/// next subset without node 2 signs.
#[tokio::test]
async fn the_leader_still_aborts_its_own_sessions_and_retries_without_the_failing_member() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, group) = cluster(tmp.path()).await;
    let intruder = Arc::new(Intruder {
        inner: as_seen_by(&nodes, 1, 0),
        targets: Vec::new(),
        answers: Default::default(),
        round2s: AtomicUsize::new(0),
        refuse_round2: AtomicBool::new(true),
        own: Default::default(),
    });
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())),
        intruder.clone(),
        Arc::new(as_seen_by(&nodes, 2, 0)),
        Arc::new(as_seen_by(&nodes, 3, 0)),
        Arc::new(as_seen_by(&nodes, 4, 0)),
    ];
    let msg = rutli_frost_core::dealer::canton_test_message(b"retry without the failing member");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.expect("the next subset signs");
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
    assert_eq!(intruder.round2s.load(Ordering::SeqCst), 1);
    for n in &nodes {
        assert_eq!(n.pending_sign_count(KEY), 0, "node {:?}: the aborted attempt left nothing", n.identifier);
    }
}

/// On a plaintext mesh no caller is identified: remote callers are one owner, as before sessions
/// had owners, but none of them is this node's own leader.
#[tokio::test]
async fn unidentified_callers_share_their_sessions_but_never_the_leaders_own() {
    use rutli_cosigner::node::SessionOwner;
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = cluster(tmp.path()).await;
    let n = &nodes[1];
    let ctx = Round1Ctx::default();
    n.sign_round1_as(KEY, "plain", &ctx, &SessionOwner::Unidentified).unwrap();
    n.abort_sign_as(KEY, "plain", &SessionOwner::Unidentified).unwrap();
    assert_eq!(n.pending_sign_count(KEY), 0);

    n.sign_round1(KEY, "own", &ctx).unwrap();
    let err = n.abort_sign_as(KEY, "own", &SessionOwner::Unidentified).unwrap_err();
    assert!(matches!(err, DaemonError::Core(CoreError::NotSessionOwner { .. })), "{err:?}");
    assert_eq!(n.pending_sign_count(KEY), 1);
}

fn marker_exists(dir: &std::path::Path, node: u16, session: &str) -> bool {
    dir.join(format!("node-{node}/{KEY}.nonces/{session}.used")).exists()
}

/// (node, call, session id) for every call a [`Scripted`] peer forwarded.
type Log = Arc<Mutex<Vec<(u16, &'static str, String)>>>;

enum Mode {
    Normal,
    /// Round 1 never answers.
    Down,
    /// Opens the session, then answers round 1 with an error (a reply lost or timed out).
    OpenThenFail,
    /// Opens the session, then never answers round 1.
    OpenThenHang,
    /// Forwards round 1; after the first one, frees these sessions of `owner` on its node.
    FreeAfterFirst(Arc<Node>, rutli_cosigner::node::SessionOwner, Vec<String>),
}

/// A peer that forwards to a real one, logs what it forwarded, and misbehaves in round 1 as told.
struct Scripted {
    inner: LocalPeer,
    mode: Mode,
    log: Log,
    round1s: AtomicUsize,
}

impl Scripted {
    fn new(inner: LocalPeer, mode: Mode, log: &Log) -> Self {
        Self { inner, mode, log: log.clone(), round1s: AtomicUsize::new(0) }
    }
    fn note(&self, call: &'static str, session: &str) {
        let id = rutli_cosigner::hosted::identifier_index(self.inner.identifier()).unwrap();
        self.log.lock().unwrap().push((id, call, session.to_string()));
    }
}

fn unavailable() -> DaemonError {
    DaemonError::Status(tonic::Status::unavailable("transport error"))
}

#[async_trait]
impl PeerApi for Scripted {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        let first = self.round1s.fetch_add(1, Ordering::SeqCst) == 0;
        match &self.mode {
            Mode::Down => return Err(unavailable()),
            Mode::OpenThenFail => {
                self.inner.sign_round1(key_id, session_id, ctx).await?;
                return Err(unavailable());
            }
            Mode::OpenThenHang => {
                self.inner.sign_round1(key_id, session_id, ctx).await?;
                std::future::pending::<()>().await;
            }
            _ => {}
        }
        let r = self.inner.sign_round1(key_id, session_id, ctx).await;
        if let (Mode::FreeAfterFirst(node, owner, fillers), true) = (&self.mode, first) {
            for f in fillers {
                node.abort_sign_as(key_id, f, owner).unwrap();
            }
        }
        if r.is_ok() {
            self.note("round1", session_id);
        }
        r
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.note("round2", session_id);
        self.inner.sign_round2(key_id, session_id, message, commitments, intent_digest).await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.note("abort", session_id);
        self.inner.abort_sign(key_id, session_id).await
    }
    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.inner.ceremony_fence(ceremony_id, key_id, kind).await
    }
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        self.inner.ceremony_release(ceremony_id, key_id).await
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(
        &self,
        ceremony_id: &str,
        key_id: &str,
        spec: &str,
        public_key_der: &[u8],
        wrapped: &rutli_cosigner::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
        self.inner.replicate_key(ceremony_id, key_id, spec, public_key_der, wrapped).await
    }
    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(key_id).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        self.inner.purge_key(ceremony_id, key_id).await
    }
}

/// A sign whose caller goes away mid-attempt (the driver's deadline; tonic drops the request's
/// future) aborts what the attempt opened: no session stays on any member until the TTL, where it
/// would count against this leader's caps.
#[tokio::test]
async fn a_dropped_attempt_leaves_no_session_on_any_member() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = cluster(tmp.path()).await;
    let log: Log = Default::default();
    let peers: Peers = vec![
        Arc::new(Scripted::new(LocalPeer::new(nodes[0].clone()), Mode::Normal, &log)),
        Arc::new(Scripted::new(as_seen_by(&nodes, 1, 0), Mode::Normal, &log)),
        Arc::new(Scripted::new(as_seen_by(&nodes, 2, 0), Mode::OpenThenHang, &log)),
        Arc::new(as_seen_by(&nodes, 3, 0)),
        Arc::new(as_seen_by(&nodes, 4, 0)),
    ];
    let msg = rutli_frost_core::dealer::canton_test_message(b"caller went away");
    let aborts = || log.lock().unwrap().iter().filter(|(_, c, _)| *c == "abort").count();
    // Waits on a condition, not on a fixed time: a loaded runner can be slow at every step.
    async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !done() {
            assert!(std::time::Instant::now() < until, "timed out waiting for {what}");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    let signing = {
        let (node, peers) = (nodes[0].clone(), peers.clone());
        tokio::spawn(async move { sign(&node, &peers, KEY, &msg).await })
    };
    // The caller goes away only once node 3 has opened its session and hangs, so that every
    // member of the attempt holds a session to abort.
    eventually("node 3 to open its session", || nodes[2].pending_sign_count(KEY) == 1).await;
    assert!(!signing.is_finished(), "the sign is still waiting on node 3");
    signing.abort();
    assert!(signing.await.unwrap_err().is_cancelled());
    // The aborts run as their own task.
    eventually("every member to be aborted", || {
        aborts() >= 3 && nodes.iter().all(|n| n.pending_sign_count(KEY) == 0)
    })
    .await;
    for (i, n) in nodes.iter().enumerate() {
        assert_eq!(n.pending_sign_count(KEY), 0, "node {} holds nothing", i + 1);
    }
    assert_eq!(aborts(), 3, "nodes 1, 2 and the hanging node 3 are each aborted once");
}

/// A member whose round 1 reply never came may still have opened the session: the leader aborts
/// it there too, under that member's id.
#[tokio::test]
async fn a_round1_that_failed_after_opening_is_aborted() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, group) = cluster(tmp.path()).await;
    let log: Log = Default::default();
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())),
        Arc::new(Scripted::new(as_seen_by(&nodes, 1, 0), Mode::OpenThenFail, &log)),
        Arc::new(as_seen_by(&nodes, 2, 0)),
        Arc::new(as_seen_by(&nodes, 3, 0)),
        Arc::new(as_seen_by(&nodes, 4, 0)),
    ];
    let msg = rutli_frost_core::dealer::canton_test_message(b"lost round 1 reply");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.expect("another subset signs");
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
    assert_eq!(nodes[1].pending_sign_count(KEY), 0, "node 2's session was aborted");
    assert_eq!(log.lock().unwrap().iter().filter(|(n, c, _)| *n == 2 && *c == "abort").count(), 1);
}

/// A member with no room left for this leader's sessions is not failing: the leader tries another
/// subset, and comes back to it once the other subsets are used up, without excluding it. Here
/// node 3 is down, so the sign needs node 2, whose room frees after its first refusal.
#[tokio::test]
async fn a_member_at_its_cap_for_this_leader_is_not_excluded() {
    use rutli_cosigner::node::{SessionOwner, MAX_PENDING_SIGN_SESSIONS_PER_OPENER};
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, group) = cluster_of(tmp.path(), 3, 2).await;
    let leader = SessionOwner::Peer("cosigner1".into());
    let fillers: Vec<String> = (0..MAX_PENDING_SIGN_SESSIONS_PER_OPENER).map(|i| format!("fill-{i}")).collect();
    for f in &fillers {
        nodes[1].sign_round1_as(KEY, f, &Round1Ctx::default(), &leader).unwrap();
    }
    let log: Log = Default::default();
    let node2 = Arc::new(Scripted::new(
        as_seen_by(&nodes, 1, 0),
        Mode::FreeAfterFirst(nodes[1].clone(), leader.clone(), fillers),
        &log,
    ));
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())),
        node2.clone(),
        Arc::new(Scripted::new(as_seen_by(&nodes, 2, 0), Mode::Down, &log)),
    ];
    let msg = rutli_frost_core::dealer::canton_test_message(b"full, then room");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.expect("node 2 is asked again and signs");
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
    assert_eq!(node2.round1s.load(Ordering::SeqCst), 2, "refused once for room, then asked again");
    for n in &nodes {
        assert_eq!(n.pending_sign_count(KEY), 0);
    }

    // Full for good: the answer is UNAVAILABLE (another leader has its own room), not a refusal
    // naming node 2.
    let fillers: Vec<String> = (0..MAX_PENDING_SIGN_SESSIONS_PER_OPENER).map(|i| format!("full-{i}")).collect();
    for f in &fillers {
        nodes[1].sign_round1_as(KEY, f, &Round1Ctx::default(), &leader).unwrap();
    }
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())),
        Arc::new(as_seen_by(&nodes, 1, 0)),
        Arc::new(Scripted::new(as_seen_by(&nodes, 2, 0), Mode::Down, &log)),
    ];
    let err = sign(&nodes[0], &peers, KEY, &msg).await.unwrap_err();
    assert!(matches!(err, DaemonError::NotServing(ref m) if m.contains("no room")), "{err:?}");
    assert_eq!(tonic::Status::from(err).code(), tonic::Code::Unavailable);
}

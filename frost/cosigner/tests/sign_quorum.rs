// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Sign-time epoch checks, stale-share detection and t-subset retry (audit H1, M1), over in-process
//! clusters (LocalPeer).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;

use rutli_cosigner::epoch_check::{self, Verdict};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{Node, Round1Ctx};
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::{DaemonError, Result};

const KEY: &str = "namespace-participant1";

/// An in-process cluster over `dir/node-<i>`; reopening the same directories models a restart.
fn cluster(dir: &Path, n: u16, t: u16) -> (Vec<Arc<Node>>, Peers) {
    let nodes: Vec<Arc<Node>> = (1..=n)
        .map(|i| {
            let ks = KeyStore::open(dir.join(format!("node-{i}"))).unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), n, t, ks))
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    (nodes, peers)
}

fn digest(tag: &[u8]) -> Vec<u8> {
    rutli_frost_core::dealer::canton_test_message(tag).to_vec()
}

fn verifies(group: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    rutli_cosigner::verify_key::signature_verifies(group, msg, sig)
}

fn share_file(dir: &Path, i: usize) -> std::path::PathBuf {
    dir.join(format!("node-{i}")).join(format!("{KEY}.json"))
}

fn view_of(n: &Node) -> (u64, [u8; 32]) {
    let v = n.key_epoch(KEY).unwrap();
    (v.epoch, v.pkp_digest.try_into().unwrap())
}

// ── round 1 refuses another sharing ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_peer_refuses_round1_from_a_leader_on_another_epoch_and_mints_no_nonce() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(tmp.path(), 3, 2);
    run_dkg(&peers, KEY).await.unwrap();
    let mine = view_of(&nodes[1]);
    assert_eq!(mine.0, 1);

    for leader in [(2, mine.1), (mine.0, [0xAB; 32])] {
        let ctx = Round1Ctx { leader_view: Some(leader), ..Default::default() };
        let err = nodes[1].sign_round1(KEY, "s-mismatch", &ctx).unwrap_err();
        match err {
            DaemonError::EpochMismatch { peer, leader: l, .. } => assert_eq!((peer, l), (mine, leader)),
            other => panic!("expected EpochMismatch, got {other:?}"),
        }
        // Over gRPC this is FAILED_PRECONDITION carrying the peer's own sharing.
        let status = tonic::Status::from(nodes[1].sign_round1(KEY, "s-mismatch", &ctx).unwrap_err());
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.metadata().get("rutli-error").unwrap(), "epoch-mismatch");
    }
    assert_eq!(nodes[1].pending_sign_count(KEY), 0, "a refused round 1 holds no nonces");

    // The matching sharing is accepted; so is a leader that names none (an older release).
    let ok = Round1Ctx { leader_view: Some(mine), ..Default::default() };
    nodes[1].sign_round1(KEY, "s-ok", &ok).unwrap();
    nodes[1].sign_round1(KEY, "s-legacy", &Round1Ctx::default()).unwrap();
    assert_eq!(nodes[1].pending_sign_count(KEY), 2);
}

#[tokio::test]
async fn require_epoch_match_refuses_a_leader_that_names_no_sharing() {
    let tmp = tempfile::tempdir().unwrap();
    let (_nodes, peers) = cluster(tmp.path(), 3, 2);
    run_dkg(&peers, KEY).await.unwrap();
    let ks = KeyStore::open(tmp.path().join("node-2")).unwrap();
    let strict = Node::new(Identifier::try_from(2).unwrap(), 3, 2, ks).with_require_epoch_match(true);
    let err = strict.sign_round1(KEY, "s", &Round1Ctx::default()).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(ref m) if m.contains("require_epoch_match")), "{err:?}");
    assert_eq!(strict.pending_sign_count(KEY), 0);
}

// ── stale shares (restore from an old backup) ─────────────────────────────────────────────────

/// DKG, back up node 2's share, refresh, then put the backup back (as a restore from an old backup
/// would) and restart every node. `wipe_records`: the restore also took node 2's ceremony records
/// (a whole-volume snapshot), so only its peers can tell it is behind.
async fn restored_from_old_backup(dir: &Path, wipe_records: bool) -> (Vec<Arc<Node>>, Peers, [u8; 32]) {
    let (nodes, peers) = cluster(dir, 3, 2);
    let group = run_dkg(&peers, KEY).await.unwrap();
    let backup = std::fs::read(share_file(dir, 2)).unwrap();
    run_refresh(&peers, KEY).await.unwrap();
    drop((nodes, peers));
    std::fs::write(share_file(dir, 2), backup).unwrap();
    if wipe_records {
        std::fs::remove_dir_all(dir.join("node-2/.ceremonies")).unwrap();
    }
    let (nodes, peers) = cluster(dir, 3, 2);
    assert_eq!(nodes[1].key_epoch(KEY).unwrap().epoch, 1);
    assert_eq!(nodes[0].key_epoch(KEY).unwrap().epoch, 2);
    (nodes, peers, group)
}

#[tokio::test]
async fn a_node_restored_from_an_old_backup_finds_itself_stale_and_leaders_route_around_it() {
    for wipe_records in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let (nodes, peers, group) = restored_from_old_backup(tmp.path(), wipe_records).await;

        // The startup check marks node 2 stale (its own commit record, or its peers, prove it).
        let verdict = epoch_check::check_key(&nodes[1], KEY).await.unwrap();
        assert!(matches!(verdict, Verdict::Stale(_)), "records wiped {wipe_records}: {verdict:?}");
        assert!(nodes[1].key_epoch(KEY).unwrap().stale);
        assert!(nodes[1].key_status(KEY).unwrap().stale);
        for n in [&nodes[0], &nodes[2]] {
            assert_eq!(epoch_check::check_key(n, KEY).await.unwrap(), Verdict::Current);
        }

        // It refuses every round 1 for the key, whatever the leader names...
        let err = nodes[1].sign_round1(KEY, "s", &Round1Ctx::default()).unwrap_err();
        assert!(matches!(err, DaemonError::StaleShare { .. }), "{err:?}");
        // ...declines to lead (UNAVAILABLE, the driver fails over)...
        let err = sign(&nodes[1], &peers, KEY, &digest(b"stale leader")).await.unwrap_err();
        assert!(matches!(err, DaemonError::NotServing(_)), "{err:?}");
        // ...and the other leaders sign around it, with the current sharing.
        for leader in [0usize, 2] {
            let msg = digest(format!("leader {leader}").as_bytes());
            let sig = sign(&nodes[leader], &peers, KEY, &msg).await.unwrap();
            assert!(verifies(&group, &msg, &sig));
        }
        assert_eq!(nodes[1].pending_sign_count(KEY), 0);
    }
}

#[tokio::test]
async fn without_the_stale_mark_round1_epoch_checks_still_keep_the_old_share_out() {
    let tmp = tempfile::tempdir().unwrap();
    // No epoch check has run yet: only the round-1 comparison protects the quorum.
    let (nodes, peers, group) = restored_from_old_backup(tmp.path(), true).await;

    // A current leader excludes node 2 (epoch mismatch) and signs with the other current node.
    let msg = digest(b"current leader");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&group, &msg, &sig));

    // Node 2 leading on its old sharing hears both peers name a newer one: it fails over rather
    // than try subsets that cannot work.
    let err = sign(&nodes[1], &peers, KEY, &digest(b"old leader")).await.unwrap_err();
    assert!(matches!(err, DaemonError::NotServing(ref m) if m.contains("not leading")), "{err:?}");
    assert_eq!(nodes[1].pending_sign_count(KEY), 0, "its own round-1 nonces were aborted");
}

#[tokio::test]
async fn a_current_cluster_reports_nobody_stale() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(tmp.path(), 3, 2);
    run_dkg(&peers, KEY).await.unwrap();
    // Nobody is behind: every node is current.
    for n in &nodes {
        assert_eq!(epoch_check::check_key(n, KEY).await.unwrap(), Verdict::Current);
        assert!(!n.key_epoch(KEY).unwrap().stale);
    }
    assert_eq!(epoch_check::check_all(&nodes[0]).await, 0, "every key conclusive");
}

// ── t-subset retry ────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Round1,
    Round2,
    BadShare,
    /// Forwards round 2 with another message than the leader declared at round 1.
    SwapMessage,
}

/// (node, call, session id, detail) for every sign call a [`Spy`] saw.
type Log = Arc<Mutex<Vec<(u16, &'static str, String, String)>>>;

/// Wraps a real peer, logs the sign traffic, and injects one fault.
struct Spy {
    inner: LocalPeer,
    fault: Fault,
    log: Log,
}

impl Spy {
    fn note(&self, what: &'static str, session: &str, extra: String) {
        let id = rutli_cosigner::hosted::identifier_index(self.inner.identifier()).unwrap();
        self.log.lock().unwrap().push((id, what, session.to_string(), extra));
    }
}

fn down() -> DaemonError {
    DaemonError::Status(tonic::Status::unavailable("transport error"))
}

#[async_trait]
impl PeerApi for Spy {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        if self.fault == Fault::Round1 {
            return Err(down());
        }
        let c = self.inner.sign_round1(key_id, session_id, ctx).await?;
        self.note("round1", session_id, serde_json::to_string(&c).unwrap());
        Ok(c)
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.note("round2", session_id, String::new());
        match self.fault {
            Fault::Round2 => Err(down()),
            Fault::BadShare => {
                // Burn the real session, then hand back a well-formed but wrong share.
                self.inner.sign_round2(key_id, session_id, message, commitments, intent_digest).await?;
                let mut one = [0u8; 32];
                one[0] = 1;
                Ok(SignatureShare::deserialize(&one).unwrap())
            }
            Fault::SwapMessage => {
                let swapped = digest(b"not what round 1 declared");
                let r = self.inner.sign_round2(key_id, session_id, &swapped, commitments, intent_digest).await;
                if let Err(e) = &r {
                    self.note("refused", session_id, e.to_string());
                }
                r
            }
            _ => self.inner.sign_round2(key_id, session_id, message, commitments, intent_digest).await,
        }
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.note("abort", session_id, String::new());
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

fn spied(nodes: &[Arc<Node>], faults: &[Fault]) -> (Peers, Log) {
    let log: Log = Default::default();
    let peers = nodes
        .iter()
        .zip(faults)
        .map(|(n, &fault)| {
            Arc::new(Spy { inner: LocalPeer::new(n.clone()), fault, log: log.clone() }) as Arc<dyn PeerApi>
        })
        .collect();
    (peers, log)
}

/// Distinct sessions in the order they first appear in the log.
fn sessions(log: &Log) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (_, _, s, _) in log.lock().unwrap().iter() {
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
    out
}

fn marker_exists(dir: &Path, node: usize, session: &str) -> bool {
    dir.join(format!("node-{node}/{KEY}.nonces/{session}.used")).exists()
}

#[tokio::test]
async fn a_peer_failing_round2_is_routed_around_with_a_fresh_session_and_fresh_commitments() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, plain) = cluster(tmp.path(), 3, 2);
    let group = run_dkg(&plain, KEY).await.unwrap();
    let (peers, log) = spied(&nodes, &[Fault::None, Fault::Round2, Fault::None]);

    let msg = digest(b"retry after round 2");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&group, &msg, &sig));

    let s = sessions(&log);
    assert_eq!(s.len(), 2, "one failed attempt, one good one: {s:?}");
    assert_ne!(s[0], s[1], "each attempt is a fresh session");
    let entries = log.lock().unwrap().clone();
    let on = |node: u16, what: &str, session: &str| {
        entries.iter().filter(|(n, w, s, _)| *n == node && *w == what && s == session).collect::<Vec<_>>()
    };
    // Attempt 1 = {1, 2}; attempt 2 = {1, 3}; node 2 is never asked again.
    assert_eq!(on(2, "round1", &s[0]).len(), 1);
    assert!(on(2, "round1", &s[1]).is_empty() && on(3, "round1", &s[0]).is_empty());
    assert_eq!(on(3, "round1", &s[1]).len(), 1);
    // The leader's commitments differ between attempts: never reused across subsets.
    assert_ne!(on(1, "round1", &s[0])[0].3, on(1, "round1", &s[1])[0].3);
    // The failed session: aborted on its members, the leader's nonce burned (it shared in round 2)
    // and node 2 holding nothing; the successful one burned on both of its signers.
    assert_eq!(on(1, "abort", &s[0]).len() + on(2, "abort", &s[0]).len(), 2);
    assert!(marker_exists(tmp.path(), 1, &s[0]) && !marker_exists(tmp.path(), 2, &s[0]));
    assert!(marker_exists(tmp.path(), 1, &s[1]) && marker_exists(tmp.path(), 3, &s[1]));
    for n in &nodes {
        assert_eq!(n.pending_sign_count(KEY), 0);
    }
}

#[tokio::test]
async fn an_invalid_signature_share_is_attributed_and_routed_around() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, plain) = cluster(tmp.path(), 3, 2);
    let group = run_dkg(&plain, KEY).await.unwrap();
    let (peers, log) = spied(&nodes, &[Fault::None, Fault::BadShare, Fault::None]);

    let msg = digest(b"bad share");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&group, &msg, &sig));
    let s = sessions(&log);
    assert_eq!(s.len(), 2, "{s:?}");
    let entries = log.lock().unwrap().clone();
    assert!(
        !entries.iter().any(|(n, w, sess, _)| *n == 2 && *w == "round1" && *sess == s[1]),
        "the culprit is not asked again"
    );

    // With the culprit in every subset there is nothing to route to: the sign fails, never
    // returning a bad signature.
    let pair: Peers = vec![peers[0].clone(), peers[1].clone()];
    let err = sign(&nodes[0], &pair, KEY, &digest(b"no way around")).await.unwrap_err();
    assert!(matches!(err, DaemonError::ThresholdNotMet { needed: 2, got: 1 }), "{err:?}");
}

#[tokio::test]
async fn three_of_five_retries_through_subsets_until_one_works() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, plain) = cluster(tmp.path(), 5, 3);
    let group = run_dkg(&plain, KEY).await.unwrap();
    // Node 2 is down in round 1 and node 3 fails round 2: the leader works through the subsets.
    let (peers, log) = spied(&nodes, &[Fault::None, Fault::Round1, Fault::Round2, Fault::None, Fault::None]);
    let msg = digest(b"three of five");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&group, &msg, &sig));
    let s = sessions(&log);
    // {1,2,3} fails at 2 (round 1), {1,3,4} fails at 3 (round 2), {1,4,5} signs.
    assert_eq!(s.len(), 3, "{s:?}");
    for n in &nodes {
        assert_eq!(n.pending_sign_count(KEY), 0);
    }

    // Three faulty nodes of five leave two: below threshold, after trying what it could.
    let (peers, _log) = spied(&nodes, &[Fault::None, Fault::Round1, Fault::Round2, Fault::BadShare, Fault::None]);
    let err = sign(&nodes[0], &peers, KEY, &digest(b"too few")).await.unwrap_err();
    assert!(matches!(err, DaemonError::ThresholdNotMet { needed: 3, got: 2 }), "{err:?}");
}

// ── session binding through the node ──────────────────────────────────────────────────────────

#[tokio::test]
async fn a_node_refuses_round2_for_another_message_or_commitment_set_than_round1_declared() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(tmp.path(), 3, 2);
    run_dkg(&peers, KEY).await.unwrap();
    let msg = digest(b"declared at round 1");
    let ctx = Round1Ctx {
        leader_view: Some(view_of(&nodes[0])),
        message: Some(msg.clone()),
        signers: Some(vec![1, 2]),
        ..Default::default()
    };
    let open = |session: &str| -> BTreeMap<Identifier, SigningCommitments> {
        [0usize, 1].iter().map(|&i| (nodes[i].identifier, nodes[i].sign_round1(KEY, session, &ctx).unwrap())).collect()
    };

    // Another message.
    let cs = open("b-msg");
    let err = nodes[0].sign_round2(KEY, "b-msg", &digest(b"substituted"), &cs).unwrap_err();
    assert!(matches!(err, DaemonError::Core(rutli_frost_core::CoreError::BindingMismatch { .. })), "{err:?}");
    assert_eq!(tonic::Status::from(err).code(), tonic::Code::FailedPrecondition);
    // Another commitment set (node 3 added).
    let mut cs = open("b-set");
    let c3 = nodes[2].sign_round1(KEY, "b-set", &Round1Ctx::default()).unwrap();
    cs.insert(nodes[2].identifier, c3);
    let err = nodes[0].sign_round2(KEY, "b-set", &msg, &cs).unwrap_err();
    assert!(matches!(err, DaemonError::Core(rutli_frost_core::CoreError::BindingMismatch { .. })), "{err:?}");
    for session in ["b-msg", "b-set"] {
        assert!(!marker_exists(tmp.path(), 1, session), "{session}: refused before the marker burns");
    }

    // A round 1 declaring a signer set without this node is refused outright.
    let not_me = Round1Ctx { signers: Some(vec![2, 3]), ..ctx.clone() };
    assert!(nodes[0].sign_round1(KEY, "b-notme", &not_me).is_err());

    // The declared message under the declared set signs.
    let cs = open("b-ok");
    nodes[0].sign_round2(KEY, "b-ok", &msg, &cs).unwrap();
    assert!(marker_exists(tmp.path(), 1, "b-ok"));
}

#[tokio::test]
async fn a_round2_tampered_in_transit_is_refused_by_the_node_and_routed_around() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, plain) = cluster(tmp.path(), 3, 2);
    let group = run_dkg(&plain, KEY).await.unwrap();
    let (peers, log) = spied(&nodes, &[Fault::None, Fault::SwapMessage, Fault::None]);
    let msg = digest(b"the real message");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&group, &msg, &sig));
    let s = sessions(&log);
    let entries = log.lock().unwrap().clone();
    let refused: Vec<_> = entries.iter().filter(|(n, w, _, _)| *n == 2 && *w == "refused").collect();
    assert_eq!(refused.len(), 1, "{entries:?}");
    assert!(refused[0].3.contains("round-1 binding"), "{}", refused[0].3);
    assert!(!marker_exists(tmp.path(), 2, &s[0]), "node 2 never burned (nor signed) the tampered session");
}

// ── nonce-marker pruning (audit L4) ───────────────────────────────────────────────────────────

#[tokio::test]
async fn marker_pruning_removes_old_markers_keeps_young_ones_and_the_node_still_signs() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(tmp.path(), 3, 2);
    let group = run_dkg(&peers, KEY).await.unwrap();
    for i in 0..4 {
        sign(&nodes[0], &peers, KEY, &digest(format!("m{i}").as_bytes())).await.unwrap();
    }
    let dir = tmp.path().join(format!("node-1/{KEY}.nonces"));
    let markers = || -> Vec<std::path::PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "used"))
            .collect();
        v.sort();
        v
    };
    let all = markers();
    assert_eq!(all.len(), 4, "the leader burned one marker per signature");
    // Age three of them past the retention.
    let retention = rutli_frost_core::session::MARKER_RETENTION;
    for p in &all[..3] {
        let f = std::fs::File::options().write(true).open(p).unwrap();
        f.set_modified(std::time::SystemTime::now() - retention - std::time::Duration::from_secs(60)).unwrap();
    }

    let r = nodes[0].prune_nonce_markers(retention, 10_000).unwrap();
    assert_eq!((r.removed, r.kept, r.truncated), (3, 1, false));
    assert_eq!(markers(), vec![all[3].clone()], "the young marker stays");
    // The store still says the key signed here: discard-partial-key keeps refusing it.
    assert!(dir.join(rutli_frost_core::nonce_store::PRUNED_SENTINEL).exists());
    assert!(nodes[0].discard_local_key(KEY).is_err());
    // Budgeted passes, and signing is unaffected.
    for p in markers() {
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(std::time::SystemTime::now() - retention - std::time::Duration::from_secs(60)).unwrap();
    }
    sign(&nodes[0], &peers, KEY, &digest(b"after pruning")).await.unwrap();
    let r = nodes[0].prune_nonce_markers(retention, 0).unwrap();
    assert!(r.truncated && r.removed == 0);
    let msg = digest(b"still signs");
    let sig = sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    assert!(verifies(&group, &msg, &sig));
}

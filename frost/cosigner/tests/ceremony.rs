// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Two-phase DKG/refresh under faults (audit H1, M5): a failure or crash at any point of a
//! ceremony never leaves nodes on mixed epochs, and every node's own resolver converges without
//! the leader.
//!
//! The rig wraps every handle — the leader's peers and each node's mesh — in [`Faulty`], driven by
//! one set of switches per node, so "node 3 is down" holds for the leader and for every resolver
//! asking node 3 alike.

// The daemon's error type is large by value (see the crate root); the test wrappers return it too.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use frost_ed25519::keys::dkg::{round1, round2};
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;
use rutli_cosigner::ceremony::{recover_commit, resolve_assume_lost, resolve_pending, Part2Outcome};
use rutli_cosigner::ceremony_record::{Phase, RecordState, StatusInfo};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{CeremonyKind, Node, StagedOutcome};
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::{pb, DaemonError, Result};

const N: u16 = 3;
const T: u16 = 2;
const KEY: &str = "frost-2pc";

/// Faults for one node, seen by everyone who talks to it.
#[derive(Default)]
struct Switches {
    /// Every call fails as a transport error.
    down: AtomicBool,
    /// Go down right after this node's part 3 succeeds (staged, then lost).
    down_after_part3: AtomicBool,
    /// Part 3 fails before reaching the node.
    fail_part3: AtomicBool,
    /// The leader's commit request to this node is lost.
    drop_commit: AtomicBool,
    /// The leader's commit request to this node is delayed (ms).
    commit_delay_ms: AtomicU64,
    /// Other nodes' resolvers see this node vote for a different outcome.
    diverge: AtomicBool,
    /// This node reports ceremony protocol 0, as a cosigner of an older release would.
    old_protocol: AtomicBool,
    /// Byzantine (audit F3): this node answers ABORTED to the resolvers of the nodes in this
    /// bitmask (bit = 0-based index of the asking node), whatever it really recorded.
    lie_aborted_to: AtomicU64,
}

struct Faulty {
    inner: LocalPeer,
    sw: Arc<Switches>,
    /// 0-based index of the node holding this mesh handle (`usize::MAX` for a leader handle).
    asker: usize,
    /// The leader's handle (commit faults apply) rather than a peer's mesh handle.
    leader: bool,
    /// Leader handles: everything passed to and returned from the node (the leader's whole view).
    /// Mesh handles: every round-2 delivery, as JSON.
    log: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Faulty {
    fn note(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }

    fn gate(&self) -> Result<()> {
        if self.sw.down.load(Ordering::SeqCst) {
            return Err(DaemonError::Status(tonic::Status::unavailable("transport error: node down")));
        }
        Ok(())
    }
}

#[async_trait]
impl PeerApi for Faulty {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &rutli_cosigner::node::Round1Ctx) -> Result<SigningCommitments> {
        self.gate()?;
        self.inner.sign_round1(key_id, session_id, ctx).await
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.gate()?;
        self.inner.sign_round2(key_id, session_id, message, commitments, intent_digest).await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.gate()?;
        self.inner.abort_sign(key_id, session_id).await
    }
    async fn ceremony_fence(&self, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
        self.gate()?;
        self.inner.ceremony_fence(ceremony_id, key_id, kind).await
    }
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> Result<()> {
        self.gate()?;
        self.inner.ceremony_release(ceremony_id, key_id).await
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        self.gate()?;
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
        self.gate()?;
        self.inner.replicate_key(ceremony_id, key_id, spec, public_key_der, wrapped).await
    }
    async fn fetch_key(&self, key_id: &str) -> Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.gate()?;
        self.inner.fetch_key(key_id).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.gate()?;
        self.inner.list_keys().await
    }
    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> Result<bool> {
        self.gate()?;
        self.inner.purge_key(ceremony_id, key_id).await
    }
    async fn key_epoch(&self, key_id: &str) -> Result<pb::KeyEpochReply> {
        self.gate()?;
        self.inner.key_epoch(key_id).await
    }
    async fn ceremony_begin(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
        intent: Option<&pb::SignedIntent>,
    ) -> Result<()> {
        self.gate()?;
        self.inner.ceremony_begin(ceremony_id, key_id, kind, expect, intent).await
    }
    async fn ceremony_commit(&self, ceremony_id: &str) -> Result<StatusInfo> {
        self.gate()?;
        if self.leader {
            let delay = self.sw.commit_delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            if self.sw.drop_commit.load(Ordering::SeqCst) {
                return Err(DaemonError::Status(tonic::Status::unavailable("transport error: commit lost")));
            }
        }
        self.inner.ceremony_commit(ceremony_id).await
    }
    async fn ceremony_status(&self, ceremony_id: &str) -> Result<StatusInfo> {
        self.gate()?;
        if !self.leader && self.sw.lie_aborted_to.load(Ordering::SeqCst) & (1 << self.asker) != 0 {
            return Ok(StatusInfo { phase: Phase::Aborted, outcome: None });
        }
        let mut info = self.inner.ceremony_status(ceremony_id).await?;
        if !self.leader && self.sw.diverge.load(Ordering::SeqCst) {
            if let Some(o) = info.outcome.as_mut() {
                o.new_pkp_digest = "ff".repeat(32);
            }
        }
        Ok(info)
    }
    async fn ceremony_abort(&self, ceremony_id: &str) -> Result<StatusInfo> {
        self.gate()?;
        self.inner.ceremony_abort(ceremony_id).await
    }
    async fn ceremony_protocol(&self) -> Result<u32> {
        self.gate()?;
        if self.sw.old_protocol.load(Ordering::SeqCst) {
            return Ok(0);
        }
        self.inner.ceremony_protocol().await
    }
    async fn ceremony_part1(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: CeremonyKind,
        roster: &[u16],
        intent: Option<&pb::SignedIntent>,
    ) -> Result<round1::Package> {
        self.gate()?;
        let r = self.inner.ceremony_part1(ceremony_id, key_id, kind, roster, intent).await;
        if let Ok(p) = &r {
            self.note(format!("part1 {ceremony_id} {key_id} {roster:?} -> {}", serde_json::to_string(p).unwrap()));
        }
        r
    }
    async fn ceremony_part2(
        &self,
        ceremony_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<Part2Outcome> {
        self.gate()?;
        let r = self.inner.ceremony_part2(ceremony_id, round1_map).await;
        self.note(format!("part2 {ceremony_id} {} -> {r:?}", serde_json::to_string(round1_map).unwrap()));
        r
    }
    async fn ceremony_deliver(
        &self,
        ceremony_id: &str,
        from: u16,
        to: u16,
        round1_digest: &[u8; 32],
        package: &round2::Package,
    ) -> Result<()> {
        self.gate()?;
        self.note(format!("deliver {from}->{to} {}", serde_json::to_string(package).unwrap()));
        self.inner.ceremony_deliver(ceremony_id, from, to, round1_digest, package).await
    }
    async fn ceremony_part3(&self, ceremony_id: &str, round1_digest: &[u8; 32]) -> Result<StagedOutcome> {
        self.part3_gate()?;
        let r = self.inner.ceremony_part3(ceremony_id, round1_digest).await;
        self.note(format!("part3 {ceremony_id} {} -> {r:?}", hex::encode(round1_digest)));
        self.after_part3(&r);
        r
    }
}

impl Faulty {
    fn part3_gate(&self) -> Result<()> {
        self.gate()?;
        if self.sw.fail_part3.load(Ordering::SeqCst) {
            return Err(DaemonError::Status(tonic::Status::unavailable("transport error: part 3 lost")));
        }
        Ok(())
    }

    fn after_part3<T>(&self, r: &Result<T>) {
        if r.is_ok() && self.sw.down_after_part3.load(Ordering::SeqCst) {
            self.sw.down.store(true, Ordering::SeqCst);
        }
    }
}

struct Rig {
    nodes: Vec<Arc<Node>>,
    sw: Vec<Arc<Switches>>,
    /// What the leader's handles saw.
    leader_log: Arc<std::sync::Mutex<Vec<String>>>,
    /// Every round-2 delivery between nodes.
    delivery_log: Arc<std::sync::Mutex<Vec<String>>>,
    /// The leader's view (node 1 leads unless a test picks another).
    peers: Peers,
    _tmp: tempfile::TempDir,
}

impl Rig {
    fn new() -> Self {
        Self::with_orphan_timeout(std::time::Duration::from_secs(900))
    }

    fn with_orphan_timeout(orphan: std::time::Duration) -> Self {
        Self::build(orphan, None)
    }

    /// `caps`: the unknown-ceremony no-vote caps (per asker, total) of every node (audit F2).
    fn build(orphan: std::time::Duration, caps: Option<(usize, usize)>) -> Self {
        Self::build_with(orphan, caps, None)
    }

    /// Every node's fence-only guard timeout is `fence` (default: the production 60 s).
    fn with_fence_timeout(fence: std::time::Duration) -> Self {
        Self::build_with(std::time::Duration::from_secs(900), None, Some(fence))
    }

    fn build_with(orphan: std::time::Duration, caps: Option<(usize, usize)>, fence: Option<std::time::Duration>) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let nodes: Vec<Arc<Node>> = (1..=N)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
                let mut node = Node::new_with_ceremony_timeout(Identifier::try_from(i).unwrap(), N, T, ks, orphan)
                    .with_regather_delay(std::time::Duration::from_millis(10));
                if let Some((per_asker, total)) = caps {
                    node = node.with_unknown_no_vote_caps(per_asker, total);
                }
                if let Some(fence) = fence {
                    node = node.with_ceremony_fence_timeout(fence);
                }
                Arc::new(node)
            })
            .collect();
        let sw: Vec<Arc<Switches>> = (0..N).map(|_| Arc::new(Switches::default())).collect();
        let leader_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let delivery_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        for (j, me) in nodes.iter().enumerate() {
            let mesh: Vec<Arc<dyn PeerApi>> = nodes
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != j)
                .map(|(k, n)| {
                    Arc::new(Faulty {
                        inner: LocalPeer::new(n.clone()).on_behalf_of(me.clone()),
                        sw: sw[k].clone(),
                        asker: j,
                        leader: false,
                        log: delivery_log.clone(),
                    }) as Arc<dyn PeerApi>
                })
                .collect();
            me.set_mesh(mesh).unwrap();
        }
        let peers = nodes
            .iter()
            .zip(&sw)
            .map(|(n, s)| {
                Arc::new(Faulty {
                    inner: LocalPeer::new(n.clone()),
                    sw: s.clone(),
                    asker: usize::MAX,
                    leader: true,
                    log: leader_log.clone(),
                }) as Arc<dyn PeerApi>
            })
            .collect();
        Rig { nodes, sw, leader_log, delivery_log, peers, _tmp: tmp }
    }

    fn share_file(&self, i: usize) -> std::path::PathBuf {
        self.nodes[i].key_store_dir().join(format!("{KEY}.json"))
    }

    fn epochs(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.key_epoch(KEY).unwrap().epoch).collect()
    }

    fn digests(&self) -> Vec<Vec<u8>> {
        self.nodes.iter().map(|n| n.key_epoch(KEY).unwrap().pkp_digest).collect()
    }

    /// No STAGED vote and no staged share, except the quarantined shares of aborted ceremonies
    /// (audit F3), which [`Rig::no_quarantine_anywhere`] checks.
    fn no_staged_anywhere(&self) -> bool {
        self.nodes.iter().all(|n| {
            let quarantined: Vec<String> = n.quarantined_records().into_iter().map(|r| r.ceremony_id).collect();
            n.staged_records().is_empty()
                && n.staged_share_files().unwrap().iter().all(|(_, c)| quarantined.contains(c))
        })
    }

    fn no_quarantine_anywhere(&self) -> bool {
        self.nodes.iter().all(|n| n.quarantined_records().is_empty() && n.staged_share_files().unwrap().is_empty())
    }

    /// Every 2-subset of nodes signs, verified under the group key.
    async fn every_pair_signs(&self, group: &[u8; 32]) {
        for (a, b) in [(0usize, 1usize), (0, 2), (1, 2)] {
            let pair: Peers = vec![self.peers[a].clone(), self.peers[b].clone()];
            let msg = rutli_frost_core::dealer::canton_test_message(format!("pair {a}{b}").as_bytes());
            let sig = sign(&self.nodes[a], &pair, KEY, &msg).await.unwrap_or_else(|e| panic!("{a}{b}: {e}"));
            assert!(rutli_cosigner::verify_key::signature_verifies(group, &msg, &sig), "pair {a}{b}");
        }
    }

    async fn resolve_everywhere(&self) {
        for n in &self.nodes {
            resolve_pending(n).await;
        }
    }

    fn the_ceremony(&self, node: usize, kind: &str) -> String {
        let mut ids: Vec<String> = self.nodes[node]
            .all_records()
            .into_iter()
            .filter(|r| r.kind == kind && r.key_id == KEY)
            .map(|r| r.ceremony_id)
            .collect();
        ids.sort();
        ids.pop().expect("a ceremony record")
    }
}

#[tokio::test]
async fn part3_failing_on_one_node_changes_no_share_and_every_pair_still_signs() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let before: Vec<Vec<u8>> = (0..3).map(|i| std::fs::read(rig.share_file(i)).unwrap()).collect();

    rig.sw[1].fail_part3.store(true, Ordering::SeqCst);
    assert!(run_refresh(&rig.peers, KEY).await.is_err());
    rig.sw[1].fail_part3.store(false, Ordering::SeqCst);

    // Node 1 had staged; it aborted on node 2's no-vote. Nobody replaced a share.
    let id = rig.the_ceremony(0, "refresh");
    assert_eq!(rig.nodes[0].ceremony_record(&id).unwrap().state, RecordState::Aborted);
    for (i, bytes) in before.iter().enumerate() {
        assert_eq!(&std::fs::read(rig.share_file(i)).unwrap(), bytes, "node {} unchanged", i + 1);
    }
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    assert!(rig.no_staged_anywhere());
    rig.every_pair_signs(&group).await;
    // No guard was left behind: the next refresh works.
    assert_eq!(run_refresh(&rig.peers, KEY).await.unwrap(), group);
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
}

#[tokio::test]
async fn a_lost_commit_is_finished_by_the_nodes_own_resolvers() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    // The leader's commit reaches only itself: node 1 confirms with nodes 2 and 3 (both STAGED) and
    // commits; nodes 2 and 3 never hear from the leader again.
    rig.sw[1].drop_commit.store(true, Ordering::SeqCst);
    rig.sw[2].drop_commit.store(true, Ordering::SeqCst);
    let err = run_refresh(&rig.peers, KEY).await.unwrap_err();
    assert!(matches!(err, DaemonError::NotServing(_)), "UNAVAILABLE, so the caller retries: {err:?}");
    assert_eq!(rig.epochs(), vec![2, 1, 1], "node 1 committed; 2 and 3 still on the old share");
    assert_eq!(rig.nodes[1].staged_records().len(), 1);

    // No leader needed: each node's resolver sees node 1 COMMITTED and the other STAGED.
    rig.resolve_everywhere().await;
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    assert!(rig.digests().windows(2).all(|w| w[0] == w[1]));
    assert!(rig.no_staged_anywhere());
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn cancelling_the_caller_mid_commit_cannot_split_epochs() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    for s in &rig.sw {
        s.commit_delay_ms.store(150, Ordering::SeqCst);
    }
    // The client gives up during the commit phase (a CronJob pod killed, a driver deadline).
    let cut = tokio::time::timeout(std::time::Duration::from_millis(100), run_refresh(&rig.peers, KEY)).await;
    assert!(cut.is_err(), "the caller was cut off mid-ceremony");
    // The ceremony is its own task: it finishes regardless.
    for _ in 0..50 {
        if rig.epochs() == vec![2, 2, 2] {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    assert!(rig.no_staged_anywhere());
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn a_node_lost_after_staging_is_waited_for_then_everyone_commits() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    rig.sw[2].down_after_part3.store(true, Ordering::SeqCst);
    let err = run_refresh(&rig.peers, KEY).await.unwrap_err();
    assert!(matches!(err, DaemonError::NotServing(_)), "{err:?}");
    // Nodes 1 and 2 cannot commit without node 3's confirmed yes-vote, and do not abort without
    // evidence. (Node 3 itself is not run: it is the one that is down.)
    resolve_pending(&rig.nodes[0]).await;
    resolve_pending(&rig.nodes[1]).await;
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    assert!(rig.nodes.iter().all(|n| n.staged_records().len() == 1));
    // Signing continues on the old sharing meanwhile, and a new ceremony for the key is refused.
    let pair: Peers = vec![rig.peers[0].clone(), rig.peers[1].clone()];
    let msg = rutli_frost_core::dealer::canton_test_message(b"while staged");
    let sig = sign(&rig.nodes[0], &pair, KEY, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
    assert!(rig.nodes[0].ceremony_begin("refresh-next", KEY, CeremonyKind::Refresh, None, None).is_err());

    // Node 3 returns (its staged vote survived): every resolver commits.
    rig.sw[2].down_after_part3.store(false, Ordering::SeqCst);
    rig.sw[2].down.store(false, Ordering::SeqCst);
    rig.resolve_everywhere().await;
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    assert!(rig.no_staged_anywhere());
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn divergent_votes_abort_on_every_node() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let before = rig.digests();
    // Nodes 1 and 2 see node 3 vote for a different sharing: no outcome can gather every vote.
    rig.sw[2].diverge.store(true, Ordering::SeqCst);
    assert!(run_refresh(&rig.peers, KEY).await.is_err());
    rig.resolve_everywhere().await;
    let id = rig.the_ceremony(0, "refresh");
    for n in &rig.nodes {
        assert_eq!(n.ceremony_record(&id).unwrap().state, RecordState::Aborted);
    }
    assert_eq!(rig.digests(), before);
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    assert!(rig.no_staged_anywhere());
    // Once every node is seen terminal with nobody committed, the next pass drops the quarantines.
    rig.resolve_everywhere().await;
    assert!(rig.no_quarantine_anywhere());
    rig.sw[2].diverge.store(false, Ordering::SeqCst);
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn break_glass_aborts_when_nobody_reachable_committed() {
    let rig = Rig::new();
    run_dkg(&rig.peers, KEY).await.unwrap();
    rig.sw[2].down_after_part3.store(true, Ordering::SeqCst);
    assert!(run_refresh(&rig.peers, KEY).await.is_err());
    let id = rig.the_ceremony(0, "refresh");
    // Without naming the lost node the break-glass refuses (node 3 does not answer).
    assert!(resolve_assume_lost(&rig.nodes[0], &id, &[]).await.is_err());
    assert!(resolve_assume_lost(&rig.nodes[0], &id, &[1]).await.is_err(), "not itself");
    let info = resolve_assume_lost(&rig.nodes[0], &id, &[3]).await.unwrap();
    assert_eq!(info.phase, Phase::Aborted);
    // Node 2 then aborts on node 1's no-vote with its normal resolver.
    resolve_pending(&rig.nodes[1]).await;
    assert_eq!(rig.nodes[1].ceremony_record(&id).unwrap().state, RecordState::Aborted);
    assert_eq!(rig.epochs()[..2], [1, 1]);
}

#[tokio::test]
async fn break_glass_commits_when_a_reachable_node_already_committed() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    rig.sw[1].drop_commit.store(true, Ordering::SeqCst);
    rig.sw[2].drop_commit.store(true, Ordering::SeqCst);
    assert!(run_refresh(&rig.peers, KEY).await.is_err());
    assert_eq!(rig.epochs(), vec![2, 1, 1]);
    // Node 3 is now lost for good. Node 1 committed (it saw node 3's yes-vote), so node 2 commits.
    rig.sw[2].down.store(true, Ordering::SeqCst);
    let id = rig.the_ceremony(1, "refresh");
    let info = resolve_assume_lost(&rig.nodes[1], &id, &[3]).await.unwrap();
    assert_eq!(info.phase, Phase::Committed);
    assert_eq!(rig.epochs()[..2], [2, 2]);
    let pair: Peers = vec![rig.peers[0].clone(), rig.peers[1].clone()];
    let msg = rutli_frost_core::dealer::canton_test_message(b"after break-glass");
    let sig = sign(&rig.nodes[1], &pair, KEY, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

#[tokio::test]
async fn a_dkg_retry_is_unavailable_while_resolving_then_returns_the_key() {
    let rig = Rig::new();
    rig.sw[1].drop_commit.store(true, Ordering::SeqCst);
    rig.sw[2].drop_commit.store(true, Ordering::SeqCst);
    assert!(matches!(run_dkg(&rig.peers, KEY).await, Err(DaemonError::NotServing(_))));
    // Canton retries the deterministic id: still resolving (the leader cannot reach 2 and 3).
    assert!(matches!(run_dkg(&rig.peers, KEY).await, Err(DaemonError::NotServing(_))));
    rig.sw[1].drop_commit.store(false, Ordering::SeqCst);
    rig.sw[2].drop_commit.store(false, Ordering::SeqCst);
    // The retry that finds it staged asks every node to resolve, and answers UNAVAILABLE once more…
    assert!(matches!(run_dkg(&rig.peers, KEY).await, Err(DaemonError::NotServing(_))));
    // …and the next one returns the committed key, never a second DKG.
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    assert_eq!(rig.nodes[2].group_key(KEY).unwrap(), group);
    let dkgs: Vec<_> = rig.nodes[0].all_records().into_iter().filter(|r| r.kind == "dkg").collect();
    assert_eq!(dkgs.len(), 1, "exactly one DKG ran");
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn refresh_keeps_the_group_key_and_old_and_new_shares_never_combine() {
    use rutli_frost_core::nonce_store::NonceStore;
    use rutli_frost_core::session::{aggregate, Cosigner};
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let ks = |i: usize| KeyStore::open(rig.nodes[i].key_store_dir()).unwrap();
    let old1 = ks(0).load(KEY).unwrap();
    assert_eq!(run_refresh(&rig.peers, KEY).await.unwrap(), group);
    let new2 = ks(1).load(KEY).unwrap();
    assert_eq!((old1.epoch, new2.epoch), (1, 2));
    assert_eq!(rig.nodes[0].group_key(KEY).unwrap(), group, "same group key");

    // Node 1's pre-refresh share with node 2's post-refresh share: no valid signature.
    let tmp = tempfile::tempdir().unwrap();
    let c1 = Cosigner::new(old1.key_package, old1.public_key_package.clone(), NonceStore::open(tmp.path().join("a")).unwrap());
    let c2 = Cosigner::new(new2.key_package, new2.public_key_package.clone(), NonceStore::open(tmp.path().join("b")).unwrap());
    let msg = rutli_frost_core::dealer::canton_test_message(b"mixed epochs");
    let commitments = BTreeMap::from([(c1.identifier(), c1.round1("s", rutli_frost_core::session::SessionBinding::new(KEY)).unwrap()), (c2.identifier(), c2.round1("s", rutli_frost_core::session::SessionBinding::new(KEY)).unwrap())]);
    let shares = BTreeMap::from([
        (c1.identifier(), c1.round2("s", KEY, &msg, &commitments, None).unwrap()),
        (c2.identifier(), c2.round2("s", KEY, &msg, &commitments, None).unwrap()),
    ]);
    for pkp in [&old1.public_key_package, &new2.public_key_package] {
        assert!(aggregate(&msg, &commitments, &shares, pkp).is_err(), "mixed epochs must not combine");
    }
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn an_unknown_ceremony_is_a_durable_no_vote_and_its_id_is_never_reused() {
    let rig = Rig::new();
    let n = &rig.nodes[0];
    let info = n.ceremony_status("dkg-never-started").unwrap();
    assert_eq!(info.phase, Phase::Aborted);
    assert_eq!(n.ceremony_record("dkg-never-started").unwrap().state, RecordState::Aborted);
    let err = n.dkg_part1("dkg-never-started", KEY).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{err:?}");
    // The leader's abort never overrides a vote either way.
    assert_eq!(n.ceremony_abort("dkg-never-started").unwrap().phase, Phase::Aborted);
}

#[tokio::test]
async fn refresh_refuses_nodes_on_mixed_epochs() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    // A mixed-epoch cluster, as a pre-two-phase refresh could leave one: node 2 on another epoch.
    let ks = KeyStore::open(rig.nodes[1].key_store_dir()).unwrap();
    let mut share = ks.load(KEY).unwrap();
    share.epoch = 7;
    ks.save(KEY, &share).unwrap();
    let before = rig.digests();
    let err = run_refresh(&rig.peers, KEY).await.unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{err:?}");
    assert_eq!(rig.digests(), before, "refused before any crypto");
    // A node refuses a leader whose view of the sharing differs from its own, too.
    let mine = rig.nodes[0].key_epoch(KEY).unwrap();
    let digest: [u8; 32] = mine.pkp_digest.as_slice().try_into().unwrap();
    let err = rig.nodes[1].ceremony_begin("refresh-x", KEY, CeremonyKind::Refresh, Some((1, digest)), None).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{err:?}");
    // At sign time the node on the other epoch never joins a quorum (audit H1): a pair that needs
    // it cannot sign, the pair on one sharing still does.
    for (a, b) in [(0usize, 1usize), (1, 2)] {
        let pair: Peers = vec![rig.peers[a].clone(), rig.peers[b].clone()];
        let msg = rutli_frost_core::dealer::canton_test_message(b"mixed");
        let err = sign(&rig.nodes[a], &pair, KEY, &msg).await.unwrap_err();
        assert!(matches!(err, DaemonError::ThresholdNotMet { needed: 2, got: 1 }), "{a}{b}: {err:?}");
    }
    let pair: Peers = vec![rig.peers[0].clone(), rig.peers[2].clone()];
    let msg = rutli_frost_core::dealer::canton_test_message(b"same sharing");
    let sig = sign(&rig.nodes[0], &pair, KEY, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

/// Install on node `i` (0-based) a share as a pre-two-phase DKG would have left it: origin DKG,
/// epoch 0. Returns the group key.
fn legacy_share(rig: &Rig, i: usize, seed: u8) -> [u8; 32] {
    let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&[seed; 32], &[1, 2, 3], T).unwrap();
    let share = rutli_cosigner::keystore::Share {
        key_package: frost_ed25519::keys::KeyPackage::try_from(shares[i].clone()).unwrap(),
        public_key_package: pkp.clone(),
        origin: None,
        epoch: 0,
        key_id: String::new(),
    };
    KeyStore::open(rig.nodes[i].key_store_dir()).unwrap().create(KEY, &share).unwrap();
    rutli_frost_core::dkg::group_verifying_key_bytes(&pkp).unwrap()
}

#[tokio::test]
async fn a_legacy_partial_key_wedges_dkg_until_discarded_on_its_holder() {
    use rutli_cosigner::ceremony::discard_partial_key;
    let rig = Rig::new();
    let partial = legacy_share(&rig, 0, 9);
    let err = run_dkg(&rig.peers, KEY).await.unwrap_err();
    assert!(
        matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("discard-partial-key")),
        "FAILED_PRECONDITION naming the operator path: {err:?}"
    );
    // The discard is guarded: the group key must be confirmed, and a burned nonce means it signed.
    assert!(discard_partial_key(&rig.nodes[0], KEY, &[0u8; 32]).await.is_err());
    let nonces = rig.nodes[0].key_store_dir().join(format!("{KEY}.nonces"));
    std::fs::create_dir_all(&nonces).unwrap();
    std::fs::write(nonces.join("sign-x"), b"burned").unwrap();
    assert!(discard_partial_key(&rig.nodes[0], KEY, &partial).await.is_err());
    std::fs::remove_file(nonces.join("sign-x")).unwrap();
    // Every peer must answer, to prove the key is partial.
    rig.sw[2].down.store(true, Ordering::SeqCst);
    assert!(discard_partial_key(&rig.nodes[0], KEY, &partial).await.is_err());
    rig.sw[2].down.store(false, Ordering::SeqCst);

    let report = discard_partial_key(&rig.nodes[0], KEY, &partial).await.unwrap();
    assert_eq!(report.holders, vec![1]);
    assert!(!rig.nodes[0].has_key(KEY));
    // The id is free again: a fresh DKG mints a new key.
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    assert_ne!(group, partial);
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
}

#[tokio::test]
async fn discard_partial_key_refuses_whenever_any_node_holds_a_committed_epoch() {
    use rutli_cosigner::ceremony::discard_partial_key;
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    // A committed key, everywhere: never partial.
    assert!(discard_partial_key(&rig.nodes[0], KEY, &group).await.is_err());
    // Node 1 looks legacy (epoch 0) and node 3 lost its file — but node 2 holds the key at a
    // committed epoch, so this is a two-phase key with a lost share, not a legacy partial one.
    let ks = KeyStore::open(rig.nodes[0].key_store_dir()).unwrap();
    let mut share = ks.load(KEY).unwrap();
    share.epoch = 0;
    ks.save(KEY, &share).unwrap();
    KeyStore::open(rig.nodes[2].key_store_dir()).unwrap().delete(KEY).unwrap();
    assert!(discard_partial_key(&rig.nodes[0], KEY, &group).await.is_err(), "its own record says committed");
    // Even with node 1's ceremony records gone (restored from a backup, which never holds them),
    // node 2's committed epoch refuses it.
    std::fs::remove_dir_all(rig.nodes[0].key_store_dir().join(".ceremonies")).unwrap();
    let fresh = Arc::new(Node::new(
        Identifier::try_from(1u16).unwrap(),
        N,
        T,
        KeyStore::open(rig.nodes[0].key_store_dir()).unwrap(),
    ));
    fresh
        .set_mesh(
            rig.nodes[1..]
                .iter()
                .map(|n| Arc::new(LocalPeer::new(n.clone()).on_behalf_of(fresh.clone())) as Arc<dyn PeerApi>)
                .collect(),
        )
        .unwrap();
    let err = discard_partial_key(&fresh, KEY, &group).await.unwrap_err();
    assert!(matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("node 2")), "{err:?}");
    assert!(fresh.has_key(KEY), "nothing deleted");
}

// ── C1: confidential, authenticated round 2 ─────────────────────────────────────────────────────

/// The signing-share hex of every round-2 package delivered between nodes.
fn delivered_shares(rig: &Rig) -> Vec<String> {
    rig.delivery_log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| {
            let json = e.split_once(' ').map(|x| x.1)?.split_once(' ')?.1;
            let v: serde_json::Value = serde_json::from_str(json).ok()?;
            v.get("signing_share").and_then(|s| s.as_str()).map(String::from)
        })
        .collect()
}

#[tokio::test]
async fn the_leader_never_sees_a_round2_package_in_dkg_or_refresh() {
    // Audit C1: with the relay, the leader of a 2-of-3 DKG saw f_i(j) for every pair and could
    // interpolate the group secret. Now everything the leader's handles carry, both ways, is
    // recorded — and no round-2 package is in it.
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    assert_eq!(run_refresh(&rig.peers, KEY).await.unwrap(), group);

    let shares = delivered_shares(&rig);
    // 2 ceremonies × 3 senders × 2 recipients, each delivered node to node.
    assert_eq!(shares.len(), 12, "{:?}", rig.delivery_log.lock().unwrap());
    let transcript = rig.leader_log.lock().unwrap().join("\n");
    assert!(transcript.contains("part1") && transcript.contains("part3"), "the leader's view was recorded");
    assert!(!transcript.contains("signing_share"), "no round-2 package passed through the leader");
    for share in &shares {
        assert!(!transcript.contains(share.as_str()), "a delivered share leaked to the leader");
    }
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    rig.every_pair_signs(&group).await;
}

/// A leader that runs the ceremony by hand and shows node `victim` (0-based, per call) a doctored
/// round-1 map. Parts 2 and 3 are driven for every node regardless of failures, with each node
/// given its own digest at part 3 — the most a malicious leader can do to get a node to stage.
async fn equivocate(
    rig: &Rig,
    kind: CeremonyKind,
    tamper: impl Fn(usize, &mut BTreeMap<Identifier, round1::Package>),
) -> String {
    let ceremony_id = format!("{}-evil-{}", kind.as_str(), uuid_like());
    let expect = (kind == CeremonyKind::Refresh).then(|| {
        let v = rig.nodes[0].key_epoch(KEY).unwrap();
        (v.epoch, v.pkp_digest.as_slice().try_into().unwrap())
    });
    for p in &rig.peers {
        p.ceremony_begin(&ceremony_id, KEY, kind, expect, None).await.unwrap();
    }
    let mut map = BTreeMap::new();
    for p in &rig.peers {
        map.insert(p.identifier(), p.ceremony_part1(&ceremony_id, KEY, kind, &[1, 2, 3], None).await.unwrap());
    }
    let mut digests = Vec::new();
    for (i, p) in rig.peers.iter().enumerate() {
        let mut shown = map.clone();
        tamper(i, &mut shown);
        digests.push(p.ceremony_part2(&ceremony_id, &shown).await.map(|o| o.round1_digest).unwrap_or([0u8; 32]));
    }
    for (i, p) in rig.peers.iter().enumerate() {
        assert!(p.ceremony_part3(&ceremony_id, &digests[i]).await.is_err(), "node {} must not stage", i + 1);
    }
    for p in &rig.peers {
        let _ = p.ceremony_release(&ceremony_id, KEY).await;
    }
    ceremony_id
}

fn uuid_like() -> String {
    format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
}

/// A valid round-1 package for `id` that no node of the cluster generated.
fn fake_round1(id: u16) -> round1::Package {
    rutli_frost_core::dkg::DkgParticipant::new(Identifier::try_from(id).unwrap(), N, T).part1().unwrap()
}

fn assert_aborted_everywhere(rig: &Rig, ceremony_id: &str) {
    for (i, n) in rig.nodes.iter().enumerate() {
        let rec = n.ceremony_record(ceremony_id).unwrap_or_else(|| panic!("node {} has no vote", i + 1));
        assert_eq!(rec.state, RecordState::Aborted, "node {}: {rec:?}", i + 1);
    }
    assert!(rig.no_staged_anywhere());
}

#[tokio::test]
async fn a_leader_showing_one_node_a_substituted_package_makes_every_node_abort() {
    let rig = Rig::new();
    // Node 2 is shown a different package for node 3.
    let fake = fake_round1(3);
    let id = equivocate(&rig, CeremonyKind::Dkg, |victim, m| {
        if victim == 1 {
            m.insert(Identifier::try_from(3u16).unwrap(), fake.clone());
        }
    })
    .await;
    assert_aborted_everywhere(&rig, &id);
    assert!(rig.nodes.iter().all(|n| !n.has_key(KEY)), "no share persisted");
    // Nothing was left behind: an honest DKG then works.
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn a_leader_substituting_a_nodes_own_package_for_the_others_makes_every_node_abort() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let before = rig.digests();
    // Nodes 2 and 3 are shown a forged package for node 1 (node 1 sees the true map).
    let fake = fake_round1(1);
    let id = equivocate(&rig, CeremonyKind::Refresh, |victim, m| {
        if victim != 0 {
            m.insert(Identifier::try_from(1u16).unwrap(), fake.clone());
        }
    })
    .await;
    assert_aborted_everywhere(&rig, &id);
    assert_eq!(rig.digests(), before, "no share replaced");
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn a_node_refuses_a_map_with_a_forged_package_of_its_own_or_a_foreign_digest() {
    let rig = Rig::new();
    // Every node is shown a forged package for itself: each refuses at part 2.
    let id = equivocate(&rig, CeremonyKind::Dkg, |victim, m| {
        m.insert(Identifier::try_from(victim as u16 + 1).unwrap(), fake_round1(victim as u16 + 1));
    })
    .await;
    assert_aborted_everywhere(&rig, &id);

    // An honest map, but the leader hands part 3 a digest that is not the nodes' own.
    let ceremony_id = "dkg-wrong-digest";
    for p in &rig.peers {
        p.ceremony_begin(ceremony_id, KEY, CeremonyKind::Dkg, None, None).await.unwrap();
    }
    let mut map = BTreeMap::new();
    for p in &rig.peers {
        map.insert(p.identifier(), p.ceremony_part1(ceremony_id, KEY, CeremonyKind::Dkg, &[1, 2, 3], None).await.unwrap());
    }
    for p in &rig.peers {
        p.ceremony_part2(ceremony_id, &map).await.unwrap();
    }
    for p in &rig.peers {
        assert!(p.ceremony_part3(ceremony_id, &[7u8; 32]).await.is_err());
    }
    assert_aborted_everywhere(&rig, ceremony_id);
}

#[tokio::test]
async fn a_round2_delivery_is_bound_to_its_real_sender_and_recipient() {
    let rig = Rig::new();
    let ceremony_id = "dkg-deliveries";
    for p in &rig.peers {
        p.ceremony_begin(ceremony_id, KEY, CeremonyKind::Dkg, None, None).await.unwrap();
        p.ceremony_part1(ceremony_id, KEY, CeremonyKind::Dkg, &[1, 2, 3], None).await.unwrap();
    }
    let pkg = |b: u8| {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        round2::Package::new(frost_ed25519::keys::SigningShare::deserialize(&bytes).unwrap())
    };
    // Node 3 delivering to node 1 as node 2: refused (the sender is who the transport says).
    let as_node3 = LocalPeer::new(rig.nodes[0].clone()).on_behalf_of(rig.nodes[2].clone());
    let err = as_node3.ceremony_deliver(ceremony_id, 2, 1, &[1u8; 32], &pkg(1)).await.unwrap_err();
    assert!(err.to_string().contains("cannot deliver"), "{err}");
    // A package addressed to node 2 is not accepted by node 1.
    let err = as_node3.ceremony_deliver(ceremony_id, 3, 2, &[1u8; 32], &pkg(1)).await.unwrap_err();
    assert!(err.to_string().contains("delivered to node 1"), "{err}");
    // Node 3's own delivery is accepted; a retry of the same bytes too; a different second package
    // is equivocation and aborts node 1's session.
    as_node3.ceremony_deliver(ceremony_id, 3, 1, &[1u8; 32], &pkg(1)).await.unwrap();
    as_node3.ceremony_deliver(ceremony_id, 3, 1, &[1u8; 32], &pkg(1)).await.unwrap();
    assert!(as_node3.ceremony_deliver(ceremony_id, 3, 1, &[1u8; 32], &pkg(2)).await.is_err());
    assert_eq!(rig.nodes[0].ceremony_record(ceremony_id).unwrap().state, RecordState::Aborted);
}

#[tokio::test]
async fn a_leader_dying_before_every_part3_leaves_one_staged_node_that_aborts_on_orphans() {
    // Generous enough that parts 1–3 (fsyncing on slow CI disks) finish before anything orphans.
    let orphan_timeout = std::time::Duration::from_secs(3);
    let rig = Rig::with_orphan_timeout(orphan_timeout);
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let before = rig.digests();
    let ceremony_id = "refresh-leader-died";
    let v = rig.nodes[0].key_epoch(KEY).unwrap();
    let expect = Some((v.epoch, v.pkp_digest.as_slice().try_into().unwrap()));
    for p in &rig.peers {
        p.ceremony_begin(ceremony_id, KEY, CeremonyKind::Refresh, expect, None).await.unwrap();
    }
    let mut map = BTreeMap::new();
    for p in &rig.peers {
        map.insert(p.identifier(), p.ceremony_part1(ceremony_id, KEY, CeremonyKind::Refresh, &[1, 2, 3], None).await.unwrap());
    }
    let mut digest = [0u8; 32];
    for p in &rig.peers {
        digest = p.ceremony_part2(ceremony_id, &map).await.unwrap().round1_digest;
    }
    // Only node 1 gets part 3; then the leader is gone.
    rig.peers[0].ceremony_part3(ceremony_id, &digest).await.unwrap();
    resolve_pending(&rig.nodes[0]).await;
    assert_eq!(rig.nodes[0].ceremony_record(ceremony_id).unwrap().state, RecordState::Staged, "2 and 3 in progress");
    // Past the orphan timeout nodes 2 and 3 vote no when asked, and node 1 aborts on it.
    tokio::time::sleep(orphan_timeout + std::time::Duration::from_millis(250)).await;
    resolve_pending(&rig.nodes[0]).await;
    assert_aborted_everywhere(&rig, ceremony_id);
    assert_eq!(rig.digests(), before);
    rig.every_pair_signs(&group).await;
    // The orphaned guards are gone with the sessions: the next refresh runs.
    assert_eq!(run_refresh(&rig.peers, KEY).await.unwrap(), group);
}

#[tokio::test]
async fn a_cluster_with_an_old_protocol_node_refuses_ceremonies_loudly() {
    let rig = Rig::new();
    rig.sw[2].old_protocol.store(true, Ordering::SeqCst);
    let err = run_dkg(&rig.peers, KEY).await.unwrap_err();
    assert!(
        matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("cosigner 3 speaks ceremony protocol 0")),
        "{err:?}"
    );
    // Refused before any fence or session: no node recorded anything.
    assert!(rig.nodes.iter().all(|n| n.all_records().is_empty()));
    // A node that cannot be asked is refused the same way.
    rig.sw[2].old_protocol.store(false, Ordering::SeqCst);
    rig.sw[2].down.store(true, Ordering::SeqCst);
    assert!(matches!(run_dkg(&rig.peers, KEY).await, Err(DaemonError::CeremonyRefused(_))));
    rig.sw[2].down.store(false, Ordering::SeqCst);
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    rig.sw[1].old_protocol.store(true, Ordering::SeqCst);
    assert!(matches!(run_refresh(&rig.peers, KEY).await, Err(DaemonError::CeremonyRefused(_))));
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    rig.every_pair_signs(&group).await;
}

#[tokio::test]
async fn a_ceremony_over_a_roster_other_than_the_nodes_own_is_refused() {
    let rig = Rig::new();
    for roster in [&[1u16, 2][..], &[1, 2, 3, 4], &[1, 2, 4]] {
        let err = rig.nodes[0].ceremony_part1("dkg-roster", KEY, CeremonyKind::Dkg, roster, None).unwrap_err();
        assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{roster:?}: {err:?}");
    }
}

#[tokio::test]
async fn a_repeated_part1_keeps_the_live_session_and_its_guard() {
    let rig = Rig::new();
    let n = &rig.nodes[0];
    n.ceremony_begin("dkg-twice", KEY, CeremonyKind::Dkg, None, None).unwrap();
    n.ceremony_part1("dkg-twice", KEY, CeremonyKind::Dkg, &[1, 2, 3], None).unwrap();
    assert!(n.ceremony_part1("dkg-twice", KEY, CeremonyKind::Dkg, &[1, 2, 3], None).is_err());
    // Still held by the live ceremony: another one for the key is refused.
    let err = n.ceremony_begin("dkg-other", KEY, CeremonyKind::Dkg, None, None).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "{err:?}");
    assert_eq!(n.ceremony_status("dkg-twice").unwrap().phase, Phase::InProgress);
}


/// Audit F2: a peer asking about made-up ceremony ids cannot make a node write unbounded durable
/// no-votes. Within the cap each answer is a durable no-vote (and the id is never started later);
/// beyond it the node refuses — no record, no answer, so it may still take part in that id.
#[tokio::test]
async fn a_flood_of_unknown_ceremony_ids_is_bounded_per_peer_and_in_total() {
    let rig = Rig::build(std::time::Duration::from_secs(900), Some((3, 5)));
    let target = &rig.nodes[0];
    let records_dir = target.key_store_dir().join(".ceremonies");
    let count_files = || std::fs::read_dir(&records_dir).map(|d| d.count()).unwrap_or(0);
    // Node 2 floods node 1 through its mesh handle (asks as `cosigner2`).
    let as_node2 = rig.nodes[1].mesh_peer(1).unwrap();
    let mut answered = 0;
    let mut refused = Vec::new();
    for i in 0..50 {
        let id = format!("refresh-junk-{i}");
        match if i % 2 == 0 { as_node2.ceremony_status(&id).await } else { as_node2.ceremony_abort(&id).await } {
            Ok(info) => {
                assert_eq!(info.phase, Phase::Aborted);
                answered += 1;
            }
            Err(e) => {
                assert!(matches!(e, DaemonError::RateLimited(_)), "{e:?}");
                refused.push(id);
            }
        }
    }
    assert_eq!(answered, 3, "node 2's quota");
    // The leader's commit (resolve) path is capped the same way.
    assert!(as_node2.ceremony_commit("refresh-junk-commit").await.is_err());
    // Node 3 still has its own quota, up to the total.
    let as_node3 = rig.nodes[2].mesh_peer(1).unwrap();
    assert!(as_node3.ceremony_status("refresh-n3-a").await.is_ok());
    assert!(as_node3.ceremony_status("refresh-n3-b").await.is_ok());
    assert!(matches!(as_node3.ceremony_status("refresh-n3-c").await, Err(DaemonError::RateLimited(_))), "total cap");
    assert_eq!(count_files(), 5, "bounded on disk");

    // Safety: a recorded no-vote stays one and its id never starts; a refused id left no vote, so
    // starting it later contradicts nothing this node said.
    assert_eq!(as_node2.ceremony_status("refresh-junk-0").await.unwrap().phase, Phase::Aborted);
    assert!(matches!(target.dkg_part1("refresh-junk-0", "frost-other"), Err(DaemonError::CeremonyRefused(_))));
    assert!(target.ceremony_record(&refused[0]).is_none());
    target.dkg_part1(&refused[0], "frost-other").unwrap();
    assert_eq!(as_node2.ceremony_status(&refused[0]).await.unwrap().phase, Phase::InProgress);

    // The cluster still runs ceremonies and signs.
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    rig.every_pair_signs(&group).await;
}

/// Ceremony sessions in memory are bounded: a peer opening sessions for made-up key ids is
/// refused past [`rutli_cosigner::node::MAX_CEREMONY_SESSIONS`], and orphans make room.
#[tokio::test]
async fn ceremony_sessions_in_memory_are_bounded() {
    // The timeout must outlast filling the table (each part 1 fsyncs; slow CI disks take tens of
    // milliseconds per call), or the first sessions orphan and make room before the cap is probed.
    let orphan_timeout = std::time::Duration::from_secs(5);
    let rig = Rig::with_orphan_timeout(orphan_timeout);
    let n = &rig.nodes[0];
    let max = rutli_cosigner::node::MAX_CEREMONY_SESSIONS;
    let started = std::time::Instant::now();
    for i in 0..max {
        n.dkg_part1(&format!("dkg-flood-{i}"), &format!("frost-flood-{i}")).unwrap();
    }
    let refused = n.dkg_part1("dkg-flood-x", "frost-flood-x");
    assert!(started.elapsed() < orphan_timeout, "filling the table outlasted the orphan timeout; raise it");
    assert!(matches!(refused, Err(DaemonError::NotServing(_))), "{refused:?}");
    // Past the orphan timeout the orphans are dropped (each with a no-vote) to make room.
    tokio::time::sleep(orphan_timeout.saturating_sub(started.elapsed()) + std::time::Duration::from_millis(250)).await;
    n.dkg_part1("dkg-flood-x", "frost-flood-x").unwrap();
    assert_eq!(n.ceremony_record("dkg-flood-0").unwrap().state, RecordState::Aborted);
    // Their guards went with them: a ceremony on one of those keys runs.
    n.dkg_part1("dkg-flood-0-again", "frost-flood-0").unwrap();
}

/// Audit F2: sessions a peer opens and lets orphan are bounded too — beyond the cap their no-vote
/// is not recorded, and a node STAGED in such a ceremony waits instead of acting on a refusal.
#[tokio::test]
async fn orphaned_session_no_votes_are_capped_and_a_refusal_is_not_evidence() {
    // The orphan timeout must outlast the setup DKG and parts 1-3 on a loaded CI runner.
    let orphan = std::time::Duration::from_secs(5);
    let rig = Rig::build(orphan, Some((0, 0)));
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let ceremony_id = "refresh-capped-orphans";
    let v = rig.nodes[0].key_epoch(KEY).unwrap();
    let expect = Some((v.epoch, v.pkp_digest.as_slice().try_into().unwrap()));
    for p in &rig.peers {
        p.ceremony_begin(ceremony_id, KEY, CeremonyKind::Refresh, expect, None).await.unwrap();
    }
    let mut map = BTreeMap::new();
    for p in &rig.peers {
        map.insert(p.identifier(), p.ceremony_part1(ceremony_id, KEY, CeremonyKind::Refresh, &[1, 2, 3], None).await.unwrap());
    }
    let mut digest = [0u8; 32];
    for p in &rig.peers {
        digest = p.ceremony_part2(ceremony_id, &map).await.unwrap().round1_digest;
    }
    // Only node 1 stages; the leader is gone; nodes 2 and 3 orphan but may record no no-vote.
    rig.peers[0].ceremony_part3(ceremony_id, &digest).await.unwrap();
    tokio::time::sleep(orphan + std::time::Duration::from_millis(250)).await;
    for _ in 0..3 {
        resolve_pending(&rig.nodes[0]).await;
    }
    assert_eq!(rig.nodes[0].ceremony_record(ceremony_id).unwrap().state, RecordState::Staged, "waits");
    for n in &rig.nodes[1..] {
        assert!(n.ceremony_record(ceremony_id).is_none(), "no no-vote beyond the cap");
        assert!(n.staged_share_files().unwrap().is_empty(), "never staged, so never commits");
    }
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    // Signing continues on the old sharing.
    let pair: Peers = vec![rig.peers[1].clone(), rig.peers[2].clone()];
    let msg = rutli_frost_core::dealer::canton_test_message(b"capped");
    let sig = sign(&rig.nodes[1], &pair, KEY, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

/// Audit F3: one Byzantine cosigner telling one honest node STAGED and the other ABORTED splits a
/// refresh. Detected (equivocation, split flag) and recovered: the aborted node's share was
/// quarantined, survives a restart, and `recover_commit` commits it once a peer proves COMMITTED.
#[tokio::test]
async fn a_byzantine_split_is_detected_and_recovered_from_the_quarantine() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    // Node 3 lies ABORTED to node 2's resolver, and tells node 1 the truth.
    rig.sw[2].lie_aborted_to.store(1 << 1, Ordering::SeqCst);
    assert!(run_refresh(&rig.peers, KEY).await.is_err());
    let id = rig.the_ceremony(0, "refresh");
    assert_eq!(rig.nodes[0].ceremony_record(&id).unwrap().state, RecordState::Committed);
    let rec2 = rig.nodes[1].ceremony_record(&id).unwrap();
    assert_eq!(rec2.state, RecordState::Aborted);
    assert!(rec2.quarantined, "the aborted node keeps its staged share");
    assert_ne!(rec2.split_detected_ms, 0, "COMMITTED and ABORTED for one ceremony: equivocation");
    assert_eq!(rig.nodes[1].split_count(), 1);
    assert_eq!(rig.epochs()[..2], [2, 1], "the split");
    // Further resolver passes keep the quarantine (a split is never garbage-collected silently).
    rig.resolve_everywhere().await;
    assert!(rig.nodes[1].ceremony_record(&id).unwrap().quarantined);

    // The quarantined share survives a restart of node 2.
    let restarted = Node::new(Identifier::try_from(2u16).unwrap(), N, T, KeyStore::open(rig.nodes[1].key_store_dir()).unwrap());
    assert_eq!(restarted.quarantined_records().len(), 1);
    assert_eq!(restarted.staged_share_files().unwrap().len(), 1);
    drop(restarted);

    // Recovery needs proof: with node 1 unreachable, nobody proves COMMITTED.
    rig.sw[0].down.store(true, Ordering::SeqCst);
    let err = recover_commit(&rig.nodes[1], &id).await.unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{err:?}");
    rig.sw[0].down.store(false, Ordering::SeqCst);
    // Node 1 reports COMMITTED and holds that sharing live: node 2 commits its quarantined share.
    let info = recover_commit(&rig.nodes[1], &id).await.unwrap();
    assert_eq!(info.phase, Phase::Committed);
    let rec2 = rig.nodes[1].ceremony_record(&id).unwrap();
    assert!(rec2.recovered && !rec2.quarantined);
    assert_eq!(rig.nodes[1].split_count(), 0);
    // Node 3 (honest code, it was only lying in the test harness) recovers the same way.
    rig.sw[2].lie_aborted_to.store(0, Ordering::SeqCst);
    if rig.nodes[2].ceremony_record(&id).unwrap().state != RecordState::Committed {
        recover_commit(&rig.nodes[2], &id).await.unwrap();
    }
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    assert!(rig.no_quarantine_anywhere());
    rig.every_pair_signs(&group).await;
    // A recovered ceremony is not recoverable twice.
    assert!(recover_commit(&rig.nodes[1], &id).await.is_err());
}

/// Audit F3, crash faults: one node failing part 3 aborts the rest; the abort is re-gathered,
/// never counted as equivocation, and the quarantine is dropped once every peer is terminal.
#[tokio::test]
async fn a_crash_abort_is_not_a_split_and_its_quarantine_is_dropped() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    rig.sw[2].down_after_part3.store(true, Ordering::SeqCst);
    assert!(run_refresh(&rig.peers, KEY).await.is_err());
    let id = rig.the_ceremony(0, "refresh");
    // Node 3 staged, then went away: nodes 1 and 2 wait. (Node 3's own resolver is not run: it is
    // the one that is gone — run, it would commit, and the break-glass below would then be the
    // misuse the docs warn about, which the split detection does catch.)
    resolve_pending(&rig.nodes[0]).await;
    resolve_pending(&rig.nodes[1]).await;
    assert!(rig.nodes[..2].iter().all(|n| n.ceremony_record(&id).unwrap().state == RecordState::Staged));
    // Break-glass on node 1 (node 3 "lost"): node 1 aborts, node 2 then aborts on node 1's no-vote
    // while node 3 is still unreachable — quarantined, not a split.
    resolve_assume_lost(&rig.nodes[0], &id, &[3]).await.unwrap();
    resolve_pending(&rig.nodes[1]).await;
    let rec2 = rig.nodes[1].ceremony_record(&id).unwrap();
    assert_eq!(rec2.state, RecordState::Aborted);
    assert!(rec2.quarantined && rec2.split_detected_ms == 0);
    assert_eq!(rig.nodes.iter().map(|n| n.split_count()).sum::<usize>(), 0);
    // Node 3 returns and aborts too; then everybody is terminal and nobody committed.
    rig.sw[2].down_after_part3.store(false, Ordering::SeqCst);
    rig.sw[2].down.store(false, Ordering::SeqCst);
    rig.resolve_everywhere().await;
    rig.resolve_everywhere().await;
    assert!(rig.no_quarantine_anywhere(), "{:?}", rig.nodes.iter().map(|n| n.quarantined_records()).collect::<Vec<_>>());
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    rig.every_pair_signs(&group).await;
}

/// Audit F11: a failed round-2 delivery reaches the leader as a category, never the recipient's
/// error text.
#[tokio::test]
async fn a_failed_delivery_tells_the_leader_only_its_category() {
    let rig = Rig::new();
    let ceremony_id = "dkg-delivery-category";
    for p in &rig.peers {
        p.ceremony_begin(ceremony_id, KEY, CeremonyKind::Dkg, None, None).await.unwrap();
    }
    let mut map = BTreeMap::new();
    for p in &rig.peers {
        map.insert(p.identifier(), p.ceremony_part1(ceremony_id, KEY, CeremonyKind::Dkg, &[1, 2, 3], None).await.unwrap());
    }
    // Node 3 drops its session: node 1's delivery to it fails there with "unknown dkg session …".
    rig.peers[2].ceremony_abort(ceremony_id).await.unwrap();
    let err = rig.peers[0].ceremony_part2(ceremony_id, &map).await.unwrap_err().to_string();
    assert!(err.contains("node 3") && err.contains("recipient has no such session"), "{err}");
    assert!(!err.contains("unknown dkg session"), "the recipient's text leaked to the leader: {err}");
}

/// Pre-existing (review): a peer could fence a FROST key as a hosted-key "genkey"/"delkey" and
/// stall its signing; and round 1 without an intent could open sessions without bound.
#[tokio::test]
async fn hosted_key_fences_never_cover_a_frost_key_and_pending_sign_sessions_are_bounded() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    for kind in ["genkey", "delkey"] {
        let err = rig.nodes[0].ceremony_fence(&format!("{kind}-evil"), KEY, kind).unwrap_err();
        assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{kind}: {err:?}");
    }
    rig.every_pair_signs(&group).await;

    let n = &rig.nodes[0];
    let max = rutli_cosigner::node::MAX_PENDING_SIGN_SESSIONS_PER_KEY;
    let ctx = rutli_cosigner::node::Round1Ctx::default();
    for i in 0..max {
        n.sign_round1(KEY, &format!("flood-{i}"), &ctx).unwrap();
    }
    let err = n.sign_round1(KEY, "flood-x", &ctx).unwrap_err();
    assert!(matches!(err, DaemonError::NotServing(_)), "{err:?}");
    for i in 0..max {
        n.abort_sign(KEY, &format!("flood-{i}"));
    }
    rig.every_pair_signs(&group).await;
}

// ── signing is not fenced by DKG/refresh; guard hygiene (0.4.0-rc.4) ──

/// Every 2-subset signs; returns the signatures (each verified under `group`).
async fn sign_every_pair(rig: &Rig, group: &[u8; 32], tag: &str) -> Vec<Vec<u8>> {
    let mut sigs = Vec::new();
    for (a, b) in [(0usize, 1usize), (0, 2), (1, 2)] {
        let pair: Peers = vec![rig.peers[a].clone(), rig.peers[b].clone()];
        let msg = rutli_frost_core::dealer::canton_test_message(format!("{tag} {a}{b}").as_bytes());
        let sig = sign(&rig.nodes[a], &pair, KEY, &msg).await.unwrap_or_else(|e| panic!("{tag} {a}{b}: {e}"));
        assert!(rutli_cosigner::verify_key::signature_verifies(group, &msg, &sig), "{tag} {a}{b}");
        sigs.push(sig.to_vec());
    }
    sigs
}

fn expect_of(rig: &Rig) -> Option<(u64, [u8; 32])> {
    let v = rig.nodes[0].key_epoch(KEY).unwrap();
    Some((v.epoch, v.pkp_digest.as_slice().try_into().unwrap()))
}

/// Signing goes on between the fence and every part of a refresh and across its commit; part 3
/// only stages (the live share file is byte-identical until commit); a sign begun before the fence
/// completes after part 3; no two signatures share a nonce commitment.
#[tokio::test]
async fn signing_continues_through_every_phase_of_a_refresh_and_across_its_commit() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let live = |rig: &Rig| (0..N as usize).map(|i| std::fs::read(rig.share_file(i)).unwrap()).collect::<Vec<_>>();
    let before = live(&rig);
    let mut sigs = sign_every_pair(&rig, &group, "before").await;

    // A sign whose round 1 runs before the fence; its round 2 comes after part 3.
    let early_msg = rutli_frost_core::dealer::canton_test_message(b"early");
    let ctx = rutli_cosigner::node::Round1Ctx {
        leader_view: Some(rig.nodes[0].signing_view(KEY).unwrap().view),
        ..Default::default()
    };
    let mut early = BTreeMap::new();
    for n in &rig.nodes[..2] {
        early.insert(n.identifier, n.sign_round1(KEY, "early", &ctx).unwrap());
    }

    let id = "refresh-while-signing";
    for p in &rig.peers {
        p.ceremony_begin(id, KEY, CeremonyKind::Refresh, expect_of(&rig), None).await.unwrap();
    }
    sigs.extend(sign_every_pair(&rig, &group, "fenced").await);
    let mut map = BTreeMap::new();
    for p in &rig.peers {
        map.insert(p.identifier(), p.ceremony_part1(id, KEY, CeremonyKind::Refresh, &[1, 2, 3], None).await.unwrap());
    }
    sigs.extend(sign_every_pair(&rig, &group, "part1").await);
    let mut digest = [0u8; 32];
    for p in &rig.peers {
        digest = p.ceremony_part2(id, &map).await.unwrap().round1_digest;
    }
    sigs.extend(sign_every_pair(&rig, &group, "part2").await);
    for p in &rig.peers {
        p.ceremony_part3(id, &digest).await.unwrap();
    }
    // Part 3 staged a share and a yes-vote on every node, and wrote nothing live.
    assert_eq!(live(&rig), before, "part 3 must never write the live share");
    assert_eq!(rig.epochs(), vec![1, 1, 1]);
    for n in &rig.nodes {
        assert_eq!(n.ceremony_record(id).unwrap().state, RecordState::Staged);
        assert!(n.staged_share_files().unwrap().iter().any(|(k, c)| k == KEY && c == id));
    }
    sigs.extend(sign_every_pair(&rig, &group, "staged").await);

    // The early sign completes on the unchanged live share.
    let shares: BTreeMap<_, _> = rig.nodes[..2]
        .iter()
        .map(|n| (n.identifier, n.sign_round2(KEY, "early", &early_msg, &early).unwrap()))
        .collect();
    let pkp = KeyStore::open(rig.nodes[0].key_store_dir()).unwrap().load(KEY).unwrap().public_key_package;
    let signing_package = frost_ed25519::SigningPackage::new(early.clone(), &early_msg);
    let sig = frost_ed25519::aggregate(&signing_package, &shares, &pkp).unwrap().serialize().unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &early_msg, &sig));
    sigs.push(sig);

    // Commit: the live share changes now, and signing goes on at epoch 2.
    for p in &rig.peers {
        assert_eq!(p.ceremony_commit(id).await.unwrap().phase, Phase::Committed);
    }
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    assert!(live(&rig).iter().zip(&before).all(|(a, b)| a != b), "commit replaced every live share");
    sigs.extend(sign_every_pair(&rig, &group, "committed").await);

    // No nonce was ever used twice: every signature has its own R.
    let rs: std::collections::BTreeSet<Vec<u8>> = sigs.iter().map(|s| s[..32].to_vec()).collect();
    assert_eq!(rs.len(), sigs.len(), "a nonce commitment repeated");
}

/// A fence never followed by part 1 (a leader that died, or a peer fencing on its own) is orphaned
/// after the short fence timeout, so the next ceremony takes the key; a guard with a session keeps
/// the orphan timeout.
#[tokio::test]
async fn a_fence_only_guard_expires_after_the_fence_timeout_and_a_new_ceremony_takes_the_key() {
    // Generous: the "still fresh" check below must run inside the fence on a loaded CI runner
    // (a 300 ms fence expired before the first refresh attempt on an 8-vCPU parallel run).
    let fence = std::time::Duration::from_secs(3);
    let rig = Rig::with_fence_timeout(fence);
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    // Freshness is judged from the FIRST peer's fence (the earliest to expire); the wait for expiry
    // from the LAST peer's (the latest to expire).
    let first_fenced = std::time::Instant::now();
    for p in &rig.peers {
        p.ceremony_begin("refresh-abandoned", KEY, CeremonyKind::Refresh, expect_of(&rig), None).await.unwrap();
    }
    let last_fenced = std::time::Instant::now();
    // While it is fresh it holds off another ceremony (signing is unaffected either way).
    let err = run_refresh(&rig.peers, KEY).await.unwrap_err();
    assert!(first_fenced.elapsed() < fence, "the fence expired before it was probed; raise `fence`");
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "{err:?}");
    rig.every_pair_signs(&group).await;

    tokio::time::sleep((fence + std::time::Duration::from_millis(250)).saturating_sub(last_fenced.elapsed())).await;
    assert_eq!(run_refresh(&rig.peers, KEY).await.unwrap(), group);
    assert_eq!(rig.epochs(), vec![2, 2, 2]);
    rig.every_pair_signs(&group).await;

    // A guard whose part 1 ran is a live session: the fence timeout does not apply to it.
    let n = &rig.nodes[0];
    n.ceremony_begin("refresh-with-session", KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap();
    n.ceremony_part1("refresh-with-session", KEY, CeremonyKind::Refresh, &[1, 2, 3], None).unwrap();
    tokio::time::sleep(fence + std::time::Duration::from_millis(250)).await;
    let err = n.ceremony_begin("refresh-next", KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "{err:?}");
}

/// Re-sending a fence under the same ceremony id keeps the guard's original start (rc.3 reset it,
/// so a fence repeated every so often held the key forever).
#[tokio::test]
async fn re_fencing_under_the_same_id_does_not_extend_the_guard() {
    let fence = std::time::Duration::from_secs(2);
    let rig = Rig::with_fence_timeout(fence);
    run_dkg(&rig.peers, KEY).await.unwrap();
    let n = &rig.nodes[0];
    let started = std::time::Instant::now();
    n.ceremony_begin("refresh-renewed", KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap();
    let err = n.ceremony_begin("refresh-other", KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "{err:?}");
    assert!(started.elapsed() < fence, "the fence expired before it was probed; raise `fence`");
    // A second DKG/refresh fence under the same id is refused outright (a second leader for one
    // ceremony, ceremony intents)...
    let err = n.ceremony_begin("refresh-renewed", KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap_err();
    assert!(matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("second")), "{err:?}");
    // ...and re-taking the guard under that id (the raw fence) every 500 ms, past the timeout, never
    // extends it: the last one lands well inside a would-be reset.
    while started.elapsed() < fence + std::time::Duration::from_millis(500) {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        n.ceremony_fence("refresh-renewed", KEY, "refresh").unwrap();
    }
    n.ceremony_begin("refresh-other", KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap();
    // The preempted id's part 1 is refused: the key is held by the newer fence.
    let err = n.ceremony_part1("refresh-renewed", KEY, CeremonyKind::Refresh, &[1, 2, 3], None).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "{err:?}");
    // The same id cannot change kind under its guard either.
    assert!(matches!(n.ceremony_fence("refresh-other", KEY, "dkg"), Err(DaemonError::CeremonyRefused(_))));
}

/// The fence refuses a ceremony id this node already holds a record for (part 1 always did), so a
/// used id never even takes the guard.
#[tokio::test]
async fn a_fence_for_a_ceremony_id_with_a_record_is_refused_and_takes_no_guard() {
    let rig = Rig::new();
    let group = run_dkg(&rig.peers, KEY).await.unwrap();
    let dkg_id = rig.the_ceremony(0, "dkg");
    let n = &rig.nodes[0];
    // A committed id, and an id this node voted no on as unknown.
    assert_eq!(n.ceremony_status("refresh-unknown").unwrap().phase, Phase::Aborted);
    for id in [dkg_id.as_str(), "refresh-unknown"] {
        let err = n.ceremony_begin(id, KEY, CeremonyKind::Refresh, expect_of(&rig), None).unwrap_err();
        assert!(matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("already used")), "{id}: {err:?}");
    }
    // No guard was left behind: a refresh runs at once.
    assert_eq!(run_refresh(&rig.peers, KEY).await.unwrap(), group);
}

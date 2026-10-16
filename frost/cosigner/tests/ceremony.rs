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
use rutli_cosigner::ceremony::{resolve_assume_lost, resolve_pending};
use rutli_cosigner::ceremony_record::{Phase, RecordState, StatusInfo};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{CeremonyKind, Node};
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
}

struct Faulty {
    inner: LocalPeer,
    sw: Arc<Switches>,
    /// The leader's handle (commit faults apply) rather than a peer's mesh handle.
    leader: bool,
}

impl Faulty {
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
    async fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments> {
        self.gate()?;
        self.inner.sign_round1(key_id, session_id).await
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        self.gate()?;
        self.inner.sign_round2(key_id, session_id, message, commitments).await
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
    async fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package> {
        self.gate()?;
        self.inner.dkg_part1(dkg_id, key_id).await
    }
    async fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        self.gate()?;
        self.inner.dkg_part2(dkg_id, round1_map).await
    }
    async fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        self.part3_gate()?;
        let r = self.inner.dkg_part3(dkg_id, round1_map, round2_for_me).await;
        self.after_part3(&r);
        r
    }
    async fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        self.gate()?;
        self.inner.refresh_part1(refresh_id, key_id).await
    }
    async fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        self.gate()?;
        self.inner.refresh_part2(refresh_id, round1_map).await
    }
    async fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        self.part3_gate()?;
        let r = self.inner.refresh_part3(refresh_id, round1_map, round2_for_me).await;
        self.after_part3(&r);
        r
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
    ) -> Result<()> {
        self.gate()?;
        self.inner.ceremony_begin(ceremony_id, key_id, kind, expect).await
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
    /// The leader's view (node 1 leads unless a test picks another).
    peers: Peers,
    _tmp: tempfile::TempDir,
}

impl Rig {
    fn new() -> Self {
        Self::with_orphan_timeout(std::time::Duration::from_secs(900))
    }

    fn with_orphan_timeout(orphan: std::time::Duration) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let nodes: Vec<Arc<Node>> = (1..=N)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
                Arc::new(Node::new_with_ceremony_timeout(Identifier::try_from(i).unwrap(), N, T, ks, orphan))
            })
            .collect();
        let sw: Vec<Arc<Switches>> = (0..N).map(|_| Arc::new(Switches::default())).collect();
        for (j, me) in nodes.iter().enumerate() {
            let mesh: Vec<Arc<dyn PeerApi>> = nodes
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != j)
                .map(|(k, n)| {
                    Arc::new(Faulty {
                        inner: LocalPeer::new(n.clone()).on_behalf_of(me.clone()),
                        sw: sw[k].clone(),
                        leader: false,
                    }) as Arc<dyn PeerApi>
                })
                .collect();
            me.set_mesh(mesh).unwrap();
        }
        let peers = nodes
            .iter()
            .zip(&sw)
            .map(|(n, s)| {
                Arc::new(Faulty { inner: LocalPeer::new(n.clone()), sw: s.clone(), leader: true }) as Arc<dyn PeerApi>
            })
            .collect();
        Rig { nodes, sw, peers, _tmp: tmp }
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

    fn no_staged_anywhere(&self) -> bool {
        self.nodes.iter().all(|n| n.staged_records().is_empty() && n.staged_share_files().unwrap().is_empty())
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
    assert!(rig.nodes[0].ceremony_begin("refresh-next", KEY, CeremonyKind::Refresh, None).is_err());

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
    let commitments = BTreeMap::from([(c1.identifier(), c1.round1("s").unwrap()), (c2.identifier(), c2.round1("s").unwrap())]);
    let shares = BTreeMap::from([
        (c1.identifier(), c1.round2("s", &msg, &commitments).unwrap()),
        (c2.identifier(), c2.round2("s", &msg, &commitments).unwrap()),
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
    let err = rig.nodes[1].ceremony_begin("refresh-x", KEY, CeremonyKind::Refresh, Some((1, digest))).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{err:?}");
    rig.every_pair_signs(&group).await;
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

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Exercises the daemon's DKG + signing orchestration across a 3-node cluster wired with
//! in-process peers (LocalPeer). This covers node state, the orchestrator, and the keystore —
//! everything except the tonic transport — and verifies the output with a strict independent
//! Ed25519 verifier.

use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::DaemonError;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};

const N: u16 = 3;
const T: u16 = 2;
const KEY_ID: &str = "namespace-participant1";

fn cluster(tmp: &tempfile::TempDir) -> (Vec<Arc<Node>>, Peers) {
    let mut nodes = Vec::new();
    for i in 1..=N {
        let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
        let id = Identifier::try_from(i).unwrap();
        nodes.push(Arc::new(Node::new(id, N, T, ks)));
    }
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    (nodes, peers)
}

fn canton_digest(msg: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12u8, 0x20u8];
    out.extend(msg.iter().cycle().take(32));
    out
}

#[tokio::test]
async fn dkg_then_sign_across_cluster_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);

    // Distributed key generation — every node ends up with a persisted share.
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();
    for n in &nodes {
        assert!(n.has_key(KEY_ID), "each node persists its own share");
        assert_eq!(n.group_key(KEY_ID).unwrap(), group_key, "nodes agree on the group key");
    }

    // Threshold signature over Canton's 34-byte payload, verified by an independent strict verifier.
    let message = canton_digest(b"NamespaceDelegation");
    let sig = sign(&nodes[0], &peers, KEY_ID, &message).await.unwrap();
    assert_eq!(sig.len(), 64);

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .expect("cluster signature must be a valid RFC 8032 Ed25519 signature");
}

#[tokio::test]
async fn refresh_rotates_shares_keeping_group_key_and_still_signs() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    let share_path = tmp.path().join("node-1").join(format!("{KEY_ID}.json"));
    let before = std::fs::read(&share_path).unwrap();

    // Proactive refresh — same group key out.
    let after_key = run_refresh(&peers, KEY_ID).await.unwrap();
    assert_eq!(after_key, group_key, "refresh must not change the group key (node identity stable)");
    for n in &nodes {
        assert_eq!(n.group_key(KEY_ID).unwrap(), group_key);
    }

    // Shares were actually rewritten on disk (re-randomized).
    let after = std::fs::read(&share_path).unwrap();
    assert_ne!(before, after, "refresh must rewrite the share on disk");

    // Refreshed cluster still signs, verifiable under the unchanged group key.
    let message = canton_digest(b"after refresh");
    let sig = sign(&nodes[0], &peers, KEY_ID, &message).await.unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();

    // Refresh again — chains cleanly.
    assert_eq!(run_refresh(&peers, KEY_ID).await.unwrap(), group_key);
}

#[tokio::test]
async fn a_lost_node_recovers_from_a_share_backup_and_the_cluster_signs() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();
    drop(nodes);
    drop(peers);

    // Back up node-1's key dir (as `rutli-cosigner backup` does — a file copy of the sealed shares).
    let keys1 = tmp.path().join("node-1");
    let backup = tmp.path().join("backup-node-1");
    std::fs::create_dir_all(&backup).unwrap();
    for e in std::fs::read_dir(&keys1).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), backup.join(e.file_name())).unwrap();
        }
    }

    // Catastrophe: node-1's disk is wiped.
    std::fs::remove_dir_all(&keys1).unwrap();

    // Restore from backup, then rebuild the cluster.
    std::fs::create_dir_all(&keys1).unwrap();
    for e in std::fs::read_dir(&backup).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), keys1.join(e.file_name())).unwrap();
        }
    }
    let (nodes, peers) = cluster(&tmp);

    // Same group key, and the recovered node participates in a valid signature.
    for n in &nodes {
        assert_eq!(n.group_key(KEY_ID).unwrap(), group_key);
    }
    let message = canton_digest(b"after restore");
    let sig = sign(&nodes[0], &peers, KEY_ID, &message).await.unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
}

#[tokio::test]
async fn signing_survives_one_downed_cosigner() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    // Only the first two nodes are available (2-of-3). Leader is node 0.
    let available: Peers = peers.iter().take(2).cloned().collect();
    let message = canton_digest(b"OwnerToKeyMapping");
    let sig = sign(&nodes[0], &available, KEY_ID, &message).await.unwrap();

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
}

#[tokio::test]
async fn sealed_shares_are_encrypted_at_rest_and_reload_with_the_right_key() {
    use rutli_cosigner::seal::Sealer;

    let tmp = tempfile::tempdir().unwrap();

    // Cluster with sealing enabled on every node (same master secret, per-node derived keys).
    let mut nodes = Vec::new();
    for i in 1..=N {
        let sealer = Arc::new(Sealer::from_master_secret(b"cluster master secret", i));
        let ks = KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
        nodes.push(Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, ks)));
    }
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    // On-disk file must be a sealed envelope, not plaintext frost JSON.
    let share_path = tmp.path().join("node-1").join(format!("{KEY_ID}.json"));
    let bytes = std::fs::read(&share_path).unwrap();
    assert!(Sealer::is_sealed(&bytes), "share file must be sealed");
    assert!(
        !String::from_utf8_lossy(&bytes).contains("key_package"),
        "sealed file must not leak plaintext share fields"
    );

    // Reload with the RIGHT key: works, and the cluster still signs.
    let mut reloaded = Vec::new();
    for i in 1..=N {
        let sealer = Arc::new(Sealer::from_master_secret(b"cluster master secret", i));
        let ks = KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
        reloaded.push(Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, ks)));
    }
    let peers2: Peers =
        reloaded.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    let message = canton_digest(b"sealed shares");
    let sig = sign(&reloaded[0], &peers2, KEY_ID, &message).await.unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();

    // Reload with the WRONG key: refuses.
    let wrong = Arc::new(Sealer::from_master_secret(b"not the master secret", 1));
    let ks = KeyStore::open_with_sealer(tmp.path().join("node-1"), Some(wrong)).unwrap();
    let node = Node::new(Identifier::try_from(1u16).unwrap(), N, T, ks);
    assert!(node.group_key(KEY_ID).is_err(), "wrong seal key must not open the share");

    // And without any sealer configured: refuses loudly (no silent plaintext fallback).
    let ks = KeyStore::open(tmp.path().join("node-1")).unwrap();
    let node = Node::new(Identifier::try_from(1u16).unwrap(), N, T, ks);
    assert!(node.group_key(KEY_ID).is_err(), "sealed share must not open without sealing configured");
}

#[tokio::test]
async fn shares_persist_across_node_reload() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();
    drop(nodes);
    drop(peers);

    // Rebuild the cluster from the same data dirs — shares must load from disk, no new DKG.
    let mut reloaded = Vec::new();
    for i in 1..=N {
        let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
        reloaded.push(Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, ks)));
    }
    let peers2: Peers =
        reloaded.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();

    for n in &reloaded {
        assert_eq!(n.group_key(KEY_ID).unwrap(), group_key);
    }
    let message = canton_digest(b"after restart");
    let sig = sign(&reloaded[0], &peers2, KEY_ID, &message).await.unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
}

// ── ceremony serialization (regression: concurrent DKG/refresh must not split-brain shares) ──

#[tokio::test]
async fn dkg_refuses_a_concurrent_ceremony_for_the_same_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _peers) = cluster(&tmp);
    let n = &nodes[0];
    // One ceremony reserves the key at part1.
    n.dkg_part1("ceremony-A", KEY_ID).unwrap();
    // A different, overlapping ceremony for the same key is refused (would split-brain the shares).
    let err = n.dkg_part1("ceremony-B", KEY_ID).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "got {err:?}");
}

#[tokio::test]
async fn dkg_refuses_when_the_key_already_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    run_dkg(&peers, KEY_ID).await.unwrap(); // provision the key

    // A fresh DKG against a provisioned key is refused — re-DKG would destroy the (non-rotatable) key.
    let err = nodes[0].dkg_part1("ceremony-new", KEY_ID).unwrap_err();
    assert!(matches!(err, DaemonError::KeyExists(_)), "got {err:?}");
    // A full orchestrated re-DKG fails rather than overwriting.
    assert!(run_dkg(&peers, KEY_ID).await.is_err(), "second DKG must fail, not overwrite");

    // The original key still signs and verifies.
    let msg = canton_digest(b"after refused re-dkg");
    let sig = sign(&nodes[0], &peers, KEY_ID, &msg).await.unwrap();
    let gk = nodes[0].group_key(KEY_ID).unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&gk)
        .unwrap()
        .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

#[tokio::test]
async fn refresh_refuses_a_concurrent_ceremony_for_the_same_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    run_dkg(&peers, KEY_ID).await.unwrap();
    let n = &nodes[0];
    n.refresh_part1("refresh-A", KEY_ID).unwrap();
    let err = n.refresh_part1("refresh-B", KEY_ID).unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "got {err:?}");
}

/// Build a cluster whose ceremony orphan-guard timeout is tiny, so a stalled ceremony can be
/// preempted in a test without waiting the production 15 minutes.
fn cluster_fast_orphan(tmp: &tempfile::TempDir) -> (Vec<Arc<Node>>, Peers) {
    let mut nodes = Vec::new();
    for i in 1..=N {
        let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
        let id = Identifier::try_from(i).unwrap();
        nodes.push(Arc::new(Node::new_with_ceremony_timeout(
            id, N, T, ks, std::time::Duration::from_millis(1),
        )));
    }
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    (nodes, peers)
}

#[tokio::test]
async fn a_superseded_refresh_cannot_persist_after_orphan_preempt() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster_fast_orphan(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    // A stale refresh grabs the per-key guard on node 0, then stalls (the leader "died").
    nodes[0].refresh_part1("stale-refresh", KEY_ID).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await; // exceed the tiny orphan timeout

    // A real cluster-wide refresh preempts the orphan and completes; group key unchanged.
    assert_eq!(run_refresh(&peers, KEY_ID).await.unwrap(), group_key);

    // The stale ceremony can no longer persist — its finish is refused (superseded / session gone).
    let empty1: std::collections::BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package> =
        std::collections::BTreeMap::new();
    let empty2: std::collections::BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package> =
        std::collections::BTreeMap::new();
    assert!(nodes[0].refresh_part3("stale-refresh", &empty1, &empty2).is_err());

    // The cluster is consistent and still signs under the unchanged group key.
    for n in &nodes {
        assert_eq!(n.group_key(KEY_ID).unwrap(), group_key);
    }
    let msg = canton_digest(b"after preempt");
    let sig = sign(&nodes[0], &peers, KEY_ID, &msg).await.unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&group_key)
        .unwrap()
        .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

#[tokio::test]
async fn sign_is_refused_while_a_refresh_holds_the_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    // A refresh grabs the per-key guard (part1) but hasn't finished.
    nodes[0].refresh_part1("refresh-1", KEY_ID).unwrap();

    // A new sign on that node is refused while the refresh is in progress (no undefined interleave).
    let err = nodes[0].sign_round1(KEY_ID, "sign-during-refresh").unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "got {err:?}");

    // Signing on a node NOT mid-refresh still works (its guard is free).
    assert!(nodes[1].sign_round1(KEY_ID, "elsewhere").is_ok());

    // group_key still readable; the cluster is consistent.
    assert_eq!(nodes[0].group_key(KEY_ID).unwrap(), group_key);
}

// ── sign abort on failure (P1.3): a give-up frees in-flight nonces now, not at the pending TTL ──

use std::collections::BTreeMap;
use async_trait::async_trait;
use frost_ed25519::keys::dkg::{round1, round2};
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use rutli_cosigner::Result as DaemonResult;

/// Wraps a real peer but fails `sign_round2`, so the leader's round 2 gives up. Every other call —
/// including `abort_sign` — forwards to the inner peer, modelling a live cosigner that simply can't
/// complete this signature.
struct FailRound2 {
    inner: LocalPeer,
}

#[async_trait]
impl PeerApi for FailRound2 {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str) -> DaemonResult<SigningCommitments> {
        self.inner.sign_round1(key_id, session_id).await
    }
    async fn sign_round2(
        &self,
        _key_id: &str,
        _session_id: &str,
        _message: &[u8],
        _commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> DaemonResult<SignatureShare> {
        Err(DaemonError::Disagreement("forced round2 failure".into()))
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> DaemonResult<()> {
        self.inner.abort_sign(key_id, session_id).await
    }
    async fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> DaemonResult<round1::Package> {
        self.inner.dkg_part1(dkg_id, key_id).await
    }
    async fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        self.inner.dkg_part2(dkg_id, round1_map).await
    }
    async fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        self.inner.dkg_part3(dkg_id, round1_map, round2_for_me).await
    }
    async fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> DaemonResult<round1::Package> {
        self.inner.refresh_part1(refresh_id, key_id).await
    }
    async fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        self.inner.refresh_part2(refresh_id, round1_map).await
    }
    async fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        self.inner.refresh_part3(refresh_id, round1_map, round2_for_me).await
    }
}

#[tokio::test]
async fn a_failed_sign_round2_aborts_the_in_flight_session_on_every_quorum_member() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _local_peers) = cluster(&tmp);
    let group_key = run_dkg(&nodes_peers(&nodes), KEY_ID).await.unwrap();

    // Quorum = node 0 (leader, real) + node 1 (fails round 2). Node 2 is omitted so the quorum is
    // exactly these two and round 2 must touch the failing peer.
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
        Arc::new(FailRound2 { inner: LocalPeer::new(nodes[1].clone()) }) as Arc<dyn PeerApi>,
    ];

    let message = canton_digest(b"round2 will fail");
    let err = sign(&nodes[0], &peers, KEY_ID, &message).await.unwrap_err();
    assert!(matches!(err, DaemonError::Disagreement(_)), "got {err:?}");

    // The load-bearing assertion: node 1 held a round-1 nonce (it answered round 1) and the leader's
    // abort freed it immediately — no waiting for the pending TTL. Node 0 burned its own in round 2.
    assert_eq!(group_key.len(), 32);
    assert_eq!(nodes[1].pending_sign_count(KEY_ID), 0, "failed sign must abort node 1's session");
    assert_eq!(nodes[0].pending_sign_count(KEY_ID), 0, "leader's own session is consumed/aborted");

    // The cluster is unharmed: a fresh, all-real quorum still signs and verifies.
    let sig = sign(&nodes[0], &nodes_peers(&nodes), KEY_ID, &message).await.unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&group_key)
        .unwrap()
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

#[tokio::test]
async fn a_threshold_shortfall_after_round1_aborts_the_lone_commitment() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _peers) = cluster(&tmp);
    let group_key = run_dkg(&nodes_peers(&nodes), KEY_ID).await.unwrap();

    // Only node 0 is offered to the leader — below the 2-of-3 threshold. It mints one commitment,
    // then the sign gives up; that lone nonce must be aborted, not left for the TTL.
    let only_leader: Peers = vec![Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>];
    let err = sign(&nodes[0], &only_leader, KEY_ID, &canton_digest(b"lonely")).await.unwrap_err();
    assert!(matches!(err, DaemonError::ThresholdNotMet { .. }), "got {err:?}");
    assert_eq!(nodes[0].pending_sign_count(KEY_ID), 0, "shortfall must abort the lone commitment");
    assert_eq!(group_key.len(), 32);
}

/// Fresh all-real peer set over the same nodes (each call makes new LocalPeers; nodes are shared).
fn nodes_peers(nodes: &[Arc<Node>]) -> Peers {
    nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect()
}

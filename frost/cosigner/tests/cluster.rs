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
async fn sign_rejects_non_canton_digest_lengths() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    run_dkg(&peers, KEY_ID).await.unwrap();

    let err = sign(&nodes[0], &peers, KEY_ID, b"too-short").await.unwrap_err();
    assert!(matches!(err, DaemonError::InvalidMessageLength { got: 9, expected: 34 }), "got {err:?}");

    let err = sign(&nodes[0], &peers, KEY_ID, &[0u8; 64]).await.unwrap_err();
    assert!(matches!(err, DaemonError::InvalidMessageLength { got: 64, expected: 34 }), "got {err:?}");
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
async fn reseal_plaintext_shares_migrates_legacy_files_at_startup() {
    use rutli_cosigner::seal::Sealer;

    let tmp = tempfile::tempdir().unwrap();
    // Provision plaintext shares (no sealer).
    let (_nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();
    let share_path = tmp.path().join("node-1").join(format!("{KEY_ID}.json"));
    assert!(!Sealer::is_sealed(&std::fs::read(&share_path).unwrap()));

    // Re-open with sealing and migrate — plaintext must become a sealed envelope.
    let sealer = Arc::new(Sealer::from_master_secret(b"cluster master secret!!", 1));
    let ks = KeyStore::open_with_sealer(tmp.path().join("node-1"), Some(sealer)).unwrap();
    assert_eq!(ks.reseal_plaintext_shares().unwrap(), 1);
    assert!(Sealer::is_sealed(&std::fs::read(&share_path).unwrap()));
    assert_eq!(ks.reseal_plaintext_shares().unwrap(), 0, "idempotent");

    // Share still loads under the same group key.
    let n = Node::new(Identifier::try_from(1u16).unwrap(), N, T, ks);
    assert_eq!(n.group_key(KEY_ID).unwrap(), group_key);
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
async fn sign_is_refused_on_every_node_after_cluster_wide_refresh_fence() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    // Cluster-wide fence (what run_refresh does before crypto): every peer takes the guard.
    for n in &nodes {
        n.ceremony_fence("refresh-1", KEY_ID, "refresh").unwrap();
    }

    // A new sign is refused on EVERY node — not just the leader that started the ceremony.
    for (i, n) in nodes.iter().enumerate() {
        let err = n.sign_round1(KEY_ID, &format!("sign-during-refresh-{i}")).unwrap_err();
        assert!(
            matches!(err, DaemonError::CeremonyInProgress { .. }),
            "node {i}: got {err:?}"
        );
    }

    // group_key still readable; the cluster is consistent.
    assert_eq!(nodes[0].group_key(KEY_ID).unwrap(), group_key);
    let _ = peers; // roster present for the cluster helper
}

#[tokio::test]
async fn refresh_is_refused_while_a_sign_is_in_flight_on_any_node() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();

    // Node 1 has an in-flight sign (round1 done, round2 not yet).
    nodes[1].sign_round1(KEY_ID, "in-flight").unwrap();
    assert_eq!(nodes[1].pending_sign_count(KEY_ID), 1);

    // Cluster refresh must fail at the fence (reverse fence), not mutate shares under the sign.
    let err = run_refresh(&peers, KEY_ID).await.unwrap_err();
    assert!(matches!(err, DaemonError::SignInProgress { .. }), "got {err:?}");

    // Partial fence rolled back: a node with no pending signs accepts a new round1 (not stuck
    // behind a leftover ceremony guard from the aborted refresh).
    assert!(nodes[0].sign_round1(KEY_ID, "after-rollback").is_ok());
    assert!(nodes[2].sign_round1(KEY_ID, "after-rollback-2").is_ok());

    // Abort the in-flight session and confirm the cluster still signs under the same group key.
    nodes[1].abort_sign(KEY_ID, "in-flight");
    let msg = canton_digest(b"after reverse-fence");
    let sig = sign(&nodes[0], &peers, KEY_ID, &msg).await.unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&group_key)
        .unwrap()
        .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
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
    async fn ceremony_fence(
        &self,
        ceremony_id: &str,
        key_id: &str,
        kind: &'static str,
    ) -> DaemonResult<()> {
        self.inner.ceremony_fence(ceremony_id, key_id, kind).await
    }
    async fn ceremony_release(&self, ceremony_id: &str, key_id: &str) -> DaemonResult<()> {
        self.inner.ceremony_release(ceremony_id, key_id).await
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
    // Hosted-key methods just forward: this wrapper only sabotages sign round 2.
    async fn node_info(&self) -> DaemonResult<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(
        &self,
        ceremony_id: &str,
        key_id: &str,
        spec: &str,
        public_key_der: &[u8],
        wrapped: &rutli_cosigner::wrap::Wrapped,
    ) -> DaemonResult<Vec<u8>> {
        self.inner.replicate_key(ceremony_id, key_id, spec, public_key_der, wrapped).await
    }
    async fn fetch_key(
        &self,
        key_id: &str,
    ) -> DaemonResult<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(key_id).await
    }
    async fn list_keys(&self) -> DaemonResult<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, ceremony_id: &str, key_id: &str) -> DaemonResult<bool> {
        self.inner.purge_key(ceremony_id, key_id).await
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

// ── mesh-API hardening: the Peer path must not be a forgery oracle ──

#[tokio::test]
async fn peer_round2_refuses_a_non_canton_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = cluster(&tmp);
    run_dkg(&peers, KEY_ID).await.unwrap();

    // The mesh Peer RPC lands directly on Node::sign_round2, bypassing the leader. Without a
    // digest guard here, a caller on the Peer API could gather `threshold` shares over an
    // arbitrary message and aggregate a valid namespace signature offline.
    let forged = b"arbitrary attacker-chosen message, not a 34-byte Canton digest".to_vec();
    let commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    let err = nodes[0].sign_round2(KEY_ID, "forge-session", &forged, &commitments).unwrap_err();
    assert!(
        matches!(err, DaemonError::InvalidMessageLength { expected: 34, .. }),
        "peer-path round2 must refuse non-digest payloads, got {err:?}"
    );

    // A well-formed 34-byte digest is still accepted through the same path (round1 first).
    let msg = canton_digest(b"legit");
    let c0 = nodes[0].sign_round1(KEY_ID, "ok-session").unwrap();
    let mut cs = BTreeMap::new();
    cs.insert(nodes[0].identifier, c0);
    let c1 = nodes[1].sign_round1(KEY_ID, "ok-session").unwrap();
    cs.insert(nodes[1].identifier, c1);
    assert!(nodes[0].sign_round2(KEY_ID, "ok-session", &msg, &cs).is_ok());
}

// ── cluster-hosted (non-FROST) keys: RSA encryption + AES symmetric held by the cluster ──

use rutli_cosigner::hosted::HostedSpec;
use rutli_cosigner::orchestrator::{
    anti_entropy_sweep, delete_hosted_key, generate_hosted_key, repair_hosted_key,
    DEFAULT_WRITE_QUORUM,
};

const HOSTED_MASTER: &[u8] = b"hosted key cluster master secret for tests";
const CLUSTER: &str = "testcluster00000";

/// A cluster with hosted keys enabled on every node (sealed keystores, shared master secret).
fn hosted_cluster(tmp: &tempfile::TempDir) -> (Vec<Arc<Node>>, Peers) {
    use rutli_cosigner::seal::Sealer;
    let mut nodes = Vec::new();
    for i in 1..=N {
        let sealer = Arc::new(Sealer::from_master_secret(HOSTED_MASTER, i));
        let ks =
            KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
        let node = Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
            .with_hosted_keys(HOSTED_MASTER, CLUSTER.to_string())
            .unwrap();
        nodes.push(Arc::new(node));
    }
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    (nodes, peers)
}

#[tokio::test]
async fn a_hosted_rsa_key_is_replicated_and_every_node_can_decrypt() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    let (key, created, replicas) =
        generate_hosted_key(&nodes[0], &peers, "rutli-enc-1", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();
    assert!(created);
    assert_eq!(replicas, N as usize, "every cosigner should hold the key");

    // Encrypt to the published public key, exactly as a Canton peer would.
    let ciphertext = key.encrypt_oaep(b"canton view session key").unwrap();

    // ANY node can serve the decrypt — that is the availability property hosted keys buy.
    for n in &nodes {
        let plain = n.hosted_decrypt("rutli-enc-1", &ciphertext).unwrap();
        assert_eq!(plain, b"canton view session key");
    }

    // The material on disk is sealed, not readable.
    let raw = std::fs::read(tmp.path().join("node-2").join("rutli-enc-1.json")).unwrap();
    assert!(rutli_cosigner::seal::Sealer::is_sealed(&raw));
    assert!(!String::from_utf8_lossy(&raw).contains("private_der"));
}

#[tokio::test]
async fn a_hosted_symmetric_key_round_trips_across_nodes() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);
    generate_hosted_key(&nodes[0], &peers, "rutli-sym-1", HostedSpec::Aes256Gcm, DEFAULT_WRITE_QUORUM)
        .await
        .unwrap();

    // Encrypt on one node, decrypt on another: the replicas are genuinely the same key.
    let blob = nodes[0].hosted_encrypt_symmetric("rutli-sym-1", b"wrapped private key store").unwrap();
    assert_eq!(
        nodes[2].hosted_decrypt_symmetric("rutli-sym-1", &blob).unwrap(),
        b"wrapped private key store"
    );
}

#[tokio::test]
async fn generate_is_idempotent_so_a_retry_cannot_mint_a_second_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    let (first, created1, _) =
        generate_hosted_key(&nodes[0], &peers, "rutli-enc-2", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();
    // A client retry / driver failover repeats the request with the same id.
    let (second, created2, _) =
        generate_hosted_key(&nodes[0], &peers, "rutli-enc-2", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();

    assert!(created1 && !created2, "the second call must not create a new key");
    assert_eq!(first.public_der, second.public_der, "the key must be unchanged");
    // Ciphertext from before the retry still decrypts — the key was not silently replaced.
    let ct = first.encrypt_oaep(b"still valid").unwrap();
    assert_eq!(nodes[1].hosted_decrypt("rutli-enc-2", &ct).unwrap(), b"still valid");
}

#[tokio::test]
async fn a_node_that_missed_a_write_is_repaired_and_then_serves_decrypts() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    // Simulate an under-quorum write: only nodes 0 and 1 receive the key (node 2 was down).
    let partial: Peers = peers.iter().take(2).cloned().collect();
    let (key, _, replicas) =
        generate_hosted_key(&nodes[0], &partial, "rutli-enc-3", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();
    assert_eq!(replicas, 2);
    assert!(!nodes[2].hosted_exists("rutli-enc-3"), "node 3 should be missing it");

    // Read-repair: node 2 pulls the key on demand rather than returning NOT_FOUND. It sees the
    // others as peers calling on its behalf, so replies are wrapped to it, as over gRPC.
    let as_node2: Peers = nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone()).on_behalf_of(nodes[2].clone())) as Arc<dyn PeerApi>)
        .collect();
    assert!(repair_hosted_key(&nodes[2], &as_node2, "rutli-enc-3").await.unwrap());
    let ct = key.encrypt_oaep(b"after repair").unwrap();
    assert_eq!(nodes[2].hosted_decrypt("rutli-enc-3", &ct).unwrap(), b"after repair");
}

#[tokio::test]
async fn anti_entropy_pushes_a_key_to_a_node_that_missed_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);
    let partial: Peers = peers.iter().take(2).cloned().collect();
    generate_hosted_key(&nodes[0], &partial, "rutli-sym-3", HostedSpec::Aes256Gcm, DEFAULT_WRITE_QUORUM)
        .await
        .unwrap();
    assert!(!nodes[2].hosted_exists("rutli-sym-3"));

    // The sweep on the holder pushes what the peer lacks — this is what heals a 2-of-3 write.
    let (_pulled, pushed) = anti_entropy_sweep(&nodes[0], &peers).await.unwrap();
    assert!(pushed >= 1, "sweep should push the missing key");
    assert!(nodes[2].hosted_exists("rutli-sym-3"));

    // Converged: a second sweep has nothing to do.
    assert_eq!(anti_entropy_sweep(&nodes[0], &peers).await.unwrap(), (0, 0));
}

#[tokio::test]
async fn a_failed_write_quorum_rolls_back_instead_of_leaving_one_lonely_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    // Only the leader is available — below the write quorum of 2.
    let alone: Peers = peers.iter().take(1).cloned().collect();
    let err = generate_hosted_key(&nodes[0], &alone, "rutli-enc-4", HostedSpec::Rsa2048, 2)
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::ThresholdNotMet { .. }), "got {err:?}");

    // A single surviving copy is exactly what hosted keys exist to prevent, so the id must be free
    // for a clean retry rather than half-created.
    assert!(!nodes[0].hosted_exists("rutli-enc-4"), "under-quorum write must roll back");
}

#[tokio::test]
async fn hosted_keys_and_frost_shares_do_not_interfere() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    // A FROST namespace key and a hosted encryption key, side by side in the same keystore.
    let group_key = run_dkg(&peers, KEY_ID).await.unwrap();
    generate_hosted_key(&nodes[0], &peers, "rutli-enc-5", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
        .await
        .unwrap();

    // Threshold signing still works...
    let msg = canton_digest(b"topology tx");
    let sig = sign(&nodes[0], &peers, KEY_ID, &msg).await.unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&group_key)
        .unwrap()
        .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();

    // ...and the hosted inventory lists ONLY the hosted key. A FROST share must never be treated
    // as replicable: copying one would give two nodes the same share and break the threshold.
    assert_eq!(nodes[0].hosted_list().unwrap(), vec!["rutli-enc-5".to_string()]);
    assert!(nodes[0].hosted_load(KEY_ID).is_err(), "a FROST share must not load as a hosted key");
    assert!(nodes[0].hosted_delete(KEY_ID).is_err(), "the namespace key must not be deletable");
}

#[tokio::test]
async fn deleting_a_hosted_key_removes_it_cluster_wide() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);
    generate_hosted_key(&nodes[0], &peers, "rutli-enc-6", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
        .await
        .unwrap();

    assert!(delete_hosted_key(&peers, "rutli-enc-6").await.unwrap());
    for n in &nodes {
        assert!(!n.hosted_exists("rutli-enc-6"));
    }
    // Idempotent: deleting again is a no-op, not an error.
    assert!(!delete_hosted_key(&peers, "rutli-enc-6").await.unwrap());
}

#[tokio::test]
async fn hosted_keys_survive_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let ciphertext = {
        let (nodes, peers) = hosted_cluster(&tmp);
        let (key, _, _) = generate_hosted_key(
            &nodes[0],
            &peers,
            "rutli-enc-7",
            HostedSpec::Rsa2048,
            DEFAULT_WRITE_QUORUM,
        )
        .await
        .unwrap();
        key.encrypt_oaep(b"before restart").unwrap()
    }; // cluster dropped — as if every process exited

    // The whole point of the feature: rebuild from the same data dirs and still decrypt.
    let (reloaded, _) = hosted_cluster(&tmp);
    for n in &reloaded {
        assert_eq!(n.hosted_decrypt("rutli-enc-7", &ciphertext).unwrap(), b"before restart");
    }
}

/// A peer that is *unreachable* (transport-level), as opposed to one that refuses.
struct UnreachablePeer {
    id: Identifier,
}

/// A peer that always fails with one specific error — used to assert how the orchestrator
/// classifies "absent" versus "refusing".
struct FixedErrorPeer {
    id: Identifier,
    error: DaemonError,
}

#[async_trait]
impl PeerApi for UnreachablePeer {
    fn identifier(&self) -> Identifier {
        self.id
    }
    async fn sign_round1(&self, _: &str, _: &str) -> DaemonResult<SigningCommitments> {
        Err(down())
    }
    async fn sign_round2(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: &BTreeMap<Identifier, SigningCommitments>,
    ) -> DaemonResult<SignatureShare> {
        Err(down())
    }
    async fn abort_sign(&self, _: &str, _: &str) -> DaemonResult<()> {
        Err(down())
    }
    async fn ceremony_fence(&self, _: &str, _: &str, _: &'static str) -> DaemonResult<()> {
        Err(down())
    }
    async fn ceremony_release(&self, _: &str, _: &str) -> DaemonResult<()> {
        Err(down())
    }
    async fn dkg_part1(&self, _: &str, _: &str) -> DaemonResult<round1::Package> {
        Err(down())
    }
    async fn dkg_part2(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        Err(down())
    }
    async fn dkg_part3(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
        _: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        Err(down())
    }
    async fn refresh_part1(&self, _: &str, _: &str) -> DaemonResult<round1::Package> {
        Err(down())
    }
    async fn refresh_part2(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        Err(down())
    }
    async fn refresh_part3(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
        _: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        Err(down())
    }
    async fn node_info(&self) -> DaemonResult<(u16, [u8; 32])> {
        Err(down())
    }
    async fn replicate_key(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &[u8],
        _: &rutli_cosigner::wrap::Wrapped,
    ) -> DaemonResult<Vec<u8>> {
        Err(down())
    }
    async fn fetch_key(
        &self,
        _: &str,
    ) -> DaemonResult<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        Err(down())
    }
    async fn list_keys(&self) -> DaemonResult<Vec<(String, String, Vec<u8>)>> {
        Err(down())
    }
    async fn purge_key(&self, _: &str, _: &str) -> DaemonResult<bool> {
        Err(down())
    }
}

fn clone_err(e: &DaemonError) -> DaemonError {
    match e {
        DaemonError::Status(s) => DaemonError::Status(tonic::Status::new(s.code(), s.message())),
        DaemonError::CeremonyInProgress { key_id, kind, other } => DaemonError::CeremonyInProgress {
            key_id: key_id.clone(),
            kind,
            other: other.clone(),
        },
        _ => DaemonError::Config("unexpected".into()),
    }
}

#[async_trait]
impl PeerApi for FixedErrorPeer {
    fn identifier(&self) -> Identifier {
        self.id
    }
    async fn sign_round1(&self, _: &str, _: &str) -> DaemonResult<SigningCommitments> {
        Err(clone_err(&self.error))
    }
    async fn sign_round2(
        &self,
        _: &str,
        _: &str,
        _: &[u8],
        _: &BTreeMap<Identifier, SigningCommitments>,
    ) -> DaemonResult<SignatureShare> {
        Err(clone_err(&self.error))
    }
    async fn abort_sign(&self, _: &str, _: &str) -> DaemonResult<()> {
        Err(clone_err(&self.error))
    }
    async fn ceremony_fence(&self, _: &str, _: &str, _: &'static str) -> DaemonResult<()> {
        Err(clone_err(&self.error))
    }
    async fn ceremony_release(&self, _: &str, _: &str) -> DaemonResult<()> {
        Err(clone_err(&self.error))
    }
    async fn dkg_part1(&self, _: &str, _: &str) -> DaemonResult<round1::Package> {
        Err(clone_err(&self.error))
    }
    async fn dkg_part2(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        Err(clone_err(&self.error))
    }
    async fn dkg_part3(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
        _: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        Err(clone_err(&self.error))
    }
    async fn refresh_part1(&self, _: &str, _: &str) -> DaemonResult<round1::Package> {
        Err(clone_err(&self.error))
    }
    async fn refresh_part2(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
    ) -> DaemonResult<BTreeMap<Identifier, round2::Package>> {
        Err(clone_err(&self.error))
    }
    async fn refresh_part3(
        &self,
        _: &str,
        _: &BTreeMap<Identifier, round1::Package>,
        _: &BTreeMap<Identifier, round2::Package>,
    ) -> DaemonResult<[u8; 32]> {
        Err(clone_err(&self.error))
    }
    async fn node_info(&self) -> DaemonResult<(u16, [u8; 32])> {
        Err(clone_err(&self.error))
    }
    async fn replicate_key(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &[u8],
        _: &rutli_cosigner::wrap::Wrapped,
    ) -> DaemonResult<Vec<u8>> {
        Err(clone_err(&self.error))
    }
    async fn fetch_key(
        &self,
        _: &str,
    ) -> DaemonResult<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        Err(clone_err(&self.error))
    }
    async fn list_keys(&self) -> DaemonResult<Vec<(String, String, Vec<u8>)>> {
        Err(clone_err(&self.error))
    }
    async fn purge_key(&self, _: &str, _: &str) -> DaemonResult<bool> {
        Err(clone_err(&self.error))
    }
}

/// What a stopped cosigner ACTUALLY produces over a real gRPC channel.
///
/// Not `Unavailable`, as one would assume (and as an earlier version of this test asserted, which
/// is why the live cluster still failed): tonic surfaces a connection that died below the RPC layer
/// as `Unknown` with the message "transport error".
fn down() -> DaemonError {
    DaemonError::Status(tonic::Status::unknown("transport error"))
}

/// The other shapes an unreachable peer can take, all of which must classify the same way.
fn down_variants() -> Vec<DaemonError> {
    vec![
        DaemonError::Status(tonic::Status::unknown("transport error")),
        DaemonError::Status(tonic::Status::unavailable("dns error")),
        DaemonError::Status(tonic::Status::deadline_exceeded("timed out")),
    ]
}

#[tokio::test]
async fn a_hosted_key_can_be_generated_with_one_cosigner_unreachable() {
    // Regression (found only in a live cluster, not by the in-process tests): the cluster-wide
    // ceremony fence aborted on the FIRST unreachable peer, so a write could never complete with a
    // node down — which is exactly what write_quorum = 2 of 3 exists to allow. A node that is down
    // cannot start a racing operation, so it must be skipped, not treated as a conflict.
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    let degraded: Peers = vec![
        peers[0].clone(),
        peers[1].clone(),
        Arc::new(UnreachablePeer { id: nodes[2].identifier }) as Arc<dyn PeerApi>,
    ];

    let (key, created, replicas) = generate_hosted_key(
        &nodes[0],
        &degraded,
        "rutli-enc-degraded",
        HostedSpec::Rsa2048,
        DEFAULT_WRITE_QUORUM,
    )
    .await
    .expect("a 2-of-3 write must succeed with one node unreachable");
    assert!(created);
    assert_eq!(replicas, 2, "two live nodes hold it; the third is down");

    // The key works on both live nodes...
    let ct = key.encrypt_oaep(b"written while degraded").unwrap();
    assert_eq!(nodes[1].hosted_decrypt("rutli-enc-degraded", &ct).unwrap(), b"written while degraded");

    // ...and the node that was down is healed once it is back, without operator action.
    let (_pulled, pushed) = anti_entropy_sweep(&nodes[0], &peers).await.unwrap();
    assert!(pushed >= 1);
    assert_eq!(nodes[2].hosted_decrypt("rutli-enc-degraded", &ct).unwrap(), b"written while degraded");
}

#[tokio::test]
async fn a_hosted_write_still_fails_when_too_few_cosigners_are_reachable() {
    // The flip side: tolerating unreachable peers must not silently drop below the write quorum.
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _peers) = hosted_cluster(&tmp);
    let mostly_down: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
        Arc::new(UnreachablePeer { id: nodes[1].identifier }) as Arc<dyn PeerApi>,
        Arc::new(UnreachablePeer { id: nodes[2].identifier }) as Arc<dyn PeerApi>,
    ];
    let err =
        generate_hosted_key(&nodes[0], &mostly_down, "rutli-enc-lonely", HostedSpec::Rsa2048, 2)
            .await
            .unwrap_err();
    assert!(matches!(err, DaemonError::ThresholdNotMet { .. }), "got {err:?}");
    assert!(!nodes[0].hosted_exists("rutli-enc-lonely"));
}

#[tokio::test]
async fn anti_entropy_publishes_the_replica_shortfall() {
    // The rutli_key_replicas gauge is what makes a write quorum below n safe to default to: a
    // transiently under-replicated key is fine, one that STAYS under-replicated must page. The
    // sweep is what measures it, so it must count correctly both before and after healing.
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);
    let partial: Peers = peers.iter().take(2).cloned().collect();
    generate_hosted_key(&nodes[0], &partial, "rutli-enc-count", HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
        .await
        .unwrap();

    // Before healing: node 3 lacks the key, so the sweep both repairs it and reports the count.
    let (_pulled, pushed) = anti_entropy_sweep(&nodes[0], &peers).await.unwrap();
    assert!(pushed >= 1, "the sweep should have pushed the missing replica");

    // After healing every node holds it, and a second sweep is a no-op.
    assert_eq!(anti_entropy_sweep(&nodes[0], &peers).await.unwrap(), (0, 0));
    for n in &nodes {
        assert!(n.hosted_exists("rutli-enc-count"));
    }
}

#[tokio::test]
async fn every_shape_of_unreachable_peer_is_tolerated_by_a_hosted_write() {
    // Regression: the first fix only recognised Unavailable/DeadlineExceeded, but a stopped
    // cosigner reports Unknown("transport error"), so the live cluster still refused to write with
    // a node down. Assert every shape, not just the one that was assumed.
    for (i, variant) in down_variants().into_iter().enumerate() {
        let tmp = tempfile::tempdir().unwrap();
        let (nodes, _peers) = hosted_cluster(&tmp);
        let degraded: Peers = vec![
            Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
            Arc::new(LocalPeer::new(nodes[1].clone())) as Arc<dyn PeerApi>,
            Arc::new(FixedErrorPeer { id: nodes[2].identifier, error: variant }) as Arc<dyn PeerApi>,
        ];
        let key_id = format!("rutli-enc-shape-{i}");
        let (_key, created, replicas) =
            generate_hosted_key(&nodes[0], &degraded, &key_id, HostedSpec::Rsa2048, DEFAULT_WRITE_QUORUM)
                .await
                .unwrap_or_else(|e| panic!("variant {i} must be tolerated, got {e:?}"));
        assert!(created);
        assert_eq!(replicas, 2);
    }
}

#[tokio::test]
async fn a_peer_that_refuses_still_aborts_a_hosted_write() {
    // The other side of the same coin: tolerating *absence* must never tolerate a genuine conflict,
    // or two leaders could write the same key id concurrently.
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _peers) = hosted_cluster(&tmp);
    let conflicted: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
        Arc::new(LocalPeer::new(nodes[1].clone())) as Arc<dyn PeerApi>,
        Arc::new(FixedErrorPeer {
            id: nodes[2].identifier,
            error: DaemonError::CeremonyInProgress {
                key_id: "rutli-enc-conflict".into(),
                kind: "refresh",
                other: "someone-else".into(),
            },
        }) as Arc<dyn PeerApi>,
    ];
    let err = generate_hosted_key(
        &nodes[0],
        &conflicted,
        "rutli-enc-conflict",
        HostedSpec::Rsa2048,
        DEFAULT_WRITE_QUORUM,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "got {err:?}");
    assert!(!nodes[0].hosted_exists("rutli-enc-conflict"));
}

/// A commitment is compared across nodes (replication acks, anti-entropy), so it must be identical
/// on every node, and byte-identical to what 0.3.1 nodes computed (they all keyed it off the
/// distribution key for index 0) so a mixed-version cluster still agrees during a rolling upgrade.
#[tokio::test]
async fn hosted_commitments_are_node_independent_and_match_the_031_value() {
    use sha2::{Digest, Sha256};
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _peers) = hosted_cluster(&tmp);
    let key = rutli_cosigner::hosted::HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();

    let legacy = {
        let mut h = Sha256::new();
        h.update(b"rutli-keycommit-v1");
        h.update(rutli_cosigner::wrap::DistKey::derive(HOSTED_MASTER, 0).public_bytes());
        h.update(key.spec.as_str().as_bytes());
        h.update(key.private_der.as_bytes());
        h.finalize().to_vec()
    };
    for n in &nodes {
        assert_eq!(n.hosted_commitment(&key).unwrap(), legacy);
    }
}

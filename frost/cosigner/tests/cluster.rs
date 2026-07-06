// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Exercises the daemon's DKG + signing orchestration across a 3-node cluster wired with
//! in-process peers (LocalPeer). This covers node state, the orchestrator, and the keystore —
//! everything except the tonic transport — and verifies the output with a strict independent
//! Ed25519 verifier.

use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::keystore::KeyStore;
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

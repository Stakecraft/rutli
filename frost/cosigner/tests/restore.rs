// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Audit M1: restore is epoch-checked, verified before it writes anything, atomic per file and
//! lock-guarded — and a node restored by break-glass is caught by the stale-share check.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use frost_ed25519::Identifier;

use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::restore::{apply, plan, BreakGlass};
use rutli_cosigner::seal::{KeyFileBinding, Sealer};

const N: u16 = 3;
const T: u16 = 2;
const KEY: &str = "frost-participant1-namespace";
const MASTER: &[u8] = b"restore test cluster master secret";
const UUID: &str = "5a1f2e3d-4c5b-4a69-8778-9a0b1c2d3e4f";

fn sealer(node: u16, cluster: &str) -> Arc<Sealer> {
    Arc::new(Sealer::from_master_secret(MASTER, node).with_binding(KeyFileBinding {
        node,
        cluster_uuid: Some(cluster.into()),
        write_version: 2,
        accept_v1: true,
    }))
}

fn keys(root: &Path, i: u16) -> PathBuf {
    root.join(format!("node-{i}")).join("keys")
}

fn store(root: &Path, i: u16) -> KeyStore {
    KeyStore::open_with_sealer(keys(root, i), Some(sealer(i, UUID))).unwrap()
}

/// A 2-of-3 cluster with `KEY` DKG'd (epoch 1); its nodes and in-process peers.
async fn cluster(root: &Path) -> (Vec<Arc<Node>>, Peers) {
    let nodes: Vec<Arc<Node>> =
        (1..=N).map(|i| Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, store(root, i)))).collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    run_dkg(&peers, KEY).await.unwrap();
    (nodes, peers)
}

/// Copy node `i`'s committed key files into a fresh backup directory.
fn backup(root: &Path, i: u16, name: &str) -> PathBuf {
    let out = root.join(name);
    std::fs::create_dir_all(&out).unwrap();
    for e in std::fs::read_dir(keys(root, i)).unwrap() {
        let e = e.unwrap();
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".json") && !n.starts_with('.') {
            std::fs::copy(e.path(), out.join(&n)).unwrap();
        }
    }
    out
}

fn refused<T: std::fmt::Debug>(r: rutli_cosigner::Result<T>, needle: &str) -> String {
    let e = r.expect_err("must be refused").to_string();
    assert!(e.contains(needle), "expected {needle:?} in {e}");
    e
}

#[tokio::test]
async fn an_older_epoch_is_refused_even_with_force_and_break_glass_is_caught_by_the_stale_check() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (nodes, peers) = cluster(root).await;
    let old = backup(root, 1, "backup-epoch1");
    run_refresh(&peers, KEY).await.unwrap(); // every node now on epoch 2
    let live_before = std::fs::read(keys(root, 1).join(format!("{KEY}.json"))).unwrap();

    let ks = store(root, 1);
    let e = refused(plan(&ks, &old, true, None), "refused even with --force");
    assert!(e.contains("epoch 1") && e.contains("--break-glass --key-id"), "{e}");
    // The break-glass must name exactly this backup.
    let digest = e.split("--expected-digest ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    let wrong = BreakGlass { key_id: KEY.into(), expected_epoch: 1, expected_digest: "00".repeat(32) };
    refused(plan(&ks, &old, false, Some(&wrong)), "does not name this backup");
    assert_eq!(std::fs::read(keys(root, 1).join(format!("{KEY}.json"))).unwrap(), live_before, "nothing written");

    // BREAK-GLASS: installed — and the node, restarted, finds its share behind its peers and
    // refuses to sign with it (the phase-2 stale check).
    let glass = BreakGlass { key_id: KEY.into(), expected_epoch: 1, expected_digest: digest };
    let p = plan(&ks, &old, false, Some(&glass)).unwrap();
    assert_eq!(p.broke_glass, vec![KEY.to_string()]);
    assert_eq!(apply(&ks, &p, false).unwrap(), 1);
    let restarted = Arc::new(Node::new(Identifier::try_from(1).unwrap(), N, T, store(root, 1)));
    let mesh: Peers = std::iter::once(Arc::new(LocalPeer::new(restarted.clone())) as Arc<dyn PeerApi>)
        .chain(peers.iter().skip(1).cloned())
        .collect();
    restarted.set_mesh(mesh).unwrap();
    rutli_cosigner::epoch_check::check_all(&restarted).await;
    assert!(restarted.stale_mark(KEY).is_some(), "the restored share must be marked stale");
    drop(nodes);
}

#[tokio::test]
async fn a_newer_epoch_needs_force_and_the_same_sharing_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_nodes, peers) = cluster(root).await;
    let same = backup(root, 1, "backup-same");
    let ks = store(root, 1);
    let p = plan(&ks, &same, false, None).unwrap();
    assert!(p.install.is_empty() && p.skipped.len() == 1, "{p:?}");

    // A backup ahead of the live share (the live file rolled back by a volume snapshot): forward
    // needs --force, and is allowed with it.
    let epoch1 = backup(root, 1, "backup-epoch1");
    run_refresh(&peers, KEY).await.unwrap();
    let epoch2 = backup(root, 1, "backup-epoch2");
    std::fs::copy(epoch1.join(format!("{KEY}.json")), keys(root, 1).join(format!("{KEY}.json"))).unwrap();
    assert_eq!(ks.load(KEY).unwrap().epoch, 1);
    refused(plan(&ks, &epoch2, false, None), "pass --force");
    let p = plan(&ks, &epoch2, true, None).unwrap();
    assert_eq!(p.install.len(), 1);
    apply(&ks, &p, false).unwrap();
    assert_eq!(ks.load(KEY).unwrap().epoch, 2);
}

#[tokio::test]
async fn a_deleted_live_file_does_not_let_an_old_epoch_back_in() {
    // The live file is gone (deleted by hand, lost), but this node's ceremony records say it
    // committed epoch 2: an epoch-1 backup is still a rollback.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_nodes, peers) = cluster(root).await;
    let old = backup(root, 1, "backup-epoch1");
    run_refresh(&peers, KEY).await.unwrap();
    std::fs::remove_file(keys(root, 1).join(format!("{KEY}.json"))).unwrap();
    refused(plan(&store(root, 1), &old, true, None), "this node committed epoch 2");
}

#[tokio::test]
async fn files_of_another_node_or_cluster_and_plaintext_files_are_refused_and_nothing_is_written() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    cluster(root).await;
    let ks = store(root, 1);
    // A good, new hosted key in the backup next to a bad file: one refusal refuses everything.
    let mixed = root.join("mixed");
    std::fs::create_dir_all(&mixed).unwrap();
    let other = KeyStore::open_with_sealer(root.join("scratch"), Some(sealer(1, UUID))).unwrap();
    other.save_hosted("rutli-new", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
    std::fs::copy(root.join("scratch").join("rutli-new.json"), mixed.join("rutli-new.json")).unwrap();
    // Node 2's share in node 1's backup.
    std::fs::copy(keys(root, 2).join(format!("{KEY}.json")), mixed.join(format!("{KEY}.json"))).unwrap();
    refused(plan(&ks, &mixed, true, None), "belongs to node 2");
    assert!(!keys(root, 1).join("rutli-new.json").exists());

    // Another cluster's file.
    let foreign = root.join("foreign");
    std::fs::create_dir_all(&foreign).unwrap();
    let theirs = KeyStore::open_with_sealer(root.join("scratch2"), Some(sealer(1, "11111111-2222-4333-8444-555555555555"))).unwrap();
    theirs.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
    std::fs::copy(root.join("scratch2").join("rutli-x.json"), foreign.join("rutli-x.json")).unwrap();
    refused(plan(&ks, &foreign, true, None), "another cluster");

    // A file renamed to another key id.
    let renamed = root.join("renamed");
    std::fs::create_dir_all(&renamed).unwrap();
    std::fs::copy(root.join("scratch").join("rutli-new.json"), renamed.join("rutli-other.json")).unwrap();
    refused(plan(&ks, &renamed, true, None), "holds key rutli-new");

    // A plaintext file under sealing.
    let plain = root.join("plain");
    KeyStore::open(&plain).unwrap().save_hosted("rutli-p", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
    refused(plan(&ks, &plain, true, None), "PLAINTEXT");
}

#[tokio::test]
async fn a_tombstoned_key_is_not_restored_without_break_glass() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    cluster(root).await;
    let ks = store(root, 1);
    let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
    ks.save_hosted("rutli-gone", &key).unwrap();
    let before = backup(root, 1, "backup-before-delete");
    // The key is deleted: its file is now a tombstone.
    let t = rutli_cosigner::hosted::Tombstone {
        key_id: "rutli-gone".into(),
        spec: "aes-256-gcm".into(),
        created_at: 1,
        commitment: String::new(),
        deleted_at_ms: 1,
        purge_after_ms: 2,
        delete_intent: hex::encode(prost::Message::encode_to_vec(&rutli_cosigner::pb::SignedIntent {
            intent: vec![1, 2, 3],
            ..Default::default()
        })),
        retained: None,
    };
    ks.save_tombstone("rutli-gone", &t).unwrap();
    let e = refused(plan(&ks, &before, true, None), "TOMBSTONE");
    let digest = e.split("--expected-digest ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    let glass = BreakGlass { key_id: "rutli-gone".into(), expected_epoch: 0, expected_digest: digest };
    let p = plan(&ks, &before, false, Some(&glass)).unwrap();
    apply(&ks, &p, false).unwrap();
    assert_eq!(ks.load_hosted("rutli-gone").unwrap().private_der, key.private_der);
}

#[tokio::test]
async fn a_crash_before_the_install_leaves_the_live_store_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    cluster(root).await;
    let ks = store(root, 1);
    let src = KeyStore::open_with_sealer(root.join("scratch"), Some(sealer(1, UUID))).unwrap();
    for id in ["rutli-a", "rutli-b"] {
        src.save_hosted(id, &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
    }
    let p = plan(&ks, &root.join("scratch"), false, None).unwrap();
    assert_eq!(p.install.len(), 2);
    assert!(apply(&ks, &p, true).is_err());
    assert!(!keys(root, 1).join("rutli-a.json").exists() && !keys(root, 1).join("rutli-b.json").exists());
    assert!(ks.list_hosted().unwrap().is_empty(), "a staging dir is never inventory");
    // The next restore sweeps the leftover staging directory and completes.
    assert_eq!(apply(&ks, &p, false).unwrap(), 2);
    let leftovers: Vec<_> = std::fs::read_dir(keys(root, 1))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(rutli_cosigner::restore::STAGING_PREFIX))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert_eq!(ks.list_hosted().unwrap(), vec!["rutli-a".to_string(), "rutli-b".to_string()]);
}

/// Audit F7: a backup carries the break-glass "cleared delete intent" markers, and a restore merges
/// them (never removes one), so a node restored after an undelete keeps ignoring that tombstone.
#[tokio::test]
async fn cleared_markers_in_a_backup_are_merged_on_restore() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    cluster(root).await;
    let ks = store(root, 1);
    let from = backup(root, 1, "with-markers");
    let digest = "ab".repeat(32);
    std::fs::create_dir_all(from.join(".cleared")).unwrap();
    std::fs::write(from.join(".cleared").join(format!("rutli-x.{digest}")), b"").unwrap();
    std::fs::write(from.join(".cleared").join("not-a-marker"), b"").unwrap();
    std::fs::write(from.join(".cleared").join("../escape.aa"), b"").ok();
    let p = plan(&ks, &from, false, None).unwrap();
    assert_eq!(p.cleared, vec![format!("rutli-x.{digest}")]);
    apply(&ks, &p, false).unwrap();
    let mut d = [0u8; 32];
    d.copy_from_slice(&hex::decode(&digest).unwrap());
    assert!(ks.is_cleared("rutli-x", &d).unwrap());
    assert!(!keys(root, 1).join(".cleared").join("not-a-marker").exists());
    // Idempotent.
    apply(&ks, &p, false).unwrap();
}

#[test]
fn the_restore_command_takes_the_instance_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("cfg.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": 1, "listen": "127.0.0.1:0", "threshold": 2, "data_dir": tmp.path().join("data"),
            "peers": (1..=3).map(|j| serde_json::json!({"identifier": j, "endpoint": format!("http://127.0.0.1:{}", 19400 + j)})).collect::<Vec<_>>(),
        })
        .to_string(),
    )
    .unwrap();
    std::fs::create_dir_all(tmp.path().join("backup")).unwrap();
    std::fs::create_dir_all(tmp.path().join("data")).unwrap();
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&tmp.path().join("data")).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .args(["--config", cfg.to_str().unwrap(), "restore", "--from", tmp.path().join("backup").to_str().unwrap()])
        .env_remove("RUTLI_COSIGNER_CONFIG")
        .output()
        .unwrap();
    assert!(!out.status.success(), "a restore must not run under a live daemon");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("already in use by another rutli-cosigner process"), "{text}");
}

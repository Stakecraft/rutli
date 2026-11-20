// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `residue-scan`: one fixture per finding class, tars (mixed epochs, unreadable), the legacy
//! master, the fields the output may carry, and a scan running next to a signing cluster.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use frost_ed25519::Identifier;
use zeroize::Zeroizing;

use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::residue::{scan, Class, Report, ScanInput, NOT_CHECKED};
use rutli_cosigner::seal::{derive_share_dek, KeyFileBinding, NodeSealBundle, RecordKind, RecordMeta, Sealer};

const UUID: &str = "6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b";
/// Put inside every plaintext fixture: it must never reach the output.
const MARKER: &str = "PLAINTEXT-SHARE-MARKER-7f3a";

fn binding(node: u16) -> KeyFileBinding {
    KeyFileBinding { node, cluster_uuid: Some(UUID.into()), write_version: 2, accept_v1: true }
}

fn sealer_of(bundle: &NodeSealBundle) -> Sealer {
    bundle.sealer().with_binding(binding(1))
}

fn v2(s: &Sealer, kind: RecordKind, key_id: &str, epoch: u64) -> Vec<u8> {
    let plain = serde_json::json!({ "opaque": MARKER }).to_string();
    s.seal_record_as(2, &RecordMeta { kind, key_id, epoch, digest: &[] }, plain.as_bytes()).unwrap()
}

fn v1(s: &Sealer, epoch: u64) -> Vec<u8> {
    s.seal(serde_json::json!({ "key_package": { "x": MARKER }, "epoch": epoch }).to_string().as_bytes()).unwrap()
}

fn plaintext_share(epoch: u64) -> Vec<u8> {
    serde_json::json!({ "key_package": { "x": MARKER }, "epoch": epoch }).to_string().into_bytes()
}

fn put(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn run(dd: &Path, sealer: Option<&Sealer>, backups: &[PathBuf], legacy: Option<Zeroizing<[u8; 32]>>) -> Report {
    scan(&ScanInput {
        data_dir: dd,
        node: 1,
        cluster_uuid: Some(UUID),
        sealer,
        backups,
        legacy_dek: legacy,
        config_names_secret_env: false,
    })
}

/// (class, path relative to `root`) of every finding.
fn found(r: &Report, root: &Path) -> BTreeSet<(Class, String)> {
    let root = root.to_string_lossy().into_owned();
    r.findings
        .iter()
        .map(|f| (f.class, f.path.strip_prefix(&root).unwrap_or(&f.path).trim_start_matches('/').to_string()))
        .collect()
}

fn set(items: &[(Class, &str)]) -> BTreeSet<(Class, String)> {
    items.iter().map(|(c, p)| (*c, p.to_string())).collect()
}

// ── tar writer (test only) ─────────────────────────────────────────────────────────────────────

fn tar_header(name: &str, size: usize, typeflag: u8) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| *b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn tar_add(out: &mut Vec<u8>, name: &str, data: &[u8], typeflag: u8) {
    out.extend_from_slice(&tar_header(name, data.len(), typeflag));
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
}

fn pax(path: &str) -> Vec<u8> {
    let body = format!(" path={path}\n");
    let mut len = body.len() + 1;
    while format!("{len}{body}").len() != len {
        len += 1;
    }
    format!("{len}{body}").into_bytes()
}

fn tar_end(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0u8; 1024]);
}

// ── fixtures ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_clean_store_finds_nothing_and_still_lists_what_was_not_checked() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path();
    let s = sealer_of(&NodeSealBundle::random(1));
    put(&dd.join("keys/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 3));
    put(&dd.join("keys/rutli-h.json"), &v2(&s, RecordKind::HostedKey, "rutli-h", 0));
    put(&dd.join("keys/frost-b.json"), &v1(&s, 1));
    std::fs::create_dir_all(dd.join("keys/.ceremonies")).unwrap();
    std::fs::create_dir_all(dd.join("keys/.cleared")).unwrap();
    std::fs::create_dir_all(dd.join("keys/frost-a.nonces")).unwrap();
    put(&dd.join("journal/seg-0001.jsonl"), b"{}\n");
    put(&dd.join("cluster-id"), b"abc");
    put(&dd.join(".rutli-cosigner.lock"), b"");
    // A current backup: same epoch, current DEK. Expected, not residue.
    let backup = tempfile::tempdir().unwrap();
    put(&backup.path().join("frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 3));
    put(&backup.path().join("frost-b.json"), &v1(&s, 1));

    let r = run(dd, Some(&s), &[backup.path().to_path_buf()], None);
    assert!(r.findings.is_empty() && r.unclassified.is_empty() && r.errors.is_empty(), "{}", r.text());
    assert_eq!(r.exit_code(), 0);
    assert_eq!((r.live.frost, r.live.hosted, r.live.tombstones), (2, 1, 0));
    for n in NOT_CHECKED {
        assert!(r.not_checked.iter().any(|x| x == n), "{n}");
    }
    let text = r.text();
    assert!(text.contains("nothing found on the paths given") && text.contains("NOT CHECKED"), "{text}");
    assert!(!text.contains("destroyed"), "{text}");
}

#[test]
fn every_class_on_the_volume_and_in_a_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    let old = NodeSealBundle::random(1);
    let now = old.rotated();
    let (s_old, s) = (sealer_of(&old), sealer_of(&now));

    // Live store.
    put(&dd.join("keys/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 3));
    put(&dd.join("keys/frost-b.json"), &v1(&s, 1));
    put(&dd.join("keys/frost-plain.json"), &plaintext_share(1));
    put(&dd.join("keys/frost-olddek.json"), &v2(&s_old, RecordKind::FrostShare, "frost-olddek", 2));
    put(&dd.join("keys/rutli-h.json"), &v2(&s, RecordKind::HostedKey, "rutli-h", 0));
    put(&dd.join("keys/rutli-t.json"), &v2(&s, RecordKind::Tombstone, "rutli-t", 0));
    put(&dd.join("keys/frost-a.json.tmp"), &v2(&s, RecordKind::FrostShare, "frost-a", 3));
    put(&dd.join("keys/.create-frost-c-1.tmp"), b"partial");
    // Staged: cer1 has no record (orphan), cer2 is in progress.
    put(&dd.join("keys/.staged/frost-a.cer1.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 4));
    put(&dd.join("keys/.staged/frost-a.cer2.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 4));
    put(
        &dd.join("keys/.ceremonies/cer2.json"),
        serde_json::json!({ "ceremony_id": "cer2", "state": "staged", "key_id": "frost-a" }).to_string().as_bytes(),
    );
    // Split-ceremony material, leftovers, lost+found.
    put(&dd.join("ceremony/frost-z.recipient"), &v2(&s, RecordKind::Recipient, "frost-z", 0));
    put(&dd.join("backup-1/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 2));
    put(&dd.join("retired-2026-07/frost-gone.json"), &v2(&s, RecordKind::FrostShare, "frost-gone", 5));
    put(&dd.join("lost+found/#1234"), b"orphaned inode");

    // A backup directory.
    let bk = tmp.path().join("bk");
    put(&bk.join("frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 3)); // current: nothing
    put(&bk.join("rutli-h.json"), &v2(&s, RecordKind::HostedKey, "rutli-h", 0));
    put(&bk.join("old/frost-b.json"), &v1(&s_old, 1)); // v1 the current DEK does not open
    put(&bk.join("journal/seg-0001.jsonl"), b"{}\n"); // not a candidate: ignored

    let r = run(&dd, Some(&s), std::slice::from_ref(&bk), None);
    assert!(r.errors.is_empty(), "{}", r.text());
    let got = found(&r, tmp.path());
    let want = set(&[
        (Class::Plaintext, "data/keys/frost-plain.json"),
        (Class::NonCurrentDek, "data/keys/frost-olddek.json"),
        (Class::Tombstone, "data/keys/rutli-t.json"),
        (Class::TempFile, "data/keys/frost-a.json.tmp"),
        (Class::TempFile, "data/keys/.create-frost-c-1.tmp"),
        (Class::StagedOrphan, "data/keys/.staged/frost-a.cer1.json"),
        (Class::CeremonyMaterial, "data/ceremony/frost-z.recipient"),
        (Class::OtherDir, "data/backup-1"),
        (Class::OlderEpoch, "data/backup-1/frost-a.json"),
        (Class::OtherDir, "data/retired-2026-07"),
        (Class::NotLiveKey, "data/retired-2026-07/frost-gone.json"),
        (Class::LostFound, "data/lost+found"),
        (Class::HostedCopy, "bk/rutli-h.json"),
        (Class::NonCurrentDek, "bk/old/frost-b.json"),
    ]);
    assert_eq!(got, want, "{}", r.text());
    assert_eq!(r.exit_code(), 1);
    // The plaintext finding comes first (most severe), and hosted copies say what a copy means.
    assert_eq!(r.findings[0].class, Class::Plaintext);
    let hosted = r.findings.iter().find(|f| f.class == Class::HostedCopy).unwrap();
    assert!(hosted.note.unwrap().contains("no threshold at rest") && hosted.key_id.as_deref() == Some("rutli-h"));
    let tomb = r.findings.iter().find(|f| f.class == Class::Tombstone).unwrap();
    assert!(tomb.note.unwrap().contains("no threshold at rest") && tomb.key_id.as_deref() == Some("rutli-t"));
    let older = r.findings.iter().find(|f| f.class == Class::OlderEpoch).unwrap();
    assert_eq!((older.key_id.as_deref(), older.epoch, older.dek.clone()), (Some("frost-a"), Some(2), Some(s.current_dek_id())));
    let text = r.text();
    assert!(text.contains(&format!("[finding] older-epoch: {}", dd.join("backup-1/frost-a.json").display())), "{text}");
}

#[test]
fn a_mixed_epoch_tar_is_read_in_place_and_its_names_never_touch_the_filesystem() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    let s = sealer_of(&NodeSealBundle::random(1));
    put(&dd.join("keys/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 5));

    let mut t = Vec::new();
    tar_add(&mut t, "./frost-a.json", &v2(&s, RecordKind::FrostShare, "frost-a", 5), b'0');
    tar_add(&mut t, "old/frost-a.json", &v2(&s, RecordKind::FrostShare, "frost-a", 4), b'0');
    // A pax name that climbs out of the archive: reported as text, never opened or written.
    let escape = "../../../../etc/frost-a.json";
    tar_add(&mut t, "PaxHeaders/x", &pax(escape), b'x');
    tar_add(&mut t, "ignored-name", &v2(&s, RecordKind::FrostShare, "frost-a", 3), b'0');
    tar_add(&mut t, "journal/seg-0001.jsonl", b"{}\n", b'0');
    tar_add(&mut t, "dir/", b"", b'5');
    tar_end(&mut t);
    let tar = tmp.path().join("node-1-20261120.tar");
    std::fs::write(&tar, &t).unwrap();

    let r = run(&dd, Some(&s), std::slice::from_ref(&tar), None);
    assert!(r.errors.is_empty(), "{}", r.text());
    let shown = tar.to_string_lossy();
    let older: Vec<_> = r.findings.iter().filter(|f| f.class == Class::OlderEpoch).map(|f| (f.path.clone(), f.epoch)).collect();
    assert_eq!(
        older,
        vec![(format!("{shown}!{escape}"), Some(3)), (format!("{shown}!old/frost-a.json"), Some(4))],
        "{}",
        r.text()
    );
    assert_eq!(r.findings.len(), 2, "{}", r.text());
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn an_unreadable_tar_is_a_read_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    std::fs::create_dir_all(&dd).unwrap();
    let s = sealer_of(&NodeSealBundle::random(1));

    let mut good = Vec::new();
    tar_add(&mut good, "frost-a.json", &v2(&s, RecordKind::FrostShare, "frost-a", 1), b'0');
    tar_end(&mut good);

    // A flipped header byte: the checksum no longer matches.
    let mut bad_sum = good.clone();
    bad_sum[10] ^= 0x01;
    // Cut short: no end-of-archive marker.
    let truncated = good[..700].to_vec();
    for (name, bytes) in [("bad-sum.tar", bad_sum), ("truncated.tar", truncated)] {
        let p = tmp.path().join(name);
        std::fs::write(&p, &bytes).unwrap();
        let r = run(&dd, Some(&s), std::slice::from_ref(&p), None);
        assert_eq!(r.exit_code(), 2, "{name}: {}", r.text());
        assert_eq!(r.errors.len(), 1, "{name}");
        assert!(r.errors[0].error.contains("not a readable tar"), "{name}: {}", r.errors[0].error);
        assert!(r.text().contains("the scan is incomplete"), "{name}");
    }
}

#[test]
fn a_symlink_is_reported_and_never_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    std::fs::create_dir_all(dd.join("keys")).unwrap();
    let s = sealer_of(&NodeSealBundle::random(1));
    let outside = tmp.path().join("outside.json");
    std::fs::write(&outside, plaintext_share(1)).unwrap();
    let bk = tmp.path().join("bk");
    std::fs::create_dir_all(&bk).unwrap();
    std::os::unix::fs::symlink(&outside, bk.join("frost-x.json")).unwrap();

    let r = run(&dd, Some(&s), std::slice::from_ref(&bk), None);
    assert!(r.findings.is_empty(), "{}", r.text());
    assert_eq!(r.unclassified.len(), 1);
    assert!(r.unclassified[0].reason.contains("symbolic link"), "{:?}", r.unclassified);
}

#[test]
fn the_legacy_master_derivation_is_found_in_constant_time_and_never_printed() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    let master = "legacy-master-for-the-test-0123456789abcdef";
    // A node split from the legacy master and never rotated: its DEK is the derivation.
    let bundle = NodeSealBundle::from_legacy_master(master.as_bytes(), 1);
    let s = sealer_of(&bundle);
    put(&dd.join("keys/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 1));

    let r = run(&dd, Some(&s), &[], Some(derive_share_dek(master.as_bytes(), 1)));
    let f: Vec<_> = r.findings.iter().filter(|f| f.class == Class::LegacyMasterDek).collect();
    assert_eq!(f.len(), 1, "{}", r.text());
    assert_eq!(f[0].path, "share_seal: the current DEK");
    assert_eq!(f[0].dek.as_deref(), Some(s.current_dek_id().as_str()));

    // Rotated once: the derivation is now a previous DEK, still reported.
    let rotated = sealer_of(&bundle.rotated());
    let r = run(&dd, Some(&rotated), &[], Some(derive_share_dek(master.as_bytes(), 1)));
    assert!(r.findings.iter().any(|f| f.class == Class::LegacyMasterDek && f.path == "share_seal: previous DEK 0"), "{}", r.text());

    // Another master: nothing.
    let r = run(&dd, Some(&s), &[], Some(derive_share_dek(b"some-other-master-0123456789abcdef", 1)));
    assert!(!r.findings.iter().any(|f| f.class == Class::LegacyMasterDek), "{}", r.text());

    // A config on secret_env scanned without the flag says so in NOT CHECKED.
    let r = scan(&ScanInput {
        data_dir: &dd,
        node: 1,
        cluster_uuid: Some(UUID),
        sealer: Some(&s),
        backups: &[],
        legacy_dek: None,
        config_names_secret_env: true,
    });
    assert!(r.not_checked.iter().any(|n| n.starts_with("legacy-master check not done")), "{:?}", r.not_checked);
    assert!(r.text().contains("legacy-master check not done"));
}

#[test]
fn the_output_carries_only_the_allowed_fields_and_no_key_material() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    let master = "legacy-master-for-the-output-test-0123456789";
    let bundle = NodeSealBundle::from_legacy_master(master.as_bytes(), 1);
    let s = sealer_of(&bundle);
    put(&dd.join("keys/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 2));
    put(&dd.join("keys/frost-plain.json"), &plaintext_share(1));
    put(&dd.join("keys/frost-b.json"), &v1(&s, 1));
    put(&dd.join("backup-1/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 1));
    put(&dd.join("backup-1/rutli-h.json"), &v2(&s, RecordKind::HostedKey, "rutli-h", 0));
    put(&dd.join("keys/stray"), b"x");

    let r = run(&dd, Some(&s), &[tmp.path().join("missing-backup")], Some(derive_share_dek(master.as_bytes(), 1)));
    let json = serde_json::to_value(&r).unwrap();
    let keys = |v: &serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<BTreeSet<_>>();
    let names = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(
        keys(&json),
        names(&["schema", "node", "data_dir", "backups", "findings", "unclassified", "errors", "changed", "live", "not_checked", "exit"])
    );
    assert_eq!(json["schema"], "rutli-residue-scan/1");
    assert_eq!(keys(&json["live"]), names(&["frost", "hosted", "tombstones"]));
    for f in json["findings"].as_array().unwrap() {
        assert_eq!(keys(f), names(&["class", "path", "key_id", "epoch", "dek", "note"]));
    }
    for u in json["unclassified"].as_array().unwrap() {
        assert_eq!(keys(u), names(&["path", "reason"]));
    }
    for c in json["changed"].as_array().unwrap() {
        assert_eq!(keys(c), names(&["path", "change"]));
    }
    for e in json["errors"].as_array().unwrap() {
        assert_eq!(keys(e), names(&["path", "error"]));
    }
    assert!(!json["findings"].as_array().unwrap().is_empty() && !json["unclassified"].as_array().unwrap().is_empty());
    // A missing --backup path vanished, it is not a read error.
    assert!(json["changed"].as_array().unwrap().iter().any(|c| c["change"] == "vanished"));

    // No secret in either form: not the DEK, not the master, not plaintext share content.
    let dek_hex = hex::encode(derive_share_dek(master.as_bytes(), 1).as_ref());
    let out = format!("{}\n{}", serde_json::to_string(&r).unwrap(), r.text());
    for secret in [dek_hex.as_str(), master, MARKER] {
        assert!(!out.contains(secret), "the output carries a secret");
    }
}

// ── next to a running node ─────────────────────────────────────────────────────────────────────

/// The scan takes no lock the signing path takes: with the node's instance lock held and signs
/// and a refresh running, every sign succeeds within its deadline and no scan hits a read error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scan_during_signing_neither_blocks_nor_fails_a_signature() {
    const KEY: &str = "frost-residue";
    let tmp = tempfile::tempdir().unwrap();
    let bundles: Vec<NodeSealBundle> = (1..=3).map(NodeSealBundle::random).collect();
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let sealer = Arc::new(bundles[i as usize - 1].sealer().with_binding(binding(i)));
            let ks = KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}/keys")), Some(sealer)).unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks))
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    run_dkg(&peers, KEY).await.unwrap();

    let dd = tmp.path().join("node-1");
    // What the daemon holds for its whole life.
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&dd).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let scans = Arc::new(AtomicUsize::new(0));
    let scanner = {
        let (stop, scans, dd) = (stop.clone(), scans.clone(), dd.clone());
        let sealer = bundles[0].sealer().with_binding(binding(1));
        std::thread::spawn(move || {
            let mut worst = 0;
            while !stop.load(Ordering::Relaxed) {
                let r = scan(&ScanInput {
                    data_dir: &dd,
                    node: 1,
                    cluster_uuid: Some(UUID),
                    sealer: Some(&sealer),
                    backups: &[],
                    legacy_dek: None,
                    config_names_secret_env: false,
                });
                assert!(r.errors.is_empty(), "a scan next to the node hit a read error:\n{}", r.text());
                worst = worst.max(r.exit_code());
                scans.fetch_add(1, Ordering::Relaxed);
            }
            worst
        })
    };

    let deadline = std::time::Duration::from_secs(10);
    for round in 0..20u8 {
        if round == 10 {
            // A refresh renames staged files over live ones while the scan walks them.
            tokio::time::timeout(deadline, run_refresh(&peers, KEY)).await.expect("refresh in time").unwrap();
        }
        let msg = [round; 34];
        tokio::time::timeout(deadline, sign(&nodes[0], &peers, KEY, &msg))
            .await
            .expect("a sign blocked behind the scan")
            .expect("a sign failed next to the scan");
    }
    // Let at least a few scans overlap the signs.
    while scans.load(Ordering::Relaxed) < 3 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    stop.store(true, Ordering::Relaxed);
    let worst = scanner.join().expect("the scanner thread panicked");
    assert!(worst < 2);
}

// ── the binary ─────────────────────────────────────────────────────────────────────────────────

fn config(dd: &Path) -> serde_json::Value {
    serde_json::json!({
        "profile": "lab",
        "identifier": 1,
        "listen": "127.0.0.1:0",
        "threshold": 2,
        "data_dir": dd,
        "peers": [
            {"identifier": 1, "endpoint": "https://a:9101"},
            {"identifier": 2, "endpoint": "https://b:9101"},
            {"identifier": 3, "endpoint": "https://c:9101"}
        ],
        "share_seal": {"secret_env": "RUTLI_RS_TEST_MASTER"},
        "keyfile": {"write_version": 2, "cluster_uuid": UUID, "accept_v1": true}
    })
}

fn cli(dir: &Path, cfg: &serde_json::Value, env: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let path = dir.join("cosigner.json");
    std::fs::write(&path, serde_json::to_string_pretty(cfg).unwrap()).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"));
    cmd.arg("--config").arg(&path).arg("residue-scan").args(args).env_remove("RUTLI_RS_TEST_MASTER");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn the_command_exits_by_result_and_refuses_a_short_legacy_master() {
    let tmp = tempfile::tempdir().unwrap();
    let dd = tmp.path().join("data");
    let master = "legacy-master-for-the-cli-test-0123456789abcdef";
    let s = Sealer::from_master_secret(master.as_bytes(), 1).with_binding(binding(1));
    put(&dd.join("keys/frost-a.json"), &v2(&s, RecordKind::FrostShare, "frost-a", 1));
    let cfg = config(&dd);
    let env = [("RUTLI_RS_TEST_MASTER", master)];

    // Clean, without the flag: exit 0, and the legacy check is named as not done.
    let (code, out, err) = cli(tmp.path(), &cfg, &env, &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("legacy-master check not done"), "{out}");

    // With the flag: the current DEK is the derivation (exit 1). JSON parses and says so.
    let (code, out, err) = cli(tmp.path(), &cfg, &env, &["--legacy-master-env", "RUTLI_RS_TEST_MASTER", "--json"]);
    assert_eq!(code, 1, "{out}{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["exit"], 1);
    assert_eq!(v["findings"][0]["class"], "legacy-master-dek");
    assert!(!out.contains(master) && !err.contains(master));

    // An empty or short value is refused, not reported as "no finding".
    for bad in ["", "short"] {
        let (code, out, err) = cli(tmp.path(), &cfg, &[("RUTLI_RS_TEST_MASTER", master), ("RS_BAD", bad)], &["--legacy-master-env", "RS_BAD"]);
        assert_eq!(code, 2, "{bad:?}: {out}{err}");
        assert!(err.contains("--legacy-master-env"), "{err}");
    }
    // Unset: refused too.
    let (code, _, err) = cli(tmp.path(), &cfg, &env, &["--legacy-master-env", "RS_UNSET_VAR"]);
    assert_eq!(code, 2, "{err}");

    // A --backup that is neither a directory, a tar nor a key file: unclassified, exit 1.
    let (code, out, _) = cli(tmp.path(), &cfg, &env, &["--backup", tmp.path().join("cosigner.json").to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("[unclassified]") && out.contains("compressed archives are not read"), "{out}");
}

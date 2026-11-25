// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner backup-retain` through the real binary, on real tars made the way the backup
//! sidecar makes them (symlinks into a stage, `tar -h`), with real sealed v2 key files.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use rutli_cosigner::keystore::{KeyStore, Share};
use rutli_cosigner::seal::{KeyFileBinding, Sealer};

const MASTER: &str = "0123456789abcdef0123456789abcdef-backup-retain-master";
const UUID: &str = "2b0c6a52-4c1e-4b7a-9d1e-3f1a7c2e9b10";
const KEY: &str = "frost-ret";

fn cosigner(cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .arg("--config")
        .arg(cfg)
        .args(args)
        .env_remove("RUTLI_COSIGNER_CONFIG")
        .env("RUTLI_SEAL_SECRET", MASTER)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn config(dir: &Path) -> PathBuf {
    let cfg = dir.join("cosigner.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": 1, "listen": "127.0.0.1:0", "threshold": 2, "data_dir": dir.join("data"),
            "peers": (1..=3).map(|j| serde_json::json!({
                "identifier": j, "endpoint": format!("http://127.0.0.1:{}", 19400 + j),
            })).collect::<Vec<_>>(),
            "share_seal": { "secret_env": "RUTLI_SEAL_SECRET" },
            "keyfile": { "write_version": 2, "cluster_uuid": UUID },
        })
        .to_string(),
    )
    .unwrap();
    cfg
}

fn store(keys: &Path) -> KeyStore {
    let sealer = Sealer::from_master_secret(MASTER.as_bytes(), 1).with_binding(KeyFileBinding {
        node: 1,
        cluster_uuid: Some(UUID.into()),
        write_version: 2,
        accept_v1: true,
    });
    KeyStore::open_with_sealer(keys, Some(Arc::new(sealer))).unwrap()
}

/// The same sharing (one dealt split, made once) at `epoch`.
fn share(epoch: u64) -> Share {
    static SPLIT: std::sync::OnceLock<(
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    )> = std::sync::OnceLock::new();
    let (kp, pkp) = SPLIT.get_or_init(|| {
        let (shares, pkp) =
            rutli_frost_core::dealer::split_ed25519_seed(&[5u8; 32], &[1, 2, 3], 2).unwrap();
        (
            frost_ed25519::keys::KeyPackage::try_from(shares[0].clone()).unwrap(),
            pkp,
        )
    });
    Share {
        key_package: kp.clone(),
        public_key_package: pkp.clone(),
        origin: None,
        epoch,
        key_id: KEY.into(),
    }
}

/// A tar of one key file of `epoch`, named as the sidecar names it.
fn archive(dir: &Path, stamp: &str, epoch: u64) {
    let scratch = tempfile::tempdir().unwrap();
    let keys = scratch.path().join("keys");
    store(&keys).create(KEY, &share(epoch)).unwrap();
    let stage = scratch.path().join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    std::os::unix::fs::symlink(
        keys.join(format!("{KEY}.json")),
        stage.join(format!("{KEY}.json")),
    )
    .unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let ok = Command::new("tar")
        .args(["-h", "-C"])
        .arg(&stage)
        .arg("-cf")
        .arg(dir.join(format!("node-1-{stamp}.tar")))
        .arg(".")
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

fn tars(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tar"))
        .collect();
    v.sort();
    v
}

#[test]
fn old_epochs_go_only_after_the_new_one_is_proven_and_never_on_a_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let keys = tmp.path().join("data").join("keys");
    let backups = tmp.path().join("backup");
    let live = share(3);
    store(&keys).create(KEY, &live).unwrap();
    for (stamp, epoch) in [
        ("20261101T000000Z", 1),
        ("20261102T000000Z", 2),
        ("20261103T000000Z", 3),
    ] {
        archive(&backups, stamp, epoch);
    }
    let dir = backups.to_str().unwrap();
    let all = vec![
        "node-1-20261101T000000Z.tar",
        "node-1-20261102T000000Z.tar",
        "node-1-20261103T000000Z.tar",
    ];

    // No proof: every older archive stays, and says why.
    let out = cosigner(
        &cfg,
        &["backup-retain", "--dir", dir, "--min-proof-age-days", "0"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("reason=unproven-epoch"),
        "{}",
        text(&out)
    );
    assert_eq!(tars(&backups), all);

    // Prove epoch 3 (the operator's statement), then a dry run lists, a real run deletes.
    let digest = hex::encode(live.pkp_digest().unwrap());
    let group = hex::encode(
        rutli_frost_core::dkg::group_verifying_key_bytes(&live.public_key_package).unwrap(),
    );
    let report = serde_json::json!({
        "key_id": KEY, "ok": true, "problems": [], "group_verifying_key": group, "pkp_digest": digest, "epoch": 3,
        "nodes": (1..=3).map(|i| serde_json::json!({
            "identifier": i, "endpoint": "x", "present": true, "pkp_digest": digest,
            "own_share_in_package": true, "epoch": 3, "stale": false,
        })).collect::<Vec<_>>(),
        "sign_test": [
            {"leader": 1, "signers": [1, 2], "ok": true},
            {"leader": 2, "signers": [1, 3], "ok": true},
            {"leader": 3, "signers": [2, 3], "ok": true},
        ],
    });
    let report_path = tmp.path().join("report.json");
    std::fs::write(&report_path, report.to_string()).unwrap();
    let proved = cosigner(
        &cfg,
        &[
            "keyfile",
            "prove",
            "--key-id",
            KEY,
            "--epoch",
            "3",
            "--report",
            report_path.to_str().unwrap(),
        ],
    );
    assert!(proved.status.success(), "{}", text(&proved));
    // A report that states no sign-test message version comes from an older verify-key.
    assert!(
        text(&proved).contains("sign-test message version 1") && text(&proved).contains("WARNING"),
        "{}",
        text(&proved)
    );

    // The proof is seconds old: with the default 7 days nothing goes.
    let young = cosigner(&cfg, &["backup-retain", "--dir", dir]);
    assert!(young.status.success(), "{}", text(&young));
    assert_eq!(tars(&backups), all, "a young proof deletes nothing");
    let warning = format!("BACKUP_RETENTION_WARNING node=1 key={KEY} epoch=3 proof=version-1");
    assert!(text(&young).contains(&warning), "{}", text(&young));

    let dry = cosigner(
        &cfg,
        &[
            "backup-retain",
            "--dir",
            dir,
            "--min-proof-age-days",
            "0",
            "--dry-run",
        ],
    );
    assert!(dry.status.success(), "{}", text(&dry));
    assert_eq!(
        text(&dry).matches("verdict=would-delete").count(),
        2,
        "{}",
        text(&dry)
    );
    assert!(text(&dry).contains("dry_run=true"));
    assert_eq!(tars(&backups), all, "a dry run deletes nothing");

    let real = cosigner(
        &cfg,
        &["backup-retain", "--dir", dir, "--min-proof-age-days", "0"],
    );
    assert!(real.status.success(), "{}", text(&real));
    assert_eq!(
        tars(&backups),
        vec!["node-1-20261103T000000Z.tar"],
        "{}",
        text(&real)
    );
    // A version 1 proof still counted; it was named in a warning.
    assert!(text(&real).contains(&warning), "{}", text(&real));

    // The same epoch proven again from a 0.5 report (version 2): the warning is gone.
    let mut v2 = report;
    v2["sign_test_message_version"] = 2.into();
    for (i, row) in v2["sign_test"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        row["challenge"] = hex::encode([i as u8 + 1; 32]).into();
    }
    std::fs::write(&report_path, v2.to_string()).unwrap();
    let reproved = cosigner(
        &cfg,
        &[
            "keyfile",
            "prove",
            "--key-id",
            KEY,
            "--epoch",
            "3",
            "--report",
            report_path.to_str().unwrap(),
        ],
    );
    assert!(reproved.status.success(), "{}", text(&reproved));
    assert!(
        text(&reproved).contains("sign-test message version 2")
            && !text(&reproved).contains("WARNING"),
        "{}",
        text(&reproved)
    );
    let after = cosigner(&cfg, &["backup-retain", "--dir", dir, "--dry-run"]);
    assert!(after.status.success(), "{}", text(&after));
    assert!(
        !text(&after).contains("BACKUP_RETENTION_WARNING"),
        "{}",
        text(&after)
    );
}

#[test]
fn a_node_behind_its_newest_archive_deletes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let keys = tmp.path().join("data").join("keys");
    let backups = tmp.path().join("backup");
    store(&keys).create(KEY, &share(2)).unwrap(); // this node missed the refresh to 3
    archive(&backups, "20261101T000000Z", 1);
    archive(&backups, "20261103T000000Z", 3);
    let out = cosigner(
        &cfg,
        &[
            "backup-retain",
            "--dir",
            backups.to_str().unwrap(),
            "--min-proof-age-days",
            "0",
            "--keep-count",
            "1",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("BACKUP_RETENTION_SKIPPED") && text(&out).contains("nothing-deleted"),
        "{}",
        text(&out)
    );
    assert_eq!(tars(&backups).len(), 2, "not even the count cap runs");
}

#[test]
fn an_unreadable_directory_is_an_error_and_a_damaged_archive_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path());
    let keys = tmp.path().join("data").join("keys");
    let backups = tmp.path().join("backup");
    store(&keys).create(KEY, &share(3)).unwrap();
    let missing = cosigner(
        &cfg,
        &[
            "backup-retain",
            "--dir",
            tmp.path().join("nope").to_str().unwrap(),
        ],
    );
    assert!(
        !missing.status.success() && text(&missing).contains("cannot list"),
        "{}",
        text(&missing)
    );

    archive(&backups, "20261101T000000Z", 3);
    archive(&backups, "20261103T000000Z", 3);
    let damaged = backups.join("node-1-20261102T000000Z.tar");
    std::fs::write(&damaged, vec![1u8; 700]).unwrap();
    let out = cosigner(
        &cfg,
        &[
            "backup-retain",
            "--dir",
            backups.to_str().unwrap(),
            "--min-proof-age-days",
            "0",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        damaged.exists(),
        "an archive whose epoch cannot be read is never deleted: {}",
        text(&out)
    );
}

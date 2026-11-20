// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner keyfile …` and the daemon's start-up checks of the key-file format (audit M4),
//! through the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use sha2::Digest as _;

use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::seal::{KeyFileBinding, Sealer};

const MASTER: &str = "0123456789abcdef0123456789abcdef-keyfile-cli-master";
const UUID: &str = "2b0c6a52-4c1e-4b7a-9d1e-3f1a7c2e9b10";

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
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn config(dir: &Path, write_version: u8) -> PathBuf {
    let cfg = dir.join(format!("cosigner-v{write_version}.json"));
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": 1,
            "listen": "127.0.0.1:0",
            "threshold": 2,
            "data_dir": dir.join("data"),
            "peers": (1..=3).map(|j| serde_json::json!({
                "identifier": j, "endpoint": format!("http://127.0.0.1:{}", 19300 + j),
            })).collect::<Vec<_>>(),
            "share_seal": { "secret_env": "RUTLI_SEAL_SECRET" },
            "keyfile": { "write_version": write_version, "cluster_uuid": UUID },
        })
        .to_string(),
    )
    .unwrap();
    cfg
}

fn keys(dir: &Path) -> PathBuf {
    dir.join("data").join("keys")
}

fn sealed_store(dir: &Path, write_version: u8) -> KeyStore {
    let sealer = Sealer::from_master_secret(MASTER.as_bytes(), 1).with_binding(KeyFileBinding {
        node: 1,
        cluster_uuid: Some(UUID.into()),
        write_version,
        accept_v1: true,
    });
    KeyStore::open_with_sealer(keys(dir), Some(Arc::new(sealer))).unwrap()
}

fn version_of(path: &Path) -> Option<u8> {
    rutli_cosigner::seal::file_version(&std::fs::read(path).unwrap())
}

#[test]
fn a_plaintext_key_file_stops_the_daemon_until_migrate_plaintext_seals_it_with_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path(), 2);
    let key = HostedKey::generate(HostedSpec::EcP256, 5).unwrap();
    KeyStore::open(keys(tmp.path())).unwrap().save_hosted("rutli-enc-1", &key).unwrap();

    let out = cosigner(&cfg, &["serve"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("PLAINTEXT key file") && text(&out).contains("rutli-enc-1.json"), "{}", text(&out));

    // First run: shows what the file is and a code; seals nothing.
    let shown = cosigner(&cfg, &["keyfile", "migrate-plaintext", "--key-id", "rutli-enc-1"]);
    assert!(shown.status.success(), "{}", text(&shown));
    assert!(text(&shown).contains("ec-p256-ecies"), "{}", text(&shown));
    assert_eq!(version_of(&keys(tmp.path()).join("rutli-enc-1.json")), None);
    let code = text(&shown).split("--confirm ").nth(1).unwrap().trim().to_string();

    let wrong = cosigner(&cfg, &["keyfile", "migrate-plaintext", "--key-id", "rutli-enc-1", "--confirm", "00"]);
    assert!(!wrong.status.success());
    let ok = cosigner(&cfg, &["keyfile", "migrate-plaintext", "--key-id", "rutli-enc-1", "--confirm", &code]);
    assert!(ok.status.success(), "{}", text(&ok));
    assert_eq!(version_of(&keys(tmp.path()).join("rutli-enc-1.json")), Some(2));
    assert_eq!(sealed_store(tmp.path(), 2).load_hosted("rutli-enc-1").unwrap().created_at, 5);
}

#[test]
fn migrate_downgrade_and_status_rewrite_every_key_file_under_the_instance_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path(), 2);
    let v1 = sealed_store(tmp.path(), 1);
    v1.save_hosted("rutli-a", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
    v1.save_hosted("rutli-b", &HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap()).unwrap();
    let a = keys(tmp.path()).join("rutli-a.json");

    let status = cosigner(&cfg, &["keyfile", "status"]);
    assert!(status.status.success(), "{}", text(&status));
    assert!(text(&status).contains("2 not yet v2"), "{}", text(&status));

    let migrated = cosigner(&cfg, &["keyfile", "migrate"]);
    assert!(migrated.status.success(), "{}", text(&migrated));
    assert_eq!(version_of(&a), Some(2));
    assert!(text(&cosigner(&cfg, &["keyfile", "status"])).contains("0 not yet v2"));

    let down = cosigner(&cfg, &["keyfile", "downgrade"]);
    assert!(down.status.success(), "{}", text(&down));
    assert!(text(&down).contains("set it to 1"), "{}", text(&down));
    assert_eq!(version_of(&a), Some(1));
    // A release that knows only v1 opens it with the v1 unseal.
    assert!(Sealer::from_master_secret(MASTER.as_bytes(), 1).unseal(&std::fs::read(&a).unwrap()).is_ok());

    // Not while a daemon holds the data directory.
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&tmp.path().join("data")).unwrap();
    let locked = cosigner(&cfg, &["keyfile", "migrate"]);
    assert!(!locked.status.success(), "{}", text(&locked));
    assert_eq!(version_of(&a), Some(1));
}

/// A dealt 2-of-3 share for node 1 at `epoch`, and the report `verify-key --sign-test --json` would
/// print for it when the whole cluster agrees.
fn share_and_report(key_id: &str, epoch: u64) -> (rutli_cosigner::keystore::Share, serde_json::Value) {
    let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&[5u8; 32], &[1, 2, 3], 2).unwrap();
    let share = rutli_cosigner::keystore::Share {
        key_package: frost_ed25519::keys::KeyPackage::try_from(shares[0].clone()).unwrap(),
        public_key_package: pkp,
        origin: None,
        epoch,
        key_id: key_id.into(),
    };
    let digest = hex::encode(share.pkp_digest().unwrap());
    let group = hex::encode(rutli_frost_core::dkg::group_verifying_key_bytes(&share.public_key_package).unwrap());
    let report = serde_json::json!({
        "key_id": key_id, "ok": true, "problems": [], "group_verifying_key": group,
        "pkp_digest": digest, "threshold": 2, "epoch": epoch,
        "nodes": (1..=3).map(|i| serde_json::json!({
            "identifier": i, "endpoint": "x", "present": true, "pkp_digest": digest,
            "own_share_in_package": true, "epoch": epoch, "stale": false,
        })).collect::<Vec<_>>(),
        "sign_test": [
            {"leader": 1, "signers": [1, 2], "ok": true},
            {"leader": 2, "signers": [1, 3], "ok": true},
            {"leader": 3, "signers": [2, 3], "ok": true},
        ],
    });
    (share, report)
}

#[test]
fn keyfile_prove_writes_a_marker_only_for_this_nodes_live_epoch_and_sharing() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(tmp.path(), 2);
    let (share, report) = share_and_report("frost-prove", 4);
    let ks = sealed_store(tmp.path(), 2);
    ks.create("frost-prove", &share).unwrap();
    // The header digest the gauges and the retention compare is the share's PKP digest.
    let file = std::fs::read(keys(tmp.path()).join("frost-prove.json")).unwrap();
    assert_eq!(rutli_cosigner::seal::header_of(&file).unwrap().digest, hex::encode(share.pkp_digest().unwrap()));

    let report_path = tmp.path().join("report.json");
    std::fs::write(&report_path, report.to_string()).unwrap();
    let r = report_path.to_str().unwrap();
    let marker = keys(tmp.path()).join(".proven").join("frost-prove.4.json");

    // Another epoch than this node's live one: refused, nothing written.
    let wrong = cosigner(&cfg, &["keyfile", "prove", "--key-id", "frost-prove", "--epoch", "5", "--report", r]);
    assert!(!wrong.status.success() && text(&wrong).contains("epoch 4"), "{}", text(&wrong));
    assert!(!marker.exists());

    // A report whose group key is not this node's: refused.
    let mut other = report.clone();
    other["group_verifying_key"] = hex::encode([1u8; 32]).into();
    let other_path = tmp.path().join("other.json");
    std::fs::write(&other_path, other.to_string()).unwrap();
    let bad = cosigner(&cfg, &["keyfile", "prove", "--key-id", "frost-prove", "--epoch", "4", "--report", other_path.to_str().unwrap()]);
    assert!(!bad.status.success() && text(&bad).contains("group key"), "{}", text(&bad));
    assert!(!marker.exists());

    // The right epoch and report: the marker, and a note that it is the operator's statement.
    let ok = cosigner(&cfg, &["keyfile", "prove", "--key-id", "frost-prove", "--epoch", "4", "--report", r]);
    assert!(ok.status.success(), "{}", text(&ok));
    assert!(text(&ok).contains("YOUR statement"), "{}", text(&ok));
    let m: serde_json::Value = serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    assert_eq!(m["epoch"], 4);
    assert_eq!(m["pkp_digest"], report["pkp_digest"]);
    assert_eq!(m["report_sha256"], hex::encode(sha2::Sha256::digest(report.to_string().as_bytes())));
    // The key file itself is untouched, and the store still loads (the marker dir is no key file).
    assert_eq!(sealed_store(tmp.path(), 2).load("frost-prove").unwrap().epoch, 4);
    assert_eq!(sealed_store(tmp.path(), 2).list_frost().unwrap(), vec!["frost-prove".to_string()]);
}

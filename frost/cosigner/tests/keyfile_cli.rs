// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner keyfile …` and the daemon's start-up checks of the key-file format (audit M4),
//! through the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

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

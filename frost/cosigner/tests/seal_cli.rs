// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner seal …` and a node running on a seal bundle, through the real binary.
//!
//! The migration this supports (docs/runbook-per-node-seal.md): split the legacy shared master into
//! one bundle per node on a workstation, mount each node's bundle as a file, and keep every sealed
//! file as it is.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::seal::{NodeSealBundle, Sealer};

const MASTER: &str = "0123456789abcdef0123456789abcdef-soak-like-master";

fn cosigner(args: &[&str], master: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"));
    cmd.args(args).env_remove("RUTLI_COSIGNER_CONFIG").env_remove("RUTLI_SEAL_SECRET");
    if let Some(m) = master {
        cmd.env("RUTLI_SEAL_SECRET", m);
    }
    cmd.output().unwrap()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn split(dir: &Path) -> Output {
    cosigner(
        &["seal", "split-legacy", "--nodes", "1,2,3", "--out-dir", dir.to_str().unwrap()],
        Some(MASTER),
    )
}

#[test]
fn split_legacy_writes_one_private_bundle_per_node_with_the_current_derivations() {
    let tmp = tempfile::tempdir().unwrap();
    let out = split(tmp.path());
    assert!(out.status.success(), "{}", text(&out));
    let printed = text(&out);

    let commitment = hex::encode(rutli_cosigner::wrap::legacy_commitment_key(MASTER.as_bytes()));
    assert!(printed.contains(&commitment), "commitment key must be printed: {printed}");
    for i in 1..=3u16 {
        let path = tmp.path().join(format!("node-{i}.json"));
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600, "a bundle is a secret");
        let bundle = NodeSealBundle::parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(bundle.node, i);
        let pin = hex::encode(rutli_cosigner::wrap::DistKey::derive(MASTER.as_bytes(), i).public_bytes());
        assert_eq!(hex::encode(bundle.dist_public_key()), pin);
        assert!(printed.contains(&pin), "node {i}'s pin must be printed");
        // The DEK is the one the node already seals with.
        let sealed = Sealer::from_master_secret(MASTER.as_bytes(), i).seal(b"share").unwrap();
        assert_eq!(bundle.sealer().unseal(&sealed).unwrap(), b"share");
    }
    assert!(!printed.contains(MASTER), "the master must never be echoed");

    // Never overwrites a bundle (a re-run must not clobber a file someone already distributed).
    let again = split(tmp.path());
    assert!(!again.status.success());
    assert!(text(&again).contains("refusing to overwrite"), "{}", text(&again));
}

#[test]
fn split_legacy_refuses_a_missing_or_short_master() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path().to_str().unwrap();
    let none = cosigner(&["seal", "split-legacy", "--nodes", "1", "--out-dir", d], None);
    assert!(!none.status.success() && text(&none).contains("not set"), "{}", text(&none));
    let short = cosigner(&["seal", "split-legacy", "--nodes", "1", "--out-dir", d], Some("short"));
    assert!(!short.status.success() && text(&short).contains("too short"), "{}", text(&short));
    let dup = cosigner(&["seal", "split-legacy", "--nodes", "1,1", "--out-dir", d], Some(MASTER));
    assert!(!dup.status.success());
}

#[test]
fn new_node_and_inspect() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("n4.json");
    let out = cosigner(&["seal", "new-node", "--node", "4", "--out", path.to_str().unwrap()], None);
    assert!(out.status.success(), "{}", text(&out));
    let bundle = NodeSealBundle::parse(&std::fs::read(&path).unwrap()).unwrap();
    let pin = hex::encode(bundle.dist_public_key());
    assert!(text(&out).contains(&pin));
    let shown = cosigner(&["seal", "inspect", "--in", path.to_str().unwrap()], None);
    assert!(shown.status.success());
    assert_eq!(
        text(&shown),
        format!("node 4\ndist_public_key {pin}\nshare_dek id {} (+0 previous)\n", bundle.dek_id())
    );
}

/// DEK rotation tooling (decision P1): rotate keeps the old DEK as previous and the distribution
/// key unchanged; drop-previous removes it; neither ever overwrites a file.
#[test]
fn rotate_dek_then_drop_previous() {
    let tmp = tempfile::tempdir().unwrap();
    let p = |n: &str| tmp.path().join(n).to_str().unwrap().to_string();
    assert!(cosigner(&["seal", "new-node", "--node", "2", "--out", &p("a.json")], None).status.success());
    let rotated = cosigner(&["seal", "rotate-dek", "--in", &p("a.json"), "--out", &p("b.json")], None);
    assert!(rotated.status.success(), "{}", text(&rotated));
    let a = NodeSealBundle::parse(&std::fs::read(p("a.json")).unwrap()).unwrap();
    let b = NodeSealBundle::parse(&std::fs::read(p("b.json")).unwrap()).unwrap();
    assert_eq!(a.dist_public_key(), b.dist_public_key());
    assert_ne!(a.dek_id(), b.dek_id());
    assert_eq!(b.previous_count(), 1);
    // A file sealed under the old DEK opens under the rotated bundle, not after the drop.
    let sealed = a.sealer().seal(b"share").unwrap();
    assert_eq!(b.sealer().unseal(&sealed).unwrap(), b"share");
    let dropped = cosigner(&["seal", "drop-previous", "--in", &p("b.json"), "--out", &p("c.json")], None);
    assert!(dropped.status.success(), "{}", text(&dropped));
    let c = NodeSealBundle::parse(&std::fs::read(p("c.json")).unwrap()).unwrap();
    assert_eq!((c.previous_count(), c.dek_id()), (0, b.dek_id()));
    assert!(c.sealer().unseal(&sealed).is_err());
    // Never overwrites, and refuses a bundle with nothing to drop.
    assert!(!cosigner(&["seal", "rotate-dek", "--in", &p("a.json"), "--out", &p("b.json")], None).status.success());
    assert!(!cosigner(&["seal", "drop-previous", "--in", &p("c.json"), "--out", &p("d.json")], None).status.success());
}

/// A config for node `id` on `bundle`, hosted keys on, with `pins` for nodes 1..=3.
fn bundle_config(dir: &Path, id: u16, bundle: &Path, pins: &[String; 3], commitment: &str) -> std::path::PathBuf {
    let cfg = dir.join(format!("cosigner{id}.json"));
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": id,
            "listen": "127.0.0.1:0",
            "threshold": 2,
            "data_dir": dir.join(format!("data-{id}")),
            "peers": (1..=3).map(|j| serde_json::json!({
                "identifier": j,
                "endpoint": format!("http://127.0.0.1:{}", 19100 + j),
                "dist_public_key": pins[j as usize - 1],
            })).collect::<Vec<_>>(),
            "share_seal": { "secret_file": bundle },
            "hosted_keys": { "enabled": true, "commitment_key": commitment },
        })
        .to_string(),
    )
    .unwrap();
    cfg
}

#[cfg(unix)]
#[test]
fn a_node_on_its_split_bundle_opens_keys_sealed_under_the_master_and_refuses_misconfiguration() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let bundles = tmp.path().join("bundles");
    assert!(split(&bundles).status.success());
    for i in 1..=3 {
        let p = bundles.join(format!("node-{i}.json"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    let pins: [String; 3] =
        [1u16, 2, 3].map(|i| hex::encode(rutli_cosigner::wrap::DistKey::derive(MASTER.as_bytes(), i).public_bytes()));
    let commitment = hex::encode(rutli_cosigner::wrap::legacy_commitment_key(MASTER.as_bytes()));

    // A hosted key written by node 2 while it still ran on the shared master.
    let legacy = Arc::new(Sealer::from_master_secret(MASTER.as_bytes(), 2));
    let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
    KeyStore::open_with_sealer(tmp.path().join("data-2").join("keys"), Some(legacy))
        .unwrap()
        .save_hosted("rutli-sym-legacy", &key)
        .unwrap();

    // Node 2 on its bundle (no master in the environment at all) reads it: export goes through
    // the same seal-key loading as the daemon.
    let cfg = bundle_config(tmp.path(), 2, &bundles.join("node-2.json"), &pins, &commitment);
    let exported = tmp.path().join("export.json");
    let out = cosigner(
        &["--config", cfg.to_str().unwrap(), "export-key", "--key-id", "rutli-sym-legacy",
          "--out", exported.to_str().unwrap(), "--unsafe-plaintext"],
        None,
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(exported.exists());

    // Node 1's bundle mounted into node 2: refused before anything is opened.
    let cfg = bundle_config(tmp.path(), 2, &bundles.join("node-1.json"), &pins, &commitment);
    let out = cosigner(&["--config", cfg.to_str().unwrap(), "serve"], None);
    assert!(!out.status.success());
    assert!(text(&out).contains("wrong Secret mounted"), "{}", text(&out));

    // The daemon refuses to start when its own pin does not match its bundle.
    let mut wrong = pins.clone();
    wrong[1] = pins[0].clone();
    wrong[0] = pins[1].clone();
    let cfg = bundle_config(tmp.path(), 2, &bundles.join("node-2.json"), &wrong, &commitment);
    let out = cosigner(&["--config", cfg.to_str().unwrap(), "serve"], None);
    assert!(!out.status.success());
    assert!(text(&out).contains("wrong seal bundle"), "{}", text(&out));

    // A world-readable bundle is refused too.
    std::fs::set_permissions(bundles.join("node-2.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let cfg = bundle_config(tmp.path(), 2, &bundles.join("node-2.json"), &pins, &commitment);
    let out = cosigner(&["--config", cfg.to_str().unwrap(), "serve"], None);
    assert!(!out.status.success());
    assert!(text(&out).contains("every user"), "{}", text(&out));
}

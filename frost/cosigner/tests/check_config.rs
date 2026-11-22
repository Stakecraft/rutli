// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner check-config` and the production profile through the real binary.

use std::path::Path;
use std::process::Command;

fn enforced() -> serde_json::Value {
    serde_json::json!({
        "profile": "production",
        "identifier": 1,
        "listen": "127.0.0.1:0",
        "threshold": 2,
        "data_dir": "/nonexistent/rutli-check-config",
        "peers": [
            {"identifier": 1, "endpoint": "https://a:9101"},
            {"identifier": 2, "endpoint": "https://b:9101"},
            {"identifier": 3, "endpoint": "https://c:9101"}
        ],
        "tls": {"ca_cert": "/nonexistent/ca.crt", "cert": "/nonexistent/tls.crt", "key": "/nonexistent/tls.key"},
        "share_seal": {"secret_file": "/nonexistent/seal.json"},
        "signer_allowlist": ["driver"],
        "peer_allowlist": ["cosigner1", "cosigner2", "cosigner3"],
        "operator_allowlist": ["operator"],
        "refresh_allowlist": ["refresher"],
        "cluster_id": "0123456789abcdef",
        "keyfile": {"write_version": 2, "cluster_uuid": "6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b", "accept_v1": false},
        "signing_policy": {
            "require_epoch_match": true,
            "signer_acl_required": true,
            "signer_may_refresh": false,
            "signer_acl": {"driver": [""]},
            "signer_pins": {"driver": ["00".repeat(32)]}
        }
    })
}

fn run(dir: &Path, cfg: &serde_json::Value, args: &[&str]) -> (i32, String) {
    let path = dir.join("cosigner.json");
    std::fs::write(&path, serde_json::to_string_pretty(cfg).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .arg("--config")
        .arg(&path)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn check_config_lists_findings_under_any_profile_and_the_node_refuses_under_production() {
    let tmp = tempfile::tempdir().unwrap();

    // Every required setting on; no approval rule is advisory only.
    let (code, out) = run(tmp.path(), &enforced(), &["check-config"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("0 required and 1 advisory")
            && out.contains("[advisory] signing_policy.rules"),
        "{out}"
    );
    assert!(out.contains("meets the production profile"), "{out}");

    // Two gaps: listed by check-config (exit 1), and the node refuses to load the config at all,
    // naming both and pointing to the doc.
    let mut gaps = enforced();
    gaps["signing_policy"]["require_epoch_match"] = false.into();
    gaps["keyfile"]["accept_v1"] = true.into();
    let (code, out) = run(tmp.path(), &gaps, &["check-config"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("[required] signing_policy.require_epoch_match: false"),
        "{out}"
    );
    assert!(out.contains("[required] keyfile.accept_v1"), "{out}");
    let (code, out) = run(tmp.path(), &gaps, &["health"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("profile is \"production\"") && out.contains("2 enforcement setting(s)"),
        "{out}"
    );
    assert!(
        out.contains("signing_policy.require_epoch_match")
            && out.contains("docs/production-profile.md"),
        "{out}"
    );

    // The same file as lab: check-config still lists the gaps; the node loads it.
    gaps["profile"] = "lab".into();
    let (code, out) = run(tmp.path(), &gaps, &["check-config"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("profile lab, 2 required"), "{out}");

    // A config that does not load: exit 2.
    let mut broken = enforced();
    broken["profile"] = "staging".into();
    let (code, out) = run(tmp.path(), &broken, &["check-config"]);
    assert_eq!(code, 2, "{out}");
    let mut typo = enforced();
    typo["signing_policy"]["require_epoch_matc"] = true.into();
    let (code, out) = run(tmp.path(), &typo, &["check-config"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("require_epoch_matc"), "{out}");
}

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

#[test]
fn the_refresh_interval_off_or_under_72_hours_is_a_required_finding() {
    let tmp = tempfile::tempdir().unwrap();
    for (secs, found) in [(0, "0 (off)"), (86_400, "86400 (less than 72 h)")] {
        let line = format!(
            "[required] signing_policy.refresh_min_interval_secs: {found} — production requires at \
             least 259200 (72 h, the default)"
        );
        let mut cfg = enforced();
        cfg["signing_policy"]["refresh_min_interval_secs"] = secs.into();
        let (code, out) = run(tmp.path(), &cfg, &["check-config"]);
        assert_eq!(code, 1, "{out}");
        assert!(
            out.contains("profile production, 1 required") && out.contains(&line),
            "{out}"
        );
        // The node refuses to load the config and names the setting.
        let (code, out) = run(tmp.path(), &cfg, &["health"]);
        assert_eq!(code, 1, "{out}");
        assert!(
            out.contains("profile is \"production\"") && out.contains(&line),
            "{out}"
        );
        // As lab the finding is still listed, and it is no longer what stops the node.
        cfg["profile"] = "lab".into();
        let (code, out) = run(tmp.path(), &cfg, &["check-config"]);
        assert_eq!(code, 1, "{out}");
        assert!(
            out.contains("profile lab, 1 required") && out.contains(&line),
            "{out}"
        );
        // The config loads: `health` gets as far as the key store, which this config does not have.
        let (code, out) = run(tmp.path(), &cfg, &["health"]);
        assert_eq!(code, 1, "{out}");
        assert!(
            out.contains("not ready: keystore") && !out.contains("refresh_min_interval_secs"),
            "{out}"
        );
    }
    // The default written out, and a longer interval, meet the profile.
    for secs in [259_200, 604_800] {
        let mut cfg = enforced();
        cfg["signing_policy"]["refresh_min_interval_secs"] = secs.into();
        let (code, out) = run(tmp.path(), &cfg, &["check-config"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("0 required"), "{out}");
    }
}

#[test]
fn check_config_rejects_peer_deadlines_outside_their_bounds() {
    let tmp = tempfile::tempdir().unwrap();

    let mut ok = enforced();
    ok["peer_deadlines"] = serde_json::json!({"sign_round1_ms": 5000, "sign_round2_ms": 9000});
    let (code, out) = run(tmp.path(), &ok, &["check-config"]);
    assert_eq!(code, 0, "{out}");

    // Each bound, just outside it. (The sum check cannot fire within the bounds: 5 s + 9 s is
    // under the 20 s sign budget; it is unit-tested in config.rs.)
    for (r1, r2, key) in [
        (499, 5000, "sign_round1_ms"),
        (5001, 5000, "sign_round1_ms"),
        (2000, 999, "sign_round2_ms"),
        (2000, 9001, "sign_round2_ms"),
    ] {
        let mut bad = enforced();
        bad["peer_deadlines"] = serde_json::json!({"sign_round1_ms": r1, "sign_round2_ms": r2});
        let (code, out) = run(tmp.path(), &bad, &["check-config"]);
        assert_eq!(code, 2, "{r1}/{r2}: {out}");
        assert!(out.contains(&format!("peer_deadlines.{key}")), "{out}");
    }
}

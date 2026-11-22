// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! The daemon turns core dumps off at start, before it opens a key store, and says so in its log.

use std::process::Command;

#[test]
fn the_daemon_turns_core_dumps_off_before_it_opens_a_key_store() {
    let tmp = tempfile::tempdir().unwrap();
    // data_dir under a regular file: the daemon stops at its instance lock, right after the
    // hardening, without opening a key store or a port.
    let blocker = tmp.path().join("not-a-dir");
    std::fs::write(&blocker, b"").unwrap();
    let cfg = serde_json::json!({
        "profile": "lab",
        "identifier": 1,
        "listen": "127.0.0.1:0",
        "threshold": 2,
        "data_dir": blocker.join("data"),
        "peers": [
            {"identifier": 1, "endpoint": "https://a:9101"},
            {"identifier": 2, "endpoint": "https://b:9101"},
            {"identifier": 3, "endpoint": "https://c:9101"}
        ]
    });
    let path = tmp.path().join("cosigner.json");
    std::fs::write(&path, serde_json::to_string(&cfg).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .arg("--config")
        .arg(&path)
        .arg("serve")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let log =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{log}");
    let line = log
        .lines()
        .find(|l| l.contains("core dumps off") || l.contains("core dumps not fully off"))
        .unwrap_or_else(|| panic!("no core-dump line in the start-up log:\n{log}"));
    assert!(line.contains("rlimit_core_zero=true"), "{line}");
    if cfg!(target_os = "linux") {
        assert!(line.contains("not_dumpable=true"), "{line}");
    }
}

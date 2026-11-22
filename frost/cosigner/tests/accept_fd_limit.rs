// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! The daemon under a low open-file limit: more connections than it has descriptors for do not
//! stop it. Runs the real binary with `ulimit -n 128` (soft and hard, so the start-up raise cannot
//! lift it), holds 300 connections open, and checks that the daemon is still serving afterwards
//! and still exits cleanly on SIGTERM.

#![cfg(unix)]

use std::io::Read;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HELD: usize = 300;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_until(what: &str, timeout: Duration, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn more_connections_than_descriptors_do_not_stop_the_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = tmp.path().join("cosigner1.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": 1,
            "listen": format!("127.0.0.1:{port}"),
            "threshold": 1,
            "data_dir": tmp.path().join("data"),
            "peers": [{ "identifier": 1, "endpoint": format!("http://127.0.0.1:{port}") }],
        })
        .to_string(),
    )
    .unwrap();
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let log_path = tmp.path().join("cosigner.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let bin = env!("CARGO_BIN_EXE_rutli-cosigner");
    // `ulimit -n` sets the soft and the hard limit.
    let mut child = Command::new("sh")
        .args([
            "-c",
            r#"ulimit -n 128 && exec "$0" --config "$1" serve"#,
            bin,
            cfg.to_str().unwrap(),
        ])
        .env_remove("RUTLI_COSIGNER_CONFIG")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let read_log = || {
        let mut s = String::new();
        std::fs::File::open(&log_path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    };
    let alive = |child: &mut std::process::Child| child.try_wait().unwrap().is_none();

    wait_until("the daemon to listen", Duration::from_secs(30), || {
        assert!(
            alive(&mut child),
            "the daemon exited at start:\n{}",
            read_log()
        );
        TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
    });
    let started = read_log();
    assert!(
        started.contains("open-file limit"),
        "the limit is logged at start:\n{started}"
    );
    assert!(
        started.contains("connection_limit=64"),
        "the cap follows the limit:\n{started}"
    );

    // Far more connections than the daemon has descriptors: past its cap they wait in the listen
    // backlog instead of being accepted.
    let held: Vec<TcpStream> = (0..HELD)
        .filter_map(|_| TcpStream::connect_timeout(&addr, Duration::from_secs(1)).ok())
        .collect();
    assert!(held.len() > 128, "only {} connections opened", held.len());
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        alive(&mut child),
        "the daemon stopped while the connections were open:\n{}",
        read_log()
    );

    drop(held);
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        alive(&mut child),
        "the daemon stopped after the connections closed:\n{}",
        read_log()
    );

    // Still serving: the readiness probe connects and finds the key store.
    let probe = Command::new(bin)
        .args(["--config", cfg.to_str().unwrap(), "health"])
        .env_remove("RUTLI_COSIGNER_CONFIG")
        .output()
        .unwrap();
    assert_eq!(
        (
            probe.status.code(),
            String::from_utf8_lossy(&probe.stdout).trim()
        ),
        (Some(0), "ready"),
        "{}\n{}",
        String::from_utf8_lossy(&probe.stderr),
        read_log()
    );

    // A requested stop is still a clean one.
    assert!(Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "no exit after SIGTERM:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success(),
        "SIGTERM must end the daemon with exit 0, got {status}:\n{}",
        read_log()
    );
}

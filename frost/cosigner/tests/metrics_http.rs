// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! End-to-end smoke test for the Prometheus /metrics endpoint: install the real exporter, emit
//! each metric the daemon records, and scrape it over plain HTTP like Prometheus would.
//!
//! Lives alone in this file because `metrics::install` sets a process-global recorder (each test
//! binary is its own process, so this cannot collide with other test files).

use std::io::{Read, Write};

#[tokio::test(flavor = "multi_thread")]
async fn metrics_endpoint_serves_all_daemon_metrics() {
    // Unusual fixed port — the exporter offers no way to discover an OS-assigned one.
    let listen = "127.0.0.1:19644";
    rutli_cosigner::metrics::install(listen).expect("install exporter");

    // Emit one sample of everything the daemon records.
    metrics::counter!(rutli_cosigner::metrics::SIGN_REQUESTS, "result" => "ok").increment(1);
    metrics::histogram!(rutli_cosigner::metrics::SIGN_DURATION, "result" => "ok").record(0.05);
    metrics::counter!(rutli_cosigner::metrics::CEREMONY_REQUESTS, "kind" => "dkg", "result" => "ok")
        .increment(1);
    metrics::counter!(rutli_cosigner::metrics::SIGN_ROUND1_SKIPS).increment(1);
    metrics::counter!(rutli_cosigner::metrics::SIGN_ABORTS).increment(1);
    metrics::gauge!(rutli_cosigner::metrics::PENDING_SIGN_SESSIONS).set(2.0);

    // Scrape like Prometheus: plain HTTP GET (retry briefly while the listener comes up).
    let body = scrape(listen).await;

    for name in [
        "rutli_sign_requests_total",
        "rutli_sign_duration_seconds",
        "rutli_ceremony_requests_total",
        "rutli_sign_round1_skips_total",
        "rutli_sign_aborts_total",
        "rutli_pending_sign_sessions",
    ] {
        assert!(body.contains(name), "scrape missing {name}:\n{body}");
    }
    assert!(body.contains(r#"result="ok""#), "labels must survive to the exposition");
    assert!(body.contains("rutli_pending_sign_sessions 2"), "gauge value must be exposed");

    // A bad address is a config error, not a panic.
    assert!(rutli_cosigner::metrics::install("not-an-addr").is_err());
}

async fn scrape(listen: &str) -> String {
    for _ in 0..50 {
        if let Ok(mut stream) = std::net::TcpStream::connect(listen) {
            stream
                .write_all(format!("GET /metrics HTTP/1.0\r\nHost: {listen}\r\n\r\n").as_bytes())
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            if let Some((_, body)) = response.split_once("\r\n\r\n") {
                return body.to_string();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("metrics endpoint never came up on {listen}");
}

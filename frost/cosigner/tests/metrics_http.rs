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

    // Emit one sample of everything the daemon records. The latency samples straddle several
    // bucket bounds so the histogram assertions below see a non-trivial cumulative distribution.
    metrics::counter!(rutli_cosigner::metrics::SIGN_REQUESTS, "result" => "ok").increment(1);
    for secs in [0.05, 0.083, 0.7, 3.0] {
        metrics::histogram!(rutli_cosigner::metrics::SIGN_DURATION, "result" => "ok").record(secs);
    }
    metrics::histogram!(rutli_cosigner::metrics::SIGN_DURATION, "result" => "error").record(0.2);
    metrics::counter!(rutli_cosigner::metrics::CEREMONY_REQUESTS, "kind" => "dkg", "result" => "ok")
        .increment(1);
    metrics::counter!(rutli_cosigner::metrics::SIGN_ROUND1_SKIPS).increment(1);
    metrics::counter!(rutli_cosigner::metrics::SIGN_ABORTS).increment(1);
    metrics::gauge!(rutli_cosigner::metrics::PENDING_SIGN_SESSIONS).set(2.0);
    metrics::gauge!(rutli_cosigner::metrics::KEYSTORE_UNREADABLE).set(1.0);

    // Scrape like Prometheus: plain HTTP GET (retry briefly while the listener comes up).
    let body = scrape(listen).await;

    for name in [
        "rutli_sign_requests_total",
        "rutli_sign_duration_seconds",
        "rutli_ceremony_requests_total",
        "rutli_sign_round1_skips_total",
        "rutli_sign_aborts_total",
        "rutli_pending_sign_sessions",
        "rutli_keystore_unreadable",
    ] {
        assert!(body.contains(name), "scrape missing {name}:\n{body}");
    }
    assert!(body.contains(r#"result="ok""#), "labels must survive to the exposition");
    assert!(body.contains("rutli_pending_sign_sessions 2"), "gauge value must be exposed");
    assert!(body.contains("rutli_keystore_unreadable 1"), "keystore gauge must be exposed");

    assert_sign_duration_is_a_histogram(&body);

    // A bad address is a config error, not a panic.
    assert!(rutli_cosigner::metrics::install("not-an-addr").is_err());
}

/// Every consumer of `rutli_sign_duration_seconds` — the `RutliSignLatencyHigh` rule, the Grafana
/// latency panel, the soak gate — runs `histogram_quantile()` over `_bucket` series. Without
/// explicit buckets the exporter silently renders a *summary* instead (`quantile=` series, no
/// `_bucket`), which is exactly what the 2026-10-07 DevNet soak found on the live endpoint, so
/// this pins the wire format.
fn assert_sign_duration_is_a_histogram(exposition: &str) {
    const NAME: &str = "rutli_sign_duration_seconds";
    assert!(
        exposition.contains(&format!("# TYPE {NAME} histogram")),
        "{NAME} must be typed as a histogram:\n{exposition}"
    );
    assert!(
        !exposition.contains(&format!("# TYPE {NAME} summary")),
        "{NAME} must not be rendered as a summary:\n{exposition}"
    );
    assert!(!exposition.contains("quantile="), "no summary quantiles anywhere:\n{exposition}");

    // Exactly the configured bounds, plus +Inf, for each label set that was recorded.
    for result in ["ok", "error"] {
        for le in rutli_cosigner::metrics::SIGN_DURATION_BUCKETS {
            let line = format!(r#"{NAME}_bucket{{result="{result}",le="{le}"}} "#);
            assert!(exposition.contains(&line), "missing bucket line {line:?}:\n{exposition}");
        }
        let inf = format!(r#"{NAME}_bucket{{result="{result}",le="+Inf"}} "#);
        assert!(exposition.contains(&inf), "missing +Inf bucket {inf:?}:\n{exposition}");
        for suffix in ["sum", "count"] {
            let line = format!(r#"{NAME}_{suffix}{{result="{result}"}} "#);
            assert!(exposition.contains(&line), "missing {line:?}:\n{exposition}");
        }
    }

    // Cumulative counts for result="ok" (samples 0.05, 0.083, 0.7, 3.0): the 1 s bound — the
    // soak gate's threshold — must sit at exactly the right place in the distribution.
    assert_eq!(bucket_count(exposition, "ok", "0.05"), 1, "le=0.05 holds the 50 ms sample");
    assert_eq!(bucket_count(exposition, "ok", "0.1"), 2, "le=0.1 adds the 83 ms sample");
    assert_eq!(bucket_count(exposition, "ok", "1"), 3, "le=1 adds the 700 ms sample");
    assert_eq!(bucket_count(exposition, "ok", "5"), 4, "le=5 adds the 3 s sample");
    assert_eq!(bucket_count(exposition, "ok", "10"), 4, "le=10 (headroom above the 5 s alert)");
    assert_eq!(bucket_count(exposition, "ok", "+Inf"), 4, "+Inf holds every sample");
    assert_eq!(bucket_count(exposition, "error", "0.25"), 1, "error sample lands in le=0.25");
    assert_eq!(bucket_count(exposition, "error", "0.15"), 0, "error sample is above le=0.15");
}

fn bucket_count(exposition: &str, result: &str, le: &str) -> u64 {
    let prefix = format!(r#"rutli_sign_duration_seconds_bucket{{result="{result}",le="{le}"}} "#);
    exposition
        .lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no line starting {prefix:?}:\n{exposition}"))
        .trim()
        .parse()
        .expect("bucket count is an integer")
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

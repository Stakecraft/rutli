// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for the cosigner daemon.
//!
//! Served as a plaintext HTTP `/metrics` endpoint when `metrics_listen` is configured (see
//! [`crate::config::Config`]). Every metric is an operation count, latency, or in-flight gauge —
//! never key material, digests, or session ids — which is why plaintext HTTP is acceptable here
//! while everything else in the daemon rides mTLS.
//!
//! When no exporter is installed (tests, `metrics_listen` unset) the `metrics` macros are no-ops,
//! so the instrumented paths cost nothing to callers that don't opt in.

use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
use metrics_exporter_prometheus::PrometheusBuilder;

use crate::{DaemonError, Result};

/// Leader-side `Signer.Sign` outcomes. Labels: `result` = "ok" | "error".
pub const SIGN_REQUESTS: &str = "rutli_sign_requests_total";
/// Leader-side `Signer.Sign` latency histogram. Labels: `result` = "ok" | "error".
pub const SIGN_DURATION: &str = "rutli_sign_duration_seconds";
/// Key-ceremony outcomes. Labels: `kind` = "dkg" | "refresh", `result` = "ok" | "error".
pub const CEREMONY_REQUESTS: &str = "rutli_ceremony_requests_total";
/// Peers skipped during sign round 1 (unreachable or refusing) — a quorum-margin canary.
pub const SIGN_ROUND1_SKIPS: &str = "rutli_sign_round1_skips_total";
/// Leader-issued aborts of in-flight sign sessions (one per given-up signature).
pub const SIGN_ABORTS: &str = "rutli_sign_aborts_total";
/// In-flight (round-1, not yet round-2) sign sessions currently held on this node.
pub const PENDING_SIGN_SESSIONS: &str = "rutli_pending_sign_sessions";
/// Hosted keys repaired by anti-entropy (pulled here or pushed to a peer).
pub const ANTI_ENTROPY_REPAIRS: &str = "rutli_anti_entropy_repairs_total";
/// Hosted keys found with *different* material on two nodes under one id. Any increase is a
/// page-worthy invariant violation, not a transient.
pub const ANTI_ENTROPY_CONFLICTS: &str = "rutli_anti_entropy_conflicts_total";
/// Hosted keys held by this node.
pub const HOSTED_KEYS: &str = "rutli_hosted_keys";
/// Key files present on disk that could not be opened (wrong seal secret, corruption). Skipped
/// from the hosted-key inventory, so any non-zero value means a key is silently not being
/// replicated or repaired — alert on it.
pub const UNREADABLE_KEY_FILES: &str = "rutli_unreadable_key_files_total";
/// Hosted-key decryptions refused by the per-key rate limit. Non-zero means either a node that has
/// outgrown its configured ceiling, or bulk decryption by someone holding the driver certificate —
/// both worth an operator's attention, so alert on any sustained value.
pub const DECRYPT_RATE_LIMITED: &str = "rutli_decrypt_rate_limited_total";
/// Hosted-key operations by op and result (generate/decrypt/symmetric/delete).
pub const HOSTED_KEY_OPS: &str = "rutli_hosted_key_ops_total";
/// The *fewest* cosigners holding any one hosted key, as last observed by anti-entropy.
///
/// This is the alert that makes a write quorum below `n` safe: a key written to only a quorum is
/// fine transiently, but must not stay that way. Alert below `n` (warning) and below the write
/// quorum (critical).
pub const KEY_REPLICAS: &str = "rutli_key_replicas";

/// Install the process-global Prometheus recorder and serve `/metrics` on `listen`.
/// Call at most once, before serving traffic.
pub fn install(listen: &str) -> Result<()> {
    let addr: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| DaemonError::Config(format!("bad metrics_listen addr {listen}: {e}")))?;
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| DaemonError::Config(format!("metrics exporter on {listen}: {e}")))?;
    describe();
    prime();
    Ok(())
}

/// Initialize every fixed label combination to zero so an idle daemon's scrape already exposes
/// all series — `increase()`/`rate()` alert rules misbehave on series that don't exist yet.
fn prime() {
    for result in ["ok", "error"] {
        metrics::counter!(SIGN_REQUESTS, "result" => result).absolute(0);
        for kind in ["dkg", "refresh"] {
            metrics::counter!(CEREMONY_REQUESTS, "kind" => kind, "result" => result).absolute(0);
        }
    }
    metrics::counter!(SIGN_ROUND1_SKIPS).absolute(0);
    metrics::counter!(ANTI_ENTROPY_REPAIRS).absolute(0);
    metrics::counter!(ANTI_ENTROPY_CONFLICTS).absolute(0);
    metrics::gauge!(HOSTED_KEYS).set(0.0);
    metrics::counter!(UNREADABLE_KEY_FILES).absolute(0);
    metrics::counter!(DECRYPT_RATE_LIMITED).absolute(0);
    // No hosted keys yet means no shortfall — not a shortfall of zero, which would page instantly.
    metrics::gauge!(KEY_REPLICAS).set(f64::NAN);
    metrics::counter!(SIGN_ABORTS).absolute(0);
    metrics::gauge!(PENDING_SIGN_SESSIONS).set(0.0);
}

/// Register help texts (shown in the Prometheus exposition; harmless without a recorder).
pub fn describe() {
    describe_counter!(SIGN_REQUESTS, "Leader-side Sign RPC outcomes, by result");
    describe_histogram!(SIGN_DURATION, Unit::Seconds, "Leader-side Sign RPC latency, by result");
    describe_counter!(CEREMONY_REQUESTS, "DKG/refresh ceremony outcomes, by kind and result");
    describe_counter!(SIGN_ROUND1_SKIPS, "Peers skipped during sign round 1 (quorum-margin canary)");
    describe_counter!(SIGN_ABORTS, "Aborted in-flight sign sessions (one per given-up signature)");
    describe_gauge!(PENDING_SIGN_SESSIONS, "In-flight round-1 sign sessions held on this node");
    describe_counter!(ANTI_ENTROPY_REPAIRS, "Hosted keys repaired by anti-entropy");
    describe_counter!(ANTI_ENTROPY_CONFLICTS, "Hosted keys with divergent material across nodes");
    describe_gauge!(HOSTED_KEYS, "Cluster-hosted keys held by this node");
    describe_counter!(HOSTED_KEY_OPS, "Hosted-key operations, by op and result");
    describe_counter!(UNREADABLE_KEY_FILES, "Key files that could not be opened and were skipped");
    describe_counter!(DECRYPT_RATE_LIMITED, "Hosted-key decryptions refused by the per-key rate limit");
    describe_gauge!(KEY_REPLICAS, "Fewest cosigners holding any one hosted key");
}

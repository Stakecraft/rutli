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
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder};

use crate::{DaemonError, Result};

/// Leader-side `Signer.Sign` outcomes. Labels: `result` = "ok" | "error".
pub const SIGN_REQUESTS: &str = "rutli_sign_requests_total";
/// Leader-side `Signer.Sign` latency histogram. Labels: `result` = "ok" | "error".
pub const SIGN_DURATION: &str = "rutli_sign_duration_seconds";
/// Key-ceremony outcomes. Labels: `kind` = "dkg" | "refresh", `result` = "ok" | "error".
pub const CEREMONY_REQUESTS: &str = "rutli_ceremony_requests_total";
/// Two-phase ceremonies this node resolved, by `result` (committed | aborted).
pub const CEREMONY_RESOLUTIONS: &str = "rutli_ceremony_resolutions_total";
/// STAGED ceremonies on this node that are not yet resolved (resolver waiting on a peer).
pub const CEREMONIES_STAGED: &str = "rutli_ceremonies_staged";
/// Peers skipped during sign round 1 (unreachable or refusing) — a quorum-margin canary.
pub const SIGN_ROUND1_SKIPS: &str = "rutli_sign_round1_skips_total";
/// Leader-issued aborts of in-flight sign sessions (one per given-up signature).
pub const SIGN_ABORTS: &str = "rutli_sign_aborts_total";
/// In-flight (round-1, not yet round-2) sign sessions currently held on this node.
pub const PENDING_SIGN_SESSIONS: &str = "rutli_pending_sign_sessions";
/// Sign round-1 refusals on this node because the leader signed with another sharing of the key
/// than this node committed (audit H1/M1). Any increase means two nodes hold different epochs of
/// one key: alert on it.
pub const EPOCH_MISMATCH: &str = "rutli_epoch_mismatch_total";
/// Sign round-1 requests from a leader that sent no sharing (a release before epochs): the epoch
/// check was skipped. Expected only during a rolling upgrade.
pub const EPOCH_CHECK_SKIPPED: &str = "rutli_epoch_check_skipped_total";
/// 1 while this node's epoch check finds its share of `key` stale (a peer holds a newer committed
/// sharing this node never voted for — typically a restore from an old backup), else 0. A stale
/// node refuses to sign or lead for the key. Labels: `key`. Alert on any 1.
pub const STALE_SHARE: &str = "rutli_stale_share";
/// Sign attempts beyond the first within one Sign request: a t-subset failed and the leader
/// retried with another (fresh session, fresh commitments).
/// Sign rounds this node took part in without a signing intent (a driver or leader older than
/// intents), accepted because `signing_policy.require_intent` is off.
pub const SIGN_INTENT_ABSENT: &str = "rutli_sign_intent_absent_total";
/// Signing-policy refusals at this node, by `reason` (certificate, signer, pin, signature, cluster,
/// key, purpose, expiry, acl, approval, malformed, missing, role, sign-test).
pub const SIGN_POLICY_REFUSALS: &str = "rutli_sign_policy_refusals_total";
/// Signature shares this node refused because a per-key sign rate limit or the per-request share
/// cap was reached.
pub const SIGN_RATE_LIMITED: &str = "rutli_sign_rate_limited_total";
/// Key operations by a Signer client CN with no `signing_policy.signer_acl` entry (allowed while
/// `signer_acl_required` is off).
pub const SIGNER_ACL_ABSENT: &str = "rutli_signer_acl_absent_total";
/// Sign journal entries appended (one per released signature share).
pub const SIGN_JOURNAL_ENTRIES: &str = "rutli_sign_journal_entries_total";
/// Sign journal failures (corrupt on open, append failed): the share was refused.
pub const SIGN_JOURNAL_ERRORS: &str = "rutli_sign_journal_errors_total";
pub const SIGN_RETRIES: &str = "rutli_sign_retries_total";
/// Signature shares that failed verification at aggregation (attributed to a cosigner and routed
/// around). Any increase means a cosigner returned a bad share: alert on it.
pub const INVALID_SIGNATURE_SHARES: &str = "rutli_invalid_signature_shares_total";
/// Burned-session nonce markers removed past their retention (audit L4).
pub const NONCE_MARKERS_PRUNED: &str = "rutli_nonce_markers_pruned_total";
/// Burned-session nonce markers on this node after the last prune pass, all keys. Each costs an
/// inode on the key volume; it stays bounded by the sign rate over the retention window.
pub const NONCE_MARKERS: &str = "rutli_nonce_markers";
/// Locks recovered after a panicking request poisoned them (audit L3), by `lock`. The node kept
/// serving; the panic itself is a bug — alert on any increase and report it.
pub const LOCK_POISON_RECOVERIES: &str = "rutli_lock_poison_recoveries_total";
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
/// Gauge, labels `format` (v1|v2|plaintext) and `dek` (current|previous|unknown|none): this node's
/// key files at start-up (audit M4). A v2 migration watches `format="v1"` reach 0; a DEK rotation
/// watches `dek="previous"` reach 0 before the previous DEK is dropped from the seal bundle.
pub const KEYFILES: &str = "rutli_keyfiles";
/// Hosted-key decryptions refused by the per-key rate limit. Non-zero means either a node that has
/// outgrown its configured ceiling, or bulk decryption by someone holding the driver certificate —
/// both worth an operator's attention, so alert on any sustained value.
pub const DECRYPT_RATE_LIMITED: &str = "rutli_decrypt_rate_limited_total";
/// Split-ceremony sign tests refused by the per-key rate limit. A `verify-key --sign-test` run never
/// trips it; a non-zero value means something is looping `CeremonySignTest`.
pub const CEREMONY_SIGN_TEST_RATE_LIMITED: &str = "rutli_ceremony_sign_test_rate_limited_total";
/// Hosted-key operations by op and result (generate/decrypt/symmetric/delete).
pub const HOSTED_KEY_OPS: &str = "rutli_hosted_key_ops_total";
/// The *fewest* cosigners holding any one hosted key, as last observed by anti-entropy.
///
/// This is the alert that makes a write quorum below `n` safe: a key written to only a quorum is
/// fine transiently, but must not stay that way. Alert below `n` (warning) and below the write
/// quorum (critical).
pub const KEY_REPLICAS: &str = "rutli_key_replicas";
/// 1 while this node's key store fails its readiness probe — the volume under `data_dir/keys`
/// cannot be listed, opened, read or written — else 0. Every Sign/Dkg this node touches fails in
/// that state, so alert on it (critical). Refreshed by the daemon's own probe loop and by every
/// `Signer.Health` call; not the same as [`UNREADABLE_KEY_FILES`] (one file failing to unseal).
pub const KEYSTORE_UNREADABLE: &str = "rutli_keystore_unreadable";

/// Upper bounds (seconds) of the `rutli_sign_duration_seconds` histogram buckets.
///
/// Without explicit buckets `metrics-exporter-prometheus` renders a `histogram!` as a Prometheus
/// *summary* (`{quantile="…"}` series, no `_bucket`), which is what the 2026-10-07 DevNet soak
/// found on the live endpoint: `histogram_quantile()` in the latency alert, the dashboard and the
/// soak gate had nothing to read. The bounds bracket the observed 50–150 ms FROST round trip (two
/// mTLS hops to a quorum) with ~25 ms resolution, then widen past the 1 s soak gate and the 5 s
/// `RutliSignLatencyHigh` threshold. The 10 s bound is load-bearing: `histogram_quantile()` can
/// only report an estimate *above* a threshold when a finite bucket lies above it (a quantile that
/// lands in `+Inf` is reported as the highest finite bound), so without it a `> 5` rule could
/// never fire.
pub const SIGN_DURATION_BUCKETS: &[f64] =
    &[0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// The exporter configuration shared by [`install`] and the exposition-format test below, so the
/// test pins exactly what the daemon serves.
fn builder() -> std::result::Result<PrometheusBuilder, BuildError> {
    PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Full(SIGN_DURATION.to_owned()), SIGN_DURATION_BUCKETS)
}

/// Install the process-global Prometheus recorder and serve `/metrics` on `listen`.
/// Call at most once, before serving traffic.
pub fn install(listen: &str) -> Result<()> {
    let addr: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| DaemonError::Config(format!("bad metrics_listen addr {listen}: {e}")))?;
    builder()
        .and_then(|b| b.with_http_listener(addr).install())
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
    for result in ["committed", "aborted"] {
        metrics::counter!(CEREMONY_RESOLUTIONS, "result" => result).absolute(0);
    }
    metrics::gauge!(CEREMONIES_STAGED).set(0.0);
    metrics::counter!(SIGN_ROUND1_SKIPS).absolute(0);
    metrics::counter!(EPOCH_MISMATCH).absolute(0);
    metrics::counter!(EPOCH_CHECK_SKIPPED).absolute(0);
    metrics::counter!(SIGN_RETRIES).absolute(0);
    metrics::counter!(INVALID_SIGNATURE_SHARES).absolute(0);
    metrics::counter!(NONCE_MARKERS_PRUNED).absolute(0);
    metrics::counter!(ANTI_ENTROPY_REPAIRS).absolute(0);
    metrics::counter!(ANTI_ENTROPY_CONFLICTS).absolute(0);
    metrics::gauge!(HOSTED_KEYS).set(0.0);
    metrics::counter!(UNREADABLE_KEY_FILES).absolute(0);
    metrics::counter!(DECRYPT_RATE_LIMITED).absolute(0);
    metrics::counter!(CEREMONY_SIGN_TEST_RATE_LIMITED).absolute(0);
    metrics::counter!(SIGN_INTENT_ABSENT).absolute(0);
    metrics::counter!(SIGN_RATE_LIMITED).absolute(0);
    metrics::counter!(SIGNER_ACL_ABSENT).absolute(0);
    metrics::counter!(SIGN_JOURNAL_ENTRIES).absolute(0);
    metrics::counter!(SIGN_JOURNAL_ERRORS).absolute(0);
    // No hosted keys yet means no shortfall — not a shortfall of zero, which would page instantly.
    metrics::gauge!(KEY_REPLICAS).set(f64::NAN);
    metrics::counter!(SIGN_ABORTS).absolute(0);
    metrics::gauge!(PENDING_SIGN_SESSIONS).set(0.0);
    metrics::gauge!(KEYSTORE_UNREADABLE).set(0.0);
}

/// Register help texts (shown in the Prometheus exposition; harmless without a recorder).
pub fn describe() {
    describe_counter!(SIGN_REQUESTS, "Leader-side Sign RPC outcomes, by result");
    describe_histogram!(SIGN_DURATION, Unit::Seconds, "Leader-side Sign RPC latency, by result");
    describe_counter!(CEREMONY_REQUESTS, "DKG/refresh ceremony outcomes, by kind and result");
    describe_counter!(CEREMONY_RESOLUTIONS, "Two-phase ceremonies resolved on this node, by result");
    describe_gauge!(CEREMONIES_STAGED, "Staged (yes-voted, unresolved) ceremonies on this node");
    describe_counter!(SIGN_ROUND1_SKIPS, "Peers skipped during sign round 1 (quorum-margin canary)");
    describe_counter!(SIGN_INTENT_ABSENT, "Sign rounds accepted without a signing intent (require_intent off)");
    describe_counter!(SIGN_POLICY_REFUSALS, "Signing-policy refusals at this node, by reason");
    describe_counter!(SIGN_RATE_LIMITED, "Signature shares refused by the per-key sign rate limit or share cap");
    describe_counter!(SIGNER_ACL_ABSENT, "Key operations by a client CN without a signer_acl entry");
    describe_counter!(SIGN_JOURNAL_ENTRIES, "Sign journal entries appended (one per released share)");
    describe_counter!(SIGN_JOURNAL_ERRORS, "Sign journal failures; the share was refused");
    describe_counter!(EPOCH_MISMATCH, "Sign round-1 refusals: the leader signed with another sharing (epoch)");
    describe_counter!(EPOCH_CHECK_SKIPPED, "Sign round-1 requests without the leader's sharing (pre-epoch leader)");
    describe_gauge!(STALE_SHARE, "1 while this node's share of the key is stale (refuses to sign), else 0");
    describe_counter!(SIGN_RETRIES, "Sign attempts beyond the first (a t-subset failed; retried with another)");
    describe_counter!(INVALID_SIGNATURE_SHARES, "Signature shares that failed verification at aggregation");
    describe_counter!(NONCE_MARKERS_PRUNED, "Burned-session nonce markers removed past their retention");
    describe_gauge!(NONCE_MARKERS, "Burned-session nonce markers on this node after the last prune pass");
    describe_counter!(LOCK_POISON_RECOVERIES, "Locks recovered after a panicking request poisoned them, by lock");
    describe_counter!(SIGN_ABORTS, "Aborted in-flight sign sessions (one per given-up signature)");
    describe_gauge!(PENDING_SIGN_SESSIONS, "In-flight round-1 sign sessions held on this node");
    describe_counter!(ANTI_ENTROPY_REPAIRS, "Hosted keys repaired by anti-entropy");
    describe_counter!(ANTI_ENTROPY_CONFLICTS, "Hosted keys with divergent material across nodes");
    describe_gauge!(HOSTED_KEYS, "Cluster-hosted keys held by this node");
    describe_counter!(HOSTED_KEY_OPS, "Hosted-key operations, by op and result");
    describe_counter!(UNREADABLE_KEY_FILES, "Key files that could not be opened and were skipped");
    describe_counter!(DECRYPT_RATE_LIMITED, "Hosted-key decryptions refused by the per-key rate limit");
    describe_counter!(
        CEREMONY_SIGN_TEST_RATE_LIMITED,
        "Split-ceremony sign tests refused by the per-key rate limit"
    );
    describe_gauge!(KEY_REPLICAS, "Fewest cosigners holding any one hosted key");
    describe_gauge!(
        KEYSTORE_UNREADABLE,
        "1 while this node's key store cannot be listed, opened or written (readiness probe), else 0"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render the daemon's exporter configuration in-process (a local recorder, so no global state
    /// and no port) and check `rutli_sign_duration_seconds` comes out as a real histogram. Without
    /// explicit buckets the exporter renders a *summary* (`quantile=` series, no `_bucket`), which
    /// every consumer's `histogram_quantile()` silently reads as "no data" — the 2026-10-07 soak
    /// finding.
    #[test]
    fn sign_duration_renders_as_histogram_with_buckets() {
        let recorder = builder().expect("valid buckets").build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            describe();
            prime();
            metrics::histogram!(SIGN_DURATION, "result" => "ok").record(0.083);
            metrics::histogram!(SIGN_DURATION, "result" => "ok").record(1.7);
        });
        let out = handle.render();

        assert!(out.contains("# TYPE rutli_sign_duration_seconds histogram"), "{out}");
        assert!(!out.contains("quantile="), "summary quantiles must not be rendered:\n{out}");
        for le in SIGN_DURATION_BUCKETS {
            let line = format!(r#"{SIGN_DURATION}_bucket{{result="ok",le="{le}"}} "#);
            assert!(out.contains(&line), "missing {line:?}:\n{out}");
        }
        // Cumulative: the 83 ms sample is under the 1 s soak-gate bound, the 1.7 s one is not.
        for (le, count) in [("1", 1), ("2.5", 2), ("+Inf", 2)] {
            let line = format!(r#"{SIGN_DURATION}_bucket{{result="ok",le="{le}"}} {count}"#);
            assert!(out.lines().any(|l| l == line), "missing {line:?}:\n{out}");
        }
        assert!(out.contains(r#"rutli_sign_duration_seconds_count{result="ok"} 2"#), "{out}");
    }

    #[test]
    fn buckets_are_strictly_increasing_and_span_the_alert_threshold() {
        assert!(SIGN_DURATION_BUCKETS.windows(2).all(|w| w[0] < w[1]));
        // RutliSignLatencyHigh fires on p99 > 5 s; histogram_quantile() can only estimate above
        // 5 when a finite bucket bound lies above it.
        assert!(SIGN_DURATION_BUCKETS.iter().any(|&b| b > 5.0));
        // The soak gate's 1 s threshold should be a bucket bound, so "p99 < 1" is exact.
        assert!(SIGN_DURATION_BUCKETS.contains(&1.0));
    }
}

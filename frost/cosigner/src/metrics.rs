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
/// Two-phase ceremonies this node resolved, by `result` (committed | aborted | recovered).
pub const CEREMONY_RESOLUTIONS: &str = "rutli_ceremony_resolutions_total";
/// STAGED ceremonies on this node that are not yet resolved (resolver waiting on a peer).
pub const CEREMONIES_STAGED: &str = "rutli_ceremonies_staged";
/// Ceremonies this node aborted while a peer reports them COMMITTED (a split; audit F3), with the
/// staged share still quarantined for `ceremony recover-commit`.
pub const CEREMONIES_SPLIT: &str = "rutli_ceremonies_split";
/// One ceremony reported both COMMITTED and ABORTED by peers: a cosigner equivocated (audit F3).
pub const CEREMONY_EQUIVOCATIONS: &str = "rutli_ceremony_equivocations_total";
/// No-votes this node refused to record (and so did not answer) for unknown ceremony ids or
/// orphaned sessions, because a cap was reached (audit F2).
pub const CEREMONY_UNKNOWN_REFUSED: &str = "rutli_ceremony_unknown_refused_total";
/// No-votes held for ceremony ids peers asked about that this node never knew (audit F2).
pub const CEREMONY_UNKNOWN_NO_VOTES: &str = "rutli_ceremony_unknown_no_votes";
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
/// Counter, label `reason`: DKG/refresh ceremony intents this node refused — at the fence or part 1
/// of a ceremony a peer leads, or as leader on Signer.Dkg/Refresh (certificate, signer, pin,
/// signature, cluster, purpose, key, expiry, acl, malformed, ceremony-id, missing). A refusal on the
/// mesh path means a leader asked for a ceremony no authorized client requested: alert on it.
pub const CEREMONY_INTENT_REFUSALS: &str = "rutli_ceremony_intent_refusals_total";
/// Counter: DKG/refresh fences and part 1s this node accepted without a ceremony intent (a leader
/// or client that predates them), because `signing_policy.require_ceremony_intent` is off.
pub const CEREMONY_INTENT_ABSENT: &str = "rutli_ceremony_intent_absent_total";
/// Counter, label `reason`: hosted-key delete intents this node refused (audit M2) — on DeleteKey,
/// on a peer's PurgeKey, and on a tombstone a peer propagated in anti-entropy. A forged or
/// unauthorized tombstone shows up here.
pub const DELETE_INTENT_REFUSALS: &str = "rutli_delete_intent_refusals_total";
/// Counter, label `how` (converted|recorded): tombstones this node wrote, once per node and delete
/// (a repeated or retried delete of a tombstoned id writes nothing). `converted`: a live copy
/// replaced by a tombstone — by a delete this node took part in (DeleteKey's fan-out, a peer's
/// PurgeKey with the intent) or by a peer's tombstone in anti-entropy. `recorded`: a tombstone
/// recorded for a key this node did not hold. Dropping the retained material after the grace
/// period writes no tombstone and is not counted. The node that served the DeleteKey also counts
/// it in `rutli_hosted_key_ops_total{op="delete"}`.
pub const HOSTED_TOMBSTONES_WRITTEN: &str = "rutli_hosted_tombstones_written_total";
/// Gauge: tombstones on this node (deleted hosted keys), and how many still retain material for
/// undelete (`retained="true"`).
pub const HOSTED_TOMBSTONES: &str = "rutli_hosted_tombstones";
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

/// Every `reason` label value `rutli_sign_policy_refusals_total` can carry (the string literals the
/// `refused(..)` call sites in `intent.rs`, `sign_policy.rs`, `service.rs` and `node.rs` pass).
/// Primed to 0 at start so the first refusal moves the series from 0 to 1 and `increase()` sees it
/// (`RutliSignPolicyRefusals`). The `reasons_cover_the_call_sites` test fails when a call site uses
/// a literal missing here.
pub const SIGN_POLICY_REASONS: &[&str] = &[
    "acl",
    "approval",
    "certificate",
    "cluster",
    "expiry",
    "key",
    "malformed",
    "missing",
    "pin",
    "purpose",
    "role",
    "sign-test",
    "signature",
    "signer",
];
/// Every `reason` of `rutli_ceremony_intent_refusals_total` (`refused_ceremony(..)` and the shared
/// signer checks it drives). Primed for `RutliCeremonyIntentRefused`.
pub const CEREMONY_INTENT_REASONS: &[&str] = &[
    "acl",
    "ceremony-id",
    "certificate",
    "cluster",
    "expiry",
    "key",
    "malformed",
    "missing",
    "pin",
    "purpose",
    "signature",
    "signer",
];
/// Every `reason` of `rutli_delete_intent_refusals_total` (`refused_delete(..)` and the shared
/// signer checks it drives). Primed for `RutliDeleteIntentRefused`.
pub const DELETE_INTENT_REASONS: &[&str] = &[
    "acl",
    "approval",
    "certificate",
    "cluster",
    "disabled",
    "expiry",
    "key",
    "malformed",
    "missing",
    "pin",
    "policy-changed",
    "purpose",
    "role",
    "rollback",
    "signature",
    "signer",
    "stale",
];
/// The `how` values `rutli_hosted_tombstones_written_total` is incremented with in `node.rs`
/// (`RutliHostedKeyDeleted`); a test checks the call sites and the doc comment against it.
pub const TOMBSTONE_HOWS: &[&str] = &["converted", "recorded"];
/// The `lock` names passed to `sync::recover` / `recover_reset` / `note` and the sign-session map
/// recovery (`RutliLockPoisonRecovered`). `test_hook` (test-only hooks) is left out.
pub const LOCK_NAMES: &[&str] = &[
    "ceremony_book",
    "ceremony_guards",
    "hosted_created_in",
    "key_cache",
    "rate_limiter",
    "sign_journal",
    "sign_sessions",
    "stale_marks",
];
/// The `op` values of `rutli_hosted_key_ops_total` (`record_hosted_op` call sites in `service.rs`);
/// `result` is "ok" | "error" (`RutliHostedKeyErrors`).
pub const HOSTED_KEY_OPS_NAMES: &[&str] =
    &["generate", "delete", "decrypt", "ecdh_derive", "symmetric_encrypt", "symmetric_decrypt"];

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
/// all series — `increase()`/`rate()` alert rules misbehave on series that don't exist yet: a
/// series created by its first event starts at 1, `increase()` reads 0 for it, and the alert never
/// fires for that first event (the 2026-10-20 soak: the rc.3 negative test did not fire
/// `RutliSignPolicyRefusals`). Labels that are not a closed set (`rutli_stale_share{key}`)
/// cannot be primed.
fn prime() {
    for result in ["ok", "error"] {
        metrics::counter!(SIGN_REQUESTS, "result" => result).absolute(0);
        for kind in ["dkg", "refresh"] {
            metrics::counter!(CEREMONY_REQUESTS, "kind" => kind, "result" => result).absolute(0);
        }
    }
    for result in ["committed", "aborted", "recovered"] {
        metrics::counter!(CEREMONY_RESOLUTIONS, "result" => result).absolute(0);
    }
    metrics::gauge!(CEREMONIES_STAGED).set(0.0);
    metrics::gauge!(CEREMONIES_SPLIT).set(0.0);
    metrics::counter!(CEREMONY_EQUIVOCATIONS).absolute(0);
    metrics::counter!(CEREMONY_UNKNOWN_REFUSED).absolute(0);
    metrics::gauge!(CEREMONY_UNKNOWN_NO_VOTES).set(0.0);
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
    metrics::counter!(CEREMONY_INTENT_ABSENT).absolute(0);
    metrics::counter!(SIGN_RATE_LIMITED).absolute(0);
    metrics::counter!(SIGNER_ACL_ABSENT).absolute(0);
    metrics::counter!(SIGN_JOURNAL_ENTRIES).absolute(0);
    metrics::counter!(SIGN_JOURNAL_ERRORS).absolute(0);
    for reason in SIGN_POLICY_REASONS {
        metrics::counter!(SIGN_POLICY_REFUSALS, "reason" => *reason).absolute(0);
    }
    for reason in CEREMONY_INTENT_REASONS {
        metrics::counter!(CEREMONY_INTENT_REFUSALS, "reason" => *reason).absolute(0);
    }
    for reason in DELETE_INTENT_REASONS {
        metrics::counter!(DELETE_INTENT_REFUSALS, "reason" => *reason).absolute(0);
    }
    for how in TOMBSTONE_HOWS {
        metrics::counter!(HOSTED_TOMBSTONES_WRITTEN, "how" => *how).absolute(0);
    }
    for lock in LOCK_NAMES {
        metrics::counter!(LOCK_POISON_RECOVERIES, "lock" => *lock).absolute(0);
    }
    for op in HOSTED_KEY_OPS_NAMES {
        for result in ["ok", "error"] {
            metrics::counter!(HOSTED_KEY_OPS, "op" => *op, "result" => result).absolute(0);
        }
    }
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
    describe_gauge!(CEREMONIES_SPLIT, "Ceremonies aborted here that a peer reports COMMITTED (quarantined share held)");
    describe_counter!(CEREMONY_EQUIVOCATIONS, "Ceremonies reported both COMMITTED and ABORTED by peers (equivocation)");
    describe_counter!(CEREMONY_UNKNOWN_REFUSED, "No-votes for unknown ceremonies not recorded because a cap was reached");
    describe_gauge!(CEREMONY_UNKNOWN_NO_VOTES, "No-votes held for ceremony ids peers asked about that this node never knew");
    describe_counter!(SIGN_ROUND1_SKIPS, "Peers skipped during sign round 1 (quorum-margin canary)");
    describe_counter!(SIGN_INTENT_ABSENT, "Sign rounds accepted without a signing intent (require_intent off)");
    describe_counter!(SIGN_POLICY_REFUSALS, "Signing-policy refusals at this node, by reason");
    describe_counter!(CEREMONY_INTENT_REFUSALS, "DKG/refresh ceremony intents refused at this node, by reason");
    describe_counter!(
        CEREMONY_INTENT_ABSENT,
        "DKG/refresh fences and part 1s accepted without a ceremony intent (require_ceremony_intent off)"
    );
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

    use std::collections::BTreeMap;

    /// Label sets one counter must expose after `prime()`.
    type LabelSets = Vec<Vec<(String, String)>>;
    /// Called with each call site's reason literal and a description of the site.
    type SiteCheck<'a> = Box<dyn FnMut(&str, &str) + 'a>;

    /// The series `name` in a rendered exposition: its labels and its value text.
    fn series(out: &str, name: &str) -> Vec<(BTreeMap<String, String>, String)> {
        out.lines()
            .filter_map(|line| {
                let rest = line.strip_prefix(name)?;
                let (labels, value) = rest.strip_prefix('{')?.split_once("} ")?;
                let labels = labels
                    .split(',')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_owned(), v.trim_matches('"').to_owned()))
                    .collect();
                Some((labels, value.to_owned()))
            })
            .collect()
    }

    /// After `prime()` every labelled alerting counter already exposes each of its series at 0, so
    /// the first refusal takes a series from 0 to 1 and `increase()` sees it (2026-10-20 soak: the
    /// first `rutli_sign_policy_refusals_total{reason}` created the series at 1 and
    /// `RutliSignPolicyRefusals` never fired for it).
    #[test]
    fn prime_exposes_every_labelled_alert_series_at_zero() {
        let recorder = builder().expect("valid buckets").build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            describe();
            prime();
        });
        let out = handle.render();

        let one = |label: &str, values: &[&str]| -> LabelSets {
            values.iter().map(|v| vec![(label.to_owned(), (*v).to_owned())]).collect()
        };
        let mut expected: Vec<(&str, LabelSets)> = vec![
            (SIGN_POLICY_REFUSALS, one("reason", SIGN_POLICY_REASONS)),
            (CEREMONY_INTENT_REFUSALS, one("reason", CEREMONY_INTENT_REASONS)),
            (DELETE_INTENT_REFUSALS, one("reason", DELETE_INTENT_REASONS)),
            (HOSTED_TOMBSTONES_WRITTEN, one("how", TOMBSTONE_HOWS)),
            (LOCK_POISON_RECOVERIES, one("lock", LOCK_NAMES)),
        ];
        let mut ops = Vec::new();
        for op in HOSTED_KEY_OPS_NAMES {
            for result in ["ok", "error"] {
                ops.push(vec![("op".to_owned(), (*op).to_owned()), ("result".to_owned(), result.to_owned())]);
            }
        }
        expected.push((HOSTED_KEY_OPS, ops));

        for (name, wanted) in expected {
            assert!(!wanted.is_empty(), "{name}");
            let rendered = series(&out, name);
            for labels in wanted {
                let found = rendered.iter().find(|(l, _)| labels.iter().all(|(k, v)| l.get(k) == Some(v)));
                match found {
                    Some((_, value)) => assert_eq!(value, "0", "{name}{labels:?} is not primed at 0:\n{out}"),
                    None => panic!("{name}{labels:?} is not primed:\n{out}"),
                }
            }
        }
    }

    /// Every non-test `.rs` file of this crate, as `(name, text)`; `metrics.rs` is left out (its
    /// own lists and tests quote the literals being looked for).
    fn crate_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("metrics.rs") {
                    let text = std::fs::read_to_string(&path).expect("read source");
                    out.push((path.display().to_string(), text));
                }
            }
        }
        let mut out = Vec::new();
        walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
        assert!(out.len() > 5, "found only {} sources: the scan is stale", out.len());
        out
    }

    /// The arguments (top-level comma split, trimmed) of every call `callee(...)` in `src`, outside
    /// `//` comments. Parentheses, brackets and braces nest; string literals are skipped whole. A
    /// definition (`fn callee(`) and a longer identifier (`xcallee(`, `callee_x(`) are not calls.
    fn calls(src: &str, callee: &str) -> Vec<Vec<String>> {
        let code: String = src
            .lines()
            .map(|l| if l.trim_start().starts_with("//") { "" } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        let needle = format!("{callee}(");
        let mut found = Vec::new();
        for (at, _) in code.match_indices(&needle) {
            let before = &code[..at];
            if before.chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_') || before.ends_with("fn ") {
                continue;
            }
            let (mut depth, mut args, mut cur) = (1usize, Vec::new(), String::new());
            let mut chars = code[at + needle.len()..].chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => {
                        cur.push(c);
                        while let Some(d) = chars.next() {
                            cur.push(d);
                            if d == '\\' {
                                cur.extend(chars.next());
                            } else if d == '"' {
                                break;
                            }
                        }
                    }
                    '(' | '[' | '{' => {
                        depth += 1;
                        cur.push(c);
                    }
                    ')' | ']' | '}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        cur.push(c);
                    }
                    ',' if depth == 1 => args.push(std::mem::take(&mut cur).trim().to_owned()),
                    _ => cur.push(c),
                }
            }
            if !cur.trim().is_empty() {
                args.push(cur.trim().to_owned());
            }
            found.push(args);
        }
        found
    }

    /// `arg` as a plain string literal's contents, or a failure naming the call.
    fn literal<'a>(arg: Option<&'a String>, what: &str) -> &'a str {
        arg.and_then(|a| a.strip_prefix('"')?.strip_suffix('"'))
            .unwrap_or_else(|| panic!("{what}: the argument is not a plain string literal ({arg:?}), so it cannot be checked against the primed lists"))
    }

    /// The reason lists are written out by hand; this reads the call sites so a new
    /// `refused("new-reason", ..)` fails here instead of silently going unprimed (and its first
    /// occurrence going unalerted).
    ///
    /// - `refused_ceremony(..)` / `refused_delete(..)` / `refused(..)` are the three counters; their
    ///   own call sites' literals must be in their own list.
    /// - The checks shared by the three paths take the refusal function as a parameter named
    ///   `refuse` (`verify_signer`, `check_acl_with`, `check_pin_with`, `check_times_with`,
    ///   `count_approvals`); every literal they pass can land on any of the three counters, so it
    ///   must be in all three lists — except `approval`, which only the sign and delete paths reach
    ///   (a ceremony intent carries no approvals; `verify_ceremony` never calls `count_approvals`).
    /// - A reason that is not a literal cannot be checked, so it fails the test too.
    #[test]
    fn reasons_cover_the_call_sites() {
        let sources = crate_sources();
        let each = |callee: &str, mut f: SiteCheck<'_>| {
            let mut seen = 0;
            for (file, src) in &sources {
                // keystore.rs's tests have their own `refused(result, msg)` helper, unrelated.
                if file.ends_with("keystore.rs") {
                    continue;
                }
                // export.rs has an unrelated `refuse` closure; the shared checks are all in intent.rs.
                if callee == "refuse" && !file.ends_with("intent.rs") {
                    continue;
                }
                for args in calls(src, callee) {
                    let what = format!("{file}: {callee}(..)");
                    f(literal(args.first(), &what), &what);
                    seen += 1;
                }
            }
            assert!(seen > 0, "no {callee}(..) call found: the scan is stale");
        };
        for (callee, list) in [
            ("refused", SIGN_POLICY_REASONS),
            ("refused_ceremony", CEREMONY_INTENT_REASONS),
            ("refused_delete", DELETE_INTENT_REASONS),
        ] {
            each(callee, Box::new(|lit, what| assert!(list.contains(&lit), "{what}: {lit:?} is not in {list:?}")));
        }
        each(
            "refuse",
            Box::new(|lit, what| {
                for (list, name) in [
                    (SIGN_POLICY_REASONS, "SIGN_POLICY_REASONS"),
                    (CEREMONY_INTENT_REASONS, "CEREMONY_INTENT_REASONS"),
                    (DELETE_INTENT_REASONS, "DELETE_INTENT_REASONS"),
                ] {
                    if lit == "approval" && name == "CEREMONY_INTENT_REASONS" {
                        continue;
                    }
                    assert!(list.contains(&lit), "{what}: shared reason {lit:?} is not in {name}");
                }
            }),
        );
        each("record_hosted_op", Box::new(|lit, what| assert!(HOSTED_KEY_OPS_NAMES.contains(&lit), "{what}: {lit:?}")));
    }

    /// The lock names behind `rutli_lock_poison_recoveries_total{lock}`: `sync::recover(&l, "x")`,
    /// `sync::recover_reset(&l, "x", ..)`, `sync::note("x", ..)` and the sign-session map's direct
    /// counter increment. Arguments are parsed with nesting, so `recover(lock.write().unwrap(),
    /// "x")` and rustfmt's multi-line form are both seen.
    #[test]
    fn lock_names_cover_the_call_sites() {
        let sources = crate_sources();
        // sync.rs's own tests use "test"; node.rs/hooks use "test_hook" for test-only locks.
        let ignored = ["test", "test_hook"];
        for (callee, at) in [("recover", 1), ("recover_reset", 1), ("note", 0)] {
            let mut seen = 0;
            for (file, src) in &sources {
                // sync.rs forwards its callers' names (`note(name, ..)`); its tests use "test".
                if file.ends_with("sync.rs") {
                    continue;
                }
                for args in calls(src, callee) {
                    // `note(..)` is also a method elsewhere; only sync's two-string form counts.
                    if callee == "note" && (args.len() != 2 || !args.iter().all(|a| a.starts_with('"'))) {
                        continue;
                    }
                    let what = format!("{file}: {callee}(..)");
                    let lit = literal(args.get(at), &what);
                    if ignored.contains(&lit) {
                        continue;
                    }
                    assert!(LOCK_NAMES.contains(&lit), "{what}: lock {lit:?} is not in LOCK_NAMES");
                    seen += 1;
                }
            }
            assert!(seen > 0, "no {callee}(..) lock call found: the scan is stale");
        }
        // The direct counter increment (frost/core cannot export metrics, so node.rs publishes it).
        let mut direct = 0;
        for (file, src) in &sources {
            if file.ends_with("sync.rs") {
                continue; // forwards its caller's name
            }
            for args in calls(src, "metrics::counter!") {
                if args.first().is_some_and(|a| a.ends_with("LOCK_POISON_RECOVERIES")) {
                    let value = args.get(1).and_then(|a| a.split_once("=>")).map(|(_, v)| v.trim().to_owned());
                    let lit = literal(value.as_ref(), file);
                    assert!(LOCK_NAMES.contains(&lit), "{file}: lock {lit:?} is not in LOCK_NAMES");
                    direct += 1;
                }
            }
        }
        assert!(direct > 0, "no direct LOCK_POISON_RECOVERIES increment found: the scan is stale");
    }

    /// `TOMBSTONE_HOWS` (what `prime()` starts at 0) is exactly the set of `how` values the
    /// tombstone counter is incremented with, and the counter's doc comment names exactly those:
    /// it once documented a `how="deleted"` that no call site emitted.
    #[test]
    fn tombstone_hows_match_the_call_sites_and_the_docs() {
        let mut emitted = std::collections::BTreeSet::new();
        for (file, src) in &crate_sources() {
            for args in calls(src, "metrics::counter!") {
                if args.first().is_some_and(|a| a.ends_with("HOSTED_TOMBSTONES_WRITTEN")) {
                    let value = args.get(1).and_then(|a| a.split_once("=>")).map(|(_, v)| v.trim().to_owned());
                    emitted.insert(literal(value.as_ref(), file).to_owned());
                }
            }
        }
        let listed: std::collections::BTreeSet<String> = TOMBSTONE_HOWS.iter().map(|h| (*h).to_owned()).collect();
        assert_eq!(emitted, listed, "rutli_hosted_tombstones_written_total: call sites vs TOMBSTONE_HOWS");

        let this = include_str!("metrics.rs");
        let decl = this.find("pub const HOSTED_TOMBSTONES_WRITTEN").expect("the const is declared here");
        let doc: Vec<&str> = this[..decl].lines().rev().take_while(|l| l.starts_with("///")).collect();
        let first = doc.last().expect("the const has a doc comment");
        let wanted = format!("label `how` ({})", TOMBSTONE_HOWS.join("|"));
        assert!(first.contains(&wanted), "the HOSTED_TOMBSTONES_WRITTEN doc names other values than {wanted:?}: {first}");
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Key-store readiness: the verdict behind `Signer.Health`, the `rutli_keystore_unreadable` gauge,
//! the node's refusal to lead or join work it cannot finish, and the daemon's background probe loop.
//!
//! Why it exists: on 2026-10-07 a DevNet cosigner's `/data/keys` became unreadable. Its probes were
//! TCP-only and Health always answered ok, so it stayed "ready" and the driver kept choosing it as
//! leader while it failed every Sign with `Permission denied` — a total signing outage with two
//! healthy nodes beside it. A node that cannot read its key store must look unhealthy everywhere:
//! Health, container readiness (`rutli-cosigner health`), metrics — and it must stay out of other
//! leaders' quorums ([`Node::sign_round1`]), where a cached share would let it pass round 1 and
//! then sink the signature at round 2.
//!
//! The probe itself is [`KeyStore::check_dir`]. This module runs it at most once at a time, serves a
//! verdict younger than [`FRESH`] from cache (a Health flood never turns into a probe flood), bounds
//! it by [`PROBE_TIMEOUT`], publishes it, and logs transitions only.
//!
//! A filesystem call that never returns (a dead hard mount) pins the one in-flight probe: no new
//! probe can start, so every caller — Health and the monitor loop alike — gets the "unresponsive"
//! verdict published at the timeout until that call returns. At most one blocking thread is ever
//! parked on a dead volume.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::keystore::KeyStore;
use crate::node::Node;
use crate::{DaemonError, Result};

/// How long a probe may take before the store counts as unresponsive (a hung mount). Well inside
/// the driver's request deadline and the k8s readiness `timeoutSeconds`.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// How often the daemon re-probes on its own, so the gauge stays fresh with nobody calling Health.
pub const MONITOR_INTERVAL: Duration = Duration::from_secs(15);
/// A verdict younger than this is served from cache instead of probing again.
pub const FRESH: Duration = Duration::from_secs(5);

/// The last published probe outcome.
struct Verdict {
    /// `None` = healthy; otherwise the failure, as Health reports it.
    failure: Option<String>,
    /// Start sequence of the probe that produced it: a result from an older probe is dropped, so
    /// a slow probe finishing late can never overwrite a newer verdict.
    seq: u64,
    /// When it was published; `None` until the first probe.
    at: Option<Instant>,
}

/// One node's key-store readiness state. Shared (`Arc`) between the node, Health and the monitor.
pub struct KeystoreHealth {
    dir: PathBuf,
    fresh: Duration,
    /// Mirror of `verdict.failure.is_some()`, for the lock-free hot path (every sign round 1).
    down: AtomicBool,
    verdict: Mutex<Verdict>,
    /// A probe is running — single-flight.
    in_flight: AtomicBool,
    /// Last issued probe sequence number.
    seq: AtomicU64,
}

impl KeystoreHealth {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            fresh: FRESH,
            down: AtomicBool::new(false),
            verdict: Mutex::new(Verdict { failure: None, seq: 0, at: None }),
            in_flight: AtomicBool::new(false),
            seq: AtomicU64::new(0),
        }
    }

    /// Serve cached verdicts for `fresh` instead of [`FRESH`]. Tests pass zero to probe on every
    /// Health call.
    pub fn with_freshness(mut self, fresh: Duration) -> Self {
        self.fresh = fresh;
        self
    }

    /// Whether the last published verdict was a failure. Lock-free: read on every sign round 1.
    pub fn is_down(&self) -> bool {
        self.down.load(Ordering::Relaxed)
    }

    /// Probe now — bypassing the cache and the single-flight gate — and publish. Blocking IO. For
    /// tests and tools; the daemon goes through [`probe`].
    pub fn check(&self) -> Result<()> {
        let seq = self.next_seq();
        let verdict = KeyStore::check_dir(&self.dir);
        self.publish(seq, verdict.as_ref().err().map(ToString::to_string), false);
        verdict
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn lock(&self) -> MutexGuard<'_, Verdict> {
        self.verdict.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The current verdict, as Health reports it (healthy until the first probe says otherwise).
    fn current(&self) -> std::result::Result<(), String> {
        self.lock().failure.clone().map_or(Ok(()), Err)
    }

    fn fresh_verdict(&self) -> Option<std::result::Result<(), String>> {
        let v = self.lock();
        let fresh = v.at.is_some_and(|at| at.elapsed() < self.fresh);
        fresh.then(|| v.failure.clone().map_or(Ok(()), Err))
    }

    /// Publish probe `seq`'s outcome — verdict, gauge and hot-path flag together, under one lock —
    /// unless a later probe already published. `placeholder` marks the "unresponsive" verdict for a
    /// probe that hit the timeout: it must not overwrite that same probe's real result if the result
    /// landed first, while the real result, arriving later, does replace the placeholder.
    fn publish(&self, seq: u64, failure: Option<String>, placeholder: bool) {
        let mut v = self.lock();
        if seq < v.seq || (placeholder && seq == v.seq) {
            return;
        }
        let (was_down, down) = (v.failure.is_some(), failure.is_some());
        metrics::gauge!(crate::metrics::KEYSTORE_UNREADABLE).set(if down { 1.0 } else { 0.0 });
        self.down.store(down, Ordering::Relaxed);
        match (&failure, was_down) {
            (Some(e), false) => tracing::error!(
                error = %e,
                "key store failed its readiness probe — this node now refuses to lead or join \
                 signing and ceremonies; Health reports NOT_SERVING until it recovers. Check the \
                 data volume (mount flags, ownership/permissions, anything that touched the PVC)"
            ),
            (None, true) => tracing::info!("key store readable again — Health reports serving"),
            _ => {}
        }
        *v = Verdict { failure, seq, at: Some(Instant::now()) };
    }
}

/// Clears the single-flight flag when the probe finishes — or when its closure is dropped without
/// running (runtime shutdown), so the flag can never stick.
struct InFlight(Arc<KeystoreHealth>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::Release);
    }
}

/// The verdict `Signer.Health` reports: `Err(detail)` while the key store is unusable.
///
/// Cached for [`FRESH`]; otherwise runs the probe off the async runtime, at most one at a time (a
/// caller that finds one running gets the current verdict instead of starting another), bounded by
/// [`PROBE_TIMEOUT`]. On timeout the store is published as unresponsive; the blocking probe cannot
/// be cancelled and publishes its real result whenever it returns.
pub async fn probe(health: &Arc<KeystoreHealth>) -> std::result::Result<(), String> {
    if let Some(verdict) = health.fresh_verdict() {
        return verdict;
    }
    if health.in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
    {
        return health.current();
    }
    let seq = health.next_seq();
    let guard = InFlight(health.clone());
    let task = tokio::task::spawn_blocking(move || {
        let h = &guard.0;
        let verdict = KeyStore::check_dir(&h.dir);
        h.publish(seq, verdict.err().map(|e| e.to_string()), false);
    });
    if tokio::time::timeout(PROBE_TIMEOUT, task).await.is_err() {
        let hung = DaemonError::KeystoreUnavailable {
            path: health.dir.clone(),
            what: "unresponsive",
            source: std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("probe did not return within {PROBE_TIMEOUT:?}"),
            ),
        };
        health.publish(seq, Some(hung.to_string()), true);
    }
    health.current()
}

/// Probe immediately, then every `interval`, for the life of the process — keeps the gauge, the
/// transition log and the refusal gate current even when nothing polls Health. Each tick also
/// prunes expired in-flight sign sessions: `round1` normally does that, and a node refusing round 1
/// would otherwise hold them (and `rutli_pending_sign_sessions`) until it recovers.
pub fn spawn_monitor(node: Arc<Node>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = probe(node.keystore_health()).await;
            node.prune_expired_sign_sessions();
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_probe_result_never_overwrites_a_newer_one() {
        let h = KeystoreHealth::new("/nonexistent");
        h.publish(2, None, false);
        h.publish(1, Some("stale failure".into()), false); // probe 1 finished after probe 2
        assert!(!h.is_down(), "an older probe's result must be dropped");

        // A timed-out probe's placeholder must not clobber its own result that landed first…
        h.publish(3, None, false);
        h.publish(3, Some("unresponsive".into()), true);
        assert!(!h.is_down());
        // …but its real result, arriving after the placeholder, replaces it.
        h.publish(4, Some("unresponsive".into()), true);
        assert!(h.is_down());
        h.publish(4, None, false);
        assert!(!h.is_down());
        assert_eq!(h.current(), Ok(()));
    }

    #[tokio::test]
    async fn health_serves_a_fresh_verdict_from_cache_and_never_stacks_probes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        std::fs::create_dir_all(&dir).unwrap();
        let cached = Arc::new(KeystoreHealth::new(&dir));
        let live = Arc::new(KeystoreHealth::new(&dir).with_freshness(Duration::ZERO));
        assert_eq!(probe(&cached).await, Ok(()));
        assert_eq!(probe(&live).await, Ok(()));

        std::fs::remove_dir_all(&dir).unwrap(); // the store is gone
        assert_eq!(probe(&cached).await, Ok(()), "a fresh verdict is served without probing");

        // A probe already in flight: callers get the current verdict rather than a second probe.
        live.in_flight.store(true, Ordering::Release);
        assert_eq!(probe(&live).await, Ok(()), "must not start a second probe");
        live.in_flight.store(false, Ordering::Release);

        let detail = probe(&live).await.expect_err("an uncached probe sees the missing store");
        assert!(detail.contains("unreadable"), "{detail}");
        assert!(live.is_down());
    }
}

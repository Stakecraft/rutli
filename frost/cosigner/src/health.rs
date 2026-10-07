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
//! The probe itself is [`KeyStore::check_dir`]. This module runs it at most once at a time, on a
//! thread of its own, serves a verdict younger than [`FRESH`] from cache (a Health flood never
//! turns into a probe flood), publishes it, and logs transitions only.
//!
//! **Nothing here depends on the async runtime being responsive.** The probe runs on a plain
//! thread, the monitor loop *is* a plain thread ([`spawn_monitor`]), and `Signer.Health` only
//! awaits a notification — it needs neither a free worker for long nor a thread from tokio's
//! blocking pool. That matters for the hung-volume variant of the incident (a dead NFS/CSI mount, a
//! volume frozen by a snapshot hook): a filesystem call on such a volume parks its thread for as
//! long as the kernel says, and the verdict must still flip to "down" then — it is what turns later
//! calls away before they touch the store ([`Node::refuse_if_keystore_down`]). The handlers' own
//! store calls leave the async workers too ([`Node::blocking`]).
//!
//! Two kinds of failure, two speeds. A *definite* error — the probe returned and said no: EACCES,
//! EROFS, ENOSPC, EIO, ESTALE — is published the moment it arrives. A probe that does not return at
//! all is published as "unresponsive" only once it has been hung for [`UNRESPONSIVE_AFTER`] (two
//! probe timeouts), so a short stall that is correlated across every cosigner — one snapshot job
//! freezing all three PVCs — does not refuse every sign cluster-wide; a leader's peer deadline
//! covers that window. The hung probe keeps the single-flight slot (no new probe starts until it
//! returns), whoever looks meanwhile — Health or the monitor — publishes "unresponsive" once it is
//! due, and the probe's real result replaces that placeholder whenever it lands. At most one
//! thread is ever parked on a dead volume by this module.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::keystore::KeyStore;
use crate::node::Node;
use crate::{DaemonError, Result};

/// How long a caller waits for a probe it started. `Signer.Health` answers within it either way —
/// well inside the driver's request deadline and the k8s readiness `timeoutSeconds` — with the
/// verdict as it stands.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// A probe still hung after this long is published as unresponsive: two timeouts, not one, so a
/// short stall (a snapshot fsfreeze, an NFS hiccup) does not take the node — or, when the stall is
/// correlated, the cluster — out of signing. A probe that *returns* an error is published at once.
pub const UNRESPONSIVE_AFTER: Duration = Duration::from_secs(2 * PROBE_TIMEOUT.as_secs());
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

/// The one probe in flight (single-flight).
struct Running {
    seq: u64,
    since: Instant,
    /// The "has not returned yet" warning was logged for this probe.
    slow_logged: bool,
}

struct State {
    verdict: Verdict,
    running: Option<Running>,
}

impl State {
    fn is_running(&self, seq: u64) -> bool {
        self.running.as_ref().is_some_and(|r| r.seq == seq)
    }
}

/// One node's key-store readiness state. Shared (`Arc`) between the node, Health and the monitor.
pub struct KeystoreHealth {
    dir: PathBuf,
    fresh: Duration,
    unresponsive_after: Duration,
    /// The key store's fault-injection seam ([`crate::keystore::IoHook`]), run before each probe.
    io_hook: Option<crate::keystore::IoHook>,
    /// Mirror of the verdict's `failure.is_some()`, for the lock-free hot path (every round 1).
    down: AtomicBool,
    state: Mutex<State>,
    /// Signalled when a probe finishes: `finished` for blocking waiters (the monitor thread),
    /// `finished_async` for async ones (Health) — runtime-independent, notified from the probe thread.
    finished: Condvar,
    finished_async: tokio::sync::Notify,
    /// Last issued probe sequence number.
    seq: AtomicU64,
}

/// What asking for a verdict found.
enum Started {
    /// A verdict younger than `fresh`.
    Cached(std::result::Result<(), String>),
    /// Another caller's probe is running, since `since`.
    InFlight { seq: u64, since: Instant },
    /// This caller started a probe.
    Probing { seq: u64, since: Instant },
}

impl KeystoreHealth {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            fresh: FRESH,
            unresponsive_after: UNRESPONSIVE_AFTER,
            io_hook: None,
            down: AtomicBool::new(false),
            state: Mutex::new(State {
                verdict: Verdict { failure: None, seq: 0, at: None },
                running: None,
            }),
            finished: Condvar::new(),
            finished_async: tokio::sync::Notify::new(),
            seq: AtomicU64::new(0),
        }
    }

    /// Serve cached verdicts for `fresh` instead of [`FRESH`]. Tests pass zero to probe on every
    /// Health call.
    pub fn with_freshness(mut self, fresh: Duration) -> Self {
        self.set_freshness(fresh);
        self
    }

    pub(crate) fn set_freshness(&mut self, fresh: Duration) {
        self.fresh = fresh;
    }

    /// Publish a hung probe as unresponsive after `after` instead of [`UNRESPONSIVE_AFTER`]. A hung
    /// probe is only noticed when a wait for it times out, so this never fires sooner than that.
    pub(crate) fn set_unresponsive_after(&mut self, after: Duration) {
        self.unresponsive_after = after;
    }

    pub(crate) fn set_io_hook(&mut self, hook: Option<crate::keystore::IoHook>) {
        self.io_hook = hook;
    }

    /// Whether the last published verdict was a failure. Lock-free: read on every sign round 1.
    pub fn is_down(&self) -> bool {
        self.down.load(Ordering::Relaxed)
    }

    /// Probe now on the calling thread — bypassing the cache and the single-flight slot — and
    /// publish. Blocking IO. For tests and tools; the daemon goes through [`probe`] and
    /// [`spawn_monitor`].
    pub fn check(&self) -> Result<()> {
        let seq = self.next_seq();
        let verdict = self.run_check();
        self.publish(seq, verdict.as_ref().err().map(ToString::to_string), false);
        verdict
    }

    /// The probe: [`KeyStore::check_dir`], behind the store's fault-injection seam.
    fn run_check(&self) -> Result<()> {
        if let Some(hook) = &self.io_hook {
            hook(&self.dir);
        }
        KeyStore::check_dir(&self.dir)
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The current verdict, as Health reports it (healthy until the first probe says otherwise).
    fn current(&self) -> std::result::Result<(), String> {
        self.lock().verdict.failure.clone().map_or(Ok(()), Err)
    }

    /// Publish probe `seq`'s outcome — verdict, gauge and hot-path flag together, under one lock —
    /// unless a later probe already published. `placeholder` marks the "unresponsive" verdict for a
    /// probe that is still hung: it must not overwrite that same probe's real result if the result
    /// landed first, while the real result, arriving later, does replace the placeholder.
    fn publish(&self, seq: u64, failure: Option<String>, placeholder: bool) {
        let mut s = self.lock();
        let v = &mut s.verdict;
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

    /// Serve the cache, find the probe already running, or start one on its own thread.
    fn start(self: &Arc<Self>) -> Started {
        let (seq, since) = {
            let mut s = self.lock();
            if s.verdict.at.is_some_and(|at| at.elapsed() < self.fresh) {
                return Started::Cached(s.verdict.failure.clone().map_or(Ok(()), Err));
            }
            if let Some(r) = &s.running {
                return Started::InFlight { seq: r.seq, since: r.since };
            }
            let (seq, since) = (self.next_seq(), Instant::now());
            s.running = Some(Running { seq, since, slow_logged: false });
            (seq, since)
        };
        // A plain thread, not tokio's blocking pool: a probe parked on a dead volume is parked for
        // as long as the kernel says, and the verdict must keep moving while the runtime — or its
        // pool — is stuck. `slot` frees the single-flight slot and wakes waiters when the probe
        // ends, or when the closure is dropped unrun because the thread could not start.
        let slot = Slot(self.clone(), seq);
        let spawned = std::thread::Builder::new().name("rutli-keystore-probe".into()).spawn(move || {
            let h = &slot.0;
            let verdict = h.run_check();
            h.publish(seq, verdict.err().map(|e| e.to_string()), false);
            drop(slot);
        });
        match spawned {
            Ok(_) => Started::Probing { seq, since },
            Err(e) => {
                tracing::error!(error = %e, "could not start the key-store probe thread");
                Started::Cached(self.current())
            }
        }
    }

    /// The probe `seq`, started at `since`, has not returned. Once it has been hung for
    /// `unresponsive_after`, publish it as unresponsive (a placeholder its real result replaces);
    /// before that, log it once and leave the verdict alone.
    fn still_running(&self, seq: u64, since: Instant) {
        let hung = since.elapsed();
        if hung >= self.unresponsive_after {
            let unresponsive = DaemonError::KeystoreUnavailable {
                path: self.dir.clone(),
                what: "unresponsive",
                source: std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("readiness probe has not returned for {}s", hung.as_secs()),
                ),
            };
            self.publish(seq, Some(unresponsive.to_string()), true);
            return;
        }
        let mut s = self.lock();
        if let Some(r) = s.running.as_mut().filter(|r| r.seq == seq && !r.slow_logged) {
            r.slow_logged = true;
            tracing::warn!(
                path = %self.dir.display(),
                hung_ms = hung.as_millis() as u64,
                grace_ms = self.unresponsive_after.as_millis() as u64,
                "key-store readiness probe has not returned — a stalled volume? Not counted as \
                 unresponsive yet, so a short stall does not fail signing; the node refuses work \
                 if the probe is still hung when the grace runs out"
            );
        }
    }

    /// Wait, blocking, for probe `seq` until `since + patience`, checking on it every
    /// [`PROBE_TIMEOUT`] and at the end (so a deadline already past still publishes if due).
    fn wait_blocking(&self, seq: u64, since: Instant, patience: Duration) {
        let deadline = since + patience;
        loop {
            let slice = deadline.saturating_duration_since(Instant::now()).min(PROBE_TIMEOUT);
            let s = self.lock();
            let (s, _) = self
                .finished
                .wait_timeout_while(s, slice, |s| s.is_running(seq))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !s.is_running(seq) {
                return; // it returned, and published before freeing the slot
            }
            drop(s);
            self.still_running(seq, since);
            if Instant::now() >= deadline {
                return;
            }
        }
    }

    /// Wait for probe `seq` until `since + PROBE_TIMEOUT` without holding a thread: Health's path.
    async fn wait_async(&self, seq: u64, since: Instant) {
        let deadline = tokio::time::Instant::from_std(since + PROBE_TIMEOUT);
        loop {
            // Register before checking, so a probe finishing in between still wakes us.
            let notified = self.finished_async.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.lock().is_running(seq) {
                return;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                self.still_running(seq, since);
                return;
            }
        }
    }

    /// The verdict, probing if it is stale and waiting for the probe in flight — this call's or
    /// another caller's — until `patience` after it started. Blocking; needs no async runtime: the
    /// monitor thread's path. Waiting on a probe Health started too is what lets the monitor publish
    /// "unresponsive" on time however the hung probe began.
    pub fn probe_blocking(self: &Arc<Self>, patience: Duration) -> std::result::Result<(), String> {
        match self.start() {
            Started::Cached(verdict) => return verdict,
            Started::InFlight { seq, since } | Started::Probing { seq, since } => {
                self.wait_blocking(seq, since, patience)
            }
        }
        self.current()
    }
}

/// The single-flight slot of probe `.1`: freed, and waiters woken, when the probe ends.
struct Slot(Arc<KeystoreHealth>, u64);

impl Drop for Slot {
    fn drop(&mut self) {
        let h = &self.0;
        {
            let mut s = h.lock();
            if s.is_running(self.1) {
                s.running = None;
            }
        }
        h.finished.notify_all();
        h.finished_async.notify_waiters();
    }
}

/// The verdict `Signer.Health` reports: `Err(detail)` while the key store is unusable.
///
/// Cached for [`FRESH`]; otherwise probes on a thread of its own and waits at most
/// [`PROBE_TIMEOUT`], so Health always answers in time. A probe still hung then is published as
/// unresponsive only once it has been hung for [`UNRESPONSIVE_AFTER`] — by this call if that is
/// already due, otherwise by a later Health call or the monitor.
pub async fn probe(health: &Arc<KeystoreHealth>) -> std::result::Result<(), String> {
    match health.start() {
        Started::Cached(verdict) => return verdict,
        Started::InFlight { seq, since } => health.still_running(seq, since),
        Started::Probing { seq, since } => health.wait_async(seq, since).await,
    }
    health.current()
}

/// Probe immediately, then every `interval`, for the life of the process — keeps the gauge, the
/// transition log and the refusal gate current even when nothing polls Health. Each tick also
/// prunes expired in-flight sign sessions: `round1` normally does that, and a node refusing round 1
/// would otherwise hold them (and `rutli_pending_sign_sessions`) until it recovers.
///
/// A dedicated thread — a watchdog — and deliberately not a tokio task: the verdict is what makes a
/// node with a stalled volume turn work away, so it must keep moving when that stall has wedged the
/// async runtime. Each tick waits for its own probe long enough to publish "unresponsive" itself.
pub fn spawn_monitor(node: Arc<Node>, interval: Duration) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("rutli-keystore-watchdog".into())
        .spawn(move || loop {
            let health = node.keystore_health();
            let _ = health.probe_blocking(health.unresponsive_after.max(PROBE_TIMEOUT));
            node.prune_expired_sign_sessions();
            std::thread::sleep(interval);
        })
        .expect("spawn the key-store watchdog thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pretend a probe has been hung for `for_`; returns its sequence number.
    fn hang(h: &KeystoreHealth, for_: Duration) -> u64 {
        let seq = h.next_seq();
        h.lock().running = Some(Running { seq, since: Instant::now() - for_, slow_logged: false });
        seq
    }

    #[test]
    fn a_late_probe_result_never_overwrites_a_newer_one() {
        let h = KeystoreHealth::new("/nonexistent");
        h.publish(2, None, false);
        h.publish(1, Some("stale failure".into()), false); // probe 1 finished after probe 2
        assert!(!h.is_down(), "an older probe's result must be dropped");

        // A hung probe's placeholder must not clobber its own result that landed first…
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
        hang(&live, Duration::ZERO);
        assert_eq!(probe(&live).await, Ok(()), "must not start a second probe");
        live.lock().running = None;

        let detail = probe(&live).await.expect_err("an uncached probe sees the missing store");
        assert!(detail.contains("unreadable"), "{detail}");
        assert!(live.is_down());
        assert!(live.lock().running.is_none(), "a finished probe frees the single-flight slot");
    }

    #[tokio::test]
    async fn a_hung_probe_is_unresponsive_only_after_the_grace_but_a_definite_error_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        std::fs::create_dir_all(&dir).unwrap();
        let h = Arc::new(KeystoreHealth::new(&dir).with_freshness(Duration::ZERO));

        // Hung for one timeout: logged, not a verdict — a short stall must not fail signing.
        hang(&h, PROBE_TIMEOUT);
        assert_eq!(probe(&h).await, Ok(()), "one timeout must not fail the node");
        assert!(!h.is_down());
        assert!(h.lock().running.as_ref().unwrap().slow_logged, "the stall is logged");

        // Hung for the whole grace: unresponsive — from Health and from the monitor's path alike…
        h.lock().running = None;
        let seq = hang(&h, UNRESPONSIVE_AFTER);
        let detail = probe(&h).await.expect_err("two timeouts = unresponsive");
        assert!(detail.contains("unresponsive"), "{detail}");
        assert!(detail.contains(&dir.display().to_string()), "must name the path: {detail}");
        assert!(h.is_down());
        assert!(h.probe_blocking(PROBE_TIMEOUT).is_err());
        // …and the hung probe's real result, whenever it lands, replaces the placeholder.
        h.publish(seq, None, false);
        assert!(!h.is_down());
        h.lock().running = None;

        // The monitor waits out a hung probe someone else (Health) started, so "unresponsive" is
        // published when the grace runs out, not a whole monitor interval later.
        hang(&h, UNRESPONSIVE_AFTER - Duration::from_millis(100));
        let detail = h.probe_blocking(UNRESPONSIVE_AFTER).expect_err("published at the grace");
        assert!(detail.contains("unresponsive"), "{detail}");
        h.lock().running = None;
        h.check().unwrap();
        assert!(!h.is_down());

        // A definite error needs no grace: published by the probe the moment it returns.
        std::fs::remove_dir_all(&dir).unwrap();
        let detail = h.probe_blocking(PROBE_TIMEOUT).expect_err("a missing store fails at once");
        assert!(detail.contains("unreadable"), "{detail}");
        assert!(h.is_down());
    }
}

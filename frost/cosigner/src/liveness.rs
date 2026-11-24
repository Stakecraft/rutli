// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Peer liveness: what a leader knows about each remote cosigner between calls, and the load
//! counters every node reports with its sign replies.
//!
//! **[`PeerHealth`]** — one per remote peer, inside [`crate::peer::GrpcPeer`], shared by every
//! signature and every call class. Fed only by this leader's own pinned mTLS calls to that peer
//! (no gossip). Three states:
//!
//! - `Up`.
//! - `Down { Unreachable }`: a hard transport failure (connect, TLS, keepalive close, a plain
//!   UNAVAILABLE), or a `NodeInfo` call or probe past its deadline (`KeyEpoch` and
//!   `CeremonyStatus` read the store: past their deadline they open nothing). Closed by a
//!   single-flight `NodeInfo` probe every [`crate::peer::PROBE_EVERY`] (or by any answer from the
//!   peer).
//! - `Down { Stalled }`: a sign round past its deadline while the peer's member-wide progress
//!   counter ([`Load`], the `rutli-load` reply metadata) did not move during the wait — a busy
//!   member keeps completing rounds for someone and is never opened. A peer that reports no load
//!   (0.4.x) is never opened Stalled: nothing tells its queue from a stall. `Down { Refusing }`:
//!   the peer answered with the `keystore-down` trailer. Both are closed by a real sign round that
//!   succeeds (a *trial*: after a window of [`crate::peer::BREAKER_WINDOW`], doubling up to
//!   [`crate::peer::BREAKER_WINDOW_CAP`], one signature per window puts a subset with the peer
//!   first — [`PeerHealth::take_trial`]), or by a probe whose self-reported load shows the store
//!   working again.
//!
//! What it does with that: the sign path sorts its candidate subsets by their worst member
//! ([`Tier`]: Up, Trial, Down) — a Down peer is tried last, never skipped, within the signature's
//! attempts and time. A leader also refuses at once when fewer than `t` cosigners are visible,
//! counting only `Unreachable` peers as missing. DKG, refresh and hosted-key writes do not look at
//! it.
//!
//! What never opens a breaker: an answered refusal (policy, epoch, sessions-full, an unknown
//! session, an invalid share — those keep today's per-signature exclusion), and UNAVAILABLE that
//! carries any other `rutli-error` trailer. A member that misses a sign deadline is still excluded
//! from *that* signature, busy or not; the breaker only decides the order of later ones.
//!
//! **[`Load`]** is self-reported by the peer. It may keep that peer's own breaker shut (a lying
//! member that claims progress costs each signature it joins one deadline), never open the breaker
//! of another peer, and never changes which checks run.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::Instant;

use crate::peer::Liveness;

/// Response metadata (on success and on error) in which every node reports its sign load.
pub const LOAD_HEADER: &str = "rutli-load";

/// A node's sign load as it reports it: `inflight=<n>; r1done=<n>; r2done=<n>; store=ok|down`.
/// `inflight` counts sign rounds queued or running on the node (any leader, its own included);
/// `r1done` / `r2done` count completed rounds since start; `store` is its key-store verdict.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Load {
    pub inflight: u64,
    pub r1done: u64,
    pub r2done: u64,
    pub store_ok: bool,
}

impl Load {
    /// The metadata value.
    pub fn header_value(&self) -> String {
        format!(
            "inflight={}; r1done={}; r2done={}; store={}",
            self.inflight,
            self.r1done,
            self.r2done,
            if self.store_ok { "ok" } else { "down" }
        )
    }

    /// Parse a metadata value; unknown keys are ignored, `inflight` and `r2done` are required.
    pub fn parse(value: &str) -> Option<Self> {
        let mut out = Load {
            store_ok: true,
            ..Default::default()
        };
        let (mut inflight, mut r2done) = (false, false);
        for part in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=')?;
            let (k, v) = (k.trim(), v.trim());
            match k {
                "inflight" => {
                    out.inflight = v.parse().ok()?;
                    inflight = true;
                }
                "r1done" => out.r1done = v.parse().ok()?,
                "r2done" => {
                    out.r2done = v.parse().ok()?;
                    r2done = true;
                }
                "store" => out.store_ok = v == "ok",
                _ => {}
            }
        }
        (inflight && r2done).then_some(out)
    }

    /// The load a reply carries, if any.
    pub fn from_metadata(md: &tonic::metadata::MetadataMap) -> Option<Self> {
        md.get(LOAD_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(Self::parse)
    }

    /// Attach this load to a reply's metadata.
    pub fn insert_into(&self, md: &mut tonic::metadata::MetadataMap) {
        if let Ok(v) = self.header_value().parse() {
            md.insert(LOAD_HEADER, v);
        }
    }
}

/// A sign round, for the load counters and the progress test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
    One,
    Two,
}

impl Round {
    /// This round's entry of a per-round pair.
    fn pick<T>(self, pair: &[T; 2]) -> &T {
        let [one, two] = pair;
        match self {
            Round::One => one,
            Round::Two => two,
        }
    }

    fn pick_mut<T>(self, pair: &mut [T; 2]) -> &mut T {
        let [one, two] = pair;
        match self {
            Round::One => one,
            Round::Two => two,
        }
    }
}

/// This node's sign counters: rounds it serves (as a member or for its own leader) and signatures
/// it leads. Reported as [`Load`] on its sign and `NodeInfo` replies.
#[derive(Debug, Default)]
pub struct SignLoad {
    leading: AtomicUsize,
    inflight: AtomicU64,
    done: [AtomicU64; 2],
}

/// One sign round counted in flight until dropped (inside the blocking closure, so a round the
/// caller stopped waiting for still counts until it really ends), then counted done.
pub struct OpGuard {
    load: Arc<SignLoad>,
    round: Round,
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.load.inflight.fetch_sub(1, Ordering::AcqRel);
        self.round
            .pick(&self.load.done)
            .fetch_add(1, Ordering::AcqRel);
    }
}

/// One signature led here, counted until dropped.
pub struct LeadGuard {
    load: Arc<SignLoad>,
    /// Signatures led here at the moment this one started, itself included.
    pub count: usize,
}

impl Drop for LeadGuard {
    fn drop(&mut self) {
        self.load.leading.fetch_sub(1, Ordering::AcqRel);
        metrics::gauge!(crate::metrics::SIGNS_IN_FLIGHT).decrement(1.0);
    }
}

impl SignLoad {
    pub fn begin(self: &Arc<Self>, round: Round) -> OpGuard {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        OpGuard {
            load: self.clone(),
            round,
        }
    }

    /// Count one signature led here until the guard drops; `rutli_signs_in_flight` follows. The
    /// gauge's only writers are this increment and the guard's decrement (it is primed at 0), so
    /// concurrent updates cannot publish a stale value.
    pub fn lead(self: &Arc<Self>) -> LeadGuard {
        let count = self.leading.fetch_add(1, Ordering::AcqRel) + 1;
        metrics::gauge!(crate::metrics::SIGNS_IN_FLIGHT).increment(1.0);
        LeadGuard {
            load: self.clone(),
            count,
        }
    }

    /// Signatures led here right now.
    pub fn leading(&self) -> usize {
        self.leading.load(Ordering::Acquire)
    }

    pub fn snapshot(&self, store_ok: bool) -> Load {
        Load {
            inflight: self.inflight.load(Ordering::Acquire),
            r1done: self.done[0].load(Ordering::Acquire),
            r2done: self.done[1].load(Ordering::Acquire),
            store_ok,
        }
    }
}

/// Why a peer is down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownReason {
    /// No transport to it (connect, TLS, keepalive), or a `NodeInfo` call past its deadline.
    Unreachable,
    /// Reachable, but a sign round passed its deadline with no progress anywhere on the peer.
    Stalled,
    /// It answered that its key store is down.
    Refusing,
}

impl DownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DownReason::Unreachable => "unreachable",
            DownReason::Stalled => "stalled",
            DownReason::Refusing => "refusing",
        }
    }
}

/// Where a peer sorts in the sign path's subset order (lower first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Up,
    Trial,
    Down,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Up,
    Down {
        reason: DownReason,
        /// Until when no signature may try it as a trial (and when the next re-check is due).
        until: Instant,
        backoff: Duration,
        /// A signature took the trial for the current window.
        trial: bool,
        /// The peer's `r2done` when it was opened Stalled (from the last load it reported).
        r2_mark: Option<u64>,
    },
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::Up => "up",
            State::Down { trial: true, .. } => "trial",
            State::Down { .. } => "down",
        }
    }
}

/// One taking of a peer's trial ([`PeerHealth::take_trial`]), for [`PeerHealth::release_trial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrialTaken {
    /// The end of the hold this taking set: no other taking sets the same one.
    until: Instant,
}

/// What this leader had seen from a peer when a call started: the input of the progress test.
#[derive(Clone, Copy, Debug)]
pub struct Mark {
    pub at: Instant,
    /// The peer had reported a load before the call: something to compare with.
    baseline: bool,
    done: [u64; 2],
}

/// The last load a peer reported, and when its counters last moved.
#[derive(Clone, Copy, Debug, Default)]
struct Seen {
    last: Option<Load>,
    /// When a reply last showed progress since the reply before it: for round 1 any completed
    /// round, for round 2 only completed round 2s (round 1 does not touch the key store, so a
    /// member with a hung volume still completes round 1s). A counter going down (the peer
    /// restarted) counts as progress: nothing of the old process is stuck there.
    progress_at: [Option<Instant>; 2],
    /// Loads seen so far.
    samples: u64,
}

/// The outcome of a `NodeInfo` probe.
#[derive(Clone, Copy, Debug)]
pub enum Probed {
    /// It answered (the load it reported, if it reports one).
    Answered(Option<Load>),
    /// No answer: transport failure or past the probe deadline.
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeRecord {
    pub(crate) at: Instant,
    pub(crate) outcome: Probed,
}

/// The verdict on a sign round that passed its deadline, before any probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judged {
    /// The peer made progress during the wait: busy, not opened.
    Busy,
    /// No progress seen: one probe at the end of the wait decides (a reply seen early in the wait
    /// says nothing about the rest of it).
    Probe,
}

/// A remote peer's health as this leader sees it. See the module docs.
pub struct PeerHealth {
    peer: u16,
    label: String,
    timing: Liveness,
    state: Mutex<State>,
    seen: Mutex<Seen>,
    /// Sign rounds this leader completed with the peer, by round.
    done: [AtomicU64; 2],
    /// Single flight for `NodeInfo` probes (the prober, the progress test, the quorum check).
    pub(crate) probe_slot: tokio::sync::Mutex<()>,
    last_probe: Mutex<Option<ProbeRecord>>,
    /// While a sign round's deadline is being judged (the progress probe in flight): sorted like a
    /// trial, so the next signatures do not walk into the same deadline before the verdict. Not a
    /// state: no transition, nothing published.
    suspect_until: Mutex<Option<Instant>>,
    /// Breaker transitions so far (for tests; the metric is the operator's view).
    transitions: AtomicU64,
    /// The background prober runs.
    pub(crate) prober: AtomicBool,
    /// Wakes the prober for an immediate probe.
    pub(crate) wake: tokio::sync::Notify,
}

impl std::fmt::Debug for PeerHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerHealth")
            .field("peer", &self.peer)
            .field("state", &self.state_name())
            .finish()
    }
}

impl PeerHealth {
    /// Health for roster peer `peer`; publishes its state gauge and primes its transition counters.
    pub fn new(peer: u16, timing: Liveness) -> Self {
        let label = peer.to_string();
        for state in crate::metrics::PEER_STATES {
            let up = if *state == "up" { 1.0 } else { 0.0 };
            metrics::gauge!(crate::metrics::PEER_STATE, "peer" => label.clone(), "state" => *state)
                .set(up);
        }
        for (to, reason) in crate::metrics::PEER_TRANSITIONS_LABELS {
            metrics::counter!(crate::metrics::PEER_TRANSITIONS, "peer" => label.clone(), "to" => *to, "reason" => *reason)
                .absolute(0);
        }
        Self {
            peer,
            label,
            timing,
            state: Mutex::new(State::Up),
            seen: Mutex::new(Seen::default()),
            done: Default::default(),
            probe_slot: tokio::sync::Mutex::new(()),
            last_probe: Mutex::new(None),
            suspect_until: Mutex::new(None),
            transitions: AtomicU64::new(0),
            prober: AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
        }
    }

    pub fn peer(&self) -> u16 {
        self.peer
    }

    pub fn timing(&self) -> &Liveness {
        &self.timing
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// "up" | "down" | "trial", as the state gauge reports it.
    pub fn state_name(&self) -> &'static str {
        self.lock().name()
    }

    /// Why it is down, or `None` while up.
    pub fn down_reason(&self) -> Option<DownReason> {
        match *self.lock() {
            State::Up => None,
            State::Down { reason, .. } => Some(reason),
        }
    }

    pub fn is_unreachable(&self) -> bool {
        self.down_reason() == Some(DownReason::Unreachable)
    }

    /// The last load the peer reported.
    pub fn last_load(&self) -> Option<Load> {
        self.seen().last
    }

    fn seen(&self) -> Seen {
        *self.seen.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the peer's counters moved for `round` after `since`.
    fn progressed_since(&self, round: Round, since: Instant) -> bool {
        round
            .pick(&self.seen().progress_at)
            .is_some_and(|at| at > since)
    }

    pub(crate) fn last_probe(&self) -> Option<ProbeRecord> {
        *self.last_probe.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn record_probe(&self, outcome: Probed) {
        *self.last_probe.lock().unwrap_or_else(|p| p.into_inner()) = Some(ProbeRecord {
            at: Instant::now(),
            outcome,
        });
    }

    /// Mark the peer suspect for `for_` (a sign round's deadline is being judged).
    pub fn suspect(&self, for_: Duration) {
        *self.suspect_until.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now() + for_);
    }

    /// The judgment is in: no longer suspect.
    pub fn clear_suspect(&self) {
        *self.suspect_until.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// A sign round's deadline on this peer is being judged.
    pub fn is_suspect(&self) -> bool {
        self.suspect_until
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|until| Instant::now() < until)
    }

    /// Breaker transitions so far.
    pub fn transitions(&self) -> u64 {
        self.transitions.load(Ordering::Acquire)
    }

    /// The tier of this peer for one signature's subset order. Read only: an up peer whose deadline
    /// is being judged sorts as a trial; a down peer sorts as down, its trial included (that is
    /// taken apart, [`PeerHealth::take_trial`], so it is never used up by a signature that does not
    /// contact the peer).
    pub fn sign_tier(&self) -> Tier {
        match *self.lock() {
            State::Up if self.is_suspect() => Tier::Trial,
            State::Up => Tier::Up,
            State::Down { .. } => Tier::Down,
        }
    }

    /// A Stalled or Refusing peer whose window has passed (and whose trial, if one was taken, is
    /// over): the next signature may take it as a trial. Read only. An unreachable peer gets no
    /// trial; its prober decides.
    pub fn trial_due(&self) -> bool {
        Self::due(&self.lock(), Instant::now())
    }

    fn due(s: &State, now: Instant) -> bool {
        match *s {
            State::Down {
                reason: DownReason::Stalled | DownReason::Refusing,
                until,
                ..
            } => now >= until,
            _ => false,
        }
    }

    /// Take the trial for the current window: `Some` for exactly one caller per window (checked
    /// and set under the state lock), which must then send the peer a sign round. Called by the
    /// sign path only when an attempt whose members include the peer starts. The trial is held for
    /// one round 1 plus one round 2 ([`crate::peer::Liveness::trial_hold`]). An attempt that ends
    /// before it sent the peer any round gives it back ([`PeerHealth::release_trial`]); one that
    /// sent a round and got no verdict (the attempt failed at another member meanwhile) leaves it
    /// to be taken again after the hold.
    pub fn take_trial(&self) -> Option<TrialTaken> {
        let mut s = self.lock();
        let now = Instant::now();
        if !Self::due(&s, now) {
            return None;
        }
        let State::Down {
            reason,
            backoff,
            trial,
            r2_mark,
            ..
        } = *s
        else {
            return None;
        };
        let until = now + self.timing.trial_hold();
        let next = State::Down {
            reason,
            until,
            backoff,
            trial: true,
            r2_mark,
        };
        if !trial {
            self.transition(&s, &next, "window");
        }
        *s = next;
        Some(TrialTaken { until })
    }

    /// Give back a trial whose attempt sent the peer no round (it ended at another member first, or
    /// was dropped): down again at once, published as `down`, due for the next signature, its
    /// window not doubled — nothing was learnt about the peer. A no-op once the trial has a verdict
    /// or was taken again after its hold (`taken` names one taking).
    pub fn release_trial(&self, taken: TrialTaken) {
        let mut s = self.lock();
        let State::Down {
            reason,
            until,
            backoff,
            trial: true,
            r2_mark,
        } = *s
        else {
            return;
        };
        if until != taken.until {
            return;
        }
        let next = State::Down {
            reason,
            until: Instant::now(),
            backoff,
            trial: false,
            r2_mark,
        };
        self.transition(&s, &next, reason.as_str());
        *s = next;
    }

    /// What this leader has seen from the peer so far.
    pub fn mark(&self) -> Mark {
        Mark {
            at: Instant::now(),
            baseline: self.seen().samples > 0,
            done: [
                self.done[0].load(Ordering::Acquire),
                self.done[1].load(Ordering::Acquire),
            ],
        }
    }

    /// A reply (success or answered refusal) arrived, with the load it reported.
    pub fn note_reply(&self, load: Option<Load>) {
        if let Some(load) = load {
            let now = Instant::now();
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(prev) = seen.last {
                let restarted = load.r1done < prev.r1done || load.r2done < prev.r2done;
                if restarted || load.r1done > prev.r1done || load.r2done > prev.r2done {
                    *Round::One.pick_mut(&mut seen.progress_at) = Some(now);
                }
                if restarted || load.r2done > prev.r2done {
                    *Round::Two.pick_mut(&mut seen.progress_at) = Some(now);
                }
            }
            seen.last = Some(load);
            seen.samples += 1;
        }
    }

    /// A sign round with the peer completed.
    pub fn note_done(&self, round: Round) {
        round.pick(&self.done).fetch_add(1, Ordering::AcqRel);
    }

    /// Publish a state change: the gauge, the transition counter, one log line.
    fn transition(&self, old: &State, new: &State, reason: &'static str) {
        let (from, to) = (old.name(), new.name());
        let reason_changed = match (old, new) {
            (State::Down { reason: a, .. }, State::Down { reason: b, .. }) => a != b,
            _ => false,
        };
        if from == to && !reason_changed {
            return;
        }
        if from != to {
            metrics::gauge!(crate::metrics::PEER_STATE, "peer" => self.label.clone(), "state" => from).set(0.0);
            metrics::gauge!(crate::metrics::PEER_STATE, "peer" => self.label.clone(), "state" => to).set(1.0);
        }
        metrics::counter!(crate::metrics::PEER_TRANSITIONS, "peer" => self.label.clone(), "to" => to, "reason" => reason)
            .increment(1);
        self.transitions.fetch_add(1, Ordering::AcqRel);
        match new {
            State::Down {
                reason: why,
                backoff,
                ..
            } if to == "down" => tracing::warn!(
                peer = self.peer,
                from,
                reason = why.as_str(),
                window_ms = backoff.as_millis() as u64,
                "cosigner marked down for signing: later signatures try it last (never skip it)"
            ),
            _ => tracing::info!(
                peer = self.peer,
                from,
                to,
                reason,
                "cosigner liveness changed"
            ),
        }
    }

    /// Open (or keep open) the breaker for `reason`. A failure after a trial was taken doubles the
    /// window (up to the cap); a repeated failure inside a window leaves it.
    pub fn open(&self, reason: DownReason) {
        let mut s = self.lock();
        let now = Instant::now();
        let r2_now = || self.last_load().map(|l| l.r2done);
        let next = match *s {
            State::Up => State::Down {
                reason,
                until: now + self.timing.window,
                backoff: self.timing.window,
                trial: false,
                r2_mark: r2_now(),
            },
            State::Down {
                trial: true,
                backoff,
                r2_mark,
                ..
            } => {
                let backoff = (backoff * 2).min(self.timing.window_cap);
                State::Down {
                    reason,
                    until: now + backoff,
                    backoff,
                    trial: false,
                    r2_mark: r2_mark.or_else(r2_now),
                }
            }
            State::Down {
                until,
                backoff,
                r2_mark,
                trial: false,
                ..
            } => State::Down {
                reason,
                until,
                backoff,
                trial: false,
                r2_mark: r2_mark.or_else(r2_now),
            },
        };
        self.transition(&s, &next, reason.as_str());
        *s = next;
    }

    /// A re-check found the peer still down: double its window (up to the cap), keep the reason
    /// unless `reason` is given.
    fn extend(&self, reason: Option<DownReason>) {
        let mut s = self.lock();
        if let State::Down {
            reason: old,
            backoff,
            r2_mark,
            trial,
            ..
        } = *s
        {
            let backoff = (backoff * 2).min(self.timing.window_cap);
            let reason = reason.unwrap_or(old);
            let next = State::Down {
                reason,
                until: Instant::now() + backoff,
                backoff,
                trial: false,
                r2_mark,
            };
            if trial || reason != old {
                self.transition(&s, &next, reason.as_str());
            }
            *s = next;
        }
    }

    /// Close the breaker (`how`: "probe" | "call").
    pub fn close(&self, how: &'static str) {
        let mut s = self.lock();
        if matches!(*s, State::Up) {
            return;
        }
        self.transition(&s, &State::Up, how);
        *s = State::Up;
    }

    /// A call of `class` succeeded. Any success closes Unreachable; a sign round closes Refusing (a
    /// node refuses round 1 while its store is down); only a round 2 closes Stalled (round 1 does
    /// not touch the store).
    pub fn on_success(&self, class: crate::peer::CallClass) {
        use crate::peer::CallClass;
        let closes = match (self.down_reason(), class) {
            (None, _) => false,
            (Some(DownReason::Unreachable), _) => true,
            (Some(DownReason::Refusing), CallClass::Round1 | CallClass::Round2) => true,
            (Some(DownReason::Stalled), CallClass::Round2) => true,
            _ => false,
        };
        if closes {
            self.close("call");
        }
    }

    /// The peer answered (a refusal): it is reachable, whatever else it is.
    pub fn on_answer(&self) {
        if self.is_unreachable() {
            self.close("call");
        }
    }

    /// The progress test for a sign round that passed its deadline (started at `start`): busy if
    /// this leader completed a round of that kind with the peer meanwhile, or the peer's own
    /// counters were seen moving meanwhile; otherwise one probe decides.
    pub fn judge(&self, round: Round, start: &Mark) -> Judged {
        let now = self.mark();
        if round.pick(&now.done) > round.pick(&start.done) || self.progressed_since(round, start.at)
        {
            return Judged::Busy;
        }
        Judged::Probe
    }

    /// The progress test's probe (whose answer, recorded by [`PeerHealth::note_reply`], is the last
    /// sample): `None` = not opened, else why to open. Not opened when the peer shows progress, when
    /// it reported no load to this leader before the call (a stall cannot be told from a queue it
    /// has not seen moving; the next deadline has a baseline), or when its answer carries no load at
    /// all — a 0.4.x member, whose breaker only `Unreachable` (no answer) or the `keystore-down`
    /// trailer may open, never `Stalled`.
    pub fn judge_probe(&self, round: Round, start: &Mark, probed: Probed) -> Option<DownReason> {
        match probed {
            Probed::Failed => Some(DownReason::Unreachable),
            Probed::Answered(None) => None,
            Probed::Answered(Some(_)) if self.progressed_since(round, start.at) => None,
            Probed::Answered(Some(_)) if !start.baseline => None,
            Probed::Answered(Some(_)) => Some(DownReason::Stalled),
        }
    }

    /// The prober's verdict on a probe of a down peer.
    pub fn after_probe(&self, probed: Probed) {
        let state = *self.lock();
        let State::Down {
            reason, r2_mark, ..
        } = state
        else {
            return;
        };
        match (reason, probed) {
            (DownReason::Unreachable, Probed::Failed) => {}
            (DownReason::Unreachable, Probed::Answered(Some(load))) if !load.store_ok => {
                self.open(DownReason::Refusing);
            }
            (DownReason::Unreachable, Probed::Answered(_)) => self.close("probe"),
            (_, Probed::Failed) => {
                self.open(DownReason::Unreachable);
            }
            // No load in the answer (a refusal before the handler, or a peer that stopped reporting
            // one): nothing to go on, a trial decides. A 0.4.x member never gets here: it is never
            // opened Stalled or Refusing (`judge_probe`).
            (_, Probed::Answered(None)) => {}
            (_, Probed::Answered(Some(load))) if !load.store_ok => {
                self.extend(Some(DownReason::Refusing))
            }
            (DownReason::Refusing, Probed::Answered(Some(_))) => self.close("probe"),
            (DownReason::Stalled, Probed::Answered(Some(load))) => {
                // Round 2s complete there again (the stuck ones, or other leaders'): its store
                // moves. Nothing in flight proves nothing — a request can be stuck before the
                // handler — so that is left to a trial.
                // (A counter below the mark is a restarted peer: nothing of the old one is stuck.)
                if r2_mark.is_some_and(|m| load.r2done != m) {
                    self.close("probe");
                } else if load.inflight > 0 {
                    self.extend(None);
                }
            }
        }
    }

    /// How long the prober waits before its next probe; `None` while up (it stops).
    pub fn next_probe_in(&self) -> Option<Duration> {
        match *self.lock() {
            State::Up => None,
            State::Down {
                reason: DownReason::Unreachable,
                ..
            } => Some(self.timing.probe_every),
            State::Down { until, .. } => Some(
                until
                    .saturating_duration_since(Instant::now())
                    .max(self.timing.probe_every),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::CallClass;

    fn load(inflight: u64, r1: u64, r2: u64) -> Load {
        Load {
            inflight,
            r1done: r1,
            r2done: r2,
            store_ok: true,
        }
    }

    #[test]
    fn the_load_header_round_trips_and_tolerates_unknown_keys() {
        let l = Load {
            inflight: 3,
            r1done: 10,
            r2done: 9,
            store_ok: false,
        };
        assert_eq!(Load::parse(&l.header_value()), Some(l));
        assert_eq!(
            Load::parse("inflight=1; r2done=2; future=x"),
            Some(Load {
                inflight: 1,
                r1done: 0,
                r2done: 2,
                store_ok: true
            })
        );
        assert_eq!(Load::parse("inflight=1"), None, "r2done is required");
        assert_eq!(Load::parse("inflight=x; r2done=2"), None);
        let mut md = tonic::metadata::MetadataMap::new();
        l.insert_into(&mut md);
        assert_eq!(Load::from_metadata(&md), Some(l));
    }

    #[tokio::test(start_paused = true)]
    async fn the_breaker_opens_doubles_its_window_on_a_failed_trial_and_closes_on_a_round_2() {
        let h = PeerHealth::new(2, Liveness::default());
        assert_eq!(h.sign_tier(), Tier::Up);
        h.note_reply(Some(load(1, 5, 5)));
        h.open(DownReason::Stalled);
        assert_eq!((h.state_name(), h.sign_tier()), ("down", Tier::Down));
        // A round 1 success does not prove the store: still down.
        h.on_success(CallClass::Round1);
        assert_eq!(h.down_reason(), Some(DownReason::Stalled));
        assert!(
            !h.trial_due() && h.take_trial().is_none(),
            "inside the window"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        // The window passed. Looking does not use the trial up: only an attempt that includes the
        // peer takes it, and exactly one does.
        for _ in 0..3 {
            assert_eq!(h.sign_tier(), Tier::Down);
            assert!(h.trial_due());
        }
        assert_eq!(h.state_name(), "down");
        assert!(h.take_trial().is_some());
        assert_eq!(h.state_name(), "trial");
        assert!(
            !h.trial_due() && h.take_trial().is_none(),
            "one trial per window"
        );
        // The trial failed: down again for twice the window.
        h.open(DownReason::Stalled);
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(!h.trial_due(), "the window doubled to 4 s");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(h.take_trial().is_some());
        h.on_success(CallClass::Round2);
        assert_eq!((h.state_name(), h.sign_tier()), ("up", Tier::Up));
    }

    /// A trial whose attempt sent the peer a round but got no verdict (the attempt failed at
    /// another member meanwhile) is held for one round 1 plus one round 2, then may be taken again
    /// with no transition and no doubled window. One whose attempt sent the peer nothing is given
    /// back at once: `down` again, due for the next signature, the window not doubled; giving back
    /// an older taking does nothing.
    #[tokio::test(start_paused = true)]
    async fn a_trial_with_no_verdict_can_be_taken_again_after_its_hold() {
        let h = PeerHealth::new(2, Liveness::default());
        h.open(DownReason::Refusing);
        tokio::time::advance(Duration::from_secs(2)).await;
        let first = h.take_trial().expect("due");
        let after_take = h.transitions();
        tokio::time::advance(Liveness::default().trial_hold() - Duration::from_millis(1)).await;
        assert!(h.take_trial().is_none(), "still held");
        tokio::time::advance(Duration::from_millis(1)).await;
        let second = h.take_trial().expect("held no longer");
        assert_eq!(h.transitions(), after_take);
        // The first taking is over: giving it back now leaves the second one alone.
        h.release_trial(first);
        assert_eq!(h.state_name(), "trial");
        assert!(h.take_trial().is_none());
        // The second attempt ends without reaching the peer: given back, due again at once.
        h.release_trial(second);
        assert_eq!(
            (h.state_name(), h.down_reason()),
            ("down", Some(DownReason::Refusing))
        );
        assert_eq!(h.transitions(), after_take + 1);
        assert!(h.trial_due());
        assert!(h.take_trial().is_some(), "the next signature takes it");
        // Not doubled: a failed trial now opens a 4 s window (2 s doubled once), not 8 s.
        h.open(DownReason::Refusing);
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(
            h.trial_due(),
            "the window doubled once, for the one trial that had a verdict"
        );
        // An unreachable peer gets no trial at all: its prober decides.
        let u = PeerHealth::new(3, Liveness::default());
        u.open(DownReason::Unreachable);
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(!u.trial_due() && u.take_trial().is_none());
    }

    /// A 0.4.x member reports no load: a round deadline on it never opens it Stalled, however
    /// often; only no answer at all (Unreachable) does.
    #[tokio::test(start_paused = true)]
    async fn a_member_that_reports_no_load_is_never_opened_stalled() {
        let h = PeerHealth::new(2, Liveness::default());
        for _ in 0..3 {
            let start = h.mark();
            tokio::time::advance(Duration::from_secs(5)).await;
            h.note_reply(None);
            assert_eq!(h.judge(Round::Two, &start), Judged::Probe);
            assert_eq!(
                h.judge_probe(Round::Two, &start, Probed::Answered(None)),
                None
            );
            assert_eq!(
                h.judge_probe(Round::One, &start, Probed::Answered(None)),
                None
            );
        }
        let start = h.mark();
        assert_eq!(
            h.judge_probe(Round::Two, &start, Probed::Failed),
            Some(DownReason::Unreachable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_window_is_capped() {
        let h = PeerHealth::new(2, Liveness::default());
        h.open(DownReason::Refusing);
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(31)).await;
            assert!(h.take_trial().is_some());
            h.open(DownReason::Refusing);
        }
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(h.take_trial().is_some(), "never more than 30 s");
    }

    #[tokio::test(start_paused = true)]
    async fn progress_anywhere_on_the_peer_keeps_it_up_and_a_frozen_counter_opens_it() {
        let h = PeerHealth::new(3, Liveness::default());
        h.note_reply(Some(load(4, 100, 90)));
        tokio::time::advance(Duration::from_millis(10)).await;
        let start = h.mark();
        tokio::time::advance(Duration::from_millis(10)).await;
        // Another leader's round 2s completed meanwhile (seen in a reply to another signature).
        h.note_reply(Some(load(4, 101, 91)));
        assert_eq!(h.judge(Round::Two, &start), Judged::Busy);

        tokio::time::advance(Duration::from_millis(10)).await;
        let start = h.mark();
        tokio::time::advance(Duration::from_millis(10)).await;
        // Replies kept coming, round 1s completed, but no round 2 anywhere: the probe at the end of
        // the wait decides.
        h.note_reply(Some(load(5, 120, 91)));
        assert_eq!(h.judge(Round::Two, &start), Judged::Probe);
        assert_eq!(
            h.judge(Round::One, &start),
            Judged::Busy,
            "round 1s still complete there"
        );

        // Nothing heard: a probe decides (its answer is recorded before it is judged).
        tokio::time::advance(Duration::from_millis(10)).await;
        let start = h.mark();
        tokio::time::advance(Duration::from_millis(10)).await;
        assert_eq!(h.judge(Round::Two, &start), Judged::Probe);
        h.note_reply(Some(load(5, 125, 91)));
        assert_eq!(
            h.judge_probe(Round::Two, &start, Probed::Answered(Some(load(5, 125, 91)))),
            Some(DownReason::Stalled)
        );
        h.note_reply(Some(load(5, 125, 92)));
        assert_eq!(
            h.judge_probe(Round::Two, &start, Probed::Answered(Some(load(5, 125, 92)))),
            None
        );
        assert_eq!(
            h.judge_probe(Round::Two, &start, Probed::Failed),
            Some(DownReason::Unreachable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_load_from_before_the_call_only_counters_seen_moving_count() {
        let h = PeerHealth::new(3, Liveness::default());
        let start = h.mark();
        tokio::time::advance(Duration::from_millis(10)).await;
        // No load seen before the call (the first ones arrive at the end of the wait, with the
        // probe): nothing to compare with, not opened.
        let first = Some(load(9, 50, 40));
        h.note_reply(first);
        h.note_reply(first);
        assert_eq!(
            h.judge_probe(Round::Two, &start, Probed::Answered(first)),
            None
        );
        let h = PeerHealth::new(3, Liveness::default());
        let start = h.mark();
        tokio::time::advance(Duration::from_millis(10)).await;
        // One reply during the wait: a first sample, no baseline — not proof of a stall.
        h.note_reply(Some(load(9, 50, 40)));
        assert_eq!(h.judge(Round::Two, &start), Judged::Probe);
        // Two samples during the wait that move: busy.
        h.note_reply(Some(load(9, 51, 41)));
        assert_eq!(h.judge(Round::Two, &start), Judged::Busy);
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_closes_unreachable_and_a_self_report_closes_a_recovered_store() {
        let h = PeerHealth::new(2, Liveness::default());
        h.open(DownReason::Unreachable);
        assert_eq!(
            h.sign_tier(),
            Tier::Down,
            "an unreachable peer gets no trial; the prober decides"
        );
        h.after_probe(Probed::Failed);
        assert!(h.is_unreachable());
        h.after_probe(Probed::Answered(Some(Load {
            store_ok: false,
            ..load(0, 0, 0)
        })));
        assert_eq!(
            h.down_reason(),
            Some(DownReason::Refusing),
            "reachable, but its store is down"
        );
        h.after_probe(Probed::Answered(Some(load(0, 0, 0))));
        assert_eq!(h.state_name(), "up");

        h.note_reply(Some(load(1, 10, 10)));
        h.open(DownReason::Stalled);
        h.after_probe(Probed::Answered(Some(load(1, 30, 10))));
        assert_eq!(
            h.down_reason(),
            Some(DownReason::Stalled),
            "still one round stuck, no round 2 done"
        );
        h.after_probe(Probed::Answered(None));
        assert_eq!(
            h.down_reason(),
            Some(DownReason::Stalled),
            "no load reported: a trial decides"
        );
        h.after_probe(Probed::Answered(Some(load(0, 30, 10))));
        assert_eq!(
            h.down_reason(),
            Some(DownReason::Stalled),
            "nothing in flight proves nothing"
        );
        h.after_probe(Probed::Answered(Some(load(0, 30, 11))));
        assert_eq!(h.state_name(), "up", "round 2s complete there again");
        // An answered refusal proves reachability, nothing more.
        h.open(DownReason::Unreachable);
        h.on_answer();
        assert_eq!(h.state_name(), "up");
    }
}

// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! What one load run observed from the client side: outcomes by gRPC code, latency percentiles of
//! the successful requests, and a per-second timeline (so a failover shows up as the second it
//! happened in, not as a slightly higher p99).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

/// How many distinct error messages are kept apart; the rest are counted as `(other)`.
const MAX_DISTINCT_MESSAGES: usize = 31;
/// Microseconds in a millisecond.
const MICROS_PER_MS: f64 = 1000.0;
/// The scale that rounds a value in milliseconds to three decimals.
const MS_ROUNDING_SCALE: f64 = 1000.0;
/// The divisor that turns a percentage into a fraction.
const PERCENT_DIVISOR: f64 = 100.0;
/// The median, as a percentile.
const PERCENTILE_P50: f64 = 50.0;
/// The 95th percentile.
const PERCENTILE_P95: f64 = 95.0;
/// The 99th percentile.
const PERCENTILE_P99: f64 = 99.0;

/// The outcome of one logical request (a driver call: every failover attempt included).
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Offset of the request's start from the start of the run.
    pub at: Duration,
    pub latency: Duration,
    /// `"OK"`, or the name of the final gRPC code (see [`code_name`]).
    pub code: &'static str,
    /// The codes that made the client move to another cosigner before the final answer.
    pub failovers: Vec<&'static str>,
    /// The cluster answered OK with something that does not verify (a bad signature, a wrong
    /// ECDH secret, another group key).
    pub bad_answer: bool,
    /// The cosigner that gave the final answer (the leader of a signature); `None` if the
    /// request never reached one.
    pub leader: Option<String>,
}

/// The upper-case name of a gRPC code, as the driver's audit log and the cosigner docs write it.
pub fn code_name(code: tonic::Code) -> &'static str {
    use tonic::Code::*;
    match code {
        Ok => "OK",
        Cancelled => "CANCELLED",
        Unknown => "UNKNOWN",
        InvalidArgument => "INVALID_ARGUMENT",
        DeadlineExceeded => "DEADLINE_EXCEEDED",
        NotFound => "NOT_FOUND",
        AlreadyExists => "ALREADY_EXISTS",
        PermissionDenied => "PERMISSION_DENIED",
        ResourceExhausted => "RESOURCE_EXHAUSTED",
        FailedPrecondition => "FAILED_PRECONDITION",
        Aborted => "ABORTED",
        OutOfRange => "OUT_OF_RANGE",
        Unimplemented => "UNIMPLEMENTED",
        Internal => "INTERNAL",
        Unavailable => "UNAVAILABLE",
        DataLoss => "DATA_LOSS",
        Unauthenticated => "UNAUTHENTICATED",
    }
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct Latency {
    pub count: u64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct Second {
    /// Seconds since the start of the run.
    pub t: u64,
    pub ok: u64,
    pub errors: u64,
    /// The slowest successful request that started in this second.
    pub max_ms: f64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ClientReport {
    pub requests: u64,
    pub ok: u64,
    /// Final outcomes other than OK, by gRPC code. `CLIENT_SATURATED`: a request an open-loop
    /// run could not start because `--max-in-flight` earlier ones were still unanswered.
    pub errors: BTreeMap<String, u64>,
    /// OK answers that did not verify. Always an error.
    pub bad_answers: u64,
    /// Attempts that failed over to another cosigner, by the code that caused it.
    pub failovers: BTreeMap<String, u64>,
    /// One example message per error code, to make a report readable without the logs.
    pub error_samples: BTreeMap<String, String>,
    /// Errors counted by code and message, with digits masked so that ids and numbers do not
    /// split one cause into many (`UNAVAILABLE: … have no room for more of this leader's sign
    /// sessions`). At most 32 distinct messages; the rest under `(other)`.
    pub error_messages: BTreeMap<String, u64>,
    /// Of the successful requests.
    pub latency: Latency,
    pub wall_seconds: f64,
    /// Successful requests per second of wall time.
    pub ok_per_second: f64,
    pub timeline: Vec<Second>,
    /// Per cosigner that gave the final answer: its successes, its errors and the latency of
    /// its successes (a request that failed over counts for the cosigner it ended on).
    pub by_leader: BTreeMap<String, LeaderReport>,
    /// With --eager-connect: how long each client's first connection took, set by the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<ConnectReport>,
    /// The most file descriptors this process held during the run, and its soft limit (Linux;
    /// absent elsewhere): a generator near its limit fails connections itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd_peak: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd_limit: Option<u64>,
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct ConnectReport {
    /// Of the connections that were made.
    pub latency: Latency,
    /// Connections that failed: `timeout` (no connection within --timeout-secs) or `error`.
    pub errors: BTreeMap<String, u64>,
    pub error_sample: Option<String>,
}

/// [`latency`] for callers outside this module (connection times).
pub fn latency_of(micros: &mut [u64]) -> Latency {
    latency(micros)
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct LeaderReport {
    pub ok: u64,
    pub errors: u64,
    pub latency: Latency,
}

/// Collects outcomes during a run.
#[derive(Debug, Default)]
pub struct Recorder {
    outcomes: Vec<Outcome>,
    samples: BTreeMap<String, String>,
    messages: BTreeMap<String, u64>,
    saturated: u64,
}

/// `CODE: message`, digits masked, cut to 160 characters.
fn message_key(code: &str, message: &str) -> String {
    let masked: String = message
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .take(160)
        .collect();
    format!("{code}: {masked}")
}

impl Recorder {
    pub fn record(&mut self, outcome: Outcome, message: Option<String>) {
        if let Some(m) = message {
            let key = message_key(outcome.code, &m);
            // 31 messages and `(other)`: at most 32 entries.
            let key = if self.messages.contains_key(&key)
                || self.messages.len() < MAX_DISTINCT_MESSAGES
            {
                key
            } else {
                "(other)".into()
            };
            *self.messages.entry(key).or_default() += 1;
            self.samples.entry(outcome.code.to_string()).or_insert(m);
        }
        self.outcomes.push(outcome);
    }

    /// An open-loop request that was never sent.
    pub fn saturated(&mut self) {
        self.saturated += 1;
    }

    pub fn report(mut self, wall: Duration) -> ClientReport {
        let mut tally = Tally::default();
        for o in &self.outcomes {
            tally.add(o);
        }
        let Tally {
            mut errors,
            failovers,
            mut ok_micros,
            timeline,
            bad_answers,
            leaders,
        } = tally;
        if self.saturated > 0 {
            errors.insert("CLIENT_SATURATED".into(), self.saturated);
        }
        let ok = ok_micros.len() as u64;
        let wall_seconds = wall.as_secs_f64();
        ClientReport {
            requests: self.outcomes.len() as u64 + self.saturated,
            ok,
            errors,
            bad_answers,
            failovers,
            error_samples: std::mem::take(&mut self.samples),
            error_messages: std::mem::take(&mut self.messages),
            latency: latency(&mut ok_micros),
            wall_seconds: round3(wall_seconds),
            ok_per_second: if wall_seconds > 0.0 {
                round3(ok as f64 / wall_seconds)
            } else {
                0.0
            },
            timeline: timeline.into_values().collect(),
            by_leader: leader_reports(leaders),
            connect: None,
            fd_peak: None,
            fd_limit: None,
        }
    }
}

/// What the outcomes of a run add up to, before the percentiles are taken.
#[derive(Default)]
struct Tally {
    errors: BTreeMap<String, u64>,
    failovers: BTreeMap<String, u64>,
    ok_micros: Vec<u64>,
    timeline: BTreeMap<u64, Second>,
    bad_answers: u64,
    /// Per cosigner that gave the final answer: its errors and the latencies of its successes.
    leaders: BTreeMap<String, (u64, Vec<u64>)>,
}

impl Tally {
    /// Count one outcome.
    fn add(&mut self, o: &Outcome) {
        if let Some(name) = &o.leader {
            let entry = self.leaders.entry(name.clone()).or_default();
            if o.code == "OK" && !o.bad_answer {
                entry.1.push(o.latency.as_micros() as u64);
            } else {
                entry.0 += 1;
            }
        }
        let sec = self
            .timeline
            .entry(o.at.as_secs())
            .or_insert_with(|| Second {
                t: o.at.as_secs(),
                ..Default::default()
            });
        if o.code == "OK" && !o.bad_answer {
            self.ok_micros.push(o.latency.as_micros() as u64);
            sec.ok += 1;
            sec.max_ms = sec.max_ms.max(millis(o.latency.as_micros() as u64));
        } else {
            sec.errors += 1;
            if o.code != "OK" {
                *self.errors.entry(o.code.to_string()).or_default() += 1;
            }
        }
        if o.bad_answer {
            self.bad_answers += 1;
        }
        for f in &o.failovers {
            *self.failovers.entry(f.to_string()).or_default() += 1;
        }
    }
}

/// The per-cosigner report of the tallied leaders (errors, latencies of the successes).
fn leader_reports(leaders: BTreeMap<String, (u64, Vec<u64>)>) -> BTreeMap<String, LeaderReport> {
    leaders
        .into_iter()
        .map(|(name, (errors, mut micros))| {
            (
                name,
                LeaderReport {
                    ok: micros.len() as u64,
                    errors,
                    latency: latency(&mut micros),
                },
            )
        })
        .collect()
}

fn millis(micros: u64) -> f64 {
    round3(micros as f64 / MICROS_PER_MS)
}

fn round3(v: f64) -> f64 {
    (v * MS_ROUNDING_SCALE).round() / MS_ROUNDING_SCALE
}

/// Percentiles by nearest rank: the smallest sample with at least `p` percent at or below it.
fn latency(micros: &mut [u64]) -> Latency {
    if micros.is_empty() {
        return Latency::default();
    }
    micros.sort_unstable();
    let rank = |p: f64| {
        let n = micros.len();
        let idx = ((p / PERCENT_DIVISOR) * n as f64).ceil() as usize;
        micros.get(idx.clamp(1, n) - 1).copied().unwrap_or_default()
    };
    let sum: u128 = micros.iter().map(|&m| u128::from(m)).sum();
    Latency {
        count: micros.len() as u64,
        mean_ms: millis((sum / micros.len() as u128) as u64),
        p50_ms: millis(rank(PERCENTILE_P50)),
        p95_ms: millis(rank(PERCENTILE_P95)),
        p99_ms: millis(rank(PERCENTILE_P99)),
        max_ms: millis(*micros.last().expect("not empty")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(at_ms: u64, latency_ms: u64, code: &'static str) -> Outcome {
        Outcome {
            at: Duration::from_millis(at_ms),
            latency: Duration::from_millis(latency_ms),
            code,
            failovers: Vec::new(),
            bad_answer: false,
            leader: Some(
                if latency_ms.is_multiple_of(2) {
                    "cosigner1"
                } else {
                    "cosigner2"
                }
                .to_string(),
            ),
        }
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let mut micros: Vec<u64> = (1..=100).map(|ms| ms * 1000).collect();
        let l = latency(&mut micros);
        assert_eq!(
            (l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms),
            (50.0, 95.0, 99.0, 100.0)
        );
        assert_eq!(l.mean_ms, 50.5);
        // One sample is every percentile.
        let l = latency(&mut [7_000]);
        assert_eq!((l.p50_ms, l.p99_ms, l.max_ms, l.count), (7.0, 7.0, 7.0, 1));
        assert_eq!(latency(&mut []), Latency::default());
    }

    #[test]
    fn a_report_counts_by_code_and_keeps_errors_out_of_the_latency() {
        let mut r = Recorder::default();
        r.record(outcome(100, 10, "OK"), None);
        r.record(outcome(200, 30, "OK"), None);
        r.record(
            outcome(1200, 5000, "UNAVAILABLE"),
            Some("could not reach signing threshold".into()),
        );
        r.record(outcome(1300, 1, "RESOURCE_EXHAUSTED"), Some("first".into()));
        r.record(
            outcome(1400, 1, "RESOURCE_EXHAUSTED"),
            Some("second".into()),
        );
        let mut failed_over = outcome(1500, 40, "OK");
        failed_over.failovers = vec!["UNAVAILABLE"];
        r.record(failed_over, None);
        let mut bad = outcome(1600, 2, "OK");
        bad.bad_answer = true;
        r.record(bad, Some("signature does not verify".into()));
        r.saturated();

        let rep = r.report(Duration::from_secs(2));
        assert_eq!(rep.requests, 8);
        assert_eq!(rep.ok, 3);
        assert_eq!(rep.bad_answers, 1);
        assert_eq!(rep.errors["UNAVAILABLE"], 1);
        assert_eq!(rep.errors["RESOURCE_EXHAUSTED"], 2);
        assert_eq!(rep.errors["CLIENT_SATURATED"], 1);
        assert_eq!(rep.failovers["UNAVAILABLE"], 1);
        assert_eq!(rep.error_samples["RESOURCE_EXHAUSTED"], "first");
        // Counted by message: the two rate-limit refusals have different texts.
        assert_eq!(rep.error_messages["RESOURCE_EXHAUSTED: first"], 1);
        assert_eq!(
            rep.error_messages["UNAVAILABLE: could not reach signing threshold"],
            1
        );
        assert_eq!(
            message_key("UNAVAILABLE", "sign for k-12: 256 sessions"),
            "UNAVAILABLE: sign for k-##: ### sessions"
        );
        assert_eq!(rep.latency.count, 3);
        assert_eq!(rep.latency.max_ms, 40.0);
        assert_eq!(rep.ok_per_second, 1.5);
        assert_eq!(rep.timeline.len(), 2);
        assert_eq!(
            (
                rep.timeline[0].ok,
                rep.timeline[0].errors,
                rep.timeline[0].max_ms
            ),
            (2, 0, 30.0)
        );
        assert_eq!(
            (
                rep.timeline[1].ok,
                rep.timeline[1].errors,
                rep.timeline[1].max_ms
            ),
            (1, 4, 40.0)
        );
        // Split by the cosigner that answered (even latencies cosigner1, odd cosigner2 here).
        let c1 = &rep.by_leader["cosigner1"];
        assert_eq!((c1.ok, c1.errors, c1.latency.max_ms), (3, 2, 40.0));
        let c2 = &rep.by_leader["cosigner2"];
        assert_eq!((c2.ok, c2.errors), (0, 2));
    }
}

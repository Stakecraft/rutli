// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! What one load run observed from the client side: outcomes by gRPC code, latency percentiles of
//! the successful requests, and a per-second timeline (so a failover shows up as the second it
//! happened in, not as a slightly higher p99).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

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
    /// Of the successful requests.
    pub latency: Latency,
    pub wall_seconds: f64,
    /// Successful requests per second of wall time.
    pub ok_per_second: f64,
    pub timeline: Vec<Second>,
}

/// Collects outcomes during a run.
#[derive(Debug, Default)]
pub struct Recorder {
    outcomes: Vec<Outcome>,
    samples: BTreeMap<String, String>,
    saturated: u64,
}

impl Recorder {
    pub fn record(&mut self, outcome: Outcome, message: Option<String>) {
        if let Some(m) = message {
            self.samples.entry(outcome.code.to_string()).or_insert(m);
        }
        self.outcomes.push(outcome);
    }

    /// An open-loop request that was never sent.
    pub fn saturated(&mut self) {
        self.saturated += 1;
    }

    pub fn report(mut self, wall: Duration) -> ClientReport {
        let mut errors: BTreeMap<String, u64> = BTreeMap::new();
        let mut failovers: BTreeMap<String, u64> = BTreeMap::new();
        let mut ok_micros: Vec<u64> = Vec::new();
        let mut timeline: BTreeMap<u64, Second> = BTreeMap::new();
        let mut bad_answers = 0;
        for o in &self.outcomes {
            let sec = timeline.entry(o.at.as_secs()).or_insert_with(|| Second { t: o.at.as_secs(), ..Default::default() });
            if o.code == "OK" && !o.bad_answer {
                ok_micros.push(o.latency.as_micros() as u64);
                sec.ok += 1;
                sec.max_ms = sec.max_ms.max(millis(o.latency.as_micros() as u64));
            } else {
                sec.errors += 1;
                if o.code != "OK" {
                    *errors.entry(o.code.to_string()).or_default() += 1;
                }
            }
            if o.bad_answer {
                bad_answers += 1;
            }
            for f in &o.failovers {
                *failovers.entry(f.to_string()).or_default() += 1;
            }
        }
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
            latency: latency(&mut ok_micros),
            wall_seconds: round3(wall_seconds),
            ok_per_second: if wall_seconds > 0.0 { round3(ok as f64 / wall_seconds) } else { 0.0 },
            timeline: timeline.into_values().collect(),
        }
    }
}

fn millis(micros: u64) -> f64 {
    round3(micros as f64 / 1000.0)
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Percentiles by nearest rank: the smallest sample with at least `p` percent at or below it.
fn latency(micros: &mut [u64]) -> Latency {
    if micros.is_empty() {
        return Latency::default();
    }
    micros.sort_unstable();
    let rank = |p: f64| {
        let n = micros.len();
        let idx = ((p / 100.0) * n as f64).ceil() as usize;
        micros[idx.clamp(1, n) - 1]
    };
    let sum: u128 = micros.iter().map(|&m| m as u128).sum();
    Latency {
        count: micros.len() as u64,
        mean_ms: millis((sum / micros.len() as u128) as u64),
        p50_ms: millis(rank(50.0)),
        p95_ms: millis(rank(95.0)),
        p99_ms: millis(rank(99.0)),
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
        }
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let mut micros: Vec<u64> = (1..=100).map(|ms| ms * 1000).collect();
        let l = latency(&mut micros);
        assert_eq!((l.p50_ms, l.p95_ms, l.p99_ms, l.max_ms), (50.0, 95.0, 99.0, 100.0));
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
        r.record(outcome(1200, 5000, "UNAVAILABLE"), Some("could not reach signing threshold".into()));
        r.record(outcome(1300, 1, "RESOURCE_EXHAUSTED"), Some("first".into()));
        r.record(outcome(1400, 1, "RESOURCE_EXHAUSTED"), Some("second".into()));
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
        assert_eq!(rep.latency.count, 3);
        assert_eq!(rep.latency.max_ms, 40.0);
        assert_eq!(rep.ok_per_second, 1.5);
        assert_eq!(rep.timeline.len(), 2);
        assert_eq!((rep.timeline[0].ok, rep.timeline[0].errors, rep.timeline[0].max_ms), (2, 0, 30.0));
        assert_eq!((rep.timeline[1].ok, rep.timeline[1].errors, rep.timeline[1].max_ms), (1, 4, 40.0));
    }
}

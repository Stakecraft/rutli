// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! The cosigners' side of a load run: their `/metrics` pages scraped before and after, and what
//! changed in between. Counters are reported as deltas, the sign latency histogram
//! (`rutli_sign_duration_seconds{result="ok"}`) as percentiles of the run's own observations.
//!
//! The metrics endpoint is plain HTTP on the cluster network (docs/observability.md), so a GET
//! over a TCP stream is all that is needed here; no HTTP client crate.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The median, as a quantile.
const QUANTILE_P50: f64 = 0.50;
/// The 95th percentile, as a quantile.
const QUANTILE_P95: f64 = 0.95;
/// The 99th percentile, as a quantile.
const QUANTILE_P99: f64 = 0.99;
/// How many times shorter than its deadline a call is expected to finish (the "3x margin", #249).
const DEADLINE_MARGIN_FACTOR: f64 = 3.0;
/// The scale that rounds a value in milliseconds to three decimals.
const MS_ROUNDING_SCALE: f64 = 1000.0;
/// The scale that rounds a share of calls to six decimals.
const SHARE_ROUNDING_SCALE: f64 = 1e6;

/// The histogram whose percentiles a run reports.
pub const SIGN_DURATION: &str = "rutli_sign_duration_seconds";
/// Per-call durations at the calling leader, by `call` (the peer-liveness deadlines, #249).
pub const PEER_CALL_DURATION: &str = rutli_cosigner::metrics::PEER_CALL_DURATION;

/// The deadline of a `call` value of [`PEER_CALL_DURATION`], or `None` (the leader's own share has
/// none). `control` also covers the liveness probe, whose deadline (2 s) is shorter than the 3 s
/// used here; its calls are few next to `NodeInfo`, `KeyEpoch` and `CeremonyStatus`.
pub fn peer_call_deadline(call: &str) -> Option<Duration> {
    use rutli_cosigner::peer::{
        ABORT_DEADLINE, CONTROL_DEADLINE, ROUND1_DEADLINE, ROUND2_DEADLINE,
    };
    match call {
        "sign_round1" => Some(ROUND1_DEADLINE),
        "sign_round2" => Some(ROUND2_DEADLINE),
        "abort" => Some(ABORT_DEADLINE),
        "control" => Some(CONTROL_DEADLINE),
        _ => None,
    }
}

/// One parsed `/metrics` page.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Scrape {
    /// Metric name -> `counter` | `gauge` | `histogram` | ... (from the `# TYPE` lines).
    pub types: BTreeMap<String, String>,
    /// `name{labels}` exactly as exported -> value.
    pub series: BTreeMap<String, f64>,
}

/// Parse the Prometheus text exposition format, as far as the cosigner's exporter uses it.
pub fn parse(text: &str) -> Scrape {
    let mut out = Scrape::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut it = rest.split_whitespace();
            if let (Some(name), Some(kind)) = (it.next(), it.next()) {
                out.types.insert(name.to_string(), kind.to_string());
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The value follows the last space outside the label braces; label values the cosigner
        // exports (reasons, kinds, key ids) contain no `}`.
        let split = match line.rfind('}') {
            Some(close) => close + 1,
            None => line.find(' ').unwrap_or(line.len()),
        };
        let (series, rest) = line.split_at(split);
        // A timestamp may follow the value.
        if let Some(value) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
        {
            out.series.insert(series.trim().to_string(), value);
        }
    }
    out
}

/// The metric name of a series (`name{…}` -> `name`).
fn metric_name(series: &str) -> &str {
    series.split('{').next().unwrap_or(series)
}

/// The value of label `key` in a series, if it has one.
fn label<'a>(series: &'a str, key: &str) -> Option<&'a str> {
    let labels = series.split_once('{')?.1.strip_suffix('}')?;
    labels.split(',').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"'))
    })
}

/// `GET` a plain-HTTP metrics URL (`http://host:port/path`).
pub async fn fetch(url: &str, timeout: Duration) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url}: only http:// metrics URLs are supported"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/metrics"),
    };
    let work = async {
        let mut stream = tokio::net::TcpStream::connect(authority)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        // HTTP/1.0: the server answers with the whole body and closes, never chunked.
        let request =
            format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\nAccept: text/plain\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| format!("read: {e}"))?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or("no HTTP header in the answer")?;
        let status = head.lines().next().unwrap_or_default();
        if !status
            .split_whitespace()
            .nth(1)
            .is_some_and(|code| code == "200")
        {
            return Err(format!("answered {status:?}"));
        }
        Ok(body.to_string())
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(result) => result.map_err(|e: String| format!("{url}: {e}")),
        Err(_) => Err(format!("{url}: no answer within {} s", timeout.as_secs())),
    }
}

#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct HistogramReport {
    /// Observations during the run, over every scraped cosigner.
    pub count: f64,
    pub mean_ms: f64,
    /// Interpolated inside a bucket, as `histogram_quantile()` does: no finer than the bucket
    /// bounds (10, 25, 50, 75, 100, 150, 250, 500 ms, …).
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// One `call` class of [`PEER_CALL_DURATION`] over the run, summed over the cosigners.
#[derive(Debug, Default, Clone, Serialize, PartialEq)]
pub struct PeerCallReport {
    pub count: f64,
    /// Bucket-interpolated, as `histogram_quantile()`.
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    /// The call's deadline, if it has one.
    pub deadline_ms: Option<f64>,
    /// Share of the calls that finished within a third of the deadline, read at the bucket edge
    /// there (the buckets have one at every deadline/3), so no interpolation is involved. `None`
    /// without a deadline, or if the page has no bucket at that edge.
    pub within_third: Option<f64>,
    /// The 3x margin rule of #249: at least 99.9 % of the calls within a third of the deadline.
    pub margin_3x: Option<bool>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TargetReport {
    pub scraped_before: bool,
    pub scraped_after: bool,
    /// The cosigner restarted during the run (the caller said so, or one of its counters went
    /// down between the scrapes): its deltas are what it counted since the restart.
    pub counters_reset: bool,
    /// Counter deltas of this cosigner (zero deltas left out).
    pub counters: BTreeMap<String, f64>,
    /// Gauges at the end of the run.
    pub gauges: BTreeMap<String, f64>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ServerReport {
    /// `rutli_sign_duration_seconds{result="ok"}` over the run, from the cosigners scraped both
    /// before and after it (or restarted in between). `None`: there was none, or none led a
    /// successful signature.
    pub sign_duration: Option<HistogramReport>,
    /// Counter deltas summed over the cosigners (zero deltas left out).
    pub counters: BTreeMap<String, f64>,
    /// [`PEER_CALL_DURATION`] by `call`, over the cosigners scraped before and after (or restarted
    /// in between). Empty when no cosigner reports it (before 0.5.0) or none made a peer call.
    pub peer_calls: BTreeMap<String, PeerCallReport>,
    pub targets: BTreeMap<String, TargetReport>,
    /// Scrapes that failed, in words.
    pub scrape_errors: Vec<String>,
}

/// What changed between `before` and `after` (target name -> scrape; a missing entry is a scrape
/// that failed). `restarted` names the cosigners known to have restarted in between: their
/// counters started again from zero, so the earlier scrape is not subtracted. A restart nobody
/// announced is recognised when a counter went down; one after which every counter already passed
/// its old value cannot be, which is why the caller should say.
pub fn report(
    before: &BTreeMap<String, Scrape>,
    after: &BTreeMap<String, Scrape>,
    names: &[String],
    restarted: &[String],
    scrape_errors: Vec<String>,
) -> ServerReport {
    let empty = Scrape::default();
    let mut out = ServerReport {
        scrape_errors,
        ..Default::default()
    };
    let mut histograms = Histograms::default();
    for name in names {
        let mut target = TargetReport {
            scraped_before: before.contains_key(name),
            scraped_after: after.contains_key(name),
            ..Default::default()
        };
        let Some(a) = after.get(name) else {
            out.targets.insert(name.clone(), target);
            continue;
        };
        let Some(b) = before
            .get(name)
            .or_else(|| restarted.contains(name).then_some(&empty))
        else {
            // No baseline: everything this cosigner counted since it started would pass for the
            // run's own. Its gauges are still what they are.
            for (series, &value) in &a.series {
                if a.types
                    .get(metric_name(series))
                    .is_some_and(|t| t == "gauge")
                {
                    target.gauges.insert(series.clone(), value);
                }
            }
            out.scrape_errors.push(format!(
                "{name}: not scraped before the run, so its counters are left out"
            ));
            out.targets.insert(name.clone(), target);
            continue;
        };
        let cumulative = |series: &str| {
            let metric = metric_name(series);
            let base = metric
                .strip_suffix("_bucket")
                .or_else(|| metric.strip_suffix("_sum"))
                .or_else(|| metric.strip_suffix("_count"))
                .unwrap_or(metric);
            [metric, base].iter().any(|m| {
                a.types
                    .get(*m)
                    .is_some_and(|t| t == "counter" || t == "histogram")
            })
        };
        target.counters_reset = restarted.contains(name)
            || b.series.iter().any(|(series, &was)| {
                cumulative(series) && a.series.get(series).is_none_or(|&now| now < was)
            });
        let b = if target.counters_reset { &empty } else { b };
        for (series, &value) in &a.series {
            let metric = metric_name(series);
            let base = metric
                .strip_suffix("_bucket")
                .or_else(|| metric.strip_suffix("_sum"))
                .or_else(|| metric.strip_suffix("_count"))
                .filter(|base| a.types.get(*base).is_some_and(|t| t == "histogram"));
            let kind = a
                .types
                .get(base.unwrap_or(metric))
                .map_or("untyped", String::as_str);
            if kind == "gauge" {
                target.gauges.insert(series.clone(), value);
                continue;
            }
            if kind != "counter" && kind != "histogram" {
                continue;
            }
            let delta = value - b.series.get(series).copied().unwrap_or(0.0);
            if kind == "counter" {
                if delta != 0.0 {
                    target.counters.insert(series.clone(), delta);
                    *out.counters.entry(series.clone()).or_default() += delta;
                }
            } else {
                histograms.add(series, metric, base, delta);
            }
        }
        out.targets.insert(name.clone(), target);
    }
    out.peer_calls = histograms.peer_calls();
    out.sign_duration = histograms.sign_duration();
    out
}

/// The histogram deltas a report reads, summed over the cosigners.
#[derive(Default)]
struct Histograms {
    /// [`SIGN_DURATION`] with `result="ok"`: le -> cumulative count, and its sum and count.
    sign_buckets: BTreeMap<String, f64>,
    sign_sum: f64,
    sign_count: f64,
    /// [`PEER_CALL_DURATION`]: call -> le -> cumulative count.
    peer: BTreeMap<String, BTreeMap<String, f64>>,
}

impl Histograms {
    /// Add one histogram series' delta (`metric` is its name, `base` the histogram it belongs to).
    fn add(&mut self, series: &str, metric: &str, base: Option<&str>, delta: f64) {
        let le = label(series, "le");
        if base == Some(PEER_CALL_DURATION) {
            if let (Some(call), Some(le)) = (label(series, "call"), le) {
                let calls = self.peer.entry(call.to_string()).or_default();
                *calls.entry(le.to_string()).or_default() += delta;
            }
            return;
        }
        if base != Some(SIGN_DURATION) || label(series, "result") != Some("ok") {
            return;
        }
        match le {
            Some(le) => *self.sign_buckets.entry(le.to_string()).or_default() += delta,
            None if metric.ends_with("_sum") => self.sign_sum += delta,
            None => self.sign_count += delta,
        }
    }

    fn sign_duration(&self) -> Option<HistogramReport> {
        if self.sign_count <= 0.0 {
            return None;
        }
        let cumulative = sorted_cumulative(&self.sign_buckets);
        let q = |q: f64| round3(quantile(q, &cumulative) * MS_PER_SEC);
        Some(HistogramReport {
            count: self.sign_count,
            mean_ms: round3(self.sign_sum / self.sign_count * MS_PER_SEC),
            p50_ms: q(QUANTILE_P50),
            p95_ms: q(QUANTILE_P95),
            p99_ms: q(QUANTILE_P99),
        })
    }

    fn peer_calls(&self) -> BTreeMap<String, PeerCallReport> {
        self.peer
            .iter()
            .filter_map(|(call, buckets)| Some((call.clone(), peer_call_report(call, buckets)?)))
            .collect()
    }
}

const MS_PER_SEC: f64 = 1000.0;
/// The share of calls that must finish within a third of their deadline (#249).
const MARGIN_SHARE: f64 = 0.999;
/// How far a bucket edge may sit from the exact third of a deadline (the edges are rounded: 0.33,
/// 0.67, 1.67, each a little above, which makes the rule that much lenient).
const THIRD_EDGE_TOLERANCE_SECS: f64 = 0.005;

/// Cumulative buckets (`le` -> count) as (upper bound, count) sorted by bound; `+Inf` is infinite,
/// an unparsable `le` is left out.
fn sorted_cumulative(buckets: &BTreeMap<String, f64>) -> Vec<(f64, f64)> {
    let mut cumulative: Vec<(f64, f64)> = buckets
        .iter()
        .filter_map(|(le, &n)| {
            let bound = if le == "+Inf" {
                f64::INFINITY
            } else {
                le.parse().ok()?
            };
            Some((bound, n))
        })
        .collect();
    cumulative.sort_by(|x, y| x.0.total_cmp(&y.0));
    cumulative
}

/// One call class from its summed cumulative buckets (`le` -> count), or `None` if it saw no call.
fn peer_call_report(call: &str, buckets: &BTreeMap<String, f64>) -> Option<PeerCallReport> {
    let cumulative = sorted_cumulative(buckets);
    let total = cumulative.last().map(|&(_, n)| n).filter(|&n| n > 0.0)?;
    let deadline = peer_call_deadline(call).map(|d| d.as_secs_f64());
    let within_third = deadline.and_then(|d| {
        cumulative
            .iter()
            .find(|(bound, _)| {
                (bound - d / DEADLINE_MARGIN_FACTOR).abs() < THIRD_EDGE_TOLERANCE_SECS
            })
            .map(|&(_, n)| n / total)
    });
    let q = |q: f64| round3(quantile(q, &cumulative) * MS_PER_SEC);
    Some(PeerCallReport {
        count: total,
        p50_ms: q(QUANTILE_P50),
        p99_ms: q(QUANTILE_P99),
        p999_ms: q(MARGIN_SHARE),
        deadline_ms: deadline.map(|d| round3(d * MS_PER_SEC)),
        within_third: within_third
            .map(|w| (w * SHARE_ROUNDING_SCALE).round() / SHARE_ROUNDING_SCALE),
        margin_3x: within_third.map(|w| w >= MARGIN_SHARE),
    })
}

fn round3(v: f64) -> f64 {
    (v * MS_ROUNDING_SCALE).round() / MS_ROUNDING_SCALE
}

/// `histogram_quantile(q, …)` over cumulative buckets sorted by upper bound: linear interpolation
/// inside the bucket the rank falls in, from 0 for the first bucket; a rank in the `+Inf` bucket
/// answers the highest finite bound.
pub fn quantile(q: f64, cumulative: &[(f64, f64)]) -> f64 {
    let Some(&(_, total)) = cumulative.last() else {
        return f64::NAN;
    };
    if total <= 0.0 {
        return f64::NAN;
    }
    let rank = q * total;
    let (mut lower, mut below) = (0.0, 0.0);
    for &(upper, count) in cumulative {
        if count >= rank {
            if upper.is_infinite() {
                return lower;
            }
            if count == below {
                return upper;
            }
            return lower + (upper - lower) * (rank - below) / (count - below);
        }
        lower = upper;
        below = count;
    }
    lower
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "\
# HELP rutli_sign_requests_total Sign outcomes
# TYPE rutli_sign_requests_total counter
rutli_sign_requests_total{result=\"ok\"} 10
rutli_sign_requests_total{result=\"error\"} 1
# TYPE rutli_pending_sign_sessions gauge
rutli_pending_sign_sessions 3
# TYPE rutli_sign_duration_seconds histogram
rutli_sign_duration_seconds_bucket{result=\"ok\",le=\"0.01\"} 2
rutli_sign_duration_seconds_bucket{result=\"ok\",le=\"0.025\"} 8
rutli_sign_duration_seconds_bucket{result=\"ok\",le=\"0.05\"} 10
rutli_sign_duration_seconds_bucket{result=\"ok\",le=\"+Inf\"} 10
rutli_sign_duration_seconds_sum{result=\"ok\"} 0.2
rutli_sign_duration_seconds_count{result=\"ok\"} 10
rutli_sign_duration_seconds_bucket{result=\"error\",le=\"+Inf\"} 1
rutli_sign_duration_seconds_sum{result=\"error\"} 45
rutli_sign_duration_seconds_count{result=\"error\"} 1
rutli_untyped_thing 7
";

    #[test]
    fn parses_types_series_and_labels() {
        let s = parse(PAGE);
        assert_eq!(s.types["rutli_sign_requests_total"], "counter");
        assert_eq!(s.types["rutli_sign_duration_seconds"], "histogram");
        assert_eq!(s.series["rutli_sign_requests_total{result=\"ok\"}"], 10.0);
        assert_eq!(s.series["rutli_pending_sign_sessions"], 3.0);
        let bucket = "rutli_sign_duration_seconds_bucket{result=\"ok\",le=\"0.025\"}";
        assert_eq!(s.series[bucket], 8.0);
        assert_eq!(metric_name(bucket), "rutli_sign_duration_seconds_bucket");
        assert_eq!(label(bucket, "le"), Some("0.025"));
        assert_eq!(label(bucket, "result"), Some("ok"));
        assert_eq!(label(bucket, "nope"), None);
        assert_eq!(label("rutli_pending_sign_sessions", "le"), None);
    }

    #[test]
    fn quantiles_interpolate_like_prometheus() {
        let buckets = [
            (0.01, 2.0),
            (0.025, 8.0),
            (0.05, 10.0),
            (f64::INFINITY, 10.0),
        ];
        // Rank 5 of 10 lies in (0.01, 0.025], 3 of its 6 observations in.
        assert!((quantile(0.5, &buckets) - 0.0175).abs() < 1e-12);
        // Rank 9.5 lies in (0.025, 0.05].
        assert!((quantile(0.95, &buckets) - 0.04375).abs() < 1e-12);
        // Everything in the first bucket: from 0.
        assert!((quantile(0.5, &[(0.01, 4.0), (f64::INFINITY, 4.0)]) - 0.005).abs() < 1e-12);
        // A rank beyond the last finite bound answers that bound.
        assert_eq!(
            quantile(0.99, &[(0.01, 1.0), (10.0, 1.0), (f64::INFINITY, 100.0)]),
            10.0
        );
        assert!(quantile(0.5, &[]).is_nan());
    }

    #[test]
    fn a_report_is_the_difference_of_two_scrapes() {
        let before = parse(PAGE);
        let mut after = before.clone();
        *after
            .series
            .get_mut("rutli_sign_requests_total{result=\"ok\"}")
            .unwrap() = 30.0;
        for (le, v) in [
            ("0.01", 2.0),
            ("0.025", 18.0),
            ("0.05", 30.0),
            ("+Inf", 30.0),
        ] {
            *after
                .series
                .get_mut(&format!(
                    "rutli_sign_duration_seconds_bucket{{result=\"ok\",le=\"{le}\"}}"
                ))
                .unwrap() = v;
        }
        *after
            .series
            .get_mut("rutli_sign_duration_seconds_sum{result=\"ok\"}")
            .unwrap() = 0.8;
        *after
            .series
            .get_mut("rutli_sign_duration_seconds_count{result=\"ok\"}")
            .unwrap() = 30.0;
        *after.series.get_mut("rutli_pending_sign_sessions").unwrap() = 0.0;

        let names = vec!["cosigner1".to_string(), "cosigner2".to_string()];
        let b = BTreeMap::from([("cosigner1".to_string(), before.clone())]);
        let a = BTreeMap::from([("cosigner1".to_string(), after)]);
        let r = report(
            &b,
            &a,
            &names,
            &[],
            vec!["cosigner2: connect: refused".into()],
        );

        assert_eq!(
            r.counters.len(),
            1,
            "only the counter that moved: {:?}",
            r.counters
        );
        assert_eq!(r.counters["rutli_sign_requests_total{result=\"ok\"}"], 20.0);
        let h = r.sign_duration.expect("the run observed signatures");
        // The run's own 20 observations: 0 up to 10 ms, 10 up to 25 ms, 10 up to 50 ms.
        assert_eq!(h.count, 20.0);
        assert_eq!(h.mean_ms, 30.0);
        assert_eq!(h.p50_ms, 25.0);
        assert_eq!(h.p95_ms, 47.5);
        let t = &r.targets["cosigner1"];
        assert!(t.scraped_before && t.scraped_after && !t.counters_reset);
        assert_eq!(t.gauges["rutli_pending_sign_sessions"], 0.0);
        assert!(!r.targets["cosigner2"].scraped_after);
        assert_eq!(r.scrape_errors.len(), 1);

        // Scraped only after the run: without a baseline its lifetime counters are not the run's.
        let r = report(&BTreeMap::new(), &a, &names[..1], &[], Vec::new());
        assert!(
            r.counters.is_empty() && r.sign_duration.is_none(),
            "{:?}",
            r.counters
        );
        assert_eq!(
            r.targets["cosigner1"].gauges["rutli_pending_sign_sessions"],
            0.0
        );
        assert_eq!(r.scrape_errors.len(), 1);
    }

    /// The per-call readout behind #249: per `call`, summed over cosigners, the delta of the run,
    /// quantiles, and the share within a third of the deadline read at that bucket edge.
    #[test]
    fn peer_call_durations_are_read_per_call_with_the_3x_margin() {
        let page = |r1: [u64; 4], r2: [u64; 3], local: u64| {
            parse(&format!(
                "# TYPE rutli_peer_call_duration_seconds histogram\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round1\",le=\"0.25\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round1\",le=\"0.67\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round1\",le=\"2\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round1\",le=\"+Inf\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round2\",le=\"0.5\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round2\",le=\"1.67\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"sign_round2\",le=\"+Inf\"}} {}\n\
                 rutli_peer_call_duration_seconds_bucket{{call=\"local_share\",le=\"+Inf\"}} {local}\n",
                r1[0], r1[1], r1[2], r1[3], r2[0], r2[1], r2[2]
            ))
        };
        let names = vec!["c1".to_string(), "c2".to_string()];
        let before = BTreeMap::from([
            ("c1".to_string(), page([5, 5, 5, 5], [5, 5, 5], 9)),
            ("c2".to_string(), page([0; 4], [0; 3], 0)),
        ]);
        // Run: round 1 on c1 10000 calls, 9995 within 0.67 s; c2 adds 990 of 1000 within 0.25 s.
        // Round 2: every call within 1.67 s.
        let after = BTreeMap::from([
            (
                "c1".to_string(),
                page([9005, 10000, 10005, 10005], [2005, 2005, 2005], 9),
            ),
            ("c2".to_string(), page([990, 1000, 1000, 1000], [0; 3], 0)),
        ]);
        let r = report(&before, &after, &names, &[], Vec::new());
        let r1 = &r.peer_calls["sign_round1"];
        assert_eq!(r1.count, 11000.0);
        assert_eq!(r1.deadline_ms, Some(2000.0));
        // 10995 of 11000 within 0.67 s: 99.95 %, the rule holds.
        assert_eq!(r1.within_third, Some(0.999545));
        assert_eq!(r1.margin_3x, Some(true));
        // 99.95 % within 0.67 s puts p99.9 inside that bucket.
        assert!(r1.p999_ms > 250.0 && r1.p999_ms <= 670.0, "{r1:?}");
        let r2 = &r.peer_calls["sign_round2"];
        assert_eq!(
            (r2.count, r2.within_third, r2.margin_3x),
            (2000.0, Some(1.0), Some(true))
        );
        // The leader's own share has no deadline, and a call class that saw no call is left out.
        assert!(
            !r.peer_calls.contains_key("local_share"),
            "{:?}",
            r.peer_calls
        );

        // One call in 500 past a third of the deadline breaks the rule.
        let after = BTreeMap::from([
            ("c1".to_string(), page([5, 4995, 5005, 5005], [5, 5, 5], 9)),
            ("c2".to_string(), page([0; 4], [0; 3], 0)),
        ]);
        let r1 = &report(&before, &after, &names, &[], Vec::new()).peer_calls["sign_round1"];
        assert_eq!(r1.margin_3x, Some(false), "{r1:?}");
        assert_eq!(peer_call_deadline("local_share"), None);
        assert_eq!(peer_call_deadline("control"), Some(Duration::from_secs(3)));
    }

    #[test]
    fn a_restarted_cosigner_reports_what_it_counted_since() {
        let before = parse(PAGE);
        let mut after = before.clone();
        *after
            .series
            .get_mut("rutli_sign_requests_total{result=\"ok\"}")
            .unwrap() = 4.0;
        let names = vec!["cosigner1".to_string()];
        let (b, a) = (
            BTreeMap::from([("cosigner1".to_string(), before.clone())]),
            BTreeMap::from([("cosigner1".to_string(), after)]),
        );
        // One counter went down: nothing of the earlier scrape is subtracted, not even from the
        // series that did not go down.
        let r = report(&b, &a, &names, &[], Vec::new());
        assert!(r.targets["cosigner1"].counters_reset);
        assert_eq!(r.counters["rutli_sign_requests_total{result=\"ok\"}"], 4.0);
        assert_eq!(
            r.counters["rutli_sign_requests_total{result=\"error\"}"],
            1.0
        );
        assert_eq!(r.sign_duration.unwrap().count, 10.0);

        // Announced by the caller: the same, although every counter passed its old value.
        let mut grown = before.clone();
        *grown
            .series
            .get_mut("rutli_sign_requests_total{result=\"ok\"}")
            .unwrap() = 12.0;
        let a = BTreeMap::from([("cosigner1".to_string(), grown)]);
        let r = report(&b, &a, &names, &[], Vec::new());
        assert_eq!(r.counters["rutli_sign_requests_total{result=\"ok\"}"], 2.0);
        let r = report(&b, &a, &names, &names, Vec::new());
        assert!(r.targets["cosigner1"].counters_reset);
        assert_eq!(r.counters["rutli_sign_requests_total{result=\"ok\"}"], 12.0);
    }
}

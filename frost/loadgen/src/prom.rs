// Copyright 2026 StakeCraft
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

/// The histogram whose percentiles a run reports.
pub const SIGN_DURATION: &str = "rutli_sign_duration_seconds";

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
    // le -> cumulative count over the cosigners, and the histogram's sum and count.
    let mut buckets: BTreeMap<String, f64> = BTreeMap::new();
    let (mut hist_sum, mut hist_count) = (0.0, 0.0);
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
                .map(String::as_str)
                .unwrap_or("untyped");
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
            } else if base == Some(SIGN_DURATION) && label(series, "result") == Some("ok") {
                if metric.ends_with("_bucket") {
                    if let Some(le) = label(series, "le") {
                        *buckets.entry(le.to_string()).or_default() += delta;
                    }
                } else if metric.ends_with("_sum") {
                    hist_sum += delta;
                } else {
                    hist_count += delta;
                }
            }
        }
        out.targets.insert(name.clone(), target);
    }
    if hist_count > 0.0 {
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
        let q = |q: f64| round3(quantile(q, &cumulative) * 1000.0);
        out.sign_duration = Some(HistogramReport {
            count: hist_count,
            mean_ms: round3(hist_sum / hist_count * 1000.0),
            p50_ms: q(0.50),
            p95_ms: q(0.95),
            p99_ms: q(0.99),
        });
    }
    out
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
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

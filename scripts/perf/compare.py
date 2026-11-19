#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Compare a load run (scripts/perf/run.py) with a previous one.

Usage: compare.py [--threshold 0.20] [--floor-ms 2] [--markdown FILE] PREVIOUS CURRENT

Prints a table and exits 1 when
  - a p95 or p99 of the current run is more than the threshold (default 20 %) above the previous
    run's, for a scenario both runs made with the same load (and the difference is more than the
    floor, default 2 ms: below that it is timer and scheduler noise, not a regression). A two-hour
    run is not compared with a one-minute run: the load must be the same, its length included; or
  - the current run has a failed scenario: a request that ended in a code the scenario does not
    allow, an answer that did not verify, an unhealthy cosigner, memory or descriptors out of
    bounds. That is judged on the current run alone.

Compared per scenario: the client's p95 and p99 (every request, failovers included) and the
cosigners' own p95 and p99 from rutli_sign_duration_seconds (leader side, bucket-interpolated).
Only scenarios the run marks for comparison: a limit test's latency is the latency of refusals.

PREVIOUS may be missing (a first run): then only the current run's failures count. Exit 2 on a
usage error or an unreadable CURRENT. Standard library only.
"""

import argparse
import json
import os
import sys


def load_params(scenario):
    """What must be equal for two runs' latencies to be comparable."""
    loads = [l for l in scenario.get("loads", []) if "failed" not in l]
    return [(l.get("command"), l.get("rate"), l.get("clients"), l.get("count"), l.get("duration_secs")) for l in loads]


def latencies(scenario):
    """metric name -> milliseconds, for the first load of a scenario."""
    out = {}
    loads = [l for l in scenario.get("loads", []) if "failed" not in l]
    if not loads:
        return out
    client = loads[0].get("client", {}).get("latency", {})
    server = loads[0].get("server", {}).get("sign_duration") or {}
    for q in ("p95_ms", "p99_ms"):
        if client.get("count"):
            out[f"client {q[:-3]}"] = client.get(q)
        if server.get("count"):
            out[f"cosigner {q[:-3]}"] = server.get(q)
    return {k: v for k, v in out.items() if isinstance(v, (int, float))}


def compare(previous, current, threshold, floor_ms):
    """(rows, problems): table rows and the reasons to fail."""
    rows, problems = [], []
    for name in current.get("failed", []):
        scenario = next((s for s in current.get("scenarios", []) if s.get("name") == name), None)
        failed = [c for c in (scenario or {}).get("checks", []) if not c.get("ok")]
        if not failed:
            failed = [{"check": "the scenario ran", "detail": str(current.get("setup", {}).get("failed", ""))}]
        for c in failed:
            detail = f"{c['check']}: {c.get('detail', '')}".rstrip(": ")
            rows.append((name, "check", "", "", "", f"FAILED: {detail}"))
            problems.append(f"{name}: {detail}")

    comparable = previous is not None and all(
        previous.get(k) == current.get(k) for k in ("schema", "kind", "environment")
    )
    if previous is not None and not comparable:
        rows.append(("(all)", "latency", "", "", "", "not compared: the previous run is of another kind or environment"))
    before = {s.get("name"): s for s in (previous or {}).get("scenarios", [])} if comparable else {}
    for scenario in current.get("scenarios", []):
        name = scenario.get("name")
        if not scenario.get("compare_latency"):
            continue
        now = latencies(scenario)
        old_scenario = before.get(name)
        if old_scenario is None:
            for metric, value in now.items():
                rows.append((name, metric, "", f"{value:.1f}", "", "no previous value"))
            continue
        if load_params(old_scenario) != load_params(scenario):
            for metric, value in now.items():
                rows.append((name, metric, "", f"{value:.1f}", "", "not compared: the load differs"))
            continue
        old = latencies(old_scenario)
        for metric, value in now.items():
            if metric not in old:
                rows.append((name, metric, "", f"{value:.1f}", "", "no previous value"))
                continue
            was = old[metric]
            change = (value - was) / was if was > 0 else 0.0
            regressed = value > was * (1 + threshold) and value - was > floor_ms
            verdict = "REGRESSION" if regressed else "ok"
            rows.append((name, metric, f"{was:.1f}", f"{value:.1f}", f"{change:+.0%}", verdict))
            if regressed:
                problems.append(f"{name}: {metric} {was:.1f} ms -> {value:.1f} ms ({change:+.0%})")
    return rows, problems


def table(rows):
    head = ("scenario", "metric", "previous ms", "current ms", "change", "verdict")
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in row) + " |")
    return "\n".join(lines)


def read(path):
    with open(path) as f:
        return json.load(f)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("previous")
    p.add_argument("current")
    p.add_argument("--threshold", type=float, default=0.20)
    p.add_argument("--floor-ms", type=float, default=2.0)
    p.add_argument("--markdown", help="also write the report to this file")
    args = p.parse_args(argv)

    try:
        current = read(args.current)
    except (OSError, ValueError) as e:
        print(f"compare: cannot read the current run {args.current}: {e}", file=sys.stderr)
        return 2
    previous, note = None, ""
    if not os.path.exists(args.previous):
        note = "No previous run to compare with: only this run's own failures are judged."
    else:
        try:
            previous = read(args.previous)
        except (OSError, ValueError) as e:
            note = f"The previous run {args.previous} is unreadable ({e}): only this run's own failures are judged."

    rows, problems = compare(previous, current, args.threshold, args.floor_ms)
    lines = [
        f"Load run {current.get('commit', '?')[:12]} ({current.get('started_at', '?')})"
        + (f" against {previous.get('commit', '?')[:12]} ({previous.get('started_at', '?')})" if previous else ""),
        "",
    ]
    if note:
        lines += [note, ""]
    lines += [table(rows) if rows else "Nothing to compare.", ""]
    if problems:
        lines += [f"{len(problems)} problem(s):"] + [f"- {x}" for x in problems]
    else:
        lines += [f"No regression above {args.threshold:.0%} and no failed scenario."]
    report = "\n".join(lines) + "\n"
    print(report, end="")
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(report)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

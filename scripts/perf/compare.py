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


def judge(rows, problems, name, metric, was, value, threshold, floor_ms):
    """One latency against its previous value: a row, and a problem if it regressed."""
    change = (value - was) / was if was > 0 else 0.0
    regressed = value > was * (1 + threshold) and value - was > floor_ms
    rows.append((name, metric, f"{was:.1f}", f"{value:.1f}", f"{change:+.0%}", "REGRESSION" if regressed else "ok"))
    if regressed:
        problems.append(f"{name}: {metric} {was:.1f} ms -> {value:.1f} ms ({change:+.0%})")


def compare_ramp(previous, current, threshold, floor_ms, rows, problems):
    """The cluster suite's scale ramp: the headroom factor must not drop, and each factor both
    runs passed must not be slower (same profile only)."""
    now, old = current.get("ramp"), (previous or {}).get("ramp")
    if not now:
        return
    if now.get("failed"):
        return  # reported with the failed scenarios
    head = now.get("headroom_factor")
    if not old or previous.get("profile") != current.get("profile"):
        rows.append(("ramp", "headroom factor", "", f"{head}", "", "no previous value with this profile"))
        return
    was_head = old.get("headroom_factor")
    dropped = isinstance(head, (int, float)) and isinstance(was_head, (int, float)) and head < was_head
    rows.append(("ramp", "headroom factor", f"{was_head}", f"{head}", "", "REGRESSION" if dropped else "ok"))
    if dropped:
        problems.append(f"ramp: headroom factor {was_head} -> {head}")
    before = {st.get("factor"): st for st in old.get("steps", []) if st.get("passed")}
    for st in now.get("steps", []):
        prev = before.get(st.get("factor"))
        if not st.get("passed") or prev is None:
            continue
        for op, o in st.get("ops", {}).items():
            po = prev.get("ops", {}).get(op)
            if po:
                judge(rows, problems, f"ramp x{st['factor']:g}", f"{op} p99", po.get("p99_ms", 0), o.get("p99_ms", 0),
                      threshold, floor_ms)


def compare_keys(previous, current, threshold, floor_ms, rows, problems):
    """The cluster suite's key-count dimension: per key count, sign p95/p99 and the slowest
    cosigner's mean ListKeys time."""
    same_profile = previous is not None and previous.get("profile") == current.get("profile")
    old = {k.get("count"): k for k in (previous or {}).get("keys") or []} if same_profile else {}
    for k in current.get("keys") or []:
        name = f"keys {k.get('count')}"
        if not k.get("passed"):
            continue
        lat = (k.get("sign") or {}).get("latency") or {}
        lists = [t.get("mean_ms", 0) for t in (k.get("list_keys") or {}).values()]
        now = {"sign p95": lat.get("p95_ms"), "sign p99": lat.get("p99_ms"), "list-keys mean (slowest)": max(lists) if lists else None}
        prev = old.get(k.get("count"))
        if not prev or not prev.get("passed"):
            for metric, value in now.items():
                if value is not None:
                    rows.append((name, metric, "", f"{value:.1f}", "", "no previous value"))
            continue
        plat = (prev.get("sign") or {}).get("latency") or {}
        plists = [t.get("mean_ms", 0) for t in (prev.get("list_keys") or {}).values()]
        was = {"sign p95": plat.get("p95_ms"), "sign p99": plat.get("p99_ms"), "list-keys mean (slowest)": max(plists) if plists else None}
        for metric, value in now.items():
            if value is not None and was.get(metric) is not None:
                judge(rows, problems, name, metric, was[metric], value, threshold, floor_ms)


def compare(previous, current, threshold, floor_ms):
    """(rows, problems): table rows and the reasons to fail."""
    rows, problems = [], []
    # Rütli's failures, then the rig's (a load generator that could not run or be reached): both
    # fail the comparison, but a rig failure says nothing about Rütli and is labelled so.
    marked = [(n, "FAILED", "") for n in current.get("failed", [])] + \
             [(n, "RIG FAILED", "rig: ") for n in current.get("rig_failed", [])]
    for name, verdict, prefix in marked:
        scenario = next((s for s in current.get("scenarios", []) if s.get("name") == name), None)
        failed = [c for c in (scenario or {}).get("checks", []) if not c.get("ok")]
        if not failed and name == "keys":
            failed = [{"check": "every key count passed", "detail": "; ".join(
                f"{k.get('count')} keys: {k.get('setup_failed') or k.get('list_keys_failed') or (k.get('sign') or {}).get('errors') or 'failed'}"
                for k in current.get("keys") or [] if not k.get("passed"))}]
        elif not failed and name == "ramp":
            failed = [{"check": "the ramp ran", "detail": str((current.get("ramp") or {}).get("failed", ""))}]
        elif not failed:
            failed = [{"check": "the scenario ran", "detail": str(current.get("setup", {}).get("failed", ""))}]
        for c in failed:
            detail = f"{c['check']}: {c.get('detail', '')}".rstrip(": ")
            rows.append((name, "check", "", "", "", f"{verdict}: {detail}"))
            problems.append(f"{prefix}{name}: {detail}")

    comparable = previous is not None and all(
        previous.get(k) == current.get(k) for k in ("schema", "kind", "environment", "client_policy")
    )
    # A diagnostic run (data on tmpfs) is never a baseline, nor compared with one.
    diagnostic = previous is not None and (previous.get("diagnostic") or current.get("diagnostic"))
    if diagnostic:
        comparable = False
        rows.append(("(all)", "latency", "", "", "",
                     f"not compared: a diagnostic run ({previous.get('diagnostic') or current.get('diagnostic')}) is never a baseline"))
    elif previous is not None and not comparable:
        rows.append(("(all)", "latency", "", "", "",
                     "not compared: the previous run is of another kind, environment or client deadline policy"))
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
            judge(rows, problems, name, metric, old[metric], value, threshold, floor_ms)
    for skipped in current.get("skipped") or []:
        rows.append((skipped.get("name"), "skipped", "", "", "", skipped.get("reason", "")))
    if current.get("kind") == "cluster":
        prev = previous if comparable else None
        compare_ramp(prev, current, threshold, floor_ms, rows, problems)
        compare_keys(prev, current, threshold, floor_ms, rows, problems)
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
    if current.get("diagnostic"):
        lines += [f"DIAGNOSTIC RUN ({current['diagnostic']}): not a configuration, never a baseline.", ""]
    dx = current.get("diagnosis") or {}
    if dx.get("steps"):
        lines += [f"Diagnosis: knee at x{dx.get('knee_factor')}, at most {dx.get('max_ok_per_sec')} signatures/s; "
                  f"the volume's flushes alone would allow about "
                  f"{dx.get('predicted_ceiling_signs_per_sec')}/s; keys: {dx.get('keys_verdict', 'not run')}", ""]
    if current.get("headroom_factor") is not None:
        lines += [f"Headroom factor: {current['headroom_factor']} (profile {current.get('profile')})", ""]
    real = (current.get("ramp") or {}).get("real_load_headroom") or []
    if real:
        lines += ["Headroom against the real load: " + "; ".join(
            f"{h['name']} ({h['per_sec']:g}/s) x{h['factor']:g}{' or more' if h.get('lower_bound') else ''}"
            if h.get("factor") is not None else f"{h['name']} ({h['per_sec']:g}/s) not reached"
            for h in real), ""]
    plateau = dx.get("plateau_vs_real") or []
    if plateau:
        lines += ["Diagnosis plateau against the real load: "
                  + "; ".join(f"{h['name']} x{h['factor']:g}" for h in plateau), ""]
    for name, secs in (current.get("recovery_secs") or {}).items():
        healthy = (current.get("time_to_healthy_secs") or {}).get(name)
        lines += [f"After {name}: healthy again in {'(not within the limit)' if healthy is None else f'{healthy:g} s'}, "
                  f"signing within the SLO in {'(not within the limit)' if secs is None else f'{secs:g} s'}"]
    if current.get("recovery_secs"):
        lines += [""]
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

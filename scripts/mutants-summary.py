#!/usr/bin/env python3
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
"""Summarise cargo-mutants results per source file, as JSON.

Usage: mutants-summary.py [--commit SHA] [--expect N] [--markdown FILE] OUTCOMES_JSON... > summary.json

Each OUTCOMES_JSON is a `mutants.out/outcomes.json` written by cargo-mutants (one per job of
.github/workflows/mutants.yml). The output schema is documented in docs/mutation-testing.md and
versioned by its "version" field; readers should refuse a version they do not know.

Only the standard library: the self-hosted runners have python3 and nothing else is installed.
"""

import argparse
import json
import sys

SCHEMA_VERSION = 1

# cargo-mutants' outcome summaries -> the counters of this report.
OUTCOMES = {
    "CaughtMutant": "caught",
    "MissedMutant": "missed",
    "Unviable": "unviable",
    "Timeout": "timeout",
}
COUNTERS = ("caught", "missed", "timeout", "unviable")


def empty():
    return {c: 0 for c in COUNTERS} | {"total": 0, "missed_mutants": []}


def mutant_name(m):
    """The mutant as cargo-mutants lists it: `file:line:col: replace … with …`."""
    if m.get("name"):
        return m["name"]
    span = m.get("span", {}).get("start", {})
    func = (m.get("function") or {}).get("function_name", "?")
    return f"{m['file']}:{span.get('line', '?')}:{span.get('column', '?')}: {m.get('replacement', '?')} in {func}"


def summarise(paths):
    modules = {}
    baseline_ok = True
    runs = 0
    # Outcomes that are no verdict on the tests (a broken build or test tool, a shape this script
    # does not know): counted, and the report is then not complete.
    unrecognised = 0
    # Runs that stopped before every mutant had a verdict (a job cut off by its time limit or
    # cancelled): their numbers are partial, and the report is then not complete.
    incomplete_runs = 0
    for path in paths:
        runs += 1
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        baselines = 0
        tested = 0
        for o in data.get("outcomes", []):
            scenario = o.get("scenario")
            summary = o.get("summary")
            if scenario == "Baseline":
                baselines += 1
                baseline_ok &= summary == "Success"
                continue
            mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
            counter = OUTCOMES.get(summary)
            if mutant is None or counter is None:
                print(f"warning: unrecognised outcome {scenario!r}: {summary!r} in {path}", file=sys.stderr)
                unrecognised += 1
                continue
            tested += 1
            mod = modules.setdefault(mutant["file"], empty())
            mod[counter] += 1
            mod["total"] += 1
            if counter == "missed":
                mod["missed_mutants"].append(mutant_name(mutant))
        # Each run has exactly one baseline (the workflow never skips it).
        baseline_ok &= baselines == 1
        if "total_mutants" in data and tested != data["total_mutants"]:
            print(f"warning: {path} has {tested} of {data['total_mutants']} mutants tested", file=sys.stderr)
            incomplete_runs += 1
    total = empty()
    del total["missed_mutants"]
    for mod in modules.values():
        mod["missed_mutants"].sort()
        for c in (*COUNTERS, "total"):
            total[c] += mod[c]
    return {
        "version": SCHEMA_VERSION,
        "runs": runs,
        "baseline_ok": baseline_ok,
        "unrecognised": unrecognised,
        "incomplete_runs": incomplete_runs,
        "modules": dict(sorted(modules.items())),
        "total": total,
    }


def markdown(report):
    lines = [
        "| Module | Caught | Missed | Timeout | Unviable | Total |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    rows = list(report["modules"].items()) + [("**total**", report["total"])]
    for name, m in rows:
        lines.append(
            f"| {name} | {m['caught']} | {m['missed']} | {m['timeout']} | {m['unviable']} | {m['total']} |"
        )
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--commit", default=None, help="the commit the mutants were generated from")
    p.add_argument("--expect", type=int, default=None, help="the number of runs (modules) expected")
    p.add_argument("--markdown", default=None, help="also write a Markdown table to this file")
    p.add_argument("outcomes", nargs="+")
    args = p.parse_args()
    report = summarise(args.outcomes)
    expected = args.expect if args.expect is not None else report["runs"]
    report = {
        "version": report.pop("version"),
        "commit": args.commit,
        "complete": report["runs"] == expected and report["baseline_ok"] and report["unrecognised"] == 0
        and report["incomplete_runs"] == 0,
    } | report
    json.dump(report, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    if args.markdown:
        with open(args.markdown, "a", encoding="utf-8") as f:
            f.write(markdown(report))


if __name__ == "__main__":
    main()

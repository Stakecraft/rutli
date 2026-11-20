#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Tests of scripts/perf/compare.py. Run: python3 scripts/perf/test_compare.py"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare  # noqa: E402


def run(steady_p95=20.0, steady_p99=30.0, server_p95=18.0, failed=(), rate=20, compare_latency=True, secs=60):
    scenario = {
        "name": "steady",
        "compare_latency": compare_latency,
        "loads": [
            {
                "command": "sign",
                "rate": rate,
                "clients": 4,
                "count": 0,
                "duration_secs": secs,
                "client": {"latency": {"count": 1200, "p95_ms": steady_p95, "p99_ms": steady_p99}},
                "server": {"sign_duration": {"count": 1200, "p95_ms": server_p95, "p99_ms": 24.0}},
            }
        ],
        "checks": [{"check": "every answer verifies", "ok": "steady" not in failed, "detail": "3 answers did not verify"}],
    }
    limit = {
        "name": "limit-rate",
        "compare_latency": False,
        "loads": [{"command": "sign", "client": {"latency": {"count": 150, "p95_ms": 900.0, "p99_ms": 950.0}}}],
        "checks": [],
    }
    return {
        "schema": 1,
        "kind": "load",
        "environment": "compose",
        "commit": "0123456789abcdef",
        "started_at": "2026-11-23T03:00:00Z",
        "scenarios": [scenario, limit],
        "failed": list(failed),
    }


class Compare(unittest.TestCase):
    def verdicts(self, previous, current, threshold=0.20, floor=2.0):
        rows, problems = compare.compare(previous, current, threshold, floor)
        return {(r[0], r[1]): r[5] for r in rows}, problems

    def test_equal_runs_pass(self):
        v, problems = self.verdicts(run(), run())
        self.assertEqual(problems, [])
        self.assertEqual(v[("steady", "client p95")], "ok")
        self.assertEqual(v[("steady", "cosigner p99")], "ok")
        # A limit test's latency is never compared.
        self.assertFalse(any(name == "limit-rate" for name, _ in v))

    def test_a_p95_more_than_20_percent_up_is_a_regression(self):
        v, problems = self.verdicts(run(steady_p95=20.0), run(steady_p95=24.1))
        self.assertEqual(v[("steady", "client p95")], "REGRESSION")
        self.assertEqual(v[("steady", "client p99")], "ok")
        self.assertEqual(len(problems), 1)
        # Exactly 20 % is not above the threshold.
        _, problems = self.verdicts(run(steady_p95=20.0), run(steady_p95=24.0))
        self.assertEqual(problems, [])
        # Faster is never a regression.
        _, problems = self.verdicts(run(steady_p95=20.0), run(steady_p95=5.0))
        self.assertEqual(problems, [])

    def test_the_cosigners_own_histogram_counts_too(self):
        v, problems = self.verdicts(run(server_p95=18.0), run(server_p95=40.0))
        self.assertEqual(v[("steady", "cosigner p95")], "REGRESSION")
        self.assertEqual(len(problems), 1)

    def test_a_difference_below_the_floor_is_noise(self):
        _, problems = self.verdicts(run(steady_p95=3.0), run(steady_p95=4.5))
        self.assertEqual(problems, [], "+50 % but 1.5 ms")
        _, problems = self.verdicts(run(steady_p95=3.0), run(steady_p95=4.5), floor=1.0)
        self.assertEqual(len(problems), 1)

    def test_a_failed_scenario_fails_without_any_previous_run(self):
        v, problems = self.verdicts(None, run(failed=("steady",)))
        self.assertEqual(len(problems), 1)
        self.assertIn("3 answers did not verify", problems[0])
        self.assertTrue(v[("steady", "check")].startswith("FAILED"))
        # And a clean first run passes, with its values listed.
        v, problems = self.verdicts(None, run())
        self.assertEqual(problems, [])
        self.assertEqual(v[("steady", "client p95")], "no previous value")

    def test_a_failed_setup_is_a_problem(self):
        current = run(failed=("setup",))
        current["setup"] = {"failed": "the cluster did not become healthy"}
        _, problems = self.verdicts(run(), current)
        self.assertEqual(problems, ["setup: the scenario ran: the cluster did not become healthy"])

    def test_another_load_is_not_compared(self):
        v, problems = self.verdicts(run(rate=20, steady_p95=20.0), run(rate=40, steady_p95=90.0))
        self.assertEqual(problems, [])
        self.assertEqual(v[("steady", "client p95")], "not compared: the load differs")
        # A release candidate's two hours against the weekly minute: not the same load either.
        v, problems = self.verdicts(run(secs=60, steady_p95=20.0), run(secs=7200, steady_p95=90.0))
        self.assertEqual(problems, [])
        self.assertEqual(v[("steady", "client p95")], "not compared: the load differs")

    def test_another_environment_is_not_compared(self):
        previous = run(steady_p95=1.0)
        previous["environment"] = "k8s"
        _, problems = self.verdicts(previous, run(steady_p95=90.0))
        self.assertEqual(problems, [])

    def test_the_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            prev, cur, md = (os.path.join(d, n) for n in ("prev.json", "cur.json", "report.md"))
            with open(prev, "w") as f:
                json.dump(run(steady_p99=30.0), f)
            with open(cur, "w") as f:
                json.dump(run(steady_p99=60.0), f)
            self.assertEqual(compare.main([prev, cur, "--markdown", md]), 1)
            with open(md) as f:
                self.assertIn("REGRESSION", f.read())
            self.assertEqual(compare.main([prev, prev]), 0)
            self.assertEqual(compare.main([os.path.join(d, "missing.json"), prev]), 0)
            self.assertEqual(compare.main([prev, os.path.join(d, "missing.json")]), 2)


if __name__ == "__main__":
    unittest.main()

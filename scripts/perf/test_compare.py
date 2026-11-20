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


def cluster_run(headroom=10, ramp_p99=50.0, keys_p99=30.0, list_ms=4.0, profile="placeholder", keys_ok=True):
    doc = run()
    doc["kind"] = "cluster"
    doc["profile"] = profile
    doc["headroom_factor"] = headroom
    steps = [{"factor": f, "passed": f <= headroom, "ops": {"sign": {"p99_ms": ramp_p99}}} for f in (1, 3, 10, 30)]
    doc["ramp"] = {"steps": [st for st in steps if st["factor"] <= headroom * 3], "headroom_factor": headroom}
    doc["keys"] = [{"count": 10, "passed": keys_ok, "sign": {"latency": {"p95_ms": keys_p99 * 0.8, "p99_ms": keys_p99}},
                    "list_keys": {"cosigner1": {"mean_ms": list_ms}, "cosigner2": {"mean_ms": 1.0}}}]
    doc["skipped"] = [{"name": "partition", "reason": "HOOK_PARTITION is not set"}]
    if not keys_ok:
        doc["failed"] = ["keys"]
        doc["keys"][0]["setup_failed"] = "DKG refused"
    return doc


class Cluster(unittest.TestCase):
    def verdicts(self, previous, current):
        rows, problems = compare.compare(previous, current, 0.20, 2.0)
        return {(r[0], r[1]): r[5] for r in rows}, problems

    def test_equal_runs_pass_and_list_the_skipped(self):
        v, problems = self.verdicts(cluster_run(), cluster_run())
        self.assertEqual(problems, [])
        self.assertEqual(v[("ramp", "headroom factor")], "ok")
        self.assertEqual(v[("ramp x10", "sign p99")], "ok")
        self.assertEqual(v[("keys 10", "list-keys mean (slowest)")], "ok")
        self.assertEqual(v[("partition", "skipped")], "HOOK_PARTITION is not set")

    def test_a_lower_headroom_factor_is_a_regression(self):
        _, problems = self.verdicts(cluster_run(headroom=30), cluster_run(headroom=10))
        self.assertEqual(problems, ["ramp: headroom factor 30 -> 10"])
        _, problems = self.verdicts(cluster_run(headroom=10), cluster_run(headroom=30))
        self.assertEqual(problems, [])

    def test_a_slower_step_or_key_count_is_a_regression(self):
        _, problems = self.verdicts(cluster_run(ramp_p99=50), cluster_run(ramp_p99=70))
        self.assertEqual(len(problems), 3, problems)  # x1, x3, x10
        _, problems = self.verdicts(cluster_run(list_ms=4.0), cluster_run(list_ms=9.0))
        self.assertEqual(len(problems), 1, problems)
        _, problems = self.verdicts(cluster_run(keys_p99=30), cluster_run(keys_p99=40))
        self.assertEqual(len(problems), 2, problems)  # p95 and p99, both +33 % and above the floor
        self.assertTrue(all(p.startswith("keys 10:") for p in problems))

    def test_another_profile_is_not_compared(self):
        _, problems = self.verdicts(cluster_run(headroom=100, profile="soak-2026-11"), cluster_run(headroom=1))
        self.assertEqual(problems, [])
        _, problems = self.verdicts(cluster_run(keys_p99=5, profile="soak-2026-11"), cluster_run(keys_p99=50))
        self.assertEqual(problems, [])

    def test_a_rig_failure_is_labelled_and_still_fails(self):
        current = run()
        current["scenarios"].append({"name": "ecies", "compare_latency": True, "loads": [{"failed": "x", "rig": True}],
                                     "checks": [{"check": "the load generator ran", "ok": False,
                                                 "detail": "the load generator exited 3", "rig": True}]})
        current["rig_failed"] = ["ecies"]
        v, problems = self.verdicts(None, current)
        self.assertEqual(problems, ["rig: ecies: the load generator ran: the load generator exited 3"])
        self.assertTrue(v[("ecies", "check")].startswith("RIG FAILED"))

    def test_another_client_deadline_policy_is_not_compared(self):
        previous = cluster_run(ramp_p99=5)
        current = cluster_run(ramp_p99=500)
        current["client_policy"] = {"attempt_timeout_secs": 5.0, "request_timeout_secs": 30.0}
        v, problems = self.verdicts(previous, current)
        self.assertEqual(problems, [])
        self.assertIn("client deadline policy", v[("(all)", "latency")])

    def test_a_diagnostic_run_is_never_a_baseline(self):
        previous = cluster_run(headroom=300, ramp_p99=5)
        previous["diagnostic"] = "tmpfs"
        v, problems = self.verdicts(previous, cluster_run(headroom=10, ramp_p99=500))
        self.assertEqual(problems, [])
        self.assertIn("never a baseline", v[("(all)", "latency")])
        current = cluster_run(headroom=1)
        current["diagnostic"] = "tmpfs"
        _, problems = self.verdicts(cluster_run(headroom=300), current)
        self.assertEqual(problems, [])

    def test_a_failed_key_count_fails_on_its_own(self):
        _, problems = self.verdicts(None, cluster_run(keys_ok=False))
        self.assertEqual(len(problems), 1)
        self.assertIn("DKG refused", problems[0])


class RigOrCluster(unittest.TestCase):
    def test_only_a_cluster_answer_is_the_clusters_failure(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import run
        cluster = [
            "rutli-loadgen: DKG of perf-t0-kc-0: FailedPrecondition: ceremony refused: cosigner 2 could not report",
            "rutli-loadgen: GroupKey of k: NotFound: unknown key",
            "rutli-loadgen: not healthy after 120 s: [\"cosigner2\"]",
            "rutli-loadgen: the cosigners do not agree on a cluster id (answers: [])",
        ]
        for line in cluster:
            self.assertFalse(run.rig_failure(2, "progress\n" + line), line)
        rig = [
            (2, "rutli-loadgen: cannot read /certs/ca.crt: No such file or directory"),
            (2, "error: unexpected argument '--bogus' found\n\nUsage: rutli-loadgen [OPTIONS]"),
            (101, "thread 'main' panicked at src/main.rs:1:1"),
            (3, "k8s_loadgen: could not start the load generator: error: connection reset by peer"),
            (1, "error: error reading from error stream: connection reset by peer"),
        ]
        for code, line in rig:
            self.assertTrue(run.rig_failure(code, line), line)


if __name__ == "__main__":
    unittest.main()

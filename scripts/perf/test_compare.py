#!/usr/bin/env python3
# Copyright 2026 StakeCraft LLC
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


class RealLoad(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    def test_a_profile_without_phases_is_one_phase_of_step_secs(self):
        import cluster
        ph = cluster.ramp_phases({"sign_per_sec": 2, "ecdh_per_sec": 0.5}, 300)
        self.assertEqual(ph, [{"name": "step", "sign_per_sec": 2.0, "ecdh_per_sec": 0.5, "secs": 300}])
        ph = cluster.ramp_phases({"phases": [{"name": "burst", "sign_per_sec": 2.3, "secs": 10}]}, 300)
        self.assertEqual(ph, [{"name": "burst", "sign_per_sec": 2.3, "ecdh_per_sec": 0.0, "secs": 10}])

    def test_headroom_against_each_measure(self):
        import cluster
        real = [{"name": "average", "per_sec": 0.063, "min_secs": 60},
                {"name": "busiest minute", "per_sec": 0.87, "min_secs": 60},
                {"name": "burst", "per_sec": 2.3, "min_secs": 0}]
        steps = []
        for f, burst_ok, minute_ok in [(10, True, True), (45, True, True), (70, False, True), (100, None, True),
                                       (150, None, False)]:
            phases = {"average": {"sign_per_sec": 0.063 * f, "secs": 120, "passed": True},
                      "busiest-minute": {"sign_per_sec": 0.87 * f, "secs": 60, "passed": minute_ok}}
            if burst_ok is not None:
                phases["burst"] = {"sign_per_sec": 2.3 * f, "secs": 10, "passed": burst_ok}
            steps.append({"factor": f, "phases": phases})
        h = {x["name"]: x for x in cluster.real_load_headroom(steps, real)}
        # The busiest minute passed at x100 (87/s): x1381 of the average, x100 of the minute.
        self.assertAlmostEqual(h["average"]["factor"], round(87.0 / 0.063, 1))
        self.assertEqual(h["busiest minute"]["factor"], 100.0)
        # The burst passed at x45 (103.5/s); a minute at 87/s is shorter in rate.
        self.assertEqual(h["burst"]["factor"], 45.0)
        self.assertNotIn("lower_bound", h["burst"])
        # Every measure saw a failing phase that stands for it (the minute at x150).
        self.assertNotIn("lower_bound", h["average"])

    def test_a_measure_never_failed_is_a_lower_bound(self):
        import cluster
        steps = [{"factor": 1, "phases": {"average": {"sign_per_sec": 0.063, "secs": 120, "passed": True}}}]
        h = cluster.real_load_headroom(steps, [{"name": "average", "per_sec": 0.063, "min_secs": 60}])
        self.assertEqual(h[0]["factor"], 1.0)
        self.assertTrue(h[0]["lower_bound"])
        h = cluster.real_load_headroom([], [{"name": "average", "per_sec": 0.063}])
        self.assertIsNone(h[0]["factor"])


class KeyClasses(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    def suite(self, profile):
        import cluster
        s = cluster.Suite.__new__(cluster.Suite)
        s.profile = profile
        return s

    def test_without_tenants_one_driver_on_the_suite_keys(self):
        s = self.suite({})
        self.assertEqual(s.tenants(), [{"name": "a", "cn": "driver", "prefix": "perf-"}])
        self.assertEqual(s.class_keys(s.tenants()[0]), {})

    def test_the_production_profile_names_what_k8s_deploy_limits(self):
        import json
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "profiles", "production.json")) as f:
            s = self.suite(json.load(f))
        keys = [s.class_keys(t) for t in s.tenants()]
        self.assertEqual(keys, [{"namespace": "perf-frost-namespace", "hosted": "perf-rutli-enc"},
                                {"namespace": "tenantb-frost-namespace", "hosted": "tenantb-rutli-enc"}])
        with open(os.path.join(here, "k8s-deploy.sh")) as f:
            deploy = f.read()
        # The namespace rate limits and the ACLs of the install match the profile's names.
        for t, k in zip(s.tenants(), keys):
            self.assertIn(f"key_id_prefix: {k['namespace']}, per_min: 10, per_day: 200", deploy)
            self.assertIn(f'{t["cn"]}: ["{t["prefix"]}"', deploy)


class SlowNode(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    def test_the_scenarios_are_ms_and_policy(self):
        import argparse

        import cluster
        self.assertEqual(cluster.parse_slow_node("2500:sticky, 6000:rotate"), [(2500, "sticky"), (6000, "rotate")])
        for bad in ("2500", "x:rotate", "0:rotate", "2500:random"):
            with self.assertRaises(argparse.ArgumentTypeError):
                cluster.parse_slow_node(bad)

    def test_node_shares_are_over_the_successful_signatures(self):
        import cluster
        load = {"client": {"ok": 300}, "server": {"targets": {
            "cosigner1": {"counters": {"rutli_sign_requests_total": 100.0, "rutli_sign_journal_entries_total": 200.0}},
            "cosigner2": {"counters": {"rutli_sign_requests_total{outcome=\"ok\"}": 100.0,
                                       "rutli_sign_journal_entries_total": 200.0}},
        }}}
        self.assertEqual(cluster.node_shares(load), {"cosigner1": {"led": 0.33, "took_part": 0.67},
                                                     "cosigner2": {"led": 0.33, "took_part": 0.67}})
        self.assertEqual(cluster.node_shares({"client": {"ok": 0}}), {})


class PeerCalls(unittest.TestCase):
    def test_the_generators_margin_is_kept_and_an_older_report_gets_one(self):
        new = {"sign_round1": {"count": 1e4, "p999_ms": 800.0, "deadline_ms": 2000.0, "within_third": 0.9985,
                               "margin_3x": False},
               "local_share": {"count": 1e4, "p999_ms": 9.0, "deadline_ms": None, "within_third": None,
                               "margin_3x": None}}
        m = compare.peer_margin(new)
        self.assertIs(m["sign_round1"]["margin_3x"], False)   # the generator's exact reading, not p99.9
        self.assertIsNone(m["local_share"]["margin_3x"])
        old = compare.peer_margin({"abort": {"count": 10, "p999_ms": 300.0}, "control": {"count": 10, "p999_ms": 1200.0}})
        self.assertEqual((old["abort"]["margin_3x"], old["abort"]["deadline_ms"]), (True, 1000.0))
        self.assertIs(old["control"]["margin_3x"], False)

    def test_a_miss_is_flagged_in_the_report_not_failed(self):
        calls = compare.peer_margin({"sign_round1": {"count": 1e4, "p50_ms": 30.0, "p99_ms": 400.0, "p999_ms": 800.0,
                                                     "deadline_ms": 2000.0, "within_third": 0.9985, "margin_3x": False}})
        import tempfile
        cur = cluster_run()
        cur["peer_calls"] = [{"where": "ramp x100 sign burst", "calls": calls}]
        with tempfile.TemporaryDirectory() as d:
            path, md_path = os.path.join(d, "cur.json"), os.path.join(d, "report.md")
            with open(path, "w") as f:
                json.dump(cur, f)
            rc = compare.main([os.path.join(d, "none.json"), path, "--markdown", md_path])
            with open(md_path) as f:
                md = f.read()
        self.assertIn("| ramp x100 sign burst | sign_round1 | 10000 |", md)
        self.assertIn("99.85%", md)
        self.assertIn("**NO**", md)
        self.assertIn("FLAG: 1 call(s) without a 3x margin", md)
        self.assertEqual(rc, 0)  # flagged, not failed
        self.assertIn("not measured", compare.peer_call_lines([])[0])

    def test_every_place_is_listed_in_run_order(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import cluster
        c = {"abort": {"margin_3x": True}}
        results = [{"name": "steady", "peer_calls": c}, {"name": "burst"}]
        ramp = {"steps": [{"factor": 3, "ops": {"sign average": {"peer_calls": c}, "ecdh average": {}}}]}
        diag = {"steps": [{"factor": 30, "ops": {"sign": {"peer_calls": c}}}]}
        self.assertEqual([e["where"] for e in cluster.peer_call_entries(results, ramp, diag)],
                         ["steady", "ramp x3 sign average", "diagnose x30 sign"])


class Placement(unittest.TestCase):
    def run_at(self, zones):
        run = cluster_run()
        run["placement"] = {f"rutli-cosigner-n{i + 1}-0": {"node": f"node{i}", "zone": z, "region": ""}
                            for i, z in enumerate(zones)}
        run["placement"]["rutli-perf-loadgen"] = {"node": "lg", "zone": zones[0], "region": ""}
        return run

    def test_runs_placed_differently_are_not_compared(self):
        before, now = self.run_at(["a", "b", "far"]), self.run_at(["a", "far", "b"])
        rows, _ = compare.compare(before, now, 0.20, 2.0)
        self.assertTrue(any("NOT COMPARED" in r[-1] and "a / b / far" in r[-1] for r in rows), rows)
        self.assertFalse(any("REGRESSION" in r[-1] for r in rows))

    def test_the_same_placement_compares_and_the_generator_does_not_count(self):
        before, now = self.run_at(["a", "b", "far"]), self.run_at(["a", "b", "far"])
        now["placement"]["rutli-perf-loadgen"]["zone"] = "elsewhere"
        rows, _ = compare.compare(before, now, 0.20, 2.0)
        self.assertFalse(any("NOT COMPARED" in r[-1] for r in rows), rows)
        self.assertEqual(compare.placement_text({}), "unrecorded")

    def test_a_cosigner_not_read_is_unrecorded_and_the_report_says_not_compared(self):
        before, now = self.run_at(["a", "b", "far"]), self.run_at(["a", "b", "far"])
        now["placement"]["rutli-cosigner-n2-0"] = {"node": "", "zone": "", "region": ""}
        self.assertIsNone(compare.placement_key(now))
        rows, problems = compare.compare(before, now, 0.20, 2.0)
        self.assertTrue(any("NOT COMPARED" in r[-1] and "unrecorded now" in r[-1] for r in rows), rows)
        self.assertEqual(problems, [])
        with tempfile.TemporaryDirectory() as d:
            prev, cur, md = (os.path.join(d, n) for n in ("prev.json", "cur.json", "report.md"))
            with open(prev, "w") as f:
                json.dump(before, f)
            with open(cur, "w") as f:
                json.dump(now, f)
            self.assertEqual(compare.main([prev, cur, "--markdown", md]), 0)
            with open(md) as f:
                report = f.read()
            self.assertIn("Latency NOT COMPARED", report)
            self.assertNotIn("No regression above", report)


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


class ConnectionContext(unittest.TestCase):
    def test_the_accept_path_and_messages_are_summarised(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import run

        class Fake:
            @staticmethod
            def generator_fd_limit():
                return 1024

        runner = run.Runner(Fake(), None)
        load = {
            "client": {"error_messages": {"UNKNOWN: transport error": 94, "CANCELLED: operation was canceled": 7}},
            "server": {
                "counters": {"rutli_grpc_handshake_timeouts_total": 12.0, "rutli_grpc_accept_errors_total": 1.0},
                "targets": {"cosigner1": {"gauges": {"rutli_grpc_connections": 2.0, "rutli_grpc_connection_limit": 768.0}}},
            },
        }
        line = runner.connection_context([load])
        self.assertIn("handshake timeouts 12", line)
        self.assertIn("accept errors 1", line)
        self.assertIn("'cosigner1': 768.0", line)
        self.assertIn("descriptors peak ? of 1024", line)
        self.assertIn("94 x UNKNOWN: transport error", line)
        self.assertIn("verdict: handshake timeouts 12 > 0", line)

    def test_the_verdict(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import run
        self.assertTrue(run.context_verdict(3, 0.0, 10, 1024).startswith("handshake timeouts 3 > 0"))
        self.assertIn("rig was strained", run.context_verdict(3, 0.4, 10, 1024))
        self.assertEqual(run.context_verdict(0, 0.4, 10, 1024), "the rig: generator throttled 40%")
        self.assertEqual(run.context_verdict(0, 0.0, 1000, "1024"), "the rig: generator descriptors 1000 of 1024")
        self.assertTrue(run.context_verdict(0, None, None, "?").startswith("undecided"))


if __name__ == "__main__":
    unittest.main()

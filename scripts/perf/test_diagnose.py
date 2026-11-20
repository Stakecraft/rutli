#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Tests of scripts/perf/diagnose.py. Run: python3 scripts/perf/test_diagnose.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diagnose  # noqa: E402

CGROUP = """== cpu.stat
usage_usec 1000000
user_usec 700000
system_usec 300000
nr_periods 50
nr_throttled 2
throttled_usec 20000
== cpu.pressure
some avg10=0.00 avg60=0.00 avg300=0.00 total=100000
full avg10=0.00 avg60=0.00 avg300=0.00 total=50000
== io.pressure
some avg10=1.00 avg60=0.50 avg300=0.10 total=200000
full avg10=0.50 avg60=0.20 avg300=0.05 total=150000
== memory.pressure
some avg10=0.00 avg60=0.00 avg300=0.00 total=0
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
== io.stat
259:0 rbytes=4096 wbytes=1048576 rios=1 wios=100 dbytes=0 dios=0
259:16 rbytes=0 wbytes=4096 rios=0 wios=1 dbytes=0 dios=0
== memory.current
26214400
== cpu.max
200000 100000
"""


def later(**more):
    text = CGROUP
    for old, new in more.items():
        text = text.replace(old, new)
    return text


class Cgroup(unittest.TestCase):
    def test_parse(self):
        c = diagnose.parse_cgroup(CGROUP)
        self.assertEqual(c["cpu_usage_usec"], 1_000_000)
        self.assertEqual(c["cpu_throttled_usec"], 20_000)
        self.assertEqual(c["cpu_some_usec"], 100_000)
        self.assertEqual((c["io_some_usec"], c["io_full_usec"]), (200_000, 150_000))
        self.assertEqual((c["io_wios"], c["io_wbytes"]), (101, 1_052_672))
        self.assertEqual(c["memory_bytes"], 26_214_400)
        self.assertEqual(c["cpu_quota_cores"], 2.0)

    def test_missing_files_and_no_limit(self):
        c = diagnose.parse_cgroup("== cpu.stat\nusage_usec 5\n== cpu.max\nmax 100000\n== io.stat\n")
        self.assertEqual(c, {"cpu_usage_usec": 5})
        self.assertEqual(diagnose.parse_cgroup(""), {})

    def test_derive(self):
        before = diagnose.parse_cgroup(CGROUP)
        after = diagnose.parse_cgroup(CGROUP.replace("usage_usec 1000000", "usage_usec 16000000")
                                      .replace("throttled_usec 20000", "throttled_usec 1020000")
                                      .replace("some avg10=1.00 avg60=0.50 avg300=0.10 total=200000",
                                               "some avg10=1.00 avg60=0.50 avg300=0.10 total=5200000")
                                      .replace("wios=100", "wios=1100"))
        d = diagnose.derive(before, after, 10.0)
        self.assertEqual(d["cpu_cores"], 1.5)            # 15 s of CPU in 10 s
        self.assertEqual(d["cpu_throttled_share"], 0.1)  # throttled 1 s of 10
        self.assertEqual(d["io_pressure_share"], 0.5)    # tasks waited on IO half the time
        self.assertEqual(d["writes_per_sec"], 100.0)
        self.assertEqual(d["memory_mib"], 25.0)
        self.assertEqual(d["cpu_quota_cores"], 2.0)
        self.assertEqual(diagnose.derive({}, {}, 10), {})


class Flush(unittest.TestCase):
    def test_dd_and_the_ceiling(self):
        dd = "100+0 records in\n100+0 records out\n409600 bytes (410 kB, 400 KiB) copied, 0.5 s, 819 kB/s\n"
        self.assertEqual(diagnose.parse_dd(dd), 5.0)
        self.assertIsNone(diagnose.parse_dd("dd: failed to open"))
        # 5 ms per flush, 3 per share: 66.7 shares/s per node; 3 nodes, 2 shares per signature.
        self.assertEqual(diagnose.predicted_ceiling(5.0), 100.0)
        self.assertIsNone(diagnose.predicted_ceiling(None))


class Verdicts(unittest.TestCase):
    def step(self, factor, offered, ok, p99=100, errors=0):
        return {"factor": factor, "offered_per_sec": offered, "ok_per_sec": ok, "server_p99_ms": p99, "errors_sent": errors}

    def test_knee(self):
        steps = [self.step(30, 30, 30), self.step(50, 50, 49.9), self.step(70, 70, 60)]
        self.assertEqual(diagnose.knee(steps, 1000), 70)       # achieved < 95 % of offered
        self.assertEqual(diagnose.knee([self.step(30, 30, 30, p99=1500)], 1000), 30)
        self.assertEqual(diagnose.knee([self.step(30, 30, 30, errors=1)], 1000), 30)
        self.assertIsNone(diagnose.knee(steps[:2], 1000))

    def test_generator_bound(self):
        calm = {"cosigner1": {"cpu_pressure_share": 0.01, "io_pressure_share": 0.0}}
        busy_gen = {"g1": {"cpu_cores": 3.9, "cpu_quota_cores": 4.0}}
        self.assertTrue(diagnose.generator_bound({"generators": busy_gen, "cosigners": calm}))
        self.assertTrue(diagnose.generator_bound({"generators": {}, "cosigners": calm, "not_sent": 10}))
        # Requests not sent while a cosigner waited on IO: the cluster, not the generator.
        stressed = {"cosigner1": {"cpu_pressure_share": 0.0, "io_pressure_share": 0.6}}
        self.assertFalse(diagnose.generator_bound({"generators": {}, "cosigners": stressed, "not_sent": 10}))
        self.assertFalse(diagnose.generator_bound({"generators": {"g1": {"cpu_cores": 1, "cpu_quota_cores": 4}},
                                                    "cosigners": calm}))

    def test_keys_verdict(self):
        self.assertIn("per-key lock", diagnose.keys_verdict([{"keys": 2, "ok_per_sec": 100}, {"keys": 200, "ok_per_sec": 300}]))
        self.assertIn("shared limit", diagnose.keys_verdict([{"keys": 2, "ok_per_sec": 100}, {"keys": 200, "ok_per_sec": 110}]))
        self.assertEqual(diagnose.keys_verdict([{"keys": 2, "ok_per_sec": 100}]), "inconclusive")

    def test_cpu_per_signature(self):
        cos = {"a": {"cpu_cores": 0.5}, "b": {"cpu_cores": 0.3}, "c": {"cpu_cores": 0.2}}
        self.assertEqual(diagnose.cpu_per_signature_ms(cos, 100), 10.0)
        self.assertIsNone(diagnose.cpu_per_signature_ms(cos, 0))


if __name__ == "__main__":
    unittest.main()

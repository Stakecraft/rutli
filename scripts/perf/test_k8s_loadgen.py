#!/usr/bin/env python3
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests of scripts/perf/k8s_loadgen.py against a fake kubectl that runs the pod's commands
locally, drops some connections, and a fake rutli-loadgen. No cluster is contacted.
Run: python3 scripts/perf/test_k8s_loadgen.py"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "k8s_loadgen.py")

FAKE_KUBECTL = r"""#!/bin/sh
# kubectl -n NS exec POD -- sh -c SCRIPT: runs SCRIPT here. Every call listed in $DROP (1-based)
# fails as a dropped API connection does.
n=$(($(cat "$STATE/calls" 2>/dev/null || echo 0) + 1)); echo "$n" > "$STATE/calls"
for d in $DROP; do
  if [ "$d" = "$n" ]; then echo "error: read tcp: connection reset by peer" >&2; exit 1; fi
done
shift 6   # -n NS exec POD -- sh
[ "$1" = "-c" ] || exit 99
sh -c "$2"; rc=$?
# Run, then lose the answer (call number in $STATE/drop_after).
if [ "$(cat "$STATE/drop_after" 2>/dev/null)" = "$n" ]; then echo "error: connection reset by peer" >&2; exit 1; fi
# Wipe the pod's files after the start, as a replaced pod would.
if [ -n "$WIPE" ] && [ "$n" = 1 ]; then sleep 0.2; rm -rf "$WIPE"/*; fi
exit $rc
"""

FAKE_LOADGEN = r"""#!/bin/sh
# Prints its arguments as JSON after a short pause; exits with $LG_EXIT.
echo run >> "$STATE/runs"
sleep 1
echo "loadgen progress line" >&2
printf '{"args": "%s"}\n' "$*"
exit "${LG_EXIT:-0}"
"""


class Helper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.bin, self.state, self.pod = (os.path.join(d, x) for x in ("bin", "state", "pod"))
        for x in (self.bin, self.state, self.pod):
            os.makedirs(x)
        for name, body in (("kubectl", FAKE_KUBECTL), ("rutli-loadgen", FAKE_LOADGEN)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_helper(self, drop="", lg_exit=0, extra=(), wipe_after_start=False):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", STATE=self.state, DROP=drop,
                   LG_EXIT=str(lg_exit), WIPE=self.pod if wipe_after_start else "")
        return subprocess.run([sys.executable, "-I", HELPER, "--namespace", "ns", "--poll-secs", "0.3",
                               "--dir", self.pod, *extra, "--", "sign", "--key", "k one"],
                              env=env, capture_output=True, text=True, timeout=120)

    def test_the_output_and_exit_code_are_the_load_generators(self):
        out = self.run_helper()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), {"args": "sign --key k one"})
        self.assertIn("loadgen progress line", out.stderr)
        self.assertEqual(os.listdir(self.pod), [], "the run's files are removed")

    def test_its_own_failure_code_is_passed_on(self):
        self.assertEqual(self.run_helper(lg_exit=2).returncode, 2)

    def test_dropped_connections_are_retried(self):
        # The start, a poll and the fetch of stdout each lose their first attempt.
        out = self.run_helper(drop="1 3 7")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout)["args"], "sign --key k one")

    def test_a_start_that_never_gets_through_is_the_rigs_failure(self):
        out = self.run_helper(drop="1 2 3 4 5")
        self.assertEqual(out.returncode, 3)
        self.assertIn("could not start", out.stderr)

    def test_a_start_retried_after_a_lost_answer_runs_once(self):
        # The first start goes through, but its answer is lost (the fake drops the call after
        # running it): the retry must not launch a second run.
        env_drop_after = os.path.join(self.state, "drop_after")
        with open(env_drop_after, "w") as f:
            f.write("1")
        out = self.run_helper()
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(self.state, "runs")) as f:
            self.assertEqual(f.read().count("run"), 1)

    def test_lost_run_files_fail_fast(self):
        out = self.run_helper(extra=("--max-secs", "60"), wipe_after_start=True)
        self.assertEqual(out.returncode, 3)
        self.assertIn("files are gone", out.stderr)

    def test_a_run_that_does_not_end_in_time_is_the_rigs_failure(self):
        out = self.run_helper(extra=("--max-secs", "0.2"))
        self.assertEqual(out.returncode, 3)
        self.assertIn("did not finish", out.stderr)


if __name__ == "__main__":
    unittest.main()

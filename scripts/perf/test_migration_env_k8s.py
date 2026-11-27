#!/usr/bin/env python3
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests of the client pod of scripts/e2e-migration-env-k8s.sh against a fake kubectl that records
every call. No cluster is contacted.

The operator's and the refresher's commands must run `rutli-cosigner` of the cosigners' release:
the cluster suite holds its ceremony on the previous release's cosigners, and a `verify-key
--sign-test` of another release may ask for a sign-test message they do not sign (issue #355).
Run: python3 scripts/perf/test_migration_env_k8s.py"""

import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_SCRIPT = os.path.join(HERE, "..", "e2e-migration-env-k8s.sh")

FAKE_KUBECTL = r"""#!/bin/bash
# Records the call (one line) and, for `apply -f -`, the manifest. Answers the reads the client pod
# functions make; everything else succeeds silently.
printf '%s\n' "$*" >> "$STATE/calls"
case "$*" in
  *"apply -f -"*) cat >> "$STATE/applied" ;;
  *"get pod rutli-cosigner-n1-0 "*".image}"*) printf '%s' "$COSIGNER_IMAGE" ;;
  *"get pod rutli-cosigner-n1-0 "*"{.spec.imagePullSecrets}"*) printf '%s' "$PULL_SECRETS" ;;
  *"get pod rutli-perf-client --ignore-not-found -o name"*)
    [ -z "$CLIENT_LEFT" ] || echo pod/rutli-perf-client
    [ -z "$GET_FAILS" ] || exit 1 ;;
esac
exit 0
"""

HARNESS = r"""
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
. "$1"
shift
"$@"
"""

RELEASE = "ghcr.io/example/rutli-cosigner:0.4.1@sha256:" + "ab" * 32


class ClientPod(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, "state")
        bindir = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.state)
        os.makedirs(bindir)
        kubectl = os.path.join(bindir, "kubectl")
        with open(kubectl, "w") as f:
            f.write(FAKE_KUBECTL)
        os.chmod(kubectl, 0o755)
        self.env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"], STATE=self.state,
                        RUTLI_NAMESPACE="ns1", COSIGNER_IMAGE=RELEASE, PULL_SECRETS="", CLIENT_LEFT="",
                        GET_FAILS="")
        # The load generator is of the build under test: nothing below may fall back to it.
        self.env.pop("E2E_CLIENT_SECRET", None)

    def tearDown(self):
        self.tmp.cleanup()

    def run_env(self, *call, **env):
        return subprocess.run(["bash", "-c", HARNESS, "harness", ENV_SCRIPT, *call], env=dict(self.env, **env),
                              capture_output=True, text=True, check=False)

    def read(self, name):
        path = os.path.join(self.state, name)
        if not os.path.exists(path):
            return ""
        with open(path) as f:
            return f.read()

    def test_the_client_pod_runs_the_image_of_the_cosigners(self):
        r = self.run_env("_client_up")
        self.assertEqual(r.returncode, 0, r.stderr)
        applied = self.read("applied")
        pod = applied.split("\n---\n")[1]
        self.assertIn("kind: Pod", pod)
        self.assertIn("name: rutli-perf-client", pod)
        self.assertIn(f'image: "{RELEASE}"', pod)
        self.assertEqual(pod.count("image:"), 1)
        self.assertIn('rutli.io/client: "true"', pod)
        self.assertIn("secretName: rutli-perf-driver", pod)
        self.assertIn("emptyDir: { medium: Memory", pod)
        self.assertIn("imagePullSecrets: []", pod)
        self.assertIn("kind: NetworkPolicy", applied.split("\n---\n")[0])
        calls = self.read("calls")
        self.assertIn("-n ns1 wait --for=condition=Ready pod/rutli-perf-client", calls)
        self.assertIn(RELEASE, r.stdout)

    def test_the_pull_secrets_of_the_cosigner_pod_are_carried(self):
        r = self.run_env("_client_up", PULL_SECRETS='[{"name":"regcred"}]', E2E_CLIENT_SECRET="other-certs")
        self.assertEqual(r.returncode, 0, r.stderr)
        applied = self.read("applied")
        self.assertIn('imagePullSecrets: [{"name":"regcred"}]', applied)
        self.assertIn("secretName: other-certs", applied)

    def test_no_image_on_the_cosigner_pod_stops_the_run(self):
        r = self.run_env("_client_up", COSIGNER_IMAGE="")
        self.assertEqual(r.returncode, 1)
        self.assertIn("names no image", r.stderr)
        self.assertEqual(self.read("applied"), "")

    def test_the_operator_and_the_refresher_run_in_the_client_pod(self):
        r = self.run_env("env_client", "operator", "verify-key", "--key-id", "k1", "--sign-test")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_env("env_client", "refresher", "refresh", "--key-id", "k1")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.read("calls").splitlines()
        self.assertEqual(calls, [
            "-n ns1 exec rutli-perf-client -- env RUST_LOG=off rutli-cosigner --config /tmp/e2e-operator.json "
            "verify-key --key-id k1 --sign-test",
            "-n ns1 exec rutli-perf-client -- env RUST_LOG=off rutli-cosigner --config /tmp/e2e-refresher.json "
            "refresh --key-id k1",
        ])

    def test_nothing_of_the_environment_runs_in_the_load_generator_pod(self):
        with open(ENV_SCRIPT) as f:
            script = f.read()
        self.assertNotIn("rutli-perf-loadgen", script)
        self.assertNotIn("LOADGEN_POD", script)

    def test_the_client_pod_goes_before_its_network_policy(self):
        r = self.run_env("_client_down")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.read("calls").splitlines()
        self.assertEqual(len(calls), 3)
        self.assertIn("delete pod rutli-perf-client --wait=true", calls[0])
        self.assertIn("get pod rutli-perf-client --ignore-not-found -o name", calls[1])
        self.assertIn("delete networkpolicy rutli-perf-client", calls[2])

    def test_a_client_pod_that_may_still_be_there_is_reported(self):
        for env in ({"CLIENT_LEFT": "1"}, {"GET_FAILS": "1"}):
            open(os.path.join(self.state, "calls"), "w").close()
            r = self.run_env("_client_down", **env)
            self.assertEqual(r.returncode, 1, env)
            self.assertNotIn("delete networkpolicy", self.read("calls"), env)


if __name__ == "__main__":
    unittest.main()

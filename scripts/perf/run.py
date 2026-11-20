#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Run the load scenarios against a running three-cosigner cluster and write one JSON file.

The cluster is brought up by the caller (scripts/perf-load.sh for Docker Compose); this script
drives `rutli-loadgen` through the scenarios, restarts cosigners where a scenario says so, reads
each cosigner's memory and open file descriptors before and after, and judges every scenario:

  steady          a fixed-rate stream of signatures
  burst           200 signatures asked for at the same moment
  clients         16 clients on two keys, each as fast as it gets answers
  ecies           a fixed-rate stream of EcdhDerive on a hosted ECIES key
  restart         the steady stream while one cosigner is killed and started again
  cold-cache      one cosigner restarted, then a burst of first signatures through it
  limit-rate      more signatures than a key's per-minute ceiling
  limit-ceremony  80 DKGs at once, 10 DKGs of one key at once, two refreshes back to back
  limit-decrypt   more EcdhDerive than the key's per-minute ceiling
  limit-sessions  1500 signatures of one key asked of one leader at the same moment
  recovery        a short stream of signatures after all of the above

A scenario fails when a request ends in a gRPC code the scenario does not allow, an answer does
not verify, a code it requires never appears (a limit test that hit no limit proves nothing), a
cosigner is unhealthy afterwards, or a cosigner's memory or file descriptors are out of bounds.
The exit code is 1 if any scenario failed, after the JSON is written.

Standard library only. Usage: see scripts/perf-load.sh, or `run.py --help`.
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time

NODES = ["cosigner1", "cosigner2", "cosigner3"]

# Keys of a run. `perf-limited` is the prefix scripts/perf-load.sh gives a sign rate limit of
# LIMITED_PER_MIN; every other key has none.
KEY_STEADY = "perf-steady"
KEY_SECOND = "perf-second"
KEY_LIMITED = "perf-limited-a"
KEY_ECIES = "rutli-perf-ecies"
LIMITED_PER_MIN = 120
THRESHOLD, CLUSTER_SIZE = 2, 3
# hosted_keys.decrypt_rate_limit_per_min of deploy/frost/config-tls: a bucket of one minute's worth.
DECRYPT_PER_MIN = 6000


# What rutli-loadgen prints when the cluster itself refused what a run needed: its error line
# carries the gRPC code of a cosigner's answer, or says the cosigners did not become healthy or
# agree on a cluster id. Any other failure (an unreadable file, a usage error, a panic, a lost
# connection to the pod) is the rig's.
CLUSTER_ANSWER = re.compile(
    r"rutli-loadgen: .*(\b(Cancelled|Unknown|InvalidArgument|DeadlineExceeded|NotFound|AlreadyExists|"
    r"PermissionDenied|ResourceExhausted|FailedPrecondition|Aborted|OutOfRange|Unimplemented|Internal|"
    r"Unavailable|DataLoss|Unauthenticated)\b|not healthy after|do not agree on a cluster id)")


def rig_failure(returncode, stderr):
    """Whether a failed rutli-loadgen run is the rig's failure rather than the cluster's."""
    return not (returncode == 2 and CLUSTER_ANSWER.search(stderr or ""))


def log(msg):
    print(f"[perf] {msg}", file=sys.stderr, flush=True)


class ComposeCluster:
    """Three cosigners under Docker Compose; the load generator runs as a container on their
    network, from the same image."""

    def __init__(self, env):
        self.compose = shlex.split(env["PERF_COMPOSE"])
        self.network = env["PERF_NETWORK"]
        self.image = env["PERF_IMAGE"]
        self.certs = env["PERF_CERTS"]
        self.uid = env.get("PERF_CERT_UID", "")
        self.kind = "compose"

    def _targets(self):
        args = []
        for i, node in enumerate(NODES, start=1):
            args += ["--target", f"{node}=https://{node}:910{i}"]
            args += ["--metrics", f"{node}=http://{node}:9200/metrics"]
        return args

    def loadgen_argv(self, args, timeout_secs):
        # The generator holds a connection per client and cosigner: far above Docker's default
        # descriptor limit in the limit-sessions scenario. The cosigners keep the default.
        argv = ["docker", "run", "--rm", "--label", "rutli-perf=loadgen", "--network", self.network,
                "--ulimit", "nofile=65536:65536"]
        if self.uid:
            argv += ["--user", self.uid]
        argv += ["-v", f"{self.certs}:/certs:ro", "--entrypoint", "rutli-loadgen", self.image]
        argv += ["--ca", "/certs/ca.crt", "--cert", "/certs/driver.crt", "--key", "/certs/driver.key"]
        argv += ["--timeout-secs", str(timeout_secs)]
        return argv + self._targets() + args

    def exec(self, node, shell):
        out = subprocess.run(
            self.compose + ["exec", "-T", node, "sh", "-c", shell],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return out.stdout if out.returncode == 0 else None

    def kill(self, node):
        subprocess.run(self.compose + ["kill", "-s", "SIGKILL", node], check=True, timeout=60, capture_output=True)

    def start(self, node):
        subprocess.run(self.compose + ["start", node], check=True, timeout=60, capture_output=True)

    def restart(self, node):
        subprocess.run(self.compose + ["restart", node], check=True, timeout=120, capture_output=True)


class Runner:
    def __init__(self, cluster, args):
        self.cluster = cluster
        self.args = args
        self.results = []

    # -- the load generator -------------------------------------------------------------------

    def loadgen_start(self, args, timeout_secs=30):
        argv = self.cluster.loadgen_argv(args, timeout_secs)
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def loadgen_finish(self, proc, wall_timeout):
        """The JSON report of a started load generator, or {"failed": why}. `"rig": True` marks a
        failure of the test rig (the load generator could not be run or reached, or never
        finished) rather than an answer of the cluster: rutli-loadgen itself exits 2 when the
        cluster refused what it needed (a DKG, a key) and says so (`rig_failure`); anything else
        is the rig's."""
        try:
            out, err = proc.communicate(timeout=wall_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            return {"failed": f"the load generator did not finish within {wall_timeout} s", "stderr": err[-2000:],
                    "rig": True}
        for line in err.splitlines():
            log(f"  {line}")
        if proc.returncode != 0:
            return {"failed": f"the load generator exited {proc.returncode}", "stderr": err[-2000:],
                    "rig": rig_failure(proc.returncode, err)}
        try:
            return json.loads(out) if out.strip() else {}
        except json.JSONDecodeError as e:
            return {"failed": f"the load generator's output is not JSON: {e}", "stdout": out[-2000:], "rig": True}

    def loadgen(self, args, timeout_secs=30, wall_timeout=600):
        return self.loadgen_finish(self.loadgen_start(args, timeout_secs), wall_timeout)

    def wait_healthy(self, within=120):
        return "failed" not in self.loadgen(["wait", "--within-secs", str(within)], wall_timeout=within + 60)

    # -- the cosigners' processes -------------------------------------------------------------

    def resources(self):
        """Per cosigner: resident memory now and at its peak (kB), open file descriptors, the
        soft limit on them, and when the process started (clock ticks since boot): a different
        start time is a process that died and was started again."""
        out = {}
        script = ("grep -E '^Vm(RSS|HWM):' /proc/1/status; echo fds: $(ls /proc/1/fd | wc -l); "
                  "echo started: $(cut -d' ' -f22 /proc/1/stat); "
                  "echo fd_limit: $(awk '/^Max open files/ {print $4}' /proc/1/limits)")
        names = {"VmRSS": "rss_kb", "VmHWM": "peak_rss_kb", "fds": "fds", "started": "started", "fd_limit": "fd_limit"}
        for node in NODES:
            text = self.cluster.exec(node, script)
            entry = {}
            for line in (text or "").splitlines():
                name, _, value = line.partition(":")
                number = value.split()[0] if value.split() else ""
                if number.isdigit():
                    entry[names.get(name, name)] = int(number)
            out[node] = entry
        return out

    # -- judging ------------------------------------------------------------------------------

    def scenario(self, name, body, allowed=(), required=(), compare_latency=False, restarted=()):
        """Run `body` (which returns the load generator's report or a list of them) and judge it.
        `allowed`: the codes a request may end in besides OK; a list of such tuples judges each
        of the body's loads by its own."""
        log(f"scenario {name}")
        before = self.resources()
        started = time.time()
        try:
            loads = body()
        except subprocess.SubprocessError as e:
            loads = {"failed": f"{type(e).__name__}: {e}"}
        loads = loads if isinstance(loads, list) else [loads]
        # Connections of the run are closed by now; give the cosigners a moment to notice.
        time.sleep(3)
        after = self.resources()

        checks = []

        def check(what, ok, detail="", rig=False):
            # rig: a failure of the test rig, not a finding about the cluster.
            checks.append({"check": what, "ok": bool(ok), "detail": detail, "rig": bool(rig)})

        per_load = bool(allowed) and isinstance(allowed[0], (tuple, list))
        errors, samples, bad, total_ok, unexpected = {}, {}, 0, 0, []
        for i, load in enumerate(loads):
            if "failed" in load:
                check("the load generator ran", False, load["failed"], rig=load.get("rig", False))
                continue
            client = load.get("client", {})
            total_ok += client.get("ok", 0)
            bad += client.get("bad_answers", 0)
            may = (allowed[i] if i < len(allowed) else ()) if per_load else allowed
            for code, n in client.get("errors", {}).items():
                errors[code] = errors.get(code, 0) + n
                if code not in may:
                    sample = client.get("error_samples", {}).get(code, "")[:160]
                    unexpected.append(f"{load.get('name') or name}: {n} x {code} ({sample})")
            samples.update(client.get("error_samples", {}))
            # A cosigner the scenario restarts is judged by how long it takes to be healthy again
            # (cluster.py records that), not by its health the moment the load ends.
            unhealthy = sorted(n for n, ok in load.get("health", {}).items() if not ok and n not in restarted)
            check("every cosigner is healthy afterwards", not unhealthy, ", ".join(unhealthy))
        check("no request ended in a code the scenario does not allow", not unexpected, "; ".join(unexpected))
        check("every answer verifies", bad == 0, f"{bad} answers did not verify: {samples.get('OK', '')[:160]}")
        for code in required:
            check(f"the limit was reached ({code} seen)", errors.get(code, 0) > 0, f"errors by code: {errors}")
        for node in NODES:
            b, a = before.get(node, {}), after.get(node, {})
            if "fds" not in a or "peak_rss_kb" not in a:
                check(f"{node}: process readable", False, "could not read /proc/1 in the container", rig=True)
                continue
            if node not in restarted:
                # A cosigner that died and came back passes every other check here with a fresh
                # process: its memory and descriptors start again from nothing.
                check(f"{node}: the process was not restarted",
                      "started" in b and b.get("started") == a.get("started"),
                      f"process start time {b.get('started')} before, {a.get('started')} after")
            peak_mib = a["peak_rss_kb"] / 1024
            check(
                f"{node}: peak resident memory within {self.args.max_rss_mib} MiB",
                peak_mib <= self.args.max_rss_mib,
                f"{peak_mib:.0f} MiB",
            )
            if node not in restarted and "fds" in b:
                grown = a["fds"] - b["fds"]
                check(
                    f"{node}: open file descriptors back within {self.args.max_fd_growth} of before",
                    grown <= self.args.max_fd_growth,
                    f"{b['fds']} before, {a['fds']} after",
                )

        result = {
            "name": name,
            "compare_latency": compare_latency,
            "allowed_codes": [sorted(x) for x in allowed] if per_load else sorted(allowed),
            "required_codes": sorted(required),
            "seconds": round(time.time() - started, 1),
            "ok": total_ok,
            "errors": errors,
            "loads": loads,
            "resources": {"before": before, "after": after},
            "checks": checks,
        }
        self.results.append(result)
        return result, check

    def close(self, result):
        result["passed"] = all(c["ok"] for c in result["checks"])
        failing = [c for c in result["checks"] if not c["ok"]]
        # Who failed: the cluster (a check about its behaviour), or only the rig.
        result["failed_by"] = None if not failing else ("rutli" if any(not c.get("rig") for c in failing) else "rig")
        for c in result["checks"]:
            if not c["ok"]:
                log(f"  FAILED: {c['check']}: {c['detail']}")
        log(f"  {'ok' if result['passed'] else 'FAILED'}: {result['ok']} ok, errors {result['errors']}")

    # -- the scenarios ------------------------------------------------------------------------

    def run(self):
        a = self.args
        sign_steady = ["sign", "--key", KEY_STEADY, "--rate", str(a.rate), "--clients", "4"]

        r, _ = self.scenario(
            "steady",
            lambda: self.loadgen(
                sign_steady + ["--name", "steady", "--duration-secs", str(a.steady_secs)],
                wall_timeout=a.steady_secs + 300,
            ),
            compare_latency=True,
        )
        self.close(r)

        r, _ = self.scenario(
            "burst",
            lambda: self.loadgen(
                ["sign", "--key", KEY_STEADY, "--name", "burst", "--count", "200", "--clients", "200"],
                timeout_secs=60,
            ),
            compare_latency=True,
        )
        self.close(r)

        clients_secs = max(30, min(600, a.steady_secs // 6))
        r, _ = self.scenario(
            "clients",
            lambda: self.loadgen(
                ["sign", "--key", KEY_STEADY, "--key", KEY_SECOND, "--name", "clients", "--clients", "16",
                 "--duration-secs", str(clients_secs)],
                wall_timeout=clients_secs + 300,
            ),
            compare_latency=True,
        )
        self.close(r)

        r, _ = self.scenario(
            "ecies",
            lambda: self.loadgen(
                ["ecdh", "--key", KEY_ECIES, "--name", "ecies", "--rate", "50", "--clients", "4", "--duration-secs", "30"]
            ),
            compare_latency=True,
        )
        self.close(r)

        def restart_under_load():
            proc = self.loadgen_start(
                ["sign", "--key", KEY_STEADY, "--name", "restart", "--rate", str(a.rate), "--clients", "6",
                 "--duration-secs", "40", "--restarted", "cosigner2"]
            )
            time.sleep(12)
            log("  killing cosigner2 (SIGKILL)")
            self.cluster.kill("cosigner2")
            time.sleep(4)
            log("  starting cosigner2")
            self.cluster.start("cosigner2")
            report = self.loadgen_finish(proc, 400)
            if not self.wait_healthy():
                return [report, {"failed": "cosigner2 did not become healthy again"}]
            return report

        # Every signature must still succeed: a client whose leader died asks the next cosigner
        # with the same intent, and a leader that lost a member signs with the other one.
        r, _ = self.scenario("restart", restart_under_load, restarted=("cosigner2",))
        self.close(r)

        def cold_cache():
            log("  restarting cosigner2")
            self.cluster.restart("cosigner2")
            if not self.wait_healthy():
                return {"failed": "cosigner2 did not become healthy after the restart"}
            # The first signatures after the restart, many at once, all led by the restarted node:
            # its first uses of the key race each other.
            return self.loadgen(
                ["sign", "--key", KEY_STEADY, "--name", "cold-cache", "--count", "300", "--clients", "100",
                 "--prefer", "cosigner2"],
                timeout_secs=60,
            )

        r, check = self.scenario("cold-cache", cold_cache, restarted=("cosigner2",))
        lost = sum(
            n
            for load in r["loads"]
            for series, n in load.get("server", {}).get("counters", {}).items()
            if series.startswith("rutli_sign_round2_unknown_session_total")
        )
        # A node that drops a session it opened moments ago has lost its nonces: the race fixed in
        # 0.5.0 (two first uses of a key after a restart each building their own signer).
        check("no cosigner lost a session between the rounds", lost == 0,
              f"rutli_sign_round2_unknown_session_total rose by {lost:g}")
        self.close(r)

        r, check = self.scenario(
            "limit-rate",
            lambda: self.loadgen(
                ["sign", "--key", KEY_LIMITED, "--name", "limit-rate", "--count", "400", "--clients", "8", "--no-failover"]
            ),
            allowed=("RESOURCE_EXHAUSTED",),
            required=("RESOURCE_EXHAUSTED",),
        )
        for load in r["loads"]:
            wall = load.get("client", {}).get("wall_seconds", 0)
            # Each signature is charged on the t nodes that signed it, and each node allows
            # LIMITED_PER_MIN per sliding minute.
            ceiling = (CLUSTER_SIZE * LIMITED_PER_MIN // THRESHOLD) * (1 + int(wall // 60))
            ok = load.get("client", {}).get("ok", 0)
            check(f"no more than {ceiling} signatures passed the {LIMITED_PER_MIN}/min ceiling", ok <= ceiling, f"{ok} ok")
            check(f"the first {LIMITED_PER_MIN} signatures were not refused", ok >= LIMITED_PER_MIN, f"{ok} ok")
        self.close(r)

        storm = f"perf-storm-{int(time.time())}"
        # What a busy or refusing node answers. ALREADY_EXISTS only where the key is contested.
        # INTERNAL too: a leader passes a member's ABORTED ("a dkg ceremony ... is already in
        # progress") on to the client as INTERNAL (seen on the first run, reported). The scenario
        # is about the nodes surviving the storm, not about that code.
        busy = ("UNAVAILABLE", "ABORTED", "FAILED_PRECONDITION", "RESOURCE_EXHAUSTED", "DEADLINE_EXCEEDED", "INTERNAL")
        ceremony_codes = [busy, busy + ("ALREADY_EXISTS",), ("FAILED_PRECONDITION", "ABORTED")]

        def ceremonies():
            return [
                # More DKGs at once than a node holds ceremony sessions (64).
                self.loadgen(["dkg", "--prefix", storm, "--name", "dkg-distinct", "--count", "80", "--clients", "80",
                              "--prefer", "cosigner1"], timeout_secs=120, wall_timeout=900),
                # One key, ten DKGs at once: whatever is answered OK must be the same key.
                self.loadgen(["dkg", "--prefix", f"{storm}-same", "--same-key", "--name", "dkg-same-key", "--count", "10",
                              "--clients", "10"], timeout_secs=120, wall_timeout=900),
                # A refresh right after a refresh: allowed or refused, never a broken key.
                self.loadgen(["refresh", "--key", KEY_SECOND, "--name", "refresh-twice", "--count", "2", "--clients", "1"],
                             timeout_secs=120, wall_timeout=900),
            ]

        r, check = self.scenario("limit-ceremony", ceremonies, allowed=ceremony_codes)
        if len(r["loads"]) == 3 and "failed" not in r["loads"][1]:
            check("a DKG of the contested key succeeded", r["loads"][1].get("client", {}).get("ok", 0) >= 1)
        if r["loads"] and "failed" not in r["loads"][0]:
            check("some of the 80 DKGs succeeded", r["loads"][0].get("client", {}).get("ok", 0) >= 1)
        self.close(r)

        r, check = self.scenario(
            "limit-decrypt",
            lambda: self.loadgen(
                ["ecdh", "--key", KEY_ECIES, "--name", "limit-decrypt", "--count", str(2 * DECRYPT_PER_MIN), "--clients", "64",
                 "--prefer", "cosigner1", "--no-failover"]
            ),
            allowed=("RESOURCE_EXHAUSTED",),
            required=("RESOURCE_EXHAUSTED",),
        )
        for load in r["loads"]:
            wall = load.get("client", {}).get("wall_seconds", 0)
            # A bucket of one minute's worth, refilled at the per-minute rate while the run lasts,
            # and already drawn on by the `ecies` scenario. 5 % for the edges of the refill.
            ceiling = int(DECRYPT_PER_MIN * (1 + wall / 60) * 1.05)
            ok = load.get("client", {}).get("ok", 0)
            check(f"no more than {ceiling} decryptions passed the {DECRYPT_PER_MIN}/min ceiling", ok <= ceiling, f"{ok} ok")
        self.close(r)

        # Far more signatures in flight on one key through one leader than a node keeps sessions
        # for: some are refused or time out, the nodes stay up and give their memory and
        # descriptors back.
        r, _ = self.scenario(
            "limit-sessions",
            lambda: self.loadgen(
                ["sign", "--key", KEY_STEADY, "--name", "limit-sessions", "--count", "1500", "--clients", "1500",
                 "--prefer", "cosigner1", "--no-failover"],
                timeout_secs=90, wall_timeout=900,
            ),
            allowed=("UNAVAILABLE", "DEADLINE_EXCEEDED", "ABORTED", "RESOURCE_EXHAUSTED"),
        )
        self.close(r)

        r, _ = self.scenario(
            "recovery",
            lambda: self.loadgen(
                ["sign", "--key", KEY_STEADY, "--key", KEY_SECOND, "--name", "recovery", "--rate", "10", "--clients", "3",
                 "--duration-secs", "15"]
            ),
        )
        self.close(r)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", choices=["compose"], default="compose")
    p.add_argument("--out", required=True, help="the JSON file to write")
    p.add_argument("--steady-secs", type=int, default=60,
                   help="length of the steady stream (default 60; hours for a release candidate)")
    p.add_argument("--rate", type=int, default=20, help="signatures per second of the steady stream (default 20)")
    p.add_argument("--max-rss-mib", type=int, default=512, help="bound on a cosigner's peak resident memory")
    p.add_argument("--max-fd-growth", type=int, default=64,
                   help="bound on how many more descriptors a cosigner holds after a scenario than before")
    p.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    args = p.parse_args()

    cluster = ComposeCluster(os.environ)
    runner = Runner(cluster, args)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    log("waiting for the cluster")
    setup = {"failed": "the cluster did not become healthy"}
    runner.setup_args = ["setup", "--frost-key", KEY_STEADY, "--frost-key", KEY_SECOND, "--frost-key", KEY_LIMITED,
                         "--ecies-key", KEY_ECIES]
    if runner.wait_healthy(300):
        setup = runner.loadgen(runner.setup_args, wall_timeout=600)
    runner.setup_report = setup
    if "failed" not in setup:
        runner.run()

    failed = [r["name"] for r in runner.results if r.get("failed_by") == "rutli"]
    rig_failed = [r["name"] for r in runner.results if r.get("failed_by") == "rig"]
    if "failed" in setup:
        (rig_failed if setup.get("rig") else failed).insert(0, "setup")
        log(f"setup FAILED: {setup['failed']}\n{setup.get('stderr', '')}")
    doc = {
        "schema": 1,
        "kind": "load",
        "environment": cluster.kind,
        "commit": args.commit,
        "started_at": started,
        "steady_secs": args.steady_secs,
        "rate": args.rate,
        "setup": setup,
        "scenarios": runner.results,
        "failed": failed,
        "rig_failed": rig_failed,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    log(f"wrote {args.out}")
    if rig_failed:
        log(f"RIG FAILED (no verdict on Rütli): {', '.join(rig_failed)}")
    if failed:
        log(f"FAILED scenarios: {', '.join(failed)}")
        return 1
    if rig_failed:
        return 3
    log("all scenarios passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

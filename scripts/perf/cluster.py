#!/usr/bin/env python3
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
"""The cluster suite: the load scenarios against Rütli on any Kubernetes cluster.

Bring a kubeconfig and a namespace; install with scripts/perf/k8s-deploy.sh, then

  cluster.py --namespace NS --profile scripts/perf/profiles/devnet-validator.json --out result.json \\
             [--suites upgrade,scenarios,connect,keys,ramp,disrupt] [--upgrade-image REF --work DIR]

writes one JSON file. scripts/perf/compare.py compares it with a previous one.

Suites:

  upgrade    helm upgrade from the previous release (installed with k8s-deploy.sh --previous) to
             --upgrade-image under a light stream of signatures; afterwards every key is there
             with its public key unchanged and signs.
  scenarios  the scenarios of scripts/perf/run.py: steady, burst, clients, ecies, a cosigner pod
             killed under load, cold cache, and the limits.
  disrupt    a cosigner's node lost, its data volume lost, a network partition between two
             cosigners' nodes, one cosigner cut off from both others, added network delay — each
             under the steady stream, through the
             provider hooks below. Without a hook, a node loss falls back to cordoning the node
             and deleting the pod; the other three are reported as skipped.
  connect    N new clients connecting at the same moment (50, 200, 500 by default), one
             signature each: connection time apart from the request, and connections the
             cosigners cut at their handshake deadline. A measurement, not a pass/fail test.
  keys       the key-count dimension: for each count of the profile, that many FROST keys and
             hosted keys (spread over ten tenant prefixes), sign latency over all of them, and how
             long each cosigner takes to list its hosted keys (Peer API ListKeys).
  ramp       the scale ramp: the profile's baseline load times each factor; a step runs the
             baseline's phases (average, busiest minute, burst) one after another. A phase over
             the SLO or with an error drops out of the later steps. The last factor at which every
             phase passed is the headroom factor, a top-level number; against each measure of the
             real load (`real` of the profile) the best rate that passed is a headroom of its own.

Provider hooks: executables named by environment variables, called with `start` and later `stop`
(stop always, even when the scenario failed), with KUBECONFIG and RUTLI_NAMESPACE set:

  HOOK_KILL_NODE     start|stop NODE            take the Kubernetes node down / bring it back
  HOOK_DETACH_VOLUME start|stop NODE NS/PVC     detach the volume behind the PVC / attach it again
  HOOK_PARTITION     start|stop NODE_A NODE_B   cut / restore the network between two nodes
  HOOK_NET_DELAY     start|stop MS NODE...      add / remove MS milliseconds of delay on the nodes

Load paths: `--load-path grpc` (default) drives the cosigners' Signer API directly, as the driver
does. `--load-path canton` is the entry point for load through a Canton participant with the
driver: set CANTON_LOAD_CMD to a command that takes the arguments of `rutli-loadgen ... sign`
and prints the same JSON report (frost/loadgen/src/main.rs, LoadReport); until such a command
exists the option refuses to run.

Standard library only.
"""

import argparse
import contextlib
import json
import math
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare
import diagnose  # noqa: E402  (the diagnostic pass's parsers and verdicts)
import run as base  # noqa: E402  (the compose suite: Runner, scenarios, key names)

NODES = base.NODES
DEALER_POD = "rutli-perf-dealer"  # scripts/e2e-migration-env-k8s.sh: one suite run per namespace
HERE = os.path.dirname(os.path.abspath(__file__))
# The driver's deadlines (#196): 5 s a sign attempt, 10 s an attempt of any other call, 30 s a
# call. The key-class spot checks use them whatever the run's own policy is.
DRIVER_DEADLINES = ["--sign-attempt-timeout-secs", "5", "--attempt-timeout-secs", "10", "--request-timeout-secs", "30"]

HOOKS = ("HOOK_KILL_NODE", "HOOK_DETACH_VOLUME", "HOOK_PARTITION", "HOOK_NET_DELAY")
log = base.log


class K8sCluster:
    """Three cosigners installed by scripts/perf/k8s-deploy.sh in one namespace; the load
    generator is the pod rutli-perf-loadgen there, driven with `kubectl exec`."""

    def __init__(self, namespace, kind, load_path, client_policy=None):
        self.ns = namespace
        self.kind = kind
        self.load_path = load_path
        # The load generator's deadline policy for calls that fail over: flags added to every run.
        self.client_flags = []
        for flag, value in (client_policy or {}).items():
            if value is not None:
                self.client_flags += [f"--{flag.replace('_', '-')}", value if isinstance(value, str) else f"{value:g}"]

    @staticmethod
    def pod(node):
        return f"rutli-cosigner-n{NODES.index(node) + 1}-0"

    def kubectl(self, *args, timeout=300, check=True, namespaced=True):
        argv = ["kubectl"] + (["-n", self.ns] if namespaced else []) + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=check)

    def loadgen_argv(self, args, timeout_secs, pod="rutli-perf-loadgen", cn=None, flags=None):
        if self.load_path == "canton" and args and args[0] == "sign" and cn is None and flags is None:
            # The entry point for load through a participant (see the module docs). Not for a load
            # that names its certificate or deadlines (a tenant's, the key-class spot checks).
            return shlex.split(os.environ["CANTON_LOAD_CMD"]) + args
        # Run detached in the pod and fetched afterwards (k8s_loadgen.py): a stream held open
        # through the API server for a whole run was reset on a real cluster.
        # `cn`: the client certificate (the secret holds one per tenant's driver, the operator's
        # and the refresher's); `flags`: a deadline policy that replaces the run's own.
        cn = cn or "driver"
        argv = [sys.executable, "-I", os.path.join(HERE, "k8s_loadgen.py"), "--namespace", self.ns, "--pod", pod, "--",
                "--ca", "/certs/ca.crt", "--cert", f"/certs/{cn}.crt", "--key", f"/certs/{cn}.key",
                "--timeout-secs", str(timeout_secs)] + (self.client_flags if flags is None else list(flags))
        for i, node in enumerate(NODES, start=1):
            # gRPC through the per-node Service; metrics through the pod's name behind the headless
            # Service, which the per-node Service does not expose.
            argv += ["--target", f"{node}=https://rutli-node-{i}.{self.ns}.svc:9101"]
            argv += ["--metrics", f"{node}=http://{self.pod(node)}.rutli-cosigner.{self.ns}.svc:9200/metrics"]
        return argv + args

    def exec(self, node, shell):
        out = self.kubectl("exec", self.pod(node), "-c", "cosigner", "--", "sh", "-c", shell, timeout=30, check=False)
        return out.stdout if out.returncode == 0 else None

    def generator_cgroup(self, script):
        """`script` (diagnose.CGROUP_SCRIPT) in the first load generator pod; its output or None."""
        out = self.kubectl("exec", "rutli-perf-loadgen", "--", "sh", "-c", script, timeout=30, check=False)
        return out.stdout if out.returncode == 0 else None

    def generator_fd_limit(self):
        """The soft descriptor limit a load generator run gets in its pod, or "?"."""
        out = self.kubectl("exec", "rutli-perf-loadgen", "--", "sh", "-c", "ulimit -n", timeout=30, check=False)
        return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else "?"

    def kill(self, node):
        self.kubectl("delete", "pod", self.pod(node), "--grace-period=0", "--force", "--wait=false")

    def start(self, node, within=600):
        """Wait until the cosigner's pod is back and ready. Not `rollout status`: the chart's per-node
        StatefulSets use updateStrategy OnDelete, which that command refuses."""
        pod = self.pod(node)
        deadline = time.time() + within
        while True:
            r = self.kubectl("wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=10s", timeout=40, check=False)
            if r.returncode == 0:
                return
            if time.time() > deadline:
                raise RuntimeError(f"{pod} was not ready within {within}s: {r.stderr.strip()[-300:]}")
            time.sleep(2)

    def restart(self, node):
        self.kubectl("delete", "pod", self.pod(node), timeout=180)
        self.start(node)

    def node_of(self, node):
        return self.kubectl("get", "pod", self.pod(node), "-o", "jsonpath={.spec.nodeName}").stdout.strip()

    def pvc_of(self, node):
        return f"{self.ns}/data-{self.pod(node)[: -len('-0')]}"


def peer_call_entries(results, ramp, diagnosis):
    """Every place the run read the cosigners' peer calls (#249): each scenario, each ramp step's
    phase and each diagnosis step, as [{"where", "calls"}] in run order."""
    out = [{"where": r["name"], "calls": r["peer_calls"]} for r in results if r.get("peer_calls")]
    for st in (ramp or {}).get("steps", []):
        for op, o in st.get("ops", {}).items():
            if o.get("peer_calls"):
                out.append({"where": f"ramp x{st['factor']:g} {op}", "calls": o["peer_calls"]})
    for st in (diagnosis or {}).get("steps", []):
        for op, o in st.get("ops", {}).items():
            if o.get("peer_calls"):
                out.append({"where": f"diagnose x{st['factor']:g} {op}", "calls": o["peer_calls"]})
    return out


def node_shares(load):
    """Per cosigner, from one load's server readings: the share of the successful signatures it
    led (rutli_sign_requests_total) and took part in (rutli_sign_journal_entries_total: one entry
    per share released). Rounded to 0.01; {} without readings."""
    ok = load.get("client", {}).get("ok", 0)
    out = {}
    for node, t in (load.get("server", {}).get("targets") or {}).items():
        counters = t.get("counters", {})
        led = sum(v for k, v in counters.items() if k.split("{")[0] == "rutli_sign_requests_total")
        part = sum(v for k, v in counters.items() if k.split("{")[0] == "rutli_sign_journal_entries_total")
        if ok:
            out[node] = {"led": round(led / ok, 2), "took_part": round(part / ok, 2)}
    return out


def parse_slow_node(text):
    """`--slow-node`: comma-separated ms:policy pairs (policy sticky or rotate)."""
    out = []
    for item in [x.strip() for x in text.split(",") if x.strip()]:
        ms, _, policy = item.partition(":")
        if not ms.isdigit() or int(ms) <= 0 or policy not in ("sticky", "rotate"):
            raise argparse.ArgumentTypeError(f"--slow-node: {item!r} is not <ms>:sticky|rotate")
        out.append((int(ms), policy))
    return out


def ramp_phases(base_mix, step_secs):
    """The phases of one ramp step at x1: the baseline's `phases` (each a name, its rates and
    seconds), or one phase of `step_secs` with the baseline's own rates."""
    if base_mix.get("phases"):
        return [{"name": ph["name"], "sign_per_sec": float(ph.get("sign_per_sec", 0)),
                 "ecdh_per_sec": float(ph.get("ecdh_per_sec", 0)), "secs": int(ph["secs"])}
                for ph in base_mix["phases"]]
    return [{"name": "step", "sign_per_sec": float(base_mix.get("sign_per_sec", 0)),
             "ecdh_per_sec": float(base_mix.get("ecdh_per_sec", 0)), "secs": int(step_secs)}]


def real_load_headroom(steps, real):
    """Headroom against each measure of the real load (`real` of the profile: name, per_sec, and
    min_secs, the shortest phase that may stand for it: a busiest minute needs a phase of a minute
    or more, a burst does not). The factor is the highest signing rate that passed in such a phase
    over the measure's rate; `lower_bound` when no such phase ever failed (the ramp ended first)."""
    out = []
    for m in real:
        passed, failed = [], False
        for st in steps:
            for r in st.get("phases", {}).values():
                if r.get("secs", 0) < int(m.get("min_secs", 0)) or r.get("rig_failed"):
                    continue
                if r.get("passed"):
                    passed.append(r.get("sign_per_sec", 0))
                else:
                    failed = True
        best = max(passed, default=None)
        entry = {"name": m["name"], "per_sec": m["per_sec"], "best_passed_per_sec": best,
                 "factor": round(best / float(m["per_sec"]), 1) if best else None}
        if best and not failed:
            entry["lower_bound"] = True
        out.append(entry)
    return out


class Suite(base.Runner):
    def __init__(self, cluster, args, profile):
        super().__init__(cluster, args)
        self.profile = profile
        self.skipped = []
        self.ramp = None
        self.keys = None
        self.spot_checks = []
        self.imported_key = None

    # -- tenants and key classes ---------------------------------------------------------------

    def tenants(self):
        """The profile's tenants: a driver certificate (cn) and the key prefix its ACL allows.
        Without `tenants`, one: the driver, on the suite's own `perf-` keys."""
        return self.profile.get("tenants") or [{"name": "a", "cn": "driver", "prefix": "perf-"}]

    def class_keys(self, tenant):
        """The tenant's namespace-class and hosted-class key ids (those the profile has). After the
        migration suite, the first tenant's namespace-class key is the key it imported."""
        classes = self.profile.get("classes") or {}
        keys = {c: tenant["prefix"] + classes[c]["key"] for c in ("namespace", "hosted") if c in classes}
        imported = getattr(self, "imported_key", None)
        if imported and tenant["name"] == self.tenants()[0]["name"] and "namespace" in keys:
            keys["namespace"] = imported
        return keys

    # -- migration -----------------------------------------------------------------------------

    def migration(self):
        """docs/migration.md's cosigner half on this cluster, first: an existing Canton namespace key
        (B1's Canton 3.6.1 test export) brought in by the split ceremony, as scripts/e2e-migration.sh
        runs it (E2E_ENV=k8s E2E_STAGES=ceremony: recipient requests and SAS, the dealer in a pod of
        its own, dry run, install, verify-key --sign-test, refresh with the refresher, founding
        backups, the destruction checks). The imported key then is the first tenant's
        namespace-class key for every later suite. A new key prefix per run: imported ids are never
        deleted."""
        a = self.args
        image = a.dealer_image or self.cluster.kubectl(
            "get", "pod", "rutli-perf-loadgen", "-o", "jsonpath={.spec.containers[0].image}").stdout.strip()
        prefix = f"perf-mig{int(time.time())}-"
        result_path = os.path.join(a.work, f"migration-{prefix.rstrip('-')}.json")
        stage = {}

        # The script's local work dir (the export, the dealer's output) is made here, so that this
        # side can remove it even when the script was killed before its own cleanup.
        scratch = tempfile.mkdtemp(prefix="rutli-e2e-migration-k8s.")

        def remove_leftovers():
            """Whatever happened to the script, once: the local work dir, the ceremony's files in the
            cosigners' /tmp (bundles, founding backups), the dealer pod (and the memory-backed work
            dir it holds), then its NetworkPolicy once the API confirms the pod is gone. Each call in
            a session of its own, so that a signal to this process group cannot cut it short."""
            shutil.rmtree(scratch, ignore_errors=True)
            argv = ["kubectl", "-n", self.cluster.ns]
            for n in NODES:
                try:
                    rm = subprocess.run(argv + ["exec", self.cluster.pod(n), "-c", "cosigner", "--", "sh", "-c",
                                                "rm -rf /tmp/r[0-9].json /tmp/share-*.json /tmp/backup-founding-node*"],
                                        capture_output=True, timeout=60, start_new_session=True, check=False)
                    removed = rm.returncode == 0
                except subprocess.TimeoutExpired:
                    removed = False
                if not removed:
                    log(f"  WARNING: the ceremony's files in {n}'s /tmp could not be removed. Remove them by hand.")
            try:
                subprocess.run(argv + ["delete", "pod", DEALER_POD, "--wait=true", "--timeout=120s",
                                       "--ignore-not-found"], capture_output=True, timeout=180, start_new_session=True, check=False)
                left = subprocess.run(argv + ["get", "pod", DEALER_POD, "--ignore-not-found", "-o", "name"],
                                      capture_output=True, text=True, timeout=60, start_new_session=True, check=False)
                if left.returncode == 0 and not left.stdout.strip():
                    subprocess.run(argv + ["delete", "networkpolicy", DEALER_POD, "--ignore-not-found"],
                                   capture_output=True, timeout=60, start_new_session=True, check=False)
                    return
            except subprocess.TimeoutExpired:
                pass
            log(f"  WARNING: the dealer pod {DEALER_POD} may still be there (it stops at its 30-minute deadline). "
                "Delete it and its NetworkPolicy by hand.")

        def body():
            env = dict(os.environ, E2E_ENV="k8s", E2E_STAGES="ceremony", E2E_PREFIX=prefix,
                       RUTLI_NAMESPACE=self.cluster.ns, E2E_CERTS=os.path.join(a.work, "certs"),
                       E2E_DEALER_IMAGE=image, E2E_RESULT=result_path, E2E_SCRATCH=scratch)
            # Set either way: an inherited E2E_ALLOW_UNISOLATED_DEALER must not decide it, nor an
            # inherited KEEP keep the export on disk.
            env["E2E_ALLOW_UNISOLATED_DEALER"] = "1" if a.allow_unisolated_dealer else "0"
            env["KEEP"] = "0"
            started = time.time()
            proc = subprocess.Popen(["bash", os.path.join(HERE, "..", "e2e-migration.sh")], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    start_new_session=True)
            try:
                stdout, stderr = proc.communicate(timeout=1800)
                out = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
            except BaseException as e:
                # A timeout, Ctrl-C or any other error: SIGTERM to the script's group, so that its EXIT
                # trap cleans up (work dir, dealer pod, the pods' files); SIGKILL after 5 minutes.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
                except ProcessLookupError:
                    pass
                if not isinstance(e, subprocess.TimeoutExpired):
                    raise
                return [{"failed": "the split ceremony on the cluster did not finish within 30 minutes"}]
            finally:
                remove_leftovers()
            stage.update({"seconds": round(time.time() - started, 1), "dealer_image": image,
                          "steps": [line[4:] for line in out.stdout.splitlines() if line.startswith("==> ")]})
            for line in out.stdout.splitlines():
                if line.startswith("==> "):
                    log(f"  {line[4:]}")
            if out.returncode != 0:
                # The step it failed in and its exit code, never the script's output: nothing a
                # command printed reaches cluster.json or the log. To see it, run the script by hand
                # (docs/cluster-suite.md).
                last = stage["steps"][-1] if stage["steps"] else "before the first step"
                return [{"failed": f"the split ceremony on the cluster failed in: {last} (exit {out.returncode})"}]
            with open(result_path) as f:
                stage.update(json.load(f))
            self.imported_key = stage["key_id"]
            # The Signer API with the imported key, under the driver's deadlines: the key-class spot
            # checks when the profile has classes (the imported key is the first tenant's namespace
            # key now), else one signature with it.
            loads = self.spots("migration")
            if not any(load.get("name", "").startswith("namespace-") for load in loads):
                loads.append(self.loadgen(["sign", "--key", stage["key_id"], "--name", "migration-sign", "--count", "1",
                                           "--clients", "1"], timeout_secs=10, wall_timeout=300, flags=DRIVER_DEADLINES))
            return loads

        r, _ = self.scenario("migration", body)
        r["migration"] = stage
        if stage.get("key_id"):
            log(f"  imported {stage['key_id']} (fingerprint {stage.get('fingerprint')}); "
                f"the first tenant's namespace-class key from here on")
        self.close(r)

    def setup_classes(self):
        """Every tenant's keys besides the suite's own: its namespace-class FROST key and its
        hosted encryption key, made with that tenant's certificate. {} when all went well."""
        for t in self.tenants():
            keys = self.class_keys(t)
            args = ["setup"]
            if "namespace" in keys:
                args += ["--frost-key", keys["namespace"]]
            if "hosted" in keys:
                args += ["--ecies-key", keys["hosted"]]
            if t["cn"] != "driver":
                # The second tenant's own signing key, for the ramp.
                args += ["--frost-key", f"{t['prefix']}steady"]
            if len(args) == 1:
                continue
            r = self.setup_keys(args, wall_timeout=900, cn=t["cn"])
            if "failed" in r:
                return {"failed": f"tenant {t['name']}: {r['failed']}", "rig": bool(r.get("rig"))}
        return {}

    def spots(self, during):
        """One signature with each tenant's namespace-class key and one decryption (ECDH) with
        its hosted key, under the driver's deadlines (5 s a sign attempt, 10 s another call, 30 s a
        call). Returns their reports, judged by the scenario that runs them: every one must
        succeed. Their health readings are dropped: a disruption in progress is not the question."""
        loads = []
        for t in self.tenants():
            for cls, key in self.class_keys(t).items():
                op = "sign" if cls == "namespace" else "ecdh"
                r = self.loadgen([op, "--key", key, "--name", f"{cls}-{during}-{t['name']}", "--count", "1",
                                  "--clients", "1"], timeout_secs=10, wall_timeout=300, cn=t["cn"],
                                 flags=DRIVER_DEADLINES)
                r.pop("health", None)
                client = r.get("client", {})
                spot = {"during": during, "tenant": t["name"], "class": cls, "ok": client.get("ok", 0) == 1,
                        "errors": client.get("errors", {}), "ms": (client.get("latency") or {}).get("max_ms"),
                        "failed": r.get("failed")}
                self.spot_checks.append(spot)
                took = "" if spot["ms"] is None else f" in {spot['ms']:g} ms"
                verdict = "ok" if spot["ok"] else f"FAILED {spot['errors'] or spot['failed']}"
                log(f"  {cls} key of tenant {t['name']} during {during}: {verdict}{took}")
                loads.append(r)
        return loads

    def wait_for_a_restart(self, within):
        """True as soon as some cosigner pod is missing or not Ready; False after `within` s."""
        end = time.time() + within
        while time.time() < end:
            for node in NODES:
                out = self.cluster.kubectl("get", "pod", self.cluster.pod(node), "-o",
                                           'jsonpath={.status.conditions[?(@.type=="Ready")].status}',
                                           timeout=30, check=False)
                if out.returncode != 0 or out.stdout.strip() != "True":
                    return True
            time.sleep(2)
        return False

    def key_classes(self):
        """The key classes at rest: one spot check of each, then the namespace-class rate limit:
        twice its per-minute budget plus five, at once, on the first tenant's namespace key. Each
        signature is charged on the two nodes that made it, so between the budget and one and a
        half times it pass; the rest must be RESOURCE_EXHAUSTED."""
        classes = self.profile.get("classes") or {}
        if not classes:
            return
        n_spots = sum(len(self.class_keys(t)) for t in self.tenants())
        ns = classes.get("namespace")
        limit = int(ns.get("per_min", 10)) if ns else 0
        t0 = self.tenants()[0]

        def body():
            loads = self.spots("quiet")
            if ns:
                # A fresh minute: the spot signature above must not count against the burst.
                time.sleep(61)
                loads.append(self.loadgen(["sign", "--key", self.class_keys(t0)["namespace"], "--name",
                                           "namespace-rate-limit", "--count", str(2 * limit + 5), "--clients", "5"],
                                          timeout_secs=10, wall_timeout=600, cn=t0["cn"], flags=DRIVER_DEADLINES))
            return loads

        allowed = [()] * n_spots + ([("RESOURCE_EXHAUSTED",)] if ns else [])
        r, check = self.scenario("key-classes", body, allowed=allowed)
        if ns and len(r["loads"]) == n_spots + 1 and "failed" not in r["loads"][-1]:
            client = r["loads"][-1].get("client", {})
            ok, refused = client.get("ok", 0), client.get("errors", {}).get("RESOURCE_EXHAUSTED", 0)
            ceiling = limit + limit // 2
            check(f"the namespace rate limit ({limit}/min) let {limit} to {ceiling} signatures through",
                  limit <= ok <= ceiling, f"{ok} ok")
            check("the namespace rate limit refused the rest with RESOURCE_EXHAUSTED", refused > 0 and ok + refused == 2 * limit + 5,
                  f"{refused} refused of {2 * limit + 5}")
        self.close(r)

    # -- hooks ---------------------------------------------------------------------------------

    def hook(self, name, action, *args):
        cmd = os.environ.get(name)
        env = dict(os.environ, RUTLI_NAMESPACE=self.cluster.ns)
        log(f"  {name} {action} {' '.join(args)}")
        out = subprocess.run(shlex.split(cmd) + [action, *args], env=env, capture_output=True, text=True,
                             timeout=900, check=False)
        if out.returncode != 0:
            raise subprocess.SubprocessError(f"{name} {action} exited {out.returncode}: {out.stderr.strip()[-500:]}")

    def skip(self, name, why):
        log(f"scenario {name}: skipped ({why})")
        self.skipped.append({"name": name, "reason": why})

    # -- upgrade -------------------------------------------------------------------------------

    def upgrade(self):
        """helm upgrade from the previous release with live keys and a light stream of signatures.
        k8s-deploy.sh upgrade runs helm upgrade, then scripts/upgrade-cosigners.sh, which restarts the
        cosigners one at a time: with 2 of 3 up there is always a quorum, so NO signature may fail.
        Afterwards every key is there with the same public key, and signs."""
        a = self.args
        before = self.setup_report

        def body():
            proc = self.loadgen_start(
                ["sign", "--key", base.KEY_STEADY, "--name", "upgrade", "--rate", "5", "--clients", "3",
                 "--duration-secs", "360"] + [x for n in NODES for x in ("--restarted", n)]
            )
            # The key classes during the rollout: a topology change or a decryption while
            # cosigners restart one at a time is the case that matters.
            spot_loads = []

            def spot_during_rollout():
                # As soon as a cosigner is seen not ready (the rollout restarts them one at a
                # time); after five minutes without one, anyway, and the log says so.
                seen = self.wait_for_a_restart(300)
                if not seen:
                    log("  no cosigner seen restarting within 300 s: the key-class checks run anyway")
                spot_loads.extend(self.spots("upgrade" if seen else "upgrade-unseen"))

            spotter = threading.Thread(target=spot_during_rollout)
            spotter.start()
            time.sleep(10)
            log(f"  helm upgrade to {a.upgrade_image}")
            argv = [os.path.join(HERE, "k8s-deploy.sh"), "upgrade", "--namespace", self.cluster.ns,
                    "--image", a.upgrade_image, "--work", a.work]
            for values in a.values:
                argv += ["--values", values]
            up = subprocess.run(argv, capture_output=True, text=True, timeout=1200, check=False)
            report = self.loadgen_finish(proc, 900)
            spotter.join()
            if up.returncode != 0:
                return [report, {"failed": f"helm upgrade failed: {up.stderr[-1000:]}"}] + spot_loads
            if not self.wait_healthy(600):
                return [report, {"failed": "the cosigners did not become healthy after the upgrade"}] + spot_loads
            self.after_upgrade = self.loadgen(self.setup_args, wall_timeout=900)
            return [report, self.loadgen(["sign", "--key", base.KEY_STEADY, "--key", base.KEY_SECOND,
                                          "--name", "after-upgrade", "--count", "50", "--clients", "5"])] + spot_loads

        r, check = self.scenario("upgrade", body, allowed=[()], restarted=tuple(NODES))
        after = getattr(self, "after_upgrade", {"failed": "not reached"})
        if "failed" in after:
            check("the keys can be read after the upgrade", False, after["failed"])
        else:
            for group in ("frost_keys", "ecies_keys"):
                for key_id, was in before.get(group, {}).items():
                    now = after.get(group, {}).get(key_id, {})
                    check(f"{key_id} survived the upgrade unchanged",
                          now.get("public_key") == was.get("public_key") and not now.get("created"),
                          f"public key {'changed' if now.get('public_key') != was.get('public_key') else 'same'}, "
                          f"created again: {now.get('created')}")
        if r["loads"] and "failed" not in r["loads"][0]:
            timeline = r["loads"][0].get("client", {}).get("timeline", [])
            r["seconds_with_failed_signatures"] = sum(1 for sec in timeline if sec.get("errors"))
        self.close(r)

    # -- recovery ------------------------------------------------------------------------------

    def time_to_healthy(self, since):
        """Seconds from `since` until every cosigner answers Health ok again, or None if that
        does not happen within --settle-secs from now."""
        asked = time.time()
        r = self.loadgen(["wait", "--within-secs", str(self.args.settle_secs)], wall_timeout=self.args.settle_secs + 120)
        if "failed" in r or "healthy_after_secs" not in r:
            return None
        return round(asked - since + float(r["healthy_after_secs"]), 1)

    def setup_keys(self, args, wall_timeout, cn=None):
        """`setup` for a suite's keys, tried three times a minute apart: a DKG needs every cosigner
        reachable, and a suite should not fail on a moment when one was not. Each failed attempt
        is logged."""
        for attempt in range(3):
            r = self.loadgen(args, timeout_secs=120, wall_timeout=wall_timeout, cn=cn)
            if "failed" not in r:
                return r
            log(f"  key setup failed (attempt {attempt + 1} of 3): {r.get('stderr', r['failed'])[-300:]}")
            if attempt < 2:
                time.sleep(60)
        return r

    def settle(self, within=None):
        """Wait until the cluster signs normally again: rounds of 20 signatures through every
        cosigner as leader until one round has no error and a p99 under the profile's SLO.
        Health alone is not enough: a node can be healthy while its connections to its peers are
        still dead after a disruption. Returns the seconds it took, or None if it did not settle."""
        within = within or self.args.settle_secs
        slo = float(self.profile.get("slo", {}).get("p99_ms", 1000))
        started = time.time()
        while time.time() - started < within:
            r = self.loadgen(["sign", "--key", base.KEY_STEADY, "--name", "settle", "--count", "20", "--clients", "6",
                              "--no-failover"], timeout_secs=15, wall_timeout=300)
            client = r.get("client", {})
            if "failed" not in r and not client.get("errors") and client.get("latency", {}).get("p99_ms", 1e9) <= slo:
                return round(time.time() - started, 1)
            time.sleep(5)
        return None

    # -- disruption ----------------------------------------------------------------------------

    def under_load(self, name, victims, strike, recover, allowed=(), flags=None, clients=6):
        """The steady stream for `disrupt_secs`; 15 s in, `strike()`; 15 s before its end,
        `recover()` (always, even if the strike failed); then wait for the cluster. Every
        signature must succeed: a threshold of cosigners keeps signing throughout."""
        secs = max(60, self.args.disrupt_secs)

        def body():
            # No --restarted for the victims: whether a victim's process restarted before the
            # load generator's last scrape is not known here, and a counter that went down tells
            # it reliably (prom.rs).
            proc = self.loadgen_start(
                ["sign", "--key", base.KEY_STEADY, "--name", name, "--rate", str(self.args.rate), "--clients", str(clients),
                 "--duration-secs", str(secs)], flags=flags
            )
            problems, spot_loads = [], []
            time.sleep(15)
            try:
                strike()
                struck = time.time()
                time.sleep(5)
                # The key classes during the disruption (each must succeed within the driver's
                # deadlines), then the rest of the disruption.
                spot_loads = self.spots(name)
                time.sleep(max(0, secs - 30 - (time.time() - struck)))
            except (subprocess.SubprocessError, OSError) as e:
                problems.append({"failed": f"strike: {e}", "rig": True})
            finally:
                ended = time.time()
                try:
                    recover()
                except (subprocess.SubprocessError, OSError) as e:
                    problems.append({"failed": f"recover: {e}", "rig": True})
                # A disrupted cosigner restarting is expected; what counts is how long until it
                # serves again. Measured from the end of the disruption (recovery included: a
                # rebooting node is part of it); the limit applies from the end of recovery.
                healthy[0] = self.time_to_healthy(ended)
            report = self.loadgen_finish(proc, secs + 900)
            # After a rig failure (a hook or kubectl error) the cluster's state is not what the
            # scenario meant to produce: what follows says nothing about Rütli.
            rig = bool(problems)
            if healthy[0] is None:
                problems.append({"failed": f"{', '.join(victims) or 'a cosigner'} was not healthy again within "
                                           f"{self.args.settle_secs} s of the end of the recovery", "rig": rig})
            settled[0] = self.settle()
            if settled[0] is None:
                problems.append({"failed": f"the cluster did not sign normally again within {self.args.settle_secs} s",
                                 "rig": rig})
            return [report] + spot_loads + problems

        settled, healthy = [None], [None]
        r, _ = self.scenario(name, body, restarted=tuple(victims), allowed=allowed)
        # How long after the disruption ended the cluster took to sign within the SLO again, and
        # every cosigner (the disrupted one included) took to answer Health ok again.
        r["recovery_secs"] = settled[0]
        r["time_to_healthy_secs"] = healthy[0]
        log(f"  time to healthy {healthy[0]} s, recovery (signing within the SLO) {settled[0]} s")
        # Latency split by the cosigner that answered: which leaders waited on the disruption.
        if r["loads"] and "failed" not in r["loads"][0]:
            for leader, rep in sorted(r["loads"][0].get("client", {}).get("by_leader", {}).items()):
                lat = rep.get("latency", {})
                log(f"  answered by {leader}: {rep.get('ok')} ok, {rep.get('errors')} errors, "
                    f"p50 {lat.get('p50_ms')} ms, p99 {lat.get('p99_ms')} ms")
        self.close(r)

    def victims(self):
        """Cosigners to disrupt, best first: not on the load generator's node, nor on a
        control-plane node."""
        lg = self.cluster.kubectl("get", "pod", "rutli-perf-loadgen", "-o", "jsonpath={.spec.nodeName}").stdout.strip()
        cp = set(self.cluster.kubectl("get", "nodes", "-l", "node-role.kubernetes.io/control-plane",
                                      "-o", "jsonpath={.items[*].metadata.name}", namespaced=False,
                                      check=False).stdout.split())
        return sorted(NODES, key=lambda n: (self.cluster.node_of(n) in cp, self.cluster.node_of(n) == lg, -NODES.index(n)))

    def disrupt(self):
        c = self.cluster
        order = self.victims()
        victim = order[0]
        node = c.node_of(victim)

        if os.environ.get("HOOK_KILL_NODE"):
            def back():
                self.hook("HOOK_KILL_NODE", "stop", node)
                c.kubectl("wait", "--for=condition=Ready", f"node/{node}", "--timeout=900s", namespaced=False, timeout=930)
                c.start(victim, within=900)
            self.under_load("node-kill", [victim], lambda: self.hook("HOOK_KILL_NODE", "start", node), back)
        else:
            # kubectl only: the node is cordoned and the cosigner's pod deleted. It stays down
            # (another node may take it if its volume can move there and no other cosigner runs
            # there), then the node is uncordoned.
            def cordon():
                c.kubectl("cordon", node, namespaced=False)
                c.kill(victim)

            def uncordon():
                c.kubectl("uncordon", node, namespaced=False)
                c.start(victim, within=900)
            log("  HOOK_KILL_NODE is not set: cordon the node and delete the pod instead")
            self.under_load("node-cordon", [victim], cordon, uncordon)

        victim = order[1] if len(order) > 1 else order[0]
        node, pvc = c.node_of(victim), c.pvc_of(victim)
        if os.environ.get("HOOK_DETACH_VOLUME"):
            def reattach():
                self.hook("HOOK_DETACH_VOLUME", "stop", node, pvc)
                # The pod keeps the dead mount: replace it.
                c.kill(victim)
                c.start(victim, within=900)
            self.under_load("lost-volume", [victim], lambda: self.hook("HOOK_DETACH_VOLUME", "start", node, pvc), reattach)
        else:
            self.skip("lost-volume", "HOOK_DETACH_VOLUME is not set")

        a, b, third = order[0], order[1 % len(order)], order[2 % len(order)]
        na, nb, nc = c.node_of(a), c.node_of(b), c.node_of(third)
        if os.environ.get("HOOK_PARTITION"):
            # Two cosigners lose each other; each still reaches the third, so every leader still
            # has a threshold. Signatures through a leader on either side must succeed.
            self.under_load("partition", [], lambda: self.hook("HOOK_PARTITION", "start", na, nb),
                            lambda: self.hook("HOOK_PARTITION", "stop", na, nb))

            # One cosigner cut off from both others, as when a data centre loses its links: it
            # cannot reach a threshold, so signatures it leads fail and clients move on; the other
            # two keep signing with each other.
            def isolate():
                self.hook("HOOK_PARTITION", "start", na, nb)
                self.hook("HOOK_PARTITION", "start", na, nc)

            def reconnect():
                try:
                    self.hook("HOOK_PARTITION", "stop", na, nb)
                finally:
                    self.hook("HOOK_PARTITION", "stop", na, nc)
            self.under_load("partition-isolated", [], isolate, reconnect)
        else:
            self.skip("partition", "HOOK_PARTITION is not set")
            self.skip("partition-isolated", "HOOK_PARTITION is not set")

        if os.environ.get("HOOK_NET_DELAY"):
            nodes = sorted({c.node_of(n) for n in NODES})
            for delay in self.args.net_delay_ms:
                ms = str(delay)
                self.under_load(f"net-delay-{ms}ms", [], lambda ms=ms: self.hook("HOOK_NET_DELAY", "start", ms, *nodes),
                                lambda ms=ms: self.hook("HOOK_NET_DELAY", "stop", ms, *nodes))
                self.results[-1]["compare_latency"] = True
            self.slow_node(victim)
        else:
            self.skip("net-delay", "HOOK_NET_DELAY is not set")
            self.skip("slow-node", "HOOK_NET_DELAY is not set")

    def slow_node(self, victim):
        """One cosigner slow, not dead: HOOK_NET_DELAY on its node alone, under the steady stream
        with the driver's deadlines and each leader policy of --slow-node (ms:policy). Under 5 s
        (the sign attempt deadline) nothing should demote it: rotate then brings it into about
        2/3 of the signatures against about 1/2 under a healthy sticky leader. Over 5 s rotate
        demotes it. Each run records the policy, which cosigner was slow, and every cosigner's
        share of the signatures it led and took part in (its rutli_sign_requests_total and
        rutli_sign_journal_entries_total over the signatures that succeeded)."""
        node = self.cluster.node_of(victim)
        for ms, policy in self.args.slow_node:
            name = f"slow-node-{ms}ms-{policy}"
            # Enough clients that the slow cosigner's signatures do not hold the stream back.
            clients = max(6, int(self.args.rate * (ms / 1000.0 + 1)) + 6)
            self.under_load(name, [], lambda ms=ms: self.hook("HOOK_NET_DELAY", "start", str(ms), node),
                            lambda ms=ms: self.hook("HOOK_NET_DELAY", "stop", str(ms), node),
                            flags=DRIVER_DEADLINES + ["--sign-leader", policy], clients=clients)
            r = self.results[-1]
            r.update({"sign_leader": policy, "slow_cosigner": victim, "added_delay_ms": ms})
            if r["loads"] and "failed" not in r["loads"][0]:
                load = r["loads"][0]
                r["node_shares"] = node_shares(load)
                r["failovers"] = load.get("client", {}).get("failovers", {})
                mine = r["node_shares"].get(victim, {})
                log(f"  slow {victim} (+{ms} ms, {policy}): led {mine.get('led')}, took part in {mine.get('took_part')} "
                    f"of the signatures; failovers {r['failovers']}")

    # -- connection setup ----------------------------------------------------------------------

    def connect_burst(self):
        """N new clients connecting at the same moment, one signature each (#181): how long the
        connections take, apart from the requests, and how many the cosigners cut at their
        handshake deadline. A measurement: refusals and timeouts are recorded, not failed."""
        for n in self.profile.get("connect", {}).get("clients", [50, 200, 500]):
            n = int(n)
            name = f"connect-{n}"
            r, _ = self.scenario(
                name,
                lambda n=n, name=name: self.loadgen(
                    ["sign", "--key", base.KEY_STEADY, "--name", name, "--count", str(n), "--clients", str(n),
                     "--eager-connect"], timeout_secs=30, wall_timeout=900),
                allowed=("UNAVAILABLE", "DEADLINE_EXCEEDED"),
            )
            load = r["loads"][0] if r["loads"] else {}
            conn = load.get("client", {}).get("connect") or {}
            dropped = sum(v for k, v in load.get("server", {}).get("counters", {}).items()
                          if k.startswith("rutli_grpc_handshake_timeouts_total"))
            r["connect"] = {"clients": n, "latency": conn.get("latency"), "errors": conn.get("errors"),
                            "error_sample": conn.get("error_sample"), "handshake_timeouts": dropped}
            lat = conn.get("latency") or {}
            log(f"  {n} connections: p50 {lat.get('p50_ms')} ms, p99 {lat.get('p99_ms')} ms, failed {conn.get('errors')}, "
                f"cut at the cosigners' handshake deadline: {dropped:g}")
            self.close(r)

    # -- key count -----------------------------------------------------------------------------

    def key_count(self):
        """For each count N: N FROST keys and N hosted keys over ten tenant prefixes; sign latency
        over all N; Peer.ListKeys time on every cosigner."""
        p = self.profile.get("keys", {})
        rate = float(p.get("sign_per_sec", 5))
        secs = int(p.get("secs", 60))
        out = []
        for n in sorted(set(int(x) for x in p.get("counts", [1, 10]))):
            frost = [f"perf-t{i % 10}-kc-{i}" for i in range(n)]
            hosted = [f"rutli-perf-t{i % 10}-kc-{i}" for i in range(n)]
            log(f"keys: {n}")
            setup = self.setup_keys(["setup"] + [x for k in frost for x in ("--frost-key", k)]
                                    + [x for k in hosted for x in ("--ecies-key", k)], wall_timeout=3600)
            entry = {"count": n, "setup_failed": setup.get("failed"), "rig": bool(setup.get("rig"))}
            if "failed" not in setup:
                load = self.loadgen(["sign", "--name", f"keys-{n}", "--rate", f"{rate:g}", "--clients", "6",
                                     "--duration-secs", str(secs)] + [x for k in frost for x in ("--key", k)],
                                    wall_timeout=secs + 900)
                lk = self.loadgen(["list-keys", "--repeat", "5", "--peer-cert", "/certs-peer/peer.crt",
                                   "--peer-key", "/certs-peer/peer.key"], wall_timeout=600)
                client = load.get("client", {})
                entry.update({
                    "sign": {"ok": client.get("ok"), "errors": client.get("errors"), "latency": client.get("latency"),
                             "server": load.get("server", {}).get("sign_duration"), "failed": load.get("failed")},
                    "list_keys": lk.get("targets", {}), "list_keys_failed": lk.get("failed"),
                    "rig": bool(load.get("rig") or lk.get("rig")),
                })
            ok = (not entry.get("setup_failed") and not entry.get("list_keys_failed")
                  and not entry.get("sign", {}).get("failed") and not entry.get("sign", {}).get("errors")
                  and all(not t.get("errors") for t in entry.get("list_keys", {}).values()))
            # Only the rig's fault if every failure here is a rig failure: errors the cluster
            # answered with, or a run that failed on the cluster's answer, are Rütli's.
            if not ok and "failed" not in setup:
                cluster_side = (entry.get("sign", {}).get("errors")
                                or any(t.get("errors") for t in entry.get("list_keys", {}).values())
                                or (load.get("failed") and not load.get("rig"))
                                or (lk.get("failed") and not lk.get("rig")))
                entry["rig"] = not cluster_side
            entry["passed"] = bool(ok)
            log(f"  {n} keys: {'ok' if ok else 'FAILED'}: sign p99 {entry.get('sign', {}).get('latency', {}).get('p99_ms')} ms, "
                f"list-keys mean {[round(t.get('mean_ms', 0), 1) for t in entry.get('list_keys', {}).values()]} ms")
            out.append(entry)
            if not ok:
                break
        self.keys = out

    # -- scale ramp ----------------------------------------------------------------------------

    def scale_ramp(self):
        """The baseline times each factor; a step runs the baseline's phases one after another
        (one phase of step_secs for a profile without phases), each phase's rates times the factor.

        The headroom factor is the last factor at which every phase passed (0: not even x1). A
        phase that fails (over the SLO, or an error) is dropped from the later steps and the ramp
        goes on with the others until none is left: so a profile shaped like real traffic (an
        average, a busiest minute, a burst) learns how far each part of it can grow, not only the
        first to give out. Against the profile's `real` measures, the best rate that passed is
        then a headroom of its own (real_load_headroom)."""
        p = self.profile
        base_mix = p["baseline"]
        slo = float(p["slo"]["p99_ms"])
        step_secs = int(p.get("step_secs", 300))
        phases = ramp_phases(base_mix, step_secs)
        n_keys = max(1, int(base_mix.get("sign_keys", 2)))
        # Every tenant carries the whole shape on its own signing keys, with its own certificate
        # (the first tenant on the suite's perf-ramp-* keys).
        tenant_keys = [(t, [f"{t['prefix']}ramp-{i}" for i in range(n_keys)]) for t in self.tenants()]
        n_hosted = max(1, int(base_mix.get("ecdh_keys", 1)))
        ecdh_keys = [f"rutli-perf-ramp-{i}" for i in range(n_hosted)] if any(ph["ecdh_per_sec"] > 0 for ph in phases) else []
        setup = {}
        for i, (t, keys) in enumerate(tenant_keys):
            extra = [x for k in ecdh_keys for x in ("--ecies-key", k)] if i == 0 else []
            setup = self.setup_keys(["setup"] + [x for k in keys for x in ("--frost-key", k)] + extra,
                                    wall_timeout=1800, cn=t["cn"])
            if "failed" in setup:
                break
        steps, headroom = [], 0
        if "failed" in setup:
            self.ramp = {"failed": f"setup: {setup['failed']}", "rig": bool(setup.get("rig")), "steps": [],
                         "headroom_factor": 0}
            return
        rig_stop = None
        active = [ph["name"] for ph in phases]
        shape_whole = True  # every phase still in the step
        clients = lambda r: str(max(3, min(256, math.ceil(r))))  # noqa: E731
        for factor in p.get("factors", [1, 3, 10, 30, 100]):
            step = {"factor": factor, "phases": {}, "ops": {}}
            reasons = []
            for ph in phases:
                if ph["name"] not in active:
                    continue
                sign_rate, ecdh_rate, secs = ph["sign_per_sec"] * factor, ph["ecdh_per_sec"] * factor, ph["secs"]
                label = f"ramp-x{factor:g}" + ("" if len(phases) == 1 else f"-{ph['name']}")
                log(f"ramp x{factor:g} {ph['name']}: {sign_rate:g} signatures/s, {ecdh_rate:g} ECDH/s for {secs} s")
                procs = []
                if sign_rate > 0:
                    for t, keys in tenant_keys:
                        procs.append(("sign", self.loadgen_start(
                            ["sign", "--name", label + ("" if len(tenant_keys) == 1 else f"-{t['name']}"),
                             "--rate", f"{sign_rate:g}", "--clients", clients(sign_rate),
                             "--duration-secs", str(secs)] + [x for k in keys for x in ("--key", k)], cn=t["cn"])))
                if ecdh_rate > 0 and ecdh_keys:
                    # One hosted key per stream; each has its own per-minute decryption ceiling.
                    per_key = ecdh_rate / len(ecdh_keys)
                    for k in ecdh_keys:
                        procs.append(("ecdh", self.loadgen_start(
                            ["ecdh", "--key", k, "--name", label, "--rate", f"{per_key:g}",
                             "--clients", clients(per_key), "--duration-secs", str(secs)])))
                result = {"sign_per_sec": sign_rate, "ecdh_per_sec": ecdh_rate, "secs": secs}
                why = []
                for op, proc in procs:
                    report = self.loadgen_finish(proc, secs + 900)
                    if "failed" in report:
                        if report.get("rig"):
                            # Not the cluster's limit: the step says nothing about headroom.
                            rig_stop = f"x{factor:g} {ph['name']} {op}: {report['failed']}"
                        else:
                            why.append(f"{op}: {report['failed']}")
                        continue
                    client = report.get("client", {})
                    key = op if len(phases) == 1 else f"{op} {ph['name']}"
                    o = step["ops"].setdefault(key, {"ok": 0, "errors": {}, "p99_ms": 0.0, "p95_ms": 0.0, "server": None})
                    o["ok"] += client.get("ok", 0)
                    for code, n in client.get("errors", {}).items():
                        o["errors"][code] = o["errors"].get(code, 0) + n
                    lat = client.get("latency", {})
                    o["p99_ms"] = max(o["p99_ms"], lat.get("p99_ms", 0.0))
                    o["p95_ms"] = max(o["p95_ms"], lat.get("p95_ms", 0.0))
                    if op == "sign":
                        o["server"] = report.get("server", {}).get("sign_duration")
                        if report.get("server", {}).get("peer_calls") and "peer_calls" not in o:
                            o["peer_calls"] = compare.peer_margin(report["server"]["peer_calls"])
                for key in {op if len(phases) == 1 else f"{op} {ph['name']}" for op, _ in procs}:
                    o = step["ops"].get(key)
                    if o and o["errors"]:
                        why.append(f"{key}: errors {o['errors']}")
                    if o and o["p99_ms"] > slo:
                        why.append(f"{key}: p99 {o['p99_ms']:.1f} ms above the SLO of {slo:g} ms")
                if rig_stop:
                    result["rig_failed"] = rig_stop
                    step["phases"][ph["name"]] = result
                    break
                result["passed"] = not why
                result["reasons"] = why
                step["phases"][ph["name"]] = result
                if why:
                    reasons += [f"{ph['name']}: {w}" for w in why]
            if rig_stop:
                step["rig_failed"] = rig_stop
                if reasons:
                    # A phase before the rig failure already failed on the cluster: that verdict stands.
                    step.update({"passed": False, "reasons": reasons})
                steps.append(step)
                log(f"  x{factor:g}: the rig failed ({rig_stop}); the ramp stops without a verdict on the rest of this step")
                break
            step["passed"] = not reasons
            step["reasons"] = reasons
            step["whole_shape"] = shape_whole
            steps.append(step)
            log(f"  x{factor:g}: {'ok' if not reasons else 'STOP for ' + '; '.join(reasons)}")
            if not reasons and shape_whole:
                headroom = factor
            failed = [name for name, r in step["phases"].items() if not r.get("passed")]
            if failed:
                shape_whole = False
                active = [name for name in active if name not in failed]
                if not active:
                    break
                # The overload of the failed phase must not count against the next one.
                if self.settle() is None:
                    log("  the cluster did not settle after the failed phase; the ramp stops")
                    break
        self.ramp = {"profile": p.get("name"), "slo_p99_ms": slo, "step_secs": step_secs,
                     "phases": [ph["name"] for ph in phases], "steps": steps, "headroom_factor": headroom}
        if p.get("real"):
            self.ramp["real_load_headroom"] = real_load_headroom(steps, p["real"])
            log("ramp: headroom against the real load: " + "; ".join(
                f"{h['name']} x{h['factor']:g}{' or more' if h.get('lower_bound') else ''}"
                for h in self.ramp["real_load_headroom"] if h.get("factor") is not None))
        if rig_stop:
            self.ramp.update({"failed": f"the rig failed: {rig_stop}", "rig": True})
            if not steps[-1].get("reasons"):
                # The headroom factor is then a lower bound: the step was never judged.
                self.ramp["headroom_is_lower_bound"] = True

class Diagnosis:
    """The diagnostic pass (`--diagnose`): what limits the cluster's throughput. In order of what
    each step tells for its cost: the flush cost of the cosigners' volume; a fine ramp around the
    knee with every cosigner's and generator's CPU, CPU and IO pressure and writes per step; then
    the same overloaded rate over 2, 20 and 200 keys. The load is spread over every load generator
    pod (k8s-deploy.sh --generators), so that no step is generator-bound unnoticed."""

    def __init__(self, suite):
        self.s = suite
        self.c = suite.cluster
        self.p = suite.profile

    def generators(self):
        names = self.c.kubectl("get", "pods", "-l", "app.kubernetes.io/name=rutli-perf-loadgen",
                               "-o", "jsonpath={.items[*].metadata.name}", check=False).stdout.split()
        return sorted(names) or ["rutli-perf-loadgen"]

    def start_on(self, pod, args, timeout_secs=30):
        return subprocess.Popen(self.c.loadgen_argv(args, timeout_secs, pod=pod), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    def cgroups(self, gens):
        cos = {n: diagnose.parse_cgroup(self.c.exec(n, diagnose.CGROUP_SCRIPT) or "") for n in NODES}
        gen = {}
        for pod in gens:
            out = self.c.kubectl("exec", pod, "--", "sh", "-c", diagnose.CGROUP_SCRIPT, check=False, timeout=30)
            gen[pod] = diagnose.parse_cgroup(out.stdout if out.returncode == 0 else "")
        return cos, gen

    def fsync_probe(self):
        """On each cosigner's own data volume, before any load: O_DSYNC writes, and the flush
        sequence of one released share (diagnose.FSYNC_PROBE_SCRIPT)."""
        out = {}
        for n in NODES:
            text = self.c.exec(n, diagnose.FSYNC_PROBE_SCRIPT) or ""
            out[n] = {"ms_per_dsync_write": diagnose.parse_dd(text), "ms_per_share": diagnose.parse_share_probe(text)}
            log(f"  flush probe {n}: {out[n]['ms_per_dsync_write']} ms per O_DSYNC write, "
                f"{out[n]['ms_per_share']} ms per share's flushes")
        return out

    def step(self, gens, name, secs, sign_rate, sign_keys, ecdh_rate=0.0, ecdh_keys=()):
        """One step at these rates, spread over the generators; what the cluster achieved and
        what every container did meanwhile."""
        clients = lambda r: str(max(3, min(256, math.ceil(r))))  # noqa: E731
        g = len(gens)
        procs = []
        for pod in gens:
            if sign_rate > 0:
                r = sign_rate / g
                procs.append(("sign", self.start_on(pod, ["sign", "--name", name, "--rate", f"{r:g}", "--clients", clients(r),
                                                          "--duration-secs", str(secs)] + [x for k in sign_keys for x in ("--key", k)])))
            for k in ecdh_keys if ecdh_rate > 0 else ():
                r = ecdh_rate / g / len(ecdh_keys)
                procs.append(("ecdh", self.start_on(pod, ["ecdh", "--key", k, "--name", name, "--rate", f"{r:g}",
                                                          "--clients", clients(r), "--duration-secs", str(secs)])))
        # The readings bracket the middle of the load, not the generators' start-up and shutdown:
        # every rate below is over the same window.
        settle = min(10.0, secs / 6)
        time.sleep(settle)
        before, t0 = self.cgroups(gens), time.time()
        time.sleep(max(1.0, secs - 2 * settle))
        after, elapsed = self.cgroups(gens), time.time() - t0
        ops, rig = {}, []
        for op, proc in procs:
            rep = self.s.loadgen_finish(proc, secs + 900)
            if "failed" in rep:
                if rep.get("rig"):
                    rig.append(f"{op}: {rep['failed']}")
                o = ops.setdefault(op, {"ok": 0, "errors": {}, "error_messages": {}, "p99_ms": 0.0})
                o["errors"]["(run failed)"] = o["errors"].get("(run failed)", 0) + 1
                continue
            c = rep.get("client", {})
            o = ops.setdefault(op, {"ok": 0, "errors": {}, "error_messages": {}, "p99_ms": 0.0})
            o["ok"] += c.get("ok", 0)
            for code, n in c.get("errors", {}).items():
                o["errors"][code] = o["errors"].get(code, 0) + n
            for msg, n in c.get("error_messages", {}).items():
                o["error_messages"][msg] = o["error_messages"].get(msg, 0) + n
            # Percentiles do not add up across generators: the worst one is kept.
            o["p99_ms"] = max(o["p99_ms"], c.get("latency", {}).get("p99_ms", 0.0))
            # Each generator scraped the cosigners around its own run; the worst view is kept.
            srv = rep.get("server", {}).get("sign_duration") if op == "sign" else None
            if srv and (not o.get("server") or (srv.get("p99_ms") or 0) > (o["server"].get("p99_ms") or 0)):
                o["server"] = srv
                if rep.get("server", {}).get("peer_calls"):
                    o["peer_calls"] = compare.peer_margin(rep["server"]["peer_calls"])
        cos = {n: diagnose.derive(before[0].get(n, {}), after[0].get(n, {}), elapsed) for n in NODES}
        gen = {p: diagnose.derive(before[1].get(p, {}), after[1].get(p, {}), elapsed) for p in gens}
        sign = ops.get("sign", {})
        errors = sign.get("errors", {})
        ok_per_sec = round(sign.get("ok", 0) / secs, 2)
        out = {
            "offered_per_sec": sign_rate, "ok_per_sec": ok_per_sec,
            "not_sent": errors.get("CLIENT_SATURATED", 0),
            "errors_sent": sum(n for code, n in errors.items() if code != "CLIENT_SATURATED"),
            "server_p99_ms": (sign.get("server") or {}).get("p99_ms"),
            "ops": ops, "cosigners": cos, "generators": gen,
            "cpu_ms_per_signature": diagnose.cpu_per_signature_ms(cos, ok_per_sec),
        }
        out["generator_bound"] = diagnose.generator_bound(out)
        if rig:
            out["rig_failed"] = rig
        return out

    def run(self):
        d = self.p.get("diagnose", {})
        mix = self.p["baseline"]
        slo = float(self.p["slo"]["p99_ms"])
        secs = int(d.get("step_secs", 120))
        gens = self.generators()
        log(f"diagnose: {len(gens)} load generator(s): {', '.join(gens)}")
        out = {"generators": gens, "step_secs": secs, "slo_p99_ms": slo}
        out["fsync_probe"] = self.fsync_probe()
        per_node = {NODES.index(n) + 1: v["ms_per_share"] for n, v in out["fsync_probe"].items()}
        # What the flushes alone would allow (diagnose.predicted_ceiling), from each node's own
        # probe and how often each node releases a share, to hold against the measured plateau.
        out["predicted_ceiling_signs_per_sec"] = diagnose.predicted_ceiling(per_node)
        out["ceiling_model"] = ("each node flushes its shares one after another; leaders spread evenly; "
                                "partners after a hash of the request id (#250): each node releases a share "
                                "for t/n of the signatures")

        sign_keys = [f"perf-ramp-{i}" for i in range(max(1, int(mix.get("sign_keys", 2))))]
        ecdh_keys = [f"rutli-perf-ramp-{i}" for i in range(int(mix.get("ecdh_keys", 1)))] if d.get("with_ecdh") else []
        setup = self.s.setup_keys(["setup"] + [x for k in sign_keys for x in ("--frost-key", k)]
                                  + [x for k in ecdh_keys for x in ("--ecies-key", k)], wall_timeout=1800)
        if "failed" in setup:
            out.update({"failed": f"setup: {setup['failed']}", "rig": bool(setup.get("rig"))})
            return out
        steps, past = [], 0
        # Factors of this rate (a profile shaped by phases has no single baseline rate).
        base_rate = float(d.get("sign_per_sec", mix.get("sign_per_sec", 1)))
        for f in d.get("factors", [30, 50, 70, 100, 130, 160, 200, 250, 300]):
            sign_rate = base_rate * f
            log(f"diagnose x{f:g}: {sign_rate:g} signatures/s for {secs} s")
            # Signing only, unless the profile asks for the mix: CPU per signature and the knee are
            # about signing.
            ecdh_rate = float(mix.get("ecdh_per_sec", 0)) * f if d.get("with_ecdh") else 0.0
            st = self.step(gens, f"diag-x{f:g}", secs, sign_rate, sign_keys, ecdh_rate, ecdh_keys)
            st["factor"] = f
            steps.append(st)
            cpu = {n: c.get("cpu_cores") for n, c in st["cosigners"].items()}
            log(f"  x{f:g}: {st['ok_per_sec']}/s of {sign_rate:g}/s, server p99 {st['server_p99_ms']} ms, "
                f"not sent {st['not_sent']}, cosigner cores {cpu}, generator-bound {st['generator_bound']}")
            if st.get("rig_failed"):
                out["rig_failed"] = st["rig_failed"]
                break
            # One step past the knee shows the plateau; a second one adds nothing.
            if diagnose.knee([st], slo) is not None:
                past += 1
                if past >= 2:
                    break
        out["steps"] = steps
        out["knee_factor"] = diagnose.knee(steps, slo)
        out["max_ok_per_sec"] = max((st["ok_per_sec"] for st in steps), default=None)
        out["generator_bound_steps"] = [st["factor"] for st in steps if st.get("generator_bound") is not False]
        if self.p.get("real") and out["max_ok_per_sec"]:
            # The plateau against each measure of the real load (a burst is short, so the same rate).
            out["plateau_vs_real"] = [{"name": m["name"], "per_sec": m["per_sec"],
                                       "factor": round(out["max_ok_per_sec"] / float(m["per_sec"]), 1)}
                                      for m in self.p["real"]]
        log(f"diagnose: knee at x{out['knee_factor']}, at most {out['max_ok_per_sec']} signatures/s; "
            f"the flushes alone would allow about {out['predicted_ceiling_signs_per_sec']}/s; "
            f"steps without a verdict (generator-bound or no readings): {out['generator_bound_steps']}")

        k = out["knee_factor"]
        if k and not out.get("rig_failed"):
            # The knee's (overloaded) rate over more keys: does the throughput follow the key count?
            rate = base_rate * k
            results = []
            for n in d.get("key_counts", [2, 20, 200]):
                keys = [f"perf-dk-{i}" for i in range(int(n))]
                r = self.s.setup_keys(["setup"] + [x for key in keys for x in ("--frost-key", key)], wall_timeout=3600)
                if "failed" in r:
                    results.append({"keys": n, "failed": r["failed"], "rig": bool(r.get("rig"))})
                    break
                st = self.step(gens, f"diag-keys-{n}", secs, rate, keys)
                results.append({"keys": n, "offered_per_sec": rate, "ok_per_sec": st["ok_per_sec"],
                                "server_p99_ms": st["server_p99_ms"], "errors_sent": st["errors_sent"],
                                "cosigners": st["cosigners"], "generator_bound": st["generator_bound"]})
                log(f"  {n} keys: {st['ok_per_sec']}/s of {rate:g}/s, server p99 {st['server_p99_ms']} ms")
            out["keys"] = results
            out["keys_verdict"] = diagnose.keys_verdict(results)
            log(f"diagnose: {out['keys_verdict']}")
        return out


def terminated(signum, _frame):
    """SIGTERM as an exception, so that a stopped run still runs its `finally` blocks (the
    migration stops its ceremony and removes the dealer pod)."""
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, terminated)
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--namespace", default="rutli-perf")
    p.add_argument("--profile", required=True, help="the load profile (scripts/perf/profiles/)")
    p.add_argument("--out", required=True)
    # Disruption last: whatever it leaves behind cannot skew the measurements of the others.
    p.add_argument("--suites", default="migration,upgrade,scenarios,connect,keys,ramp,disrupt")
    p.add_argument("--allow-unisolated-dealer", action="store_true",
                   help="migration suite: go on when the dealer pod reaches the network (a cluster whose network "
                        "plugin enforces no NetworkPolicy, such as kind's default); otherwise that is a failure")
    p.add_argument("--dealer-image", default="",
                   help="migration suite: the dealer's image (rutli-dealer of the cosigners' release). Default: the load "
                        "generator's image; with the upgrade suite, whose cosigners start on the previous release, one "
                        "built from that release (frost/Dockerfile.dealer) is required, else the migration is skipped")
    p.add_argument("--diagnose", action="store_true",
                   help="run the diagnostic pass instead of the suites (what limits the throughput; profile 'diagnose')")
    p.add_argument("--env-name", default="k8s",
                   help="what the result calls its environment; runs are compared within one only")
    p.add_argument("--upgrade-image", default="", help="upgrade suite: the image to upgrade to")
    p.add_argument("--work", default="", help="upgrade suite: the --work directory of k8s-deploy.sh")
    p.add_argument("--values", action="append", default=[], help="upgrade suite: extra chart values, as for k8s-deploy.sh")
    p.add_argument("--load-path", choices=["grpc", "canton"], default="grpc")
    p.add_argument("--sign-attempt-timeout-secs", type=float, default=None,
                   help="the load generator's deadline per attempt of a signature (default: as "
                        "--attempt-timeout-secs)")
    p.add_argument("--attempt-timeout-secs", type=float, default=None,
                   help="the load generator's deadline per attempt of another call that fails over, ECDH "
                        "(default: one timeout per attempt, 30 s)")
    p.add_argument("--request-timeout-secs", type=float, default=None,
                   help="the load generator's budget per call across its attempts (default: none)")
    p.add_argument("--driver-deadlines", action="store_true",
                   help="the driver's policy: 5 s per sign attempt, 10 s per other attempt, 30 s per call "
                        "(frost.sign-attempt-timeout, frost.attempt-timeout, frost.request-timeout), unless "
                        "the flags above say otherwise")
    p.add_argument("--steady-secs", type=int, default=None, help="default: the profile's, else 60")
    p.add_argument("--rate", type=int, default=None, help="steady stream signatures/s; default: the profile's, else 20")
    p.add_argument("--disrupt-secs", type=int, default=120)
    p.add_argument("--net-delay-ms", type=lambda v: [int(x) for x in v.split(",") if x.strip()], default=[50, 150],
                   help="the net-delay scenarios' added delays, comma-separated (default 50,150)")
    p.add_argument("--slow-node", type=parse_slow_node, default=parse_slow_node("2500:sticky,2500:rotate,6000:rotate"),
                   help="the slow-node scenarios (with HOOK_NET_DELAY): added delay in ms and leader policy each")
    p.add_argument("--sign-leader", choices=("sticky", "rotate"), default=None,
                   help="where the load generator starts a signature, as the driver's frost.sign-leader "
                        "(default: sticky; rotate with --driver-deadlines, the driver's default)")
    p.add_argument("--settle-secs", type=int, default=600,
                   help="after a disruption, how long the cluster may take to sign normally again")
    p.add_argument("--max-rss-mib", type=int, default=None, help="default: the profile's, else 256 (the chart's limit)")
    p.add_argument("--max-fd-growth", type=int, default=64)
    p.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    args = p.parse_args()

    with open(args.profile) as f:
        profile = json.load(f)
    steady = profile.get("steady", {})
    args.steady_secs = args.steady_secs or int(steady.get("secs", 60))
    args.rate = args.rate or int(steady.get("sign_per_sec", 20))
    args.max_rss_mib = args.max_rss_mib or int(profile.get("max_rss_mib", 256))
    suites = ["diagnose"] if args.diagnose else [s.strip() for s in args.suites.split(",") if s.strip()]
    if len(set(suites)) != len(suites):
        p.error(f"a suite is listed twice: {suites}")
    unknown = set(suites) - {"migration", "upgrade", "scenarios", "connect", "disrupt", "keys", "ramp", "diagnose"}
    if unknown:
        p.error(f"unknown suites: {sorted(unknown)}")
    # The dealer and the cosigners of a ceremony are one release (docs/split-ceremony.md): with the
    # upgrade suite the cosigners start on the previous release, so the default dealer (this build's)
    # does not fit, and the migration is skipped rather than run against the rule.
    args.migration_skip = None
    if "migration" in suites and not args.work:
        args.migration_skip = "needs --work (the installation's certificates)"
    elif "migration" in suites and "upgrade" in suites and suites.index("upgrade") < suites.index("migration"):
        p.error("migration must run before upgrade: its dealer is a dealer of the cosigners' release")
    elif "migration" in suites and "upgrade" in suites and not args.dealer_image:
        args.migration_skip = ("the cosigners start on the previous release: --dealer-image must be a dealer of that "
                               "release (frost/Dockerfile.dealer)")
    if "upgrade" in suites and not (args.upgrade_image and args.work):
        p.error("the upgrade suite needs --upgrade-image and --work (or leave it out of --suites)")
    if args.load_path == "canton" and not os.environ.get("CANTON_LOAD_CMD"):
        p.error("--load-path canton needs CANTON_LOAD_CMD (see the module docs); not available yet")
    for name in HOOKS:
        if os.environ.get(name) and not shutil.which(shlex.split(os.environ[name])[0]):
            p.error(f"{name}={os.environ[name]!r}: not an executable")

    if args.driver_deadlines:
        args.sign_attempt_timeout_secs = args.sign_attempt_timeout_secs or 5.0
        args.attempt_timeout_secs = args.attempt_timeout_secs or 10.0
        args.request_timeout_secs = args.request_timeout_secs or 30.0
        args.sign_leader = args.sign_leader or "rotate"
    for flag in ("sign_attempt_timeout_secs", "attempt_timeout_secs", "request_timeout_secs"):
        if getattr(args, flag) is not None and getattr(args, flag) <= 0:
            p.error(f"--{flag.replace('_', '-')} must be positive")
    client_policy = {"sign_attempt_timeout_secs": args.sign_attempt_timeout_secs,
                     "attempt_timeout_secs": args.attempt_timeout_secs,
                     "request_timeout_secs": args.request_timeout_secs,
                     "sign_leader": args.sign_leader}
    cluster = K8sCluster(args.namespace, args.env_name, args.load_path, client_policy)
    # A diagnostic installation (k8s-deploy.sh --diagnostic-tmpfs) says so on its namespace; its
    # results are labelled and never a baseline.
    diagnostic = subprocess.run(["kubectl", "get", "namespace", args.namespace, "-o",
                                 "jsonpath={.metadata.annotations.rutli-perf/diagnostic}"],
                                capture_output=True, text=True, check=False).stdout.strip() or None
    if diagnostic and set(suites) & {"upgrade", "disrupt"}:
        p.error(f"namespace {args.namespace} is a diagnostic installation ({diagnostic}): its data is lost on any "
                "restart, so the upgrade and disrupt suites cannot run there")
    suite = Suite(cluster, args, profile)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    suite.setup_args = ["setup", "--frost-key", base.KEY_STEADY, "--frost-key", base.KEY_SECOND,
                        "--frost-key", base.KEY_LIMITED, "--ecies-key", base.KEY_ECIES]
    log(f"waiting for the cosigners in namespace {args.namespace}")
    setup = {"failed": "the cosigners did not become healthy"}
    if suite.wait_healthy(600):
        setup = suite.loadgen(suite.setup_args, wall_timeout=900)
        if "failed" not in setup:
            setup = suite.setup_classes() or setup
    suite.setup_report = setup
    diagnosis = None
    if "failed" not in setup:
        for name in suites:
            if name == "diagnose":
                diagnosis = Diagnosis(suite).run()
                continue
            if name == "migration" and args.migration_skip:
                suite.skip("migration", args.migration_skip)
                continue
            {"migration": suite.migration, "upgrade": suite.upgrade, "scenarios": suite.run,
             "connect": suite.connect_burst, "disrupt": suite.disrupt, "keys": suite.key_count,
             "ramp": suite.scale_ramp}[name]()
        if not args.diagnose and suite.profile.get("classes"):
            # At the end: its rate-limit burst empties the namespace key's bucket for a minute.
            suite.key_classes()

    # `failed`: Rütli failed a check. `rig_failed`: only the test rig failed (a load generator that
    # could not be run or reached, a hook or kubectl error): nothing is known about Rütli there.
    failed = [r["name"] for r in suite.results if r.get("failed_by") == "rutli"]
    rig_failed = [r["name"] for r in suite.results if r.get("failed_by") == "rig"]
    if "failed" in setup:
        (rig_failed if setup.get("rig") else failed).insert(0, "setup")
        log(f"setup FAILED: {setup['failed']}\n{setup.get('stderr', '')}")
    bad_keys = [k for k in suite.keys or [] if not k.get("passed")]
    if bad_keys:
        (rig_failed if all(k.get("rig") for k in bad_keys) else failed).append("keys")
    if suite.ramp and suite.ramp.get("failed"):
        (rig_failed if suite.ramp.get("rig") else failed).append("ramp")
    if diagnosis and (diagnosis.get("failed") or diagnosis.get("rig_failed")):
        (rig_failed if diagnosis.get("rig") or diagnosis.get("rig_failed") else failed).append("diagnose")
    doc = {
        "schema": 1,
        "kind": "cluster",
        "environment": args.env_name,
        "load_path": args.load_path,
        # How the load generator times out and fails over a call (None: its defaults); runs are
        # compared only under the same policy.
        "client_policy": client_policy if any(v is not None for v in client_policy.values()) else None,
        # "tmpfs": a diagnostic installation, never a configuration and never a baseline.
        "diagnostic": diagnostic,
        "commit": args.commit,
        "started_at": started,
        "profile": profile.get("name"),
        "steady_secs": args.steady_secs,
        "rate": args.rate,
        "suites": suites,
        "hooks": sorted(h for h in HOOKS if os.environ.get(h)),
        # The ramp's result as one number: how many times the baseline load the cluster carried
        # within the SLO. None: the ramp did not run.
        "headroom_factor": suite.ramp.get("headroom_factor") if suite.ramp else None,
        # Per disruption: seconds from its end until the cluster signed within the SLO again;
        # None: it never did within --settle-secs.
        "recovery_secs": {r["name"]: r.get("recovery_secs") for r in suite.results if "recovery_secs" in r},
        # Per disruption: seconds from its end until every cosigner, the disrupted one included,
        # answered Health ok again; None: not within --settle-secs.
        "time_to_healthy_secs": {r["name"]: r.get("time_to_healthy_secs") for r in suite.results
                                 if "time_to_healthy_secs" in r},
        "setup": setup,
        "scenarios": suite.results,
        "skipped": suite.skipped,
        "tenants": [t["name"] for t in suite.tenants()],
        "key_class_spot_checks": suite.spot_checks,
        "keys": suite.keys,
        "ramp": suite.ramp,
        "diagnosis": diagnosis,
        "peer_calls": peer_call_entries(suite.results, suite.ramp, diagnosis),
        "failed": failed,
        "rig_failed": rig_failed,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    log(f"wrote {args.out}; headroom factor {doc['headroom_factor']}")
    if rig_failed:
        log(f"RIG FAILED (no verdict on Rütli): {', '.join(rig_failed)}")
    if failed:
        log(f"FAILED (Rütli): {', '.join(failed)}")
        return 1
    # 3: only the rig failed; the run says nothing either way about what it could not do.
    return 3 if rig_failed else 0


if __name__ == "__main__":
    sys.exit(main())

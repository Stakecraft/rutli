#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""The cluster suite: the load scenarios against Rütli on any Kubernetes cluster.

Bring a kubeconfig and a namespace; install with scripts/perf/k8s-deploy.sh, then

  cluster.py --namespace NS --profile scripts/perf/profiles/placeholder.json --out result.json \\
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
  ramp       the scale ramp: the profile's baseline load times 1, 3, 10, 30, 100, ... for
             step_secs each, stopping at the first step whose p99 exceeds the SLO or that has an
             error. The last step that passed is the headroom factor, a top-level number.

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
import json
import math
import os
import shlex
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run as base  # noqa: E402  (the compose suite: Runner, scenarios, key names)

NODES = base.NODES
HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = ("HOOK_KILL_NODE", "HOOK_DETACH_VOLUME", "HOOK_PARTITION", "HOOK_NET_DELAY")
log = base.log


class K8sCluster:
    """Three cosigners installed by scripts/perf/k8s-deploy.sh in one namespace; the load
    generator is the pod rutli-perf-loadgen there, driven with `kubectl exec`."""

    def __init__(self, namespace, kind, load_path):
        self.ns = namespace
        self.kind = kind
        self.load_path = load_path

    @staticmethod
    def pod(node):
        return f"rutli-cosigner-n{NODES.index(node) + 1}-0"

    def kubectl(self, *args, timeout=300, check=True, namespaced=True):
        argv = ["kubectl"] + (["-n", self.ns] if namespaced else []) + list(args)
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=check)

    def loadgen_argv(self, args, timeout_secs):
        if self.load_path == "canton" and args and args[0] == "sign":
            # The entry point for load through a participant (see the module docs).
            return shlex.split(os.environ["CANTON_LOAD_CMD"]) + args
        # Run detached in the pod and fetched afterwards (k8s_loadgen.py): a stream held open
        # through the API server for a whole run was reset on a real cluster.
        argv = [sys.executable, "-I", os.path.join(HERE, "k8s_loadgen.py"), "--namespace", self.ns, "--",
                "--ca", "/certs/ca.crt", "--cert", "/certs/driver.crt", "--key", "/certs/driver.key",
                "--timeout-secs", str(timeout_secs)]
        for i, node in enumerate(NODES, start=1):
            # gRPC through the per-node Service; metrics through the pod's name behind the headless
            # Service, which the per-node Service does not expose.
            argv += ["--target", f"{node}=https://rutli-node-{i}.{self.ns}.svc:9101"]
            argv += ["--metrics", f"{node}=http://{self.pod(node)}.rutli-cosigner.{self.ns}.svc:9200/metrics"]
        return argv + args

    def exec(self, node, shell):
        out = self.kubectl("exec", self.pod(node), "-c", "cosigner", "--", "sh", "-c", shell, timeout=30, check=False)
        return out.stdout if out.returncode == 0 else None

    def kill(self, node):
        self.kubectl("delete", "pod", self.pod(node), "--grace-period=0", "--force", "--wait=false")

    def start(self, node, within=600):
        """Wait until the cosigner's StatefulSet has its pod back and ready."""
        sts = self.pod(node)[: -len("-0")]
        self.kubectl("rollout", "status", f"statefulset/{sts}", f"--timeout={within}s", timeout=within + 30)

    def restart(self, node):
        self.kubectl("delete", "pod", self.pod(node), timeout=180)
        self.start(node)

    def node_of(self, node):
        return self.kubectl("get", "pod", self.pod(node), "-o", "jsonpath={.spec.nodeName}").stdout.strip()

    def pvc_of(self, node):
        return f"{self.ns}/data-{self.pod(node)[: -len('-0')]}"


class Suite(base.Runner):
    def __init__(self, cluster, args, profile):
        super().__init__(cluster, args)
        self.profile = profile
        self.skipped = []
        self.ramp = None
        self.keys = None

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
        The chart restarts every cosigner at once, so signatures fail while they restart: counted,
        not forbidden. Afterwards every key is there with the same public key, and signs."""
        a = self.args
        before = self.setup_report

        def body():
            proc = self.loadgen_start(
                ["sign", "--key", base.KEY_STEADY, "--name", "upgrade", "--rate", "5", "--clients", "3",
                 "--duration-secs", "150"] + [x for n in NODES for x in ("--restarted", n)]
            )
            time.sleep(10)
            log(f"  helm upgrade to {a.upgrade_image}")
            argv = [os.path.join(HERE, "k8s-deploy.sh"), "upgrade", "--namespace", self.cluster.ns,
                    "--image", a.upgrade_image, "--work", a.work]
            for values in a.values:
                argv += ["--values", values]
            up = subprocess.run(argv, capture_output=True, text=True, timeout=1200, check=False)
            report = self.loadgen_finish(proc, 900)
            if up.returncode != 0:
                return [report, {"failed": f"helm upgrade failed: {up.stderr[-1000:]}"}]
            if not self.wait_healthy(600):
                return [report, {"failed": "the cosigners did not become healthy after the upgrade"}]
            self.after_upgrade = self.loadgen(self.setup_args, wall_timeout=900)
            return [report, self.loadgen(["sign", "--key", base.KEY_STEADY, "--key", base.KEY_SECOND,
                                          "--name", "after-upgrade", "--count", "50", "--clients", "5"])]

        down = ("UNAVAILABLE", "DEADLINE_EXCEEDED", "UNKNOWN", "ABORTED", "CANCELLED", "INTERNAL")
        r, check = self.scenario("upgrade", body, allowed=[down, ()], restarted=tuple(NODES))
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

    def setup_keys(self, args, wall_timeout):
        """`setup` for a suite's keys, tried three times a minute apart: a DKG needs every cosigner
        reachable, and a suite should not fail on a moment when one was not. Each failed attempt
        is logged."""
        for attempt in range(3):
            r = self.loadgen(args, timeout_secs=120, wall_timeout=wall_timeout)
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

    def under_load(self, name, victims, strike, recover, allowed=()):
        """The steady stream for `disrupt_secs`; 15 s in, `strike()`; 15 s before its end,
        `recover()` (always, even if the strike failed); then wait for the cluster. Every
        signature must succeed: a threshold of cosigners keeps signing throughout."""
        secs = max(60, self.args.disrupt_secs)

        def body():
            # No --restarted for the victims: whether a victim's process restarted before the
            # load generator's last scrape is not known here, and a counter that went down tells
            # it reliably (prom.rs).
            proc = self.loadgen_start(
                ["sign", "--key", base.KEY_STEADY, "--name", name, "--rate", str(self.args.rate), "--clients", "6",
                 "--duration-secs", str(secs)]
            )
            problems = []
            time.sleep(15)
            try:
                strike()
                time.sleep(max(0, secs - 30))
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
            return [report] + problems

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
            ms = str(self.args.net_delay_ms)
            nodes = sorted({c.node_of(n) for n in NODES})
            self.under_load(f"net-delay-{ms}ms", [], lambda: self.hook("HOOK_NET_DELAY", "start", ms, *nodes),
                            lambda: self.hook("HOOK_NET_DELAY", "stop", ms, *nodes))
            self.results[-1]["compare_latency"] = True
        else:
            self.skip("net-delay", "HOOK_NET_DELAY is not set")

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
        """The baseline mix times each factor for step_secs; stop at the first step over the SLO
        or with an error. Headroom factor: the last step that passed (0: not even the baseline)."""
        p = self.profile
        base_mix = p["baseline"]
        slo = float(p["slo"]["p99_ms"])
        step_secs = int(p.get("step_secs", 300))
        n_keys = max(1, int(base_mix.get("sign_keys", 2)))
        sign_keys = [f"perf-ramp-{i}" for i in range(n_keys)]
        n_hosted = max(1, int(base_mix.get("ecdh_keys", 1)))
        ecdh_keys = [f"rutli-perf-ramp-{i}" for i in range(n_hosted)]
        setup = self.setup_keys(["setup"] + [x for k in sign_keys for x in ("--frost-key", k)]
                                + [x for k in ecdh_keys for x in ("--ecies-key", k)], wall_timeout=1800)
        steps, headroom = [], 0
        if "failed" in setup:
            self.ramp = {"failed": f"setup: {setup['failed']}", "rig": bool(setup.get("rig")), "steps": [],
                         "headroom_factor": 0}
            return
        rig_stop = None
        for factor in p.get("factors", [1, 3, 10, 30, 100]):
            procs = []
            sign_rate = float(base_mix.get("sign_per_sec", 0)) * factor
            ecdh_rate = float(base_mix.get("ecdh_per_sec", 0)) * factor
            log(f"ramp x{factor:g}: {sign_rate:g} signatures/s, {ecdh_rate:g} ECDH/s for {step_secs} s")
            clients = lambda r: str(max(3, min(256, math.ceil(r))))  # noqa: E731
            if sign_rate > 0:
                procs.append(("sign", self.loadgen_start(
                    ["sign", "--name", f"ramp-x{factor:g}", "--rate", f"{sign_rate:g}", "--clients", clients(sign_rate),
                     "--duration-secs", str(step_secs)] + [x for k in sign_keys for x in ("--key", k)])))
            if ecdh_rate > 0:
                # One hosted key per stream; each has its own per-minute decryption ceiling.
                per_key = ecdh_rate / len(ecdh_keys)
                for k in ecdh_keys:
                    procs.append(("ecdh", self.loadgen_start(
                        ["ecdh", "--key", k, "--name", f"ramp-x{factor:g}", "--rate", f"{per_key:g}",
                         "--clients", clients(per_key), "--duration-secs", str(step_secs)])))
            step = {"factor": factor, "sign_per_sec": sign_rate, "ecdh_per_sec": ecdh_rate, "ops": {}}
            reasons = []
            for op, proc in procs:
                report = self.loadgen_finish(proc, step_secs + 900)
                if "failed" in report:
                    if report.get("rig"):
                        # Not the cluster's limit: the step says nothing about headroom.
                        rig_stop = f"x{factor:g} {op}: {report['failed']}"
                    else:
                        reasons.append(f"{op}: {report['failed']}")
                    continue
                client = report.get("client", {})
                o = step["ops"].setdefault(op, {"ok": 0, "errors": {}, "p99_ms": 0.0, "p95_ms": 0.0, "server": None})
                o["ok"] += client.get("ok", 0)
                for code, n in client.get("errors", {}).items():
                    o["errors"][code] = o["errors"].get(code, 0) + n
                lat = client.get("latency", {})
                o["p99_ms"] = max(o["p99_ms"], lat.get("p99_ms", 0.0))
                o["p95_ms"] = max(o["p95_ms"], lat.get("p95_ms", 0.0))
                if op == "sign":
                    o["server"] = report.get("server", {}).get("sign_duration")
            for op, o in step["ops"].items():
                if o["errors"]:
                    reasons.append(f"{op}: errors {o['errors']}")
                if o["p99_ms"] > slo:
                    reasons.append(f"{op}: p99 {o['p99_ms']:.1f} ms above the SLO of {slo:g} ms")
            if rig_stop:
                step["rig_failed"] = rig_stop
                steps.append(step)
                log(f"  x{factor:g}: the rig failed ({rig_stop}); the ramp stops without a verdict on this step")
                break
            step["passed"] = not reasons
            step["reasons"] = reasons
            steps.append(step)
            log(f"  x{factor:g}: {'ok' if not reasons else 'STOP: ' + '; '.join(reasons)}")
            if reasons:
                break
            headroom = factor
        self.ramp = {"profile": p.get("name"), "slo_p99_ms": slo, "step_secs": step_secs,
                     "steps": steps, "headroom_factor": headroom}
        if rig_stop:
            # The headroom factor is then a lower bound: the next step was never judged.
            self.ramp.update({"failed": f"the rig failed: {rig_stop}", "rig": True, "headroom_is_lower_bound": True})


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--namespace", default="rutli-perf")
    p.add_argument("--profile", required=True, help="the load profile (scripts/perf/profiles/)")
    p.add_argument("--out", required=True)
    # Disruption last: whatever it leaves behind cannot skew the measurements of the others.
    p.add_argument("--suites", default="upgrade,scenarios,connect,keys,ramp,disrupt")
    p.add_argument("--env-name", default="k8s",
                   help="what the result calls its environment; runs are compared within one only")
    p.add_argument("--upgrade-image", default="", help="upgrade suite: the image to upgrade to")
    p.add_argument("--work", default="", help="upgrade suite: the --work directory of k8s-deploy.sh")
    p.add_argument("--values", action="append", default=[], help="upgrade suite: extra chart values, as for k8s-deploy.sh")
    p.add_argument("--load-path", choices=["grpc", "canton"], default="grpc")
    p.add_argument("--steady-secs", type=int, default=None, help="default: the profile's, else 60")
    p.add_argument("--rate", type=int, default=None, help="steady stream signatures/s; default: the profile's, else 20")
    p.add_argument("--disrupt-secs", type=int, default=120)
    p.add_argument("--net-delay-ms", type=int, default=50)
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
    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    unknown = set(suites) - {"upgrade", "scenarios", "connect", "disrupt", "keys", "ramp"}
    if unknown:
        p.error(f"unknown suites: {sorted(unknown)}")
    if "upgrade" in suites and not (args.upgrade_image and args.work):
        p.error("the upgrade suite needs --upgrade-image and --work (or leave it out of --suites)")
    if args.load_path == "canton" and not os.environ.get("CANTON_LOAD_CMD"):
        p.error("--load-path canton needs CANTON_LOAD_CMD (see the module docs); not available yet")
    for name in HOOKS:
        if os.environ.get(name) and not shutil.which(shlex.split(os.environ[name])[0]):
            p.error(f"{name}={os.environ[name]!r}: not an executable")

    cluster = K8sCluster(args.namespace, args.env_name, args.load_path)
    suite = Suite(cluster, args, profile)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    suite.setup_args = ["setup", "--frost-key", base.KEY_STEADY, "--frost-key", base.KEY_SECOND,
                        "--frost-key", base.KEY_LIMITED, "--ecies-key", base.KEY_ECIES]
    log(f"waiting for the cosigners in namespace {args.namespace}")
    setup = {"failed": "the cosigners did not become healthy"}
    if suite.wait_healthy(600):
        setup = suite.loadgen(suite.setup_args, wall_timeout=900)
    suite.setup_report = setup
    if "failed" not in setup:
        for name in suites:
            {"upgrade": suite.upgrade, "scenarios": suite.run, "connect": suite.connect_burst,
             "disrupt": suite.disrupt, "keys": suite.key_count, "ramp": suite.scale_ramp}[name]()

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
    doc = {
        "schema": 1,
        "kind": "cluster",
        "environment": args.env_name,
        "load_path": args.load_path,
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
        "keys": suite.keys,
        "ramp": suite.ramp,
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

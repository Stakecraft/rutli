#!/usr/bin/env python3
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
"""Run rutli-loadgen in the cluster suite's load generator pod without holding a stream open
through the Kubernetes API for the length of the run.

  k8s_loadgen.py --namespace NS -- ARG...

starts `rutli-loadgen ARG...` detached in the pod rutli-perf-loadgen, with its output going to
files under /tmp/lg there; then asks every few seconds, with short `kubectl exec` calls, whether
it has finished; then fetches its stdout and stderr and prints them as its own, and exits with
its exit code. Each `kubectl exec` is retried, so a dropped connection to the API server (seen on
a real cluster during a long run) costs a retry, not the run.

Exit codes: the load generator's own, or 3 when the rig failed: the run could not be started,
its end could not be observed, or its output could not be fetched. Standard library only.
"""

import argparse
import shlex
import subprocess
import sys
import time
import uuid

POD = "rutli-perf-loadgen"  # the first generator; --pod names another
RIG_FAILED = 3


def log(msg):
    print(f"k8s_loadgen: {msg}", file=sys.stderr, flush=True)


def kexec(ns, script, attempts=5, timeout=60, pod=POD):
    """`sh -c script` in `pod`, retried; (returncode, stdout, stderr) of the last attempt."""
    last = (255, "", "")
    for attempt in range(attempts):
        try:
            out = subprocess.run(["kubectl", "-n", ns, "exec", pod, "--", "sh", "-c", script],
                                 capture_output=True, text=True, timeout=timeout, check=False)
            last = (out.returncode, out.stdout, out.stderr)
            # 0 or the script's own answer; kubectl reports its own failures as 1 with an
            # "error:" line, or as 255.
            if out.returncode == 0 or not (out.returncode in (1, 255) and ("error" in out.stderr.lower())):
                return last
        except subprocess.TimeoutExpired:
            last = (255, "", f"kubectl exec did not return within {timeout} s")
        time.sleep(min(30, 2 ** attempt))
    return last


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--namespace", required=True)
    p.add_argument("--poll-secs", type=float, default=5.0,
                   help="longest pause between two polls; the first polls come sooner (0.5 s, doubling)")
    p.add_argument("--max-secs", type=float, default=6 * 3600, help="give up waiting after this long")
    p.add_argument("--dir", default="/tmp/lg", help="where in the pod the run's files go (an emptyDir)")
    p.add_argument("--pod", default=POD, help="the load generator pod (default: the first)")
    p.add_argument("args", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    args = a.args[1:] if a.args[:1] == ["--"] else a.args
    ns, run = a.namespace, uuid.uuid4().hex[:12]
    q = shlex.quote
    base = f"{a.dir}/{run}"
    claim, out_f, err_f, rc_f, pid_f = (q(base + x) for x in (".claim", ".out", ".err", ".rc", ".pid"))
    cmd = " ".join(q(x) for x in ["rutli-loadgen", *args])

    # Start it detached: the shell that kubectl waits for returns at once; the run's exit code
    # lands in .rc when it ends. The claim directory is created atomically before anything starts,
    # so a start retried after its answer was lost never launches a second run.
    start = (f"mkdir -p {q(a.dir)} && if mkdir {claim} 2>/dev/null; then "
             f"( {cmd} >{out_f} 2>{err_f}; echo $? >{rc_f} ) </dev/null >/dev/null 2>&1 & "
             f"echo $! >{pid_f}; fi")
    rc, _, err = kexec(ns, start, pod=a.pod)
    if rc != 0:
        log(f"could not start the load generator: {err.strip()[-500:]}")
        return RIG_FAILED

    began = time.time()
    code = None
    pause = min(0.5, a.poll_secs)
    while time.time() - began < a.max_secs:
        # Short runs (a health wait, a round of 20 signatures) are seen ending within a second;
        # long ones are polled every --poll-secs.
        time.sleep(pause)
        pause = min(pause * 2, a.poll_secs)
        rc, out, _ = kexec(ns, f"if [ -e {rc_f} ]; then cat {rc_f}; elif [ -d {claim} ]; then echo running; "
                               f"else echo lost; fi", attempts=3, timeout=30, pod=a.pod)
        answer = out.strip()
        if rc == 0 and answer.isdigit():
            code = int(answer)
            break
        if rc == 0 and answer == "lost":
            # The pod's /tmp is an emptyDir: its files vanish when the pod is replaced.
            log("the run's files are gone from the pod (was the load generator pod restarted?)")
            return RIG_FAILED
    if code is None:
        log(f"the load generator did not finish within {a.max_secs:g} s, or its end could not be observed")
        kexec(ns, f"kill $(cat {pid_f}) 2>/dev/null || true", attempts=2, pod=a.pod)
        return RIG_FAILED

    rc_err, err, _ = kexec(ns, f"cat {err_f}", pod=a.pod)
    rc_out, out, _ = kexec(ns, f"cat {out_f}", pod=a.pod)
    kexec(ns, f"rm -f {out_f} {err_f} {rc_f} {pid_f}; rmdir {claim}", attempts=2, pod=a.pod)
    if rc_out != 0 or rc_err != 0:
        log("the load generator finished, but its output could not be fetched")
        return RIG_FAILED
    sys.stderr.write(err)
    sys.stdout.write(out)
    return code


if __name__ == "__main__":
    sys.exit(main())

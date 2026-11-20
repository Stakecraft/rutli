#!/usr/bin/env python3
# Copyright 2026 StakeCraft
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

POD = "rutli-perf-loadgen"
RIG_FAILED = 3


def log(msg):
    print(f"k8s_loadgen: {msg}", file=sys.stderr, flush=True)


def kexec(ns, script, attempts=5, timeout=60):
    """`sh -c script` in the pod, retried; (returncode, stdout, stderr) of the last attempt."""
    last = (255, "", "")
    for attempt in range(attempts):
        try:
            out = subprocess.run(["kubectl", "-n", ns, "exec", POD, "--", "sh", "-c", script],
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
    p.add_argument("args", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    args = a.args[1:] if a.args[:1] == ["--"] else a.args
    ns, run = a.namespace, uuid.uuid4().hex[:12]
    base = f"{a.dir}/{run}"
    cmd = " ".join(shlex.quote(x) for x in ["rutli-loadgen", *args])

    # Start it detached: the shell that kubectl waits for returns at once; the run's exit code
    # lands in .rc when it ends. A start whose answer was lost is not repeated if it took.
    start = (f"mkdir -p {shlex.quote(a.dir)} && if [ ! -e {base}.pid ]; then "
             f"( {cmd} >{base}.out 2>{base}.err; echo $? >{base}.rc ) </dev/null >/dev/null 2>&1 & "
             f"echo $! >{base}.pid; fi")
    rc, _, err = kexec(ns, start)
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
        rc, out, _ = kexec(ns, f"cat {base}.rc 2>/dev/null || true", attempts=3, timeout=30)
        if rc == 0 and out.strip().isdigit():
            code = int(out.strip())
            break
    if code is None:
        log(f"the load generator did not finish within {a.max_secs:g} s, or its end could not be observed")
        kexec(ns, f"kill $(cat {base}.pid) 2>/dev/null || true", attempts=2)
        return RIG_FAILED

    rc_err, err, _ = kexec(ns, f"cat {base}.err")
    rc_out, out, _ = kexec(ns, f"cat {base}.out")
    kexec(ns, f"rm -f {base}.out {base}.err {base}.rc {base}.pid", attempts=2)
    if rc_out != 0 or rc_err != 0:
        log("the load generator finished, but its output could not be fetched")
        return RIG_FAILED
    sys.stderr.write(err)
    sys.stdout.write(out)
    return code


if __name__ == "__main__":
    sys.exit(main())

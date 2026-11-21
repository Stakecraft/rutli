# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""What the cluster suite's diagnostic pass (`cluster.py --diagnose`) computes, as pure functions:
reading a container's cgroup v2 files, the flush probe, and the verdicts. cluster.py collects the
inputs; tests in test_diagnose.py. Standard library only."""

import re

# Read inside a container, in one exec. The container's own cgroup is the one /proc/self/cgroup
# names (cgroup v2: "0::<path>"): "/" under a private cgroup namespace, a path below the host's
# root otherwise. Missing files print nothing; the parsers cope.
CGROUP_SCRIPT = (
    "p=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null); echo '== path'; echo \"${p:-?}\"; "
    "cd \"/sys/fs/cgroup${p}\" 2>/dev/null || exit 0; "
    "for f in cpu.stat cpu.pressure io.pressure memory.pressure io.stat memory.current cpu.max; do "
    "echo \"== $f\"; cat $f 2>/dev/null; done"
)

# Two probes on the cosigner's own data volume, in a dot-directory removed afterwards:
# - the device: 100 blocks written with O_DSYNC;
# - what one released share does, repeated: append a line to a file and fdatasync it (the journal),
#   create a new file and fsync it, then fsync its directory (the nonce marker). A run of the same
#   loop without the flushes is subtracted, so the shell's own cost of starting commands drops out.
# Times in nanoseconds from `date +%s%N`.
FSYNC_PROBE_WRITES = 100
SHARE_PROBE_ROUNDS = 50
FSYNC_PROBE_SCRIPT = (
    "d=/data/.rutli-perf-probe; mkdir -p $d || exit 1; "
    f"echo '== dd'; dd if=/dev/zero of=$d/blk bs=4096 count={FSYNC_PROBE_WRITES} oflag=dsync 2>&1; "
    f"t0=$(date +%s%N); i=0; while [ $i -lt {SHARE_PROBE_ROUNDS} ]; do "
    "echo entry >>$d/j; : >$d/m$i; i=$((i+1)); done; t1=$(date +%s%N); "
    f"i=0; while [ $i -lt {SHARE_PROBE_ROUNDS} ]; do "
    "echo entry | dd of=$d/j oflag=append conv=notrunc,fdatasync status=none; : >$d/n$i; sync $d/n$i; sync $d; "
    "i=$((i+1)); done; t2=$(date +%s%N); "
    "echo '== share'; echo \"base_ns=$((t1-t0)) flush_ns=$((t2-t1))\"; "
    "for f in $d/*; do rm -f \"$f\"; done; rmdir $d"
)

# Flushes per released share on the sign path: the journal append's sync_data, the nonce marker
# file's sync_all and its directory's sync_all.
FLUSHES_PER_SHARE = 3

# Which nodes release a share for a signature: the leader, and the t - 1 cosigners after an offset
# of the other cosigners that a hash of the intent's request id picks (#250,
# frost/cosigner/src/orchestrator.rs). Over many requests spread evenly over the leaders, each node
# leads 1/n of the signatures and is a partner in (t - 1)/(n - 1) of the others: it releases a
# share for t/n of all signatures (two thirds each with three nodes and threshold 2).
DEFAULT_THRESHOLD = 2


def share_fractions(nodes, threshold=DEFAULT_THRESHOLD, subsets=None):
    """The fraction of all signatures for which each node releases a share. `subsets`
    ({leader: node ids}): a fixed subset per leader instead of the hashed partners, leaders spread
    evenly (a cosigner older than #250 signs with the lowest other identifiers:
    {1: (1, 2), 2: (2, 1), 3: (3, 1)})."""
    nodes = list(nodes)
    if subsets:
        return {n: sum(1 for s in subsets.values() if n in s) / len(subsets) for n in nodes}
    return {n: min(1.0, threshold / len(nodes)) for n in nodes} if nodes else {}


def parse_share_probe(text, rounds=SHARE_PROBE_ROUNDS):
    """Milliseconds per released share's flushes (journal fdatasync, marker fsync, directory
    fsync) from FSYNC_PROBE_SCRIPT, the shell's own cost subtracted; None if not measured. An
    approximation: separate processes stand in for one process's calls."""
    m = re.search(r"base_ns=(\d+) flush_ns=(\d+)", text or "")
    if not m or rounds <= 0:
        return None
    base, flush = int(m.group(1)), int(m.group(2))
    return round(max(0, flush - base) / rounds / 1e6, 3)


def parse_cgroup(text):
    """The output of CGROUP_SCRIPT -> {cpu_usage_usec, cpu_throttled_usec, cpu_nr_throttled,
    cpu_some_usec, io_some_usec, io_full_usec, mem_some_usec, io_wios, io_wbytes, memory_bytes,
    cpu_quota_cores}; absent fields are left out."""
    out, section = {}, None
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("== "):
            section = line[3:]
            continue
        if not line:
            continue
        if section == "path":
            out["cgroup_path"] = line
            continue
        if section == "cpu.stat":
            k, _, v = line.partition(" ")
            if k in ("usage_usec", "throttled_usec", "nr_throttled") and v.strip().isdigit():
                out[{"usage_usec": "cpu_usage_usec", "throttled_usec": "cpu_throttled_usec",
                     "nr_throttled": "cpu_nr_throttled"}[k]] = int(v)
        elif section in ("cpu.pressure", "io.pressure", "memory.pressure"):
            m = re.match(r"(some|full)\b.*\btotal=(\d+)", line)
            if m:
                prefix = {"cpu.pressure": "cpu", "io.pressure": "io", "memory.pressure": "mem"}[section]
                out[f"{prefix}_{m.group(1)}_usec"] = int(m.group(2))
        elif section == "io.stat":
            for k, v in re.findall(r"\b(wios|wbytes)=(\d+)", line):
                out[f"io_{k}"] = out.get(f"io_{k}", 0) + int(v)
        elif section == "memory.current" and line.isdigit():
            out["memory_bytes"] = int(line)
        elif section == "cpu.max":
            quota, _, period = line.partition(" ")
            if quota.isdigit() and period.strip().isdigit() and int(period) > 0:
                out["cpu_quota_cores"] = round(int(quota) / int(period), 3)
    return out


def derive(before, after, secs):
    """What one container did between two parse_cgroup readings `secs` apart."""
    def rate(key, scale=1e6):
        if key in before and key in after and secs > 0:
            return round(max(0, after[key] - before[key]) / scale / secs, 4)
        return None

    out = {
        "cpu_cores": rate("cpu_usage_usec"),
        # Share of the time its tasks were throttled by the CPU limit / waited for CPU / for IO.
        "cpu_throttled_share": rate("cpu_throttled_usec"),
        "cpu_pressure_share": rate("cpu_some_usec"),
        "io_pressure_share": rate("io_some_usec"),
        "io_full_pressure_share": rate("io_full_usec"),
        "writes_per_sec": rate("io_wios", 1),
        "memory_mib": round(after["memory_bytes"] / 2 ** 20, 1) if "memory_bytes" in after else None,
        "cpu_quota_cores": after.get("cpu_quota_cores"),
    }
    return {k: v for k, v in out.items() if v is not None}


def parse_dd(text, writes=FSYNC_PROBE_WRITES):
    """Milliseconds per O_DSYNC write from dd's summary line ("... copied, 0.53 s, ..."), or None."""
    m = re.search(r"copied, ([0-9.]+) s", text or "")
    if not m or writes <= 0:
        return None
    return round(float(m.group(1)) / writes * 1000, 3)


def predicted_ceiling(ms_per_share, subsets=None, threshold=DEFAULT_THRESHOLD):
    """Signatures per second the flushes alone allow, from each node's measured milliseconds per
    released share ({node id: ms}), if a node's shares are flushed one after another and requests
    are spread evenly over the leaders (share_fractions: the hashed partners, or `subsets`). A node
    that serves a fraction f of all signatures caps the rate at 1000 / (ms × f); the lowest cap is
    the ceiling. An upper bound: a per-key lock, CPU or the network lower it."""
    if not ms_per_share or any(not ms or ms <= 0 for ms in ms_per_share.values()):
        return None
    share = share_fractions(ms_per_share, threshold, subsets)
    caps = [1000.0 / (ms * share[n]) for n, ms in ms_per_share.items() if share[n] > 0]
    return round(min(caps), 1) if caps else None


def knee(steps, slo_p99_ms, achieved_share=0.95):
    """The first step whose achieved rate falls below `achieved_share` of the offered one, whose
    cosigner-side p99 exceeds the SLO, or that has errors among the requests sent. Steps:
    [{factor, offered_per_sec, ok_per_sec, server_p99_ms, errors_sent}]. Returns that step's factor,
    or None if every step kept up. A step marked generator-bound, or not known not to be, says
    nothing about the cluster and is skipped."""
    for st in steps:
        if st.get("generator_bound") is not False:
            continue
        if (st.get("ok_per_sec", 0) < achieved_share * st.get("offered_per_sec", 0)
                or (st.get("server_p99_ms") or 0) > slo_p99_ms
                or st.get("errors_sent", 0) > 0):
            return st.get("factor")
    return None


def generator_bound(step, busy_share=0.8, cluster_pressure=0.1):
    """Whether a step says more about the load generators than the cluster: a generator used
    `busy_share` of its CPU limit or was throttled, or requests were never sent, while no cosigner
    waited for CPU or IO more than `cluster_pressure` of the time."""
    cosigners = step.get("cosigners", {})
    # Without every cosigner's pressure readings nothing can be concluded either way.
    if not cosigners or any("cpu_pressure_share" not in c or "io_pressure_share" not in c for c in cosigners.values()):
        return None
    gens = step.get("generators", {}).values()
    busy = any((g.get("cpu_quota_cores") and g.get("cpu_cores", 0) >= busy_share * g["cpu_quota_cores"])
               or g.get("cpu_throttled_share", 0) > 0.05 for g in gens)
    starved = busy or step.get("not_sent", 0) > 0
    calm = all(c["cpu_pressure_share"] < cluster_pressure and c["io_pressure_share"] < cluster_pressure
               for c in cosigners.values())
    return bool(starved and calm)


def keys_verdict(results, rise=1.5):
    """From [{keys, ok_per_sec}] at the same offered rate: whether throughput rises with the number
    of keys (a per-key lock) or stays flat (something shared by all keys: the volume, CPU)."""
    pts = sorted((r["keys"], r.get("ok_per_sec", 0)) for r in results if r.get("ok_per_sec") is not None)
    if len(pts) < 2 or pts[0][1] <= 0:
        return "inconclusive"
    return "rises with keys: a per-key lock" if pts[-1][1] >= rise * pts[0][1] else \
        "flat across keys: a shared limit (the volume or CPU), not a per-key lock"


def cpu_per_signature_ms(cosigners, ok_per_sec):
    """Milliseconds of CPU per signature, summed over the cosigners, at a step's achieved rate."""
    if not ok_per_sec:
        return None
    total = sum(c.get("cpu_cores", 0) for c in cosigners.values())
    return round(total / ok_per_sec * 1000, 3)

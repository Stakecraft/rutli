# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""What the cluster suite's diagnostic pass (`cluster.py --diagnose`) computes, as pure functions:
reading a container's cgroup v2 files, the flush probe, and the verdicts. cluster.py collects the
inputs; tests in test_diagnose.py. Standard library only."""

import re

# Read inside a container, in one exec. Missing files print nothing; the parsers cope.
CGROUP_SCRIPT = (
    "cd /sys/fs/cgroup 2>/dev/null || exit 0; "
    "for f in cpu.stat cpu.pressure io.pressure memory.pressure io.stat memory.current cpu.max; do "
    "echo \"== $f\"; cat $f 2>/dev/null; done"
)

# One block per write, each written with O_DSYNC (data flushed before the write returns): what one
# journal append's fsync costs on that volume. On the cosigner's own data volume, as a dot-file
# removed afterwards.
FSYNC_PROBE_WRITES = 100
FSYNC_PROBE_SCRIPT = (
    f"f=/data/.rutli-perf-fsync-probe; dd if=/dev/zero of=$f bs=4096 count={FSYNC_PROBE_WRITES} oflag=dsync 2>&1; "
    "rc=$?; rm -f $f; exit $rc"
)

# Flushes per released share on the sign path: the journal append's sync_data, the nonce marker
# file's sync_all and its directory's sync_all.
FLUSHES_PER_SHARE = 3


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


def predicted_ceiling(ms_per_flush, nodes=3, threshold=2):
    """Signatures per second the flushes alone allow, if a node's flushes run one after another:
    each node releases at most 1000 / (FLUSHES_PER_SHARE × ms) shares a second, and every signature
    takes `threshold` shares from different nodes. An upper bound; a per-key lock lowers it."""
    if not ms_per_flush or ms_per_flush <= 0:
        return None
    per_node = 1000.0 / (FLUSHES_PER_SHARE * ms_per_flush)
    return round(per_node * nodes / threshold, 1)


def knee(steps, slo_p99_ms, achieved_share=0.95):
    """The first step whose achieved rate falls below `achieved_share` of the offered one, whose
    cosigner-side p99 exceeds the SLO, or that has errors among the requests sent. Steps:
    [{factor, offered_per_sec, ok_per_sec, server_p99_ms, errors_sent}]. Returns that step's factor,
    or None if every step kept up."""
    for st in steps:
        if (st.get("ok_per_sec", 0) < achieved_share * st.get("offered_per_sec", 0)
                or (st.get("server_p99_ms") or 0) > slo_p99_ms
                or st.get("errors_sent", 0) > 0):
            return st.get("factor")
    return None


def generator_bound(step, busy_share=0.8, cluster_pressure=0.1):
    """Whether a step says more about the load generators than the cluster: a generator used
    `busy_share` of its CPU limit or was throttled, or requests were never sent, while no cosigner
    waited for CPU or IO more than `cluster_pressure` of the time."""
    gens = step.get("generators", {}).values()
    busy = any((g.get("cpu_quota_cores") and g.get("cpu_cores", 0) >= busy_share * g["cpu_quota_cores"])
               or g.get("cpu_throttled_share", 0) > 0.05 for g in gens)
    starved = busy or step.get("not_sent", 0) > 0
    calm = all(c.get("cpu_pressure_share", 0) < cluster_pressure and c.get("io_pressure_share", 0) < cluster_pressure
               for c in step.get("cosigners", {}).values())
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

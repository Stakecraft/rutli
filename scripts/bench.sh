#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# Run the micro-benchmarks of the sign path (frost/core/benches, frost/cosigner/benches) and write
# one JSON file with a number per metric, in nanoseconds per operation.
#
# Usage (from anywhere in the repository):
#   scripts/bench.sh [--quick] [--out FILE]
#
#   --quick     1 s warm-up and 2 s of measurement per benchmark instead of criterion's 3 s and
#               5 s: enough to see that everything runs, too noisy to compare runs.
#   --out FILE  where to write the JSON (default: frost/target/bench/bench.json).
#
# Environment:
#   RUTLI_BENCH_DIR  directory for the benchmarks' files (nonce markers, the sign journal). Set it
#                    to a directory on the volume type the cosigners use; the default is the
#                    system temporary directory, which on many machines is not a real disk.
#
# The numbers that involve an fsync (frost/round2, frost/nonce_marker_burn, journal/append_fsync)
# measure the disk under that directory more than the code. Compare runs only on the same machine
# and volume.
#
# Requires: cargo (stable), python3.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
quick=0
out="$REPO/frost/target/bench/bench.json"
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) quick=1; shift ;;
    --out)
      [ $# -ge 2 ] || { echo "ERROR: --out needs a file name" >&2; exit 2; }
      out="$2"; shift 2 ;;
    -h | --help) sed -n '5,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--quick] [--out FILE]" >&2; exit 2 ;;
  esac
done
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

if [ -n "${RUTLI_BENCH_DIR:-}" ] && [ ! -d "$RUTLI_BENCH_DIR" ]; then
  echo "ERROR: RUTLI_BENCH_DIR=$RUTLI_BENCH_DIR is not a directory" >&2
  exit 2
fi

# A fresh criterion directory per run: the JSON then holds exactly this run's benchmarks, never a
# stale result of a benchmark that was renamed or removed.
CRITERION_HOME="$(mktemp -d)"
export CRITERION_HOME
trap 'rm -rf "$CRITERION_HOME"' EXIT

args=()
if [ "$quick" -eq 1 ]; then
  args=(--warm-up-time 1 --measurement-time 2)
fi

cd "$REPO/frost"
cargo bench --locked \
  -p rutli-frost-core --bench sign_rounds \
  -p rutli-cosigner --bench sign_path \
  -- ${args[@]+"${args[@]}"}

commit="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]; then
  commit="$commit-dirty"
fi

mkdir -p "$(dirname "$out")"
python3 -I - "$CRITERION_HOME" "$out" "$commit" "$quick" "$(rustc --version)" <<'PY'
import json, os, platform, sys, time

home, out, commit, quick, rustc = sys.argv[1:6]
metrics, detail = {}, {}
for root, _dirs, files in os.walk(home):
    if os.path.basename(root) != "new" or "estimates.json" not in files:
        continue
    with open(os.path.join(root, "benchmark.json")) as f:
        name = json.load(f)["full_id"]
    with open(os.path.join(root, "estimates.json")) as f:
        est = json.load(f)
    mean = est["mean"]
    metrics[name] = round(mean["point_estimate"], 1)
    detail[name] = {
        "mean_ns": round(mean["point_estimate"], 1),
        "mean_low_ns": round(mean["confidence_interval"]["lower_bound"], 1),
        "mean_high_ns": round(mean["confidence_interval"]["upper_bound"], 1),
        "median_ns": round(est["median"]["point_estimate"], 1),
        "std_dev_ns": round(est["std_dev"]["point_estimate"], 1),
    }
if not metrics:
    sys.exit("ERROR: criterion wrote no results under " + home)

doc = {
    "schema": 1,
    "unit": "ns/op",
    "commit": commit,
    "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "quick": quick == "1",
    "rustc": rustc,
    "os": platform.system().lower(),
    "arch": platform.machine(),
    "bench_dir_set": bool(os.environ.get("RUTLI_BENCH_DIR")),
    # metric -> mean nanoseconds per operation
    "metrics": dict(sorted(metrics.items())),
    "detail": dict(sorted(detail.items())),
}
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")

width = max(len(n) for n in metrics)
print()
print(f"{'metric':<{width}}  {'mean':>12}  {'median':>12}")
for name in sorted(metrics):
    d = detail[name]
    print(f"{name:<{width}}  {d['mean_ns'] / 1000:>9.1f} µs  {d['median_ns'] / 1000:>9.1f} µs")
print(f"\nwrote {out}")
PY

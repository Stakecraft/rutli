#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Write quality/baseline.json from the current.json files of Quality runs: one run on main (every
# tree metric, with coverage) and one nightly run (cargo audit, image scan). Later files win for
# keys they both have.
#
#   scripts/quality/update-baseline.sh MAIN.json [NIGHTLY.json ...]
#
# Refuses a file with failed areas or with null gated metrics: the baseline must have a value for
# every gated metric, or the ratchet fails.
set -euo pipefail

[ $# -ge 1 ] || {
  echo "usage: $0 MAIN.json [NIGHTLY.json ...]" >&2
  exit 2
}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../../quality/baseline.json"

for f in "$@"; do
  failed="$(jq -r '(.failed_areas // []) | join(" ")' "$f")"
  if [ -n "$failed" ]; then
    echo "$f: areas failed ($failed); not a baseline" >&2
    exit 1
  fi
done

jq -s --slurpfile reg "$HERE/metrics.json" '
  def merge(f): map(f // {}) | add;
  (.[0] | {schema, ref, commit, dirty, generated_at})
  + { areas: (map(.areas // []) | add | unique),
      failed_areas: [],
      metrics: merge(.metrics), notes: merge(.notes), info: merge(.info), skipped: {},
      tools: merge(.tools) }
  | . as $b
  | ([$reg[0].metrics[] | select(.gate) | .key | select($b.metrics[.] == null)]) as $missing
  | if ($missing | length) > 0 then error("no value for gated metrics: \($missing | join(", "))") else . end
' "$@" >"$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "wrote quality/baseline.json from $*"

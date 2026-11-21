#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Fail if any gated metric is worse than the baseline.
#
#   scripts/quality/ratchet.sh BASELINE.json CURRENT.json
#
# Gates, directions and tolerances are in scripts/quality/metrics.json. Counts have no tolerance;
# coverage may drop by 0.5 percentage points. A gated metric that has a baseline value but none
# now (tool failed, build broken) fails too, and so does a gated metric the baseline has no value
# for, or a baseline key that metrics.json does not know (a renamed metric would otherwise stop
# being enforced without anyone noticing). QUALITY_ALLOW_MISSING_BASELINE=1 reports those two as
# SKIP instead, for local runs against a baseline from a machine with fewer tools.
# Metrics of areas that CURRENT did not run (collect.sh --only), and metrics CURRENT marks as
# skipped (coverage off on pull requests), are not compared. An area that crashed fails.
set -euo pipefail

[ $# = 2 ] || {
  echo "usage: $0 BASELINE.json CURRENT.json" >&2
  exit 2
}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

missing=FAIL
[ "${QUALITY_ALLOW_MISSING_BASELINE:-0}" = 1 ] && missing=SKIP

report="$(jq -nr --slurpfile reg "$HERE/metrics.json" --slurpfile b "$1" --slurpfile c "$2" --arg missing "$missing" '
  def fmt: if . == null then "n/a" elif . == (. | floor) then tostring else (. * 100 | round / 100 | tostring) end;
  def area: split(".")[0] | if . == "loc" then "repo" else . end;
  ($reg[0].metrics | map(.key)) as $known
  | ($c[0].areas // null) as $ran
  | ($c[0].skipped // {}) as $skipped
  | ( ($c[0].failed_areas // [])[] | "FAIL\tarea \(.)\tcrashed\t(see the collect step log)" ),
    ( ($b[0].metrics | keys[] | select(. as $k | $known | any(. == $k) | not)
       | "\($missing)\t\(.)\tbaseline key not in scripts/quality/metrics.json\t(renamed or removed metric?)"),
      # Every gated metric needs a baseline value, whichever areas this run covers.
      ($reg[0].metrics[] | select(.gate) | . as $m
       | select(($ran != null and ($ran | any(. == ($m.key | area))) | not) and $b[0].metrics[$m.key] == null)
       | "\($missing)\t\($m.key)\tn/a\t\($m.label) (no baseline value: update quality/baseline.json)"),
      ($reg[0].metrics[] | select(.gate) | . as $m
  | select($ran == null or ($ran | any(. == ($m.key | area))))
  | if $skipped[$m.key] then "SKIP\t\($m.key)\t-\t\($m.label) (\($skipped[$m.key]))" else (
    ($b[0].metrics[$m.key]) as $bv | ($c[0].metrics[$m.key]) as $cv
  | (if $bv == null then $missing
     elif $cv == null then "FAIL"
     elif $m.better == "lower" then (if $cv > $bv + $m.tolerance then "FAIL" elif $cv < $bv then "BETTER" else "ok" end)
     else (if $cv < $bv - $m.tolerance then "FAIL" elif $cv > $bv then "BETTER" else "ok" end) end) as $s
  | "\($s)\t\($m.key)\t\($bv | fmt) -> \($cv | fmt)\t\($m.label)"
    + (if $bv == null then " (no baseline value: update quality/baseline.json)"
       elif $cv == null then " (no value: \($c[0].notes[$m.key] // "missing"))"
       elif $s == "FAIL" then " (\($m.better) is better, tolerance \($m.tolerance))" else "" end)
    ) end) )
')"

printf '%s\n' "$report" | column -t -s "$(printf '\t')" 2>/dev/null || printf '%s\n' "$report"
fails="$(printf '%s\n' "$report" | grep -c '^FAIL' || true)"
better="$(printf '%s\n' "$report" | grep -c '^BETTER' || true)"
echo
if [ "$better" -gt 0 ]; then
  echo "$better gated metric(s) improved: update quality/baseline.json in this change to lock the gain in."
fi
if [ "$fails" -gt 0 ]; then
  echo "quality ratchet: $fails gated metric(s) worse than quality/baseline.json" >&2
  exit 1
fi
echo "quality ratchet: no gated metric is worse than the baseline"

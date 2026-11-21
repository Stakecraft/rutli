#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Render two collect.sh results as a Markdown comparison, one table per area.
#
#   scripts/quality/render.sh A.json B.json [TITLE]
#
# Columns: metric, A, B, delta, and "better"/"worse" by the metric's direction in metrics.json.
# Gated metrics (the ones ratchet.sh enforces) are marked with a dagger.
set -euo pipefail

[ $# -ge 2 ] || {
  echo "usage: $0 A.json B.json [TITLE]" >&2
  exit 2
}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

jq -nr --slurpfile reg "$HERE/metrics.json" --slurpfile a "$1" --slurpfile b "$2" --arg title "${3:-}" '
  def fmt: if . == null then "n/a" elif . == (. | floor) then tostring else (. * 100 | round / 100 | tostring) end;
  def delta($x; $y):
    if $x == null or $y == null then ""
    else ($y - $x) as $d | if $d == 0 then "0" elif $d > 0 then "+" + ($d | fmt) else ($d | fmt) end end;
  def verdict($m; $x; $y):
    if $x == null or $y == null or $m.better == "none" or $x == $y then ""
    elif ($m.better == "lower") == ($y < $x) then "better" else "worse" end;
  def short: .[0:12];
  def area: split(".")[0] | if . == "loc" then "repo" else . end;
  $a[0] as $A | $b[0] as $B
  # Metrics of areas neither side ran (the image scan in a tree comparison) are left out.
  | (($A.areas // null) == null or ($B.areas // null) == null) as $all
  | ($reg[0].metrics | map(select(. as $m | $all or (($A.areas + $B.areas) | any(. == ($m.key | area)))))) as $metrics
  | ($metrics | map(.area) | reduce .[] as $x ([]; if index([$x]) then . else . + [$x] end)) as $areas
  | [
      "# " + (if $title != "" then $title else "Quality report: \($A.ref) → \($B.ref)" end),
      "",
      "| | A | B |",
      "|---|---|---|",
      "| ref | `\($A.ref)` | `\($B.ref)` |",
      "| commit | `\($A.commit | short)` | `\($B.commit | short)` |",
      "| collected | \($A.generated_at) | \($B.generated_at) |",
      "",
      "† gated: CI fails a change that makes this metric worse than `quality/baseline.json`.",
      "",
      ( [ $metrics[] | . as $m | ($A.metrics[$m.key]) as $x | ($B.metrics[$m.key]) as $y
          | select(verdict($m; $x; $y) != "")
          | {v: verdict($m; $x; $y), t: "\($m.area): \($m.label) \($x | fmt) → \($y | fmt)\(if $m.gate then " †" else "" end)"} ]
        | (map(select(.v == "better")) | map(.t)) as $up
        | (map(select(.v == "worse")) | map(.t)) as $down
        | "## Summary", "",
          "\($up | length) metrics better, \($down | length) worse, the rest unchanged or not comparable.", "",
          (if ($up | length) > 0 then "**Better**", "", ($up[] | "- " + .), "" else empty end),
          (if ($down | length) > 0 then "**Worse**", "", ($down[] | "- " + .), "" else empty end) ),
      ($areas[] as $area
        | ("## " + $area), "",
          "| Metric | A | B | Δ | |",
          "|---|--:|--:|--:|---|",
          ($metrics[] | select(.area == $area) | . as $m
            | ($A.metrics[$m.key]) as $x | ($B.metrics[$m.key]) as $y
            | "| \($m.label)\(if $m.gate then " †" else "" end) | \($x | fmt) | \($y | fmt) | \(delta($x; $y)) | \(verdict($m; $x; $y)) |"),
          ""),
      ( [ $metrics[] | . as $m
          | ([["A", $A], ["B", $B]][] | select(.[1].metrics[$m.key] == null)
             | "- \(.[0]) `\(.[1].ref)`, \($m.area) \($m.label): \(.[1].notes[$m.key] // "not collected")") ]
        | if length > 0 then "## Not measured", "", .[], "" else empty end ),
      "<details><summary>Tool versions</summary>",
      "",
      "| Tool | A | B |",
      "|---|---|---|",
      ((($A.tools | keys) + ($B.tools | keys) | unique)[] as $t
        | "| \($t) | \($A.tools[$t] // "" | gsub("\\|"; "/")) | \($B.tools[$t] // "" | gsub("\\|"; "/")) |"),
      "",
      "</details>"
    ] | .[]
'

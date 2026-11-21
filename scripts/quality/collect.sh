#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Collect the quality metrics of a tree into one JSON file. Numbers only, no pass/fail:
# ratchet.sh compares them with quality/baseline.json, render.sh turns two of them into a table.
#
#   scripts/quality/collect.sh [--root DIR] [--out FILE] [--ref NAME] [--only AREA,...]
#
#   --root  tree to measure (default: this repository)
#   --out   output file (default: stdout)
#   --ref   label stored in the result (default: `git describe` of the tree)
#   --only  run only these areas (default: all but image): rust scala shell python docker actions
#           k8s proto semgrep repo audit image
#
# A metric whose tool is missing or fails is null, with the reason under "notes". Tools are taken
# from PATH; QUALITY_TOOLS_DIR/bin (see install-tools.sh) is put in front of it when set.
# QUALITY_COVERAGE=0 skips the coverage runs (Rust and Scala), QUALITY_SCALA_BUILD=0 the sbt run.
# The image area scans the released container image (QUALITY_IMAGE, default: the image of the
# last release tag) and is not part of a tree's metrics, so it only runs when asked for.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT=""
REF=""
AREAS=(rust scala shell python docker actions k8s proto semgrep repo audit)
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$(cd "$2" && pwd)" && shift 2 ;;
    --out) OUT="$2" && shift 2 ;;
    --ref) REF="$2" && shift 2 ;;
    --only) IFS=, read -r -a AREAS <<<"$2" && shift 2 ;;
    -h | --help) sed -n '4,21p' "$0" && exit 0 ;;
    *) echo "unknown argument: $1" >&2 && exit 2 ;;
  esac
done
[ -n "${QUALITY_TOOLS_DIR:-}" ] && export PATH="$QUALITY_TOOLS_DIR/bin:$PATH"
for t in jq git; do command -v "$t" >/dev/null || {
  echo "$t is required" >&2
  exit 1
}; done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export Q_ROOT="$ROOT" Q_HERE="$HERE" Q_OUT="$WORK/out" Q_WORK="$WORK/work"
mkdir -p "$Q_OUT" "$Q_WORK"

failed=()
for a in "${AREAS[@]}"; do
  [ -f "$HERE/$a.sh" ] || {
    echo "unknown area: $a" >&2
    exit 2
  }
  echo "==> $a" >&2
  start=$SECONDS
  bash "$HERE/$a.sh" || failed+=("$a")
  echo "    $a: $((SECONDS - start))s" >&2
done

commit="$(git -C "$ROOT" rev-parse HEAD)"
[ -n "$REF" ] || REF="$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo "$commit")"
dirty=false
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || dirty=true

result="$(jq -s \
  --arg ref "$REF" --arg commit "$commit" --argjson dirty "$dirty" \
  --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg failed "${failed[*]:-}" --arg areas "${AREAS[*]}" '
  {
    schema: 1,
    ref: $ref,
    commit: $commit,
    dirty: $dirty,
    generated_at: $date,
    areas: ($areas | split(" ")),
    failed_areas: ($failed | split(" ") | map(select(. != ""))),
    metrics: (map(.metrics) | add // {}),
    notes: (map(.notes) | add // {}),
    info: (map(.info) | add // {}),
    skipped: (map(.skipped // {}) | add // {}),
    tools: (map(.tools) | add // {})
  }' "$Q_OUT"/*.json)"

if [ -n "$OUT" ]; then
  printf '%s\n' "$result" >"$OUT"
  echo "wrote $OUT" >&2
else
  printf '%s\n' "$result"
fi
[ ${#failed[@]} = 0 ] || echo "areas that failed: ${failed[*]}" >&2

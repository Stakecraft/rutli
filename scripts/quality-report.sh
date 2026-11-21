#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Compare the quality metrics of two refs, e.g. the previous release and a release candidate.
#
#   scripts/quality-report.sh REF_A REF_B [--json FILE] [--title TITLE]
#
# Checks both refs out into temporary worktrees, runs scripts/quality/collect.sh (from this
# checkout, so older refs are measured the same way) on each, prints a Markdown comparison to
# stdout and writes the two results as one JSON file ({"a": ..., "b": ...}, default
# quality-report.json). Options for collect.sh (QUALITY_TOOLS_DIR, QUALITY_COVERAGE, ...) are
# taken from the environment. See docs/release-process.md, step 6.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
JSON="quality-report.json"
TITLE=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON="$2" && shift 2 ;;
    --title) TITLE="$2" && shift 2 ;;
    -h | --help) sed -n '4,13p' "$0" && exit 0 ;;
    *) ARGS+=("$1") && shift ;;
  esac
done
[ ${#ARGS[@]} = 2 ] || {
  echo "usage: $0 REF_A REF_B [--json FILE] [--title TITLE]" >&2
  exit 2
}

WORK="$(mktemp -d)"
cleanup() {
  for side in a b; do
    [ -d "$WORK/$side" ] && git -C "$REPO" worktree remove --force "$WORK/$side" >/dev/null 2>&1
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Both trees share one cargo target directory: dependencies are built once.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$WORK/target}"

i=0
for side in a b; do
  ref="${ARGS[$i]}"
  i=$((i + 1))
  commit="$(git -C "$REPO" rev-parse --verify --end-of-options "$ref^{commit}")"
  git -C "$REPO" worktree add --detach "$WORK/$side" "$commit" >/dev/null 2>&1
  echo "==> $ref ($commit)" >&2
  "$HERE/quality/collect.sh" --root "$WORK/$side" --ref "$ref" --out "$WORK/$side.json"
done

jq -n --slurpfile a "$WORK/a.json" --slurpfile b "$WORK/b.json" '{a: $a[0], b: $b[0]}' >"$JSON"
echo "wrote $JSON" >&2
"$HERE/quality/render.sh" "$WORK/a.json" "$WORK/b.json" "$TITLE"

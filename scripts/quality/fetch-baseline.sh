#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Write the baseline a Quality run compares with: the metrics of the last successful Quality run on
# main, taken from its quality-metrics artifact. Main measures itself after every merge, so the
# baseline follows main without anyone editing a file, and pull requests never conflict over it.
#
#   scripts/quality/fetch-baseline.sh MODE OUT
#
#   MODE pr       the run for the pull request's base commit (BASE_SHA) if there is one, otherwise
#                 the newest successful run on main
#   MODE main     the newest successful run on main other than this one
#   MODE nightly  the previous nightly run (cargo audit, image scan), successful or not: a new
#                 advisory is reported once, not every night until a release can fix it
#
# Needs GH_TOKEN (actions: read), GITHUB_REPOSITORY, GITHUB_RUN_ID, curl, jq, unzip. Without a
# usable run (first run, expired artifacts, API error) it falls back to the committed
# quality/baseline.json, the floor recorded at the last release. Prints where the baseline came
# from.
set -euo pipefail

[ $# = 2 ] || {
  echo "usage: $0 pr|main|nightly OUT" >&2
  exit 2
}
MODE="$1"
OUT="$2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOOR="$HERE/../../quality/baseline.json"
API="https://api.github.com/repos/${GITHUB_REPOSITORY:?}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

fallback() {
  cp "$FLOOR" "$OUT"
  echo "baseline: quality/baseline.json ($1)"
  exit 0
}

[ -n "${GH_TOKEN:-}" ] || fallback "no GH_TOKEN"
api() { curl -fsSL --retry 2 -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

case "$MODE" in
  pr | main)
    events='["push","workflow_dispatch"]'
    need=rust
    status=success
    ;;
  nightly)
    events='["schedule"]'
    need=audit
    status=completed
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac

api "$API/actions/workflows/quality.yml/runs?branch=main&status=$status&per_page=50" >"$WORK/runs.json" \
  || fallback "could not list the runs on main"

# Candidates, newest first; for a pull request the run of its base commit goes first.
jq -r --argjson events "$events" --arg self "${GITHUB_RUN_ID:-0}" --arg base "${BASE_SHA:-}" '
  [.workflow_runs[] | select(.event as $e | $events | any(. == $e)) | select((.id | tostring) != $self)]
  | (map(select(.head_sha == $base)) + map(select(.head_sha != $base)))
  | .[] | "\(.id) \(.head_sha)"' "$WORK/runs.json" | head -8 >"$WORK/candidates"

while read -r id sha; do
  url="$(api "$API/actions/runs/$id/artifacts?name=quality-metrics" \
    | jq -r '[.artifacts[] | select(.expired | not)][0].archive_download_url // empty')" || continue
  [ -n "$url" ] || continue
  api -o "$WORK/a.zip" "$url" || continue
  rm -f "$WORK/current.json"
  unzip -q -o "$WORK/a.zip" current.json -d "$WORK" 2>/dev/null || continue
  # A run that measured the areas this mode needs, with no area that crashed.
  if jq -e --arg need "$need" '((.areas // []) | any(. == $need)) and ((.failed_areas // []) | length == 0)' \
    "$WORK/current.json" >/dev/null 2>&1; then
    cp "$WORK/current.json" "$OUT"
    echo "baseline: Quality run $id on main (${sha:0:12})"
    exit 0
  fi
done <"$WORK/candidates"

fallback "no successful run on main with an artifact"

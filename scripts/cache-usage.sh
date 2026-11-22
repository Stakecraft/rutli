#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# Size of the repository's GitHub Actions cache against its 10 GB limit, by cache family and by
# ref kind (main, pull request, other). Warns at WARN_GB (default 8), fails at FAIL_GB (default 9.5):
# above the limit GitHub evicts the least recently used entries and builds go cold.
#
# Usage: scripts/cache-usage.sh          (needs gh with GH_TOKEN, actions: read; GITHUB_REPOSITORY set)
# Output: a table on stdout (and into $GITHUB_STEP_SUMMARY when set), annotations for warn and fail.
set -euo pipefail
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
warn_gb="${WARN_GB:-8}"
fail_gb="${FAIL_GB:-9.5}"

caches="$(gh api --paginate "repos/${GITHUB_REPOSITORY}/actions/caches?per_page=100" --jq '.actions_caches[]|{key,ref,size:.size_in_bytes}')"
report="$(printf '%s\n' "$caches" | jq -rs --argjson warn "$warn_gb" --argjson fail "$fail_gb" '
  def family: .key | sub("-[0-9a-f]{8,}.*$"; "") | sub("[0-9]+(\\.[0-9]+)+.*$"; "");
  def kind: if .ref == "refs/heads/main" then "main" elif (.ref | startswith("refs/pull/")) then "pull request" else "other" end;
  (map(.size) | add // 0) as $total
  | "| cache family | ref kind | entries | MB |\n| --- | --- | --- | --- |\n"
    + ( group_by([family, kind]) | map({f: (.[0] | family), k: (.[0] | kind), n: length, mb: ((map(.size) | add) / 1e6 | floor)})
        | sort_by(-.mb) | map("| \(.f) | \(.k) | \(.n) | \(.mb) |") | join("\n") )
    + "\n\nTotal: \(($total / 1e9 * 100 | floor) / 100) GB of 10 GB (warn at \($warn) GB, fail at \($fail) GB)\n"
    + "TOTAL_GB=\($total / 1e9)"')"
total="$(printf '%s\n' "$report" | sed -n 's/^TOTAL_GB=//p')"
table="$(printf '%s\n' "$report" | grep -v '^TOTAL_GB=')"
printf '%s\n' "$table"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n' "$table" >> "$GITHUB_STEP_SUMMARY"; fi
if awk -v t="$total" -v f="$fail_gb" 'BEGIN { exit !(t >= f) }'; then
  echo "::error::Actions cache is ${total} GB, at or above ${fail_gb} GB of the 10 GB limit: prune it (docs/ci-cache.md)"
  exit 1
elif awk -v t="$total" -v w="$warn_gb" 'BEGIN { exit !(t >= w) }'; then
  echo "::warning::Actions cache is ${total} GB, at or above ${warn_gb} GB of the 10 GB limit (docs/ci-cache.md)"
fi

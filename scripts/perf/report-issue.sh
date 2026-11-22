#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# Report a failed scheduled performance run: open an issue (labels type:test, prio:p1), or add a
# comment to the open issue with the same title, so a regression that lasts for weeks stays one
# issue.
#
# Usage: scripts/perf/report-issue.sh TITLE REPORT_FILE RUN_URL
#   REPORT_FILE  the report of scripts/perf/compare.py (Markdown); may be missing if the run died
#                before it wrote one.
#
# Requires: gh, with GH_TOKEN (issues: write) and GITHUB_REPOSITORY set, as in a workflow.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 TITLE REPORT_FILE RUN_URL" >&2; exit 2; }
title="$1"
report="$2"
run_url="$3"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

body="$(mktemp)"
trap 'rm -f "$body"' EXIT
{
  echo "The scheduled run failed: ${run_url}"
  echo
  if [ -s "$report" ]; then
    # GitHub limits an issue body to 65536 characters.
    head -c 60000 "$report"
  else
    echo "The run produced no report. See its log."
  fi
  echo
  echo "The JSON result and the cosigners' logs are in the run's artifacts."
} >"$body"

# shellcheck disable=SC2016 # $ENV.TITLE is jq's, not the shell's
existing="$(TITLE="$title" gh issue list --repo "$GITHUB_REPOSITORY" --state open --label type:test --limit 200 \
  --json number,title --jq 'map(select(.title == $ENV.TITLE)) | .[0].number // empty' </dev/null)" || existing=""
if [ -n "$existing" ]; then
  gh issue comment "$existing" --repo "$GITHUB_REPOSITORY" --body-file "$body"
  echo "commented on issue #$existing"
else
  gh issue create --repo "$GITHUB_REPOSITORY" --title "$title" --body-file "$body" \
    --label type:test --label prio:p1
fi

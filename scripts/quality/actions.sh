#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# GitHub Actions metrics: actionlint and zizmor findings on .github/. actionlint checks `run:`
# scripts with the shellcheck on PATH (the pinned one in CI); pyflakes is turned off so the count
# does not depend on what else is installed. zizmor runs offline (no GitHub API calls).
# Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init actions
W="$Q_WORK/actions"
cd "$Q_ROOT"

if [ ! -d .github/workflows ]; then
  q_metric actions.actionlint 0
  q_metric actions.zizmor 0
  exit 0
fi

if q_need actionlint actions.actionlint; then
  q_tool actionlint actionlint --version
  actionlint -pyflakes= -format '{{json .}}' >"$W/actionlint.json" 2>"$W/actionlint.err" || true
  if jq -e 'type == "array"' "$W/actionlint.json" >/dev/null 2>&1; then
    q_metric actions.actionlint "$(jq length "$W/actionlint.json")"
  else
    tail -5 "$W/actionlint.err" >&2
    q_null actions.actionlint "actionlint failed"
  fi
fi

if q_need zizmor actions.zizmor; then
  q_tool zizmor zizmor --version
  zizmor --offline --no-progress --format json . >"$W/zizmor.json" 2>"$W/zizmor.err" || true
  if jq -e 'type == "array"' "$W/zizmor.json" >/dev/null 2>&1; then
    q_metric actions.zizmor "$(jq length "$W/zizmor.json")"
    q_info actions.zizmor "$(jq -r 'group_by(.determinations.severity) | map("\(.[0].determinations.severity) \(length)") | join(", ")' "$W/zizmor.json")"
  else
    tail -5 "$W/zizmor.err" >&2
    q_null actions.zizmor "zizmor failed"
  fi
fi

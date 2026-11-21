#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Repository-wide metrics on a copy of the tracked files (no build output): gitleaks findings,
# typos findings, and lines of code per language (tokei). Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init repo
W="$Q_WORK/repo"
TREE="$(q_export)"

if q_need gitleaks repo.gitleaks; then
  q_tool gitleaks gitleaks version
  if gitleaks dir "$TREE" --no-banner --log-level error --exit-code 0 \
    --report-format json --report-path "$W/gitleaks.json" 2>"$W/gitleaks.err" \
    && jq -e 'type == "array"' "$W/gitleaks.json" >/dev/null 2>&1; then
    q_metric repo.gitleaks "$(jq length "$W/gitleaks.json")"
  else
    tail -5 "$W/gitleaks.err" >&2
    q_null repo.gitleaks "gitleaks failed"
  fi
fi

if q_need typos repo.typos; then
  q_tool typos typos --version
  rc=0
  typos --format json "$TREE" >"$W/typos.jsonl" 2>"$W/typos.err" || rc=$?
  # typos exits 2 when it finds typos.
  if [ "$rc" = 0 ] || [ "$rc" = 2 ]; then
    q_metric repo.typos "$(jq -R 'fromjson? | select(.type == "typo")' "$W/typos.jsonl" | jq -s length)"
  else
    tail -5 "$W/typos.err" >&2
    q_null repo.typos "typos failed (exit $rc)"
  fi
fi

# Code lines (no comments, no blanks). The Java is the generated gRPC stubs in driver/src/main/java.
LOC=(loc.rust loc.scala loc.java loc.shell loc.python loc.yaml loc.total)
if q_need tokei "${LOC[@]}"; then
  q_tool tokei tokei --version
  if tokei "$TREE" --output json >"$W/tokei.json" 2>"$W/tokei.err"; then
    code() { jq --arg l "$1" '.[$l].code // 0' "$W/tokei.json"; }
    q_metric loc.rust "$(code Rust)"
    q_metric loc.scala "$(code Scala)"
    q_metric loc.java "$(code Java)"
    sh="$(code Shell)"
    bash="$(code BASH)"
    q_metric loc.shell "$((sh + bash))"
    q_metric loc.python "$(code Python)"
    q_metric loc.yaml "$(code YAML)"
    q_metric loc.total "$(code Total)"
  else
    for k in "${LOC[@]}"; do q_null "$k" "tokei failed"; done
  fi
fi

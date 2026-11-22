#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Shell metrics: shellcheck findings by severity and the number of files shfmt would change.
# Shell files are the tracked *.sh / *.bash files and extension-less files with a sh/bash shebang.
# shfmt uses the repository's existing style: 2-space indent, indented case arms, binary operators
# may start a line (-i 2 -ci -bn). Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init shell
W="$Q_WORK/shell"
SHFMT_FLAGS=(-i 2 -ci -bn)

FILES=()
while IFS= read -r f; do
  case "${f##*/}" in
    *.sh | *.bash) FILES+=("$f") ;;
    *.*) ;;
    *) head -1 "$Q_ROOT/$f" 2>/dev/null | grep -qE '^#!.*[/ ](bash|sh)([[:space:]]|$)' && FILES+=("$f") ;;
  esac
done < <(q_files .)
q_info shell.files "${#FILES[@]} shell files"
cd "$Q_ROOT"

LEVELS=(error warning info style)
if q_need shellcheck shell.shellcheck.error shell.shellcheck.warning shell.shellcheck.info shell.shellcheck.style; then
  q_tool shellcheck sh -c 'shellcheck --version | sed -n "s/^version: //p"'
  if [ ${#FILES[@]} = 0 ]; then
    echo '{"comments":[]}' >"$W/shellcheck.json"
  else
    shellcheck -f json1 "${FILES[@]}" >"$W/shellcheck.json" 2>"$W/shellcheck.err" || true
  fi
  if jq -e '.comments' "$W/shellcheck.json" >/dev/null 2>&1; then
    for l in "${LEVELS[@]}"; do
      q_metric "shell.shellcheck.$l" "$(jq --arg l "$l" '[.comments[] | select(.level == $l)] | length' "$W/shellcheck.json")"
    done
  else
    tail -5 "$W/shellcheck.err" >&2
    for l in "${LEVELS[@]}"; do q_null "shell.shellcheck.$l" "shellcheck failed"; done
  fi
fi

if q_need shfmt shell.shfmt.unformatted_files; then
  q_tool shfmt shfmt --version
  rc=0
  if [ ${#FILES[@]} -gt 0 ]; then
    shfmt -l "${SHFMT_FLAGS[@]}" "${FILES[@]}" >"$W/shfmt.out" 2>"$W/shfmt.err" || rc=$?
  else
    : >"$W/shfmt.out"
  fi
  if [ "$rc" -le 1 ]; then
    # A file shfmt cannot parse is not listed; count it as unformatted too.
    listed="$(q_lines "$W/shfmt.out")"
    unparsed="$(q_lines "$W/shfmt.err")"
    q_metric shell.shfmt.unformatted_files "$((listed + unparsed))"
  else
    q_null shell.shfmt.unformatted_files "shfmt failed (exit $rc)"
  fi
fi

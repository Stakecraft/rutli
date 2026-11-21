#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Python metrics: ruff findings (ruff's default rules, or the repository's ruff config if one is
# added) on the tracked *.py files. Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init python
W="$Q_WORK/python"

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(q_files '*.py')
q_need ruff python.ruff || exit 0
q_tool ruff ruff --version
if [ ${#FILES[@]} = 0 ]; then
  q_metric python.ruff 0
  exit 0
fi
cd "$Q_ROOT"
ruff check --no-cache --output-format json "${FILES[@]}" >"$W/ruff.json" 2>"$W/ruff.err" || true
if jq -e 'type == "array"' "$W/ruff.json" >/dev/null 2>&1; then
  q_metric python.ruff "$(jq length "$W/ruff.json")"
else
  tail -5 "$W/ruff.err" >&2
  q_null python.ruff "ruff failed"
fi

#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Dockerfile metrics: hadolint findings on every tracked Dockerfile (Dockerfile, Dockerfile.*,
# *.Dockerfile). Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init docker
W="$Q_WORK/docker"

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(q_files . | grep -E '(^|/)(Dockerfile([.][^/]*)?|[^/]*[.]Dockerfile)$' || true)
q_need hadolint docker.hadolint || exit 0
q_tool hadolint hadolint --version
if [ ${#FILES[@]} = 0 ]; then
  q_metric docker.hadolint 0
  exit 0
fi
cd "$Q_ROOT"
hadolint --no-fail -f json "${FILES[@]}" >"$W/hadolint.json" 2>"$W/hadolint.err" || true
if jq -e 'type == "array"' "$W/hadolint.json" >/dev/null 2>&1; then
  q_metric docker.hadolint "$(jq length "$W/hadolint.json")"
  q_info docker.hadolint "$(jq -r 'group_by(.level) | map("\(.[0].level) \(length)") | join(", ")' "$W/hadolint.json")"
else
  tail -5 "$W/hadolint.err" >&2
  q_null docker.hadolint "hadolint failed"
fi

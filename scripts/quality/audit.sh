#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# cargo audit on frost/Cargo.lock: vulnerabilities, and warnings (unmaintained, unsound, yanked).
# The counts change when new advisories are published, not only when the code changes, so CI runs
# this area nightly rather than on every pull request. Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init audit
W="$Q_WORK/audit"
KEYS=(audit.vulnerabilities audit.warnings)

if [ ! -f "$Q_ROOT/frost/Cargo.lock" ]; then
  for k in "${KEYS[@]}"; do q_null "$k" "no frost/Cargo.lock"; done
  exit 0
fi
q_need cargo-audit "${KEYS[@]}" || exit 0
q_tool cargo-audit cargo-audit audit --version
cd "$Q_ROOT/frost"
cargo-audit audit --json >"$W/audit.json" 2>"$W/audit.err" || true
if jq -e '.vulnerabilities.count' "$W/audit.json" >/dev/null 2>&1; then
  q_metric audit.vulnerabilities "$(jq '.vulnerabilities.count' "$W/audit.json")"
  q_metric audit.warnings "$(jq '[.warnings // {} | .[] | length] | add // 0' "$W/audit.json")"
  q_info audit.warnings "$(jq -r '.warnings // {} | to_entries | map("\(.key) \(.value | length)") | join(", ")' "$W/audit.json")"
  q_info audit.ids "$(jq -r '[(.vulnerabilities.list // [])[].advisory.id, ((.warnings // {})[] | .[] | .advisory.id // empty)] | unique | join(" ")' "$W/audit.json")"
else
  tail -5 "$W/audit.err" >&2
  for k in "${KEYS[@]}"; do q_null "$k" "cargo audit failed"; done
fi

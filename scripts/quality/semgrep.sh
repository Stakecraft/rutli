#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Semgrep findings by severity, on a copy of the tracked files without the generated gRPC Java.
# Rules: the rust, scala, java, bash, dockerfile and yaml sets of semgrep-rules at the commit
# pinned in tools.txt (installed by install-tools.sh into QUALITY_TOOLS_DIR/semgrep-rules, or
# SEMGREP_RULES). Runs offline: no registry, no metrics, no version check. Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init semgrep
W="$Q_WORK/semgrep"
KEYS=(semgrep.error semgrep.warning semgrep.info)
RULESETS=(rust scala java bash dockerfile yaml)
RULES="${SEMGREP_RULES:-${QUALITY_TOOLS_DIR:-/nonexistent}/semgrep-rules}"

q_need semgrep "${KEYS[@]}" || exit 0
if [ ! -d "$RULES/rust" ]; then
  for k in "${KEYS[@]}"; do q_null "$k" "semgrep rules not installed (install-tools.sh semgrep-rules)"; done
  exit 0
fi
export SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off
q_tool semgrep semgrep --version
q_info semgrep.rules "semgrep-rules $(git -C "$RULES" rev-parse --short=12 HEAD 2>/dev/null || echo '?'): ${RULESETS[*]}"

TREE="$(q_export)"
CONFIGS=()
for r in "${RULESETS[@]}"; do CONFIGS+=(--config "$RULES/$r"); done
rc=0
(cd "$TREE" && semgrep scan --metrics=off --disable-version-check --no-git-ignore --json --quiet \
  "${CONFIGS[@]}" --exclude driver/src/main/java .) >"$W/semgrep.json" 2>"$W/semgrep.err" || rc=$?
if [ "$rc" != 0 ] || ! jq -e '.results' "$W/semgrep.json" >/dev/null 2>&1; then
  tail -5 "$W/semgrep.err" >&2
  for k in "${KEYS[@]}"; do q_null "$k" "semgrep failed (exit $rc)"; done
  exit 0
fi
# A rule that fails to load is level "error": the counts would be incomplete. Files semgrep cannot
# fully parse (its bash parser, Helm templates) are level "warn" and only reported.
broken="$(jq -r '[.errors[] | select(.level == "error") | .message] | first // empty' "$W/semgrep.json")"
if [ -n "$broken" ]; then
  for k in "${KEYS[@]}"; do q_null "$k" "semgrep rule error: ${broken:0:200}"; done
  exit 0
fi
for s in ERROR WARNING INFO; do
  k="semgrep.$(echo "$s" | tr '[:upper:]' '[:lower:]')"
  q_metric "$k" "$(jq --arg s "$s" '[.results[] | select(.extra.severity == $s)] | length' "$W/semgrep.json")"
done
q_info semgrep.parse_warnings "$(jq '.errors | length' "$W/semgrep.json") files semgrep could not fully parse"

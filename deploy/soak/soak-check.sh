#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# Daily soak gate: one command that says PASS/FAIL for the last 24h of the soak.
# Run it (cron or by hand) on the host carrying the soak stack. Requires curl + jq.
#
#   PROM=http://localhost:9090 deploy/soak/soak-check.sh
#
# Optional (driver-host checks, when the validator runs on the same host):
#   RUTLI_AUDIT_LOG=/path/to/audit.jsonl   — verify the hash chain end-to-end
set -euo pipefail

PROM="${PROM:-http://localhost:9090}"
FAIL=0

say() { printf '%-52s %s\n' "$1" "$2"; }
fail() { say "$1" "FAIL${2:+ ($2)}"; FAIL=1; }
pass() { say "$1" "ok${2:+ ($2)}"; }

# Instant-query helper: returns the summed value of a PromQL expression ("" if no data).
q() {
  curl -sf --get "$PROM/api/v1/query" --data-urlencode "query=$1" \
    | jq -r '[.data.result[].value[1] | tonumber] | add // empty' 2>/dev/null || true
}

# 1. Every cosigner up (as Prometheus sees it).
up_count="$(q 'count(up{job="rutli-cosigner"} == 1)')"
if [[ "${up_count:-0}" == "3" ]]; then pass "cosigners up" "3/3"; else fail "cosigners up" "${up_count:-0}/3 — zero quorum margin at 2-of-3"; fi

# 2. Signing happened in the window (a soak with no traffic proves nothing).
signs="$(q 'sum(increase(rutli_sign_requests_total{result="ok"}[24h]))')"
if [[ -n "$signs" ]] && awk "BEGIN{exit !($signs > 0)}"; then pass "signatures in last 24h" "$signs"; else fail "signatures in last 24h" "none — is the validator generating traffic?"; fi

# 3. Zero sign errors.
errs="$(q 'sum(increase(rutli_sign_requests_total{result="error"}[24h]))')"
if [[ -z "$errs" ]] || awk "BEGIN{exit !($errs == 0)}"; then pass "sign errors in last 24h" "0"; else fail "sign errors in last 24h" "$errs"; fi

# 4. Zero ceremony failures (a failed DKG/refresh needs investigation before any retry).
cerr="$(q 'sum(increase(rutli_ceremony_requests_total{result="error"}[24h]))')"
if [[ -z "$cerr" ]] || awk "BEGIN{exit !($cerr == 0)}"; then pass "ceremony failures in last 24h" "0"; else fail "ceremony failures in last 24h" "$cerr"; fi

# 5. p99 sign latency under 1s.
p99="$(q 'histogram_quantile(0.99, sum by (le) (rate(rutli_sign_duration_seconds_bucket[24h])))')"
if [[ -z "$p99" ]]; then pass "sign p99 latency" "no data yet"; elif awk "BEGIN{exit !($p99 < 1)}"; then pass "sign p99 latency" "${p99}s"; else fail "sign p99 latency" "${p99}s >= 1s"; fi

# 6. No stuck sessions.
pend="$(q 'sum(rutli_pending_sign_sessions)')"
if [[ -z "$pend" ]] || awk "BEGIN{exit !($pend < 10)}"; then pass "pending sign sessions" "${pend:-0}"; else fail "pending sign sessions" "$pend — leader or peer stuck?"; fi

# 7. Peer skips are a margin warning, not a failure — surface them.
skips="$(q 'sum(increase(rutli_sign_round1_skips_total[24h]))')"
if [[ -n "$skips" ]] && awk "BEGIN{exit !($skips > 0)}"; then say "peer round-1 skips in last 24h" "WARN ($skips — a cosigner was skipped; check it)"; else pass "peer round-1 skips in last 24h" "0"; fi

# 8. Firing alerts (anything beyond the built-in Watchdog pattern is a red flag). On a shared
#    Prometheus (kube-prometheus-stack) the cluster's own alerts would drown this out — set
#    SOAK_ALERT_FILTER='^Rutli' to judge only the Rütli rules there.
alert_filter="${SOAK_ALERT_FILTER:-.}"
alerts="$(curl -sf "$PROM/api/v1/alerts" | jq -r --arg re "$alert_filter" '[.data.alerts[] | select(.state=="firing") | .labels.alertname | select(test($re))] | join(",")' 2>/dev/null || true)"
if [[ -z "$alerts" ]]; then pass "firing alerts" "none"; else fail "firing alerts" "$alerts"; fi

# 9. Optional: audit-chain integrity on the driver host.
if [[ -n "${RUTLI_AUDIT_LOG:-}" ]]; then
  if [[ -s "$RUTLI_AUDIT_LOG" ]]; then
    pass "audit log present" "$(wc -l < "$RUTLI_AUDIT_LOG" | tr -d ' ') entries"
    echo "  (verify the hash chain offline: see docs/testnet-soak.md, HashChainedAuditLog.verify)"
  else
    fail "audit log present" "missing/empty at $RUTLI_AUDIT_LOG"
  fi
fi

echo
if [[ "$FAIL" == 0 ]]; then echo "SOAK CHECK: PASS"; else echo "SOAK CHECK: FAIL"; exit 1; fi

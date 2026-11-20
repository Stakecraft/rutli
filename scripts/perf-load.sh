#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# Load test of a three-cosigner cluster on this machine: build the working tree, bring up the mTLS
# + sealed-share cluster of deploy/frost under Docker Compose, run the scenarios of
# scripts/perf/run.py with the load generator (frost/loadgen) on the compose network, write one
# JSON file, and compare it with a previous run if one is given.
#
# Usage (from anywhere in the repository):
#   scripts/perf-load.sh [--steady-secs N] [--rate N] [--out DIR] [--previous FILE]
#
#   --steady-secs N   length of the steady stream (default 60). Hours for a release candidate.
#   --rate N          signatures per second of the steady stream (default 20).
#   --out DIR         where the results go (default: perf-out/): load.json, compare.md (the
#                     report, also printed), and the cosigners' logs.
#   --previous FILE   a load.json of an earlier run: fail if p95/p99 regressed by more than 20 %
#                     (scripts/perf/compare.py).
#
# Exit code: 0 if every scenario passed and nothing regressed, 1 otherwise, 2 on a usage error.
#
# The cluster's certificates are written to deploy/frost/certs (where the compose file mounts them
# from) and removed afterwards. Outside CI the script refuses to run if that directory exists,
# rather than replace certificates somebody generated for another purpose.
#
# Requires: docker with the compose plugin, openssl, python3. Nothing is published and no port is
# bound on the host.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

steady_secs=60
rate=20
out="$REPO/perf-out"
previous=""
while [ $# -gt 0 ]; do
  case "$1" in
    --steady-secs | --rate | --out | --previous)
      [ $# -ge 2 ] || { echo "ERROR: $1 needs a value" >&2; exit 2; }
      case "$1" in
        --steady-secs) steady_secs="$2" ;;
        --rate) rate="$2" ;;
        --out) out="$2" ;;
        --previous) previous="$2" ;;
      esac
      shift 2 ;;
    -h | --help) sed -n '5,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--steady-secs N] [--rate N] [--out DIR] [--previous FILE]" >&2; exit 2 ;;
  esac
done
case "$steady_secs" in '' | *[!0-9]* | 0) echo "ERROR: --steady-secs must be a positive integer" >&2; exit 2 ;; esac
case "$rate" in '' | *[!0-9]* | 0) echo "ERROR: --rate must be a positive integer" >&2; exit 2 ;; esac
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
if [ -n "$previous" ]; then
  case "$previous" in /*) ;; *) previous="$PWD/$previous" ;; esac
fi

COMPOSE=(docker compose -p rutli-perf
  -f deploy/frost/docker-compose.tls.yml
  -f deploy/frost/docker-compose.perf.yml)
CERTS=deploy/frost/certs
PERF_CONFIG=deploy/frost/config-tls-perf
IMAGE="rutli-perf:local"
export RUTLI_SEAL_SECRET="${RUTLI_SEAL_SECRET:-$(openssl rand -hex 32)}"
# The compose file defaults to the published image; a load test measures the working tree.
export RUTLI_COSIGNER_IMAGE="$IMAGE"
export RUTLI_PULL_POLICY="never"

if [ -e "$CERTS" ]; then
  if [ "${CI:-}" = "true" ]; then
    sudo rm -rf "$CERTS" 2>/dev/null || rm -rf "$CERTS"
  else
    echo "ERROR: $CERTS exists. This script writes a throwaway CA and certificates there and" >&2
    echo "       removes them afterwards; move the directory away first." >&2
    exit 2
  fi
fi

# The image under test must be built as the release image is: same compiler image, same base.
if ! diff <(grep '^FROM ' frost/Dockerfile) <(grep '^FROM ' frost/Dockerfile.perf) >/dev/null; then
  echo "ERROR: the FROM lines of frost/Dockerfile.perf differ from frost/Dockerfile:" >&2
  diff <(grep '^FROM ' frost/Dockerfile) <(grep '^FROM ' frost/Dockerfile.perf) >&2 || true
  exit 1
fi

mkdir -p "$out"

save_logs() {
  for svc in cosigner1 cosigner2 cosigner3; do
    "${COMPOSE[@]}" logs --no-color "$svc" >"$out/$svc.log" 2>&1 || true
  done
}
diagnose() {
  echo "==> FAILED — container state:"
  "${COMPOSE[@]}" ps -a || true
  for svc in cosigner1 cosigner2 cosigner3; do
    echo "--- $svc logs (tail) ---"
    "${COMPOSE[@]}" logs --no-color --tail=40 "$svc" 2>&1 || true
  done
}
cleanup() {
  rc=$?
  [ "$rc" -ne 0 ] && diagnose
  save_logs
  # A load generator still running (the script was interrupted).
  docker ps -aq --filter label=rutli-perf=loadgen | xargs -r docker rm -f >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  # The certs were chowned to the container uid (see below): remove them, or a persistent runner's
  # next checkout fails while cleaning the workspace.
  sudo rm -rf "$CERTS" 2>/dev/null || rm -rf "$CERTS" 2>/dev/null || true
  rm -rf "$PERF_CONFIG" 2>/dev/null || true
  return "$rc"
}
trap cleanup EXIT

# The example configs with the sign rate limit lifted (the default, 300 a minute per key, is below
# what the scenarios send), except for keys named perf-limited*: those get a ceiling the limit
# scenario can reach in seconds. scripts/perf/run.py knows the same numbers. Ceremony and sign
# intents stay as the examples have them: the load generator signs both.
echo "==> Writing the load-test configs"
rm -rf "$PERF_CONFIG"
mkdir -p "$PERF_CONFIG"
python3 - "$PERF_CONFIG" deploy/frost/config-tls/cosigner*.json <<'PY'
import json, os, sys
out = sys.argv[1]
for src in sys.argv[2:]:
    with open(src) as f:
        cfg = json.load(f)
    policy = cfg.setdefault("signing_policy", {})
    policy["sign_rate_limit_per_min"] = 0
    policy["sign_rate_limit_per_day"] = 0
    policy["rate_limits"] = [{"key_id_prefix": "perf-limited", "per_min": 120, "per_day": 100000}]
    with open(os.path.join(out, os.path.basename(src)), "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
PY

echo "==> Generating mTLS certs"
# RUTLI_PIN_CONFIGS: gen-frost-certs.sh writes the TLS key pin of each cosigner certificate it makes
# into the load-test configs (peers[].tls_spki_sha256, required with TLS) before any node starts.
RUTLI_PIN_CONFIGS="$PERF_CONFIG" scripts/gen-frost-certs.sh 3 "$CERTS"
chmod -R a+rX "$PERF_CONFIG"
# Resolve the path now: the directory is 0700, and after the chown below this user cannot enter it.
CERTS_ABS="$(cd "$CERTS" && pwd)"

# The cosigner containers run as uid 10001; the bind-mounted keys are 0600 (see
# scripts/ci-frost-tls-smoke.sh). Everything that reads them runs as the uid that owns them.
CERT_UID="$(id -u)"
if [ "$(uname -s)" = "Linux" ]; then
  if sudo chown -R 10001:10001 "$CERTS" 2>/dev/null; then
    CERT_UID=10001
  else
    chmod -R a+rX "$CERTS"
  fi
fi

echo "==> Building the image (cosigner + load generator)"
docker build -f frost/Dockerfile.perf -t "$IMAGE" frost

echo "==> Starting the cluster"
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --wait

NETWORK="$("${COMPOSE[@]}" ps -q cosigner1 | xargs docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')"

echo "==> Running the scenarios (steady stream: ${rate}/s for ${steady_secs} s)"
rc=0
PERF_COMPOSE="${COMPOSE[*]}" PERF_NETWORK="$NETWORK" PERF_IMAGE="$IMAGE" PERF_CERTS="$CERTS_ABS" PERF_CERT_UID="$CERT_UID" \
  python3 -I scripts/perf/run.py --env compose --out "$out/load.json" \
  --steady-secs "$steady_secs" --rate "$rate" \
  --commit "$(git rev-parse HEAD 2>/dev/null || echo unknown)" || rc=$?

# Always written, so there is one report to read: with a previous run it compares, without one it
# lists this run's values and failures.
if [ -f "$out/load.json" ]; then
  echo "==> Report${previous:+ (compared with $previous)}"
  python3 -I scripts/perf/compare.py --markdown "$out/compare.md" "${previous:-$out/no-previous-run.json}" "$out/load.json" || rc=1
fi

if [ "$rc" -eq 0 ]; then
  echo "==> Load test OK: $out/load.json"
else
  echo "==> Load test FAILED: see $out/load.json"
fi
exit "$rc"

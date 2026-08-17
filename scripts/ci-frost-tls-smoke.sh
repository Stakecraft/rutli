#!/usr/bin/env bash
# CI smoke: bring up the mTLS + sealed-share cosigner cluster, run Health / DKG / Sign through
# the allowlisted driver cert, and assert a plaintext client is refused at the handshake.
#
# Usage (from repo root):
#   scripts/ci-frost-tls-smoke.sh
#
# Requires: docker compose, openssl, python3. Uses the fullstorydev/grpcurl image on the compose
# network (no host port dependency for RPCs).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

COMPOSE=(docker compose -p rutli-tls-smoke
  -f deploy/frost/docker-compose.tls.yml
  -f deploy/frost/docker-compose.tls.smoke.yml)
CERTS=deploy/frost/certs
export RUTLI_SEAL_SECRET="${RUTLI_SEAL_SECRET:-$(openssl rand -hex 32)}"
# The compose file defaults to the published GHCR image with pull_policy=always — right for
# operators, wrong for CI: a smoke test must exercise the working tree, or a broken (or fixed)
# commit gets "verified" against a released image. Force a local tag and never pull.
export RUTLI_COSIGNER_IMAGE="rutli-cosigner:ci-smoke"
export RUTLI_PULL_POLICY="never"

# On failure, dump what the cluster actually did BEFORE tearing it down — otherwise a startup
# crash in CI is invisible and the logs die with the stack.
diagnose() {
  echo "==> FAILED — container state:"
  "${COMPOSE[@]}" ps -a || true
  for svc in cosigner1 cosigner2 cosigner3; do
    echo "--- $svc logs ---"
    "${COMPOSE[@]}" logs --no-color --tail=60 "$svc" 2>&1 || true
  done
}
cleanup() {
  rc=$?
  [ "$rc" -ne 0 ] && diagnose
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  return $rc
}
trap cleanup EXIT

echo "==> Generating mTLS certs"
rm -rf "$CERTS"
scripts/gen-frost-certs.sh 3 "$CERTS"

# The cosigner containers run as uid 10001. On Linux the bind-mounted certs keep the runner's
# ownership, so the 0600 keys are unreadable in-container (macOS Docker masks this, which is why
# the smoke passes locally and failed only in CI). These certs are throwaway — hand them over.
if [ "$(uname -s)" = "Linux" ]; then
  sudo chown -R 10001:10001 "$CERTS" 2>/dev/null || chmod -R a+rX "$CERTS"
fi

# Drop any leftover cluster on the same compose project / default frost ports.
docker compose -f deploy/frost/docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
docker compose -f deploy/frost/docker-compose.tls.yml down -v --remove-orphans >/dev/null 2>&1 || true

echo "==> Building and starting TLS cosigner cluster"
"${COMPOSE[@]}" up --build -d --wait

# gRPC via the compose network — avoids relying on host port binds for the assertions.
# Proto is mounted (no gRPC reflection on the cosigner).
GRPC_IMG=fullstorydev/grpcurl:v1.9.3
NETWORK="$("${COMPOSE[@]}" ps -q cosigner1 | xargs docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
CERTS_ABS="$(cd "$CERTS" && pwd)"
PROTO_ABS="$(cd frost/cosigner/proto && pwd)"
grpc() {
  docker run --rm --network "$NETWORK" \
    -v "$CERTS_ABS:/certs:ro" \
    -v "$PROTO_ABS:/proto:ro" \
    "$GRPC_IMG" \
    -cacert /certs/ca.crt -cert /certs/driver.crt -key /certs/driver.key \
    -servername rutli-cosigner \
    -import-path /proto -proto cosigner.proto \
    "$@"
}

echo "==> Health"
grpc cosigner1:9101 rutli.cosigner.v1.Signer/Health | tee /tmp/rutli-health.json
grep -q '"ok": true' /tmp/rutli-health.json

echo "==> DKG"
grpc -d '{"key_id":"ci-smoke-namespace"}' \
  cosigner1:9101 rutli.cosigner.v1.Signer/Dkg | tee /tmp/rutli-dkg.json
python3 - <<'PY'
import json, base64
r = json.load(open("/tmp/rutli-dkg.json"))
key = base64.b64decode(r["groupVerifyingKey"])
assert len(key) == 32, f"group key len {len(key)}"
print(f"group key ok ({len(key)} bytes)")
PY

echo "==> Sign (34-byte Canton digest)"
MSG_B64="$(python3 -c 'import base64; print(base64.b64encode(b"\x12\x20"+b"C"*32).decode())')"
grpc -d "{\"key_id\":\"ci-smoke-namespace\",\"message\":\"${MSG_B64}\"}" \
  cosigner1:9101 rutli.cosigner.v1.Signer/Sign | tee /tmp/rutli-sign.json
python3 - <<'PY'
import json, base64
r = json.load(open("/tmp/rutli-sign.json"))
sig = base64.b64decode(r["signature"])
assert len(sig) == 64, f"sig len {len(sig)}"
print(f"signature ok ({len(sig)} bytes)")
PY

echo "==> Plaintext client must be refused"
if docker run --rm --network "$NETWORK" "$GRPC_IMG" \
    -plaintext -max-time 5 \
    cosigner1:9101 rutli.cosigner.v1.Signer/Health >/tmp/rutli-plain.txt 2>&1; then
  echo "ERROR: plaintext Health succeeded — mTLS is not enforced"
  cat /tmp/rutli-plain.txt
  exit 1
fi
echo "plaintext refused (expected)"

echo "==> TLS smoke OK"

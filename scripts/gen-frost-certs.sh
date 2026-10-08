#!/usr/bin/env bash
# Generate a mutual-TLS trust domain for a FROST cluster: one cluster CA, a cert per cosigner, and
# a client cert for the driver and one for the operator (split ceremony verify-key: KeyStatus and
# CeremonySignTest only, via operator_allowlist). Every cert is signed by the CA (the sole trust
# anchor). Cosigner certs carry a SAN of `cosignerN` and `127.0.0.1` so they work in Docker and
# locally, and the CN `cosignerN` (N = the node's configured identifier) — the identity the Peer
# API's FetchKey and the split ceremony's request signatures rely on.
#
#   scripts/gen-frost-certs.sh [N] [OUT_DIR]      (defaults: N=3, OUT_DIR=deploy/frost/certs)
#
# Dev tooling. Production should issue these from the operator's own PKI / cert-manager, ideally
# with per-node keys generated in the node's enclave/HSM and short-lived, rotated certs.
set -euo pipefail

N="${1:-3}"
OUT="${2:-deploy/frost/certs}"
DAYS=825

mkdir -p "$OUT"
cd "$OUT"

echo "Generating cluster CA..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.crt -days "$DAYS" -subj "/CN=rutli-frost-cluster-ca/O=rutli" >/dev/null 2>&1

gen_cert() { # name  SAN-config  extendedKeyUsage
  # End-entity TLS certs: not a CA, keyUsage digitalSignature (ECDSA), and the EKU the role needs.
  # rutli-dealer refuses a recipient request signed by a cert that is a CA, or whose keyUsage /
  # extendedKeyUsage (when present) do not allow TLS signatures (frost/cosigner/src/request_auth.rs).
  local name="$1" san="$2" eku="$3"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name/O=rutli" >/dev/null 2>&1
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$name.crt" -days "$DAYS" \
    -extfile <(printf '%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$san" "$eku") \
    >/dev/null 2>&1
  # gRPC (netty/rustls) wants PKCS#8 keys.
  openssl pkcs8 -topk8 -nocrypt -in "$name.key" -out "$name.pk8.key" >/dev/null 2>&1
  mv "$name.pk8.key" "$name.key"
  rm -f "$name.csr"
}

for i in $(seq 1 "$N"); do
  echo "Generating cert for cosigner$i..."
  # Every cosigner cert carries the SHARED SAN `rutli-cosigner` in addition to its own name. The
  # driver/cosigner TLS `domain` is a single global verification name applied to every peer dial, so
  # the mesh verifies peers against this shared SAN (works regardless of the actual DNS/pod name —
  # Docker service `cosignerN`, k8s pod `cosigner-N.rutli-cosigner`, etc.).
  gen_cert "cosigner$i" "subjectAltName=DNS:rutli-cosigner,DNS:cosigner$i,DNS:cosigner-$((i-1)),DNS:localhost,IP:127.0.0.1" \
    "serverAuth,clientAuth" # a cosigner is both mTLS server and client (the mesh)
done

echo "Generating driver client cert..."
gen_cert "driver" "subjectAltName=DNS:rutli-cosigner,DNS:driver,DNS:localhost,IP:127.0.0.1" "clientAuth"

echo "Generating operator client cert..."
gen_cert "operator" "subjectAltName=DNS:operator,DNS:localhost,IP:127.0.0.1" "clientAuth"

rm -f ca.srl
chmod 600 ./*.key

# The container images run the cosigner as uid 10001. On Linux, a bind-mounted cert directory
# keeps its host ownership, so these 0600 files — owned by whoever ran this script — are
# unreadable inside the container. (Docker Desktop on macOS masks host ownership, which is why
# this only bites on Linux.) Set RUTLI_CERT_UID to hand the keys to the container user; needs
# root, so run the script under sudo, or chown afterwards.
if [ -n "${RUTLI_CERT_UID:-}" ]; then
  if chown "$RUTLI_CERT_UID" ./*.key ./*.crt 2>/dev/null; then
    echo "Chowned certs to uid $RUTLI_CERT_UID (container user)"
  else
    echo "WARNING: could not chown certs to uid $RUTLI_CERT_UID — run as root, or the cosigner" >&2
    echo "         containers will fail to read their key with Permission denied." >&2
  fi
fi
echo
echo "Wrote CA + $N cosigner certs + driver cert + operator cert to $OUT"
echo "Point each cosigner config's tls { ca_cert, cert, key } at ca.crt / cosignerN.{crt,key},"
echo "the driver's frost.tls at ca.crt / driver.{crt,key}, and the operator's verify-key config at"
echo "ca.crt / operator.{crt,key} (CN operator, listed in operator_allowlist)."

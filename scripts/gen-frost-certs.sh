#!/usr/bin/env bash
# Generate a mutual-TLS trust domain for a FROST cluster: one cluster CA, a cert per cosigner, and
# a client cert for the driver. Every cert is signed by the CA (the sole trust anchor). Cosigner
# certs carry a SAN of `cosignerN` and `127.0.0.1` so they work in Docker and locally.
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

gen_cert() { # name  SAN-config
  local name="$1" san="$2"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name/O=rutli" >/dev/null 2>&1
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$name.crt" -days "$DAYS" -extfile <(printf '%s' "$san") >/dev/null 2>&1
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
  gen_cert "cosigner$i" "subjectAltName=DNS:rutli-cosigner,DNS:cosigner$i,DNS:cosigner-$((i-1)),DNS:localhost,IP:127.0.0.1"
done

echo "Generating driver client cert..."
gen_cert "driver" "subjectAltName=DNS:rutli-cosigner,DNS:driver,DNS:localhost,IP:127.0.0.1"

rm -f ca.srl
chmod 600 ./*.key
echo
echo "Wrote CA + $N cosigner certs + driver cert to $OUT"
echo "Point each cosigner config's tls { ca_cert, cert, key } at ca.crt / cosignerN.{crt,key},"
echo "and the driver's frost.tls at ca.crt / driver.{crt,key}."

#!/usr/bin/env bash
# Generate a mutual-TLS trust domain for a FROST cluster: one cluster CA, a cert per cosigner, and
# a client cert for the driver and one for the operator (verify-key and verify-hosted: KeyStatus,
# HostedKeyStatus and CeremonySignTest only, via operator_allowlist). Every cert is signed by the CA (the sole trust
# anchor). Cosigner certs carry a SAN of `cosignerN` and `127.0.0.1` so they work in Docker and
# locally, and the CN `cosignerN` (N = the node's configured identifier) — the identity the Peer
# API's FetchKey and the split ceremony's request signatures rely on.
#
#   scripts/gen-frost-certs.sh [N] [OUT_DIR]      (defaults: N=3, OUT_DIR=deploy/frost/certs)
#
# Environment (all optional; without any of them the script behaves as it always has, except that
# it refuses to replace an existing CA — see RUTLI_FORCE):
#
#   RUTLI_CA_DIR=<dir>  Reuse the existing CA in <dir> (ca.crt + ca.key) to issue leaves, instead of
#                       minting a new CA. ca.crt is copied into OUT_DIR; ca.key never is (unless
#                       OUT_DIR is <dir> itself). E.g. re-issue one expired leaf, or the operator
#                       cert, from the escrowed CA.
#   RUTLI_CA_CN=<cn>    Common Name of a NEW CA (default `rutli-frost-cluster-ca`). Give a rotated
#                       CA a distinct one (e.g. `rutli-frost-cluster-ca-2026-10`) so the old and the
#                       new CA can be told apart in a trust bundle (docs/ca-rotation.md). Letters,
#                       digits, `.`, `_` and `-` only, at most 64 (it goes into `-subj`, where `/`,
#                       `+` or `=` would add name attributes).
#   RUTLI_CA_DAYS=<n>   Validity of a NEW CA in days (default 825). Leaves are always 825 days.
#   RUTLI_CERTS="..."   Space-separated subset of the certs to issue, among `cosigner1..N driver
#                       operator` (default: all of them).
#   RUTLI_FORCE=1       Overwrite what is already in OUT_DIR: a ca.key or a key-less ca.crt when
#                       minting a new CA, a different ca.crt when reusing one, or any leaf key
#                       about to be issued. Without it the script refuses all of these.
#   RUTLI_CERT_UID=<u>  chown the generated files to uid <u> (the container user, 10001) — below.
#
# ca.key IS THE ROOT OF THE TRUST DOMAIN. Whoever holds it can mint a `driver` cert (and sign with
# the cluster) or a `cosignerN` cert (and join the mesh). Escrow it offline (encrypted, in two
# places, outside the cluster) and delete it from working machines. Losing it is not an outage —
# the cluster keeps running on the certs it has — but no leaf can be re-issued until the whole
# cluster is moved to a new CA: docs/ca-rotation.md is the recovery.
#
# At the end the script prints the SHA-256 of ca.crt and the cluster id a cosigner derives from it
# when `cluster_id` is not pinned in its config (the first 16 hex characters).
#
# Every file is created owner-only (umask 077), so no private key is ever readable by others, not
# even between openssl writing it and the chmod; the certificates are made world-readable at the
# end (they are public).
#
# Dev tooling. Production should issue these from the operator's own PKI / cert-manager, ideally
# with per-node keys generated in the node's enclave/HSM and short-lived, rotated certs.
set -euo pipefail
umask 077

N="${1:-3}"
OUT="${2:-deploy/frost/certs}"
DAYS=825
CA_DIR="${RUTLI_CA_DIR:-}"
CA_CN="${RUTLI_CA_CN:-rutli-frost-cluster-ca}"
CA_DAYS="${RUTLI_CA_DAYS:-825}"
FORCE="${RUTLI_FORCE:-}"

die() {
  echo "gen-frost-certs: $*" >&2
  exit 1
}

case "$N" in '' | *[!0-9]* | 0) die "N must be a positive integer, got '$N'" ;; esac
case "$CA_DAYS" in '' | *[!0-9]* | 0) die "RUTLI_CA_DAYS must be a positive integer, got '$CA_DAYS'" ;; esac
[[ "$CA_CN" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] \
  || die "RUTLI_CA_CN must be 1-64 of [A-Za-z0-9._-], starting with a letter or digit, got '$CA_CN'"

# Which certs to issue. Validated before anything is written.
ALL_CERTS="$(for i in $(seq 1 "$N"); do printf 'cosigner%s ' "$i"; done)driver operator"
CERTS="${RUTLI_CERTS:-$ALL_CERTS}"
for c in $CERTS; do
  case " $ALL_CERTS " in
    *" $c "*) ;;
    *) die "RUTLI_CERTS: unknown cert '$c' (choose among: $ALL_CERTS)" ;;
  esac
done
[ -n "$(echo $CERTS)" ] || die "RUTLI_CERTS is empty"

if [ -n "$CA_DIR" ]; then
  [ -f "$CA_DIR/ca.crt" ] || die "RUTLI_CA_DIR: no ca.crt in $CA_DIR"
  [ -f "$CA_DIR/ca.key" ] || die "RUTLI_CA_DIR: no ca.key in $CA_DIR"
  CA_DIR="$(cd "$CA_DIR" && pwd -P)"
  if [ -n "${RUTLI_CA_CN:-}" ] || [ -n "${RUTLI_CA_DAYS:-}" ]; then
    echo "gen-frost-certs: note: RUTLI_CA_CN / RUTLI_CA_DAYS apply to a new CA only; ignored with RUTLI_CA_DIR" >&2
  fi
fi

mkdir -p "$OUT"
cd "$OUT"
OUT_ABS="$(pwd -P)"

# Never silently replace a leaf key: a key that is in use (or the only copy of one) would be gone.
if [ "$FORCE" != 1 ]; then
  for c in $CERTS; do
    [ -e "$c.key" ] && die "$OUT already holds $c.key — refusing to replace it. Write elsewhere, or set RUTLI_FORCE=1"
  done
fi

if [ -n "$CA_DIR" ]; then
  # Reuse: sign with the CA in CA_DIR. The key must belong to the certificate.
  CA_CRT="$CA_DIR/ca.crt"
  CA_KEY="$CA_DIR/ca.key"
  if [ "$(openssl x509 -in "$CA_CRT" -noout -pubkey)" != "$(openssl pkey -in "$CA_KEY" -pubout)" ]; then
    die "RUTLI_CA_DIR: $CA_DIR/ca.key does not belong to $CA_DIR/ca.crt"
  fi
  openssl x509 -in "$CA_CRT" -noout -checkend 0 >/dev/null || die "RUTLI_CA_DIR: the CA in $CA_DIR has expired"
  # A day of slack, so a CA minted moments ago with the default validity does not trigger it.
  if ! openssl x509 -in "$CA_CRT" -noout -checkend $(((DAYS - 1) * 86400)) >/dev/null; then
    echo "gen-frost-certs: WARNING: the CA expires before a $DAYS-day leaf would — leaves will outlive it and" >&2
    echo "                 stop verifying when it does ($(openssl x509 -in "$CA_CRT" -noout -enddate))" >&2
  fi
  if [ "$OUT_ABS" != "$CA_DIR" ]; then
    if [ -f ca.crt ] && ! cmp -s ca.crt "$CA_CRT" && [ "$FORCE" != 1 ]; then
      die "$OUT already holds a different ca.crt — refusing to mix trust domains (RUTLI_FORCE=1 overwrites it)"
    fi
    cp "$CA_CRT" ca.crt
  fi
  echo "Reusing cluster CA $(openssl x509 -in "$CA_CRT" -noout -subject) from $CA_DIR"
else
  if [ -e ca.crt ] && [ ! -e ca.key ] && [ "$FORCE" != 1 ]; then
    die "$OUT already holds a ca.crt without its ca.key (a trust domain whose key is elsewhere or lost) — refusing to replace it. Write elsewhere, or set RUTLI_FORCE=1"
  fi
  if [ -e ca.key ] && [ "$FORCE" != 1 ]; then
    die "$OUT already holds a ca.key — refusing to replace that CA (a new CA invalidates every leaf it signed). Reuse it with RUTLI_CA_DIR=$OUT, write elsewhere, or set RUTLI_FORCE=1"
  fi
  echo "Generating cluster CA ($CA_CN, $CA_DAYS days)..."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout ca.key -out ca.crt -days "$CA_DAYS" -subj "/CN=$CA_CN/O=rutli" >/dev/null 2>&1
  chmod 600 ca.key
  CA_CRT="$OUT_ABS/ca.crt"
  CA_KEY="$OUT_ABS/ca.key"
fi

gen_cert() { # name  SAN-config  extendedKeyUsage
  # End-entity TLS certs: not a CA, keyUsage digitalSignature (ECDSA), and the EKU the role needs.
  # rutli-dealer refuses a recipient request signed by a cert that is a CA, or whose keyUsage /
  # extendedKeyUsage (when present) do not allow TLS signatures (frost/cosigner/src/request_auth.rs).
  local name="$1" san="$2" eku="$3"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$name.key" -out "$name.csr" -subj "/CN=$name/O=rutli" >/dev/null 2>&1
  # A random serial instead of -CAcreateserial: no ca.srl is written next to a reused CA (whose
  # directory may be a read-only escrow restore), and leaves re-issued later never repeat one.
  openssl x509 -req -in "$name.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 16)" \
    -out "$name.crt" -days "$DAYS" \
    -extfile <(printf '%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$san" "$eku") \
    >/dev/null 2>&1
  # gRPC (netty/rustls) wants PKCS#8 keys.
  openssl pkcs8 -topk8 -nocrypt -in "$name.key" -out "$name.pk8.key" >/dev/null 2>&1
  mv "$name.pk8.key" "$name.key"
  chmod 600 "$name.key"
  rm -f "$name.csr"
}

wanted() { # name — is it in RUTLI_CERTS?
  case " $(echo $CERTS) " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

for i in $(seq 1 "$N"); do
  wanted "cosigner$i" || continue
  echo "Generating cert for cosigner$i..."
  # Every cosigner cert carries the SHARED SAN `rutli-cosigner` in addition to its own name. The
  # driver/cosigner TLS `domain` is a single global verification name applied to every peer dial, so
  # the mesh verifies peers against this shared SAN (works regardless of the actual DNS/pod name —
  # Docker service `cosignerN`, k8s pod `cosigner-N.rutli-cosigner`, etc.).
  gen_cert "cosigner$i" "subjectAltName=DNS:rutli-cosigner,DNS:cosigner$i,DNS:cosigner-$((i-1)),DNS:localhost,IP:127.0.0.1" \
    "serverAuth,clientAuth" # a cosigner is both mTLS server and client (the mesh)
done

if wanted driver; then
  echo "Generating driver client cert..."
  gen_cert "driver" "subjectAltName=DNS:rutli-cosigner,DNS:driver,DNS:localhost,IP:127.0.0.1" "clientAuth"
fi

if wanted operator; then
  echo "Generating operator client cert..."
  gen_cert "operator" "subjectAltName=DNS:operator,DNS:localhost,IP:127.0.0.1" "clientAuth"
fi

rm -f ca.srl
# Certificates are public; keys stay 0600 (umask 077 above).
chmod 644 ./*.crt

# The container images run the cosigner as uid 10001. On Linux, a bind-mounted cert directory
# keeps its host ownership, so these 0600 files — owned by whoever ran this script — are
# unreadable inside the container. (Docker Desktop on macOS masks host ownership, which is why
# this only bites on Linux.) Set RUTLI_CERT_UID to hand the keys to the container user; needs
# root, so run the script under sudo, or chown afterwards.
if [ -n "${RUTLI_CERT_UID:-}" ]; then
  # The directory too: created 0700 under umask 077, it must be traversable by the container user.
  if chown "$RUTLI_CERT_UID" . ./*.key ./*.crt 2>/dev/null; then
    echo "Chowned certs to uid $RUTLI_CERT_UID (container user)"
  else
    echo "WARNING: could not chown certs to uid $RUTLI_CERT_UID — run as root, or the cosigner" >&2
    echo "         containers will fail to read their key with Permission denied." >&2
  fi
fi

CA_SHA256="$(openssl dgst -sha256 -r ca.crt | cut -c1-64)"
echo
if [ -n "$CA_DIR" ]; then
  echo "Wrote $(echo $CERTS) to $OUT, signed by the reused CA (ca.crt copied; ca.key stays in $CA_DIR)"
else
  echo "Wrote a new CA + $(echo $CERTS) to $OUT"
  echo "ca.key is the root of this trust domain: escrow it offline and remove it from this machine."
fi
echo "Point each cosigner config's tls { ca_cert, cert, key } at ca.crt / cosignerN.{crt,key},"
echo "the driver's frost.tls at ca.crt / driver.{crt,key}, and the operator's verify-key config at"
echo "ca.crt / operator.{crt,key} (CN operator, listed in operator_allowlist)."
echo
echo "ca.crt sha256:              $CA_SHA256"
echo "cluster_id (if unpinned):   $(printf '%s' "$CA_SHA256" | cut -c1-16)"

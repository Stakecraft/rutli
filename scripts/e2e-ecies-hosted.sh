#!/usr/bin/env bash
# End-to-end: ECIES hosted keys (roadmap Track C) on a real Canton 3.6.1 participant.
#
#   CANTON_HOME=~/.cache/canton-3.6.1/canton-open-source-3.6.1 scripts/e2e-ecies-hosted.sh
#   (from the repo root; KEEP=1 keeps the work dir; SKIP_BUILD=1 reuses existing binaries)
#
# A local 2-of-3 cosigner cluster (mTLS, sealed, hosted keys) runs as native processes on
# 127.0.0.1, exactly as scripts/e2e-split-ceremony.sh does. One Canton process runs a sequencer, a
# mediator and two participants, all in memory:
#
#   participant1  crypto = KMS through the rutli driver: frost backend, hosted keys, NO delegate,
#                 key-prefix "e2e1-", encryption key spec EC P-256 / ECIES. Its namespace and
#                 signing keys are FROST, its encryption key a cluster-hosted ec-p256-ecies key.
#   participant2  plain JCE (Canton's default ECIES), the sender of what participant1 decrypts.
#
# Checks, in order:
#   A. participant1 initialises with a cluster-generated ECIES key; pings in both directions, so
#      participant2 encrypts views to that key with Canton's own JcePureCrypto and participant1
#      decrypts them through the driver (EcdhDerive + IESEngine);
#   B. "migrate without touching the encryption key": B1's throwaway Canton 3.6.1 ECIES key is
#      imported into the cluster with `import-key` (before the cluster starts), registered on
#      participant1 by KMS id (RegisterKmsEncryptionKey) — its Canton fingerprint must come out
#      identical to the one on the old node — and rotated in as participant1's encryption key;
#      pings again, now decrypting with the imported key;
#   C. the driver's audit lines show ECIES decryptions with both keys and no failure.
#
# Requires: cargo, sbt, jq, openssl, an OpenJDK 17+ (Oracle's JDK refuses Canton's unsigned
# BouncyCastle for Cipher; set CANTON_JAVA_HOME, default: Homebrew's openjdk).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CANTON_HOME:?Set CANTON_HOME to an extracted Canton 3.6.1 release}"
JAVA_HOME="${CANTON_JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}"
export JAVA_HOME
BASE_PORT="${E2E_BASE_PORT:-19300}"
CANTON_PORT="${E2E_CANTON_PORT:-15300}"
VEC="$REPO/frost/canton-key/testdata/vectors"
FP="$(jq -r '.keys[] | select(.name == "encryption") | .fingerprint' "$VEC/manifest.json")"
export E2E_EXPORT_PASSWORD
E2E_EXPORT_PASSWORD="$(jq -r .password "$VEC/manifest.json")"
PREFIX="e2e1-"
IMPORTED_ID="${PREFIX}rutli-enc-imported-${FP:4:8}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rutli-e2e-ecies.XXXXXX")"
PIDS=(0 0 0 0)

step() { printf '\n==> %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rc=$?
  for i in 1 2 3; do
    [ "${PIDS[$i]}" != 0 ] && kill "${PIDS[$i]}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    for i in 1 2 3; do
      echo "--- node$i log (tail) ---"
      tail -n 20 "$WORK/node$i.log" 2>/dev/null || true
    done
    echo "--- canton output (tail) ---"
    tail -n 60 "$WORK/canton.out" 2>/dev/null || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
  [ "$rc" -eq 0 ] && echo "==> ECIES hosted-key e2e OK"
  return "$rc"
}
trap cleanup EXIT

BIN="$REPO/frost/target/debug"
COSIGNER="$BIN/rutli-cosigner"
DRIVER_JAR="$REPO/driver/target/scala-2.13/rutli-driver.jar"
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  step "Build rutli-cosigner and the driver fat jar from the working tree"
  (cd "$REPO/frost" && cargo build ${CARGO_FLAGS:-} -p rutli-cosigner --bins)
  (cd "$REPO" && sbt -batch driver/assembly >/dev/null)
fi
[ -x "$COSIGNER" ] || fail "no $COSIGNER"
[ -f "$DRIVER_JAR" ] || fail "no $DRIVER_JAR"

step "mTLS trust domain, seal secret, cosigner configs (127.0.0.1:$((BASE_PORT + 1))..$((BASE_PORT + 3)))"
"$REPO/scripts/gen-frost-certs.sh" 3 "$WORK/certs" >/dev/null
export RUTLI_SEAL_SECRET
RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"
for i in 1 2 3; do
  jq --arg work "$WORK" --argjson base "$BASE_PORT" --arg cert "cosigner$i" '
      .listen = "127.0.0.1:\($base + .identifier)"
    | .data_dir = "\($work)/node\(.identifier)"
    | .peers |= map(.endpoint = "https://127.0.0.1:\($base + .identifier)")
    | .tls.ca_cert = "\($work)/certs/ca.crt"
    | .tls.cert = "\($work)/certs/\($cert).crt"
    | .tls.key = "\($work)/certs/\($cert).key"
    | .hosted_keys.anti_entropy_interval_secs = 10
    | del(.metrics_listen)' "$REPO/deploy/frost/config-tls/cosigner$i.json" >"$WORK/c$i.json"
done

step "B (setup). import-key: B1's Canton ECIES encryption key into node 1, before the cluster starts"
RUST_LOG=off "$COSIGNER" --config "$WORK/c1.json" import-key --in "$VEC/encryption.export-pw.bin" \
  --passphrase-env E2E_EXPORT_PASSWORD --key-id "$IMPORTED_ID" --key-prefix "$PREFIX" --expect-fingerprint "$FP" \
  | tee "$WORK/import.out"
grep -q "ec-p256-ecies" "$WORK/import.out" || fail "import-key did not report an ec-p256-ecies key"

step "Start three cosigners"
for i in 1 2 3; do
  RUST_LOG=info "$COSIGNER" --config "$WORK/c$i.json" serve >>"$WORK/node$i.log" 2>&1 &
  PIDS[$i]=$!
done
for i in 1 2 3; do
  for _ in $(seq 1 120); do
    "$COSIGNER" --config "$WORK/c$i.json" health >/dev/null 2>&1 && break
    sleep 0.25
  done
  "$COSIGNER" --config "$WORK/c$i.json" health >/dev/null 2>&1 || fail "node $i not healthy"
done

step "Canton config: sequencer1, mediator1, participant1 (rutli KMS, ECIES), participant2 (JCE)"
P=$CANTON_PORT
cat >"$WORK/canton.conf" <<EOF
canton {
  parameters.non-standard-config = yes
  features.enable-preview-commands = yes
  sequencers.sequencer1 {
    storage.type = memory
    public-api.port = $((P + 1))
    admin-api.port = $((P + 2))
    sequencer.type = BFT
  }
  mediators.mediator1 {
    storage.type = memory
    admin-api.port = $((P + 3))
  }
  participants.participant1 {
    storage.type = memory
    ledger-api.port = $((P + 11))
    admin-api.port = $((P + 12))
    http-ledger-api.port = $((P + 13))
    crypto {
      provider = kms
      kms {
        type = driver
        name = "rutli"
        config = {
          backend = "frost"
          audit-logging = true
          frost = {
            endpoints = ["127.0.0.1:$((BASE_PORT + 1))", "127.0.0.1:$((BASE_PORT + 2))", "127.0.0.1:$((BASE_PORT + 3))"]
            hosted-keys = true
            delegate = "none"
            key-prefix = "$PREFIX"
            tls = {
              ca-cert = "$WORK/certs/ca.crt"
              cert    = "$WORK/certs/driver.crt"
              key     = "$WORK/certs/driver.key"
              domain  = "rutli-cosigner"
            }
          }
        }
      }
      signing.keys.default = ec-curve-25519
      signing.algorithms.default = ed-25519
      // The point of this run: an EC P-256 encryption key in the cluster, ECIES on the wire.
      encryption.keys.default = ec-p-256
      encryption.algorithms.default = ecies-hkdf-hmac-sha-256-aes-128-cbc
    }
  }
  participants.participant2 {
    storage.type = memory
    ledger-api.port = $((P + 21))
    admin-api.port = $((P + 22))
    http-ledger-api.port = $((P + 23))
  }
}
EOF

cat >"$WORK/e2e.canton" <<EOF
import com.digitalasset.canton.crypto.{EncryptionKeySpec, KeyPurpose}

def check(ok: Boolean, what: String): Unit = if (!ok) { println("E2E-FAIL " + what); sys.exit(1) }

nodes.local.start()
bootstrap.synchronizer_local()
participant1.synchronizers.connect_local(sequencer1, alias = "da")
participant2.synchronizers.connect_local(sequencer1, alias = "da")
utils.retry_until_true(participant1.synchronizers.active("da") && participant2.synchronizers.active("da"))

def encKeys = participant1.keys.secret.list(filterPurpose = Set(KeyPurpose.Encryption))
val generated = encKeys.map(_.publicKey).collect { case k: com.digitalasset.canton.crypto.EncryptionPublicKey => k }
check(generated.size == 1, s"participant1 should hold one encryption key, has \${generated.size}")
val gen = generated.head
check(gen.keySpec == EncryptionKeySpec.EcP256, s"generated encryption key spec is \${gen.keySpec}")
println(s"E2E generated encryption key \${gen.fingerprint} spec=\${gen.keySpec}")

// A: participant2 encrypts to the cluster-generated ECIES key; participant1 decrypts through rutli.
participant2.health.ping(participant1)
participant1.health.ping(participant2)
println("E2E-A pings OK with the generated hosted ECIES key")

// B: register B1's imported Canton key by KMS id; the fingerprint must be the old node's.
val imported = participant1.keys.secret.register_kms_encryption_key("$IMPORTED_ID", name = "imported-ecies")
println(s"E2E imported encryption key \${imported.fingerprint} spec=\${imported.keySpec}")
check(imported.fingerprint.toProtoPrimitive == "$FP", s"imported fingerprint \${imported.fingerprint} != $FP")
check(imported.keySpec == EncryptionKeySpec.EcP256, s"imported spec \${imported.keySpec}")
participant1.topology.owner_to_key_mappings.rotate_key(participant1.id.member, gen, imported)
val published = participant1.topology.owner_to_key_mappings
  .list(filterKeyOwnerUid = participant1.uid.toProtoPrimitive)
  .flatMap(_.item.keys)
  .filter(_.purpose == KeyPurpose.Encryption)
check(published.map(_.fingerprint).distinct == Seq(imported.fingerprint), s"published encryption keys: \${published.map(_.fingerprint)}")
participant2.health.ping(participant1)
participant1.health.ping(participant2)
println("E2E-B pings OK with the imported Canton ECIES key")
println("E2E-DONE")
sys.exit(0)
EOF

step "Run Canton 3.6.1 ($JAVA_HOME)"
(
  cd "$WORK"
  EXTRA_CLASSPATH="$DRIVER_JAR" "$CANTON_HOME/bin/canton" run "$WORK/e2e.canton" \
    --config "$WORK/canton.conf" --no-tty --log-file-name "$WORK/canton.log" --kms-log-file-name "$WORK/canton_kms.log" \
    >"$WORK/canton.out" 2>&1
) || fail "Canton run failed"
grep -q "E2E-DONE" "$WORK/canton.out" || fail "the bootstrap script did not finish"
grep "^E2E" "$WORK/canton.out"

step "C. The driver's audit trail: ECIES decryptions with both keys, none failed"
grep -h "AUDIT decryptAsymmetric" "$WORK"/canton*.log >"$WORK/decrypts.txt" || fail "no decryptAsymmetric in the audit log"
GEN_OK="$(grep -c "algo=EciesHkdfHmacSha256Aes128Cbc.*outcome=ok" "$WORK/decrypts.txt" || true)"
IMP_OK="$(grep "keyId=$IMPORTED_ID " "$WORK/decrypts.txt" | grep -c "outcome=ok" || true)"
BAD="$(grep -c "outcome=failed" "$WORK/decrypts.txt" || true)"
echo "ECIES decryptions ok: $GEN_OK (with the imported key: $IMP_OK), failed: $BAD"
[ "$GEN_OK" -gt "$IMP_OK" ] || fail "no ECIES decryption with the generated key"
[ "$IMP_OK" -gt 0 ] || fail "no ECIES decryption with the imported key"
[ "$BAD" -eq 0 ] || fail "$BAD decryptions failed"
grep -q "every cosigner hosts non-FROST keys (.*ec-p256-ecies" "$WORK"/canton*.log || fail "the driver never saw ec-p256-ecies in Capabilities"

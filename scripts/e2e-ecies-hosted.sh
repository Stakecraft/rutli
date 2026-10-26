#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# End-to-end: ECIES hosted keys (roadmap Track C) on a real Canton 3.6.1 participant.
#
#   CANTON_HOME=~/.cache/canton-3.6.1/canton-open-source-3.6.1 scripts/e2e-ecies-hosted.sh
#   (from the repo root; KEEP=1 keeps the work dir; SKIP_BUILD=1 reuses existing binaries;
#   KEYFILE_V2_DELETES=1 adds the key-file v2 + hosted-key delete variant, E below)
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
#   C. the driver's audit lines show ECIES decryptions with both keys and no failure; with the
#      cosigner signing policy enforced (audit C2: require_intent, the driver's key ACL and pin;
#      require_ceremony_intent, so participant1's namespace DKG ran only because the driver signed a
#      ceremony intent for it, verified on every cosigner), every FROST signature was journaled
#      under a driver intent, and `audit-cross-check` finds the driver's audit log and the three
#      cosigner journals consistent;
#   D. (SKIP_DOWN=1 skips it) with cosigner 3 stopped, a participant configured for ECIES gets past
#      Canton's crypto init: the driver still advertises EcP256 because a silent cosigner does not
#      veto it. (A *fresh* participant then needs every cosigner for its namespace DKG, so D stops
#      once key generation starts; a restarted participant with existing keys would carry on.)
#   E. (KEYFILE_V2_DELETES=1) the cosigners write key-file format v2 only and refuse v1
#      (keyfile.write_version 2, accept_v1 false, one cluster_uuid; audit M4), and the driver
#      certificate holds the hosted-key delete role (hosted_keys.delete_allowlist, delete_acl to
#      this run's prefix; audit M2). After B rotates it out, Canton deletes the generated ECIES key
#      (`keys.secret.delete`): the driver signs a delete intent, every cosigner verifies it and
#      replaces the key with a tombstone; pings still work with the imported key, every key file on
#      every node (the tombstone included) is v2, and the audit cross-check still agrees.
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
V2_DELETES="${KEYFILE_V2_DELETES:-0}"
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
# The cosigner signing policy enforced (audit C2): a driver-signed intent on every signature, the
# driver's key pinned, its key ids limited to the two prefixes this script uses.
DRIVER_PIN="$(openssl x509 -in "$WORK/certs/driver.crt" -noout -pubkey | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -hex | awk '{print $NF}')"
# E: key-file v2 only (one cluster_uuid for the cluster), and the driver on the delete role for this
# run's prefix.
CLUSTER_UUID="$(uuidgen | tr 'A-Z' 'a-z')"
for i in 1 2 3; do
  jq --arg work "$WORK" --argjson base "$BASE_PORT" --arg cert "cosigner$i" --arg pin "$DRIVER_PIN" \
    --arg v2 "$V2_DELETES" --arg uuid "$CLUSTER_UUID" --arg prefix "$PREFIX" '
      .signing_policy = { require_intent: true, require_ceremony_intent: true, signer_acl_required: true,
        signer_acl: { driver: ["e2e1-", "e2e2-"] }, signer_pins: { driver: [$pin] } }
    | if $v2 == "1" then
        .keyfile = { write_version: 2, accept_v1: false, cluster_uuid: $uuid }
        | .hosted_keys.delete_allowlist = ["driver"]
        | .hosted_keys.delete_acl = { driver: [$prefix] }
      else . end
    | .listen = "127.0.0.1:\($base + .identifier)"
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
          audit-log-path = "$WORK/driver-audit.jsonl"
          frost = {
            endpoints = [
              { url = "127.0.0.1:$((BASE_PORT + 1))", tls-name = "cosigner1" },
              { url = "127.0.0.1:$((BASE_PORT + 2))", tls-name = "cosigner2" },
              { url = "127.0.0.1:$((BASE_PORT + 3))", tls-name = "cosigner3" }
            ]
            hosted-keys = true
            delegate = "none"
            key-prefix = "$PREFIX"
            tls = {
              ca-cert = "$WORK/certs/ca.crt"
              cert    = "$WORK/certs/driver.crt"
              key     = "$WORK/certs/driver.key"
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

// E: the generated key, rotated out above, deleted through the driver (a signed delete intent).
if ("$V2_DELETES" == "1") {
  participant1.keys.secret.delete(gen.fingerprint, force = true) // force: no interactive confirmation
  check(!encKeys.exists(_.publicKey.fingerprint == gen.fingerprint), s"\${gen.fingerprint} is still in participant1's store")
  participant2.health.ping(participant1)
  participant1.health.ping(participant2)
  println(s"E2E-E deleted the rotated-out key \${gen.fingerprint}; pings OK with the imported key")
}
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

step "C2. Every FROST signature carried a driver intent; the audit log and the cosigner journals agree"
SIGNED="$(cat "$WORK"/node*/journal/*/*.jsonl 2>/dev/null | grep -c '"purpose":"sign".*"signer_cn":"driver"' || true)"
[ "$SIGNED" -gt 0 ] || fail "no cosigner journaled a driver-intent signature"
NOINTENT="$(cat "$WORK"/node*/journal/*/*.jsonl | grep -c '"purpose":"no-intent"' || true)"
[ "$NOINTENT" -eq 0 ] || fail "$NOINTENT signature(s) without an intent under require_intent"
# require_ceremony_intent: every cosigner verified the driver's DKG ceremony intent.
for i in 1 2 3; do
  sed $'s/\x1b\\[[0-9;]*m//g' "$WORK/node$i.log" | grep "dkg fence: ceremony intent verified" | grep -q "requested_by=driver" \
    || fail "cosigner $i never verified a driver DKG ceremony intent"
done
"$COSIGNER" audit-cross-check --driver-audit "$WORK/driver-audit.jsonl" \
  --journal "$WORK/node1/journal" --journal "$WORK/node2/journal" --journal "$WORK/node3/journal" \
  --min-journals 2 | tee "$WORK/cross-check.txt" || fail "audit-cross-check found discrepancies"
# Every driver sign names its message (msg=), so the check matched each one by message.
COUNTS="$(sed -n 's/^driver audit: [0-9]* entries, \([0-9]*\) sign(s) (\([0-9]*\) with an intent, \([0-9]*\) with a message digest).*/\1 \2 \3/p' "$WORK/cross-check.txt")"
read -r N_SIGNS N_INTENT N_MSG <<<"$COUNTS"
[ "${N_SIGNS:-0}" -gt 0 ] && [ "$N_INTENT" = "$N_SIGNS" ] && [ "$N_MSG" = "$N_SIGNS" ] \
  || fail "not every driver sign carries intent= and msg=: $(head -1 "$WORK/cross-check.txt")"

if [ "$V2_DELETES" = 1 ]; then
  step "E. Key-file v2 only; the rotated-out key deleted through the driver, tombstoned on every node"
  grep -q "^E2E-E " "$WORK/canton.out" || fail "the Canton script did not delete the rotated-out key"
  grep -h "AUDIT deleteKey" "$WORK"/canton*.log >"$WORK/deletes.txt" || fail "no deleteKey in the driver audit"
  DELETED="$(grep "outcome=ok" "$WORK/deletes.txt" | sed -n 's/.*keyId=\([^ ]*\).*/\1/p' | sort -u)"
  [ "$(printf '%s\n' "$DELETED" | grep -c .)" -eq 1 ] || fail "expected one deleted key, got: $DELETED"
  [ "$DELETED" != "$IMPORTED_ID" ] || fail "the imported key (in use) was deleted"
  case "$DELETED" in "$PREFIX"*) ;; *) fail "deleted $DELETED outside $PREFIX" ;; esac
  ! grep -q "outcome=failed" "$WORK/deletes.txt" || fail "a deleteKey failed: $(grep outcome=failed "$WORK/deletes.txt")"
  echo "driver deleted $DELETED"
  for i in 1 2 3; do
    # Through the leader's PurgeKey or a peer's tombstone in anti-entropy, every node holds it.
    tombstoned() {
      grep -F "$DELETED" "$WORK/node$i.log" | grep -q -e "replaced by a tombstone" -e "applied a peer's tombstone"
    }
    for _ in $(seq 1 60); do tombstoned && break; sleep 0.5; done
    tombstoned || fail "node $i never tombstoned $DELETED"
    "$COSIGNER" --config "$WORK/c$i.json" keyfile status >"$WORK/keyfile$i.txt" 2>&1 || fail "keyfile status on node $i: $(cat "$WORK/keyfile$i.txt")"
    grep -q "writes v2" "$WORK/keyfile$i.txt" || fail "node $i does not write v2"
    grep -q "$DELETED" "$WORK/keyfile$i.txt" || fail "node $i holds no file for $DELETED (a tombstone stays on disk)"
    grep -q " 0 not yet v2," "$WORK/keyfile$i.txt" || fail "node $i holds key files older than v2: $(cat "$WORK/keyfile$i.txt")"
    tail -n 1 "$WORK/keyfile$i.txt"
  done
  "$COSIGNER" audit-cross-check --driver-audit "$WORK/driver-audit.jsonl" \
    --journal "$WORK/node1/journal" --journal "$WORK/node2/journal" --journal "$WORK/node3/journal" \
    --min-journals 2 >/dev/null || fail "audit-cross-check found discrepancies after the delete"
fi

if [ "${SKIP_DOWN:-0}" != 1 ]; then
  step "D. Cosigner 3 down: a participant configured for ECIES still passes Canton's crypto init"
  kill "${PIDS[3]}" 2>/dev/null || true
  wait "${PIDS[3]}" 2>/dev/null || true
  PIDS[3]=0
  sed -e 's/key-prefix = "e2e1-"/key-prefix = "e2e2-"/' "$WORK/canton.conf" >"$WORK/canton-down.conf"
  printf 'nodes.local.start()\nparticipant1.health.wait_for_initialized()\n' >"$WORK/down.canton"
  (
    cd "$WORK"
    EXTRA_CLASSPATH="$DRIVER_JAR" exec "$CANTON_HOME/bin/canton" run "$WORK/down.canton" \
      --config "$WORK/canton-down.conf" --no-tty --log-file-name "$WORK/down.log" \
      --kms-log-file-name "$WORK/down_kms.log" >"$WORK/down.out" 2>&1
  ) &
  DOWN_PID=$!
  verdict=""
  for _ in $(seq 1 240); do
    if grep -qh "not supported by the KMS" "$WORK"/down*.log "$WORK/down.out" 2>/dev/null; then verdict=refused; break; fi
    if grep -qh "initiating distributed key generation for e2e2-" "$WORK"/down*.log 2>/dev/null; then verdict=past-crypto-init; break; fi
    kill -0 "$DOWN_PID" 2>/dev/null || { verdict=exited; break; }
    sleep 0.5
  done
  pkill -P "$DOWN_PID" 2>/dev/null || true
  kill "$DOWN_PID" 2>/dev/null || true
  wait "$DOWN_PID" 2>/dev/null || true
  grep -h "no capabilities answer from" "$WORK"/down*.log | sed 's/^.* - //' | cut -c1-300 || true
  [ "$verdict" = past-crypto-init ] || fail "with cosigner 3 down the participant did not get past crypto init ($verdict)"
  grep -qh "Advertising what every answering cosigner serves: .*ec-p256-ecies" "$WORK"/down*.log \
    || fail "the driver did not advertise ec-p256-ecies with one cosigner silent"
  echo "participant passed crypto init with EcP256 advertised while cosigner 3 was down"
fi

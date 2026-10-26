#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# End-to-end: B6, carrying a participant's protocol signing, sequencer-authentication and
# encryption keys into Rütli — possible, and discouraged (docs/migration.md, "Carrying the signing
# and encryption keys (discouraged)").
#
#   CANTON_HOME=~/.cache/canton-3.6.1/canton-open-source-3.6.1 scripts/e2e-carry-protocol-keys.sh
#   (from the repo root; KEEP=1 keeps the work dir; SKIP_BUILD=1 reuses existing binaries)
#
# A local 2-of-3 cosigner cluster (mTLS, sealed, hosted keys) runs as native processes on
# 127.0.0.1, as in scripts/e2e-split-ceremony.sh. B1's throwaway Canton 3.6.1 keys
# (frost/canton-key/testdata) stand in for the old node's:
#
#   1. `signing` {signing, proof-of-ownership} and `sequencer-auth` {sequencer-auth,
#      proof-of-ownership}: one split ceremony each against the RUNNING daemons, `--expect-usage
#      protocol --namespace-fingerprint`, ids `<prefix>frost-import-sig-<fp8>` and
#      `<prefix>frost-import-seqauth-<fp8>`; a pre-B6-shaped bundle is refused by import-share;
#      import-share, verify-key --sign-test (operator cert, provenance says "protocol"), refresh,
#      verify-key again. The dealer refuses the signing key in namespace mode first.
#   2. `encryption` (ECIES P-256): import-key into node 1 with its daemon RUNNING, then
#      verify-hosted (operator cert) until anti-entropy has put it on every node.
#   3. Canton 3.6.1, one process: sequencer, mediator, participant1 (rutli KMS, frost backend,
#      hosted ECIES keys, no delegate, key-prefix "e2e6-") and participant2 (JCE). participant1
#      registers the three carried keys by KMS id — signing as `ProtocolWithProofOfOwnership`,
#      sequencer-auth as `SequencerAuthenticationOnly` (Canton adds proof-of-ownership), the usage
#      they had — and every fingerprint must be the manifest's; then its OTK is rotated onto them, pings run both ways,
#      and participant1 reconnects so it authenticates to the sequencer with the carried key.
#   4. The driver's audit trail: `sign keyId=…frost-import-sig-…` and `…frost-import-seqauth-…`
#      ok (the latter again after the reconnect: sequencer authentication), ECIES
#      `decryptAsymmetric keyId=…rutli-enc-imported-…` ok, nothing failed for any of them; then
#      verify-key and verify-hosted once more.
#   5. The cosigner signing policy (audit C2) is fully enforced throughout (require_intent, the
#      driver's key ACL and SPKI pin, refresher-only refresh, require_ceremony_intent: the driver's
#      DKGs and the refresher's refreshes carry ceremony intents): every journal entry is a driver-signed
#      intent, and `audit-cross-check` finds the driver's hash-chained audit log and the three
#      cosigner journals consistent (every ok sign journaled on at least two nodes).
#
# Requires: cargo, sbt, jq, openssl, an OpenJDK 17+ (Oracle's JDK refuses Canton's unsigned
# BouncyCastle for Cipher; set CANTON_JAVA_HOME, default: Homebrew's openjdk).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CANTON_HOME:?Set CANTON_HOME to an extracted Canton 3.6.1 release}"
JAVA_HOME="${CANTON_JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}"
export JAVA_HOME
BASE_PORT="${E2E_BASE_PORT:-19600}"
CANTON_PORT="${E2E_CANTON_PORT:-15600}"
VEC="$REPO/frost/canton-key/testdata/vectors"
fp_of() { jq -r --arg n "$1" '.keys[] | select(.name == $n) | .fingerprint' "$VEC/manifest.json"; }
NS_FP="$(fp_of namespace)"
SIG_FP="$(fp_of signing)"
SEQ_FP="$(fp_of sequencer-auth)"
ENC_FP="$(fp_of encryption)"
export E2E_EXPORT_PASSWORD
E2E_EXPORT_PASSWORD="$(jq -r .password "$VEC/manifest.json")"
PREFIX="e2e6-"
SIG_ID="${PREFIX}frost-import-sig-${SIG_FP:4:8}"
SEQ_ID="${PREFIX}frost-import-seqauth-${SEQ_FP:4:8}"
ENC_ID="${PREFIX}rutli-enc-imported-${ENC_FP:4:8}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rutli-e2e-carry.XXXXXX")"
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
  [ "$rc" -eq 0 ] && echo "==> carry-protocol-keys e2e OK"
  return "$rc"
}
trap cleanup EXIT

BIN="$REPO/frost/target/debug"
COSIGNER="$BIN/rutli-cosigner"
DEALER="$BIN/rutli-dealer"
DRIVER_JAR="$REPO/driver/target/scala-2.13/rutli-driver.jar"
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  step "Build rutli-cosigner, rutli-dealer and the driver fat jar from the working tree"
  (cd "$REPO/frost" && cargo build ${CARGO_FLAGS:-} -p rutli-cosigner --bins)
  (cd "$REPO" && sbt -batch driver/assembly >/dev/null)
fi
for f in "$COSIGNER" "$DEALER"; do [ -x "$f" ] || fail "no $f"; done
[ -f "$DRIVER_JAR" ] || fail "no $DRIVER_JAR"

step "mTLS trust domain, seal secret, configs (127.0.0.1:$((BASE_PORT + 1))..$((BASE_PORT + 3)))"
"$REPO/scripts/gen-frost-certs.sh" 3 "$WORK/certs" >/dev/null
export RUTLI_SEAL_SECRET
RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"
# The cosigner signing policy fully enforced (audit C2): every signature needs a driver-signed
# intent, the driver may use only its own prefix, its key is pinned, and only the refresher refreshes.
DRIVER_PIN="$(openssl x509 -in "$WORK/certs/driver.crt" -noout -pubkey | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -hex | awk '{print $NF}')"
mkconfig() { # node-config-name  cert-name  out
  jq --arg work "$WORK" --arg cert "$2" --argjson base "$BASE_PORT" --arg prefix "$PREFIX" --arg pin "$DRIVER_PIN" '
      .listen = "127.0.0.1:\($base + .identifier)"
    | .data_dir = "\($work)/node\(.identifier)"
    | .peers |= map(.endpoint = "https://127.0.0.1:\($base + .identifier)")
    | .tls.ca_cert = "\($work)/certs/ca.crt"
    | .tls.cert = "\($work)/certs/\($cert).crt"
    | .tls.key = "\($work)/certs/\($cert).key"
    | .hosted_keys.anti_entropy_interval_secs = 10
    | .refresh_allowlist = ["refresher"]
    | .signing_policy = { require_intent: true, require_ceremony_intent: true, require_epoch_match: true, signer_acl_required: true,
        signer_may_refresh: false, signer_acl: { driver: [$prefix] }, signer_pins: { driver: [$pin] } }
    | del(.metrics_listen)' "$REPO/deploy/frost/config-tls/$1.json" >"$3"
}
for i in 1 2 3; do mkconfig "cosigner$i" "cosigner$i" "$WORK/c$i.json"; done
# The operator role (KeyStatus, HostedKeyStatus, CeremonySignTest) runs verify-key and
# verify-hosted; the refresher (refresh_allowlist), like the refresh CronJob, runs refresh.
mkconfig cosigner1 operator "$WORK/operator.json"
mkconfig cosigner1 refresher "$WORK/refresher.json"

start() {
  RUST_LOG=info "$COSIGNER" --config "$WORK/c$1.json" serve >>"$WORK/node$1.log" 2>&1 &
  PIDS[$1]=$!
}
wait_healthy() {
  for _ in $(seq 1 120); do
    "$COSIGNER" --config "$WORK/c$1.json" health >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  fail "node $1 did not become healthy"
}
cli() { RUST_LOG=off "$COSIGNER" "$@"; }

step "Start three cosigners (mTLS, sealed, hosted keys); every step below runs against them live"
for i in 1 2 3; do start "$i"; done
for i in 1 2 3; do wait_healthy "$i"; done

step "0. The dealer refuses a protocol key id in namespace mode, before reading anything"
: >"$WORK/dummy.json"
if "$DEALER" split-key --in "$VEC/signing.export.bin" --expect-fingerprint "$SIG_FP" --key-id "$SIG_ID" \
  --threshold 2 --ca-cert "$WORK/certs/ca.crt" --recipient "$WORK/dummy.json" --out-dir "$WORK/refused" \
  --allow-swap --allow-core-handler --confirm-sas x >"$WORK/refused.out" 2>&1; then
  fail "the dealer split a protocol key in namespace mode"
fi
grep -q "protocol key id" "$WORK/refused.out" || fail "refused for the wrong reason: $(cat "$WORK/refused.out")"
[ -e "$WORK/refused" ] && fail "a refused dealer run left output behind"
echo "namespace mode on $SIG_ID -> refused"

# One split ceremony per key: share-recipient on every node, the dealer (protocol mode), import-share,
# verify-key --sign-test, refresh, verify-key again.
carry() { # vector-name  key-id  fingerprint  recorded-usage-json
  local name=$1 key_id=$2 fp=$3 recorded=$4 ceremony out sas_list digest rep
  ceremony="e2e6-${name}-$(date +%s)"
  step "1. ${name}: share-recipient on every running node (key id ${key_id})"
  local sas=()
  for i in 1 2 3; do
    out="$(cli --config "$WORK/c$i.json" share-recipient --key-id "$key_id" --ceremony-id "$ceremony" \
      --out "$WORK/$name-r$i.json")"
    sas+=("$(awk -v n="$i" '$1 == "SAS" && $3 == n {print $4}' <<<"$out")")
  done
  sas_list="$(IFS=,; echo "${sas[*]}")"

  step "   ${name}: dealer, --expect-usage protocol --namespace-fingerprint (as migration.md §8 says)"
  "$DEALER" split-key --in "$VEC/$name.export-pw.bin" --password-env E2E_EXPORT_PASSWORD \
    --expect-usage protocol --expect-fingerprint "$fp" --namespace-fingerprint "$NS_FP" --key-id "$key_id" --threshold 2 \
    --ca-cert "$WORK/certs/ca.crt" --recipient "$WORK/$name-r1.json" --recipient "$WORK/$name-r2.json" \
    --recipient "$WORK/$name-r3.json" --out-dir "$WORK/dealer-$name" --allow-swap --allow-core-handler \
    --confirm-sas "$sas_list" | grep -E "carried for|pkp digest"
  jq -e --argjson u "$recorded" --arg ns "$NS_FP" \
    '.expected_usage == "protocol" and .recorded_usage == $u and .namespace_fingerprint == $ns' \
    "$WORK/dealer-$name/dealer-record.json" >/dev/null || fail "dealer record: $(cat "$WORK/dealer-$name/dealer-record.json")"
  digest="$(jq -r .pkp_digest "$WORK/dealer-$name/dealer-record.json")"

  step "   ${name}: a pre-B6-shaped bundle is refused, then import-share on every node"
  jq 'del(.usage) | .wrapped.version = 2' "$WORK/dealer-$name/share-$key_id-node1.json" >"$WORK/$name-pre-b6.json"
  if cli --config "$WORK/c1.json" import-share --in "$WORK/$name-pre-b6.json" --expect-fingerprint "$fp" \
    --dry-run >"$WORK/$name-pre-b6.out" 2>&1; then
    fail "node 1 accepted a pre-B6 bundle"
  fi
  grep -q "pre-B6 dealer" "$WORK/$name-pre-b6.out" || fail "pre-B6 bundle refused for the wrong reason: $(cat "$WORK/$name-pre-b6.out")"
  for i in 1 2 3; do
    rep="$(cli --config "$WORK/c$i.json" import-share --in "$WORK/dealer-$name/share-$key_id-node$i.json" \
      --expect-fingerprint "$fp")"
    jq -e --arg d "$digest" --arg ns "$NS_FP" '.outcome == "installed" and .pkp_digest == $d
      and .carried_usage.expected == "protocol" and .carried_usage.namespace_fingerprint == $ns' \
      <<<"$rep" >/dev/null || fail "import on node $i: $rep"
  done

  step "   ${name}: verify-key --sign-test (operator cert)"
  rep="$(cli --config "$WORK/operator.json" verify-key --key-id "$key_id" --expect-fingerprint "$fp" --sign-test --json || true)"
  jq -e --arg d "$digest" '.ok and .pkp_digest == $d and .refresh_count == 0 and .carried_for == "protocol"
    and (.sign_test | length == 3) and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null || fail "verify-key: $rep"

  step "   ${name}: refresh (refresher cert), verify-key again"
  cli --config "$WORK/refresher.json" refresh --key-id "$key_id" >/dev/null
  rep="$(cli --config "$WORK/operator.json" verify-key --key-id "$key_id" --expect-fingerprint "$fp" --sign-test --json || true)"
  jq -e --arg d "$digest" '.ok and .pkp_digest != $d and .refresh_count == 1 and .carried_for == "protocol"
    and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null || fail "verify-key after refresh: $rep"
  echo "${name}: carried as ${key_id}, refreshed, every quorum signs under ${fp}"
}
carry signing "$SIG_ID" "$SIG_FP" '["proof-of-ownership","signing"]'
carry sequencer-auth "$SEQ_ID" "$SEQ_FP" '["proof-of-ownership","sequencer-auth"]'

step "2. import-key: the ECIES encryption key into node 1, its daemon running"
cli --config "$WORK/c1.json" import-key --in "$VEC/encryption.export-pw.bin" \
  --passphrase-env E2E_EXPORT_PASSWORD --key-id "$ENC_ID" --key-prefix "$PREFIX" --expect-fingerprint "$ENC_FP"
first="$(cli --config "$WORK/operator.json" verify-hosted --key-id "$ENC_ID" --expect-fingerprint "$ENC_FP" --json 2>/dev/null || true)"
echo "verify-hosted right after the import: ok=$(jq .ok <<<"$first"), $(jq -c '[.nodes[] | {identifier, present}]' <<<"$first")"
step "   verify-hosted (operator cert) until anti-entropy has put it on every node"
ok=""
for _ in $(seq 1 30); do
  rep="$(cli --config "$WORK/operator.json" verify-hosted --key-id "$ENC_ID" --expect-fingerprint "$ENC_FP" --json 2>/dev/null || true)"
  if jq -e '.ok' <<<"$rep" >/dev/null; then ok=1; break; fi
  sleep 2
done
[ -n "$ok" ] || fail "verify-hosted never passed: $rep"
jq -e --arg fp "$ENC_FP" '[.nodes[] | select(.present and .fingerprint == $fp)] | length == 3' <<<"$rep" >/dev/null \
  || fail "verify-hosted: $rep"
if cli --config "$WORK/operator.json" verify-hosted --key-id "$ENC_ID" --expect-fingerprint "$NS_FP" >/dev/null 2>&1; then
  fail "verify-hosted accepted the wrong fingerprint"
fi
echo "verify-hosted OK: ${ENC_ID} on 3/3 nodes, one SPKI, fingerprint ${ENC_FP}"

step "3. Canton config: sequencer1, mediator1, participant1 (rutli KMS, prefix $PREFIX), participant2 (JCE)"
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
import com.digitalasset.canton.crypto.{EncryptionPublicKey, Fingerprint, KeyPurpose, SigningKeyUsage, SigningPublicKey}
import com.digitalasset.canton.topology.admin.grpc.TopologyStoreId

def check(ok: Boolean, what: String): Unit = if (!ok) { println("E2E-FAIL " + what); sys.exit(1) }

nodes.local.start()
bootstrap.synchronizer_local()
participant1.synchronizers.connect_local(sequencer1, alias = "da")
participant2.synchronizers.connect_local(sequencer1, alias = "da")
utils.retry_until_true(participant1.synchronizers.active("da") && participant2.synchronizers.active("da"))
participant2.health.ping(participant1)

// The keys participant1 was initialised with (FROST DKG and a generated hosted ECIES key).
def mine = participant1.keys.secret.list().map(_.publicKey)
val signing0 = mine.collect { case k: SigningPublicKey => k }
val oldSig = signing0.filter(k => k.usage.contains(SigningKeyUsage.Protocol) && !k.usage.contains(SigningKeyUsage.Namespace))
val oldSeq = signing0.filter(k => k.usage.contains(SigningKeyUsage.SequencerAuthentication) && !k.usage.contains(SigningKeyUsage.Protocol) && !k.usage.contains(SigningKeyUsage.Namespace))
val oldEnc = mine.collect { case k: EncryptionPublicKey => k }
check(oldSig.size == 1 && oldSeq.size == 1 && oldEnc.size == 1, s"initial keys: signing \${oldSig.size}, seq-auth \${oldSeq.size}, encryption \${oldEnc.size}")

// The runbook's gate before a split (migration.md §8), here on participant1: no namespace delegation
// in its authorized store or on the synchronizer names a carried key as its target.
val syncId = participant1.synchronizers.list_connected().head.physicalSynchronizerId.logical
for (fp <- Seq("$SIG_FP", "$SEQ_FP")) {
  val target = Some(Fingerprint.tryFromString(fp))
  val delegations = participant1.topology.namespace_delegations.list(store = TopologyStoreId.Authorized, filterTargetKey = target) ++
    participant1.topology.namespace_delegations.list(store = TopologyStoreId.Synchronizer(syncId), filterTargetKey = target)
  check(delegations.isEmpty, s"\$fp is the target of a namespace delegation: \$delegations")
}
println("E2E-GATE no namespace delegation targets a carried key")

// Register the carried keys by KMS id, with the usage they had on the old node (never namespace).
// Canton adds proof-of-ownership to every non-namespace key itself (Signing.scala:943-947, 1336).
val sig = participant1.keys.secret.register_kms_signing_key("$SIG_ID", SigningKeyUsage.ProtocolWithProofOfOwnership, name = "carried-signing")
val seq = participant1.keys.secret.register_kms_signing_key("$SEQ_ID", SigningKeyUsage.SequencerAuthenticationOnly, name = "carried-sequencer-auth")
check(sig.usage.contains(SigningKeyUsage.Protocol) && !sig.usage.contains(SigningKeyUsage.Namespace), s"signing usage \${sig.usage}")
check(seq.usage.contains(SigningKeyUsage.SequencerAuthentication) && !seq.usage.contains(SigningKeyUsage.Protocol), s"sequencer-auth usage \${seq.usage}")
val enc = participant1.keys.secret.register_kms_encryption_key("$ENC_ID", name = "carried-encryption")
println(s"E2E registered sig=\${sig.fingerprint} seq=\${seq.fingerprint} enc=\${enc.fingerprint}")
check(sig.fingerprint.toProtoPrimitive == "$SIG_FP", s"signing fingerprint \${sig.fingerprint} != $SIG_FP")
check(seq.fingerprint.toProtoPrimitive == "$SEQ_FP", s"sequencer-auth fingerprint \${seq.fingerprint} != $SEQ_FP")
check(enc.fingerprint.toProtoPrimitive == "$ENC_FP", s"encryption fingerprint \${enc.fingerprint} != $ENC_FP")

// Rotate participant1's OTK onto them (each new key proves ownership: a FROST sign / an ECIES key).
participant1.topology.owner_to_key_mappings.rotate_key(participant1.id.member, oldSig.head, sig)
participant1.topology.owner_to_key_mappings.rotate_key(participant1.id.member, oldSeq.head, seq)
participant1.topology.owner_to_key_mappings.rotate_key(participant1.id.member, oldEnc.head, enc)
val published = participant1.topology.owner_to_key_mappings
  .list(filterKeyOwnerUid = participant1.uid.toProtoPrimitive)
  .flatMap(_.item.keys)
  .map(_.fingerprint.toProtoPrimitive)
  .toSet
check(published == Set("$SIG_FP", "$SEQ_FP", "$ENC_FP"), s"published OTK keys: \$published")
println("E2E-OTK rotated onto the carried keys")

participant2.health.ping(participant1)
participant1.health.ping(participant2)
println("E2E-PING OK with the carried signing and encryption keys")

// A fresh sequencer connection authenticates with the carried sequencer-auth key.
participant1.synchronizers.disconnect("da")
participant1.synchronizers.reconnect("da")
utils.retry_until_true(participant1.synchronizers.active("da"))
participant1.health.ping(participant2)
println("E2E-RECONNECT OK")
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

step "4. The driver's audit trail: the carried keys sign and decrypt, nothing failed"
grep -h "AUDIT " "$WORK"/canton*.log >"$WORK/audit.txt" || fail "no audit lines"
count() { grep -F "$1" "$WORK/audit.txt" | grep -c "$2" || true; }
SIG_OK="$(count "AUDIT sign keyId=$SIG_ID " "outcome=ok")"
SEQ_OK="$(count "AUDIT sign keyId=$SEQ_ID " "outcome=ok")"
ENC_OK="$(count "AUDIT decryptAsymmetric keyId=$ENC_ID " "outcome=ok")"
BAD="$(grep -E "keyId=($SIG_ID|$SEQ_ID|$ENC_ID) " "$WORK/audit.txt" | grep -c "outcome=failed" || true)"
echo "sign ok: $SIG_ID $SIG_OK, $SEQ_ID $SEQ_OK; ECIES decrypt ok: $ENC_ID $ENC_OK; failed: $BAD"
[ "$SIG_OK" -gt 0 ] || fail "no successful sign with $SIG_ID"
[ "$SEQ_OK" -gt 0 ] || fail "no successful sign with $SEQ_ID"
[ "$ENC_OK" -gt 0 ] || fail "no successful ECIES decryption with $ENC_ID"
[ "$BAD" -eq 0 ] || fail "$BAD operations failed with a carried key"
# The first sequencer-auth sign is the key's proof of ownership in the OTK rotation; one after the
# reconnect is participant1 authenticating to the sequencer with the carried key.
DISC_TS="$(grep -h "Disconnecting from Synchronizer 'da'" "$WORK/canton.log" | grep participant1 | head -1 | cut -c1-23)"
[ -n "$DISC_TS" ] || fail "no disconnect of participant1 in the Canton log"
SEQ_AFTER="$(grep -hF "AUDIT sign keyId=$SEQ_ID " "$WORK"/canton*.log | grep "outcome=ok" \
  | awk -v t="$DISC_TS" 'substr($0, 1, 23) > t' | wc -l | tr -d ' ')"
[ "$SEQ_AFTER" -gt 0 ] || fail "participant1 did not authenticate to the sequencer with $SEQ_ID after reconnecting"
echo "sequencer authentication with $SEQ_ID after the reconnect at $DISC_TS: $SEQ_AFTER sign(s)"

step "   verify-key and verify-hosted still pass after Canton used the keys"
for pair in "$SIG_ID:$SIG_FP" "$SEQ_ID:$SEQ_FP"; do
  cli --config "$WORK/operator.json" verify-key --key-id "${pair%%:*}" --expect-fingerprint "${pair##*:}" >/dev/null \
    || fail "verify-key ${pair%%:*} after the Canton run"
done
cli --config "$WORK/operator.json" verify-hosted --key-id "$ENC_ID" --expect-fingerprint "$ENC_FP" >/dev/null \
  || fail "verify-hosted after the Canton run"

step "5. Every signature carried a driver intent; the driver audit log and the cosigner journals agree"
for i in 1 2 3; do
  n="$(cat "$WORK"/node$i/journal/*/*.jsonl 2>/dev/null | grep -c '"purpose":"sign".*"signer_cn":"driver"' || true)"
  echo "node $i journaled $n signature(s) under a driver intent"
done
NOINTENT="$(cat "$WORK"/node*/journal/*/*.jsonl | grep -c '"purpose":"no-intent"' || true)"
[ "$NOINTENT" -eq 0 ] || fail "$NOINTENT signature(s) without an intent under require_intent"
grep -q 'intent=[0-9a-f]\{32\}' "$WORK/driver-audit.jsonl" || fail "the driver audit log names no intent"
"$COSIGNER" audit-cross-check --driver-audit "$WORK/driver-audit.jsonl" \
  --journal "$WORK/node1/journal" --journal "$WORK/node2/journal" --journal "$WORK/node3/journal" \
  --min-journals 2 || fail "audit-cross-check found discrepancies"

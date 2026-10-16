#!/usr/bin/env bash
# End-to-end: the split ceremony (docs/split-ceremony.md) on a local 2-of-3 cosigner cluster with
# mutual TLS and sealed shares — the deploy/frost/config-tls configs, run as native processes on
# 127.0.0.1 from this working tree (no Docker, no image pulls, no network).
#
#   scripts/e2e-split-ceremony.sh          (from the repo root; KEEP=1 keeps the work dir)
#
# Imports B1's throwaway Canton 3.6.1 namespace key (frost/canton-key/testdata) and checks, in
# order: DKG on the import id is refused (ALREADY_EXISTS) before and after; share-recipient on the
# running nodes; the dealer; import-share --dry-run then for real; an identical re-import is a
# no-op; the startup warning for an unrefreshed dealt key; verify-key --sign-test; refresh by the
# refresher role (the driver's refresh refused: signer_may_refresh off, audit C2); verify-key again
# (new digest, refresh count 1); a re-import after refresh is refused; restart of every node then
# verify-key; a Sign with one node down and no signing intent (accepted: require_intent off, the
# rolling-upgrade mode, journaled as no-intent), verified independently by OpenSSL; then
# require_intent on: the same intent-less Sign is refused, and verify-key --sign-test still passes.
#
# Requires: cargo, openssl (3.x, for Ed25519 verify), jq, grpcurl.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_PORT="${E2E_BASE_PORT:-19100}"
VEC="$REPO/frost/canton-key/testdata/vectors"
FP="$(jq -r '.keys[] | select(.name == "namespace") | .fingerprint' "$VEC/manifest.json")"
export E2E_EXPORT_PASSWORD
E2E_EXPORT_PASSWORD="$(jq -r .password "$VEC/manifest.json")"
KEY_ID="frost-import-${FP:4:8}"
CEREMONY="e2e-$(date +%s)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rutli-e2e-split.XXXXXX")"
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
      tail -n 30 "$WORK/node$i.log" 2>/dev/null || true
    done
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
  [ "$rc" -eq 0 ] && echo "==> split ceremony e2e OK"
  return "$rc"
}
trap cleanup EXIT

step "Build rutli-cosigner and rutli-dealer from the working tree"
(cd "$REPO/frost" && cargo build ${CARGO_FLAGS:-} -p rutli-cosigner --bins)
BIN="$REPO/frost/target/debug"
COSIGNER="$BIN/rutli-cosigner"
DEALER="$BIN/rutli-dealer"

step "mTLS trust domain, seal secret, configs (deploy/frost/config-tls on 127.0.0.1:$((BASE_PORT + 1))..$((BASE_PORT + 3)))"
"$REPO/scripts/gen-frost-certs.sh" 3 "$WORK/certs" >/dev/null
export RUTLI_SEAL_SECRET
RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"
mkconfig() { # node-config-name  cert-name  out
  jq --arg work "$WORK" --arg cert "$2" --argjson base "$BASE_PORT" '
      .listen = "127.0.0.1:\($base + .identifier)"
    | .data_dir = "\($work)/node\(.identifier)"
    | .peers |= map(.endpoint = "https://127.0.0.1:\($base + .identifier)")
    | .tls.ca_cert = "\($work)/certs/ca.crt"
    | .tls.cert = "\($work)/certs/\($cert).crt"
    | .tls.key = "\($work)/certs/\($cert).key"
    | .refresh_allowlist = ["refresher"]
    | .signing_policy.signer_may_refresh = false
    | del(.metrics_listen)' "$REPO/deploy/frost/config-tls/$1.json" >"$3"
}
for i in 1 2 3; do mkconfig "cosigner$i" "cosigner$i" "$WORK/c$i.json"; done
# The operator role (operator_allowlist: KeyStatus + CeremonySignTest only) runs verify-key; the
# refresher role (refresh_allowlist: Refresh + KeyStatus only), like the refresh CronJob, runs
# refresh — the driver may not (signing_policy.signer_may_refresh off).
mkconfig cosigner1 operator "$WORK/operator.json"
mkconfig cosigner1 driver "$WORK/driver.json"
mkconfig cosigner1 refresher "$WORK/refresher.json"

start() {
  RUST_LOG=info "$COSIGNER" --config "$WORK/c$1.json" serve >>"$WORK/node$1.log" 2>&1 &
  PIDS[$1]=$!
}
stop() { kill "${PIDS[$1]}" 2>/dev/null || true; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }
wait_healthy() {
  for _ in $(seq 1 120); do
    "$COSIGNER" --config "$WORK/c$1.json" health >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  fail "node $1 did not become healthy"
}
cli() { RUST_LOG=off "$COSIGNER" "$@"; }
grpc() {
  grpcurl -cacert "$WORK/certs/ca.crt" -cert "$WORK/certs/driver.crt" -key "$WORK/certs/driver.key" \
    -servername cosigner1 -import-path "$REPO/frost/cosigner/proto" -proto cosigner.proto "$@"
}
expect_dkg_refused() {
  if out="$(grpc -d "{\"key_id\":\"$KEY_ID\"}" "127.0.0.1:$((BASE_PORT + 1))" rutli.cosigner.v1.Signer/Dkg 2>&1)"; then
    fail "Dkg on $KEY_ID succeeded: $out"
  fi
  grep -q "AlreadyExists" <<<"$out" || fail "Dkg on $KEY_ID: expected AlreadyExists, got: $out"
  echo "Dkg $KEY_ID -> AlreadyExists ($1)"
}

step "Start three cosigners (mTLS, sealed shares)"
for i in 1 2 3; do start "$i"; done
for i in 1 2 3; do wait_healthy "$i"; done

step "DKG is refused for the import id before anything is installed"
expect_dkg_refused "reserved"

step "1. share-recipient on every node (the running daemons share the data dir, as under kubectl exec)"
SAS=()
for i in 1 2 3; do
  out="$(cli --config "$WORK/c$i.json" share-recipient --key-id "$KEY_ID" --ceremony-id "$CEREMONY" \
    --out "$WORK/r$i.json")"
  jq -e --arg k "$KEY_ID" '.key_id == $k and .identifier > 0 and (.signer_chain | length) > 0' \
    "$WORK/r$i.json" >/dev/null
  # Gate 0: the SAS as printed in the pod, and as a witness re-reads it in a session of their own
  # from the node's sealed state (recipient-sas). They must agree.
  SAS+=("$(awk -v n="$i" '$1 == "SAS" && $3 == n {print $4}' <<<"$out")")
  [ -n "${SAS[$((i - 1))]}" ] || fail "share-recipient on node $i printed no SAS"
  witness="$(cli --config "$WORK/c$i.json" recipient-sas --key-id "$KEY_ID" | awk '{print $4}')"
  [ "$witness" = "${SAS[$((i - 1))]}" ] || fail "recipient-sas on node $i disagrees: $witness"
done
SAS_LIST="$(IFS=,; echo "${SAS[*]}")"
echo "SAS: $SAS_LIST"

# A laptop has swap (and macOS cannot be checked): --allow-swap. A dev Linux host usually pipes core
# dumps to systemd-coredump: --allow-core-handler. The runbook's live-boot host needs neither.
dealer() {
  "$DEALER" split-key --in "$VEC/namespace.export-pw.bin" --password-env E2E_EXPORT_PASSWORD \
    --expect-fingerprint "$FP" --key-id "$KEY_ID" --threshold 2 --ca-cert "$WORK/certs/ca.crt" \
    --recipient "$WORK/$1.json" --recipient "$WORK/r2.json" --recipient "$WORK/r3.json" \
    --out-dir "$WORK/$2" --allow-swap --allow-core-handler --confirm-sas "$3"
}

step "   a substituted request is refused (signature), whatever SAS the witnesses were shown"
jq --arg p "$(openssl rand -hex 32)" '.recipient_pub = $p' "$WORK/r1.json" >"$WORK/r1-forged.json"
if dealer r1-forged dealer-forged "$SAS_LIST" >"$WORK/forged.out" 2>&1; then fail "dealer accepted a forged request"; fi
grep -q "bad request signature" "$WORK/forged.out" || fail "forged request refused for the wrong reason: $(cat "$WORK/forged.out")"
if dealer r1 dealer-forged "0000000000000000,${SAS[1]},${SAS[2]}" >"$WORK/sas.out" 2>&1; then fail "dealer accepted a wrong SAS"; fi
grep -q "SAS mismatch" "$WORK/sas.out" || fail "wrong SAS refused for the wrong reason: $(cat "$WORK/sas.out")"
[ -e "$WORK/dealer-forged" ] && fail "a refused dealer run left output behind"

step "2. Dealer: split the Canton namespace key ${FP}"
dealer r1 dealer "$SAS_LIST"
DIGEST="$(jq -r .pkp_digest "$WORK/dealer/dealer-record.json")"
GROUP="$(jq -r .group_verifying_key "$WORK/dealer/dealer-record.json")"

step "3. import-share --dry-run on every node"
for i in 1 2 3; do
  rep="$(cli --config "$WORK/c$i.json" import-share --in "$WORK/dealer/share-$KEY_ID-node$i.json" \
    --expect-fingerprint "$FP" --dry-run)"
  jq -e --arg d "$DIGEST" '.outcome == "dry-run" and .pkp_digest == $d' <<<"$rep" >/dev/null \
    || fail "dry run on node $i: $rep"
done
[ -e "$WORK/node1/keys/$KEY_ID.json" ] && fail "a dry run installed something"

step "   wrong node and wrong fingerprint are refused"
if cli --config "$WORK/c1.json" import-share --in "$WORK/dealer/share-$KEY_ID-node2.json" \
  --expect-fingerprint "$FP" >/dev/null 2>&1; then fail "node 1 installed node 2's bundle"; fi
if cli --config "$WORK/c1.json" import-share --in "$WORK/dealer/share-$KEY_ID-node1.json" \
  --expect-fingerprint "1220$(printf '0%.0s' $(seq 1 64))" >/dev/null 2>&1; then fail "wrong fingerprint accepted"; fi

step "4. import-share on every node"
for i in 1 2 3; do
  rep="$(cli --config "$WORK/c$i.json" import-share --in "$WORK/dealer/share-$KEY_ID-node$i.json" \
    --expect-fingerprint "$FP")"
  jq -e --arg d "$DIGEST" '.outcome == "installed" and .pkp_digest == $d' <<<"$rep" >/dev/null \
    || fail "import on node $i: $rep"
  [ -e "$WORK/node$i/ceremony/$KEY_ID.recipient" ] && fail "node $i kept its recipient secret"
done
rep="$(cli --config "$WORK/c2.json" import-share --in "$WORK/dealer/share-$KEY_ID-node2.json" --expect-fingerprint "$FP")"
jq -e '.outcome == "already-installed"' <<<"$rep" >/dev/null || fail "identical re-import: $rep"
echo "identical re-import -> already-installed"

step "   a restarted node warns that the dealt key was never refreshed"
stop 1; start 1; wait_healthy 1
grep -q "never been refreshed" "$WORK/node1.log" || fail "no startup warning for the unrefreshed key"

step "5. verify-key --sign-test"
rep="$(cli --config "$WORK/operator.json" verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test --json || true)"
jq -e --arg d "$DIGEST" '.ok and .pkp_digest == $d and .refresh_count == 0 and (.sign_test | length == 3)
  and all(.sign_test[]; .ok)
  and ([.sign_test[].signers] == [[1,2],[1,3],[2,3]]) and ([.sign_test[].leader] == [1,2,3])' <<<"$rep" >/dev/null \
  || fail "verify-key: $rep"
echo "verify-key OK (operator cert): 3/3 nodes, digest $DIGEST, quorums {1,2} {1,3} {2,3} all sign"

step "   the operator cert cannot Sign an arbitrary digest (only the ceremony test digest)"
MSG_B64="$(printf '\022\040%s' "$(printf 'x%.0s' $(seq 1 32))" | base64)"
if out="$(grpcurl -cacert "$WORK/certs/ca.crt" -cert "$WORK/certs/operator.crt" -key "$WORK/certs/operator.key" \
  -servername cosigner1 -import-path "$REPO/frost/cosigner/proto" -proto cosigner.proto \
  -d "{\"key_id\":\"$KEY_ID\",\"message\":\"$MSG_B64\"}" "127.0.0.1:$((BASE_PORT + 1))" \
  rutli.cosigner.v1.Signer/Sign 2>&1)"; then fail "the operator cert signed an arbitrary digest"; fi
grep -q "PermissionDenied" <<<"$out" || fail "operator Sign refused for the wrong reason: $out"
echo "operator Sign -> PermissionDenied"

step "   DKG is still refused for the installed id"
expect_dkg_refused "installed"

step "6. refresh (refresher role; the operator and — signer_may_refresh off — the driver are refused)"
if cli --config "$WORK/operator.json" refresh --key-id "$KEY_ID" >/dev/null 2>&1; then
  fail "the operator role could run a refresh"
fi
if out="$(cli --config "$WORK/driver.json" refresh --key-id "$KEY_ID" 2>&1)"; then
  fail "the driver could run a refresh with signer_may_refresh off"
fi
grep -q "may not call Refresh" <<<"$out" || fail "driver refresh refused for the wrong reason: $out"
echo "driver refresh -> refused (signer_may_refresh off)"
out="$(cli --config "$WORK/refresher.json" refresh --key-id "$KEY_ID")"
grep -q "$GROUP" <<<"$out" || fail "refresh changed the group key: $out"
if out="$(grpcurl -cacert "$WORK/certs/ca.crt" -cert "$WORK/certs/refresher.crt" -key "$WORK/certs/refresher.key" \
  -servername cosigner1 -import-path "$REPO/frost/cosigner/proto" -proto cosigner.proto \
  -d "{\"key_id\":\"$KEY_ID\",\"message\":\"$MSG_B64\"}" "127.0.0.1:$((BASE_PORT + 1))" \
  rutli.cosigner.v1.Signer/Sign 2>&1)"; then fail "the refresher cert signed"; fi
grep -q "PermissionDenied" <<<"$out" || fail "refresher Sign refused for the wrong reason: $out"
echo "refresher Sign -> PermissionDenied"

step "7. verify-key after refresh"
rep="$(cli --config "$WORK/operator.json" verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test --json || true)"
jq -e --arg d "$DIGEST" '.ok and .pkp_digest != $d and .refresh_count == 1 and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null \
  || fail "verify-key after refresh: $rep"
echo "verify-key OK: new digest $(jq -r .pkp_digest <<<"$rep"), refresh count 1"
if cli --config "$WORK/c3.json" import-share --in "$WORK/dealer/share-$KEY_ID-node3.json" \
  --expect-fingerprint "$FP" >/dev/null 2>&1; then fail "a dealt bundle re-imported over a refreshed key"; fi
echo "re-import after refresh -> refused"

step "8. Restart every node, verify again"
for i in 1 2 3; do stop "$i"; done
for i in 1 2 3; do start "$i"; done
for i in 1 2 3; do wait_healthy "$i"; done
rep="$(cli --config "$WORK/operator.json" verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test --json || true)"
jq -e '.ok and .refresh_count == 1' <<<"$rep" >/dev/null || fail "verify-key after restart: $rep"

step "9. Sign with node 3 down and no signing intent (require_intent off), verified by OpenSSL under the Canton public key"
stop 3
MSG_HEX="1220$(printf 'rutli e2e split ceremony' | openssl dgst -sha256 -hex | awk '{print $NF}')"
MSG_B64="$(printf '%s' "$MSG_HEX" | xxd -r -p | base64)"
sig="$(grpc -d "{\"key_id\":\"$KEY_ID\",\"message\":\"$MSG_B64\"}" "127.0.0.1:$((BASE_PORT + 1))" \
  rutli.cosigner.v1.Signer/Sign | jq -r .signature)"
printf '%s' "$MSG_HEX" | xxd -r -p >"$WORK/msg.bin"
printf '%s' "$sig" | base64 -d >"$WORK/sig.bin" 2>/dev/null || printf '%s' "$sig" | base64 -D >"$WORK/sig.bin"
# SubjectPublicKeyInfo for a raw Ed25519 key: fixed 12-byte prefix ‖ 32-byte key.
printf '302a300506032b6570032100%s' "$GROUP" | xxd -r -p >"$WORK/pub.der"
openssl pkey -pubin -inform DER -in "$WORK/pub.der" -out "$WORK/pub.pem"
openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin -in "$WORK/msg.bin" -sigfile "$WORK/sig.bin" \
  || fail "OpenSSL rejects the cluster's signature"
grep -q '"purpose":"no-intent"' "$WORK"/node1/journal/"$KEY_ID"/*.jsonl \
  || fail "node 1 did not journal the intent-less signature"
grep -q '"purpose":"sign-test"' "$WORK"/node1/journal/"$KEY_ID"/*.jsonl \
  || fail "node 1 did not journal the ceremony sign tests"
echo "journaled on node 1: the sign tests and the intent-less signature"

step "10. require_intent on (every node): an intent-less Sign is refused, the ceremony sign test still passes"
for i in 1 2 3; do
  jq '.signing_policy.require_intent = true' "$WORK/c$i.json" >"$WORK/c$i.json.new" && mv "$WORK/c$i.json.new" "$WORK/c$i.json"
done
for i in 1 2; do stop "$i"; done
for i in 1 2 3; do start "$i"; done
for i in 1 2 3; do wait_healthy "$i"; done
if out="$(grpc -d "{\"key_id\":\"$KEY_ID\",\"message\":\"$MSG_B64\"}" "127.0.0.1:$((BASE_PORT + 1))" \
  rutli.cosigner.v1.Signer/Sign 2>&1)"; then fail "an intent-less Sign succeeded with require_intent on"; fi
grep -q "PermissionDenied" <<<"$out" && grep -q "no signing intent" <<<"$out" \
  || fail "intent-less Sign refused for the wrong reason: $out"
echo "intent-less Sign -> PermissionDenied"
rep="$(cli --config "$WORK/operator.json" verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test --json || true)"
jq -e '.ok and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null || fail "verify-key --sign-test under require_intent: $rep"
echo "verify-key --sign-test OK under require_intent"

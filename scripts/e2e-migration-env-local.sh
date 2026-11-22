# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# The "local" environment of scripts/e2e-migration.sh: how the cosigners and Canton are started and
# reached. Sourced by that script (E2E_ENV=local, the default), never run on its own.
#
# Everything here is about the environment; nothing here is migration procedure. Another
# environment (a Kubernetes cluster reached with a KUBECONFIG, say) provides the same functions in
# scripts/e2e-migration-env-<name>.sh:
#
#   env_init                     build or locate the binaries, set up and start the cluster, set WORK
#   env_cosigner N ARGS…         rutli-cosigner on cosigner node N with that node's config (as under
#                                `kubectl exec` in the pod)
#   env_client ROLE ARGS…        rutli-cosigner as a client of the cluster with ROLE's certificate
#                                (operator, refresher), from the operator's machine
#   env_node_out N NAME          a path node N can write NAME to (for --out)
#   env_fetch N PATH LOCAL       copy PATH from node N to LOCAL on the operator's machine
#   env_push N LOCAL             make LOCAL readable on node N; prints the path to use there
#   env_node_path N REL          node N's data_dir/REL, as node N sees it
#   env_node_exists N PATH       whether PATH exists on node N
#   env_node_cat N PATH…         cat PATH… on node N (globs are expanded on the node)
#   env_node_ls N PATH           list PATH on node N
#   env_canton_conf              print the Canton config (sequencer, mediator, the four participants)
#   env_canton_start SCRIPT      start Canton on the bootstrap SCRIPT, in the background
#   env_canton_alive             whether that Canton is still running
#   env_canton_wait              wait for it to exit; fails if it failed
#   env_canton_logs              the Canton log files (driver AUDIT lines, commitment errors)
#   env_driver_audit NAME        the driver's hash-chained audit log of participant NAME
#   env_old_db_exists / env_destroy_old_db   the old participant's database (Step 8)
#   env_cleanup RC               stop everything; print logs when RC is not 0
#
# Shared with the procedure script: WORK (a directory on the operator's machine), SYNC (where the
# Canton bootstrap script and the procedure script leave marker files), PREFIX, DEALER, and the
# helpers step and fail.

: "${CANTON_HOME:?Set CANTON_HOME to an extracted Canton 3.6.1 release}"
JAVA_HOME="${CANTON_JAVA_HOME:-${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}}"
export JAVA_HOME
BASE_PORT="${E2E_BASE_PORT:-19800}"
CANTON_PORT="${E2E_CANTON_PORT:-15800}"
PIDS=(0 0 0 0)
CANTON_PID=0

env_init() {
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/rutli-e2e-migration.XXXXXX")"
  SYNC="$WORK/sync"
  mkdir -p "$SYNC" "$WORK/export" "$WORK/old-db" "$WORK/new-db"

  local bin="$REPO/frost/target/debug"
  COSIGNER="$bin/rutli-cosigner"
  DEALER="$bin/rutli-dealer"
  DRIVER_JAR="$REPO/driver/target/scala-2.13/rutli-driver.jar"
  if [ "${SKIP_BUILD:-0}" != 1 ]; then
    step "Build rutli-cosigner, rutli-dealer and the driver fat jar from the working tree"
    # shellcheck disable=SC2086  # CARGO_FLAGS is a list of flags, split on purpose
    (cd "$REPO/frost" && cargo build ${CARGO_FLAGS:-} -p rutli-cosigner --bins)
    (cd "$REPO" && sbt -batch driver/assembly >/dev/null)
  fi
  for f in "$COSIGNER" "$DEALER"; do [ -x "$f" ] || fail "no $f"; done
  [ -f "$DRIVER_JAR" ] || fail "no $DRIVER_JAR"
  DAR="$CANTON_HOME/dars/CantonExamples.dar"
  [ -f "$DAR" ] || fail "no dars/CantonExamples.dar in $CANTON_HOME"

  # migration.md §3 "Before you start": mTLS and share_seal on, an operator certificate on
  # operator_allowlist, a refresher certificate on refresh_allowlist.
  step "mTLS trust domain, seal secret, configs (127.0.0.1:$((BASE_PORT + 1))..$((BASE_PORT + 3)))"
  # Every node pins the TLS key of every cosigner (peers[].tls_spki_sha256, required with TLS): the
  # configs take the pins of the certificates just made from certs/peer-pins.json.
  "$REPO/scripts/gen-frost-certs.sh" 3 "$WORK/certs" >/dev/null
  export RUTLI_SEAL_SECRET
  RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"
  # The cosigner signing policy fully enforced (audit C2): every signature needs a driver-signed
  # intent, the driver may use only this migration's prefix, its key is pinned, only the refresher
  # refreshes, and DKG and refresh need a ceremony intent.
  local pin
  pin="$(openssl x509 -in "$WORK/certs/driver.crt" -noout -pubkey | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -hex | awk '{print $NF}')"
  _mkconfig() { # node-config-name  cert-name  out
    jq --arg work "$WORK" --arg cert "$2" --argjson base "$BASE_PORT" --arg prefix "$PREFIX" --arg pin "$pin" \
      --slurpfile peerpins "$WORK/certs/peer-pins.json" '
        .listen = "127.0.0.1:\($base + .identifier)"
      | .data_dir = "\($work)/node\(.identifier)"
      | .peers |= map(.endpoint = "https://127.0.0.1:\($base + .identifier)"
          | .tls_spki_sha256 = ($peerpins[0].peerPins[.identifier | tostring] // error("no TLS key pin for cosigner\(.identifier)")))
      | .tls.ca_cert = "\($work)/certs/ca.crt"
      | .tls.cert = "\($work)/certs/\($cert).crt"
      | .tls.key = "\($work)/certs/\($cert).key"
      | .hosted_keys.anti_entropy_interval_secs = 10
      | .refresh_allowlist = ["refresher"]
      | .signing_policy = { require_intent: true, require_ceremony_intent: true, require_epoch_match: true, signer_acl_required: true,
          signer_may_refresh: false, signer_acl: { driver: [$prefix] }, signer_pins: { driver: [$pin] } }
      | del(.metrics_listen)' "$REPO/deploy/frost/config-tls/$1.json" >"$3"
  }
  local i
  for i in 1 2 3; do _mkconfig "cosigner$i" "cosigner$i" "$WORK/c$i.json"; done
  # The operator role (KeyStatus, HostedKeyStatus, CeremonySignTest) runs verify-key; the refresher
  # (refresh_allowlist), like the refresh CronJob, runs refresh.
  _mkconfig cosigner1 operator "$WORK/operator.json"
  _mkconfig cosigner1 refresher "$WORK/refresher.json"

  step "Start three cosigners (mTLS, sealed, hosted keys); every step below runs against them live"
  for i in 1 2 3; do
    RUST_LOG=info "$COSIGNER" --config "$WORK/c$i.json" serve >>"$WORK/node$i.log" 2>&1 &
    PIDS[i]=$!
  done
  for i in 1 2 3; do _wait_healthy "$i"; done
}

_wait_healthy() { # up to 60 s; a cold debug build on a busy runner can take a while
  for _ in $(seq 1 240); do
    "$COSIGNER" --config "$WORK/c$1.json" health >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  fail "node $1 did not become healthy"
}

# The running daemons share their data dir with the CLI, as `kubectl exec` into the pod does.
env_cosigner() { local n=$1; shift; RUST_LOG=off "$COSIGNER" --config "$WORK/c$n.json" "$@"; }
env_client() { local role=$1; shift; RUST_LOG=off "$COSIGNER" --config "$WORK/$role.json" "$@"; }
env_node_out() { printf '%s\n' "$WORK/$2"; }
env_fetch() { [ "$2" = "$3" ] || cp "$2" "$3"; }
env_push() { printf '%s\n' "$2"; }
env_node_path() { printf '%s\n' "$WORK/node$1/$2"; }
env_node_exists() { [ -e "$2" ]; }
# shellcheck disable=SC2086  # the globs in $p are meant to expand here
env_node_cat() { shift; local p; for p in "$@"; do cat $p 2>/dev/null || true; done; } # globs expand here
env_node_ls() { ls "$2"; }

env_canton_conf() {
  local P=$CANTON_PORT
  _h2() { # database file under $WORK (no extension)
    cat <<EOF
storage {
      type = h2
      config {
        url = "jdbc:h2:file:$WORK/$1;MODE=PostgreSQL;LOCK_TIMEOUT=10000;DB_CLOSE_DELAY=-1"
        user = "canton"
        password = "morethansafe"
        driver = org.h2.Driver
      }
    }
EOF
  }
  _new_participant() { # name  port-offset  database
    cat <<EOF
  participants.$1 {
    $(_h2 "$3")
    ledger-api.port = $((P + $2 + 1))
    admin-api.port = $((P + $2 + 2))
    http-ledger-api.port = $((P + $2 + 3))
    // migration.md Step 4.3: the node waits for its id, and keys and identity come from the
    // operator (Step 5), not from Canton's auto-init. The Splice participant chart does the same.
    init.identity.type = manual
    init.generate-topology-transactions-and-keys = false
    // Step 4.3, the Rütli KMS block.
    crypto {
      provider = kms
      kms {
        type = driver
        name = "rutli"
        config = {
          backend = "frost"
          audit-logging = true
          audit-log-path = "$(env_driver_audit "$1")"
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
EOF
  }
  cat <<EOF
canton {
  parameters.non-standard-config = yes
  // Nothing starts by itself: the bootstrap script starts and stops each node where the runbook does.
  parameters.manual-start = yes
  // Console waits (retry_until_true, admin commands, pings) default to 1 min and 30 s. A loaded CI
  // runner can be slower than that without anything being wrong; a real failure still fails.
  parameters.timeouts.console { bounded = 3.minutes, ledger-command = 3.minutes, ping = 2.minutes }
  // Step 2.1: the participant refuses ExportKeyPair without it, and the console needs it as well.
  features.enable-preview-commands = yes
  // repair.import_acs (the stand-in for the Splice party migrator's ACS import).
  features.enable-repair-commands = yes
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
  // OLD_DB: the validator to migrate, on Canton's own (JCE) keys, stored in this database.
  participants.oldp {
    $(_h2 old-db/participant_1)
    ledger-api.port = $((P + 11))
    admin-api.port = $((P + 12))
    http-ledger-api.port = $((P + 13))
  }
  participants.peer {
    storage.type = memory
    ledger-api.port = $((P + 21))
    admin-api.port = $((P + 22))
    http-ledger-api.port = $((P + 23))
  }
$(_new_participant newp1 30 new-db/participant_r1)
$(_new_participant newp2 40 new-db/participant_r2)
  // The operator's remote console on the old participant (b0-cutover-spike.md §1.3): the export of
  // Step 2 goes through the admin API, where the participant applies its own gate.
  remote-participants.oldpRemote {
    admin-api { address = "127.0.0.1", port = $((P + 12)) }
    ledger-api { address = "127.0.0.1", port = $((P + 11)) }
  }
}
EOF
}

env_canton_start() {
  env_canton_conf >"$WORK/canton.conf"
  (
    cd "$WORK" || exit 1
    export E2E_WORK="$WORK" E2E_DAR="$DAR" EXTRA_CLASSPATH="$DRIVER_JAR"
    exec "$CANTON_HOME/bin/canton" run "$1" \
      --config "$WORK/canton.conf" --no-tty --log-file-name "$WORK/canton.log" --kms-log-file-name "$WORK/canton_kms.log" \
      >"$WORK/canton.out" 2>&1
  ) &
  CANTON_PID=$!
}
env_canton_alive() { [ "$CANTON_PID" != 0 ] && kill -0 "$CANTON_PID" 2>/dev/null; }
env_canton_wait() {
  local rc=0
  wait "$CANTON_PID" || rc=$?
  CANTON_PID=0
  [ "$rc" -eq 0 ] || fail "Canton run failed (exit $rc)"
}
env_canton_out() { cat "$WORK/canton.out" 2>/dev/null || true; }
env_canton_logs() { printf '%s\n' "$WORK/canton.log" "$WORK/canton_kms.log"; }
env_driver_audit() { printf '%s\n' "$WORK/driver-audit-$1.jsonl"; }

# The old participant's H2 database. With DB_CLOSE_DELAY=-1 the Canton JVM may still hold it open
# after the participant stopped: deleting it removes the directory entries, which is what a script
# can check; the blocks are gone only when the JVM exits (and on an SSD not provably then).
env_old_db_exists() { ls "$WORK/old-db"/participant_1* >/dev/null 2>&1; }
env_destroy_old_db() { if [ "$(uname)" = Darwin ]; then /bin/rm -P -rf "$WORK/old-db"; else rm -rf "$WORK/old-db"; fi; }

env_cleanup() {
  local rc=$1 i
  if [ "$CANTON_PID" != 0 ]; then
    pkill -P "$CANTON_PID" 2>/dev/null || true
    kill "$CANTON_PID" 2>/dev/null || true
  fi
  for i in 1 2 3; do
    if [ "${PIDS[i]}" != 0 ]; then kill "${PIDS[i]}" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ] && [ -n "${WORK:-}" ]; then
    for i in 1 2 3; do
      echo "--- node$i log (tail) ---"
      tail -n 20 "$WORK/node$i.log" 2>/dev/null || true
    done
    echo "--- canton output (tail) ---"
    tail -n 80 "$WORK/canton.out" 2>/dev/null || true
  fi
  if [ -n "${WORK:-}" ]; then
    if [ "${KEEP:-0}" = 1 ]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
  fi
}

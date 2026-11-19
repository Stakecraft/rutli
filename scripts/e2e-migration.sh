#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# End-to-end: the whole migration procedure of docs/migration.md (Flow 2b) on a real Canton 3.6.1
# participant, as far as open-source Canton goes without Splice.
#
#   CANTON_HOME=~/.cache/canton-3.6.1/canton-open-source-3.6.1 scripts/e2e-migration.sh
#   (from the repo root; KEEP=1 keeps the work dir; SKIP_BUILD=1 reuses existing binaries)
#
# A local 2-of-3 cosigner cluster (mTLS, sealed, hosted keys, the signing policy fully enforced)
# runs as native processes on 127.0.0.1, as in scripts/e2e-split-ceremony.sh. One Canton process
# runs a sequencer, a mediator and four participants; its bootstrap script and this script take
# turns, each waiting for the other's marker file under $WORK/sync:
#
#   oldp   the validator to migrate: plain JCE keys, its database in a file (H2), so it can be
#          stopped and started again as a rollback does
#   peer   a second JCE participant with the counter-party of the contracts
#   newp1  rutli KMS, fresh database, new participant id: the cutover that is rolled back
#   newp2  rutli KMS, fresh database, another new participant id: the cutover that goes through
#
# Steps of docs/migration.md §4, in order (the commands are the ones the runbook gives):
#
#   Step 1    baselines: party id, the party's contracts, the three key fingerprints.
#   Step 2    NS_FP confirmed from the node id, the party id and the root namespace delegation;
#             `keys.secret.download_to(…, password = Some(…))`; sha256 of the export file.
#   Step 3    split ceremony (docs/split-ceremony.md §4) into the running cluster: recipient
#             requests, Gate 0 (SAS), split, dry run (Gate A), install, verify-key --sign-test with
#             the operator certificate (Gate B), refresh with the refresher certificate, verify-key
#             again (Gate C), founding backups.
#             Refused on the way: a wrong export password, no password, a wrong fingerprint at the
#             dealer, at import-share and at verify-key, and a dealt bundle after the refresh.
#   Step 4    the old participant disconnected, reference ACS exported, old participant stopped;
#             a new participant on a fresh database with the rutli KMS block of Step 4.3.
#   Step 5    register the namespace key by id (must return NS_FP), a fresh FROST signing key and a
#             fresh hosted ECIES key, init_id_from_uid(NEW_ID::NS_FP), the identity snapshot, the
#             OTK without signedBy, connect_by_config with the old node's connection config.
#   §6        rollback before the point of no return, with newp1 already onboarded: newp1 stopped,
#             oldp started on its old database, the party still there and transacting, the orphan
#             member offboarded from oldp. Then Steps 4 and 5 again with newp2 and another NEW_ID.
#   Step 6    NOT the Splice re-onboard (it needs a Splice validator app, Scan and a DSO; see
#             "Not covered" below). In its place, the same topology changes its party migrator
#             makes, issued from newp2 and signed by the imported namespace key through FROST:
#             the party unhosted from the old participant, the old trust certificate removed
#             (the point of no return), the party hosted on newp2, and the reference ACS of Step 4
#             imported with repair.import_acs.
#   Step 7    party id unchanged, hosted only on PAR::NEW_ID::NS_FP, old trust certificate gone,
#             the ACS is the reference ACS, the new participant exercises a choice on a migrated
#             contract and creates a new one with the counter-party, pings both ways, no ACS
#             commitment mismatch over several reconciliation intervals; the driver audit shows
#             signatures with the imported namespace key and the fresh signing key and ECIES
#             decryptions, none failed; at least two cosigners journaled each of them.
#   Step 8    what can be checked by a script: the export file, the old database, the dealer
#             output and the request files are deleted, no recipient secret and no pre-refresh
#             backup is left on a cosigner, the offboarded member's OTK is removed, and after all
#             of that verify-key --sign-test passes and the new participant still transacts.
#
# Not covered, and why:
#   - Step 6 as written (dump Secret, `migrateValidatorParty`, ACS import from Scan, wallet,
#     ValidatorLicense, traffic top-up): Splice only. It needs a LocalNet job.
#   - Step 2.1 on Canton 3.7 (`enable-key-download`): this runs Canton 3.6.1.
#   - Everything Kubernetes or Helm (pods, PVCs, NetworkPolicy, `kubectl cp`, Helm rollback), the
#     air-gapped dealer host, witnesses, and destruction of copies outside this machine (WAL,
#     replicas, dumps, object storage, snapshots).
#
# Requires: cargo, sbt, jq, openssl, an OpenJDK 17+ (Oracle's JDK refuses Canton's unsigned
# BouncyCastle for Cipher; set CANTON_JAVA_HOME, otherwise JAVA_HOME, otherwise Homebrew's openjdk).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${CANTON_HOME:?Set CANTON_HOME to an extracted Canton 3.6.1 release}"
JAVA_HOME="${CANTON_JAVA_HOME:-${JAVA_HOME:-/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home}}"
export JAVA_HOME
BASE_PORT="${E2E_BASE_PORT:-19800}"
CANTON_PORT="${E2E_CANTON_PORT:-15800}"

# docs/migration.md §2. NS_FP, OLD_ID and KEY_ID are read from the old participant in Step 2.
PREFIX="mig1-"
NEW_ID_ROLLED_BACK="oldp-r1"
NEW_ID="oldp-r2"
CEREMONY="e2e-migration-$(date +%s)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/rutli-e2e-migration.XXXXXX")"
PIDS=(0 0 0 0)
CANTON_PID=0

step() { printf '\n==> %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rc=$?
  if [ "$CANTON_PID" != 0 ]; then
    pkill -P "$CANTON_PID" 2>/dev/null || true
    kill "$CANTON_PID" 2>/dev/null || true
  fi
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
    tail -n 80 "$WORK/canton.out" 2>/dev/null || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
  [ "$rc" -eq 0 ] && echo "==> migration e2e OK"
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
[ -f "$CANTON_HOME/dars/CantonExamples.dar" ] || fail "no dars/CantonExamples.dar in $CANTON_HOME"

# ---------------------------------------------------------------------------------------------
# §3 "Before you start": the Rütli cluster, mTLS and share_seal on, an operator certificate on
# operator_allowlist and a refresher certificate on refresh_allowlist.
# ---------------------------------------------------------------------------------------------
step "mTLS trust domain, seal secret, configs (127.0.0.1:$((BASE_PORT + 1))..$((BASE_PORT + 3)))"
"$REPO/scripts/gen-frost-certs.sh" 3 "$WORK/certs" >/dev/null
export RUTLI_SEAL_SECRET
RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"
# The cosigner signing policy fully enforced (audit C2): every signature needs a driver-signed
# intent, the driver may use only this migration's prefix, its key is pinned, only the refresher
# refreshes, and DKG and refresh need a ceremony intent.
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
# The operator role (KeyStatus, HostedKeyStatus, CeremonySignTest) runs verify-key; the refresher
# (refresh_allowlist), like the refresh CronJob, runs refresh.
mkconfig cosigner1 operator "$WORK/operator.json"
mkconfig cosigner1 refresher "$WORK/refresher.json"

start() {
  RUST_LOG=info "$COSIGNER" --config "$WORK/c$1.json" serve >>"$WORK/node$1.log" 2>&1 &
  PIDS[$1]=$!
}
wait_healthy() { # up to 60 s; a cold debug build on a busy runner can take a while
  for _ in $(seq 1 240); do
    "$COSIGNER" --config "$WORK/c$1.json" health >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  fail "node $1 did not become healthy"
}
cli() { RUST_LOG=off "$COSIGNER" "$@"; }
verify_key() { # extra args: the report as JSON on stdout, whatever the exit code
  cli --config "$WORK/operator.json" verify-key --key-id "$KEY_ID" --expect-fingerprint "$NS_FP" "$@" --json || true
}

step "Start three cosigners (mTLS, sealed, hosted keys); every step below runs against them live"
for i in 1 2 3; do start "$i"; done
for i in 1 2 3; do wait_healthy "$i"; done

# ---------------------------------------------------------------------------------------------
# Canton: one process, started now and driven through marker files until the end.
# ---------------------------------------------------------------------------------------------
mkdir -p "$WORK/sync" "$WORK/export" "$WORK/old-db"
# Canton and this script tell each other where they are with files under $WORK/sync: `<name>` is a
# marker, `<name>.env` the KEY=value lines that go with it (written before the marker).
wait_marker() { # marker-name  [timeout-seconds]
  for _ in $(seq 1 $((${2:-600} * 2))); do
    [ -e "$WORK/sync/$1" ] && return 0
    if ! kill -0 "$CANTON_PID" 2>/dev/null; then
      grep -h "^E2E" "$WORK/canton.out" 2>/dev/null | tail -n 5 || true
      fail "Canton exited before '$1'"
    fi
    sleep 0.5
  done
  fail "timed out waiting for Canton to reach '$1'"
}
mark() { : >"$WORK/sync/$1"; }
value() { # env-file  key
  sed -n "s/^$2=//p" "$WORK/sync/$1.env" | head -n 1
}

step "Canton config: sequencer1, mediator1, oldp (JCE, H2 file), peer (JCE), newp1 and newp2 (rutli KMS, prefix $PREFIX)"
P=$CANTON_PORT
h2() { # database file under $WORK (no extension)
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
new_participant() { # name  port-offset  database
  cat <<EOF
  participants.$1 {
    $(h2 "$3")
    ledger-api.port = $((P + $2 + 1))
    admin-api.port = $((P + $2 + 2))
    http-ledger-api.port = $((P + $2 + 3))
    // What the Splice participant chart sets: the node waits for its id, and keys and identity
    // transactions come from the operator (Step 5), not from Canton's auto-init.
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
          audit-log-path = "$WORK/driver-audit-$1.jsonl"
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
cat >"$WORK/canton.conf" <<EOF
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
    $(h2 old-db/participant_1)
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
$(new_participant newp1 30 new-db/participant_r1)
$(new_participant newp2 40 new-db/participant_r2)
  // The operator's remote console on the old participant (b0-cutover-spike.md §1.3): the export of
  // Step 2 goes through the admin API, where the participant applies its own gate.
  remote-participants.oldpRemote {
    admin-api { address = "127.0.0.1", port = $((P + 12)) }
    ledger-api { address = "127.0.0.1", port = $((P + 11)) }
  }
}
EOF
mkdir -p "$WORK/new-db"

# The bootstrap script takes everything from the environment, so it needs no shell quoting.
cat >"$WORK/e2e.canton" <<'EOF'
import com.digitalasset.canton.console.{LocalParticipantReference, ParticipantReference}
import com.digitalasset.canton.crypto.{EncryptionKeySpec, EncryptionPublicKey, SigningKeySpec, SigningKeyUsage, SigningPublicKey}
import com.digitalasset.canton.examples.java.iou.{Amount, Iou}
import com.digitalasset.canton.topology.admin.grpc.TopologyStoreId
import java.nio.file.{Files, Paths}
import scala.jdk.CollectionConverters._

val WORK = sys.env("E2E_WORK")
val OLD_ID = sys.env("E2E_OLD_ID")
val NEW_ID_ROLLED_BACK = sys.env("E2E_NEW_ID_ROLLED_BACK")
val NEW_ID = sys.env("E2E_NEW_ID")
val DAR = sys.env("E2E_DAR")
val EXPORT_FILE = Paths.get(WORK, "export", "namespace.export").toString
val IDENTITY_FILE = Paths.get(WORK, "identity-authorized.bin").toString
val SYNC_DIR = Paths.get(WORK, "sync")

def fail(what: String): Nothing = { println("E2E-FAIL " + what); sys.exit(1) }
def check(ok: Boolean, what: => String): Unit = if (!ok) fail(what)
// Marker files shared with the shell script: `<name>.env` holds KEY=value lines, `<name>` says go.
def mark(name: String, values: (String, String)*): Unit = {
  if (values.nonEmpty)
    Files.write(SYNC_DIR.resolve(name + ".env"), values.map { case (k, v) => k + "=" + v }.mkString("", "\n", "\n").getBytes("UTF-8"))
  Files.write(SYNC_DIR.resolve(name), Array.emptyByteArray)
  println("E2E-MARK " + name)
}
def await(name: String): Unit = {
  val deadline = System.nanoTime + 20L * 60 * 1000 * 1000 * 1000
  while (!Files.exists(SYNC_DIR.resolve(name))) {
    if (System.nanoTime > deadline) fail("timed out waiting for the shell script to reach '" + name + "'")
    Thread.sleep(250)
  }
}
def value(file: String, key: String): String =
  Files.readAllLines(SYNC_DIR.resolve(file + ".env")).asScala.find(_.startsWith(key + "="))
    .map(_.substring(key.length + 1)).getOrElse(fail("no " + key + " in " + file + ".env"))

def iou(payer: PartyId, owner: PartyId, value: Long) =
  new Iou(payer.toProtoPrimitive, owner.toProtoPrimitive, new Amount(java.math.BigDecimal.valueOf(value), "USD"), List.empty.asJava)
    .create.commands.asScala.toSeq
def acs(p: ParticipantReference, party: PartyId): Set[String] =
  p.ledger_api.state.acs.of_party(party).map(_.event.contractId).toSet

// ------------------------------------------------------------------------------------------------
// The old world: a synchronizer, the validator to migrate (oldp) and a counter-party (peer).
// ------------------------------------------------------------------------------------------------
sequencer1.start()
mediator1.start()
oldp.start()
peer.start()
bootstrap.synchronizer_local()
oldp.synchronizers.connect_local(sequencer1, alias = "da")
peer.synchronizers.connect_local(sequencer1, alias = "da")
utils.retry_until_true(oldp.synchronizers.active("da") && peer.synchronizers.active("da"))
val ALIAS = SynchronizerAlias.tryCreate("da")
val SYNC_ID = oldp.synchronizers.list_connected().head.physicalSynchronizerId.logical
val SYNC_STORE = TopologyStoreId.Synchronizer(SYNC_ID)
val PV = oldp.synchronizers.list_connected().head.physicalSynchronizerId.protocolVersion
// No ACS commitments while the party moves. Between "hosted on the new participant" and "ACS
// imported" the new participant holds none of the party's contracts, and a reconciliation tick in
// that window would be a mismatch by construction (the Splice migrator has the same window). The
// interval comes down to seconds for the check of Step 7.
// (Ten years, as Canton's own offline party replication test does: ticks are epoch-aligned.)
sequencer1.topology.synchronizer_parameters.propose_update(
  SYNC_ID, _.update(reconciliationInterval = PositiveDurationSeconds.ofDays(10 * 365)))

oldp.dars.upload(DAR)
peer.dars.upload(DAR)
val OLD_PID = oldp.id
val OLD_UID = oldp.uid.toProtoPrimitive
val NS_FP = oldp.id.uid.namespace.fingerprint.unwrap
// HINT = OLD_ID, the Splice default (migration.md §3): the validator party is the old
// participant's admin party, so it can move only after the old participant is offboarded.
val VALIDATOR_PARTY = PartyId.tryFromProtoPrimitive(OLD_ID + "::" + NS_FP)
check(VALIDATOR_PARTY.uid.toProtoPrimitive == OLD_UID, s"the validator party $VALIDATOR_PARTY is not the admin party of $OLD_UID")
val bob = peer.parties.enable("bob", synchronizeParticipants = Seq(oldp))
// Two contracts, one in each direction: the validator party owes bob, and bob owes the validator party.
oldp.ledger_api.javaapi.commands.submit(Seq(VALIDATOR_PARTY), iou(VALIDATOR_PARTY, bob, 100))
peer.ledger_api.javaapi.commands.submit(Seq(bob), iou(bob, VALIDATOR_PARTY, 200))

// Step 1: baselines.
val ACS_BASELINE = acs(oldp, VALIDATOR_PARTY)
check(ACS_BASELINE.size == 2, s"baseline ACS of $VALIDATOR_PARTY: $ACS_BASELINE")
val oldKeys = oldp.keys.secret.list()
oldKeys.foreach { k =>
  val u = k.publicKey match { case s: SigningPublicKey => s.usage.mkString(","); case _ => "-" }
  println(s"E2E old key fp=${k.id} name=${k.name} kms=${k.kmsKeyId} purpose=${k.purpose} usage=$u")
}
check(oldKeys.nonEmpty && oldKeys.forall(_.kmsKeyId.isEmpty), "the old participant's keys are not all Canton's own (kms=None)")
val oldSigning = oldKeys.map(_.publicKey).collect { case k: SigningPublicKey if k.usage.contains(SigningKeyUsage.Protocol) => k }
val oldEncryption = oldKeys.map(_.publicKey).collect { case k: EncryptionPublicKey => k }
check(oldSigning.size == 1 && oldEncryption.size == 1, s"old keys: ${oldSigning.size} protocol signing, ${oldEncryption.size} encryption")

// Step 2.2: NS_FP three ways. The node id (above), the party id, and the target of the root
// namespace delegation on the synchronizer, read from another node.
check(VALIDATOR_PARTY.toProtoPrimitive.split("::")(1) == NS_FP, "the party id does not end in NS_FP")
val roots = peer.topology.namespace_delegations.list(store = SYNC_STORE, filterNamespace = NS_FP).filter(_.item.namespace.fingerprint.unwrap == NS_FP)
check(roots.size == 1 && roots.head.item.target.fingerprint.unwrap == NS_FP, s"root namespace delegation of $NS_FP: ${roots.map(_.item)}")

// Step 2.3: export with a password, through the admin API of a remote console.
val nsk = oldpRemote.keys.secret.list().filter(_.publicKey.fingerprint.unwrap == NS_FP).head
check(nsk.name.exists(_.unwrap.endsWith("namespace")), s"the key with fingerprint $NS_FP is named ${nsk.name}")
oldpRemote.keys.secret.download_to(nsk.publicKey.fingerprint, EXPORT_FILE, password = Some(sys.env("EXPORT_PW")))
println(s"E2E-EXPORT namespace key $NS_FP of $OLD_UID")

// Step 4.1 (b4-rehearsal.md): what the new participant needs from the old one, taken while it runs.
val syncCfg = oldp.synchronizers.config(ALIAS).getOrElse(fail("the old participant has no connection config for 'da'"))
val idSnap = oldp.topology.transactions.export_topology_snapshotV2(
  store = TopologyStoreId.Authorized,
  filterMappings = Seq(TopologyMapping.Code.NamespaceDelegation, TopologyMapping.Code.OwnerToKeyMapping),
  protocolVersion = Some(PV.toProtoPrimitiveS),
  filterNamespace = oldp.id.uid.namespace.filterString)
Files.write(Paths.get(IDENTITY_FILE), idSnap.toByteArray)
// Lessons a: the sequencer connections saved as bytes and restored, through reflection.
val toInt = (s: com.digitalasset.canton.admin.api.client.data.SequencerConnections) => s.getClass.getMethod("toInternal").invoke(s).asInstanceOf[com.digitalasset.canton.sequencing.SequencerConnections]
val fromInt = (i: com.digitalasset.canton.sequencing.SequencerConnections) => { val o = com.digitalasset.canton.admin.api.client.data.SequencerConnections; o.getClass.getMethod("fromInternal", classOf[com.digitalasset.canton.sequencing.SequencerConnections]).invoke(o, i).asInstanceOf[com.digitalasset.canton.admin.api.client.data.SequencerConnections] }
val savedConnections: Array[Byte] = toInt(syncCfg.sequencerConnections).toByteArray(ProtocolVersion.v35)
val restoredConnections = fromInt(com.digitalasset.canton.sequencing.SequencerConnections.fromTrustedByteArray(savedConnections).fold(e => sys.error(e.toString), identity))
check(restoredConnections == syncCfg.sequencerConnections, s"sequencer connections changed in the round trip: $restoredConnections")
val restoredCfg = syncCfg.copy(sequencerConnections = restoredConnections)

mark("exported", "NS_FP" -> NS_FP, "OLD_UID" -> OLD_UID, "PARTY" -> VALIDATOR_PARTY.toProtoPrimitive,
  "OLD_SIG_FP" -> oldSigning.head.fingerprint.unwrap, "OLD_ENC_FP" -> oldEncryption.head.fingerprint.unwrap)

// ------------------------------------------------------------------------------------------------
// Step 3 runs in the shell script: the split ceremony into the cosigner cluster.
// ------------------------------------------------------------------------------------------------
await("ceremony")
val KEY_ID = value("ceremony", "KEY_ID")

// Step 4.2: disconnect the old participant, export a reference ACS, stop the old participant.
def stopOld(file: String): Set[String] = {
  val before = acs(oldp, VALIDATOR_PARTY)
  oldp.synchronizers.disconnect_all()
  val end = oldp.ledger_api.state.end()
  oldp.repair.export_acs(parties = Set(VALIDATOR_PARTY), ledgerOffset = end, exportFilePath = file)
  oldp.stop()
  check(!oldp.is_running, "the old participant is still running")
  val exported = repair.acs.read_from_file(file).flatMap(_.createdEvent).map(_.contractId).toSet
  check(exported == before, s"the reference ACS has ${exported.size} contracts, the party had ${before.size}")
  exported
}

// The filters of the topology read commands match by prefix, and the new ids start with the old
// one: every listing is narrowed to the exact member here.
def trusted(via: ParticipantReference, pid: ParticipantId): Boolean =
  via.topology.synchronizer_trust_certificates.list(store = Some(SYNC_STORE), filterUid = pid.uid.toProtoPrimitive).exists(_.item.participantId == pid)
def hosts(via: ParticipantReference): Seq[ParticipantId] =
  via.topology.party_to_participant_mappings.list(SYNC_STORE, filterParty = VALIDATOR_PARTY.filterString)
    .filter(_.item.partyId == VALIDATOR_PARTY).flatMap(_.item.participants.map(_.participantId))

// Steps 4.3 and 5: a new participant on a fresh database, its keys, its identity, its onboarding.
def onboard(newp: LocalParticipantReference, newId: String, signingName: String, cfg: SynchronizerConnectionConfig): (ParticipantId, SigningPublicKey, EncryptionPublicKey) = {
  newp.start()
  utils.retry_until_true(newp.health.is_ready_for_id())
  check(newp.keys.secret.list().isEmpty, s"${newp.name} starts with keys in its store")
  // Step 5.1: the imported namespace key, by id. It must come back with the old fingerprint.
  val nsK = newp.keys.secret.register_kms_signing_key(KEY_ID, Set(SigningKeyUsage.Namespace), "namespace")
  check(nsK.fingerprint.unwrap == NS_FP, s"register_kms_signing_key($KEY_ID) returned ${nsK.fingerprint}, not $NS_FP")
  // Step 5.2: fresh keys, a FROST DKG and a cluster-hosted ECIES key.
  val sigK = newp.keys.secret.generate_signing_key(signingName, SigningKeyUsage.ProtocolWithProofOfOwnership ++ SigningKeyUsage.SequencerAuthenticationOnly, Some(SigningKeySpec.EcCurve25519))
  val encK = newp.keys.secret.generate_encryption_key("encryption", Some(EncryptionKeySpec.EcP256))
  check(encK.keySpec == EncryptionKeySpec.EcP256, s"encryption key spec ${encK.keySpec}")
  check(sigK.fingerprint != oldSigning.head.fingerprint && encK.fingerprint != oldEncryption.head.fingerprint, "the new participant got an old key")
  // Step 5.3: the new id under the old namespace, the old node's identity snapshot, the new OTK.
  val NEW_UID = UniqueIdentifier.tryCreate(newId, NS_FP)
  newp.topology.init_id_from_uid(NEW_UID)
  newp.health.wait_for_ready_for_node_topology()
  newp.topology.transactions.import_topology_snapshot_fromV2(IDENTITY_FILE, TopologyStoreId.Authorized)
  newp.topology.owner_to_key_mappings.propose(member = ParticipantId(NEW_UID), keys = NonEmpty(Seq, sigK, encK))
  newp.health.wait_for_initialized()
  check(newp.id.toProtoPrimitive == "PAR::" + newId + "::" + NS_FP, s"${newp.name} initialised as ${newp.id.toProtoPrimitive}")
  // Step 5.4: onboard with the old node's connection config.
  newp.synchronizers.connect_by_config(cfg)
  utils.retry_until_true(newp.synchronizers.active("da"))
  check(trusted(newp, ParticipantId(NEW_UID)), s"no trust certificate for $NEW_UID on the synchronizer")
  val stored = newp.keys.secret.list()
  check(stored.size == 3 && stored.forall(_.kmsKeyId.nonEmpty), s"${newp.name} keys: ${stored.map(k => k.name -> k.kmsKeyId)}")
  println(s"E2E-ONBOARDED ${newp.id.toProtoPrimitive} with keys ${stored.flatMap(_.kmsKeyId).map(_.unwrap).mkString(", ")}")
  (ParticipantId(NEW_UID), sigK, encK)
}

// ------------------------------------------------------------------------------------------------
// First cutover, rolled back before the point of no return (migration.md §6, b0-cutover-spike.md R-A).
// ------------------------------------------------------------------------------------------------
stopOld(Paths.get(WORK, "acs-old-attempt1.gz").toString)
val (rolledBackPid, rolledBackSigning, _) = onboard(newp1, NEW_ID_ROLLED_BACK, "signing", restoredCfg)
val ROLLED_BACK_PID = rolledBackPid
// The new member is onboarded. The party has not moved: stop here and go back.
newp1.synchronizers.disconnect_all()
newp1.stop()
oldp.start()
oldp.synchronizers.reconnect_all()
utils.retry_until_true(oldp.synchronizers.active("da"))
check(oldp.id == OLD_PID, s"the old participant came back as ${oldp.id}")
check(acs(oldp, VALIDATOR_PARTY) == ACS_BASELINE, "the party's contracts changed across the rollback")
// The old participant still owns the party and transacts with it.
oldp.ledger_api.javaapi.commands.submit(Seq(VALIDATOR_PARTY), iou(VALIDATOR_PARTY, bob, 300))
check(acs(oldp, VALIDATOR_PARTY).size == 3, "the old participant did not transact after the rollback")
// The orphan member is offboarded from the old participant, which holds the namespace key.
oldp.topology.synchronizer_trust_certificates.propose(ROLLED_BACK_PID, SYNC_ID, store = Some(SYNC_STORE), change = TopologyChangeOp.Remove)
utils.retry_until_true(!trusted(oldp, ROLLED_BACK_PID) && !trusted(peer, ROLLED_BACK_PID))
check(trusted(peer, OLD_PID), "the old participant lost its trust certificate in the rollback")
println(s"E2E-ROLLBACK ${ROLLED_BACK_PID.toProtoPrimitive} offboarded, $VALIDATOR_PARTY still on ${OLD_PID.toProtoPrimitive}")

// ------------------------------------------------------------------------------------------------
// Second cutover, with another NEW_ID and a signing key of its own.
// ------------------------------------------------------------------------------------------------
val ACS_FILE = Paths.get(WORK, "acs-old.gz").toString
val ACS_REFERENCE = stopOld(ACS_FILE)
val (newPid, newSigning, newEncryption) = onboard(newp2, NEW_ID, "signing-2", syncCfg)
val NEW_PID = newPid
check(newSigning.fingerprint != rolledBackSigning.fingerprint, "the retry got the signing key of the rolled-back attempt")
newp2.dars.upload(DAR)
newp2.health.ping(peer)
check(trusted(peer, OLD_PID) && hosts(peer).isEmpty, "the party moved before the point of no return")

// Step 6 without Splice. Its party migrator makes these changes, in this order; here the new
// participant issues them, signed by the imported namespace key through the cosigner cluster.
// The point of no return: the old participant's trust certificate is removed.
newp2.topology.synchronizer_trust_certificates.propose(OLD_PID, SYNC_ID, store = Some(SYNC_STORE), change = TopologyChangeOp.Remove)
utils.retry_until_true(!trusted(newp2, OLD_PID) && !trusted(peer, OLD_PID))
Thread.sleep(2000) // past the topology change delay: the removal is effective when the hosting is checked
// The party, which was the old participant's admin party, is hosted on the new participant.
newp2.topology.party_to_participant_mappings.propose(
  party = VALIDATOR_PARTY,
  newParticipants = Seq(NEW_PID -> ParticipantPermission.Submission),
  store = SYNC_STORE,
  mustFullyAuthorize = true)
utils.retry_until_true(
  newp2.topology.party_to_participant_mappings.is_known(SYNC_ID, VALIDATOR_PARTY, Seq(NEW_PID)) &&
    peer.topology.party_to_participant_mappings.is_known(SYNC_ID, VALIDATOR_PARTY, Seq(NEW_PID)))
// The ACS: Splice imports it from Scan, this imports the reference ACS of Step 4.2 (migration.md
// §7, "Non-DSO contracts"). A repair needs the node disconnected and a ledger end that is not a
// topology change, hence the ping first.
newp2.health.ping(peer)
newp2.synchronizers.disconnect_all()
newp2.repair.import_acs(SYNC_ID, ACS_FILE)
newp2.synchronizers.reconnect_all()
utils.retry_until_true(newp2.synchronizers.active("da"))
println(s"E2E-MOVED $VALIDATOR_PARTY to ${NEW_PID.toProtoPrimitive}")

// ------------------------------------------------------------------------------------------------
// Step 7: verify.
// ------------------------------------------------------------------------------------------------
check(newp2.id == NEW_PID && newp2.id.uid.namespace.fingerprint.unwrap == NS_FP, s"new participant id ${newp2.id}")
check(hosts(newp2) == Seq(NEW_PID) && hosts(peer) == Seq(NEW_PID), s"$VALIDATOR_PARTY is hosted on ${hosts(peer)}")
check(!trusted(peer, OLD_PID), "the old trust certificate is still there")
utils.retry_until_true(acs(newp2, VALIDATOR_PARTY) == ACS_REFERENCE)
println(s"E2E-ACS ${ACS_REFERENCE.size} contracts of $VALIDATOR_PARTY on the new participant, the reference ACS")
// The new participant transacts. It submits on a migrated contract (the party is the owner)…
val owned = newp2.ledger_api.javaapi.state.acs.filter(Iou.COMPANION)(VALIDATOR_PARTY, _.data.owner == VALIDATOR_PARTY.toProtoPrimitive)
check(owned.size == 1, s"migrated contracts owned by the party: ${owned.size}")
newp2.ledger_api.javaapi.commands.submit(Seq(VALIDATOR_PARTY), owned.head.id.exerciseCall().commands.asScala.toSeq)
// …it confirms when the counter-party exercises on a migrated contract the party signed…
val owed = peer.ledger_api.javaapi.state.acs.filter(Iou.COMPANION)(bob, c => c.data.payer == VALIDATOR_PARTY.toProtoPrimitive && c.data.owner == bob.toProtoPrimitive)
check(owed.size == 2, s"migrated contracts the party signed, as the counter-party sees them: ${owed.size}")
peer.ledger_api.javaapi.commands.submit(Seq(bob), owed.head.id.exerciseCall().commands.asScala.toSeq)
// …and it creates a new contract.
newp2.ledger_api.javaapi.commands.submit(Seq(VALIDATOR_PARTY), iou(VALIDATOR_PARTY, bob, 400))
newp2.health.ping(peer)
peer.health.ping(newp2)
println("E2E-TRANSACT OK: exercise as submitter, exercise as confirmer, create, pings both ways")
// ACS commitments between the new participant and the counter-party, over several intervals.
sequencer1.topology.synchronizer_parameters.propose_update(
  SYNC_ID, _.update(reconciliationInterval = PositiveDurationSeconds.ofSeconds(5)))
val commitmentsFrom = Instant.now
for (_ <- 1 to 5) { Thread.sleep(5000); newp2.health.ping(peer) }
// Informational: with protocol version 36 these inspection commands may see nothing. The shell
// script checks both nodes' logs for commitment mismatches.
val received = scala.util.Try(peer.commitments.received("da", commitmentsFrom, Instant.now, Some(NEW_PID)).size)
println(s"E2E-COMMITMENTS received by the counter-party from the new participant since the interval change: $received")

val newKeys = newp2.keys.secret.list()
def kmsId(fp: Fingerprint): String = newKeys.find(_.publicKey.fingerprint == fp).flatMap(_.kmsKeyId).map(_.unwrap).getOrElse(fail(s"no KMS id for $fp"))
mark("migrated", "NEW_PID" -> NEW_PID.toProtoPrimitive, "PARTY" -> VALIDATOR_PARTY.toProtoPrimitive,
  "NS_KMS_ID" -> kmsId(Fingerprint.tryFromString(NS_FP)), "SIG_KMS_ID" -> kmsId(newSigning.fingerprint), "ENC_KMS_ID" -> kmsId(newEncryption.fingerprint))

// ------------------------------------------------------------------------------------------------
// Step 8 runs in the shell script: every old copy on this machine is destroyed.
// ------------------------------------------------------------------------------------------------
await("destroyed")
// Optional (b4-rehearsal.md 5.2, Lessons i): the offboarded member's owner-to-key mapping, which
// still lists the old keys, is removed. The namespace key signs it through FROST.
val oldOtk = newp2.topology.owner_to_key_mappings.list(store = Some(SYNC_STORE), filterKeyOwnerUid = OLD_UID).filter(_.item.member == OLD_PID)
check(oldOtk.size == 1, s"owner-to-key mappings of the old member: ${oldOtk.size}")
newp2.topology.owner_to_key_mappings.propose(member = oldOtk.head.item.member, keys = oldOtk.head.item.keys,
  ops = TopologyChangeOp.Remove, store = SYNC_STORE, force = ForceFlags(ForceFlag.AlienMember))
utils.retry_until_true(!peer.topology.owner_to_key_mappings.list(store = Some(SYNC_STORE), filterKeyOwnerUid = OLD_UID).exists(_.item.member == OLD_PID))
// Nothing the new participant needs was among the destroyed copies.
newp2.ledger_api.javaapi.commands.submit(Seq(VALIDATOR_PARTY), iou(VALIDATOR_PARTY, bob, 500))
newp2.health.ping(peer)
peer.health.ping(newp2)
println("E2E-AFTER-DESTRUCTION the old member's OTK is removed; the new participant transacts")
println("E2E-DONE")
sys.exit(0)
EOF

export EXPORT_PW
EXPORT_PW="$(openssl rand -base64 24)" # Step 2.3: random, at least 24 characters, in the environment only
EXPORT_FILE="$WORK/export/namespace.export"

step "Run Canton 3.6.1 ($JAVA_HOME); it stays up until the end"
(
  cd "$WORK"
  export E2E_WORK="$WORK" E2E_OLD_ID="oldp" E2E_NEW_ID_ROLLED_BACK="$NEW_ID_ROLLED_BACK" E2E_NEW_ID="$NEW_ID" \
    E2E_DAR="$CANTON_HOME/dars/CantonExamples.dar" EXTRA_CLASSPATH="$DRIVER_JAR"
  exec "$CANTON_HOME/bin/canton" run "$WORK/e2e.canton" \
    --config "$WORK/canton.conf" --no-tty --log-file-name "$WORK/canton.log" --kms-log-file-name "$WORK/canton_kms.log" \
    >"$WORK/canton.out" 2>&1
) &
CANTON_PID=$!

# ---------------------------------------------------------------------------------------------
# Steps 1 and 2 (in Canton): baselines, NS_FP, the export.
# ---------------------------------------------------------------------------------------------
step "Steps 1-2. Baselines; the namespace key exported with a password (keys.secret.download_to)"
wait_marker exported
grep "^E2E" "$WORK/canton.out" || true
NS_FP="$(value exported NS_FP)"
OLD_UID="$(value exported OLD_UID)"
PARTY="$(value exported PARTY)"
OLD_SIG_FP="$(value exported OLD_SIG_FP)"
[[ "$NS_FP" =~ ^1220[0-9a-f]{64}$ ]] || fail "NS_FP from the old participant: '$NS_FP'"
[ "$PARTY" = "${OLD_UID%%::*}::$NS_FP" ] || fail "party $PARTY is not <hint>::NS_FP"
KEY_ID="${PREFIX}frost-import-${NS_FP:4:8}" # migration.md §2
[ -s "$EXPORT_FILE" ] || fail "no export file"
EXPORT_SHA="$(openssl dgst -sha256 -hex "$EXPORT_FILE" | awk '{print $NF}')"
echo "old participant $OLD_UID, party $PARTY"
echo "export file sha256 $EXPORT_SHA; KEY_ID $KEY_ID"

# ---------------------------------------------------------------------------------------------
# Step 3: split ceremony (docs/split-ceremony.md §4), against the running cluster.
# ---------------------------------------------------------------------------------------------
step "Step 3. Recipient requests and Gate 0 (SAS read back from each node's sealed state)"
SAS=()
for i in 1 2 3; do
  out="$(cli --config "$WORK/c$i.json" share-recipient --key-id "$KEY_ID" --ceremony-id "$CEREMONY" \
    --out "$WORK/r$i.json")"
  SAS+=("$(awk -v n="$i" '$1 == "SAS" && $3 == n {print $4}' <<<"$out")")
  [ -n "${SAS[$((i - 1))]}" ] || fail "share-recipient on node $i printed no SAS"
  witness="$(cli --config "$WORK/c$i.json" recipient-sas --key-id "$KEY_ID" | awk '{print $4}')"
  [ "$witness" = "${SAS[$((i - 1))]}" ] || fail "recipient-sas on node $i disagrees: $witness"
done
SAS_LIST="$(IFS=,; echo "${SAS[*]}")"

# The runbook's dealer host is air-gapped, live-booted and has neither swap nor a core handler; a
# laptop or a CI runner has both: --allow-swap --allow-core-handler. --confirm-sas types the SAS.
dealer() { # expected-fingerprint  out-dir  [password option…]
  local fp=$1 out=$2
  shift 2
  "$DEALER" split-key --in "$EXPORT_FILE" "$@" \
    --expect-fingerprint "$fp" --key-id "$KEY_ID" --threshold 2 --ca-cert "$WORK/certs/ca.crt" \
    --recipient "$WORK/r1.json" --recipient "$WORK/r2.json" --recipient "$WORK/r3.json" \
    --out-dir "$out" --allow-swap --allow-core-handler --confirm-sas "$SAS_LIST"
}
refused() { # what  expected-message  command…
  local what=$1 expect=$2
  shift 2
  if "$@" >"$WORK/refused.out" 2>&1; then fail "$what: accepted"; fi
  grep -q -- "$expect" "$WORK/refused.out" || fail "$what: refused for the wrong reason: $(cat "$WORK/refused.out")"
  echo "$what -> refused"
}

step "   the dealer refuses a wrong password, no password, and a wrong fingerprint"
export EXPORT_PW_WRONG="not-the-export-password"
refused "wrong export password" "wrong password" dealer "$NS_FP" "$WORK/dealer-refused" --password-env EXPORT_PW_WRONG
refused "no export password" "password-protected" dealer "$NS_FP" "$WORK/dealer-refused"
refused "wrong fingerprint (the old signing key's)" "not the expected" dealer "$OLD_SIG_FP" "$WORK/dealer-refused" --password-env EXPORT_PW
[ -e "$WORK/dealer-refused" ] && fail "a refused dealer run left output behind"

step "   split on the dealer (rutli-dealer split-key --password-env)"
dealer "$NS_FP" "$WORK/dealer" --password-env EXPORT_PW
DIGEST="$(jq -r .pkp_digest "$WORK/dealer/dealer-record.json")"
GROUP="$(jq -r .group_verifying_key "$WORK/dealer/dealer-record.json")"

step "   dry run (Gate A), a wrong fingerprint refused, install"
for i in 1 2 3; do
  rep="$(cli --config "$WORK/c$i.json" import-share --in "$WORK/dealer/share-$KEY_ID-node$i.json" \
    --expect-fingerprint "$NS_FP" --dry-run)"
  jq -e --arg d "$DIGEST" '.outcome == "dry-run" and .pkp_digest == $d' <<<"$rep" >/dev/null \
    || fail "dry run on node $i: $rep"
done
if cli --config "$WORK/c1.json" import-share --in "$WORK/dealer/share-$KEY_ID-node1.json" \
  --expect-fingerprint "$OLD_SIG_FP" >/dev/null 2>&1; then fail "import-share accepted a wrong fingerprint"; fi
echo "import-share with a wrong fingerprint -> refused"
for i in 1 2 3; do
  rep="$(cli --config "$WORK/c$i.json" import-share --in "$WORK/dealer/share-$KEY_ID-node$i.json" \
    --expect-fingerprint "$NS_FP")"
  jq -e --arg d "$DIGEST" '.outcome == "installed" and .pkp_digest == $d' <<<"$rep" >/dev/null \
    || fail "import on node $i: $rep"
done

step "   verify-key --sign-test with the operator certificate (Gate B)"
rep="$(verify_key --sign-test)"
jq -e --arg d "$DIGEST" '.ok and .pkp_digest == $d and .refresh_count == 0 and (.sign_test | length == 3)
  and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null || fail "verify-key: $rep"
if cli --config "$WORK/operator.json" verify-key --key-id "$KEY_ID" --expect-fingerprint "$OLD_SIG_FP" >/dev/null 2>&1; then
  fail "verify-key accepted a wrong fingerprint"
fi
echo "Gate B: 3/3 nodes, digest $DIGEST, every 2-of-3 quorum signs; a wrong fingerprint -> refused"

step "   refresh with the refresher certificate, verify-key again (Gate C)"
out="$(cli --config "$WORK/refresher.json" refresh --key-id "$KEY_ID")"
grep -q "$GROUP" <<<"$out" || fail "refresh changed the group key: $out"
rep="$(verify_key --sign-test)"
jq -e --arg d "$DIGEST" '.ok and .pkp_digest != $d and .refresh_count == 1 and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null \
  || fail "verify-key after refresh: $rep"
echo "Gate C: group key unchanged, new digest $(jq -r .pkp_digest <<<"$rep"), refresh count 1"

step "   a dealt bundle is refused after the refresh"
for i in 1 2 3; do
  if cli --config "$WORK/c$i.json" import-share --in "$WORK/dealer/share-$KEY_ID-node$i.json" \
    --expect-fingerprint "$NS_FP" >/dev/null 2>&1; then fail "node $i re-imported a dealt bundle over a refreshed key"; fi
done
echo "re-import after refresh -> refused on every node"

step "   founding backups, after the refresh (daemons running, as the chart's backup sidecar takes them)"
for i in 1 2 3; do
  out="$(cli --config "$WORK/c$i.json" backup --out "$WORK/backup-founding/node$i")"
  grep -q "^backed up [1-9][0-9]* share file(s)" <<<"$out" || fail "founding backup of node $i: $out"
  ls "$WORK/backup-founding/node$i" | grep -q -- "$KEY_ID" || fail "the founding backup of node $i lacks $KEY_ID"
done
rep="$(verify_key)"
jq -e '.ok and .refresh_count == 1' <<<"$rep" >/dev/null || fail "verify-key after the backups: $rep"

# ---------------------------------------------------------------------------------------------
# Steps 4-7 (in Canton): the cutover that is rolled back, the cutover that goes through, verify.
# ---------------------------------------------------------------------------------------------
step "Steps 4-7. Cutover rolled back (§6), cutover again, the party moved, verification"
printf 'KEY_ID=%s\n' "$KEY_ID" >"$WORK/sync/ceremony.env"
mark ceremony
wait_marker migrated 900
grep "^E2E" "$WORK/canton.out" || true
grep -q "^E2E-ROLLBACK " "$WORK/canton.out" || fail "the rollback did not run"
NEW_PID="$(value migrated NEW_PID)"
SIG_KMS_ID="$(value migrated SIG_KMS_ID)"
ENC_KMS_ID="$(value migrated ENC_KMS_ID)"
[ "$NEW_PID" = "PAR::${NEW_ID}::${NS_FP}" ] || fail "new participant id $NEW_PID"
[ "$(value migrated PARTY)" = "$PARTY" ] || fail "the party id changed: $(value migrated PARTY)"
[ "$(value migrated NS_KMS_ID)" = "$KEY_ID" ] || fail "the namespace key is registered as $(value migrated NS_KMS_ID)"
[ "$SIG_KMS_ID" = "${PREFIX}frost-signing-2" ] || fail "the signing key is $SIG_KMS_ID"
case "$ENC_KMS_ID" in "${PREFIX}rutli-enc-encryption-"*) ;; *) fail "the encryption key is $ENC_KMS_ID" ;; esac
echo "party $PARTY unchanged, hosted on $NEW_PID; keys $KEY_ID, $SIG_KMS_ID, $ENC_KMS_ID"

step "Step 4.3. The driver loaded and the cluster offers ECIES"
grep -qh "Loaded driver rutli" "$WORK"/canton*.log || fail "no 'Loaded driver rutli' in the Canton log"
grep -qh "every cosigner hosts non-FROST keys (.*ec-p256-ecies" "$WORK"/canton*.log || fail "the driver never saw ec-p256-ecies in Capabilities"

step "Step 7. The driver's audit: threshold signatures with the imported namespace key, nothing failed"
AUDIT="$WORK/driver-audit-newp2.jsonl"
[ -s "$AUDIT" ] || fail "no driver audit log for the new participant"
count() { # op  key-id
  grep -F "\"op\":\"$1\",\"detail\":\"keyId=$2 " "$AUDIT" | grep -c "outcome=ok" || true
}
NS_OK="$(count sign "$KEY_ID")"
SIG_OK="$(count sign "$SIG_KMS_ID")"
ENC_OK="$(count decryptAsymmetric "$ENC_KMS_ID")"
BAD="$(cat "$WORK"/driver-audit-newp*.jsonl | grep -c "outcome=failed" || true)"
echo "sign ok: $KEY_ID $NS_OK, $SIG_KMS_ID $SIG_OK; ECIES decrypt ok: $ENC_KMS_ID $ENC_OK; failed: $BAD"
# OTK, trust certificate, package vetting, the old trust certificate's removal, the party's hosting.
[ "$NS_OK" -ge 4 ] || fail "only $NS_OK signatures with the imported namespace key $KEY_ID"
[ "$SIG_OK" -gt 0 ] || fail "no signature with the fresh signing key $SIG_KMS_ID"
[ "$ENC_OK" -gt 0 ] || fail "no ECIES decryption with the hosted key $ENC_KMS_ID"
[ "$BAD" -eq 0 ] || fail "$BAD driver operations failed: $(cat "$WORK"/driver-audit-newp*.jsonl | grep "outcome=failed" | head -n 3)"
grep -q 'intent=[0-9a-f]\{32\}' "$AUDIT" || fail "the driver audit log names no signing intent"
# A threshold signature: at least two cosigners journaled signatures with the namespace key, each
# under an intent the driver signed; none without one.
JOURNALED=0
for i in 1 2 3; do
  n="$(cat "$WORK/node$i/journal/$KEY_ID"/*.jsonl 2>/dev/null | grep -c '"purpose":"sign".*"signer_cn":"driver"' || true)"
  echo "node $i journaled $n signature(s) with $KEY_ID under a driver intent"
  [ "$n" -gt 0 ] && JOURNALED=$((JOURNALED + 1))
done
[ "$JOURNALED" -ge 2 ] || fail "only $JOURNALED cosigner(s) journaled signatures with $KEY_ID"
NOINTENT="$(cat "$WORK"/node*/journal/*/*.jsonl | grep -c '"purpose":"no-intent"' || true)"
[ "$NOINTENT" -eq 0 ] || fail "$NOINTENT signature(s) without an intent under require_intent"

step "Step 7. No ACS commitment mismatch on the new participant or the counter-party"
if grep -hE "ACS_COMMITMENT_MISMATCH|ACS_MISMATCH_NO_SHARED_CONTRACTS|ACS_COMMITMENT_ALARM" "$WORK/canton.log" >"$WORK/commitments.txt"; then
  fail "ACS commitment errors: $(head -n 3 "$WORK/commitments.txt")"
fi

# ---------------------------------------------------------------------------------------------
# Step 8: destroy every old copy on this machine, with the checks a script can make.
# ---------------------------------------------------------------------------------------------
step "Step 8. Destruction: the export file, the old database, the dealer output, the request files"
# Lessons f: on macOS GNU coreutils can shadow /bin/rm, which has -P.
destroy() { if [ "$(uname)" = Darwin ]; then /bin/rm -P -rf "$@"; else rm -rf "$@"; fi; }
[ "$(openssl dgst -sha256 -hex "$EXPORT_FILE" | awk '{print $NF}')" = "$EXPORT_SHA" ] || fail "the export file changed since Step 2"
ls "$WORK/old-db"/participant_1* >/dev/null 2>&1 || fail "the old participant's database is not where the config put it"
ls -l "$WORK/export" "$WORK/old-db" "$WORK/dealer"
destroy "$WORK/export" "$WORK/old-db" "$WORK/dealer" "$WORK"/r[0-9].json "$WORK"/acs-old-attempt1.gz
for gone in "$WORK/export" "$WORK/old-db" "$WORK/dealer" "$WORK/r1.json" "$WORK/r2.json" "$WORK/r3.json"; do
  [ ! -e "$gone" ] || fail "$gone is still there"
done
# Ceremony residue on the cosigners: the one-time recipient secrets died at install, and the only
# backups are the founding ones, taken after the refresh.
for i in 1 2 3; do
  [ ! -e "$WORK/node$i/ceremony/$KEY_ID.recipient" ] || fail "node $i kept its recipient secret"
done
[ "$(find "$WORK" -maxdepth 1 -name 'backup-*' | wc -l | tr -d ' ')" = 1 ] || fail "a backup other than the founding one exists"
# No file left in the work dir is the export (by content), wherever it might have been copied.
while IFS= read -r f; do
  [ "$(openssl dgst -sha256 -hex "$f" | awk '{print $NF}')" != "$EXPORT_SHA" ] || fail "a copy of the export file survives: $f"
done < <(find "$WORK" -type f -size -64k)
rep="$(verify_key --sign-test)"
jq -e '.ok and .refresh_count == 1 and all(.sign_test[]; .ok)' <<<"$rep" >/dev/null || fail "verify-key after the destruction: $rep"
echo "destroyed; verify-key --sign-test OK on the refreshed shares"

step "   after the destruction: the old member's OTK removed, the new participant still transacts"
mark destroyed
if ! wait "$CANTON_PID"; then CANTON_PID=0; fail "Canton run failed"; fi
CANTON_PID=0
grep -q "^E2E-DONE" "$WORK/canton.out" || fail "the bootstrap script did not finish"
grep "^E2E-AFTER-DESTRUCTION" "$WORK/canton.out"
BAD="$(cat "$WORK"/driver-audit-newp*.jsonl | grep -c "outcome=failed" || true)"
[ "$BAD" -eq 0 ] || fail "$BAD driver operations failed after the destruction"
if grep -hE "ACS_COMMITMENT_MISMATCH|ACS_MISMATCH_NO_SHARED_CONTRACTS|ACS_COMMITMENT_ALARM" "$WORK/canton.log" >"$WORK/commitments.txt"; then
  fail "ACS commitment errors: $(head -n 3 "$WORK/commitments.txt")"
fi

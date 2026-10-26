# Runbook: in-place migration of an existing validator into Rütli (Flow 2a)

**Status:** rehearsed on DevNet 2026-10-23..26 (roadmap milestone B8: a Splice 0.9.0 / Canton 3.6.1 JCE validator, Rütli
`0.4.0-rc.4` with ceremony intents enforced). Phases 0–4 and the 5.1 verification passed. **Rotation (5.2), the 24 h
observation (5.3), the SQL cleanup (5.4) and destruction (5.5) have not been rehearsed yet: treat them as unproven.**
Every Scala block here compiles against the Canton 3.6.1 release jar (checked 2026-10-26, with a negative control); those
of Phases 0–4 and 5.1 are generalised from the blocks that ran in B8.
**Applies to:** Splice 0.9.x validators on Canton 3.6.x whose keys Canton holds itself (JCE, rows in Postgres), moving
into a Rütli cluster ≥ 0.4.0-rc.4. **Audience:** the validator operator and the cluster operator.

Flow 2a keeps **the same participant, the same database and the same UID**. Every active key is carried into the cluster
with its exact fingerprint, the node restarts on `crypto.provider = kms` and registers the carried keys by KMS id. Nothing
is re-onboarded and nothing on the ledger changes. Background and the 2a/2b decision: [roadmap.md](roadmap.md), "Two
flows". The exposure caveat of [migration.md](migration.md) ("Read this first") applies unchanged: every key that ever sat
in the database stays exposed to whoever copied it before destruction.

Conventions: zsh on macOS. `[MUTATES]` = the block changes something; run it only after reading its `Expect` and `STOP`.
`STOP` = do not continue; go to the rollback named in §R. Every block starts with `source $D/env.sh`. B8 values appear only
as *"observed in the rehearsal"*.

---

## 0. Scope: 2a or 2b

| | 2a: in place (this runbook) | 2b: new participant ([migration.md](migration.md)) |
|---|---|---|
| Participant UID, database | Unchanged | New UID (same namespace), new database |
| External parties, dApp contracts, wallet end-users | Unchanged (B8: end-user logged in without re-onboarding, balance identical to the last digit) | Unhosted / lost / must re-onboard |
| Keys carried | **All active keys** (namespace, signing, encryption) | Namespace only; fresh signing and encryption keys |
| Point of no return | None. Two rollback boundaries: RB1 (first rotation onto a Rütli-born key) and RB2 (SQL cleanup) | Removal of the old trust certificate |
| Wallet outage | ≈ 20 min (B8: 15:19:16 → 15:39:24Z) | ≈ 1 h (B4) |
| DA documentation | **Not a DA-documented procedure** (support risk) | The documented shape |

Use 2a for nodes with external parties, dApps, multi-hosted parties or many wallet users. Use 2b for a plain validator, or
when the client wants the DA-documented shape. STOP and use 2b (or ask us) if Phase 0 finds an RSA encryption key (Rütli
cannot import RSA), an intermediate namespace key you cannot carry, or a pending Splice key rotation you cannot clear.

---

## 1. Prerequisites and decisions

| # | Decision | Default |
|---|---|---|
| D1 | Key prefix `PREFIX` | Unique on the cluster, fixed forever (e.g. `acme1-`). The carried ids are `${PREFIX}frost-import-${NS_FP:4:8}`, `${PREFIX}frost-import-sig-${SIG_FP:4:8}`, `${PREFIX}rutli-enc-imported-${ENC_FP:4:8}` |
| D2 | Driver certificate | **A dedicated driver certificate per participant** (own CN, e.g. `driver-acme1`, issued by the cluster CA), its SPKI pinned. *Drill-only shortcut: B8 reused the soak participant's certificate (CA key lost), so both participants could use both key sets.* |
| D3 | Rotate after the switch (client choice, [roadmap.md](roadmap.md) "Keys across flows") | **Rotate the encryption key** (5.2a). Rotating the signing key is optional but recommended in place: it drops the namespace usage Splice's `signing` key carries. Keeping the carried keys needs confirmed destruction (5.5). Either rotation crosses RB1 |
| D4 | Post-import Refresh | **Mandatory in production** ([split-ceremony.md](split-ceremony.md) Step 6, Gate C). Needs a `refreshAllowlist` certificate, or `signer_may_refresh: true` for the window. *B8 skipped it (no refresher certificate).* |
| D5 | Export password | One random ≥ 24-char password for the three exports, in a password manager, typed at hidden prompts only |
| D6 | Dealer host | Air-gapped Linux, live-booted, no swap ([split-ceremony.md](split-ceremony.md) §3.3). A laptop with `--allow-swap` is for test networks only |
| D7 | Ping target `PING_TARGET` | A participant you operate on the same synchronizer (B8: the soak participant) |
| D8 | Observation before RB2 | ≥ 24 h, two green health checks |

**Checklist** (all before Phase 2):
- [ ] Cosigners, driver jar, dealer and `rutli-cosigner` CLI all on the same release ≥ 0.4.0-rc.4; jar sha256 recorded.
      `signing_policy.require_ceremony_intent` may be on (split and import are offline; only DKG/refresh need intents).
- [ ] Network: the validator namespace labelled `rutli.io/client-ns=true`, participant pod `rutli.io/client=true`, egress to
      the cosigners on 9101 ([migration.md](migration.md) §3).
- [ ] Capacity on the participant's node for two small helper pods.
- [ ] Wallet baseline recorded (Phase 0.3), alerting silence prepared (4.2), no network upgrade within 48 h.
- [ ] A work directory excluded from backups and sync (`tmutil addexclusion $D`): the export files pass through it.

**Environment file** (adapt the first block; `_rf` reads values Phase 0 writes):
```zsh
export D=$HOME/mig-acme1; mkdir -p $D/{con,keep,evidence,tls,cer} && chmod -R go-rwx $D && tmutil addexclusion $D
cat > $D/env.sh <<'EOF'
export D=$HOME/mig-acme1 NS=acme-validator RNS=rutli PREFIX=acme1- HINT=acme-validator-1 CLUSTER_ID='<16 hex>'
export CHART_PARTICIPANT=oci://ghcr.io/digital-asset/decentralized-canton-sync/helm/splice-participant CHART_VER=0.9.0
export PG_POD=pg-1 PG_USER=postgres PG_DATA=/var/lib/postgresql/data JAR=$D/rutli-driver.jar JAR_SHA='<release sha256>'
export PING_TARGET='PAR::<id>::<fp>' RC=$D/bin/rutli-cosigner DEALER=$D/bin/rutli-dealer NODE='<participant k8s node>'
_rf() { [ -s $D/con/$1 ] && cat $D/con/$1; }
export PDB=$(_rf PDB.txt) P_REV0=$(_rf P_REV0.txt) IMAGE_PARTICIPANT=$(_rf IMAGE.txt) NS_FP=$(_rf NS_FP.txt) SIG_FP=$(_rf SIG_FP.txt) ENC_FP=$(_rf ENC_FP.txt)
[ -n "$NS_FP" ] && export NS_ID=${PREFIX}frost-import-${NS_FP:4:8} SIG_ID=${PREFIX}frost-import-sig-${SIG_FP:4:8} ENC_ID=${PREFIX}rutli-enc-imported-${ENC_FP:4:8}
P()  { kubectl -n $NS exec $PG_POD -c postgres -- psql -U $PG_USER -At "$@"; }        # read-only unless the SQL says otherwise
kx() { local i=$1; shift; kubectl -n $RNS exec rutli-cosigner-$((i-1)) -c cosigner "$@"; }   # node i; perNode topology: rutli-node-<i>-0
cs() { local i=$1; shift; kx $i -- rutli-cosigner --config /config/cosigner-$i.json "$@"; }
rc() { RUST_LOG=warn $RC --config $D/cer/client.json "$@"; }
pf_start() { pf_stop; for o in 0 1 2; do ( while true; do kubectl -n $RNS port-forward pod/rutli-cosigner-$o 1910$((o+1)):9101 >/dev/null 2>&1; sleep 1; done ) & done; sleep 4; }
pf_stop() { pkill -f 'port-forward pod/rutli-cosigner-' 2>/dev/null; true; }
# Copies: exec/cp streams can truncate silently or arrive empty. Every copy is sha256-checked and retried.
push() { local ns=$1 pod=$2 c=$3 src=$4 dst=$5 w t; w=$(shasum -a 256 < $src | cut -d' ' -f1)
  for t in 1 2 3 4 5; do kubectl -n $ns exec -i $pod -c $c -- sh -c "umask 077; cat > $dst" < $src
    [ "$(kubectl -n $ns exec $pod -c $c -- sha256sum $dst | cut -d' ' -f1)" = "$w" ] && return 0; echo "push retry $t" >&2; done
  echo "STOP: push $src" >&2; return 1; }
pulls() { local ns=$1 pod=$2 c=$3 src=$4 dst=$5 t; for t in 1 2 3 4 5; do kubectl -n $ns exec $pod -c $c -- cat $src > $dst   # small files
  [ "$(kubectl -n $ns exec $pod -c $c -- sha256sum $src | cut -d' ' -f1)" = "$(shasum -a 256 < $dst | cut -d' ' -f1)" ] && return 0; done; echo "STOP: pull $src" >&2; return 1; }
pull() { local ns=$1 pod=$2 c=$3 src=$4 dst=$5 sz n r t w; sz=$(kubectl -n $ns exec $pod -c $c -- stat -c %s $src) || return 1; : > $dst
  for ((n = 0; n * 1048576 < sz; n++)); do r=$(( sz - n*1048576 < 1048576 ? sz - n*1048576 : 1048576 ))
    for t in 1 2 3 4 5; do kubectl -n $ns exec $pod -c $c -- sh -c "tail -c +$((n*1048576+1)) $src | head -c $r" > $dst.c 2>/dev/null
      w=$(kubectl -n $ns exec $pod -c $c -- sh -c "tail -c +$((n*1048576+1)) $src | head -c $r | sha256sum" | cut -d' ' -f1)
      [ -n "$w" ] && [ "$(shasum -a 256 < $dst.c | cut -d' ' -f1)" = "$w" ] && break; [ $t = 5 ] && { echo "STOP: pull chunk $n" >&2; return 1; }; done
    cat $dst.c >> $dst; done; rm -f $dst.c; }
AUD() { local f=$D/evidence/audit-$1.jsonl; pull $NS $(kubectl -n $NS get pod -l app=participant -o name | head -1 | cut -d/ -f2) participant /rutli-state/audit.jsonl $f && echo $f; }
con() { local s=$D/con/run-${@[-1]}.sc; (for f in "$@"; do cat $D/con/$f.sc; echo; done; echo 'sys.exit(0)') > $s
  docker run --rm --platform linux/amd64 -v $D/con:/w -e LEDGER_API_TOKEN -e EXPORT_PW -e PING_TARGET --entrypoint /app/bin/canton "$IMAGE_PARTICIPANT" \
    run /w/${s:t} -c /w/remote.conf 2>&1 | tee $D/con/${@[-1]}.out | grep -vE 'INFO|DEBUG|SLF4J|logback|^\s*$' | tail -40; }
helper() { kubectl -n $NS get pod rutli-kms-populate >/dev/null 2>&1 || kubectl -n $NS apply -f - <<H   # RWO volumes: delete it before the participant starts
{apiVersion: v1, kind: Pod, metadata: {name: rutli-kms-populate, labels: {rutli.io/client: "true"}}, spec: {restartPolicy: Never, nodeSelector: {kubernetes.io/hostname: $NODE}, containers: [{name: p, image: "docker.io/library/busybox:1.36", command: [sleep, "7200"], volumeMounts: [{name: b, mountPath: /bundle}, {name: s, mountPath: /state}]}], volumes: [{name: b, persistentVolumeClaim: {claimName: rutli-kms-bundle}}, {name: s, persistentVolumeClaim: {claimName: rutli-driver-state}}]}}
H
  kubectl -n $NS wait --for=condition=Ready pod/rutli-kms-populate --timeout=300s; }
EOF
source $D/env.sh; kubectl config current-context
cat > $D/con/remote.conf <<'EOF'
canton {
  features { enable-preview-commands = yes, enable-repair-commands = yes }
  remote-participants.participant {
    admin-api { address = "host.docker.internal", port = 5002 }
    ledger-api { address = "host.docker.internal", port = 5001 }
    token = ${?LEDGER_API_TOKEN}
  }
}
EOF
```

**Console.** Script mode (`canton run x.sc`) prints **nothing** for returned values: every block below `println`s what you
need. `LEDGER_API_TOKEN` is a ledger-API admin token from your IdP; check its `exp` before each session. In a separate tab
keep the port-forward alive: it dies on **every** participant restart, so re-check it before each console step.
```zsh
source $D/env.sh; while true; do kubectl -n $NS port-forward deploy/participant 5002:5002 5001:5001; echo "forward died $(date)"; sleep 2; done
```
`$D/con/pre.sc` (shared helpers) and `$D/con/ids.sc` (values from Phase 0), used as `con pre ids <step>`:
```scala
// pre.sc
import com.digitalasset.canton.crypto._
val p = participant; val ALIAS = SynchronizerAlias.tryCreate("global")
def rd(f: String): String = java.nio.file.Files.readString(java.nio.file.Paths.get("/w/" + f)).trim
def wr(f: String, s: String): Unit = { java.nio.file.Files.writeString(java.nio.file.Paths.get("/w/" + f), s); () }
def usageOf(k: PublicKey): String = k match { case s: SigningPublicKey => s.usage.toSeq.map(_.identifier).sorted.mkString(","); case _ => "-" }
def sha(f: String): String = java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(f))).map("%02x".format(_)).mkString
// ids.sc
val UID = rd("UID.txt"); val NS_FP = rd("NS_FP.txt"); val SIG_FP = rd("SIG_FP.txt"); val ENC_FP = rd("ENC_FP.txt"); val PREFIX = rd("PREFIX.txt")
val SYNC_ID = com.digitalasset.canton.topology.SynchronizerId.tryFromString(rd("sync-id.txt")); val SS = TopologyStoreId.Synchronizer(SYNC_ID)
val NS_ID = PREFIX + "frost-import-" + NS_FP.substring(4, 12); val SIG_ID = PREFIX + "frost-import-sig-" + SIG_FP.substring(4, 12); val ENC_ID = PREFIX + "rutli-enc-imported-" + ENC_FP.substring(4, 12)
println(s"UID=$UID NS_ID=$NS_ID SIG_ID=$SIG_ID ENC_ID=$ENC_ID")
```

---

## Phase 0: inventory and baseline (read-only)

**0.1 Facts.** Record the participant release revision that runs today, its database and image.
```zsh
source $D/env.sh; echo -n $PREFIX > $D/con/PREFIX.txt
helm -n $NS history participant | tail -3; helm -n $NS history participant | tail -1 | awk '{print $1}' > $D/con/P_REV0.txt
helm -n $NS get values participant -o yaml > $D/participant-values.pre.yaml; chmod 600 $D/participant-values.pre.yaml
helm -n $NS get values participant -o json | jq -r .persistence.databaseName > $D/con/PDB.txt
kubectl -n $NS get deploy participant -o jsonpath='{.spec.template.spec.containers[0].image}' > $D/con/IMAGE.txt; source $D/env.sh
P -d $PDB -c "select count(*), count(*) filter (where wrapper_key_id is null) from participant.common_crypto_private_keys" -c "select count(*) from participant.common_kms_metadata_store" -c "select key_id, purpose, coalesce(name,'<NULL>') from participant.common_crypto_public_keys order by 2,1"
```
Expect `3|3`, `0`, three public keys named `namespace`, `signing` (purpose 0), `encryption` (purpose 1). **STOP** on a
`<NULL>` name (registration would conflict) or a non-zero KMS count. `P_REV0` must be the revision whose values you just
saved: a rollback to an older revision can point the node at another database (B8: rev 3 pointed at a deleted Postgres).

**0.2 Console baseline** (`$D/con/baseline.sc`, run `con pre baseline`). It asserts the exact shape 2a supports and writes
the fact files:
```scala
val UID = p.uid.toProtoPrimitive; val NS_FP = p.id.uid.namespace.fingerprint.unwrap
val sk = p.keys.secret.list(); val pk = p.keys.public.list()
sk.foreach(k => println(s"secret fp=${k.id.unwrap} name=${k.name.map(_.unwrap)} kms=${k.kmsKeyId.map(_.unwrap)} usage=${usageOf(k.publicKey)}"))
assert(sk.size == 3 && sk.forall(_.kmsKeyId.isEmpty), s"STOP: expected 3 JCE keys, got ${sk.size}")
assert(sk.map(_.name.map(_.unwrap)).toSet == Set(Some("namespace"), Some("signing"), Some("encryption")), "STOP: key names")
assert(pk.map(k => k.id.unwrap -> k.name.map(_.unwrap)).toSet == sk.map(k => k.id.unwrap -> k.name.map(_.unwrap)).toSet, "STOP: public store differs")
def byName(n: String) = sk.find(_.name.exists(_.unwrap == n)).get.publicKey
val NSK = byName("namespace").asInstanceOf[SigningPublicKey]; val SIGK = byName("signing").asInstanceOf[SigningPublicKey]; val ENCK = byName("encryption").asInstanceOf[EncryptionPublicKey]
assert(NSK.fingerprint.unwrap == NS_FP && NSK.usage.forgetNE == SigningKeyUsage.NamespaceOnly.forgetNE, "STOP: namespace key")
assert(SIGK.usage.forgetNE == SigningKeyUsage.All.forgetNE && SIGK.keySpec == SigningKeySpec.EcCurve25519, s"STOP: signing key ${SIGK.usage}")
assert(ENCK.keySpec == EncryptionKeySpec.EcP256, s"STOP: encryption key ${ENCK.keySpec} (RSA cannot be carried: use 2b)")
val SIG_FP = SIGK.fingerprint.unwrap; val ENC_FP = ENCK.fingerprint.unwrap
val conn = p.synchronizers.list_connected(); assert(conn.size == 1 && conn.head.healthy, s"STOP: $conn")
val SYNC_ID = conn.head.physicalSynchronizerId.logical; val SS = TopologyStoreId.Synchronizer(SYNC_ID)
println(s"UID=$UID PSID=${conn.head.physicalSynchronizerId}")       // the protocol version is read live, never hard-coded
val otk = p.topology.owner_to_key_mappings.list(store = Some(SS), filterKeyOwnerUid = UID)
val otkA = p.topology.owner_to_key_mappings.list(store = Some(TopologyStoreId.Authorized), filterKeyOwnerUid = UID)
println(s"OTK serial=${otk.head.context.serial}")
for (o <- Seq(otk, otkA)) assert(o.size == 1 && o.head.item.keys.map(_.fingerprint.unwrap).toSet == Set(SIG_FP, ENC_FP), "STOP: OTK is not exactly {signing, encryption}")
// Splice rotates, at validator start, every OTK signing key that never signed an OTK transaction: that must be empty
val hist = p.topology.transactions.list(store = SS, timeQuery = com.digitalasset.canton.topology.store.TimeQuery.Range(None, None), operation = None, filterMappings = Seq(TopologyMapping.Code.OwnerToKeyMapping), filterNamespace = NS_FP).result
val signers = hist.filter(_.mapping match { case m: com.digitalasset.canton.topology.transaction.OwnerToKeyMapping => m.member.uid.toProtoPrimitive == UID; case _ => false }).flatMap(_.transaction.signatures.toSeq).map(_.signature.authorizingLongTermKey.unwrap).toSet
val toRotate = otk.head.item.keys.filter(_.isSigning).map(_.fingerprint.unwrap).filterNot(signers)
println(s"splice rotation predicate: toRotate=$toRotate"); assert(toRotate.isEmpty, "STOP: Splice would mint a new signing key at the next validator start")
val nsd = p.topology.namespace_delegations.list(store = SS, filterNamespace = NS_FP)
assert(nsd.nonEmpty && nsd.forall(_.item.target.fingerprint.unwrap == NS_FP), "STOP: an intermediate namespace key exists")
assert(p.topology.namespace_delegations.list(store = SS, filterTargetKey = Some(Fingerprint.tryFromString(SIG_FP))).isEmpty, "STOP: the signing key is a delegation target")
val hosted = p.parties.hosted().map(_.party); hosted.foreach(x => println("hosted party: " + x))   // NOT ledger_api.parties.list(): network-wide on public networks
wr("UID.txt", UID); wr("NS_FP.txt", NS_FP); wr("SIG_FP.txt", SIG_FP); wr("ENC_FP.txt", ENC_FP); wr("sync-id.txt", SYNC_ID.toProtoPrimitive)
```
Expect no `STOP:`, `toRotate=List()`, the hosted parties (validator party plus end-users). Observed in the rehearsal: OTK
serial 1, two hosted parties, while `ledger_api.parties.list()` returned 10 000 (DevNet-wide). Then `source $D/env.sh;
echo $NS_ID $SIG_ID $ENC_ID`.

**0.3 Wallet baseline.** Find the validator **wallet** party (it is not necessarily the participant admin party
`<participant-uid>`):
```zsh
source $D/env.sh; ( kubectl -n $NS port-forward deploy/validator-app 5003:5003 >/dev/null & PF=$!; sleep 4
  curl -sf localhost:5003/api/validator/v0/validator-user | jq -r .party_id | tee $D/evidence/wallet-party.txt; kill $PF )
```
Expect a party ending in `::$NS_FP`. In the wallet UI, record the operator balance and **one end-user's** party and balance
in `$D/evidence/wallet.txt` (CC to the last digit).

**0.4 Location inventory.** List every place the three keys exist in plaintext: L1 DB rows, L2 WAL/replicas/PITR, L3 logical
dumps (backup PVC), L4 object storage incl. versions, L5 volume snapshots and **retired volumes**, L6 identities dumps,
later L7 export files, L8 laptop, L9 dealer, L10 ceremony artefacts ([split-ceremony.md](split-ceremony.md) §3.2). Check
that the backup CronJob actually produces files; B8 found it failing on a PVC permission error.

---

## Phase 1: cosigner signing policy (cluster operator) [MUTATES]

Before any carried key can sign, every cosigner needs the participant's CN, prefix and pin. **Helm replaces lists:** the
overlay restates the cluster's existing rules. **First matching prefix wins:** the `-sig-` rule must come before the
namespace rule, because `${PREFIX}frost-import-` is a prefix of `${PREFIX}frost-import-sig-` (the same pitfall as
[migration.md](migration.md) §8, "Ids and the approval-rule pitfall").
```yaml
signerAllowlist: [driver, driver-acme1]                 # + the new participant's CN (D2)
signingPolicy:
  rate_limits:                                          # existing rules first, unchanged; then:
    - {key_id_prefix: "acme1-frost-import-sig-", per_min: 600, per_day: 100000}   # carried signing key: size to the node's load
    - {key_id_prefix: "acme1-frost-import-",     per_min: 10,  per_day: 200}      # carried namespace key: topology only
    - {key_id_prefix: "acme1-",                  per_min: 600, per_day: 100000}   # catch-all: DKG keys of 5.2b
  signer_acl:  {driver: [frost-, rutli-], driver-acme1: [acme1-]}
  signer_pins: {driver: [<existing>], driver-acme1: [<sha256 of driver-acme1 SPKI>]}
```
SPKI pin: `openssl x509 -in driver.crt -noout -pubkey | openssl pkey -pubin -outform DER | shasum -a 256`. Roll it out as a
ConfigMap change with canary restarts, as in [runbook-rc4-soak-rollout.md](runbook-rc4-soak-rollout.md) Phase 3 (render,
diff, `helm upgrade`, restart node 2 → 3 → 1 with 5 min between, sign errors flat). Verify on every node:
```zsh
source $D/env.sh; for o in 0 1 2; do kubectl -n $RNS exec rutli-cosigner-$o -c cosigner -- cat /config/cosigner-$((o+1)).json | jq -c '.signing_policy | [.signer_acl, [.rate_limits[].key_id_prefix]]'; done
```
Expect the new CN and the prefixes in the order above on every node. A refusal raises the cluster's
`RutliSignPolicyRefusals`, so never probe before the rollout. Rollback: `helm rollback` to the previous revision + the same restarts.

---

## Phase 2: export the three keys, password-protected [MUTATES: creates export copies, L7]

The participant needs `canton.features.enable-preview-commands = yes`; the Splice 0.9.0 image already sets it. Probe with
`con pre ids probe` where `probe.sc` is
`println(scala.util.Try(p.keys.secret.download(Fingerprint.tryFromString("1220" + "00" * 32))))`: expect a `Failure`
saying *no private key found*. If it says *only allowed when preview is enabled*, add the flag as an `ADDITIONAL_CONFIG_*`
env var and restart (then `P_REV0` = that revision).

`export.sc`:
```scala
val PV = p.synchronizers.list_connected().head.physicalSynchronizerId.protocolVersion   // live; DevNet moved PV 35 -> 36 mid-drill
assert(sys.env.get("EXPORT_PW").exists(_.length >= 24), "EXPORT_PW missing or short")
val ks = p.keys.secret.list(); assert(ks.size == 3 && ks.forall(_.kmsKeyId.isEmpty))
for ((fp, n) <- Seq(NS_FP -> "namespace", SIG_FP -> "signing", ENC_FP -> "encryption")) {
  val k = ks.find(_.id.unwrap == fp).get; assert(k.name.exists(_.unwrap == n))
  p.keys.secret.download_to(k.id, s"/w/$n.export-pw.bin", protocolVersion = PV, password = Some(sys.env("EXPORT_PW")))
  println(s"export $n fp=$fp sha256=${sha(s"/w/$n.export-pw.bin")}") }
```
```zsh
source $D/env.sh; ( read -rs "EXPORT_PW?Export password (hidden): "; echo; export EXPORT_PW; con pre ids export
  kubectl -n $NS logs deploy/participant --since=30m | grep -cF -f <(printf '%s' "$EXPORT_PW") ); env | grep -c '^EXPORT_PW='
for n in namespace signing encryption; do mv $D/con/$n.export-pw.bin $D/keep/; done; shasum -a 256 $D/keep/*.export-pw.bin
```
Expect three `export … sha256=` lines equal to the `shasum` output, then `0` (password not in the logs) and `0`. Never
call the validator's `/admin/participant/identities` or `/admin/domain/data-snapshot`: on JCE they return plaintext keys.

---

## Phase 3: carry the keys (two split ceremonies + one ECIES import)

Run [split-ceremony.md](split-ceremony.md) §4 **twice**, first for the namespace key, then for the signing key; only the
differences are written here. Witnesses, dealer and records as there. The client config `$D/cer/client.json` uses the
participant's driver certificate (`verify-key`, `--sign-test` and `verify-hosted` accept the driver role; no ACL needed);
build it from the cosigner-shaped template in [runbook-rc4-soak-rollout.md](runbook-rc4-soak-rollout.md) "Prerequisites".
```zsh
cer() { case $1 in ns) K=ns KEY_ID=$NS_ID FP=$NS_FP IN=$D/keep/namespace.export-pw.bin MODE=(--expect-usage namespace);;
  sig) K=sig KEY_ID=$SIG_ID FP=$SIG_FP IN=$D/keep/signing.export-pw.bin MODE=(--expect-usage protocol --namespace-fingerprint $NS_FP);; esac
  CEREMONY=${PREFIX}$K-$(date -u +%Y%m%d); W=$D/cer/$K; mkdir -p $W; echo "$K $KEY_ID $FP $CEREMONY ${MODE[*]}"; }
```
**Absence check:** `pf_start; rc verify-key --key-id $NS_ID --expect-fingerprint $NS_FP; rc verify-key --key-id $SIG_ID
--expect-fingerprint $SIG_FP; rc verify-hosted --key-id $ENC_ID --expect-fingerprint $ENC_FP` → three failures (absent).
STOP if any id exists.

**S1 recipients + Gate 0** [MUTATES]: per node `cs $i share-recipient --key-id $KEY_ID --ceremony-id $CEREMONY --out
/tmp/r$i.json`, then `pulls $RNS rutli-cosigner-$((i-1)) cosigner /tmp/r$i.json $W/r$i.json`. Witnesses run `cs $i
recipient-sas --key-id $KEY_ID` in their own sessions and record the SAS.

**S2 dealer** (dealer host): split-ceremony.md Step 2 plus `"${MODE[@]}"` and `--confirm-sas`. Expect for `sig` the line
`carried for: protocol (recorded usage: namespace,proof-of-ownership,sequencer-auth,signing)` and a record with
`expected_usage "protocol"` and `namespace_fingerprint = NS_FP`; for `ns` `expected_usage "namespace"`. STOP on `refused:`.

**S3 Gate A / S4 install** [MUTATES]. Copy each bundle verified, and parse the JSON only: rc.4 `import-share` prints a WARN
line (`IMPORTED a dealer-split FROST share …`) **before** its JSON on stdout.
```zsh
source $D/env.sh; cer ns     # then again with: cer sig
for i in 1 2 3; do push $RNS rutli-cosigner-$((i-1)) cosigner $W/out/share-$KEY_ID-node$i.json /tmp/share.json || break
  cs $i import-share --in /tmp/share.json --expect-fingerprint $FP --dry-run | sed -n '/^{/,$p' > $W/dry-$i.json; jq -c '{outcome, pkp_digest}' $W/dry-$i.json; done
```
Gate A: three `"dry-run"`, one `pkp_digest` = `dealer-record.json`. Install: the same loop without `--dry-run`
(`install-$i.json`, expect `"installed"`), then `kx $i -- rm -f /tmp/share.json /tmp/r$i.json`. For `sig` the JSON also
shows `carried_usage.expected "protocol"` and `namespace_fingerprint = NS_FP`.

**S5 Gate B:** `rc verify-key --key-id $KEY_ID --expect-fingerprint $FP --sign-test | tee $W/gate-b.txt` → `OK`, all
three quorums `ok (verify_strict under the Canton key)`, `refreshes 0`, `carried-for namespace` (or `protocol`).
**S6 Refresh + Gate C (production, D4):** split-ceremony.md Step 6 with the refresher certificate (rc.4 CLI: it signs a
`refresh` ceremony intent). Expect refresh count 1 and a new pkp digest. Without a refresher role the cosigners refuse and
count it (an alert): do not "try".

**3.7 ECIES import** [MUTATES] into one running cosigner; the password goes over stdin, the export sits in the pod's `/tmp`
for seconds ([hosted-keys.md](hosted-keys.md), "Importing a Canton node's ECIES key"):
```zsh
source $D/env.sh; push $RNS rutli-cosigner-0 cosigner $D/keep/encryption.export-pw.bin /tmp/enc.export && ( read -rs "PW?Export password: "; echo
  printf '%s\n' "$PW" | kx 1 -i -- sh -c 'IFS= read -r CANTON_EXPORT_PASSWORD; export CANTON_EXPORT_PASSWORD; rutli-cosigner --config /config/cosigner-1.json import-key --in /tmp/enc.export --passphrase-env CANTON_EXPORT_PASSWORD --key-id "$0" --key-prefix "$1" --expect-fingerprint "$2"; r=$?; rm -f /tmp/enc.export; exit $r' $ENC_ID $PREFIX $ENC_FP; echo "import exit=$?" )
for t in $(seq 1 30); do rc verify-hosted --key-id $ENC_ID --expect-fingerprint $ENC_FP --json > $D/evidence/verify-hosted.json 2>/dev/null && break; sleep 30; done; jq -c '{ok, n: [.nodes[].present]}' $D/evidence/verify-hosted.json
```
Expect `import exit=0`, then within one anti-entropy interval (default 300 s) `ok:true` with three `present`. STOP after
15 min without convergence (look for `conflict` in the cosigner logs; a conflict is a page).

**3.8 Founding backup and hygiene.** Take the cosigner key backups now ([disaster-recovery.md](disaster-recovery.md) §1;
B8: a `tar` of `/data/keys` per pod, counts checked). Without a refresh these hold never-refreshed shares: L10. Delete the
bundles (`rm -P`). Keep `$D/keep/*.export-pw.bin` until RB2: they are the only re-import path.
**ACL probe** (read-only, only after Phase 1): for each node, `grpcurl` `Signer/GroupKey` for `$NS_ID`/`$SIG_ID` and
`Signer/PublicKey` for `$ENC_ID` with the participant's driver certificate → values, no `PermissionDenied`.

---

## Phase 4: the switch

Wallet outage from 4.3 to 4.12; B8 measured 20 min. Run 4.5–4.10 without pauses: the participant sits disconnected.

**4.0 Plumbing** [MUTATES]: namespace label, an egress rule to the cosigners on 9101 for your CNI (B8: a
`CiliumNetworkPolicy` to namespace `$RNS`), two PVCs, the helper pod. Then the jar in **2 MiB chunks**, each verified (a
whole-jar `kubectl cp` truncated), the certificates verified, and a checksum file next to them:
```zsh
source $D/env.sh; kubectl label namespace $NS rutli.io/client-ns=true --overwrite
for c in rutli-kms-bundle rutli-driver-state; do echo "{apiVersion: v1, kind: PersistentVolumeClaim, metadata: {name: $c}, spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}}" | kubectl -n $NS apply -f -; done
helper; H=($NS rutli-kms-populate p); CH=$D/jar-chunks; rm -rf $CH; mkdir -p $CH && (cd $CH && split -b 2m $JAR part.)
[ "$(shasum -a 256 < $JAR | cut -d' ' -f1)" = $JAR_SHA ] || echo "STOP: local jar"
kubectl exec -n $NS rutli-kms-populate -c p -- sh -c 'mkdir -p /tmp/parts /bundle/certs; rm -f /tmp/parts/*'
for f in $CH/part.*; do push $H $f /tmp/parts/${f:t} || break; done
kubectl exec -n $NS rutli-kms-populate -c p -- sh -c 'cat /tmp/parts/part.* > /bundle/rutli-driver.jar && rm -rf /tmp/parts'
for f in ca.crt driver.crt driver.key; do push $H $D/tls/$f /bundle/certs/$f; done
kubectl exec -n $NS rutli-kms-populate -c p -- sh -c 'cd /bundle && sha256sum rutli-driver.jar certs/* > SHA256SUMS && chown -R 1001:1001 /bundle /state && chmod 0640 certs/driver.key && touch /state/.w && rm /state/.w && echo state-writable; grep -c '$JAR_SHA' SHA256SUMS'
for i in 0 1 2; do kubectl exec -n $NS rutli-kms-populate -c p -- nc -w 3 rutli-cosigner-$i.rutli-cosigner.$RNS.svc.cluster.local 9101 </dev/null; echo "cosigner-$i exit=$?"; done
```
Expect `state-writable`, `1`, `exit=0` ×3. Helper pods sleep and **expire**: if it is gone when you need it, `helper` again
and re-run `sha256sum -c /bundle/SHA256SUMS` (4.1 does). The CN in `driver.crt` must be the one Phase 1 allowed.

**4.0d Overlays** (no `persistence:` key: same database). `$D/participant-final.yaml` and the switch variant with
auto-connect off:
```zsh
source $D/env.sh; cat > $D/participant-final.yaml <<EOF
pod: { labels: { rutli.io/client: "true" } }
additionalEnvVars:
  - { name: EXTRA_CLASSPATH, value: /app/rutli-driver.jar }
  - name: ADDITIONAL_CONFIG_RUTLI_KMS
    value: |
      canton.participants.participant.crypto {
        provider = kms
        kms { type = driver, name = "rutli", config = {
          backend = "frost", audit-logging = true, audit-log-path = "/rutli-state/audit.jsonl", signing-journal = { dir = "/rutli-state/journal" }
          frost = {
            endpoints = [ "rutli-cosigner-0.rutli-cosigner.$RNS.svc.cluster.local:9101", "rutli-cosigner-1.rutli-cosigner.$RNS.svc.cluster.local:9101", "rutli-cosigner-2.rutli-cosigner.$RNS.svc.cluster.local:9101" ]
            hosted-keys = true, delegate = "none", key-prefix = "$PREFIX", cluster-id = "$CLUSTER_ID"
            tls = { ca-cert = "/rutli-certs/ca.crt", cert = "/rutli-certs/driver.crt", key = "/rutli-certs/driver.key", domain = "rutli-cosigner" }
          } } }
        signing.keys.default = ec-curve-25519, signing.algorithms.default = ed-25519
        encryption.keys.default = ec-p-256, encryption.algorithms.default = ecies-hkdf-hmac-sha-256-aes-128-cbc
      }
extraVolumeMounts:
  - { name: rutli-kms, mountPath: /app/rutli-driver.jar, subPath: rutli-driver.jar, readOnly: true }
  - { name: rutli-kms, mountPath: /rutli-certs, subPath: certs, readOnly: true }
  - { name: rutli-state, mountPath: /rutli-state }
extraVolumes: [ { name: rutli-kms, persistentVolumeClaim: { claimName: rutli-kms-bundle } }, { name: rutli-state, persistentVolumeClaim: { claimName: rutli-driver-state } } ]
EOF
yq '.additionalEnvVars += [{"name":"ADDITIONAL_CONFIG_NO_AUTOCONNECT","value":"canton.participants.participant.parameters.connect-to-synchronizers-on-startup = false"}]' $D/participant-final.yaml > $D/participant-switch.yaml
diff <(helm -n $NS get manifest participant) <(helm template participant $CHART_PARTICIPANT --version $CHART_VER -n $NS -f $D/participant-values.pre.yaml -f $D/participant-switch.yaml) | grep -E '^[<>]' | cut -c1-150
```
Expect only the label, three env vars, three mounts, two volumes. **STOP on any database or host change.** `sign-intents`
defaults to on; leave it out.

**4.1 Pre-switch check** (read-only): `con pre ids precheck` with the 0.2 key/OTK assertions repeated (keys unchanged, OTK
serial recorded, connected); `helper; kubectl -n $NS exec rutli-kms-populate -c p -- sh -c 'cd /bundle && sha256sum -c
SHA256SUMS'` prints `OK` ×4, then `kubectl -n $NS delete pod rutli-kms-populate` (RWO volumes); `rc verify-key` for both
FROST ids and `rc verify-hosted` for `$ENC_ID` are OK. Then shred the laptop's `driver.key` copy (`/bin/rm -P`).

**4.2 Silence and safety dump** [MUTATES: one more plaintext copy of the keys]. Silence the namespace's Canton and pod alerts
for 3 h (Alertmanager `POST /api/v2/silences`, matchers `namespace=$NS` and `alertname=~"CantonParticipantDown|CantonValidatorAppDown|CantonParticipantUnhealthy|CantonRoundMissed|KubeDeploymentReplicasMismatch|KubePodNotReady"`).
Suspend the backup CronJob (fewer plaintext copies), then take the dump and **verify it exists**:
```zsh
source $D/env.sh; F=$PG_DATA/premig-$(date -u +%Y%m%d%H%M).dump; date -u +T_BACKUP=%FT%TZ | tee $D/evidence/pgbackup.txt
kubectl -n $NS exec $PG_POD -c postgres -- sh -c "pg_dump -U $PG_USER -Fc -d $PDB -f $F && ls -l $F && sha256sum $F && pg_restore -l $F | grep -c 'TABLE DATA'" | tee -a $D/evidence/pgbackup.txt
```
Expect a file of plausible size (B8: 883 MB, 123 tables) and its sha. It sits on the database volume and holds the JCE
keys: destruction list. Use your own backup job instead only if you have seen its file.

**4.3 Validator to 0** [MUTATES]: `date -u +T_START=%FT%TZ > $D/evidence/times.txt; kubectl -n $NS scale deploy/validator-app
--replicas=0` and wait until no pod remains.

**4.4 Quiesce and reference ACS** [MUTATES: export file]. `quiesce.sc`:
```scala
p.synchronizers.disconnect_all(); assert(p.synchronizers.list_connected().isEmpty)
val END_PRE = p.ledger_api.state.end(); val local = p.parties.hosted().map(_.party).toSet
p.repair.export_acs(parties = local, ledgerOffset = END_PRE, exportFilePath = "/w/acs-pre.gz")
val VP = PartyId.tryFromProtoPrimitive(rd("wallet-party.txt"))
wr("acs-ids-pre.txt", p.ledger_api.state.acs.of_party(VP, limit = PositiveInt.tryCreate(100000)).map(_.contractId).sorted.mkString("\n"))
println(s"T_STOP=${java.time.Instant.now} END_PRE=$END_PRE parties=${local.size} acs-pre sha=${sha("/w/acs-pre.gz")}")
```
Run `cp $D/evidence/wallet-party.txt $D/con/; con pre ids quiesce`. If the export fails: `reconnect_all()`, validator back
to 1, investigate.

**4.5 + 4.6 Stop, then the same participant on `provider = kms`, no auto-connect** [MUTATES]:
```zsh
source $D/env.sh; kubectl -n $NS scale deploy/participant --replicas=0; kubectl -n $NS wait --for=delete pod -l app=participant --timeout=5m
[ "$(kubectl -n $NS get pods -l app=participant --no-headers 2>/dev/null | wc -l | tr -d ' ')" = 0 ] || echo "STOP: participant still running"
P -d $PDB -c "select count(*) from participant.common_crypto_private_keys" -c "select count(*) from participant.common_kms_metadata_store"
helm -n $NS upgrade participant $CHART_PARTICIPANT --version $CHART_VER -f $D/participant-values.pre.yaml -f $D/participant-switch.yaml
sleep 30; [ "$(kubectl -n $NS get pods -l app=participant --no-headers | wc -l | tr -d ' ')" = 0 ] && kubectl -n $NS scale deploy/participant --replicas=1
kubectl -n $NS rollout status deploy/participant --timeout=15m
kubectl -n $NS logs deploy/participant -c participant | grep -E 'Resuming with existing uid|reconnect on startup is disabled|Loaded driver|signing intents are signed|DIFFERENT cluster|WITHOUT' | cut -c1-200
```
Expect `0` pods, `3` and `0`, then `Resuming with existing uid <UID>`, `Not reconnecting … reconnect on startup is
disabled`, `Loaded driver rutli … build <release>`, `FROST: signing intents are signed by …CN=<your CN>`. STOP (→ R-4) on a
driver error, `DIFFERENT cluster ids`, `WITHOUT`, or no "Not reconnecting" line. (Add `--force-conflicts` only if helm
reports server-side-apply conflicts from an earlier `kubectl patch`, [migration.md](migration.md) §10 c.)

**4.7 After the start** (re-establish the port-forward first): `con pre ids after` with
```scala
assert(p.uid.toProtoPrimitive == UID, "STOP: different node id")
assert(p.synchronizers.list_connected().isEmpty, "STOP: connected without registered keys (auto-connect not disabled)")
assert(p.keys.secret.list().isEmpty, "STOP: KMS private store not empty")
val pub = p.keys.public.list(); pub.foreach(k => println(s"public fp=${k.id.unwrap} name=${k.name.map(_.unwrap)} usage=${usageOf(k.publicKey)}"))
assert(pub.map(_.id.unwrap).toSet == Set(NS_FP, SIG_FP, ENC_FP), "STOP: public store changed")
```

**4.8 Register by KMS id, with the exact stored name and usage** [MUTATES]. The public-key store compares key, usage and
name exactly, so the Splice `signing` key is registered **with** its namespace usage (`All`), unlike 2b
([migration.md](migration.md) §8). `register.sc`:
```scala
val pub = p.keys.public.list().map(k => k.id.unwrap -> k).toMap
def nm(fp: String) = pub(fp).name.map(_.unwrap).getOrElse(sys.error(s"STOP: $fp has no name"))
def us(fp: String) = pub(fp).publicKey.asInstanceOf[SigningPublicKey].usage.forgetNE
val nsR = p.keys.secret.register_kms_signing_key(NS_ID, us(NS_FP), nm(NS_FP)); assert(nsR.fingerprint.unwrap == NS_FP && nsR.usage.forgetNE == us(NS_FP), s"STOP: $nsR")
val sigR = p.keys.secret.register_kms_signing_key(SIG_ID, us(SIG_FP), nm(SIG_FP)); assert(sigR.fingerprint.unwrap == SIG_FP && sigR.usage.forgetNE == us(SIG_FP), s"STOP: $sigR")
val encR = p.keys.secret.register_kms_encryption_key(ENC_ID, nm(ENC_FP)); assert(encR.fingerprint.unwrap == ENC_FP, s"STOP: $encR")
utils.retry_until_true(p.keys.secret.list().count(_.kmsKeyId.isDefined) == 3)     // the metadata write is not awaited by the RPC
p.keys.secret.list().foreach(k => println(s"secret fp=${k.id.unwrap} name=${k.name.map(_.unwrap)} kms=${k.kmsKeyId.map(_.unwrap)}"))
assert(p.keys.public.list().size == 3, "STOP: register added a public key")
```
Expect three `kms=Some(<id>)` lines. `Existing public key … is different` = name/usage mismatch, nothing registered → R-4. A
different returned fingerprint → R-4 plus the stray-row cleanup in §R. SQL: `common_kms_metadata_store` 3 rows, private
keys still 3 (untouched: the rollback path). `jq -s '[.[]|select(.op|test("^generate"))]|length' $(AUD 4.8)` = `0`.

**4.9 Reconnect** [MUTATES]: `reconnect.sc` writes `T_RECONNECT.txt` (`java.time.Instant.now`), runs
`p.synchronizers.reconnect(ALIAS); utils.retry_until_true(p.synchronizers.active(ALIAS))` and prints the OTK serial. Expect
connected and **the same OTK serial as 4.1**. Audit: `sign` lines for `keyId=$SIG_ID` `outcome=ok` after `T_RECONNECT`
(sequencer authentication with the carried key), 0 non-ok lines. STOP (→ R-4) on an authentication or `UnknownSigningKey`
error.

**4.10 Decrypt proof** [MUTATES: one ping]: `ping.sc` =
`println("PING " + p.health.ping(ParticipantId.tryFromProtoPrimitive(sys.env.getOrElse("PING_TARGET", "")), timeout = com.digitalasset.canton.config.NonNegativeDuration.tryFromDuration(scala.concurrent.duration.DurationInt(3).minutes)))`
(the target encrypts its reply to this node, so the ping exercises the carried ECIES key). Then
`jq -s --arg k "keyId=$ENC_ID " '[.[]|select(.op=="decryptAsymmetric" and (.detail|startswith($k)) and (.detail|test("outcome=ok")))]|length' $(AUD 4.10)`
≥ 1 and no `ecies-failure=`. STOP (→ R-4) on two timeouts or 0 decrypts.

**4.11 Cold restart: drop the no-autoconnect flag** [MUTATES: participant restart]. Proves an unattended restart reconnects
by itself and leaves the final configuration in place:
```zsh
source $D/env.sh; helm -n $NS upgrade participant $CHART_PARTICIPANT --version $CHART_VER -f $D/participant-values.pre.yaml -f $D/participant-final.yaml && kubectl -n $NS rollout status deploy/participant --timeout=15m
helm -n $NS history participant | tail -1 | awk '{print $1}' > $D/con/P_REV_FINAL.txt
```
Re-establish the port-forward, then a console block: `utils.retry_until_true(p.synchronizers.active(ALIAS))`, assert every
`keys.secret.list()` entry has a `kmsKeyId`, and the 4.10 ping. Expect connected **without** a manual reconnect (B8: ping
15.4 s).

**4.12 Validator back, guarded** [MUTATES]. On start Splice re-checks its identity and may rotate OTK keys; under KMS a
rotation mints a Rütli key and crosses RB1. The guard scales the validator back to 0 on any such line:
```zsh
source $D/env.sh; kubectl -n $NS scale deploy/validator-app --replicas=1
until kubectl -n $NS get pods -l app=validator-app -o jsonpath='{..state.running.startedAt}' | grep -q .; do sleep 2; done
unset OK ABORT; while [ -z "$OK$ABORT" ]; do
 kubectl -n $NS logs -f deploy/validator-app -c validator-app --since=1h | grep --line-buffered -E 'Node has identity|Node has no identity|was expected|need to be rotated|Rotated signing key|has signed keys|already onboarded|ERROR' | while IFS= read -r l; do echo "$l" | cut -c1-250
  case "$l" in *'has signed keys'*) OK=1; echo ">>> KEYS OK"; break;; *'Node has no identity'*|*'was expected'*|*'need to be rotated'*|*'Rotated signing key'*|*ERROR*) kubectl -n $NS scale deploy/validator-app --replicas=0; ABORT=1; echo ">>> ABORT"; break;; esac; done; done
date -u +T_END=%FT%TZ | tee -a $D/evidence/times.txt; jq -s '[.[]|select(.op|test("^generate"))]|length' $(AUD 4.12)
```
Expect `Node has identity <UID>, matching expected identifier …` → `checking if OTK rotation is needed` → `Participant … has
signed keys` → `ValidatorLicense found => already onboarded`, generate `0`. On ABORT read the log: an unrelated `ERROR`
(scan retries) may be judged by hand and the validator scaled back; a rotation line means R-4. Lift the silence.

---

## Phase 5: verification, rotation, cleanup, destruction

**5.1 Verification** (read-only, then wallet actions [MUTATES: ledger]). Console (`con pre ids verify`):
```scala
assert(p.uid.toProtoPrimitive == UID && p.keys.secret.list().forall(_.kmsKeyId.isDefined), "STOP: uid or a non-KMS key")
val VP = PartyId.tryFromProtoPrimitive(rd("wallet-party.txt"))
println("OTK serial=" + p.topology.owner_to_key_mappings.list(store = Some(SS), filterKeyOwnerUid = UID).map(_.context.serial))
println("PTP serial=" + p.topology.party_to_participant_mappings.list(SS, filterParty = VP.filterString).map(_.context.serial))
assert(p.topology.synchronizer_trust_certificates.list(store = Some(SS), filterUid = UID).size == 1, "trust certificate")
val now = p.ledger_api.state.acs.of_party(VP, limit = PositiveInt.tryCreate(100000)).map(_.contractId).toSet; val pre = rd("acs-ids-pre.txt").split("\n").filter(_.nonEmpty).toSet
println(s"ACS pre=${pre.size} now=${now.size} gone=${(pre -- now).size} added=${(now -- pre).size}")
```
- Expect the OTK and party-to-participant serials **equal to 4.1** (nothing re-published) and an ACS difference explained
  by automation (B8: serials 1 and 1, ACS 7 → 7 with one contract rolled over).
- Driver audit on a fresh `AUD 5.1`: 0 non-ok lines, 0 `ecies-failure=`, 0 `generate*`; then
  [audit-cross-check.md](audit-cross-check.md) against the cosigner journals (exit 0). Cosigners:
  `rutli_sign_policy_refusals_total`, `rutli_sign_rate_limited_total`, `rutli_ceremony_intent_refusals_total` flat.
- **Wallets:** the operator balance equals the baseline ± activity; **one end-user logs in without re-onboarding** and sees
  the same balance; Tap; an **outgoing** transfer (signing) and an **incoming** one (the node decrypts the view with the
  carried ECIES key: the `decryptAsymmetric keyId=$ENC_ID` count grows). Observed in the rehearsal: both balances identical
  to the last digit; 10 + 5 CC out, 2 CC in; 121 signs and 3 decrypts, 0 non-ok.
- **Commitments** after ≥ 2 reconciliation intervals:
```scala
import com.digitalasset.canton.admin.api.client.commands.ParticipantAdminCommands.Inspection._
import com.digitalasset.canton.data.CantonTimestamp
val from = CantonTimestamp.assertFromInstant(java.time.Instant.parse(rd("T_RECONNECT.txt")))
val rc = p.commitments.lookup_received_acs_commitments(Seq(SynchronizerTimeRange(SYNC_ID, Some(TimeRange(from, CantonTimestamp.now())))), Seq.empty, Seq.empty, false).values.flatten.toSeq
println(s"commitments periods=${rc.size} mismatches=${rc.count(_.state.toString.contains("Mismatch"))}")
```
  Expect `periods > 0` and `mismatches=0`. `periods=0` is **not** a pass (B8's run 40 min after the reconnect returned 0):
  run it again later.

**5.2 Rotation per client choice (D3)** [MUTATES: topology; **crosses RB1**]. Gate: 5.1 green and the client's written yes.
Compiled against 3.6.1, **not yet rehearsed**. The 3.6.1 jar's `rotate_key(member, current, new)` works through the
Authorized store: first assert Authorized OTK = synchronizer OTK. Never `keys.secret.delete` (under KMS it deletes the key
in the cluster); the old keys stay registered to decrypt in-flight views.
```scala
// 5.2a encryption onto a fresh cluster-hosted ECIES key (default)
def otkOf(s: TopologyStoreId) = p.topology.owner_to_key_mappings.list(store = Some(s), filterKeyOwnerUid = UID).map(_.item.keys.map(_.fingerprint.unwrap).toSet)
assert(otkOf(TopologyStoreId.Authorized) == otkOf(SS), "STOP: Authorized OTK != synchronizer OTK")
val encOld = p.keys.secret.list(filterFingerprint = ENC_FP).map(_.publicKey).head
val encNew = p.keys.secret.generate_encryption_key("encryption-r1", Some(EncryptionKeySpec.EcP256))
p.topology.owner_to_key_mappings.rotate_key(p.id.member, encOld, encNew)
utils.retry_until_true(p.topology.owner_to_key_mappings.list(store = Some(SS), filterKeyOwnerUid = UID).headOption.exists(_.item.keys.map(_.fingerprint.unwrap).toSet == Set(SIG_FP, encNew.fingerprint.unwrap)))
println(s"rotated encryption to ${encNew.fingerprint}")
// 5.2b optional signing onto a fresh FROST DKG key, without namespace usage (needs a ceremony intent: rc.4 driver, pinned CN, prefix in the ACL)
// val sigNew = p.keys.secret.generate_signing_key("signing-r1", SigningKeyUsage.ProtocolWithProofOfOwnership ++ SigningKeyUsage.SequencerAuthenticationOnly, Some(SigningKeySpec.EcCurve25519))
// then rotate_key(p.id.member, sigOld, sigNew), wait until SIG_FP left the OTK, disconnect + reconnect (sequencer auth on the new key)
```
Then the 4.10 ping (decrypts under the new id), a cosigner key backup (new keys exist), and record `T_RB1`.

**5.3 Observation:** ≥ 24 h; repeat 5.1 at the end; two green health checks.

**5.4 SQL cleanup of the JCE rows (RB2)** [MUTATES: irreversible]. Gate (console): every OTK key and `NS_FP` is KMS-backed
and every `keys.secret.list()` entry has a `kmsKeyId`. Then stop the validator and the participant (0 pods) and:
```zsh
source $D/env.sh; date -u +%FT%TZ > $D/evidence/T_CLEAN.txt
kubectl -n $NS exec -i $PG_POD -c postgres -- psql -U $PG_USER -d $PDB -v ON_ERROR_STOP=1 -v ns="$NS_FP" -v sig="$SIG_FP" -v enc="$ENC_FP" <<'SQL'
BEGIN;
SELECT count(*) = 3 AS three FROM participant.common_crypto_private_keys WHERE key_id IN (:'ns', :'sig', :'enc') \gset
\if :three
DELETE FROM participant.common_crypto_private_keys WHERE key_id IN (:'ns', :'sig', :'enc');
SELECT count(*) = 0 AS empty FROM participant.common_crypto_private_keys \gset
\if :empty
COMMIT;
\echo CLEANUP-COMMITTED
\else
ROLLBACK;
\echo ROLLED-BACK-OTHER-ROWS
\endif
\else
ROLLBACK;
\echo ROLLED-BACK-NOT-THE-THREE
\endif
SQL
P -d $PDB -c "VACUUM (FULL) participant.common_crypto_private_keys"; for i in 1 2 3; do P -d postgres -c CHECKPOINT -c 'SELECT pg_switch_wal()'; done
P -d $PDB -c "select count(*) from participant.common_crypto_private_keys" -c "select count(*) from participant.common_kms_metadata_store"
```
Expect `CLEANUP-COMMITTED`, `0`, `3` (4–5 after rotations). STOP on `ROLLED-BACK-…`. Start the participant (auto-connect
on), rerun the 4.11 console check, the validator with the 4.12 guard, then resume the backup job and prove the next dump
has 0 private-key rows. `CHECKPOINT`/`pg_switch_wal` need a superuser.

**5.5 Destruction inventory (2a)** [MUTATES], with before/after evidence per row ([split-ceremony.md](split-ceremony.md)
§8 record). Gate: 5.1–5.4 green and the client's yes.

| # | Location | Action |
|---|---|---|
| L1 | `common_crypto_private_keys` (3 plaintext rows) | Done in 5.4. **No `DROP DATABASE`**: the database stays live; old heap blocks stay on the volume |
| L2 | WAL, replicas, PITR base backups, WAL archive | Switch WAL (5.4); drop base backups and archived segments ≤ `T_CLEAN`; record `archive_mode` |
| L3 | Every logical dump ≤ `T_CLEAN`: the backup PVC, **the 4.2 safety dump on the database volume** | Delete; prove the next dump is clean. An unreadable PVC (B8: permission error) is destroyed whole |
| L4 | Object storage | Every version and delete marker ≤ `T_CLEAN`; record object-lock retention |
| L5 | Volume snapshots, **retired database volumes** | Delete (B8: a pre-CNPG volume deleted unwiped held the keys) |
| L6 | Splice identities dumps, migration-dump volume | Confirm none were taken |
| L7 | `$D/keep/*.export-pw.bin` | `/bin/rm -P` (APFS/SSD: not provable) |
| L8 | Laptop: `$D`, history, clipboard, console containers, password-manager entry | Statement |
| L9 | Dealer host and media | Statement ([split-ceremony.md](split-ceremony.md) Step 9) |
| L10 | Bundles, `r?.json`, pod `/tmp` files, founding backups taken before the refresh | Delete; record which backups hold never-refreshed shares |
| L11 | Cluster (live): `NS_ID` forever; `SIG_ID`/`ENC_ID` live or, after 5.2, residue (the carried ECIES key stays whole on every cosigner) | Statement |
| L12 | Driver private-key copies (laptop, helper pods) | Delete; the PVC copy is the live one |

**5.6 Teardown of the migration workspace:** delete helper pods and port-forwards, `rm -P` the remaining files in `$D`,
revoke any temporary refresh permission (D4), keep the evidence. A drill on a scratch validator also offboards it (trust
certificate removal, signed by the carried namespace key through FROST) and removes its prefix from `signer_acl`.

---

## R. Rollback

| Point | How |
|---|---|
| Phase 1 | `helm rollback` the cosigner release + canary restarts |
| Phase 3, before Gate B | `abort-import` per node ([split-ceremony.md](split-ceremony.md) §5) |
| Phase 3, after Gate B / after `import-key` | No delete path: the id is residue. Retry under new ids, override `NS_ID`/`SIG_ID`/`ENC_ID` |
| **R-4: from 4.3 until RB1** | Below. Nothing on the ledger changed; the JCE rows and the OTK still match |
| After RB1 (5.2) | Fix forward: rotate again, cluster DR from the post-rotation cosigner backup. A return to JCE would first need the OTK rotated back onto the carried keys (still registered, still in the JCE rows): **not rehearsed**. Restoring a pre-switch dump rewinds the ledger state and is not a rollback |
| After RB2 (5.4) | As after RB1, and the JCE rows are gone |

**R-4** (participant first, healthy, then the validator):
```zsh
source $D/env.sh; kubectl -n $NS scale deploy/validator-app --replicas=0; kubectl -n $NS scale deploy/participant --replicas=0   # [MUTATES]
kubectl -n $NS wait --for=delete pod -l 'app in (participant,validator-app)' --timeout=5m
helm -n $NS rollback participant $P_REV0; kubectl -n $NS rollout status deploy/participant --timeout=15m                       # [MUTATES] JCE, same DB, auto-connect on
```
Console: reconnected by itself, three keys with `kms=None`, `p.health.ping(p)`. Then the validator to 1, resume the backup
job, lift the silence. The 4.8 metadata rows stay and are ignored by JCE; a retry re-registers idempotently. **Stray rows
after a fingerprint mismatch** in 4.8: with the participant stopped, `delete from participant.common_kms_metadata_store where
fingerprint = '<stray>'` and the same `key_id` in `common_crypto_public_keys`. If Splice minted a key into the OTK, RB1 is
crossed: fix forward. (A JCE rollback would first need the OTK rotated back to the carried keys while still on
KMS; possible, not rehearsed.)

---

## Appendix: lessons from the B8 rehearsal (2026-10-23..26)

1. **Copies truncate.** `kubectl exec`/`cp` streams dropped silently after a few MB on this cluster, and once
   `kubectl exec -i … < file` produced an empty file. Every copy is sha256-checked and retried (`push`/`pull`); the 36 MB
   jar goes in 2 MiB parts, state files in 1 MiB slices (`tail -c +N | head -c 1MiB`).
2. **Helper pods expire** (`sleep 3600`). Re-create and `sha256sum -c` before anything relies on their files.
3. **rc.4 `import-share` prints a WARN line before its JSON** on stdout: `sed -n '/^{/,$p'` before `jq`.
4. **`ledger_api.parties.list()` is network-wide** on a public network (10 000 on DevNet): `parties.hosted()` for local parties.
5. **Never hard-code the protocol version:** DevNet moved PV 35 → 36 during the drill. Read it from the connected synchronizer.
6. **The backup CronJob can be broken** (PVC permission after a database move): verify the safety dump exists; the fallback
   is `pg_dump -Fc` onto the database pod's own volume, which then goes on the destruction list.
7. **Policy first.** ACL prefix, pin, rate limits (`-sig-` before `frost-import-`, then a catch-all) on every cosigner
   before the switch; a dedicated driver certificate per participant in production.
8. **Splice's own OTK rotation** must be dormant (0.2 predicate) and the validator comes back guarded (4.12).
9. **Script-mode console prints no return values** (`println` them); **port-forwards die on every restart**.
10. **The post-import refresh** is mandatory in production and needs a refresher certificate (D4); B8 skipped it.
11. **Wallets survive in place:** operator and end-user balances identical, no re-onboard; test an outgoing *and* an incoming
    transfer. The participant admin party is not necessarily the wallet party: ask `/api/validator/v0/validator-user`.
12. **Silence alerts for the window.** Measured outage 20 min: KMS start +5 min, reconnect +10, cold restart +15, validator
    keys OK +20.
13. **Rollback boundaries:** RB1 = first OTK rotation onto a Rütli-born key; RB2 = SQL cleanup.
14. **The cold restart is part of the switch** (4.11): it is the only proof an unattended restart reconnects.
15. **Pick `P_REV0` carefully:** an older revision pointed at a deleted database; roll back only to the revision whose values
    the overlays were rendered against.

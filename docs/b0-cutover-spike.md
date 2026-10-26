# B0: cutover spike on the soak validator (runbook, B0-B)

**Status:** ready for review, 2026-10-08. **Roadmap item:** B0 in [roadmap-migration.md](roadmap-migration.md).
**Target:** `stakecraft-devnet-rutli-01` (Splice 0.9.0 / Canton 3.6.1, driver 0.3.1, cosigners 0.3.1).
**Shape (decided 2026-10-08):** a **new participant UID under the same FROST namespace**. The validator
party and its contracts move to the new participant; the old participant is offboarded.
**Who runs it:** the operator runs every command. Steps marked **[MUTATES]** change cluster or ledger
state. Everything else is a read. "Seen 2026-10-08" values come from a read-only inspection; re-record them on the day.

---

## 0. Purpose, point of no return, verdict

### What B0 proves

This is the Canton and Splice half of a migration, with no key export and no new code:
- A participant whose namespace key lives in the Rütli cluster is rebuilt as a **new participant** in the **same namespace**.
- Its keys are registered **by KMS id** only.
- It onboards to the Global Synchronizer as a new member.
- It takes over the validator party with the **same party ID**, wallet balance, and licence.

This is the shape B4 needs for a real (JCE) validator. B4 adds the key split (B2).

### Why not keep the same participant UID (B0-A, dropped)

A fresh DB under the old UID is treated as already active and replays every event since the member's
registration (`SynchronizerRegistryHelpers.scala:266-298`, `SequencerReader.scala:265-290`). That works only
inside sequencer pruning, so it cannot carry a long-lived validator. An `import_acs` on top of the replay
would create every contract a second time. A UID that was ever onboarded cannot onboard again
(`GrpcSequencerConnectService.scala:251-267`, `StoreBasedTopologySnapshot.scala:56-69`). Splice: participant
identities "can't be reused on the same global synchronizer" (`sv_operations.rst:82`).

### Same namespace root, no delegation

The new UID is `<NEW_ID>::<same namespace>`. Its trust certificate, owner-to-key mapping (OTK) and party
mappings are signed by the existing root key `frost-namespace`, registered by id. DA's test uses a
namespace delegation instead (`KmsMigrationIntegrationTest.scala:100-147`) because its target KMS could not
hold the old root key. Ours already holds it, so a delegation would only add a second key the cluster must
serve. Splice's identities-backup recovery does exactly this same-root, new-UID move (`NodeInitializer.scala:256-312`).
An intermediate key (`init.generate-intermediate-key`) is a separate hardening choice, not needed for B0.

### Point of no return (PNR)

On the soak, the validator party **is** the old participant's admin party: party hint = node identifier =
`stakecraft-rutli-soak-1`, same namespace. Canton allows a party whose UID equals a participant's UID to be
hosted **only on that participant** while its trust certificate exists (`TopologyMappingChecks.scala:608-617,1146-1177`).
So the party cannot be hosted on two participants at once. It can only move after the old
participant's trust certificate is **removed**. A removed participant can never rejoin
(`TopologyMappingChecks.scala:561-566`, `checkParticipantDoesNotRejoin`).

Splice's migrator does exactly this before importing the ACS:
1. Unhost the other parties.
2. Remove the admin party mapping.
3. Remove the old trust certificate.
4. Host the party on the new participant.
5. Import the ACS from Scan.

(`ParticipantPartyMigrator.scala`, `removeDomainTrustCertificate` / `ensurePartiesMigrated` / `importAcs`.)

> **PNR = the validator app log line `Preparing to remove domain trust certificate because we will be migrating stakecraft-rutli-soak-1::…`** (§3 step 10).
> Before it, rollback is clean: point the Helm releases back at the untouched old DBs.
> After it, the old participant is gone for good. Recovery is fix-forward only (§5).

The offline party-replication order in `party_replication.rst:342-354` (add the target with the onboarding
flag, export at the activation offset, import, clear the flag) **cannot be used here**. Adding the target
while the old trust certificate exists is rejected by the admin-party rule above.

### Go: all of these must hold

| # | Criterion |
|---|---|
| G1 | `register_kms_*_key` for the 3 recorded ids on the fresh node returns the 3 recorded fingerprints. Canton does no namespace check here (`KmsPrivateCrypto.scala:78-104`); this is Risk #1. |
| G2 | The node initialises as `PAR::<NEW_ID>::<NS_FP>`. **No key is minted:** no driver `generate*` audit entry; `rutli_ceremony_requests_total` and `rutli_hosted_key_ops_total{op="generate"}` stay flat. |
| G3 | The new member onboards: its trust certificate is on the synchronizer, `list_connected` is healthy, and the trust certificate and OTK show FROST `frost-namespace` signatures in the audit log. |
| G4 | The validator party is hosted on the new participant only (Submission, threshold 1). The old trust certificate is removed. Party ID unchanged. |
| G5 | The ACS diff against the old export is fully explained (§4). No `ACS_COMMITMENT_MISMATCH` / `ACS_MISMATCH_NO_SHARED_CONTRACTS` over ≥ 2 reconciliation intervals. |
| G6 | The validator app initialises without minting keys, without a new onboarding secret, and the `ValidatorLicense` is found. Wallet balance = `WALLET_BALANCE` ± drill activity. One transfer out and one in succeed. Traffic top-up works for the new member. |
| G7 | Zero `rutli_sign_requests_total{result="error"}`, `rutli_decrypt_rate_limited_total` flat, no alerts. `soak-check` is green 24 h later. |

### No-go: what failure looks like, and what to write up

| Symptom | Before / after PNR | Action |
|---|---|---|
| `register_kms_signing_key` errors or returns a different fingerprint | before | STOP → §5 R-A. Write-up: the error, driver audit `getPublicKey keyId=…`, the Canton log. This is the Risk #1 outcome. |
| `init_id` / snapshot import / OTK propose rejected | before | STOP → R-A. Write-up as above, plus the rejection code. |
| Connect fails: `ParticipantIsNotActive`, `…has rejected our on-boarding attempt`, `…either active on the synchronizer or has previously been offboarded` | before | STOP → R-A. The last one means `NEW_ID` was already used: pick another id. |
| A DKG attempt (`RutliCeremonyFailure`), or a validator log `Node has no identity, generating a new one` | before | STOP. The validator app started without the dump. The create-once guard refuses `frost-namespace` (`node.rs:427-432`), so nothing is minted. Scale the validator to 0 → fix values → retry, or R-A. |
| Migrator fails after the PNR line (`Party … is hosted on multiple participant`, import error, `Unknown secret` / `ValidatorLicense not found`) | after | Fix forward (§5 R-B). Never restart the old participant. |
| `ACS_COMMITMENT_MISMATCH` after migration | after | R-B step 2 (re-import from Scan per the Splice DR doc), or step 3. |

If Canton refuses at G1–G3, write it up in the soak log (§6) and in a new `## B0 result` section in
`roadmap-migration.md`. Track B pauses.

---

## 1. Pre-flight (read-only)

Work directory outside the repo: `mkdir -p ~/b0-drill/b0 && chmod 700 ~/b0-drill`. `NS=stakecraft-devnet-rutli-01`.

### 1.1 Cluster and Helm

| Var | Command | Expected (seen 2026-10-08) |
|---|---|---|
| — | `kubectl config current-context` | `hcloud-cluster` |
| `PODS_PRE` | `kubectl -n $NS get deploy,sts,pvc,cronjob` | `participant`, `validator-app` 1/1, `strategy: Recreate`; PVCs `rutli-kms-bundle`, `rutli-driver-state`, `pg-data-postgres-0`, backup PVC |
| `PARTICIPANT_REV_PRE`, `VALIDATOR_REV_PRE` | `helm -n $NS list` | participant **3** (splice-participant-0.9.0), validator **1** (splice-validator-0.9.0) |
| values | `helm -n $NS get values participant -o yaml > ~/b0-drill/participant-values.pre-b0.yaml`, and the same for `validator` | participant `persistence.databaseName: participant`; validator `persistence.databaseName: cantonnet_validator`, `nodeIdentifier` = `validatorPartyHint` = `stakecraft-rutli-soak-1`, `topup.enabled: true` |
| DB env | `kubectl -n $NS get deploy participant -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' \| grep POSTGRES_DB` | `participant` |
| `IMAGE_PARTICIPANT`, `IMAGE_VALIDATOR` | `kubectl -n $NS get deploy participant validator-app -o jsonpath='{range .items[*]}{.spec.template.spec.containers[0].image}{"\n"}{end}'` | `canton-participant:0.9.0@sha256:67bd5b1e…`, `validator-app:0.9.0@sha256:bbde8294…` |
| driver | `kubectl -n $NS logs deploy/participant \| grep -m1 'Loaded driver rutli'` | `build 0.3.1`. No `frost.key-prefix` in `ADDITIONAL_CONFIG_RUTLI_KMS`. **It must stay unset** (key-id rule in §3). |
| `CHART_*` | `helm -n $NS get metadata participant validator` plus the 2026-10-07 install notes | Splice OCI `oci://ghcr.io/digital-asset/decentralized-canton-sync/helm/splice-{participant,validator}`, 0.9.0 (confirm) |
| backups | `kubectl -n $NS get cronjob canton-validator-canton-validator-naas-backup -o jsonpath='{.spec.schedule} {.status.lastSuccessfulTime}{"\n"}'`, `kubectl -n rutli get cronjob rutli-cosigner-backup` | `0 */4 * * *` (~22 min/run); cosigner `17 3 * * *` |
| cosigners | `kubectl -n rutli get pods; helm -n rutli list` | 3/3 READY, rutli-cosigner-0.3.1 |

`helm get values canton-validator` holds secrets in plain values. Never paste it anywhere.

### 1.2 Splice 0.9.0 checks: done 2026-10-09 against the deployed artifacts

Verified from chart `splice-validator` 0.9.0 (OCI digest `sha256:a3becb24…`), image
`canton-participant:0.9.0@sha256:67bd5b1e…` and `validator-app:0.9.0@sha256:bbde8294…` (classes in
`/app/splice-node/lib/splice-node.jar`). Re-run only if the chart or image changes.

- Chart: `participantIdentitiesDumpImport.{secretName,newParticipantIdentifier}`, `migrateValidatorParty`
  and `nodeIdentifier` exist (`values.schema.json:398,571,633-636`). The dump Secret is mounted at
  `/participant-bootstrapping-dump/content`, so its key must be `content` (as in §3 step 1). With no
  `scanClient` in our values, `migrate-validator-party.scan.admin-api.url` falls back to `scanAddress`
  (`https://scan.sv-1.dev.global.canton.network.sync.global`): no overlay change needed.
- Participant image: `init = { generate-topology-transactions-and-keys = false, identity.type = manual }`
  (`/app/app.conf:23-26`), `/app/bin/canton` present, Canton 3.6.1. The image is **linux/amd64 only**:
  on an arm64 laptop add `--platform linux/amd64` to every `docker run` below (emulated, slower).
- Validator app: `ParticipantPartyMigrator` keeps the log lines this runbook keys on: `Preparing to remove
  domain trust certificate because we will be migrating …` (PNR), `Removing domain trust certificate.`,
  `Importing ACS for party ids …`, `ACS import complete`, `Party migration already complete, continuing`.
  New since 0.5.5: migration state lives in the validator DB (`DbStorePartiesToMigrate`,
  `ValidatorConfigProvider.PartiesBeingMigrated`), one more reason for the fresh `cantonnet_validator_b0`.
  No onboarding-flag use in the migrator, same as 0.5.5.
- **New check for §1.4:** `NodeInitializer` logs *"Removing keys from OwnerToKeyMapping as they are not
  flagged for proof-of-ownership usage"*. The signing key's recorded usage (`SIG_USAGE`) must include
  `ProofOfOwnership`, and §3 step 6 must register it with exactly that usage. **STOP if it does not**:
  the new member's OwnerToKeyMapping would lose its signing key.

### 1.2a Tokens (operator)

Both tokens come from the validator's Auth0 M2M client in Secret `splice-app-validator-ledger-api-auth`
(keys `url` = OIDC discovery URL, `client-id`, `client-secret`, `audience`, `ledger-api-user`). Nothing
here prints a secret; keep the shell private and `unset` the variables afterwards.

```sh
cat > ~/b0-drill/auth.sh <<'SH'
_sec() { kubectl -n stakecraft-devnet-rutli-01 get secret splice-app-validator-ledger-api-auth -o jsonpath="{.data.$1}" | base64 -d; }
_token() {  # $1 = audience
  local ep; ep=$(curl -sf "$(_sec url)" | jq -r .token_endpoint) || return 1
  jq -n --arg id "$(_sec client-id)" --arg sec "$(_sec client-secret)" --arg aud "$1" \
    '{grant_type:"client_credentials", client_id:$id, client_secret:$sec, audience:$aud}' |
  curl -sf "$ep" -H 'content-type: application/json' --data @- | jq -er .access_token
}
export LEDGER_API_TOKEN=$(_token "$(_sec audience)")
export VALIDATOR_TOKEN=$(_token "$(helm -n stakecraft-devnet-rutli-01 get values validator -o json | jq -r .auth.audience)")
SH
chmod 600 ~/b0-drill/auth.sh && source ~/b0-drill/auth.sh
echo "ledger ${#LEDGER_API_TOKEN} chars, validator ${#VALIDATOR_TOKEN} chars"   # both > 0
```

If `VALIDATOR_TOKEN` comes back empty, Auth0 has not granted this client the wallet API audience; use
the wallet UI login instead (§1.6) and fetch the dump with the browser session's token.

### 1.3 Canton console (operator machine)

`kubectl -n $NS port-forward deploy/participant 5002:5002 5001:5001`. Restart it whenever the pod is replaced.
For `ledger_api.*`, export a `LEDGER_API_TOKEN` (client-credentials of `splice-app-validator-ledger-api-auth`,
audience `https://canton.network.global`).

`~/b0-drill/b0/remote.conf`:
```hocon
canton {
  features { enable-preview-commands = yes, enable-repair-commands = yes }
  remote-participants.soak {
    admin-api  { address = "host.docker.internal", port = 5002 }
    ledger-api { address = "host.docker.internal", port = 5001 }
    token = ${?LEDGER_API_TOKEN}
  }
}
```
`docker run --rm -it --platform linux/amd64 -v ~/b0-drill/b0:/b0 -e LEDGER_API_TOKEN --entrypoint /app/bin/canton $IMAGE_PARTICIPANT -c /b0/remote.conf`

Config keys: `CantonConfig.scala:404-406`, `ParticipantNodeConfig.scala:150-156`. **Keep one console session open
from 1.4 through §3 step 8**, because step 8 reuses the in-memory `syncCfg`.

### 1.4 Console inventory on the old participant (read-only)

```scala
val p = soak
val OLD_UID = p.uid.toProtoPrimitive                  // stakecraft-rutli-soak-1::12203286ffe2…22ea
val NS_FP   = p.id.uid.namespace.fingerprint.unwrap   // 12203286ffe27c94c35ee0aa24a359d41e73f4df6e88d2aab2b72860df79ce8f22ea
p.keys.secret.list().foreach { k =>
  val u = k.publicKey match { case s: SigningPublicKey => s.usage.mkString(","); case _ => "-" }
  println(s"fp=${k.id} name=${k.name} kms=${k.kmsKeyId} purpose=${k.purpose} usage=$u") }
```

Expect exactly 3 keys, all `kms=Some`. Anything else: STOP.

| Var | Expected |
|---|---|
| `NS_KMS_ID` / `NS_FP` | `frost-namespace`, name `namespace`, usage `namespace` |
| `SIG_KMS_ID` / `SIG_FP` / `SIG_USAGE` | `frost-signing`, name `signing`. Usage is probably all four (Splice generates with `SigningKeyUsage.All`, `NodeInitializer.scala:73`; Canton `Signing.scala:757-763`). Register with exactly what is printed. |
| `ENC_KMS_ID` / `ENC_FP` | `rutli-enc-encryption-d625b676-…` (full), name `encryption` |

```scala
val ALIAS   = SynchronizerAlias.tryCreate("global")     // confirm via p.synchronizers.list_registered()
val syncCfg = p.synchronizers.config(ALIAS).get
java.nio.file.Files.writeString(java.nio.file.Paths.get("/b0/sync-config.txt"), syncCfg.toString)
val SYNC_ID = p.synchronizers.list_connected().head.physicalSynchronizerId.logical   // global-domain::1220be58c29e…
val VALIDATOR_PARTY = PartyId.tryFromProtoPrimitive("stakecraft-rutli-soak-1::" + NS_FP)
assert(VALIDATOR_PARTY.uid.toProtoPrimitive == OLD_UID)   // admin-party case → PNR as described in §0
p.parties.list(filterParticipant = OLD_UID).foreach(println)   // PARTIES_PRE: expect only the validator party
p.topology.party_to_participant_mappings.list(SYNC_ID, filterParty = VALIDATOR_PARTY.filterString).foreach(println) // 1 participant, Submission
p.traffic_control.traffic_state(SYNC_ID)                 // TRAFFIC_PRE (old member's purchased traffic is stranded after B0)
p.ledger_api.state.acs.of_party(VALIDATOR_PARTY, limit = PositiveInt.tryCreate(100000)).size   // ACS_COUNT_PRE
// NEW_ID: pick e.g. "stakecraft-rutli-soak-1-b0". It must never have existed on DevNet:
val NEW_ID = "stakecraft-rutli-soak-1-b0"
p.topology.synchronizer_trust_certificates.list(store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), filterUid = NEW_ID) // empty
p.parties.list(filterParty = NEW_ID)                                                                                      // empty
// identity topology (namespace delegation + OTK), the same set Splice dumps (TopologyAdminConnection.scala:571-586):
val idSnap = p.topology.transactions.export_topology_snapshotV2(store = TopologyStoreId.Authorized,
  filterMappings = Seq(TopologyMapping.Code.NamespaceDelegation, TopologyMapping.Code.OwnerToKeyMapping),
  filterNamespace = p.id.uid.namespace.filterString)
java.nio.file.Files.write(java.nio.file.Paths.get("/b0/identity-authorized.bin"), idSnap.toByteArray)
```

### 1.5 Identities dump (validator admin API, read-only GET)

`kubectl -n $NS port-forward deploy/validator-app 5003:5003`. Then, with a token for the validator's
ledger-API user and the validator audience:

```sh
curl -sf http://localhost:5003/api/validator/v0/admin/participant/identities -H "authorization: Bearer $VALIDATOR_TOKEN" > ~/b0-drill/identities-dump.json
jq '{id, keys: [.keys[] | {type, keyId, name, hasKeyPair: has("keyPair")}]}' ~/b0-drill/identities-dump.json
```

Expect: `id` = `PAR::` + `OLD_UID`, and 3 entries `{type: signing|encryption, keyId: <recorded ids>, name}` with
**`hasKeyPair: false` everywhere**. Splice emits `KmsKeyId` for KMS-held keys (`NodeIdentitiesStore.scala`; schema
`common-internal.yaml:92-119`), so the file holds no private key material. Any `keyPair` entry: STOP.

### 1.6 Baselines

- **Wallet** (validator wallet user): `WALLET_BALANCE` plus the latest transaction. Either the wallet UI, or
  the validator's wallet API with the `VALIDATOR_TOKEN` from §1.2a through the port-forward of §1.5:
  ```sh
  curl -sf http://localhost:5003/api/validator/v0/wallet/balance -H "authorization: Bearer $VALIDATOR_TOKEN" | jq
  curl -sf -X POST http://localhost:5003/api/validator/v0/wallet/transactions -H "authorization: Bearer $VALIDATOR_TOKEN" \
    -H 'content-type: application/json' -d '{"page_size":1}' | jq '.items[0] | {transaction_type, date, amulet_price}'
  ```
  Record `effective_unlocked_qty` (+ `effective_locked_qty`) as `WALLET_BALANCE`.
- **Grafana Explore**:
  - `sum(rutli_ceremony_requests_total) by (kind,result)` (expect dkg ok = 2)
  - `sum(rutli_hosted_key_ops_total{op="generate"})` (1)
  - `sum(rutli_decrypt_rate_limited_total)` (0)
  - `sum(increase(rutli_sign_requests_total{result="ok"}[24h]))`

The decrypt-rate risk of the dropped replay variant mostly goes away here. The new member subscribes from its
own onboarding, so there is no history to replay. An ACS import carries contracts in plaintext and needs no
decryption. Keep `rutli_decrypt_rate_limited_total` as a STOP signal only. No limit change is needed.

### 1.7 DevNet

No DevNet upgrade or reset within 48 h. `MIGRATION_ID` unchanged. Scan reachability matters: the migrator
fetches the party ACS from the configured Scan **from inside the cluster**. The operator laptop got 403 from
Scan before (allowlist), so any manual Scan call in §5 must run in-cluster.

---

## 2. Backup

1. **[MUTATES]** Start a manual pg_dumpall. Do it outside `:00`–`:25` of the 4-hourly cron (the backup PVC is RWO).
   ```sh
   JOB=b0-pre-cutover-$(date -u +%Y%m%d%H%M)
   kubectl -n $NS create job --from=cronjob/canton-validator-canton-validator-naas-backup $JOB
   kubectl -n $NS wait --for=condition=complete job/$JOB --timeout=45m && kubectl -n $NS logs job/$JOB | tail -25
   ```
   Expect `SHA-256` (record `BACKUP_SHA`), `Local backup: … (<size>)` (within ±10 % of the previous run),
   `S3 verification: OK`, `Backup Complete`. STOP on `ERROR`. Off-cluster copy:
   `aws s3 ls s3://<backup-bucket>/stakecraft-devnet-rutli-01/pg_dumpall-<TS>.sql.gz.enc`.
2. **[MUTATES: pod]** Content check. Mount the **backup** PVC read-only (never a cosigner volume) in a
   `postgres:15-alpine` Job. Run:
   ```sh
   F=$(ls -1t /backups/pg_dumpall-*.sql.gz|head -1); gzip -t "$F" && sha256sum "$F"
   zcat "$F" | grep '^CREATE DATABASE' | awk '{print $3}'
   zcat "$F" | tail -3
   for t in common_kms_metadata_store common_crypto_private_keys; do printf '%s ' $t
     zcat "$F" | awk -v t="COPY participant.$t" 'index($0,t)==1{f=1;next} f&&$0=="\\."{f=0} f'|wc -l; done
   ```
   PVC `canton-validator-canton-validator-naas-backup`, `readOnly: true`, `restartPolicy: Never`, `ttlSecondsAfterFinished: 86400`.
   Expect: sha = `BACKUP_SHA`; databases `participant`, `cantonnet_validator`, `zz_old_*`; the tail reads
   `cluster dump complete`; **kms_metadata 3 rows, private_keys 0** (the backup holds no keys).
3. **[MUTATES]** Cosigner backup:
   `kubectl -n rutli create job --from=cronjob/rutli-cosigner-backup b0-pre-cutover-cosign`, then check its logs.
   Expect `backed up 3 share file(s)` ×3. Keys are not touched, but this costs 5 s.
4. Helm values were snapshotted in 1.1.

---

## 3. Cutover

Freeze other soak activity. Expected outage: about 30–60 min (party unavailable; wallet down).

**Key-id rule (why nothing new is minted and nothing collides).** The driver derives FROST ids from the Canton
key name (`frost-<name>`) and hosted ids as `rutli-enc-<name>-<random UUID>` (`FrostKeyIds.scala:41-57`).
- In this runbook the new node **generates no keys**: it registers the three existing ids, and the Splice
  dump path registers, never generates (`NodeInitializer.scala:314-344`).
- If something did generate:
  - a FROST key named `namespace` or `signing` maps to an existing id. The cosigners refuse the DKG with
    `ALREADY_EXISTS` (`node.rs:427-432`), loudly; it is never silently reused.
  - a hosted key always gets a fresh UUID. The `created=false` idempotency (`node.rs:718-735`) only applies to
    an identical id, so it can never return the old participant's key.
- The new participant **shares** `frost-signing` and the hosted encryption key with the old member, which is
  offboarded at the PNR. Canton has no cross-member key-uniqueness check (`TopologyMappingChecks.scala:757-800`),
  and Splice recovery does the same.
- Fresh per-participant keys are an optional later rotation. Give them distinct names, e.g.
  `generate_signing_key("soak1b-signing", …)` → `frost-soak1b-signing`.
- **Do not set `frost.key-prefix`:** routing is strict on the prefix, so `frost-namespace` would go to the
  `none` delegate and registration would fail (`FrostKeyIds.scala:59-62`).

**Lessons from the 2026-10-09 run (apply them):**
- **Port-forwards drop when idle** (`error: lost connection to pod`), and console commands sent while one is down
  fail with `Connection refused` and change nothing. Restart the forward and re-run the block; keep moving.
- **Step 5 needs `--set persistence.enableParticipantDbConflictCheck=false`.** The 0.9.0 chart's `pg-init` refuses to
  create `participant_b0` while `participant` exists (`Init:CrashLoopBackOff`, nothing else happens).
- **The console caches the node id.** After `init_id_from_uid`, `p.id` in the same session still returns the *old*
  `PAR::stakecraft-rutli-soak-1…`. Use `ParticipantId(NEW_UID)` explicitly, or a fresh console session.
- **Step 7 OTK: no `signedBy`.** A participant's OwnerToKeyMapping is strictly namespace-authorized in 3.6.1
  (`TopologyManager.scala:1300-1330`); listing the signing key gives `TOPOLOGY_NO_APPROPRIATE_SIGNING_KEY_IN_STORE`.
  `propose(member = ParticipantId(NEW_UID), keys = NonEmpty(Seq, sigK, encK))` signs with the namespace key and adds
  the proof-of-ownership signature itself.
- **`wait_for_initialized()` has no timeout and ignores Ctrl+C** (`HealthAdministration.scala:205-209`). Only call it
  after a successful propose; if stuck, complete the step from a second console session and the first returns.
- **Step 8 on DevNet takes 10–30 min:** the new member downloads the synchronizer's topology state (~1 M
  transactions) and processes ~850 k bootstrap events before `list_connected()` shows it. `connect_by_config`
  blocks meanwhile. An INFO `DbLock.runLockCheck … LockCheckRejected` during the import was harmless.

| # | Step | Command | Expect / verify | STOP if |
|---|---|---|---|---|
| 1 | **[MUTATES]** Dump secret | `kubectl -n $NS create secret generic participant-bootstrap-dump --from-file=content=$HOME/b0-drill/identities-dump.json` | Secret exists; no private keys in it (1.5) | — |
| 2 | **[MUTATES]** Stop the validator app first, so it never sees an uninitialised participant without the dump config | `kubectl -n $NS scale deploy/validator-app --replicas=0 && kubectl -n $NS wait --for=delete pod -l app=validator-app --timeout=5m` | No pod | Pod lingers |
| 3 | **[MUTATES]** Quiesce the old participant and take the reference ACS. This is also the fallback source for contracts Scan does not return. | console: `p.synchronizers.disconnect_all()`<br>`val T_STOP = java.time.Instant.now; val END_OLD = p.ledger_api.state.end()`<br>`p.repair.export_acs(parties = Set(VALIDATOR_PARTY), ledgerOffset = END_OLD, exportFilePath = "/b0/acs-old.gz")` (`ParticipantRepairAdministration.scala:276`) | `list_connected()` empty, `acs-old.gz` non-empty. Record `T_STOP`, `END_OLD`. | Export error |
| 4 | **[MUTATES]** Stop the old participant | `kubectl -n $NS scale deploy/participant --replicas=0 && kubectl -n $NS wait --for=delete pod -l app=participant --timeout=5m` | **Zero participant pods.** The old DB `participant` is never written again. | Any pod |
| 5 | **[MUTATES]** New participant on a fresh DB, same deployment, so the same driver bundle and state PVCs (one consumer at a time) | `helm -n $NS upgrade participant $CHART_PARTICIPANT --version 0.9.0 -f ~/b0-drill/participant-values.pre-b0.yaml --set persistence.databaseName=participant_b0 --set persistence.enableParticipantDbConflictCheck=false` | `pg-init`: `create database participant_b0`. Log: `Loaded driver rutli (API v1) build 0.3.1`. Restart the port-forward. `p.health.status` → `WaitingForId`; `p.keys.secret.list()` empty. | Driver error; env not `participant_b0`; node already initialised |
| 6 | **[MUTATES]** Register keys by KMS id (Risk #1). Canton fetches the public key via the driver (`frost-*` → `GroupKey`, `rutli-*` → `PublicKey`, `FrostBackend.scala:359-372`), checks the key spec is allowed, and stores the key (`KmsPrivateCrypto.scala:78-104`; console `VaultAdministration.scala:178-219`). | `val nsK = p.keys.secret.register_kms_signing_key(NS_KMS_ID, Set(SigningKeyUsage.Namespace), "namespace")`<br>`val sigK = p.keys.secret.register_kms_signing_key(SIG_KMS_ID, <SIG_USAGE>, "signing")`<br>`val encK = p.keys.secret.register_kms_encryption_key(ENC_KMS_ID, "encryption")`<br>`assert(nsK.fingerprint.unwrap == NS_FP); assert(sigK.fingerprint.unwrap == SIG_FP); assert(encK.fingerprint.unwrap == ENC_FP)` | 3 fingerprints match (G1). Audit: 3× `getPublicKey`, **no** `generate*`. | Any error or mismatch → R-A |
| 7 | **[MUTATES]** Init the new UID under the existing namespace, load the root delegation, and create the new member's OTK, signed by namespace + signing via FROST. This is Canton's manual-init recipe (`TopologyManagementHelper.scala:184-207`) and Splice's `initializeFromDump` with a new id (`NodeInitializer.scala:256-312`). | `p.topology.init_id_from_uid(UniqueIdentifier.tryCreate(NEW_ID, NS_FP))`<br>`p.health.wait_for_ready_for_node_topology()`<br>`p.topology.transactions.import_topology_snapshot_fromV2("/b0/identity-authorized.bin", TopologyStoreId.Authorized)`<br>`p.topology.owner_to_key_mappings.propose(member = p.id.member, keys = NonEmpty(Seq, sigK, encK), signedBy = Seq(nsK.fingerprint, sigK.fingerprint))`<br>`p.health.wait_for_initialized(); p.id.toProtoPrimitive` | `PAR::<NEW_ID>::<NS_FP>` (G2). Audit: `sign keyId=frost-namespace` and `sign keyId=frost-signing` ok. Init completes once the authorized store holds an OTK with a signing and an encryption key (`CantonNodeBootstrap.scala:1195-1226`). | Rejection → R-A (nothing is on the synchronizer yet) |
| 8 | **[MUTATES]** Onboard the new member with the old connection config. It is not active, so it pushes its onboarding topology: trust certificate (FROST namespace) + OTK + namespace delegation. The sequencer accepts because the UID was never onboarded (`SynchronizerRegistryHelpers.scala:266-298`, `GrpcSequencerConnectService.scala:251-267`). | `p.synchronizers.connect_by_config(syncCfg)` (`ParticipantAdministration.scala:2436`)<br>`p.synchronizers.list_connected()`<br>`p.topology.synchronizer_trust_certificates.list(store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), filterUid = NEW_ID)` | Connected and healthy; trust certificate for `NEW_ID` present (G3). Catch-up is seconds, because the subscription starts at its own onboarding. | Onboarding rejected → R-A |
| 9 | **GATE: operator decision to cross the PNR.** Checklist: G1–G3 green; zero old participant pods; `acs-old.gz` exists; backup verified; secret present; the validator overlay below diffs against the pre values in exactly these keys. | Overlay `~/b0-drill/validator-b0.yaml`:<br>`nodeIdentifier: <NEW_ID>`<br>`participantIdentitiesDumpImport: {secretName: participant-bootstrap-dump, newParticipantIdentifier: <NEW_ID>}`<br>`migrateValidatorParty: true`<br>`persistence: {databaseName: cantonnet_validator_b0}`<br>(`validatorPartyHint` stays `stakecraft-rutli-soak-1`; Splice requires `nodeIdentifier` = `newParticipantIdentifier`, release notes 0.5.x) | — | Any unchecked item |
| 10 | **[MUTATES] [crosses PNR]** Start the validator on a fresh DB with the Splice re-onboard config (Splice `standalone-validator-values.yaml:28-34`). Its participant initialiser sees the node already initialised with the expected id and skips (`NodeInitializer.scala:227-253`). It then connects, vets packages, and runs the migrator. | `helm -n $NS upgrade validator $CHART_VALIDATOR --version 0.9.0 -f ~/b0-drill/validator-values.pre-b0.yaml -f ~/b0-drill/validator-b0.yaml`<br>`kubectl -n $NS logs -f deploy/validator-app \| grep -E 'dump\|initialized with id\|Vet\|Preparing to remove\|Unhosting\|Removing\|Hosting\|Importing ACS\|ACS import complete\|primary party\|ERROR'` | In order:<br>`Loading participant identities dump` → `node is initialized with id PAR::<NEW_ID>…` → vetting<br>→ **PNR:** `Preparing to remove domain trust certificate because we will be migrating stakecraft-rutli-soak-1::…`<br>→ `Removing party mapping…` → `Removing domain trust certificate.` → `Hosting … on PAR::<NEW_ID>…` → `Importing ACS for party ids … from scan` → `ACS import complete` → primary party set. Pod 1/1.<br>Audit: ≥ 3 more `sign keyId=frost-namespace` (admin party mapping removal, trust certificate removal, new hosting). | **Before the PNR line:** any ERROR, or `generating a new one` → `kubectl scale deploy/validator-app --replicas=0` **immediately** → R-A.<br>**After:** errors → R-B (do not roll back). |
| 11 | **[MUTATES]** Normalise the values: drop the dump import and the migrate flag, keep `nodeIdentifier: <NEW_ID>` and `cantonnet_validator_b0`; delete the secret | `helm -n $NS upgrade validator … -f validator-values.pre-b0.yaml -f validator-b0-final.yaml` (overlay without `participantIdentitiesDumpImport`/`migrateValidatorParty`); `kubectl -n $NS delete secret participant-bootstrap-dump` | Restart clean; `Party migration already complete` or a normal init | Re-migration attempt |

---

## 4. Verification

| Check | How | Pass |
|---|---|---|
| Identity | `p.id.toProtoPrimitive`, `p.id.uid.namespace.fingerprint.unwrap` | `PAR::<NEW_ID>::…`, = `NS_FP` |
| Keys | `p.keys.secret.list()` | Exactly the 3 recorded fingerprints/ids |
| Nothing minted | Grafana `rutli_ceremony_requests_total`, `rutli_hosted_key_ops_total{op="generate"}` vs baseline; `kubectl -n $NS logs deploy/participant \| grep -E 'AUDIT (generate\|deleteKey)'` | Flat / none |
| Hosting | `p.topology.party_to_participant_mappings.list(SYNC_ID, filterParty = VALIDATOR_PARTY.filterString)` | Only `PAR::<NEW_ID>`, Submission, threshold 1 (G4) |
| Old member gone | `p.topology.synchronizer_trust_certificates.list(store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), filterUid = OLD_UID)` | Empty (removed); `p.parties.list(filterParticipant = OLD_UID)` empty |
| ACS | `p.repair.export_acs(Set(VALIDATOR_PARTY), p.ledger_api.state.end(), "/b0/acs-new.gz")`, then:<br>`val o = repair.acs.read_from_file("/b0/acs-old.gz").flatMap(_.createdEvent); val n = repair.acs.read_from_file("/b0/acs-new.gz").flatMap(_.createdEvent)`<br>`val nIds = n.map(_.contractId).toSet; val oIds = o.map(_.contractId).toSet`<br>`o.filterNot(c => nIds(c.contractId)).groupBy(_.templateId.map(_.entityName)).view.mapValues(_.size).foreach(println)`, and the same for `n` vs `oIds` | `gone` contains only (a) contracts archived after `T_STOP` (rounds, coupons, liveness) and (b) contracts **not shared with the DSO**, which the Scan-sourced import drops by design ("preserves all party IDs and all contracts shared with the DSO party", Splice `validator_disaster_recovery.rst:108-121`). `ValidatorLicense`, `ValidatorRight`, `WalletAppInstall` and every unspent `Amulet` must be in `n`. List class (b) in the soak log. |
| Commitments | after ≥ 2 reconciliation intervals: `kubectl -n $NS logs deploy/participant --since=2h \| grep -E 'ACS_COMMITMENT_MISMATCH\|ACS_MISMATCH_NO_SHARED_CONTRACTS\|ACS_COMMITMENT_ALARM'` | None (G5) |
| Validator / licence | validator logs | No `Unknown secret`, no `ValidatorLicense not found`, no onboarding-secret fetch |
| Traffic | `p.traffic_control.traffic_state(SYNC_ID)`; validator logs for top-up | The new member started without purchased traffic; top-up bought some within minutes; submissions not rejected for traffic |
| Wallet | Wallet UI as the validator wallet user | Balance = `WALLET_BALANCE` ± activity. **If the UI offers "Onboard", do not click it** (that allocates a new party); check the logs. Other wallet users would have to re-onboard (none expected). |
| **[MUTATES]** Transfers | Send a small CC amount to another StakeCraft DevNet validator's party and back; accept offers on each side | Both complete |
| FROST | `kubectl -n $NS logs deploy/participant --since=3h \| grep -c 'AUDIT sign keyId=frost-namespace.*outcome=ok'`; the same for `frost-signing` | namespace ≥ 5 (OTK, trust certificate, admin party mapping removal, old trust certificate removal, new hosting); signing > 0; `rutli_sign_requests_total{result="error"}` flat |
| Logs / alerts | ERRORs in participant and validator-app logs since the cutover; Alertmanager; dashboard (link in soak log) | Explained only; no alerts |
| Soak | next `rutli-soak-check`, ≥ 24 h | Green |

---

## 5. Rollback

### R-A: before the PNR line (steps 1–10, before `Preparing to remove domain trust certificate`)

The old participant still owns the party, and its DBs were never written after `T_STOP`.

1. **[MUTATES]** `kubectl -n $NS scale deploy/validator-app --replicas=0` and wait. Then the same for `deploy/participant`. Verify zero participant pods.
2. **[MUTATES]** `helm -n $NS rollback participant $PARTICIPANT_REV_PRE`. Old DB `participant`; it reconnects
   on start and catches up from `T_STOP`. Check `p.health.status` and a self-ping `p.health.ping(p)`.
3. **[MUTATES]** `helm -n $NS rollback validator $VALIDATOR_REV_PRE`. Old DB `cantonnet_validator`, old `nodeIdentifier`.
4. **[MUTATES]** If step 8 ran, offboard the orphan new member so it does not hold back sequencer pruning
   (`SequencerPruningStatus.scala:162-185`: safe pruning follows **enabled** members' acknowledgements). From
   the old participant, which holds the same namespace key:
   `p.topology.synchronizer_trust_certificates.propose(ParticipantId(UniqueIdentifier.tryCreate(NEW_ID, NS_FP)), SYNC_ID, store = Some(TopologyStoreId.Synchronizer(SYNC_ID)), change = TopologyChangeOp.Remove)`.
   `NEW_ID` is burned; the next attempt needs a different one.
5. `kubectl -n $NS delete secret participant-bootstrap-dump`. Keep `participant_b0` / `cantonnet_validator_b0` for forensics (dropping them is a separate, approved step).
6. Verify party list, wallet, and no commitment mismatch on the old participant.

If the old DB is damaged (nothing writes to it, so it should not be): restore `BACKUP_FILE` with `zcat … | psql -h postgres -U cnadmin -d postgres`
from a one-off `postgres:15-alpine` pod, with validator and participant at 0 replicas. The pod needs a label
the `postgresAccess` NetworkPolicy admits (`app: participant` or `app: validator-app`). `--clean` restores
**all** DBs to the backup time, so they stay consistent with each other. This is valid only before the PNR.

### R-B: after the PNR line (fix forward; the old UID can never rejoin)

The old participant is offboarded on-chain (`TopologyMappingChecks.scala:561-566`). Restoring its DB does not
bring it back. **Never start the old participant again.**

1. **Retry.** Restart the validator app. The migrator is idempotent: it resumes from parties stored in its DB
   and treats an assigned primary party as "import done" (`ParticipantPartyMigrator.scala`, `getPartiesToMigrate`, `primaryPartyO`).
2. **Re-import from Scan**, per Splice DR troubleshooting (`validator_disaster_recovery.rst:213-262`):
   1. Stop the validator app and run `p.synchronizers.disconnect_all()`.
   2. Fetch `/api/scan/v0/acs/<party>` **from inside the cluster** (Scan allowlist).
   3. Run `p.repair.import_acs(...)` (`ParticipantRepairAdministration.scala:385`), reconnect, start the validator.

   Only do this if the node does not already hold those contracts: an import of contracts the node already has
   fails the activeness check on reconnect (`PreventDuplicateContractsIntegrationTest.scala:110-204`). If unsure, use option 3.
3. **Migrate forward again** to another fresh UID (`<NEW_ID>-2`) on another fresh DB (`participant_b0b`, `cantonnet_validator_b0b`).
   Same §3 with a dump taken from the current node, or the old dump with `id` edited to the current participant id (Splice DR doc, step 3).
4. **Missing non-DSO contracts that matter.** Write that subset of `acs-old.gz` to a file
   (`repair.acs.write_contracts_to_file`, `RepairMacros.scala:361-410`) and import it while disconnected.
   Only if those contracts are still active on the network and not already present.

---

## 6. Soak-log entry template

```markdown
**Planned event: B0 cutover drill (new participant UID, same FROST namespace), HH:MM:SS → HH:MM:SS (party unavailable N min).**
Runbook: [b0-cutover-spike.md](b0-cutover-spike.md).
- Backup: pg_dumpall `<TS>` sha256 `<…>` (S3 OK; kms_metadata 3, private_keys 0); cosigner backup `<job>`.
- T_STOP <ts>, END_OLD <offset>, reference ACS <n> contracts. Old DBs untouched; new `participant_b0` / `cantonnet_validator_b0`.
- G1 registration by id: frost-namespace → <fp> ✓, frost-signing → <fp> ✓, <enc id> → <fp> ✓.
- G2 init `PAR::<NEW_ID>::<ns>`; minted keys: none (ceremony/generate counters flat).
- G3 onboarding: trust certificate <ts>, FROST namespace signs <n>.
- PNR crossed at <ts>; old trust certificate removed <ts>; party hosted on new participant <ts>; Scan ACS import <n> contracts, done <ts>.
- G5 ACS diff: gone <n> (archived after T_STOP: <templates>; not DSO-shared: <templates>), added <n>; commitment mismatches 0 over <n> intervals.
- G6 wallet <before> → <after>; transfer out ✓ <ts>, in ✓ <ts>; licence found; no onboarding secret; top-up <amount> at <ts>.
- G7 sign errors 0, decrypt rate-limited 0, alerts none; soak-check <date> green.
- Splice 0.9.0 deltas observed: <…>. Noise: <…>.
- Verdict: GO / NO-GO (reason). Rollback: none / R-A at <step> / R-B option <n>.
- Setup table updated: participant `PAR::<NEW_ID>::…` (old `PAR::stakecraft-rutli-soak-1::…` offboarded <ts>).
```

---

## 7. Open questions and things to verify on the day

1. **Splice 0.9.0 vs the 0.5.5 source.** Check the chart keys, the image init flags, and whether the migrator
   order or the onboarding-flag use changed (1.2). In 0.5.5 the order is: unhost and offboard old → host new
   (no onboarding flag) → disconnect → import from Scan → reconnect.
2. **Scan-sourced ACS covers only DSO-shared contracts.** Expected to be everything on a plain validator; §4 proves it.
3. **The party is hosted nowhere** between removing the admin party mapping and the new hosting (seconds to
   minutes). Transactions needing its confirmation fail meanwhile. Expected, not a STOP.
4. **The new member starts with no purchased traffic.** Top-up depends on base-rate traffic for its own
   purchase transaction. Check how fast it recovers. The old member's remaining extra traffic is lost.
5. **`SPLICE_APP_DEVNET=1` auto-fetches an onboarding secret** if the app thinks it is not onboarded. The Splice
   DR doc says none is needed (`validator_disaster_recovery.rst:116-121`). Record what happens.
6. **Admin-party coupling** (hint = node identifier) forces offboarding the old participant before the move.
   A validator whose party hint differs from its node identifier could instead use Canton's offline party
   replication order (§0) with the old participant kept as a fallback. Check this for the B4 scratch validator
   and for pilots, because it changes where their PNR sits.
7. **Shared keys.** `frost-signing` and the hosted encryption key stay in the offboarded old member's OTK.
   Decide whether to rotate the new participant onto fresh, distinctly named keys after B0. It is optional.
8. **Driver state PVC.** The audit chain and signing journal continue in the same files across both identities.
   Confirm `HashChainedAuditLog.verify` still passes over the drill window.
9. **Pruning hygiene.** If the drill aborts after step 8, step 4 of R-A must run, or SV pruning will eventually
   disable the orphan member anyway.

---

## Appendix: source references

Canton = `~/.cache/canton-src` `v3.6.1` (paths under `community/`, docs under `docs-open/`). Splice = the 0.5.5 source checkout (deployed: 0.9.0).

| Claim | Where |
|---|---|
| Same-UID fresh DB is "active": skips onboarding, replays from registration | `participant/.../synchronizer/SynchronizerRegistryHelpers.scala:266-298,321`; `base/.../topology/store/TopologyStateForInititalizationService.scala:50-58,113-147`; `synchronizer/.../sequencer/SequencerReader.scala:265-290` |
| Ever-onboarded UID cannot onboard again | `synchronizer/.../sequencing/service/GrpcSequencerConnectService.scala:251-267`; `base/.../topology/client/StoreBasedTopologySnapshot.scala:56-69` |
| Removed participant cannot rejoin; party UID = participant UID ⇒ only explicit admin hosting while the trust certificate exists | `base/.../topology/transaction/checks/TopologyMappingChecks.scala:561-566,608-617,1146-1177` |
| No cross-member OTK key-uniqueness check | `TopologyMappingChecks.scala:757-800` |
| Safe pruning = min over enabled members' acks | `synchronizer/.../sequencer/SequencerPruningStatus.scala:162-185` |
| Register by KMS id: driver public key + key-spec check only | `base/.../crypto/provider/kms/KmsPrivateCrypto.scala:78-104`; `common/.../crypto/admin/grpc/GrpcVaultService.scala:418-507`; console `app-base/.../console/commands/VaultAdministration.scala:79,178,213` |
| Manual identity config; `generate-topology-transactions-and-keys` default true; auto-complete mints keys | `app/src/test/resources/participant1-manual-init.conf:2-5`; `common/.../config/InitConfig.scala:80-106`; `common/.../environment/CantonNodeBootstrap.scala:1195-1226,1248-1260` |
| Manual-init recipe; `init_id_from_uid`; topology export/import; OTK propose | `app/src/test/.../topology/TopologyManagementHelper.scala:150-207`; `app-base/.../console/commands/TopologyAdministrationGroup.scala:236,450,810` |
| Trust-certificate list/propose (incl. `change = Remove`) | `TopologyAdministrationGroup.scala:2514,2576-2600` |
| `export_acs` / `import_acs`; `connect_by_config`; `config(alias)` | `app-base/.../console/commands/ParticipantRepairAdministration.scala:276,385`; `ParticipantAdministration.scala:2436,2765` |
| Offline party replication order and onboarding flag | `docs-open/.../participant/howtos/operate/parties/party_replication.rst:342-354,483-500,541-560,723-752` |
| Duplicate-contract import → activeness failure; filter with `excludedStakeholders` | `app/src/test/.../multihostedparties/offpr/PreventDuplicateContractsIntegrationTest.scala:110-204` |
| DA KMS migration: new participant + delegation + other synchronizer | `app/src/test/.../security/kms/KmsMigrationIntegrationTest.scala:100-237` |
| Console flags / remote `token` | `app-base/.../config/CantonConfig.scala:404-406`; `participant/.../config/ParticipantNodeConfig.scala:150-156` |
| `SigningKeyUsage.All` | `base/.../crypto/Signing.scala:757-763` |
| Splice identity init / dump with KMS ids / new-UID OTK | Splice `apps/common/.../setup/NodeInitializer.scala:64-151,227-344`; `ParticipantInitializer.scala`; `identities/NodeIdentitiesStore.scala`; `common-internal.yaml:92-119` |
| Splice migrator: offboard old (admin party), host new, import from Scan | Splice `apps/validator/.../migration/ParticipantPartyMigrator.scala`; `ValidatorApp.scala:143-189,343-375` |
| Splice chart / values / docs | `cluster/helm/splice-validator/templates/validator.yaml:200-213`, `values.schema.json:263,465`; `apps/app/src/pack/examples/sv-helm/standalone-validator-values.yaml:28-34`; `docs/src/validator_operator/validator_disaster_recovery.rst:100-148,213-262`; `docs/src/sv_operator/sv_operations.rst:82` |
| Driver id derivation and routing; DKG and hosted create-once | `driver/.../backend/FrostKeyIds.scala:41-62`; `FrostBackend.scala:257-302,359-384`; `frost/cosigner/src/node.rs:427-432,700-735` |

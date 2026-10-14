# Migrating an existing Canton validator into Rütli

**Status:** draft, corrected after the DevNet rehearsal of 2026-10-14 ([b4-rehearsal.md](b4-rehearsal.md), roadmap B4; results in the
[soak log](soak-2026-10-devnet.md)). The cutover and verification ran green; destruction (Step 8) has not run yet, so treat
Step 8 as unproven. The corrections are folded in below and listed in "Lessons from the B4 rehearsal".
**Applies to:** Splice 0.9.x validators on Canton 3.6.x whose keys are held by Canton itself (JCE, keys in Postgres),
moving into a Rütli cluster ≥ 0.4.0.
**Audience:** the operator of the existing validator, and the operator of the Rütli cluster, if that is someone else.

---

## Read this first: what migration can and cannot do

**Migration protects the future, not the past.** Your namespace key has existed whole in a place other than a threshold
cluster. It sits in your participant database (`common_crypto_private_keys`, unencrypted unless you run a KMS wrapper key), in
the database's WAL and replicas, and in **every backup** ever taken of it. During this procedure it also exists in an export
file and, for a few seconds, in the dealer's memory. Rütli splits the key into threshold shares and you destroy the old copies.
From then on no single machine can sign, losing a cosigner is survivable, and every signature is audited. **Anyone who copied the
key before destruction keeps it forever, and a Canton namespace key cannot be rotated.** If that risk is unacceptable, the only
alternative is a new validator with a new namespace, whose key is born by DKG and never exists whole. That means new party IDs.

What stays and what changes:

| | After migration |
|---|---|
| Namespace (`1220…` fingerprint) | **unchanged**: the same key, now held as FROST shares |
| Party IDs (`<hint>::<namespace>`), wallet balance, `ValidatorLicense` | **unchanged** |
| Participant ID (`PAR::<id>::<namespace>`) | **new**. A participant UID that was ever onboarded cannot onboard again, so the node is rebuilt as a new member and the parties move to it |
| Signing key, encryption key | **new**: FROST DKG signing key, cluster-hosted ECIES (or RSA) encryption key. The old ones are not carried (they can be, and should not be: §8) |
| Purchased extra traffic of the old member | **lost** (stranded on the offboarded member). Top-up buys new traffic |
| Contracts | Splice re-imports the party's ACS from Scan. Contracts **not shared with the DSO** are not in that import (see Limitations) |
| The old participant | **offboarded for good** at the point of no return. It can never rejoin |

## 1. Roles and trust domains

| Role | Does | Must never also hold |
|---|---|---|
| Lead | Runs the record, decides each gate | key material |
| Canton operator | Old validator: export, cutover, Splice re-onboard | `t` cosigner seal secrets |
| Dealer operator | Air-gapped dealer host and the key file | cosigner access |
| Cosigner operators (`n`) | One cosigner each: recipient request, install, backups | the key file |
| Witnesses (≥ 2) | Compare fingerprints, SAS and digests independently; sign the records | — |

One person may hold several roles **only on a test network**. On TestNet or MainNet, the person who held the key file must never
also hold `t` seal secrets. Details: [split-ceremony.md](split-ceremony.md) §1.

## 2. Parameters

| Name | Meaning | Example |
|---|---|---|
| `NS` | Kubernetes namespace of the validator | `acme-validator` |
| `HINT` | Validator party hint (`validatorPartyHint`) | `acme-validator-1` |
| `OLD_ID` | Current node identifier (`nodeIdentifier`, often = `HINT`) | `acme-validator-1` |
| `NEW_ID` | New node identifier, never used on this network before | `acme-validator-1-r` |
| `NS_FP` | Namespace fingerprint (the part after `::` in the party ID) | `1220…` (68 hex) |
| `PREFIX` | The new participant's `frost.key-prefix`, unique on the cluster, fixed forever | `acme1-` |
| `KEY_ID` | Imported namespace key id: `${PREFIX}frost-import-${NS_FP:4:8}` | `acme1-frost-import-cb0e86a9` |
| `CEREMONY` | Ceremony id, `[A-Za-z0-9_-]{1,64}` | `acme-2026-11-20` |
| `OLD_DB` / `NEW_DB` | Participant databases | `participant_1` / `participant_r` |
| `OLD_VDB` / `NEW_VDB` | Validator databases | `cantonnet_validator` / `cantonnet_validator_r` |
| `t`/`n` | Cluster threshold and size | 2 / 3 |

## 3. Before you start

- [ ] **Rütli cluster ≥ 0.4.0** on every cosigner, `share_seal` and mTLS on. Per-node TLS (`tls.layout: perNode` or the
      `tls-select` init container). `operatorAllowlist` lists an operator certificate issued by the cluster CA. For ECIES, every
      cosigner is upgraded **and up** when the encryption key is created ([hosted-keys.md](hosted-keys.md) §2).
- [ ] **Driver ≥ 0.4.0** jar for the new participant, its sha256 recorded. The cluster's driver client certificate.
- [ ] **Network reachability:** the new participant's pods reach the cosigners on 9101. In the cosigner chart's NetworkPolicy,
      the client namespace needs label `rutli.io/client-ns=true` and the pod needs `rutli.io/client=true`. Add any egress policy of your own.
- [ ] **Dealer host:** air-gapped, live-booted, no swap, no core handler, root; `rutli-dealer` built from the release tag, sha256
      recorded; the cluster's exact `ca.crt` ([split-ceremony.md](split-ceremony.md) §3.3).
- [ ] **No network upgrade or migration** expected within 48 h. Freeze activity on the validator for the cutover window (about 1–2 h,
      party unavailable).
- [ ] **Your admin party coupling:** if `HINT` = `OLD_ID` (the Splice default), the validator party is the participant's admin
      party and can move only after the old participant is offboarded. That sets the point of no return (§5). Otherwise,
      record it and talk to us: a different order may keep the old participant as a fallback longer.
- [ ] **Location inventory** of every copy of the key, filled in before you start ([split-ceremony.md](split-ceremony.md) §3.2,
      L1–L9). Check now whether your backup bucket has **object lock** or retention; locked copies cannot be destroyed early.
- [ ] Operator laptop: a work directory excluded from backups and sync (e.g. `tmutil addexclusion`), because the export file passes through it.

## 4. Procedure

The commands are written out in full, with expected output and STOP lines, in [b4-rehearsal.md](b4-rehearsal.md). The step
numbers in brackets point there. Substitute the parameters from §2.

### Step 1: baselines and backups

Record the party ID, wallet balance, ACS size, traffic state and the three key fingerprints (namespace, signing, encryption)
[1.3–1.4, 2.2]. Take a manual database backup and a cosigner backup [4.2]. The database backup is one more copy of the key.
It is your rollback path until the point of no return, and it goes on the destruction list.

### Step 2: export the namespace key with a password

1. Enable `canton.features.enable-preview-commands = yes` **on the participant** (an `ADDITIONAL_CONFIG_*` env var) and restart it.
   The server refuses `ExportKeyPair` without it [2.1].
2. In a Canton console, confirm `NS_FP` three ways: from the console, from the validator's public `GET /api/validator/v0/validator-user`,
   and as the target of the root namespace delegation [2.2].
3. `keys.secret.download_to(<namespace fingerprint>, "namespace.export", password = Some(<random ≥ 24 chars>))` [2.3].
   Record the file's sha256. Carry one copy to the dealer host.

Never call the validator's `GET /api/validator/v0/admin/participant/identities` or `/admin/domain/data-snapshot` on a JCE
node. Both return **all private keys in plaintext**.

### Step 3: split ceremony

Run [split-ceremony.md](split-ceremony.md) §3–§4 with `KEY_ID` and `NS_FP`: recipient requests, Gate 0 (SAS), split on the dealer,
dry run (Gate A), install, `verify-key --sign-test` with the operator certificate (Gate B), refresh, `verify-key` again (Gate C),
founding backups. Suspend cosigner backups for the window. **Do not proceed past a refused request signature, a SAS mismatch or
a bundle that fails authentication. Treat them as attacks** (split-ceremony.md §6). Kubernetes specifics (pod names, running
`verify-key` from a laptop over port-forwards) [3.0–3.1].

### Step 4: new participant on a fresh database

1. Put the driver jar and its TLS material where the participant mounts them [4.0]. `kubectl cp` keeps your laptop's uid, so
   `chown` the files to the participant uid (1001) in the pod afterwards (Lessons e).
2. Stop the validator app, disconnect the old participant, export a reference ACS, stop the old participant. Check that **zero** old
   participant pods remain [4.3–4.5].
3. Start the participant on `NEW_DB` with the Rütli KMS block. Use `frost.key-prefix = PREFIX`, `delegate = "none"`, and
   `hosted-keys = true`. For ECIES, add `encryption.keys.default = ec-p-256` and
   `encryption.algorithms.default = ecies-hkdf-hmac-sha-256-aes-128-cbc`. With the Splice chart, also set
   `persistence.enableParticipantDbConflictCheck=false` [4.6–4.7]. Check the driver log: `Loaded driver rutli … build <version>`,
   and that the cluster's capabilities include `ec-p256-ecies` if you use ECIES.

### Step 5: keys, identity, onboarding

1. **Register the namespace key by id:** `register_kms_signing_key(KEY_ID, Set(Namespace), "namespace")`. It **must** return `NS_FP`.
   Otherwise STOP and roll back [4.8].
2. **Fresh keys:** `generate_signing_key("signing", <USAGE>, Some(EcCurve25519))`
   (a FROST DKG, id `${PREFIX}frost-signing`) and `generate_encryption_key("encryption", Some(EcP256))` (cluster-hosted) [4.8].
   `<USAGE>` is `SigningKeyUsage.ProtocolWithProofOfOwnership ++ SigningKeyUsage.SequencerAuthenticationOnly`;
   `SigningKeyUsage.ProofOfOwnership` itself is not accessible from the console (Lessons a).
3. `init_id_from_uid(NEW_ID::NS_FP)`, import the old node's authorized-store identity snapshot (namespace delegation + OTK), then
   propose the new OTK **without** `signedBy` (Canton adds the proof-of-ownership signatures) [4.9].
4. `connect_by_config(<old connection config>)`. The sequencer connections of the old node's config are saved and restored through
   reflection (Lessons a). If validation fails because some of the sequencers are down, retry with
   `validation = SequencerConnectionValidation.Active` (the admin-data type, Lessons b). On a busy network, expect 10–30 min while the
   new member downloads the topology state [4.10].

Until here the old participant still owns the party, and rollback is a Helm rollback to the old databases (§6).

### Step 6: Splice re-onboard, which crosses the point of no return

1. Create the dump Secret **without keys**: `id` = the **old** participant id, `keys` = the three new KMS ids,
   `authorizedStoreSnapshot` = the snapshot from step 5.3. Use Secret key **`content`** [4.11]. Splice reads the keys of a dump only to
   initialise a node that is not initialised yet. Yours is initialised by hand, and the party migrator reads only the old id.
2. **Gate.** Re-check every item [4.12]. Then upgrade the validator with `nodeIdentifier: NEW_ID`,
   `participantIdentitiesDumpImport: {secretName, newParticipantIdentifier: NEW_ID}`, `migrateValidatorParty: true` and `NEW_VDB` [4.13].
   Run `helm upgrade --dry-run=server` first. If anything ever `kubectl patch`ed the Deployment, Helm 4 stops with field-manager
   conflicts, and the upgrade needs `--force-conflicts` (Lessons c). Find that out before the PNR, not after.
3. Watch the log. **`Preparing to remove domain trust certificate because we will be migrating <HINT>::…` is the point of no
   return.** Before it, any error, `Uploading node keys`, `Node has no identity` or `need to be rotated` → scale the validator
   to 0 at once and roll back. After it, fix forward only.
4. Normalise: remove the dump import and the migrate flag, keep `NEW_ID` and `NEW_VDB`, delete the Secret [4.14].

### Step 7: verify

Party ID unchanged. The party is hosted only on `PAR::NEW_ID::NS_FP`; the old trust certificate is gone. The ACS diff is explained:
everything missing is either archived after the stop or not shared with the DSO. No ACS commitment mismatch over two intervals.
Wallet balance unchanged (write the baseline down before the cutover); a transfer out and a transfer in succeed, through the
wallet UI (Lessons j, k); top-up buys traffic. No sign errors and no ECIES failures in the
driver audit [5.1]. Observe for at least 24 h.

### Step 8: destroy every old copy (only after Step 7 is green)

For each location in your inventory: act, keep before/after evidence, fill in the destruction record ([split-ceremony.md](split-ceremony.md) §8)
[5.4].
- **Local files:** on macOS use `/bin/rm -P`, not a bare `rm` (Lessons f).
- **Database:** `DROP DATABASE OLD_DB` (it holds the old namespace, signing and encryption keys). Let the WAL recycle; drop replicas and PITR base backups.
- **Logical dumps:** delete every dump taken while `OLD_DB` existed. Your backup schedule keeps adding copies until the DROP, so drop early.
- **Object storage:** delete every **version and delete marker**, not just the current objects. If object lock is on, record the retention end date.
- **Snapshots, identities dumps, export files, laptops, dealer media, ceremony bundles, pre-refresh cosigner backups.**
- State the residual exposure in the record. SSDs, copy-on-write filesystems and cloud deletes are not provable erasure.

Optionally, remove the offboarded member's owner-to-key mapping, which still lists the old keys [5.2].

## 5. Point of no return, in one place

Before the validator logs `Preparing to remove domain trust certificate…`, everything can be undone: the old databases were never written
after the stop. After it, the old participant is offboarded on the synchronizer and can never rejoin, so recovery is
**fix-forward only**: retry the migrator, re-import from Scan, or migrate forward again to another fresh id. Never start the old
participant again.

## 6. Rollback

| When | What |
|---|---|
| Ceremony, before Gate B | `abort-import` per node; restart a cosigner that signed with the share before any re-import ([split-ceremony.md](split-ceremony.md) §5) |
| Ceremony, after Gate C | No destroy path. Leave the id as residue; to retry, use a new `KEY_ID`/`CEREMONY` |
| Cutover, before the PNR | Scale the validator, then the participant, to 0. Helm-rollback both to the old databases. If the new member already onboarded, offboard it from the old participant (it holds the namespace key). `NEW_ID` is burned ([b0-cutover-spike.md](b0-cutover-spike.md) §5 R-A) |
| Cutover, after the PNR | Fix forward ([b0-cutover-spike.md](b0-cutover-spike.md) §5 R-B). Do not destroy anything until resolved |

## 7. Known limitations

- **Exposure:** see the top of this page. An imported namespace key is not as strong as one born by DKG.
- **Non-DSO contracts:** Splice re-imports the party's contracts from Scan, which covers contracts shared with the DSO party. For a
  plain validator that is everything that matters (licence, wallet install, amulets). If your party has other contracts, plan
  their import from the reference ACS (B0 R-B option 4).
- **Party unhosted for seconds to minutes** between unhosting on the old participant and hosting on the new one. Transactions that
  need it fail meanwhile.
- **Purchased traffic** of the old member is lost.
- **Shared cluster:** `frost.key-prefix` separates key ids, not authority. Any holder of the cluster's driver certificate can address any
  key id. Use your own cluster, or your own driver CN with approval rules ([architecture.md](architecture.md)).
- **ECIES** needs every cosigner upgraded and up when the key is created. RSA does not, and remains available.
- **Cluster residue:** imported and DKG keys cannot be deleted from the cluster (by design). A failed attempt leaves its ids behind.

## 8. Carrying the signing and encryption keys (discouraged)

The procedure above carries **only the namespace key** and gives the new participant fresh signing and encryption keys
(Step 5.2). Rütli can also carry the old node's protocol signing, sequencer-authentication and encryption keys
(roadmap B6). It is possible because nothing in Canton stops it: `RegisterKmsSigningKey` checks only the key spec, and a new
member may list fingerprints that an offboarded member's OTK listed too (B0 did exactly that). **Do not do it unless something
outside Canton pins those fingerprints and cannot be changed in time.**

### Why not

- **These keys rotate; the namespace key does not.** That is the only reason the namespace key is carried at all. A signing
  or encryption key is replaced with one OTK update, at any time.
- **Carrying them buys no continuity.** The participant UID is new and its OTK is new anyway (Step 5.3). Nothing on the
  synchronizer refers to the old keys except the OTK of the member being offboarded.
- **It carries the exposure with them.** Every pre-migration copy (`common_crypto_private_keys`, its WAL and replicas, every
  `pg_dumpall`, every version in the backup bucket, the export file) can then act as the **new** member. A signing key authenticates
  to the sequencer and signs confirmations in its name; the encryption key decrypts **every future view** sent to it, by anyone who
  holds an old backup and can read the ciphertexts the sequencers store and deliver. Destruction (Step 8 of §4) then protects a
  live identity, not a retired one, and nothing proves it complete.
- **A hosted ECIES key is a whole key, replicated to all `n` cosigners** ([hosted-keys.md](hosted-keys.md)), not a threshold
  key. Carrying it adds `n` more places to the old ones.
- **"Carry, then rotate" ends where a fresh key starts.** After the rotation the carried key is out of the OTK, which is where
  Step 5.2 starts; in between it was exposed.

### Which keys exist

Print them on the old node, with usage (the B0 snippet, [b0-cutover-spike.md](b0-cutover-spike.md) §1.4):

| Node | Signing keys | Encryption |
|---|---|---|
| Canton auto-init | `namespace` {namespace}; `signing` {signing, proof-of-ownership}; `sequencer-auth` {sequencer-auth, proof-of-ownership} | `encryption` |
| Splice validator (`NodeInitializer.scala:69-73`) | `namespace` {namespace}; **one** `signing` key with `SigningKeyUsage.All` = {namespace, sequencer-auth, signing, proof-of-ownership} | `encryption` |

Splice's `signing` key lists **namespace** among its usages and is **not** the namespace key: the namespace is the fingerprint after
`::` in the node's UID, and that is the key named `namespace`. A legacy key with an empty usage list counts as `All` too. This is why
the dealer asks for `--namespace-fingerprint` wherever the usage alone is ambiguous (below). Register Splice's key on the new node
**without** namespace usage: the new member needs it to sign and to authenticate, not to authorize namespace changes.

### Before the split: the carried key must not sign for a namespace

`--namespace-fingerprint` rules out the **root** namespace key only. A key that is the target of a namespace delegation also
signs for that namespace, and carried under a protocol id it would escape the approval rule that holds namespace signatures.
On the old node, for each signing key you mean to carry, list the delegations that name it as their target, in the authorized
store and on the synchronizer (`SYNC_ID` as in [b0-cutover-spike.md](b0-cutover-spike.md) §1.4):

```scala
import com.digitalasset.canton.crypto.Fingerprint
import com.digitalasset.canton.topology.admin.grpc.TopologyStoreId
val target = Some(Fingerprint.tryFromString(SIG_FP))
p.topology.namespace_delegations.list(store = TopologyStoreId.Authorized, filterTargetKey = target) ++
  p.topology.namespace_delegations.list(store = TopologyStoreId.Synchronizer(SYNC_ID), filterTargetKey = target)
```

Both lists must be empty. **STOP if either is not**: that key is a namespace key in all but name. Do not carry it.

### One ceremony per signing key

Each carried signing key is its own split ceremony, run in full: [split-ceremony.md](split-ceremony.md) §3–§4, every gate,
founding backups, then a refresh. Canton auto-init has two (`signing`, `sequencer-auth`), Splice one (`signing`). Export each like the
namespace key (§4 Step 2) and give each its own `CEREMONY`. The dealer is told what the key is for:

```sh
rutli-dealer split-key --in signing.export --password-env EXPORT_PW \
  --expect-usage protocol --expect-fingerprint "$SIG_FP" \
  --key-id "${PREFIX}frost-import-sig-${SIG_FP:4:8}" \
  --namespace-fingerprint "$NS_FP" \
  --threshold 2 --ca-cert ca.crt --recipient r1.json --recipient r2.json --recipient r3.json --out-dir out/
```

Pass `--namespace-fingerprint` in protocol mode every time: Splice's key cannot be split without it, and for a Canton key it is a
free check that the key you carry is not the root.

| `--expect-usage` | The key's recorded usage must | Id | `--namespace-fingerprint` |
|---|---|---|---|
| `namespace` (default) | be exactly {namespace} | `${PREFIX}frost-import-<name>` | required if the usage has more than namespace, is empty (= all) or unknown (plain PKCS#8); must **equal** the key's fingerprint |
| `protocol` | include signing or sequencer-auth; plain PKCS#8 is refused | `…frost-import-sig-<name>` if it includes signing, else `…frost-import-seqauth-<name>` | required if the usage includes namespace (Splice, legacy keys); must **differ** from the key's fingerprint |

Each mode refuses the other's ids before any secret is read, and a given `--namespace-fingerprint` is always checked.
`dealer-record.json` records `expected_usage`, `recorded_usage` and `namespace_fingerprint`. The share bundles carry all three
under their AAD (envelope version 3). `import-share` re-applies every rule of the table above to them: the usage for the mode,
`--namespace-fingerprint` against the bundle's own Canton fingerprint (which must be the group key's and your
`--expect-fingerprint`), and the id's class and label. `verify-key` prints the mode and usage (`carried-for protocol`) and
requires every node to agree. Use the dealer and cosigners of one release: an older cosigner
refuses a version 3 bundle, and this release's cosigners refuse a pre-B6 (version 2) bundle.

The encryption key is not a ceremony: `import-key` it into one cosigner (its daemon may be running), then check it with
`verify-hosted` before registering it ([hosted-keys.md](hosted-keys.md), "Importing a Canton node's ECIES key"). Only an EC P-256
encryption key can be carried; RSA import is not supported (B3 was dropped), so an RSA node gets a fresh key.

### Ids and the approval-rule pitfall

| Key | Id |
|---|---|
| namespace | `${PREFIX}frost-import-${NS_FP:4:8}` |
| protocol signing (Splice: the one `signing` key) | `${PREFIX}frost-import-sig-${SIG_FP:4:8}` |
| sequencer authentication (Canton only) | `${PREFIX}frost-import-seqauth-${SEQ_FP:4:8}` |
| encryption | `${PREFIX}rutli-enc-imported-${ENC_FP:4:8}` |

Approval rules match key-id **prefixes**, first match wins ([approval-quorum.md](approval-quorum.md)). The natural rule for an
imported namespace key, `key-id-prefix = "${PREFIX}frost-import-"`, also matches the `-sig-` and `-seqauth-` ids: every confirmation
and every sequencer authentication would wait for human approvals, and the participant stalls. Either name the namespace id exactly,
or put `auto` rules for the protocol ids first:

```hocon
rules = [
  { key-id-prefix = "acme1-frost-import-sig-",     mode = "auto" },
  { key-id-prefix = "acme1-frost-import-seqauth-", mode = "auto" },
  { key-id-prefix = "acme1-frost-import-",         mode = "quorum", threshold = 2 }
]
```

The driver logs a WARN at startup for every quorum rule on `…frost-import-` that would hold a `-sig-` or `-seqauth-` id.
The reverse mistake is worse, and nothing warns about it: never let a broad `auto` rule match the namespace id.

### Register them on the new participant

Instead of Step 5.2, register each carried key by id with the usage it had, **minus namespace**. Canton adds proof-of-ownership
to every non-namespace key itself (`Signing.scala:943-947, 1336`), which the key needs to sign the OTK that lists it
(`TopologyManager.scala:1315-1318`). Each must return the old fingerprint; otherwise STOP and roll back.

```scala
import com.digitalasset.canton.crypto.SigningKeyUsage
// Canton auto-init: two keys
val sig = p.keys.secret.register_kms_signing_key(SIG_ID, SigningKeyUsage.ProtocolWithProofOfOwnership, "signing")
val seq = p.keys.secret.register_kms_signing_key(SEQ_ID, SigningKeyUsage.SequencerAuthenticationOnly, "sequencer-auth")
// Splice: one key, All without Namespace
val sig = p.keys.secret.register_kms_signing_key(SIG_ID,
  Set(SigningKeyUsage.Protocol, SigningKeyUsage.SequencerAuthentication), "signing")
val enc = p.keys.secret.register_kms_encryption_key(ENC_ID, "encryption")
```

The OTK of Step 5.3 then lists these keys, and the dump Secret of Step 6.1 lists their ids.

### Refresh, verify, destroy

- **One refresh CronJob per FROST id**: the namespace id and each carried signing id ([deploy/k8s/cronjob-refresh.yaml](../deploy/k8s/cronjob-refresh.yaml)
  takes one `KEY_ID`; copy it per id and stagger the schedules). The hosted encryption key has no shares to refresh.
- `verify-key --sign-test` per signing id after every refresh; `verify-hosted` for the encryption key after every cosigner restore.
- Step 7 adds: the driver audit shows `sign keyId=…frost-import-sig-…` (and `…-seqauth-…`) `outcome=ok` and ECIES decryptions with
  the carried encryption key.
- Step 8 is unchanged in scope, since the old database held these keys anyway, but it is now the only thing between an old backup
  and the live member.

Rehearsed end to end on Canton 3.6.1 by `scripts/e2e-carry-protocol-keys.sh`: both protocol keys split against running cosigners,
the encryption key imported into a running cosigner, all three registered with the old fingerprints, the OTK rotated onto them,
pings both ways, and a reconnect that authenticates to the sequencer with the carried key.

## 9. What to send us (pilots)

The ceremony record and the destruction record from [split-ceremony.md](split-ceremony.md) §8, the verification table from Step 7,
the time each step took, and anything in this runbook that did not match what you saw.

## 10. Lessons from the B4 rehearsal (2026-10-14)

The rehearsal moved a scratch JCE validator into the soak cluster (`v0.4.0-rc.1`): party IDs unchanged, ACS 5 → 6 with no
commitment mismatch, tap and transfers in both directions, ECIES decrypting live. Everything below cost time or failed on the
first try. Apply it.

a. **Console visibility.** `admin.api.client.data.SequencerConnections.toInternal/fromInternal` are `private[canton]`, and so is
   `SigningKeyUsage.ProofOfOwnership`. Persist the old node's sequencer connections through reflection (14 sequencers round-tripped, equal
   to the original), and build the signing usage from the public aliases:

   ```scala
   val toInt = (s: com.digitalasset.canton.admin.api.client.data.SequencerConnections) => s.getClass.getMethod("toInternal").invoke(s).asInstanceOf[com.digitalasset.canton.sequencing.SequencerConnections]
   val fromInt = (i: com.digitalasset.canton.sequencing.SequencerConnections) => { val o = com.digitalasset.canton.admin.api.client.data.SequencerConnections; o.getClass.getMethod("fromInternal", classOf[com.digitalasset.canton.sequencing.SequencerConnections]).invoke(o, i).asInstanceOf[com.digitalasset.canton.admin.api.client.data.SequencerConnections] }
   // save: toInt(syncCfg.sequencerConnections).toByteArray(ProtocolVersion.v35)
   // restore: fromInt(SequencerConnections.fromTrustedByteArray(bytes).fold(e => sys.error(e.toString), identity))
   p.keys.secret.generate_signing_key("signing", SigningKeyUsage.ProtocolWithProofOfOwnership ++ SigningKeyUsage.SequencerAuthenticationOnly, Some(SigningKeySpec.EcCurve25519))
   ```

   The same usage set goes into `register_kms_signing_key`. Export the identity snapshot with `protocolVersion = Some("35")`.
b. **`connect_by_config(…, validation = SequencerConnectionValidation.Active)`** takes the admin-data type
   (`com.digitalasset.canton.admin.api.client.data`), not the one in `sequencing`.
c. **Helm 4 uses server-side apply.** An earlier `kubectl patch` of the Deployment (we patched probes) makes `helm upgrade` fail with
   field-manager conflicts. Dry-run with `--dry-run=server`, then upgrade with `--force-conflicts`.
d. **A `kubectl port-forward` bound to a replaced pod dies on the first request.** Run it in a restart loop and retry the console
   command; a dropped forward changes nothing on the node.
e. **`kubectl cp` preserves the laptop uid.** `chown` the jar and certificates to the participant uid (1001), and check that the state
   volume is writable, before the first start.
f. **macOS:** GNU coreutils `rm` can shadow `/bin/rm`, which has `-P`. Use `/bin/rm -P` for shredding. On APFS and SSD that is still
   not provable erasure.
g. **`parties.list(filterParticipant = …)` scans the whole synchronizer** on DevNet and takes minutes. Prefer `ledger_api.parties.list()`
   on the node.
h. **`synchronizer_trust_certificates.list(filterUid = …)` matches the exact UID**, not a prefix.
i. **Removing the old member's OTK needs `force = ForceFlags(ForceFlag.AlienMember)`**; without it the console answers
   `TOPOLOGY_DANGEROUS_COMMAND_REQUIRES_FORCE_ALIEN_MEMBER`. The namespace key signs the removal through FROST.
j. **Wallet API with the validator's M2M token** answers `No wallet found for user …@clients`. Use the wallet UI user. The M2M app
   also needs a client grant for the Validator API audience (a gap on the NAAS side).
k. **The Splice wallet UI Tap amount is in USD**, not CC (10 USD gave +85.667 CC).
l. **Compile every console Scala block against the target Canton console before the cutover.** That pass caught four errors (the usage set
   of a and its two other uses, and the validation type of b) and flagged the ping timeout, all of which would otherwise have surfaced
   inside the outage window. The private `toInternal` of a was hit live, before the compile pass existed.

Timing: the B4 wallet was down about 52 min (validator stopped 16:14:52, party hosted on the new member 17:07:04); the new member
was connected and healthy within about 12 min of its trust certificate (16:30:45, healthy by 16:43). The party was hosted 2 min after the PNR.
A backup job that cannot reach S3 still leaves local dumps, and those hold the old keys: put them on the destruction list.

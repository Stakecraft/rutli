# Rütli roadmap

**Status:** 2026-10-15; audit timing updated 2026-10-27; post-0.4.0 plan added 2026-11-01; milestone and release status updated 2026-11-02; B8 completed 2026-11-12; v0.4.0 tagged 2026-11-14. **Scope:** where Rütli stands, the two ways a Canton/Splice validator ends up on it, and the
path to 1.0. Facts are stated as established only where a rehearsal or a source check backs them; everything else
is marked **unproven**. The detailed Track B record (migration spike, milestones, findings) is
[roadmap-migration.md](roadmap-migration.md).

---

## Two flows

A validator reaches Rütli one of two ways. Which one depends on whether it exists yet.

| | Flow 1: new validator | Flow 2: existing validator |
|---|---|---|
| Starting point | Nothing yet | Keys in the participant database (Canton JCE) |
| Namespace key | Born by DKG in the cluster | **Carried** in (non-rotatable), split offline |
| Signing / encryption keys | Born in the cluster | Client's choice: rotate (default) or carry |
| Has any key ever existed whole? | No | The namespace key: yes, on the old host and its backups |
| Status | Working | 2b proven; 2a rehearsed end to end (B8) |

### Flow 1: new validator on Rütli

Keys are born in the cluster by DKG at node bootstrap: the namespace key and the signing key through FROST, the
encryption key as a cluster-hosted ECIES P-256 key. **No key ever exists whole.** This is the strongest option and the
one we recommend whenever a new node is an option.

- Runbook: [key-ceremony.md](key-ceremony.md).
- **Status: working.** The DevNet soak validator `stakecraft-devnet-rutli-01` runs this way (soak since 2026-10-07,
  see [soak-2026-10-devnet.md](soak-2026-10-devnet.md)).
- Remaining before 1.0: a Splice TestNet validator run of at least 4 weeks.

### Flow 2: existing validator (keys today in the participant DB, JCE)

**Migration protects the future, not the past.** The namespace key existed whole in the participant database, its WAL
and replicas, and every backup. Splitting it removes the single point of failure going forward; it cannot un-expose
the past. Flow 2 is weaker than Flow 1 for exactly that reason, and the runbooks say so up front.

Common to both variants:

- **Namespace key: always carried.** It cannot be rotated and every party ID lives under it. Password export
  (`ExportKeyPair`), then the offline split ceremony into `t`-of-`n` FROST shares
  ([split-ceremony.md](split-ceremony.md), milestone B2), then verify the group key equals the Canton fingerprint,
  then a refresh.
- **Signing and encryption keys: the client's choice.**
  - *Default: rotate the encryption key.* A leaked copy lets an attacker read all future transactions sent to the node
    silently and undetectably. A namespace or signing leak is active: it shows on the ledger.
  - *Rotating the signing key is optional.* It is less powerful than the namespace key we carry anyway, and a fresh DKG
    key has never existed whole.
  - *Keeping the current keys* (carried via B6: split ceremony for signing and sequencer-auth keys, `import-key` for
    ECIES) is acceptable only with confirmed destruction of every old copy, and the client gets an explicit warning.
- **Destruction of every old copy is mandatory in both variants:** database rows, WAL, `pg_dumpall` files, S3 objects
  including all versions, export files and dealer media.

#### 2a: In place (same database, same participant UID)

**Status: rehearsed end to end, targeted for v0.4.0.** Milestone B8 (DevNet) **passed phases 0–4 and the 5.1
verification on 2026-10-26** with the cosigners on `v0.4.0-rc.4`: same UID, all three keys carried with their fingerprints,
wallet down ≈ 20 min, operator and end-user balances unchanged, no re-onboard. With the cosigners on `v0.4.0-rc.6`, **both
keys were rotated on 2026-11-01** (a cluster-hosted ECIES key and a FROST signing key from a DKG) **and the JCE rows were
deleted on 2026-11-12** after 11 clean days; the node restarted and reconnected on its own with no JCE private key left in
its database, and the safety dump and the key exports were destroyed. Still open: the teardown of the scratch
validator. Runbook: [runbook-migration-inplace.md](runbook-migration-inplace.md). Decided 2026-10-15: 2a
ships in v0.4.0, before the audit, so the auditors review it.

*Mechanics.* Independently checked against the Canton 3.6.1 source by two reviewers (Opus and Codex), who agree:

- `crypto.provider` is configuration only; it is not persisted.
- With `provider = kms` the node builds the KMS private store and **ignores** the JCE rows in
  `common_crypto_private_keys`: it neither refuses them nor uses them.
- `RegisterKms*Key` attaches a KMS id to an existing fingerprint if the public key, name and usage match exactly.

*Steps.*

1. While the node still runs on JCE, carry **all active keys** into Rütli with their exact fingerprints: the namespace
   key (and any intermediate namespace keys), the signing and sequencer-auth keys, and **every** active encryption key
   (in-flight views may be encrypted to any of them).
2. Back up. Stop the validator and the participant.
3. Switch to `crypto.provider = kms`, `kms.type = driver`, with the Ed25519 / ECIES defaults. Start with synchronizer
   auto-connect disabled.
4. Register every key by KMS id with the exact name and usage. Assert the fingerprints are unchanged. Then reconnect.
5. Verify.
6. Per the client's choice, rotate signing and encryption keys on the same node (generate the new key through the
   driver, then `owner_to_key_mappings.rotate_key`; `rotate_kms_node_key` does not fit keys that Canton generates in
   Rütli).

   In place, Splice's signing key must be registered with its recorded usage, which is `All` and includes
   namespace: the public-key store compares usage and name exactly. It carries no namespace authority (no delegation
   points at it), but rotating the signing key removes it, so in 2a the signing rotation is recommended.
7. Remove the old JCE rows with SQL while the node is stopped. **Never** `keys.secret.delete`: under KMS it deletes the
   key in the KMS.

*Why carry first.* To publish new keys, the node must authenticate to the sequencer with a key already in its current
owner-to-key mapping (OTK), and it must decrypt in-flight views. It therefore has to come back online with the keys the
network already knows.

*Research alternative ("pre-rotate").* Rotate to Rütli-generated keys **before** the switch, while still on JCE, using
externally added proof-of-ownership signatures on the OTK update, so the old signing and encryption keys never enter
Rütli. **Unverified** and more complex.

*Rollback.* Two boundaries instead of one point of no return. Until the first rotation onto a Rütli-born key (RB1),
switch the provider back to `jce` and restart: the JCE rows are untouched and the network still knows only the old
keys. Between RB1 and the SQL cleanup (RB2), fix forward: a JCE rollback would first need the OTK rotated back to the carried keys while still on KMS (possible, not rehearsed). After
RB2, only a restore from backup. No step removes the participant from the network, unlike 2b's trust-certificate
removal.

*Support caveat.* Digital Asset documents migration to external key storage via a **new** participant. In-place is
technically possible but **not a DA-documented procedure**. It is a support risk for clients under a DA support
contract.

#### 2b: New database, new participant UID (same namespace)

**Status: proven.** B0 (2026-10-09, the soak validator) and B4 (2026-10-14, a scratch JCE validator; the point of no
return was crossed at 17:05:01Z, gates G1 to G7 green; GO and destruction 2026-10-15, teardown 2026-10-16). Runbook:
[migration.md](migration.md); rehearsal plan: [b4-rehearsal.md](b4-rehearsal.md).

The party move uses Splice's migrator (`migrateValidatorParty`, identities dump, `newParticipantIdentifier`). Removing
the old trust certificate is the **point of no return**. The wallet is down for about one hour.

*Limitations* (from the Splice 0.9.0 `ParticipantPartyMigrator`):

- **Migrated:** all same-namespace, single-hosted parties: the validator party and the wallet users. Balances and CNS
  entries are restored from Scan; users must re-onboard in the UI.
- **Not migrated:** external parties (they end up unhosted; recovery is a separate DA procedure), multi-hosted parties
  (they stay on their other participants), parties of other namespaces.
- **Lost:** third-party dApp contracts that are not visible to the DSO (the Scan ACS export is DSO-only).

Today 2b mints fresh signing and encryption keys. With B6 the same client choice as 2a applies.

#### 2a versus 2b

| | 2a: in place | 2b: new participant |
|---|---|---|
| Participant UID | Unchanged | New (same namespace) |
| External parties | Unchanged | Unhosted; separate DA recovery |
| dApp data (non-DSO contracts) | Unchanged | Lost |
| Wallet end-users | Unchanged | Must re-onboard in the UI |
| Point of no return | None; two rollback boundaries (first rotation, SQL cleanup) | Removal of the old trust certificate |
| Downtime | Wallet about 20 min (B8) | Wallet about 1 h |
| DA documentation status | Not a DA-documented procedure | The documented shape (new participant) |
| Maturity | Rehearsed once end to end (B8), including rotation and SQL cleanup | Proven twice (B0, B4) |
| Choose when | Nodes with external parties, dApps or many users | Simple validators, or clients who want the DA-documented shape |

### Keys across flows

| Key | Flow 1 | 2a (in place) | 2b (new participant) |
|---|---|---|---|
| Namespace | Born-DKG | Carried-split | Carried-split |
| Signing (incl. sequencer-auth) | Born-DKG | Rotated-DKG (optional) or carried-split (B6) | Rotated-DKG today; carried-split with B6 |
| Encryption | Born hosted (ECIES P-256) | Rotated-hosted (default) or carried-hosted (`import-key`, B6) | Rotated-hosted today; carried-hosted with B6 |

*Born-DKG*: the key never existed whole. *Carried-split*: a whole key was split offline into FROST shares.
*Rotated-DKG* / *rotated-hosted*: a fresh key replaced the old one. *Carried-hosted*: the old encryption key was
imported into the cluster.

**The encryption key is cluster-hosted in every flow:** it is replicated whole on each node, not threshold-shared. The
namespace and signing keys are threshold keys; the encryption key is not.

---

## Milestones (status as of 2026-11-13)

| # | Milestone | Status |
|---|---|---|
| B0 | Cutover spike on the soak validator | Done: **GO** 2026-10-09 |
| B1 | Canton key parser | Done |
| B2 | Split ceremony ([split-ceremony.md](split-ceremony.md)) | Done; Codex adversarial review: nothing above low |
| B3 | RSA import | Dropped (not needed) |
| B4 | Cutover rehearsal on a scratch JCE validator | Done: cutover and verification 2026-10-14, GO and destruction 2026-10-15, teardown 2026-10-16 |
| B5 | Docs fix (stale "unsupported" claims, exposure caveat) | Done |
| B6 | Optional carry of signing and ECIES keys | Done: PR #23, merged 2026-10-15 (Opus and Codex reviews addressed) |
| B7 | 2b rehearsal with wallet end-users: verify re-onboarding keeps their parties and balances | New, proposed |
| B8 | In-place rehearsal (2a), carry-first sequence, on a fresh scratch JCE validator on DevNet | Phases 0–4 + 5.1 **passed 2026-10-26**; rotation **passed 2026-11-01** (cosigners on `v0.4.0-rc.6`); observation, SQL cleanup and destruction **passed 2026-11-12**. Open: teardown. Runbook [runbook-migration-inplace.md](runbook-migration-inplace.md) |
| C1 to C3 | ECIES hosted keys | Done; shipped in v0.4.0-rc.1. The two availability fixes from Codex's review are merged |
| CA rotation | Pin plus runbook | Done; shipped in v0.4.0-rc.2 |

Track A (soak and hardening) continues on `stakecraft-devnet-rutli-01`; exit criteria are in
[testnet-soak.md](testnet-soak.md).

---

## Releases and path to 1.0

| When | What |
|---|---|
| 2026-10-09 | v0.4.0-rc.1 tagged |
| 2026-10-28 | v0.4.0-rc.6: ceremony leader binding and durable fence marks, disjoint FROST and hosted key ids, TLS crate advisories closed; ceremony intents required by default with TLS |
| 2026-11-14 | **v0.4.0 tagged = audit code freeze:** Flow 1, Flow 2a (after B8), Flow 2b, B2, B6, ECIES, C2 fixes, CA rotation |
| Later | Pre-rotate alternative for 2a (research), if B8 shows it is worth it |
| Day v0.4.0 is tagged | Splice TestNet validator run starts; at least 4 weeks clean before 1.0 |
| After the audit | **1.0**: the audit's fixes and retest, at least 4 clean weeks on TestNet, and the 1.0 features below |

- **The audit is the critical path.** Auditor: **Cure53** (chosen 2026-10-27). The RFQ
  ([audit-rfq.md](audit-rfq.md), brief [audit-prep.md](audit-prep.md)) covers ECIES and B6, excludes `HsmBackend`, and
  replaces live access with an evidence pack. The audit starts once its funding is confirmed, expected December 2026
  to January 2027, so 1.0 follows in the first quarter of 2027 rather than in December.
- **External deadline:** Splice's `splice-postgres` chart is unsupported after 2026-11-12 (PostgreSQL 14 end of life).
  As of 2026-11-13 the soak validator still runs on that chart; its move to another PostgreSQL deployment is planned
  for after the freeze.

## After v0.4.0: v0.5.0, 1.0 and 2.0

Planned 2026-11-01, partly informed by a review of the commercial alternatives (Blockdaemon Builder
Vault's Canton KMS driver, cloud KMS). ECIES hosted keys, once planned as v0.5.0 (Track C), shipped in
v0.4.0.

| Release | Item | What and why |
|---|---|---|
| **Now** (docs) | Supported keys and algorithms, Canton compatibility matrix | In the README: which key is threshold, which is hosted, which Canton and Splice versions are tested. Done (#77) |
| **v0.5.0** | Unified admin CLI | One tool for generate, import, public key and Canton fingerprint (`1220…`), and a documented rotation recipe (`rotate_kms_node_key`, `owner_to_key_mappings.rotate_key`). Today these are spread across `rutli-cosigner` and `rutli-dealer` |
| **v0.5.0** | Shared-cluster guard | A DKG that returns an existing key says so, and the driver refuses a key it did not create unless the operator allows it. Today two participants with the same `frost.key-prefix` end up on the same Ed25519 keys without an error; only a `signer_acl` per driver certificate prevents it ([architecture.md](architecture.md), "One cluster, several participants") |
| **v0.5.0** | Canton LocalNet quickstart | Rütli next to Splice's LocalNet, all in local containers, so an operator can try it in minutes without touching a real node |
| **1.0** | Driver published to a Maven repository | Operators consume the driver as a normal dependency instead of a jar from a GitHub release |
| **1.0** | Signed audit log, exported off the host | The hash chain is periodically signed and shipped to append-only storage (for example S3 Object Lock or syslog), so a host administrator can no longer rewrite it unnoticed |
| **1.0** | Encryption-key rotation, ready for threshold ECIES | A runbook for rotating the participant's encryption key (planned or after an incident), and a driver that can serve an old hosted ECIES key and a new one side by side during the rotation, with versioned key ids so the two kinds cannot be confused. This is what makes the 2.0 migration below a routine rotation |
| **1.0** | Emergency recovery | A designed answer to "every cosigner is lost at once": shares encrypted to offline keys held by several recovery officers. It is a path to the whole key, so the design (who, how many, which ceremony) comes before the code |
| **2.0** | Threshold ECIES | The encryption key held as shares too: each cosigner computes its part of the ECDH and the driver combines them. Needs a P-256 DKG and proofs that each partial result is correct. Closes the residual "one compromised cosigner reads the hosted keys" for ECIES. **Migration:** existing nodes rotate their encryption key to a new threshold key born by DKG, with the 1.0 runbook, without downtime and without changing the node's identity. Traffic encrypted to the old key keeps the protection it had. RSA keys rotate to threshold ECIES the same way. An optional split of the existing ECIES key into shares (same public key) is possible but weaker, because the key once existed whole |
| **2.0** | Confidential computing | Cosigners in AWS Nitro Enclaves, AMD SEV-SNP or Intel TDX, so even root on the host or a memory snapshot does not reveal a share (today a documented residual, audit L7) |

**Consequence for the audit.** Threshold ECIES moved to 2.0 (decided 2026-11-02) so that the Cure53
engagement on v0.4.0 stays as scoped. The other 1.0 features are new security-critical code after the
freeze: emergency recovery, the signed audit export, and the encryption-key rotation with its mixed-mode
driver. **Decided 2026-11-02: Cure53 reviews them too**, as a second phase of the same engagement once
they are code-complete and before 1.0 is tagged. The RFQ asks for that phase as a separate line item
([audit-rfq.md](audit-rfq.md), section 2.2).

## Open decisions

- The audit's start date, which waits for funding; it sets the 1.0 date.
- Whether the pre-rotate alternative is worth pursuing after B8, or the carry-first path is enough.

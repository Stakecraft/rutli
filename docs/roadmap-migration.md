# Roadmap: migrating existing Canton nodes into Rütli

> This is the detailed Track B record; the current roadmap is [roadmap.md](roadmap.md).

**Status:** draft, 2026-10-08. **Owner:** Alex, with Claude as orchestrator; one engineer, sequential. **Goal:** show that a Splice validator that exists
today, with its keys in Postgres, can move its identity into a Rütli cluster without changing its
namespace or any party ID.

## What we learned (2026-10-08)

- Canton 3.5+ documents migrating an existing participant to a KMS by exporting keys and starting
  a new participant under the same identity. Our docs still say the opposite
  (`architecture.md:241`, `phase-2-frost.md:109`, `key-ceremony.md:53`). They are stale.
- A real JCE validator (Splice 0.9.0 / Canton 3.6.1) holds three keys: namespace Ed25519,
  signing Ed25519 (protocol + sequencer-auth), encryption **ECIES P-256**. All three sit in
  `common_crypto_private_keys` unencrypted, and in every `pg_dumpall` backup.
- Canton 3.6.1 admin API has `ExportKeyPair`, `RegisterKmsSigningKey(kms_key_id, usage)` and
  `RegisterKmsEncryptionKey(kms_key_id)`. The KMS driver SPI admits `EcP256` +
  `EciesHkdfHmacSha256Aes128Cbc`.
- The Global Synchronizer admits `EcP256`: Splice SVs use Canton's JCE defaults for static
  parameters on every network, and DevNet/TestNet validators run ECIES keys today.
- **Migration keeps the namespace, not the participant ID.** A participant UID that was ever
  onboarded cannot onboard again on the same synchronizer (`GrpcSequencerConnectService.scala:251-267`),
  and a fresh database under an already-known UID replays history from registration, so an ACS
  import on top double-creates contracts. DA's own `KmsMigrationIntegrationTest` uses a new
  participant; Splice says participant ids cannot be reused. The working shape is: **new participant
  UID under the same namespace, then move the parties** (Splice `newParticipantIdentifier` +
  `migrateValidatorParty`). Party IDs survive because they live under the namespace. Found
  2026-10-08 while writing the B0 runbook; deep-reasoner and Codex agree independently.
- `RegisterKmsSigningKey` only fetches the public key through the driver and checks its spec; there
  is no namespace or existing-identity check (`KmsPrivateCrypto.scala:78-104`).
- Rütli today: Ed25519 keys are born by DKG only. No import of an existing key as shares, no
  ECIES hosted keys. Those are the gaps.

## Tracks

### Track A: soak and hardening (running)
Unchanged. DevNet soak on `stakecraft-devnet-rutli-01`, histogram PR #6, v0.3.x patches as the
soak finds things. Exit criteria in `docs/testnet-soak.md`.

### Track B: migration of existing nodes (new)

| # | Milestone | Scope | Est. | Gate / deliverable |
|---|---|---|---|---|
| B0 | **Cutover spike** | On the soak validator `stakecraft-devnet-rutli-01`, whose keys already live in the cluster: new participant on a fresh database under a **new UID in the same namespace**, the three existing keys registered by KMS id (`RegisterKms*Key`, no key export, no new code), then the validator app re-onboards with an identities dump, `newParticipantIdentifier` and `migrateValidatorParty`, which moves the validator party and its contracts. This is the Canton and Splice half of a migration. Manual `pg_dumpall` first. Runbook: [b0-cutover-spike.md](b0-cutover-spike.md). Logged in the soak log as a planned cutover drill. | 2–3 d | **DONE 2026-10-09: GO** (soak log). **Go/no-go for the whole track.** If Canton or Splice refuses, stop and write up why. Rollback (point the releases back at the untouched old databases) only works **before** the migrator removes the old participant's trust certificate; after that, fix forward only. |
| B1 | **Canton key parser** | `canton_key.rs`: parse `SigningPrivateKey` / `EncryptionPrivateKey` protobuf (DER / RAW), PKCS#8 PEM, `ExportKeyPair` output incl. password-protected. Shared by B2, B3, C1. | 1–1.5 d | Unit tests against keys exported from a 3.6.1 node. |
| B2 | **Split ceremony** — done, runbook [split-ceremony.md](split-ceremony.md) | Offline dealer `rutli-dealer split-key` turns an Ed25519 key into t-of-n FROST shares (`frost_ed25519::keys::split`, seed→scalar via ed25519-dalek), verifies group key == Canton key, seals each share to a one-time X25519 recipient key the node minted (`share-recipient`; the hosted-key envelope construction, not the static DistKey), but only after verifying each request is signed by that node's mTLS certificate (`--ca-cert`) and confirming its SAS (Gate 0). Per node: `import-share` (no-clobber create, recipient secret deleted). `verify-key --sign-test` with an operator-role cert (new `KeyStatus` and `CeremonySignTest` RPCs; every t-subset signs) + immediate `Refresh`. DKG refuses `frost-import-` ids. Runbook incl. destruction of the whole key. Driver unchanged. | 8–12 d | Signatures verify under the original Canton public key. DKG refused for an imported id. Refresh keeps the group key. All three pinned by `frost/cosigner/tests/split_ceremony.rs` and `scripts/e2e-split-ceremony.sh`. |
| B3 | ~~**RSA import**~~ **dropped** | ~~`import-key` accepts a Canton RSA-2048 export.~~ Not needed: the encryption key need not be carried. The new participant gets a fresh hosted key, and C already imports a Canton ECIES export if anyone wants to keep theirs. | — | — |
| B4 | **Cutover rehearsal**: plan [b4-rehearsal.md](b4-rehearsal.md), pilot runbook draft [migration.md](migration.md) | A scratch JCE validator on DevNet (`stakecraft-devnet-rutli-b4`, NAAS `deploy.sh --skip-kms`) is the source. The target is the soak cluster on `v0.4.0-rc.1` (`perNode` TLS, operator role), with `frost.key-prefix = "b4-"`. Only the namespace key is carried: password export, then the B2 split ceremony (`b4-frost-import-<fp8>`). The new participant on a fresh DB gets fresh keys (FROST DKG signing, hosted **ECIES** encryption; no RSA rotation, B3 dropped), registers the imported key by id, and initialises a new UID in the same namespace. Then the Splice re-onboard with a **key-free** dump + `migrateValidatorParty` (the B0 shape). Afterwards: destruction of every old copy with evidence, and teardown. | 2.5–3 d (≈ 5 calendar days) | **Cutover DONE 2026-10-14, GO pending** (soak log: [soak-2026-10-devnet.md](soak-2026-10-devnet.md), "Planned event: B4 cutover rehearsal"): verification G1–G7 green (party IDs unchanged, ACS 5 → 6 with 0 commitment mismatches, tap and transfers in and out, ECIES decrypting live, soak participant unaffected). Destruction of every old copy (not before 2026-10-15 17:11Z, after two green soak-checks) and teardown are pending; the runbook fixes are in [migration.md](migration.md). Gate: party IDs unchanged, wallet works, tap and a transfer in and out succeed, ECIES decrypts live, soak participant unaffected, destruction record complete. |
| B5 | **Docs fix** | Remove the three stale "unsupported" claims; state the exposure caveat: an imported namespace key once lived whole on a server and in backups, it is not "as strong as DKG". | 0.5 d | Can ship any time, do it first. |
| B6 | **Optional: carry the protocol signing and encryption keys (discouraged)** — done (branch `feat/b6-carry-protocol-keys`), runbook [migration.md](migration.md) §8 | `rutli-dealer split-key --expect-usage namespace\|protocol` replaces `--any-usage`: namespace mode takes usage {namespace} alone, protocol mode needs signing or sequencer-auth, and `--namespace-fingerprint` (from the old node's UID) settles every ambiguous namespace-mode case, a Splice `signing` key (`SigningKeyUsage.All`, namespace included) above all, and is mandatory in protocol mode (the recorded usage is unsigned metadata). Protocol keys live under `<prefix>frost-import-sig-…` / `…-seqauth-…`, so approval rules can tell them from the namespace key — but a rule on the bare `<prefix>frost-import-` prefix matches all three (migration.md §8: `auto` rules for the protocol ids first, or name the namespace id exactly); each mode refuses the other's ids. The usage and the `--namespace-fingerprint` acknowledgement travel in the share bundle under its AAD (envelope v3); `import-share` re-applies every dealer rule to them against the bundle's own fingerprint and refuses pre-B6 (v2) bundles; kept in the share's provenance and shown by `verify-key`. A runbook gate checks that no namespace delegation targets a carried key (the acknowledgement rules out the root only). `verify-hosted` (new operator-role `HostedKeyStatus` RPC, no read-repair, each node reports the public key its private key derives) checks an imported encryption key is on every node with one SPKI and the expected fingerprint; it is the nodes' self-report. `import-key` is safe next to a running daemon (create race handled). | 2 d | `frost/cosigner/tests/dealer_cli.rs` (Canton's two protocol keys, a synthetic All-usage key, a legacy empty-usage key, PKCS#8, every mismatch refused), `carry.rs`, `ecies_hosted.rs`. `scripts/e2e-carry-protocol-keys.sh` on Canton 3.6.1: both protocol keys and the ECIES key carried, registered with the old fingerprints, OTK rotated onto them, pings, sequencer authentication with the carried key — **passed 2026-10-15**. |

**Release: v0.4.0 "migrate existing nodes"** after B4. Total B0–B5: **15–22 engineer-days**.

### Track C: ECIES hosted keys (v1.5 from the design record)

| # | Milestone | Scope | Est. |
|---|---|---|---|
| C1 | **Done** (branch `feat/c-ecies-hosted-keys`, on B2). `HostedSpec::EcP256` (`ec-p256-ecies`), keygen, SPKI byte-identical to Canton's, `EcdhDerive` RPC on the cosigner via aws-lc-rs (65-byte uncompressed points only, on-curve by aws-lc), under the decrypt rate limit; `import-key` also reads a Canton EC P-256 encryption key export (B1) and refuses unless the served SPKI is Canton's | 3–4 d |
| C2 | **Done.** Driver: advertise `EcP256`/ECIES from Capabilities, spec-driven keygen and public key, parse `iv ‖ V ‖ ct ‖ mac`, DEM via BouncyCastle `IESEngine` with a stub agreement that returns Z from the cluster. BouncyCastle aligned to Canton's 1.85 | 3–4 d |
| C3 | **Done**, with one substitution. Invalid-point tests are hand-built (no Wycheproof vectors offline; see below); upstream `KmsDriverTest` passes over the frost backend with ECIES advertised (`CONFORMANCE=1`); `scripts/e2e-ecies-hosted.sh` boots 3.6.1 with a generated and then an imported ECIES key and Canton decrypts through the driver | 2–3 d |

What C turned up, for the record:
- **Wycheproof:** no ECDH secp256r1 vectors were available offline. The invalid-point tests are hand-built
  from an independent Python P-256 (off-curve, (0,0), y = 0, x ≥ p, a point on y² = x³ − 3x,
  compressed, hybrid, wrong lengths), plus a known-answer `Z` shared by the Rust and JVM tests. Adding
  `ecdh_secp256r1_ecpoint_test.json` later is cheap.
- **aws-lc accepts compressed and hybrid points** in `agreement::agree`; the cosigner refuses them
  before aws-lc sees them (test `the_uncompressed_only_gate_is_load_bearing`).
- **Canton's ECIES does not authenticate the IV.** The HMAC covers the CBC ciphertext only, so a flipped
  IV bit flips the first plaintext block, and Canton's own decryptor accepts it. The driver matches
  Canton byte for byte (pinned by a test) rather than diverge; worth an upstream note.
- A Canton session key encrypted with ECIES is 145 bytes (16 + 65 + 32 + 32); Canton caches session
  keys, so a ping round trip costs one or two `EcdhDerive` calls, not one per view.
- Canton 3.6.1 runs on BouncyCastle 1.85 and its launcher puts its own jar first, so the driver's
  bundled BouncyCastle never mattered at runtime; the driver build now uses 1.85 too.
- The upstream conformance suite deletes every key it generates and the driver refuses to delete a
  FROST key, so the frost-backend run uses predefined keys.
- Adversarial review (no critical/high): fixed a mixed-version hazard (an older cosigner answers
  for an EC key as if it did not exist) with a cosigner-side refusal to create EC keys unless every
  peer reports the spec, and a driver that advertises ECIES only when every cosigner does; plus
  Capabilities retry/re-query, stricter import key ids, zeroized `Z`, ECIES failures in the audit
  entry, an exact P-256 SPKI check. Its randomised differential (3000 keys × 4 mutations, 0
  mismatches) is in the driver suite at a smaller default size. Follow-up decision (2026-10-09):
  restart availability wins — ECIES is gated on the cosigners that answer (an old one vetoes, a
  silent one does not, a majority must answer), and EC operations fail over past a node that says it
  lacks the key (`hosted-keys.md` §2).

**Release: v0.5.0.** Total **8–11 d** on top of Track B (B1 is reused). Value: an existing node
migrates without touching its encryption key, and ECIES is the key type that thresholds later (v2),
RSA never will.

### Track D: audit and 1.0
Audit scope should include B2 (split ceremony) and, if done, C. Recommend scheduling the audit
after v0.4.0 so the migration path is in scope, not bolted on after. Splice TestNet validator run
stays a 1.0 prerequisite.

## Critical path to production

Production means: third-party audit passed, Splice TestNet validator run done, 1.0 tagged. The
engineering work is not the long pole; the audit's external lead time is. So:

1. **Book the audit now** (week 1), for a start right after v0.4.0. Scope: FROST cluster, hosted
   keys, driver, **plus the split ceremony (B2)**, so the migration path is audited, not bolted on.
   Candidates with threshold-signature track record: Least Authority,
   Trail of Bits, NCC Group, Kudelski. Ask for a 2–3 week engagement with a fixed start date.
2. **Track B to v0.4.0** is the pre-audit code freeze target. Nothing else lands in the audited
   surface after it except audit fixes.
3. **Track C (ECIES) runs while the auditors work.** The engineer is otherwise idle in that window.
   It ships as v0.5.0 either inside the audit as an addendum or, if the auditor refuses scope
   creep, as the first post-1.0 release. Decide with the auditor at booking time.
4. **Splice TestNet validator run** is operations, not development. Start it the day v0.4.0 is
   tagged, in parallel with the audit. Minimum four weeks of clean operation before 1.0.
5. **Audit fixes → 1.0.**

## Sequence and timeline (one engineer, sequential)

```
wk 1        B5 docs fix · B0 spike on rutli-01 (gate) · book the audit
wk 4        onboard scratch JCE validator on DevNet for B4
wk 2–4      B1 parser · B2 split ceremony · (B3 dropped)
wk 5        B4 rehearsal → v0.4.0 (audit code freeze) · start TestNet validator run
wk 6–8      audit in progress · C1–C3 → v0.5.0
wk 9–10     audit findings · fixes · TestNet run reaches 4 weeks
wk 11       1.0
```

Calendar, if started 2026-10-13: v0.4.0 around **2026-11-14**, v0.5.0 around **2026-12-05**,
**1.0 around 2026-12-19** if an auditor can start 2026-11-17. If the earliest audit slot is later,
1.0 moves with it and nothing we do in engineering pulls it back. That is why booking is week 1.

Soak (Track A) continues in the background and may preempt a day here and there.

## Technical notes from scoping (keep; verified 2026-10-08 unless marked)

**Canton 3.6.1 facts, from source (`~/.cache/canton-src`) and a live node**
- Private key rows: `common_crypto_private_keys.data` is protobuf `SigningPrivateKey` /
  `EncryptionPrivateKey` (`crypto.proto`: `id`, `format`, `private_key`, `usage`, `key_spec`)
  **inside an `UntypedVersionedMessage` (version 30)**, `wrapper_key_id` NULL = plaintext. Public
  keys are DER SPKI. *Corrected by B1:* `format` is **DER_PKCS8 = 5** for every key 3.6.1 writes;
  DER=2 / RAW=3 are legacy labels Canton migrates on load. Ed25519 is a minimal PKCS#8 v1 around
  the 32-byte RFC 8032 **seed**; P-256 is PKCS#8 around SEC1 (with embedded public point); RSA is
  PKCS#8 CRT, e = 65537. Parser: `frost/canton-key` (docs cite file:line).
- Fingerprint = `Hash(purpose PublicKeyFingerprint=12, raw public key)`, hex-prefixed `1220`
  (`Signing.scala:1537`). The topology `namespace` column carries the `1220` prefix.
- ECIES wire format (`JcePureCrypto.scala:146-165, 521-565, 695-750`):
  `iv(16) ‖ V(65, uncompressed 0x04) ‖ AES-128-CBC ct ‖ HMAC-SHA256 tag(32)`. Parameters
  `ECIESwithSHA256andAES-CBC`, macKey 512 bit, cipherKey 128 bit, empty derivation/encoding
  vectors. KDF is BouncyCastle KDF2-SHA256 over `V‖Z`, not HKDF despite the name; the MAC adds an
  8-byte length tag. Canton caps the ciphertext at 256 bytes (`ByteString256`). JCE allows only
  the CBC variant in 3.6.1, no GCM (`CryptoProvider.scala:81-95`).
- Driver SPI decrypt is `decryptAsymmetric(ciphertext, keyId, algoSpec)`: the driver receives the
  whole blob and must parse it.
- `RegisterKmsSigningKey(kms_key_id, usage)` → driver `getPublicSigningKey(id)`; for a FROST id
  this already returns the group key, so B2 needs no driver change. The id must include the
  participant's `frost.key-prefix` if one is set.
- Splice SV static synchronizer parameters are Canton JCE defaults on every network
  (`apps/sv/.../LocalSynchronizerNode.scala:94`), so `EcP256` and `Rsa2048` are both admitted.
- `ExportKeyPair(fingerprint, protocol_version, password)` exists and needs
  `features.enable-preview-commands`. Output: versioned `CryptoKeyPair` holding only the private
  key (Canton re-derives the public key). *Verified in B1 against source and a real 3.6.1 export:*
  the password form is a versioned `PasswordBasedEncrypted` = Argon2id (m = 12288 KiB, t = 3,
  p = 1, v0x13, 16-byte salt, UTF-8 password) → AES-128-GCM, `iv(12) ‖ ct ‖ tag(16)`, no AAD,
  over the plain export bytes.
- Fingerprint input differs by key type: Ed25519 hashes the **raw 32-byte** public key, P-256 and
  RSA hash the SPKI DER (`Signing.scala:1531-1543`).
- A default-config 3.6.1 participant creates **four** keys at auto-init: namespace, `signing`
  (protocol) and `sequencer-auth` (both Ed25519, separate keys), and ECIES P-256 encryption.

**Rütli facts**
- `frost/core/src/lib.rs` states "no shard-existing-key path, by design": B2 reverses that and
  the doc comment must change. `dkg_part1` refuses if the key exists on any node, which fences a
  racing DKG during an import.
- `frost-ed25519 2.2.0` exposes `keys::split(&SigningKey, max, min, IdentifierList, rng)`.
  **Trap:** `SigningKey::deserialize` takes a scalar; Canton exports an RFC 8032 seed. Convert
  with SHA-512, clamp, reduce mod ℓ. Assert the group verifying key equals the Canton raw public
  key before writing anything.
- Hosted-key replication already wraps per recipient (`wrap.rs`, ephemeral X25519 → HKDF →
  AES-GCM, AAD-bound); reuse it to deliver dealer shares with spec `frost-ed25519-share`.
- Driver hardcodes today: `generateEncryptionKeyPair` always RSA, `getPublicKey` maps the reply
  spec as `Rsa2048`. Both must become spec-driven for C.
- Upstream `KmsDriverTest` encrypts with `JcePureCrypto` and calls `decryptAsymmetric` for every
  advertised algorithm, so advertising ECIES gives a JVM→driver differential test for free.
- Validator on DevNet keeps 8 plaintext `pg_dumpall` copies on PVC plus AES-256-CBC copies in S3
  `canton-k8s-validators-backup`. After a migration, every one of them still holds the whole
  namespace key: purge, and say so in the runbook.

**Reports behind the estimates:** deep-reasoner (read Canton source; A 7–11 d, B 7–10 d, spike
2–3 d) and Codex (A 19–31 d, B 16–28 d, blind to Canton source). The table above takes the
former's decomposition with part of the latter's buffer.

## Risks, by severity

1. **B0 fails.** The Canton-side risk (refusing a KMS key registered by id for an existing
   namespace) is retired at code level. What remains is Splice: the 0.9.0 migrator and chart are
   unverified (scoping read 0.5.5), the point of no return is early and permanent, the party is
   hosted nowhere for a short window, the Scan-sourced import covers only contracts shared with the
   DSO, and the new member starts with no purchased traffic. Mitigation: B0 is first, on the soak.
2. **Seed→scalar in B2.** `SigningKey::deserialize` takes a scalar, Canton exports a seed. Tests
   catch it; a wrong conversion signs under a different key, loudly.
3. **ECIES byte-exactness in C2.** Avoided by reusing BouncyCastle's own engine rather than
   reimplementing KDF2 and the length-tag quirk. *Retired:* Canton's `JcePureCrypto` → driver passes
   in the upstream conformance suite and on a live 3.6.1 participant.
4. **Exposure caveat is a sales risk.** Say it up front: migration protects the future and against
   loss; it cannot un-expose the past. Fresh nodes with DKG keys remain the recommended path.

## Pilot

The conference lead who asked about migration is the natural first external pilot, on DevNet,
after B4. Offer: we migrate a scratch validator of theirs alongside ours, same runbook.

## Open decisions

- Auditor choice and earliest start date. Sets the 1.0 date.
- B0 runs on the soak validator in the new-UID shape ("B0-B", decided 2026-10-08; the same-UID replay variant was dropped). B4 needs a scratch JCE validator on
  DevNet; `validator-stakecraft-validator-1` stays untouched.

# Roadmap: migrating existing Canton nodes into Rütli

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
- Rütli today: Ed25519 keys are born by DKG only. No import of an existing key as shares, no
  ECIES hosted keys. Those are the gaps.

## Tracks

### Track A: soak and hardening (running)
Unchanged. DevNet soak on `stakecraft-devnet-rutli-01`, histogram PR #6, v0.3.x patches as the
soak finds things. Exit criteria in `docs/testnet-soak.md`.

### Track B: migration of existing nodes (new)

| # | Milestone | Scope | Est. | Gate / deliverable |
|---|---|---|---|---|
| B0 | **Cutover spike** | Scratch JCE validator on DevNet. Export keys, bring up a new participant with `provider = kms` + Rütli driver, `init.identity.type = manual`, `RegisterKms*Key` for a DKG-born key under the same identifier. Prove the node starts, connects, signs topology. No new code: use a DKG-born namespace just to test the Canton path. | 2–3 d | **Go/no-go for the whole track.** If Canton refuses, stop and write up why. |
| B1 | **Canton key parser** | `canton_key.rs`: parse `SigningPrivateKey` / `EncryptionPrivateKey` protobuf (DER / RAW), PKCS#8 PEM, `ExportKeyPair` output incl. password-protected. Shared by B2, B3, C1. | 1–1.5 d | Unit tests against keys exported from a 3.6.1 node. |
| B2 | **Split ceremony** | Offline dealer: `split-key` turns an Ed25519 key into 2-of-3 FROST shares (`frost_ed25519::keys::split`, seed→scalar), verifies group key == Canton fingerprint, wraps each share to its cosigner with the existing per-recipient sealing. Per node: `import-share` under the create-once guard. `verify-key` + immediate `Refresh`. Runbook incl. destruction of the whole key. Driver unchanged. | 8–12 d | Signatures verify under the original Canton public key. DKG refused for an imported id. Refresh keeps the group key. |
| B3 | **RSA import** | `import-key` accepts a Canton RSA-2048 export (via B1), not only Rütli's own envelope. Lets the encryption key be rotated to RSA on the old JCE node *before* cutover, per Digital Asset's procedure, then carried over. | 1–2 d | Import → replicate 3/3 → Canton decrypts. |
| B4 | **Cutover rehearsal** | Full procedure on the scratch DevNet validator: rotate encryption to RSA on the old node, export, split, install, new participant, `RegisterKms*Key`, `export_acs`/`import_acs`, validator-app switch, old key cleanup. Written as `docs/migration.md`. | 2–3 d | Party IDs unchanged, wallet works, transfer in and out succeeds. |
| B5 | **Docs fix** | Remove the three stale "unsupported" claims; state the exposure caveat: an imported namespace key once lived whole on a server and in backups, it is not "as strong as DKG". | 0.5 d | Can ship any time, do it first. |

**Release: v0.4.0 "migrate existing nodes"** after B4. Total B0–B5: **15–22 engineer-days**.

### Track C: ECIES hosted keys (v1.5 from the design record)

| # | Milestone | Scope | Est. |
|---|---|---|---|
| C1 | `HostedSpec::EcP256`, keygen, SPKI, `EcdhDerive` RPC on the cosigner via aws-lc-rs, under the decrypt rate limit | 3–4 d |
| C2 | Driver: advertise `EcP256`/ECIES from Capabilities, parse `iv ‖ V ‖ ct ‖ mac`, DEM via BouncyCastle `IESEngine` with a stub agreement that returns Z from the cluster | 3–4 d |
| C3 | Tests: Wycheproof invalid-point vectors, upstream `KmsDriverTest` differential, e2e on 3.6.1 with an imported ECIES key | 2–3 d |

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
   Candidates with threshold-signature track record: Least Authority (audited ZF FROST),
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
wk 1        B5 docs fix · B0 spike (gate) · book the audit · onboard scratch DevNet validator
wk 2–4      B1 parser · B2 split ceremony · B3 RSA import
wk 5        B4 rehearsal → v0.4.0 (audit code freeze) · start TestNet validator run
wk 6–8      audit in progress · C1–C3 → v0.5.0
wk 9–10     audit findings · fixes · TestNet run reaches 4 weeks
wk 11       1.0
```

Calendar, if started 2026-10-13: v0.4.0 around **2026-11-14**, v0.5.0 around **2026-12-05**,
**1.0 around 2026-12-19** if an auditor can start 2026-11-17. If the earliest audit slot is later,
1.0 moves with it and nothing we do in engineering pulls it back. That is why booking is week 1.

Soak (Track A) continues in the background and may preempt a day here and there.

## Risks, by severity

1. **B0 fails.** Canton 3.6.1 may not accept a driver-KMS key registered by id for an existing
   namespace. DA documents the path for AWS/GCP only. Mitigation: it is the first thing we do.
2. **Seed→scalar in B2.** `SigningKey::deserialize` takes a scalar, Canton exports a seed. Tests
   catch it; a wrong conversion signs under a different key, loudly.
3. **ECIES byte-exactness in C2.** Avoided by reusing BouncyCastle's own engine rather than
   reimplementing KDF2 and the length-tag quirk.
4. **Exposure caveat is a sales risk.** Say it up front: migration protects the future and against
   loss; it cannot un-expose the past. Fresh nodes with DKG keys remain the recommended path.

## Pilot

The conference lead who asked about migration is the natural first external pilot, on DevNet,
after B4. Offer: we migrate a scratch validator of theirs alongside ours, same runbook.

## Open decisions

- Auditor choice and earliest start date. Sets the 1.0 date.
- Scratch DevNet validator for B0/B4: onboard a fresh one (recommended) rather than touching
  `validator-stakecraft-validator-1`.

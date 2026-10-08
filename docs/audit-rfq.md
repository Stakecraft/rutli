# Request for Quote: security audit of Rütli

> **Template note (delete before sending).** This is one generic RFQ, sent unchanged to Least
> Authority, Trail of Bits, NCC Group and Kudelski Security. Fill the `<PLACEHOLDERS>` and resolve
> every `TODO(verify)` before it goes out. Drafted 2026-10-08 from the repo state at v0.3.1 plus
> `docs/roadmap-migration.md`; line counts below were measured on that tree and must be re-measured
> at code freeze. Companion brief for the auditors: [audit-prep.md](audit-prep.md).

**From:** Stakecraft, maintainers of Rütli. **Contact:** `<NAME>, <EMAIL>`
**Reply requested by:** `<REPLY_BY_DATE>`. **Desired start:** 2026-11-17 (fixed date).

## 1. Project summary

Rütli is an open-source (Apache-2.0), self-hosted threshold key management system for Canton Network
and Splice node authority keys. It plugs into an unmodified Canton node through the public KMS Driver
SPI (a JVM jar loaded by the node, no Canton fork), and forwards each private-key operation to a
cluster of Rust cosigners. The Ed25519 namespace (identity) key is held as FROST-ed25519 shares
(2-of-3 by default), one per cosigner, and Canton receives a standard RFC 8032 signature. Canton's
encryption and symmetric keys can also live in the cluster as replicated, sealed whole keys (not
threshold).

The stakes are high. A Canton namespace key defines a node's on-chain identity and authorizes every
topology change. It cannot be rotated: if it leaks, an attacker controls the node, and if it is lost,
every party and Canton Coin balance hosted under that namespace is gone permanently. The project is
pre-production and has not been audited; its own docs say no production authority key should sit
behind it until an external review completes.

## 2. Scope (in)

Repository state to review: tag `v0.4.0`, target ~2026-11-14, which is also our code freeze. Nothing
else lands in the audited surface after it except audit fixes.

| # | Component | Includes | Where |
|---|---|---|---|
| a | **FROST-ed25519 cosigner cluster** | DKG; t-of-n signing (two rounds); crash-safe nonce guard; proactive refresh; share repair; share sealing at rest (AES-256-GCM, per-node keys derived from an operator secret); mutual TLS and the `signer_allowlist` / `peer_allowlist` role split; per-key ceremony guards and cluster-wide signing fence; create-once guard | `frost/core`, `frost/cosigner` |
| b | **Cluster-hosted keys** | Replicated whole keys (RSA-2048-OAEP via `aws-lc-rs`, AES-256-GCM); per-recipient wrapping (ephemeral X25519, HKDF-SHA256, AES-256-GCM, AAD-bound); write quorum, anti-entropy, read-repair; offline passphrase-encrypted export/import; per-key decrypt rate limit | `frost/cosigner` (`hosted`, `wrap`, `export`, `ratelimit`, `peer`) |
| c | **JVM KMS driver** | Key-id routing (`frost-` / `rutli-` prefixes, `frost.key-prefix`); `FrostBackend` gRPC client with failover rules; M-of-N approval gate and policy; hash-chained audit log; signing journal; Canton 34-byte digest handling | `driver/src/main` |
| d | **Split ceremony (milestone B2)** | Frozen with v0.4.0. Offline dealer binary `rutli-dealer` splits an existing Canton Ed25519 namespace key into t-of-n FROST shares via `frost_ed25519::keys::split`, using RFC 8032 seed-to-scalar conversion (ed25519-dalek's SHA-512, clamp, reduce mod l); before writing anything it proves group key == Canton key, VSS, `min_signers`, every t-subset reconstructs and signs (`verify_strict`). Each share is sealed to a one-time per-ceremony X25519 recipient key the node minted (`share-recipient`; the hosted-key envelope construction with extra AAD fields, not the static distribution key); every request is signed with the node's mTLS key and verified by the dealer to the cluster CA and the `cosigner<N>` CN, plus a human-confirmed SAS. `import-share` (offline CLI) checks bundle vs node, config and expected fingerprint, VSS, package interpolation, then a no-clobber create (`renameat2(RENAME_NOREPLACE)` / `link(2)`); `abort-import`; DKG and hosted keys refuse `frost-import-` ids; read-only `KeyStatus` and fixed-message `CeremonySignTest` RPCs for an `operator_allowlist` role, and `verify-key` (cross-node digest agreement, every t-subset signs); then `Refresh`. Process hardening of the dealer (core dumps, ptrace, core handlers, mlock, swap). Includes the Canton key parser (B1) it depends on | `frost/core/src/dealer.rs`; `frost/cosigner/src/{share_delivery,share_import,request_auth,verify_key,wrap}.rs`, `src/bin/rutli-dealer.rs`; `frost/canton-key`; runbook [split-ceremony.md](split-ceremony.md) |
| e | **Deployment artifacts** (secondary) | Helm chart, Kubernetes manifests (StatefulSet, NetworkPolicy, PDB, backup/refresh CronJobs), Docker Compose TLS config, cert generation script | `deploy/helm`, `deploy/k8s`, `deploy/frost`, `scripts/` |
| f | **Operational runbooks** (procedural review) | Key ceremony, split ceremony (incl. destruction of the whole key), DR/backup/restore, approval quorum, and the migration runbook (`docs/migration.md`, written in B4) | `docs/key-ceremony.md`, `docs/split-ceremony.md`, `docs/disaster-recovery.md`, `docs/approval-quorum.md` |

### Approximate size

Measured with `wc -l` (physical lines, including comments and blanks; no `tokei`/`cloc` run).
Tests, generated code and build output are excluded from the "reviewable" column and listed separately.

| Component | Reviewable lines | Excluded (not counted) |
|---|---|---|
| `frost/core` (Rust, crypto core) | ~560 | ~430 integration tests |
| `frost/cosigner` (Rust daemon, `src/`, test modules inside `src/` removed) | ~5,540 | ~990 inline unit tests, ~1,940 integration tests |
| `frost/cosigner/proto/cosigner.proto` | ~260 | |
| `driver/src/main/scala` (JVM driver, hand-written) | ~2,815 | ~1,990 tests; 109 checked-in grpc-java generated files under `driver/src/main/java` |
| `deploy/helm`, `deploy/k8s` (YAML) | ~1,400 | |
| Runbooks and design docs | ~2,300 (`key-ceremony`, `disaster-recovery`, `approval-quorum`, `hosted-keys*`, `phase-2-frost`, `architecture`) | |
| Split ceremony (B2): `dealer.rs`, `share_delivery.rs`, `share_import.rs`, `verify_key.rs`, `rutli-dealer` | ~2,130 (plus ~300 changed lines in `wrap`, `keystore`, `node`, `service`, `main`) | ~1,200 inline unit tests, ~670 integration tests, e2e script |
| Canton key parser (B1): `frost/canton-key` | ~1,490 | ~600 vector tests, test vectors |

Rough total: ~12,600 lines of Rust and Scala (B1 and B2 included), plus ~1,400 lines of
deployment YAML. B1/B2 sizes measured on the B2 branch before code freeze; recount at the tag.
Rust non-test lines were counted by cutting each file at its first `#[cfg(test)]`.

## 3. Out of scope

- **Upstream `frost-ed25519` crate internals.** The ZF FROST implementation has already been audited
  by NCC Group and Least Authority (TODO(verify): confirm the exact audits and report dates before
  citing them to those two firms). We do want our *usage* of it reviewed: nonce handling, DKG and
  refresh orchestration, identifier and threshold parameters, serialization at our boundaries.
- Canton and Splice themselves (validator business logic, topology semantics).
- Other third-party dependencies beyond their configuration and use by us (tonic, `aws-lc-rs`,
  BouncyCastle). Please flag known-vulnerable versions you notice.
- The HSM (PKCS#11) and `software` backends are development/legacy delegates. TODO(verify): confirm
  with the maintainers whether `HsmBackend` should be explicitly excluded or reviewed lightly.
- Threshold ECDSA (Phase 4) and the networked share-repair ceremony: not shipped.

### Optional addendum: Track C, ECIES hosted keys (v0.5.0)

Hosted EC-P256 keys with an `EcdhDerive` RPC on the cosigner (`aws-lc-rs`), and a driver-side ECIES
decrypt path (BouncyCastle `IESEngine`, with the shared secret supplied by the cluster). Estimated
8-11 engineer-days on our side, scheduled to run while the audit is in progress, so it would not exist
at code freeze. **Question for you:** would you take it as a mid-engagement addendum (we would hand
over a tagged commit and a delta list), or do you prefer it as a separate follow-up engagement? Please
price both ways if you can. It is not part of the base quote.

## 4. Threat model highlights and areas we want focus on

Each item below comes from our own design docs (`audit-prep.md`, `phase-2-frost.md`,
`hosted-keys.md`, `architecture.md`); we would like them tested, not assumed.

| Area | What we believe, and want challenged |
|---|---|
| **Nonce reuse** | Round-1 nonces are fresh per session from a CSPRNG; a nonce record is persisted and fsynced before a signature share is released; reuse is refused across restarts; in-flight nonces are freed on give-up. Reusing a nonce commitment across two messages leaks the share. |
| **Ceremony races / split-brain** | A per-key guard, ownership re-checks on DKG/refresh part 2 and 3, a cluster-wide signing fence (and reverse fence against in-flight signs), and create-once refusal of DKG should prevent two ceremonies from leaving nodes on different sharing polynomials, or from overwriting a live namespace key. |
| **Share exfiltration** | Shares are sealed at rest; the seal secret comes from the environment, never disk or config. Compromise of fewer than `t` cosigners within one refresh epoch must not yield the key. Hosted keys are the exception by design: one cosigner holds them. |
| **Malicious or compromised cosigner** | What can a cosigner holding a valid mTLS cert do to the others (bad round-1/round-2 messages, bad DKG contributions, replicating bogus hosted keys, forcing conflicts)? |
| **Peer API bypass** | The Peer RPCs are the raw FROST protocol. A caller reaching `SignRound1/2` on `t` cosigners could sign any message, so `peer_allowlist` must exclude the driver, and the 34-byte digest check is repeated in `Node::sign_round2`. We want the allowlist and CN-matching logic reviewed, including behavior under misconfiguration. |
| **Compromised driver host** | An attacker on the Canton host holds the driver's client certificate. Bounds we claim: it can request signatures (subject to approval gate and journal, which run on the same host and can be bypassed by not using the driver), and `Decrypt` is rate-limited on the cosigner. It must not reach key material or nonce state. |
| **Approval bypass** | M-of-N Ed25519 approval over a per-request random id; each approver counted once; fail-closed on timeout. It covers `sign`, deliberately not `Decrypt`. Approval is over key and opaque digest only, not transaction content (Canton does not pass more). |
| **Seed-to-scalar trap (split ceremony)** | `SigningKey::deserialize` takes a scalar but Canton exports an RFC 8032 seed. A wrong conversion signs under a different key. We assert group key == Canton public key before any write; we want the conversion, the assertion, dealer memory handling, and key-destruction steps reviewed. |
| **Share delivery (split ceremony)** | Two directions. *Forged requests* (an attacker substituting recipient keys gets real shares): requests are signed by the node's mTLS key and verified to the cluster CA with a CN → identifier rule, backed by a witnessed SAS; we want the X.509 path verification (`request_auth.rs`, aws-lc-rs over x509-parser, no webpki), the identity rule and the canonical encoding reviewed. *Forged bundles*: sealing to a public key gives confidentiality, not sender authentication; we rely on the install-time checks (expected fingerprint, VSS, package interpolation, own verifying share) and on `verify-key`'s cross-node digest comparison and every-quorum signing to make a forged or mixed bundle fail. Also: the AAD binding, recipient-secret lifetime and deletion, the operator role's reach (`CeremonySignTest`), and the reserved-id / no-clobber install races. |
| **Rollback / stale state** | Restoring a stale backup can resurrect a deleted hosted key (documented hazard, `disaster-recovery.md` section 3c); anti-entropy treats a missing key as something to repair. TODO(verify): whether replay of an old sealed share or nonce store after a refresh is covered by any control; ask maintainers before sending, and say so here if it is an open question. |
| **Hosted-key wrapping and replication** | Per-recipient wrap with a recipient key derived (never stored) from the cluster master secret; AAD binds cluster id, key id, spec and recipient; replication never touches FROST shares (stated invariant); conflicting commitments for one id are a hard error, never auto-reconciled. |
| **Key-id handling** | Ids are opaque strings to cosigners; the driver derives them deterministically from Canton key names and applies `frost.key-prefix`. On a shared cluster a prefix is a namespace, not an authorization boundary: any driver cert can address any id. Look for prefix collisions, routing confusion between `frost-` / `rutli-` / delegate, and approval rules that match on a prefix that omits `key-prefix`. |
| **Audit log and journal integrity** | Hash-chained, fsynced write-ahead audit log; fails closed if a successful operation cannot be logged. The signing journal detects replays but cannot see height or round. |
| **Hosted-key side channels and exposure** | RSA decrypt performs full OAEP (no raw `c^d mod N` oracle) on `aws-lc-rs`, avoiding the pure-Rust `rsa` crate (RUSTSEC-2023-0071). Please check the cosigner-side error and timing behavior of `Decrypt`. |
| **Operational procedure** | Are the key ceremony, DR, and (once written) migration runbooks sound? In particular the destruction of the whole key after a split, and the exposure of plaintext keys in old database backups. |

Known and accepted limits (so you do not spend time on them): the namespace key is non-rotatable;
an imported (migrated) key is weaker than a DKG key because it once existed whole; hosted keys have
no forward secrecy; seal-secret protection is software, not HSM or enclave.

## 5. Engagement

| Item | Request |
|---|---|
| Start | **2026-11-17, fixed.** We will accept a later date only if stated up front; the project's 1.0 date moves with it. |
| Duration | 2-3 weeks; tell us what you can cover in each. |
| Code freeze | `v0.4.0`, target ~2026-11-14, which includes the split ceremony. Only audit fixes land afterwards. Freeze date is a target and may slip a few days; we will give you the commit hash on the day. |
| Our availability | One maintainer engineer, available during the engagement for questions (ECIES work runs in parallel unless you advise otherwise). Walkthrough on request. |
| Deliverables | Written report with findings and severity ratings; per-finding recommendations; executive summary suitable for publication. |
| Retest | Verification of our fixes against the findings is included in the quote. State how it is scheduled and whether there is a time or finding cap. |
| Publication | The project is open source, and we expect the final report to be public (after fixes). Please state your publication policy and any embargo or redaction terms. |

## 6. What we ask in your reply

1. Earliest start date you can commit to, and whether 2026-11-17 is feasible.
2. Proposed duration and staffing (number of reviewers, seniority, person-weeks).
3. Price, and whether fixed-fee or time-and-materials; payment terms and what changes the price.
4. Your track record with threshold-signature, MPC or FROST audits (named reports, if public).
5. Retest terms: scope, timing, cost.
6. Publication terms: whether you publish, our ability to publish, embargo and redaction handling.
7. Whether the ECIES addendum (section 3) is feasible mid-engagement, and the price either way.
8. Any information you need from us before quoting (access, build instructions, a call).

## 7. Materials we provide

- **Repository:** `<REPO_URL>` (public). Tag `v0.4.0` will be cut at code freeze.
- **Design and operator docs** (relative to the repository root):
  - [README.md](../README.md), [SECURITY.md](../SECURITY.md), [CHANGELOG.md](../CHANGELOG.md)
  - [docs/audit-prep.md](audit-prep.md): engagement brief and evidence index
  - [docs/architecture.md](architecture.md), [docs/phase-2-frost.md](phase-2-frost.md)
  - [docs/hosted-keys.md](hosted-keys.md), [docs/hosted-keys-design.md](hosted-keys-design.md)
  - [docs/wire-contract.md](wire-contract.md): exactly what Canton sends the driver
  - [docs/approval-quorum.md](approval-quorum.md), [docs/key-ceremony.md](key-ceremony.md)
  - [docs/disaster-recovery.md](disaster-recovery.md), [docs/key-rotation.md](key-rotation.md)
  - [docs/roadmap-migration.md](roadmap-migration.md): split ceremony (B2) design and risks
  - [docs/split-ceremony.md](split-ceremony.md): split ceremony runbook, records and destruction
  - [docs/testnet-soak.md](testnet-soak.md), [docs/soak-2026-10-devnet.md](soak-2026-10-devnet.md)
- **Tests and CI:** `cd frost && cargo test && cargo clippy --all-targets -- -D warnings`;
  `sbt driver/test`; TLS compose smoke (`scripts/ci-frost-tls-smoke.sh`); the driver passes the
  upstream Canton KMS driver conformance suite.
- **Environment:** on request, a walkthrough of our DevNet soak cluster (3 cosigners backing a
  Splice DevNet validator), with its dashboards and failure drills. TODO(verify): confirm that
  access (read-only dashboard or live demo) is acceptable to expose to outside reviewers.
- **Build prerequisites:** JDK 17, sbt, Rust, Docker, Canton 3.6.1 release (KMS API jars are not on
  Maven Central; `scripts/publish-canton-deps.sh` handles it). TODO(verify): the README names Canton
  3.6.1 as the build target, while the end-to-end runs it describes were on 3.5.6; confirm what
  version the audited commit is verified against.

## 8. Contact

`<NAME>, <EMAIL>`

Please send questions and the quote to the address above. Vulnerabilities found during the audit that
you consider urgent can also go through the private channel in [SECURITY.md](../SECURITY.md).

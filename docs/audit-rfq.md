# Request for Quote: security audit of Rütli

> **Template note (delete before sending).** This is one generic RFQ, sent unchanged to Least
> Authority, Trail of Bits, NCC Group and Kudelski Security. Fill the `<PLACEHOLDERS>` and resolve
> every `TODO(owner)` (questions only the maintainers can answer) before it goes out. Drafted
> 2026-10-08; facts verified against the repository on 2026-10-14 at `v0.4.0-rc.1` (commit `903d318`).
> Line counts below were measured on that tree (without B6) and must be re-measured at code freeze.
> Companion brief for the auditors: [audit-prep.md](audit-prep.md).

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
else lands in the audited surface after it except audit fixes. The release candidate `v0.4.0-rc.1`
(tagged 2026-10-09) already contains the split ceremony (B2), the Canton key parser (B1) and the
ECIES hosted keys (Track C); it is available now for orientation and pre-reading. Between the
candidate and `v0.4.0` we expect only milestone B6 (row g), review fixes and documentation.

| # | Component | Includes | Where |
|---|---|---|---|
| a | **FROST-ed25519 cosigner cluster** | DKG; t-of-n signing (two rounds); crash-safe nonce guard; proactive refresh; share repair; share sealing at rest (AES-256-GCM, per-node keys derived from an operator secret); mutual TLS and the `signer_allowlist` / `peer_allowlist` role split; per-key ceremony guards and cluster-wide signing fence; create-once guard | `frost/core`, `frost/cosigner` |
| b | **Cluster-hosted keys** | Replicated whole keys (RSA-2048-OAEP via `aws-lc-rs`, AES-256-GCM, and EC-P256 ECIES keys, see row g); per-recipient wrapping (ephemeral X25519, HKDF-SHA256, AES-256-GCM, AAD-bound); write quorum, anti-entropy, read-repair; offline passphrase-encrypted export/import; per-key decrypt rate limit | `frost/cosigner` (`hosted`, `wrap`, `export`, `ratelimit`, `peer`) |
| c | **JVM KMS driver** | Key-id routing (`frost-` / `rutli-` prefixes, `frost.key-prefix`); `FrostBackend` gRPC client with failover rules; M-of-N approval gate and policy; hash-chained audit log; signing journal; Canton 34-byte digest handling; ECIES completion for hosted EC keys (`CantonEcies`) | `driver/src/main` |
| d | **Split ceremony (milestone B2)** | In `v0.4.0-rc.1`; frozen with v0.4.0 (B6 touches its usage guard, row h). Offline dealer binary `rutli-dealer` splits an existing Canton Ed25519 namespace key into t-of-n FROST shares via `frost_ed25519::keys::split`, using RFC 8032 seed-to-scalar conversion (ed25519-dalek's SHA-512, clamp, reduce mod l); before writing anything it proves group key == Canton key, VSS, `min_signers`, every t-subset reconstructs and signs (`verify_strict`). Each share is sealed to a one-time per-ceremony X25519 recipient key the node minted (`share-recipient`; the hosted-key envelope construction with extra AAD fields, not the static distribution key); every request is signed with the node's mTLS key and verified by the dealer to the cluster CA and the `cosigner<N>` CN, plus a human-confirmed SAS. `import-share` (offline CLI) checks bundle vs node, config and expected fingerprint, VSS, package interpolation, then a no-clobber create (`renameat2(RENAME_NOREPLACE)` / `link(2)`); `abort-import`; DKG and hosted keys refuse `frost-import-` ids; read-only `KeyStatus` and fixed-message `CeremonySignTest` RPCs for an `operator_allowlist` role, and `verify-key` (cross-node digest agreement, every t-subset signs); then `Refresh`. Process hardening of the dealer (core dumps, ptrace, core handlers, mlock, swap). Includes the Canton key parser (B1) it depends on | `frost/core/src/dealer.rs`; `frost/cosigner/src/{share_delivery,share_import,request_auth,verify_key,wrap}.rs`, `src/bin/rutli-dealer.rs`; `frost/canton-key`; runbook [split-ceremony.md](split-ceremony.md) |
| e | **Deployment artifacts** (secondary) | Helm chart, Kubernetes manifests (StatefulSet, NetworkPolicy, PDB, backup/refresh CronJobs), Docker Compose TLS config, cert generation script | `deploy/helm`, `deploy/k8s`, `deploy/frost`, `scripts/` |
| f | **Operational runbooks** (procedural review) | Key ceremony, split ceremony (incl. destruction of the whole key), DR/backup/restore, approval quorum, and the pilot migration runbook (`docs/migration.md`), whose steps were exercised in the DevNet B4 cutover rehearsal on 2026-10-14 | `docs/key-ceremony.md`, `docs/split-ceremony.md`, `docs/disaster-recovery.md`, `docs/approval-quorum.md`, `docs/migration.md` |
| g | **ECIES hosted keys (Track C)** | Merged and part of `v0.4.0` (in `v0.4.0-rc.1`); no longer a separate release or optional addendum. Hosted EC-P256 keys with an `EcdhDerive` RPC on the cosigner (`aws-lc-rs`) and a driver-side ECIES decrypt path (BouncyCastle `IESEngine`, shared secret supplied by the cluster); `import-key` of a Canton EC P-256 encryption key via the B1 parser. Details and our focus questions in section 2.1 | `frost/cosigner/src/{hosted,export,service,node}.rs`, `cosigner.proto`; `driver/.../backend/{CantonEcies,FrostBackend}.scala` |
| h | **Optional carry of protocol signing and ECIES encryption keys (milestone B6)** | **In progress** on branch `feat/b6-carry-protocol-keys`; lands before the audit code freeze (`v0.4.0`). A discouraged path: the recommended migration carries only the namespace key and gives the new node fresh keys. It touches the offline dealer's usage guard (`rutli-dealer --expect-usage`), adds a `rutli-cosigner verify-hosted` RPC/CLI, and docs. Size to be given with the freeze commit | `frost/core/src/dealer.rs`, `frost/cosigner/src/bin/rutli-dealer.rs`, `frost/cosigner` (`verify-hosted`), `docs/` |

### Approximate size

Measured on 2026-10-14 at `v0.4.0-rc.1` (`903d318`) with `wc -l` (physical lines, including comments and
blanks; `tokei` was not used). Rust non-test lines were counted by cutting each file at its first
`#[cfg(test)]`. Tests, generated code and build output are excluded from the "reviewable" column and
listed separately. B2 and Track C code is already included in the crate rows. B6 is not yet counted.

| Component | Reviewable lines | Excluded (not counted) |
|---|---|---|
| `frost/core` (Rust, crypto core, includes `dealer.rs`) | ~960 | ~430 integration tests, ~280 inline unit tests |
| `frost/cosigner` (Rust daemon and `rutli-dealer`, `src/`) | ~9,520 | ~2,330 inline unit tests, ~3,750 integration tests |
| `frost/canton-key` (B1, Canton key parser) | ~1,490 | ~110 inline unit tests, ~600 vector tests, test vectors |
| `frost/cosigner/proto/cosigner.proto` | ~330 | |
| `driver/src/main/scala` (JVM driver, hand-written, 18 files) | ~3,310 | ~3,190 tests; 121 checked-in grpc-java generated files under `driver/src/main/java` |
| `deploy/helm`, `deploy/k8s` (YAML) | ~1,570 | |
| Runbooks and design docs | ~3,090 (`key-ceremony`, `disaster-recovery`, `approval-quorum`, `hosted-keys*`, `phase-2-frost`, `architecture`, `split-ceremony`, `migration`) | |

Of the cosigner and core rows, the split ceremony (B2) accounts for ~2,850 lines (`dealer.rs`,
`share_delivery.rs`, `share_import.rs`, `verify_key.rs`, `request_auth.rs`, `rutli-dealer`), plus
changes in `wrap`, `keystore`, `node`, `service` and `main`. Track C (ECIES) added about 1,350 lines
across 11 files, inline tests included, in the 24 commits since its first commit (`e09d07f`),
mostly `FrostBackend.scala`, `CantonEcies.scala`, `hosted.rs` and `export.rs`.

Rough total: ~15,600 lines of Rust, protobuf and Scala (B1, B2 and Track C included), plus ~1,570
lines of deployment YAML. Recount at the tag.

### 2.1 ECIES hosted keys (Track C): detail and where we want attention

Track C is merged and ships in `v0.4.0` (it is in `v0.4.0-rc.1`); it is part of the base scope, not a
separate release. If you can, show it as a separate line item in your quote so we can see its weight.
What it added, measured as lines added in the Track C commits (inline tests included):

| Area | Files | Added lines |
|---|---|---|
| Cosigner: `ec-p256-ecies` spec, keygen, SPKI, `ecdh_p256`, peer-point gate, `validate` | `frost/cosigner/src/hosted.rs` | ~350 (about 140 non-test) |
| Cosigner: `EcdhDerive` RPC, rate limit, reserved ids, capability gating | `service.rs`, `node.rs`, `error.rs`, `peer.rs`, `orchestrator.rs`, `cosigner.proto` | ~160 |
| Cosigner: `import-key` of a Canton EC P-256 encryption key (via B1's parser) | `export.rs` (`import_canton`), `main.rs` | ~300 |
| Driver: ECIES completion in `IESEngine`, spec-driven keygen/public key, routing, gating | `driver/.../backend/CantonEcies.scala`, `FrostBackend.scala` | ~540 |

Where we would like attention, in order:

1. **The `IESEngine` composition** (`CantonEcies.decrypt`): the engine is assembled as BouncyCastle's
   JCE does for `ECIESwithSHA256andAES-CBC`, with the ECDH replaced by an agreement that returns the
   cluster's `Z` for exactly one point. Is anything in that substitution (field size, `V` handling,
   the `AsymmetricKeyParameter` placeholder, exception mapping) not equivalent to Canton's own
   decryptor?
2. **Peer-point validation and the ECDH oracle.** `EcdhDerive` answers `x(d·V)` for any valid point
   a driver-certificate holder sends — a static Diffie-Hellman oracle, bounded only by the per-key
   decryption budget. We believe the uncompressed-only gate plus aws-lc's on-curve check close
   invalid-curve and small-subgroup attacks, and that the oracle is no stronger than `Decrypt`.
3. **An upstream property we inherit:** Canton's ECIES MACs the CBC ciphertext but not the IV it
   prepends, so the first plaintext block is malleable. We match Canton byte for byte rather than
   diverge; please tell us if you see a way that matters through a KMS.
4. **Canton-key import:** that the public key the cluster serves is provably the one Canton
   recorded, and nothing else can be imported as an ECDH key.
5. **Mixed-version clusters.** The driver enables ECIES only when every cosigner advertises
   `ec-p256-ecies` in its capabilities, and a leader refuses to create an EC key unless all peers
   serve it; EC operations fail over past an old node. Please check that a rolling upgrade cannot end
   with a key that only some nodes can serve, or an ECIES decrypt silently routed to the wrong place.

## 3. Out of scope

- **Upstream `frost-ed25519` crate internals.** The Zcash Foundation FROST implementation has been
  independently assessed: NCC Group published a public report on it in October 2023 (reviewed
  release v0.6.0; the retest confirmed all findings fixed). We pin the 2.x line (`frost-ed25519` 2.2.0
  in `Cargo.lock`), which is newer than the reviewed release. We do want our *usage* of the crate reviewed: nonce
  handling, DKG and refresh orchestration, identifier and threshold parameters, serialization at our
  boundaries.
- Canton and Splice themselves (validator business logic, topology semantics).
- Other third-party dependencies beyond their configuration and use by us (tonic, `aws-lc-rs`,
  BouncyCastle). Please flag known-vulnerable versions you notice.
- The HSM (PKCS#11) and `software` backends (`HsmBackend.scala`, ~400 lines; `SoftwareBackend.scala`
  and `SoftKeyStore.scala`, ~460 lines) are delegates for non-FROST keys. The shape we deploy
  and soak is `delegate = "none"` with cluster-hosted keys, which uses neither. The HSM delegate is
  experimental (verified on SoftHSM only) and explicitly excluded; the `software` backend is for
  testing only.
- Threshold ECDSA (Phase 4) and the networked share-repair ceremony: not shipped.

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
| **Carrying protocol keys (B6, in progress)** | Carrying a node's protocol signing and ECIES encryption keys into the cluster is a discouraged path (fresh keys are the default); it depends on the dealer's usage guard (`--expect-usage`) refusing a key of the wrong usage, and on `verify-hosted` proving what the cluster serves. We want that guard and the verification reviewed for ways to carry the wrong key, or to leave a plaintext copy behind unnoticed. Details follow with the freeze commit. |
| **Share delivery (split ceremony)** | Two directions. *Forged requests* (an attacker substituting recipient keys gets real shares): requests are signed by the node's mTLS key and verified to the cluster CA with a CN → identifier rule, backed by a witnessed SAS; we want the X.509 path verification (`request_auth.rs`, aws-lc-rs over x509-parser, no webpki), the identity rule and the canonical encoding reviewed. *Forged bundles*: sealing to a public key gives confidentiality, not sender authentication; we rely on the install-time checks (expected fingerprint, VSS, package interpolation, own verifying share) and on `verify-key`'s cross-node digest comparison and every-quorum signing to make a forged or mixed bundle fail. Also: the AAD binding, recipient-secret lifetime and deletion, the operator role's reach (`CeremonySignTest`), and the reserved-id / no-clobber install races. |
| **Rollback / stale state** | Restoring a stale backup can resurrect a deleted hosted key (documented hazard, `disaster-recovery.md` section 3c); anti-entropy treats a missing key as something to repair. For FROST keys: round-1 nonces live only in RAM under a fresh random session id, and the on-disk single-use markers are keyed by that id (`nonce_store.rs`), so restoring or losing an old nonce store cannot cause nonce reuse. A node restored from a pre-refresh backup holds a stale share; the leader's aggregation verifies every signature share and attributes a bad one (`session.rs`), so it cannot produce a wrong signature, but we have **no explicit epoch or version check** that keeps such a node from taking part (the `refresh_count` in a share's provenance is informational and exists only for dealt keys). Treat this as an open question for you: is replay of an old sealed share or backup after a refresh covered, or does it need a control? |
| **Hosted-key wrapping and replication** | Per-recipient wrap with a recipient key derived (never stored) from the cluster master secret; AAD binds cluster id, key id, spec and recipient; replication never touches FROST shares (stated invariant); conflicting commitments for one id are a hard error, never auto-reconciled. |
| **Key-id handling** | Ids are opaque strings to cosigners; the driver derives them deterministically from Canton key names and applies `frost.key-prefix`. On a shared cluster a prefix is a namespace, not an authorization boundary: any driver cert can address any id. Look for prefix collisions, routing confusion between `frost-` / `rutli-` / delegate, and approval rules that match on a prefix that omits `key-prefix`. |
| **Audit log and journal integrity** | Hash-chained, fsynced write-ahead audit log; fails closed if a successful operation cannot be logged. The signing journal detects replays but cannot see height or round. |
| **Hosted-key side channels and exposure** | RSA decrypt performs full OAEP (no raw `c^d mod N` oracle) on `aws-lc-rs`, avoiding the pure-Rust `rsa` crate (RUSTSEC-2023-0071). Please check the cosigner-side error and timing behavior of `Decrypt`. |
| **Operational procedure** | Are the key ceremony, DR and migration runbooks sound? In particular the destruction of the whole key after a split, and the exposure of plaintext keys in old database backups. |

Known and accepted limits (so you do not spend time on them): the namespace key is non-rotatable;
an imported (migrated) key is weaker than a DKG key because it once existed whole; hosted keys have
no forward secrecy; seal-secret protection is software, not HSM or enclave.

## 5. Engagement

| Item | Request |
|---|---|
| Start | **2026-11-17, fixed.** We will accept a later date only if stated up front; the project's 1.0 date moves with it. |
| Duration | 2-3 weeks; tell us what you can cover in each. |
| Code freeze | `v0.4.0`, target ~2026-11-14, which includes the split ceremony, the ECIES hosted keys and milestone B6. Only audit fixes land afterwards. Freeze date is a target and may slip a few days; we will give you the commit hash on the day. |
| Our availability | One maintainer engineer, available during the engagement for questions. No feature work lands in the audited surface after the freeze. Walkthrough on request. |
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
7. The weight of the ECIES hosted keys (section 2.1) and of milestone B6 as separate line items in your quote, if you can show them.
8. Any information you need from us before quoting (access, build instructions, a call).

## 7. Materials we provide

- **Repository:** `https://github.com/Stakecraft/rutli` (public). Tag `v0.4.0-rc.1` (2026-10-09, commit `903d318`) exists now; tag `v0.4.0` will be cut at code freeze.
- **Design and operator docs** (relative to the repository root):
  - [README.md](../README.md), [SECURITY.md](../SECURITY.md), [CHANGELOG.md](../CHANGELOG.md)
  - [docs/audit-prep.md](audit-prep.md): engagement brief and evidence index
  - [docs/architecture.md](architecture.md), [docs/phase-2-frost.md](phase-2-frost.md)
  - [docs/hosted-keys.md](hosted-keys.md), [docs/hosted-keys-design.md](hosted-keys-design.md)
  - [docs/wire-contract.md](wire-contract.md): exactly what Canton sends the driver
  - [docs/approval-quorum.md](approval-quorum.md), [docs/key-ceremony.md](key-ceremony.md)
  - [docs/disaster-recovery.md](disaster-recovery.md), [docs/key-rotation.md](key-rotation.md)
  - [docs/roadmap-migration.md](roadmap-migration.md): split ceremony (B2) design and risks, milestone status
  - [docs/migration.md](migration.md): pilot migration runbook, exercised in the 2026-10-14 DevNet rehearsal
  - [docs/split-ceremony.md](split-ceremony.md): split ceremony runbook, records and destruction
  - [docs/testnet-soak.md](testnet-soak.md), [docs/soak-2026-10-devnet.md](soak-2026-10-devnet.md)
- **Tests and CI:** `cd frost && cargo test && cargo clippy --all-targets -- -D warnings`;
  `sbt driver/test`; TLS compose smoke (`scripts/ci-frost-tls-smoke.sh`); the driver passes the
  upstream Canton KMS driver conformance suite.
- **Environment:** an evidence pack from our DevNet soak (3 cosigners backing a Splice DevNet
  validator): the soak log, the B0/B4 runbooks and their evidence (driver audit logs, hashes,
  timings), and dashboard exports; a live demo over video call on request. We do not grant access
  to the cluster itself (it is shared with other DevNet validators). The DevNet B4 cutover rehearsal
  (an existing JCE validator moved into the cluster with its namespace and party IDs unchanged) ran
  green on 2026-10-14; the soak log is [docs/soak-2026-10-devnet.md](soak-2026-10-devnet.md).
- **Build prerequisites:** JDK 17, sbt, Rust, Docker, Canton 3.6.1 release (KMS API jars are not on
  Maven Central; `scripts/publish-canton-deps.sh` handles it). The audited commit is built and
  tested against Canton **v3.6.1**: `build.sbt` and the CI `CANTON_TAG`, the upstream driver
  conformance suite, the ECIES end-to-end script (`scripts/e2e-ecies-hosted.sh`, a live 3.6.1
  participant), and the DevNet soak and B4 rehearsal (Splice 0.9.0, Canton 3.6.1). The earlier
  end-to-end runs in the docs (July and August 2026) were on Canton 3.5.6; the KMS driver SPI is
  byte-identical between 3.5.6 and 3.6.1 (`build.sbt`), but we do not claim 3.5.6 for the audited
  commit.

## 8. Contact

`<NAME>, <EMAIL>`

Please send questions and the quote to the address above. Vulnerabilities found during the audit that
you consider urgent can also go through the private channel in [SECURITY.md](../SECURITY.md).

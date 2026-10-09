# Cluster-hosted keys (non-FROST key material) — design

**Status: v1 shipped — cluster side and driver side — and verified end to end on a real Canton 3.5.6
participant (2026-08-28). v1.5 (hosted EC P-256 keys, ECIES) shipped 2026-10-09 (roadmap Track C,
branch `feat/c-ecies-hosted-keys`) and verified end to end on Canton 3.6.1 — see *What v1.5 adds*.**
Written after the 2026-08-12 DevNet incident in which a participant restart destroyed a heap-only
RSA encryption key. Two independent design passes plus a Rust
threshold-crypto crate survey fed this document; where they disagreed, the resolution is called out.

The rationale below is left as written — it is the record of *why* each choice was made, not a
description of the running system. Sections now carry a status note: **Shipped**, **Changed in
implementation** (the design said one thing, the code does another, and why), or **Not shipped**.
Where the design left something open and the implementation settled it, the answer is stated in
place.

## What v1 is, concretely

Cluster side (Rust cosigner), implemented and covered by tests:

- `HostedKey` — RSA-2048-OAEP-SHA256 and AES-256-GCM — sealed on disk in `data_dir/keys/` beside
  FROST shares: [`hosted.rs`](../frost/cosigner/src/hosted.rs),
  [`keystore.rs`](../frost/cosigner/src/keystore.rs).
- Per-recipient wrapping for anything that crosses the mesh:
  [`wrap.rs`](../frost/cosigner/src/wrap.rs).
- Leader-driven generation under the existing per-key ceremony fence, write quorum with cluster-wide
  rollback, anti-entropy sweep, read-repair:
  [`orchestrator.rs`](../frost/cosigner/src/orchestrator.rs).
- Signer RPCs `Capabilities`, `GenerateKey`, `PublicKey`, `KeyInfo`, `DeleteKey`, `Decrypt`,
  `SymmetricEncrypt`, `SymmetricDecrypt`; Peer RPCs `ReplicateKey`, `FetchKey`, `ListKeys`,
  `PurgeKey`, `NodeInfo`: [`cosigner.proto`](../frost/cosigner/proto/cosigner.proto).
- Offline CLI subcommands `export-key` / `import-key` for a portable, passphrase-protected copy of a
  hosted key: [`export.rs`](../frost/cosigner/src/export.rs). Not in this design — see *Export and
  import* below.
- Config block `hosted_keys { enabled, write_quorum, anti_entropy_interval_secs }`, rejected at load
  time unless `share_seal` is configured, with `write_quorum` carried through to the orchestrator.
  Metrics `rutli_hosted_keys`, `rutli_hosted_key_ops_total{op,result}`,
  `rutli_anti_entropy_repairs_total`, `rutli_anti_entropy_conflicts_total`, `rutli_key_replicas`
  (fewest cosigners holding any one key, as of the last sweep) and
  `rutli_unreadable_key_files_total` (key files that could not be opened and were skipped from the
  inventory — any non-zero value means a key is silently not being replicated or repaired, so alert
  on it).

Driver side (Scala), shipped in the same release:

- Routing by key-id prefix in
  [`FrostBackend`](../driver/src/main/scala/com/stakecraft/rutli/backend/FrostBackend.scala):
  `frost-` → threshold Ed25519 in the cluster, `rutli-` → cluster-hosted, anything else → the
  delegate. Gated by `frost.hosted-keys = true`.
- `frost.delegate = "none"` is served by a
  [`NoDelegateBackend`](../driver/src/main/scala/com/stakecraft/rutli/backend/NoDelegateBackend.scala)
  that refuses every operation and names the key id, and is refused at startup unless
  `hosted-keys = true` — otherwise nothing would serve the encryption keys.
- Supported specs come from the cluster's `Capabilities` at startup rather than a hardcoded list, so
  a cluster can add a key type without a driver release. An older or unreachable cluster falls back
  to the configured expectation and logs it.
- **No automatic fallback to the delegate on `NOT_FOUND`**, and endpoint failover stays restricted
  to `UNAVAILABLE` / `DEADLINE_EXCEEDED`. A fallback would silently split custody — the shape of
  the August incident.
- The driver mints the `rutli-` key id itself, since Canton's SPI does not let a caller name a key.

**Verified end to end (2026-08-28).**
[`deploy/devnet/canton-hosted.conf`](../deploy/devnet/canton-hosted.conf) boots a real Canton 3.5.6
participant with **no local key state and no HSM**: all three Ed25519 keys (namespace, signing,
sequencer-auth) are born via cluster DKG and threshold-signed, and the RSA-2048 encryption key is
generated as a cluster-hosted key and confirmed replicated to all three cosigners on disk, beside
the FROST shares. One config gotcha worth recording: Canton's HOCON name for the algorithm is
`rsa-oaep-sha-256` — pureconfig kebab-cases `RsaOaepSha256`, splitting the digits — not the driver
SPI's `RsaEsOaepSha256` spelling.

### What v1.5 adds (Track C, 2026-10-09)

- `HostedSpec::EcP256`, on the wire `ec-p256-ecies`: an EC P-256 **encryption** key, generated on
  aws-lc-rs, stored as PKCS#8, served as SPKI DER byte-identical to Canton's encoding, replicated,
  sealed, exported and imported like every hosted key. `HostedKey::validate` refuses EC material
  whose stored public key is not the one its scalar derives, on replication and on import.
- Signer RPC `EcdhDerive(key_id, peer_point) → Z`, the 32-byte x-coordinate of `d·V`
  ([`hosted.rs`](../frost/cosigner/src/hosted.rs), [`service.rs`](../frost/cosigner/src/service.rs)).
  Only a 65-byte uncompressed SEC1 point is accepted — aws-lc's `agree` would also take compressed
  and hybrid encodings, so the gate is ours — and aws-lc refuses a point off the curve. Refused for
  every other spec and for ids reserved for the split ceremony; charged to the per-key decryption
  budget it shares with `Decrypt`; counted as `op="ecdh_derive"`.
- `import-key` also reads an existing Canton node's EC P-256 encryption key (B1's parser) and refuses
  unless the SPKI the cluster will serve is Canton's, byte for byte — the node migrates without
  rotating its encryption key ([`export.rs`](../frost/cosigner/src/export.rs) `import_canton`).
- Driver: `EcP256` / `EciesHkdfHmacSha256Aes128Cbc` advertised only when the cluster reports
  `ec-p256-ecies`; spec-driven `generateEncryptionKeyPair` and `getPublicKey`; ECIES decryption in
  [`CantonEcies`](../driver/src/main/scala/com/stakecraft/rutli/backend/CantonEcies.scala) — the
  blob's shape is checked before any cluster call, and the DEM is BouncyCastle's own `IESEngine` with
  a stub agreement that returns the cluster's `Z` for exactly one `V`. BouncyCastle 1.85, Canton's.
- Verified: upstream `KmsDriverTest` over the frost backend with ECIES advertised (Canton's
  `JcePureCrypto` encrypts, the driver decrypts), a BouncyCastle differential over every plaintext
  length up to the 256-byte bound, and `scripts/e2e-ecies-hosted.sh`: a Canton 3.6.1 participant
  with a cluster-generated, then a Canton-imported ECIES key (same fingerprint as on the old node),
  pinging a JCE participant both ways.

### Export and import — not in this design, added on operator request

The design assumed `backup`/`restore` were enough because hosted keys live in `data_dir/keys/`
(**Storage**). They are not: a backup is *sealed ciphertext*, openable only with the cluster's seal
master secret and only on the node it came from. That covers routine node and cluster loss and
nothing else. Operators asked for the two cases it structurally cannot cover — recovering after the
seal master secret is lost, and moving a key to a different cluster or KMS — so `export-key` /
`import-key` were added: Argon2id → AES-256-GCM under an operator passphrase, portable, node- and
cluster-independent.

**Offline CLI, never an RPC**, and that is the load-bearing decision. An export RPC would turn a
stolen driver certificate from an online, rate-limited, journalled decrypt *oracle* into permanent
silent possession of the key. That is the same posture as keeping the full OAEP unpad server-side
(**Where the trust boundary sits**): expose the weakest capability that does the job, never the key
itself. As a CLI command the operation needs host access **and** the seal secret, two inputs already
kept in separate trust domains. Hosted keys only: a FROST share is not a whole key, so `export-key`
refuses one, and the namespace key still cannot leave the cluster.

Mechanics, properties and the security tradeoff of keeping an export at all are in
[`hosted-keys.md`](hosted-keys.md) §4 (*Export and import*); the recovery procedure is
[`disaster-recovery.md`](disaster-recovery.md) §3d. Not repeated here.

### What is still missing

Gaps that are deliberate deferrals rather than oversights are marked in place below. Two of the four
listed here previously have since closed: `rutli_key_replicas` and its alerts shipped, which was
this design's condition for the 2-of-3 write-quorum default, and `hosted_keys.write_quorum` is now
honoured instead of being overridden by the compiled-in default (both under **Replication**). What
remains, worth knowing before running this in production:

1. No cosigner-side rate limit on decrypt (**Rate limiting and auditing for decrypt**).
2. No pinned peer distribution keys, so no startup self-check on the seal secret (**Replication**).

## The problem

Rütli's FROST cluster holds only the Ed25519 namespace/identity key. Every other key Canton needs —
the RSA-2048 encryption keypair, the AES symmetric wrapping key — is served by a *delegate* backend:
an HSM (durable, but requires an HSM) or the software backend (no HSM, but the keys lived in JVM
heap until [`SoftKeyStore`](../driver/src/main/scala/com/stakecraft/rutli/backend/SoftKeyStore.scala)
gave them sealed disk persistence). Neither option puts that material in the cluster, so an HSM-less
deployment keeps private keys on the Canton participant host — the busiest, most exposed machine in
the deployment.

Goal: let the cosigner cluster hold the non-FROST key material too, so a participant needs **no HSM
and no local key state**.

## Decision 1 — threshold RSA is out. Permanently.

Not "later", not "roadmap". Two independent blockers compound:

1. **No Rust implementation exists.** A sweep of crates.io (threshold rsa, shoup, threshold
   decryption, threshold paillier, distributed key generation, the `threshold` keyword index) found
   nothing implementing threshold RSA decryption — audited or not. Shoup's construction exists in Go
   (cloudflare/circl), C++ (Safeheron), and Java; not in Rust. Confium, the most ambitious 2026 Rust
   threshold framework (65 crates), covers FROST/GG18/CMP20/BLS/ElGamal and explicitly omits RSA.
   Building it means writing novel crypto in the language with the weakest RSA foundation.
2. **The underlying primitive is unfit.** [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
   (Marvin timing side-channel, private-key recovery by a *network* attacker) is still **unpatched**
   as of 2026 — advisory last modified 2026-04-25, patched versions: none. The RustCrypto `rsa`
   README still carries the warning. A network-facing KMS doing RSA decryption is precisely the
   deployment the advisory warns against.

Distributed RSA keygen is also expensive (3-party honest-majority: single-digit minutes semi-honest,
low tens malicious), and the trusted-dealer alternative — generate centrally, Shamir-share `d` —
would mean one machine held the whole key at birth, contradicting Rütli's core claim.

**Consequence for RSA decrypt in v1:** do **not** use the pure-Rust `rsa` crate for decryption.
Use `aws-lc-rs` (FIPS-validated, constant-time) or OpenSSL bindings. Keygen via `rsa` is acceptable
but must run on `spawn_blocking`. This is a blocking implementation decision, not a preference.

> **Shipped, and stricter than the design allowed for.** The `rsa` crate is not in the dependency
> tree at all: `aws-lc-rs` does keygen *and* OAEP decryption, so the "keygen via `rsa` is
> acceptable" fallback was never taken. Decryption failures return one opaque error for every
> cause — a distinguishable padding failure is itself an oracle.
>
> **Also shipped since:** the `spawn_blocking` half — RSA-2048 keygen runs on a blocking thread
> (`orchestrator::generate_hosted_key`), and so does every hosted-key read and write
> (`Node::blocking`), so neither CPU-heavy keygen nor a stalled data volume can occupy an async
> worker.

## Decision 2 — v1 is replicated, sealed, whole keys

Generate on the leader, replicate to every cosigner, seal per node at rest, any node serves decrypt.

Both design passes reached this independently. The honest framing of what it buys:

| | software delegate (the incident) | HSM delegate | **cluster-hosted v1** |
|---|---|---|---|
| Survives restart | **no** (heap) | yes | yes — 3 sealed replicas |
| Key material on the participant host | yes | no | **no** |
| Participant host compromise yields | **every private key** | decrypt oracle | nothing |
| One cosigner compromise yields | — | — | that key (3 copies exist) |
| Namespace key | unaffected | unaffected | **unaffected — still 2-of-3** |

Two framings that are defensible, and one cost that must not be buried:

- **The security tier matches the recoverability tier.** The one key Canton *cannot* rotate (the
  namespace key) stays in real threshold MPC. The keys that get only replication are exactly the
  keys Canton *can* rotate under that namespace key. A replicated-key compromise costs a topology
  transaction; a namespace-key compromise costs the node's identity.
- **The win is relocation, not a threshold property.** v1 moves key material off an
  internet-adjacent Canton host onto three hardened, single-purpose, allowlisted, sealed nodes.
- **The cost:** Canton's encryption keys protect per-view session keys. An attacker who extracts one
  gains *retrospective* read access to any recorded traffic encrypted to it. Rotation fixes the
  future, not the past. There is no forward secrecy here. Say so in the README, not a footnote.

On MPCH Stronghold's "MPC for all key types": for RSA that is trusted-dealer sharing, an
HSM/enclave, or marketing. Rütli's differentiator should be precision — state exactly what each key
class gets.

> **Shipped, with the gate the table depends on.** `hosted_keys.enabled` is refused at config load
> unless `share_seal` is configured, and a hosted key is written through the same sealed envelope
> and atomic-write path as a FROST share. Without that gate the "3 sealed replicas" column would be
> "3 plaintext replicas", which is strictly worse than the HSM delegate this replaces.

## Decision 3 — the ECIES lever (why the roadmap inverts)

> **v1.5 shipped (2026-10-09); v2 not yet.** The cluster advertises `ec-p256-ecies` through
> `Capabilities`, serves `EcdhDerive`, and the driver advertises `EcP256` + ECIES to Canton. The
> constraint at the end of this section is answered: yes (see *Open questions*). v2 (threshold) is
> unchanged as a plan.

The scheme Canton's KMS mode uses by default (RSA) is the one that cannot be thresholded; the scheme
that thresholds beautifully (ECIES over P-256) is one Canton supports but AWS/GCP KMS cannot serve —
which is why `CryptoProvider.Kms` defaults away from it.

**The driver declares its own `supportedEncryptionKeySpecs`.** Canton's spec converter maps
`EciesHkdfHmacSha256Aes128Cbc` in both directions, so Rütli may advertise `EcP256` + ECIES and steer
deployments onto the scheme it can actually threshold. That is a real differentiator available only
to a self-hosted KMS.

Why threshold ECDH is tractable where threshold RSA is not: with Shamir shares `dᵢ` of `d`, each node
returns `λᵢ·dᵢ·R`; the leader adds the *points* and takes the x-coordinate once at the end. One
round, **stateless, no nonces** — none of the nonce-reuse hazard that dominates the FROST path's
operational risk. And Canton's ECIES has exactly one secret-dependent step (the point
multiplication); KDF2 → AES-128-CBC → HMAC are all public computation on the derived key.

`frost-p256` (same Zcash Foundation codebase already vendored for Ed25519, NCC-audited 2023) supplies
a ready-made P-256 DKG whose `signing_share` *is* the Shamir share needed, and whose group verifying
key *is* a valid P-256 encryption public key — so v2 reuses the existing DKG orchestration, keystore
and ceremony guard, adding ~40 lines of Lagrange point math plus a Chaum–Pedersen DLEQ proof.

**Caveat to write into the threat model:** the `p256` crate's curve arithmetic is, by its own
README, *never independently audited*. The NCC Group 2023 review covered `crypto-bigint`,
`crypto-primes` and `k256` — not `p256`.

**Constraint to verify before investing in v2:** the Global Synchronizer's
`StaticSynchronizerParameters.requiredEncryptionSpecs` decides whether participants may use
`EcP256`/ECIES at all. The mechanism is confirmed in Canton source; the deployed values are not.

## Architecture

### Where the trust boundary sits, per primitive

- **RSA:** the cluster performs the **full OAEP decrypt**. Returning raw `c^d mod N` for the driver
  to unpad would build a textbook Bleichenbacher/Manger oracle. RSAES-OAEP-SHA256 is fully
  standardized, so server-side carries no byte-compat risk.
- **ECIES (v1.5+):** the cluster performs **only the ECDH** — `EcdhDerive(key_id, ephemeral_point)
  → shared_point`. The driver completes KDF2 + HMAC + AES-128-CBC using BouncyCastle's own
  `IESEngine` with a stub `BasicAgreement` returning the precomputed Z. Two wins: the byte-exact
  reference implementation stays in the JVM next to Canton's own encryptor (no reimplementation of
  BC's framing in Rust), and **the wire contract is identical for v1.5 (whole key) and v2
  (threshold)** — promoting to real threshold becomes a server-side change plus a config flag.
  Mandatory: strict point validation (on-curve, not infinity, correct encoding) and refusing
  `EcdhDerive` on keys whose recorded usage is signing.

> **RSA: shipped as described.** `Decrypt` performs the full RSAES-OAEP-SHA256 operation server-side
> and returns plaintext; raw `c^d mod N` is never exposed. The ciphertext length is checked against
> the 256-byte RSA-2048 bound before the key is touched, and every failure — wrong length, wrong
> key, bad padding — returns the same opaque error.
> **ECIES: shipped as described (v1.5).** The cluster returns `Z = x(d·V)` and nothing else; the
> driver completes KDF2 + AES-128-CBC + HMAC-SHA256 in BouncyCastle's `IESEngine`, assembled exactly
> as `IESCipher.ECIESwithSHA256andAESCBC` assembles it, with the agreement swapped for one that
> returns the cluster's `Z` for the one `V` it was computed for. Point validation is a 65-byte
> uncompressed-only gate on the cluster (aws-lc would accept compressed and hybrid points) plus
> aws-lc's on-curve check; the driver repeats both with BouncyCastle before calling the cluster.
> "Refusing `EcdhDerive` on keys whose recorded usage is signing" is enforced by the spec: the only
> EC spec is `ec-p256-ecies`, an encryption key, and the Canton import refuses a P-256 signing key.
> One upstream property surfaced: Canton's ECIES MACs the ciphertext but not the IV, so the first
> plaintext block is malleable; the driver matches Canton rather than diverge
> ([`hosted-keys.md`](hosted-keys.md) §5).

### Replication

Wrap key material to a **per-node distribution key derived from that node's seal secret**:

```
dist_sk_j = HKDF-SHA256(ikm = node j's seal secret, salt = "rutli-dist/node-{j}", info = "x25519-v1")
```

HPKE base mode (DHKEM-X25519, HKDF-SHA256, AES-256-GCM) to `dist_pk_j`, AAD binding
`(cluster_id, key_id, spec, usage, recipient_id)` so a wrapped blob cannot be replayed to a
different recipient or key. Use the `hpke` crate (rozbb, 0.14.0 — zero advisories ever, same
`p256`/`aes-gcm`/`hkdf` tree). **Avoid `hpke-rs`** (RUSTSEC-2026-0071, CVSS 9.3 nonce reuse, and the
vulnerable releases were never yanked).

> **Changed in implementation, in three places.**
>
> 1. The envelope is HPKE-*shaped* but hand-rolled on `x25519-dalek` + `hkdf` + `aes-gcm`, not the
>    `hpke` crate: ephemeral X25519 → HKDF-SHA256 (the `info` string binds both the ephemeral and
>    the recipient public key) → AES-256-GCM. Call it that, not "HPKE" — it is not RFC 9180 and does
>    not interoperate with an RFC 9180 implementation. The envelope carries its own `wrap_version`
>    on the wire, so swapping in real HPKE later is a version bump, not a migration. `hpke-rs`
>    remains excluded for the reason given above.
> 2. The AAD binds `(cluster_id, key_id, spec, recipient_id)` — **no `usage`**. v1 has no usage
>    dimension at all: `GenerateKey` takes only `key_id` and `spec`, because with RSA-decrypt and
>    AES-symmetric there is nothing to disambiguate. `usage` was to come back in v1.5, where refusing
>    `EcdhDerive` on a signing key needs it.
> 3. `cluster_id` needed no new config field: it is the first 8 bytes of SHA-256 over the cluster CA
>    certificate, so it changes exactly when the trust domain changes and an envelope can never be
>    replayed into another deployment. (Without TLS it is the literal `plaintext-dev`, which is dev
>    only by construction.)

Why derived rather than freshly generated: no first-boot ordering problem, and each node can
self-check at startup that its derived `dist_pubkey` matches the one pinned in config — catching a
wrong-secret/wrong-mount *before* any key is generated, which is exactly the class of failure that
caused the incident. Pinning `peers[].dist_pubkey` also becomes the first cryptographic binding of
material to a *specific* node identity in the system (today the shared `rutli-cosigner` SAN means
peer 2 is not distinguishable from peer 3 or from the driver).

Note a fact worth stating plainly in the threat model: `Sealer::from_master_secret` uses the node id
only as an HKDF *salt* over a **shared** master secret, so any node can already derive any peer's
DEK. Moving to per-node seal secrets upgrades this design's property with no code change.

> **Derivation shipped; the pinning and the startup self-check did not.** `peers[]` still carries
> only `identifier` and `endpoint`. On the pull path (`FetchKey`) the responder derives the
> caller's distribution key locally from the node id in its client certificate, never from a
> recipient named in the request — so a peer cannot ask for material addressed elsewhere. On the
> push path (`ReplicateKey`) the leader takes the recipient's key from that peer's `NodeInfo`
> reply, which an allowlisted-but-hostile cosigner could answer with a key of its choosing; the
> leader could derive the same value locally instead, which is exactly what pinning would make
> unconditional.
>
> The consequence worth naming: without the pinned value there is no startup check that this node's
> derived `dist_pubkey` matches what the cluster expects, so a wrong-secret or wrong-mount is still
> only discovered when an operation fails — and that discovery-too-late is the incident class this
> feature exists to close. Smallest useful next step, ahead of per-node seal secrets.

**Write quorum: 2-of-3 by default, with anti-entropy mandatory.** The two passes split here (3/3 vs
2/3). Resolution: 3/3 would mean you cannot rotate an encryption key while any node is down, which
contradicts the cluster's own 2-of-3 fault model — but 2/3 is only safe with (a) a periodic
anti-entropy sweep that pushes *and* pulls, (b) on-demand read-repair before returning `NOT_FOUND`,
and (c) a `rutli_key_replicas < 3` alert. If any of those three is not shipped, default to 3/3.

> **Shipped at 2-of-3, with all three preconditions now met.** (a) the sweep runs every
> `anti_entropy_interval_secs` (default 300), pulling what this node lacks and pushing what a peer
> lacks; (b) every serving path (`Decrypt`, `PublicKey`, `KeyInfo`, both symmetric ops) read-repairs
> before it can return `NOT_FOUND`. A write that lands below quorum is purged cluster-wide and the
> id left free for a clean retry, rather than leaving one lonely copy.
>
> (c) shipped after the fact: the sweep publishes `rutli_key_replicas` — the fewest cosigners
> holding any one hosted key, recounted *after* repair so the gauge reflects the healed state — and
> the shipped rules alert below the cluster size (warning) and below the write quorum (critical).
> The count is also returned in `GenerateKeyReply` and `KeyInfoReply`. With that in place the 2-of-3
> default is no longer provisional by this document's own rule. The gauge is absent, not zero, until
> the first sweep sees a hosted key; zero would page an idle cluster instantly.
>
> **Config plumbing, fixed after the fact:** `hosted_keys.write_quorum` was parsed and
> range-validated at load while the Signer service passed the compiled-in default (2) to the
> orchestrator, so an operator who set `write_quorum: 3` silently got 2 — the wrong direction for a
> knob whose whole purpose is to be more conservative than the default. The configured value is now
> carried on `SignerSvc` as a required field, so it cannot be dropped again without a compile error.

**Hard rule, enforced in code: anti-entropy and `FetchKey` cover hosted keys ONLY, never FROST
shares.** Copying node 1's FROST share to node 3 would give two nodes the same share and silently
break the threshold scheme.

Hosted keys are **create-once-immutable**: a `key_id` maps to one key forever; Canton rotates by
minting a new id plus a topology transaction. That removes all conflict resolution from
anti-entropy — a key either exists or does not, and divergence is a hard error, not a merge.

> **Both shipped.** The separation is enforced at the store, not just at the caller: `list_hosted`
> skips FROST records so a share is never even named to a peer, the typed loads refuse the wrong
> kind in both directions, and the hosted delete path refuses a FROST share outright. Immutability
> is enforced in `hosted_store`, which refuses to overwrite an existing id whose material commits
> differently; the anti-entropy sweep logs the conflict and increments
> `rutli_anti_entropy_conflicts_total` rather than reconciling. Nodes compare a keyed commitment
> (scoped to the cluster master, so it means nothing off-cluster) rather than the material itself.

### Storage

One directory, one file per key, reusing the existing sealed envelope and the existing atomic
write path (tmp → fsync → rename → fsync dir). The envelope *plaintext* becomes a tagged union
(`kind: "frost-ed25519" | "hosted"`), with `#[serde(default)]` so existing share files parse
unchanged. Keeping hosted keys inside `data_dir/keys/` means the existing `backup`/`restore`
subcommands cover them for free — a sibling directory would be silently skipped, which is the exact
failure class being fixed. `KeyStore::reseal_plaintext_shares` must become type-aware first.

**Do not claim secure erasure on delete.** On COW filesystems, wear-levelled SSDs and snapshotted
PVs, removing a file does not destroy bytes. Honest statement: delete removes the only referenced
copy; true destruction requires master-secret rotation (a `rewrap` ceremony that re-seals every live
key under a new master, rendering old sealed blobs — including in backups — undecryptable).

> **Shipped, with the tagged union simplified to one tag.** One directory, one file per key, one
> sealed envelope, the same tmp → fsync → rename → fsync-dir write path. Only hosted keys carry
> `"kind": "hosted"`; anything untagged is a FROST share, which is the same backward compatibility
> the `frost-ed25519` tag would have bought without writing a tag no reader needs. `backup` and
> `restore` therefore cover hosted keys with no change. `reseal_plaintext_shares` became
> record-aware, as required — it re-seals a hosted key through the hosted path instead of parsing
> it as a share. The delete caveat above is repeated in the code, and no API claims erasure.
>
> **Changed after the end-to-end run:** `list_hosted` first failed the whole listing on an
> unreadable key file (one left sealed under a rotated master secret), on the reasoning that a key
> which cannot be opened must not look like a deleted one to anti-entropy. That is worse, not safer
> — it stops anti-entropy for every *healthy* key too, so one damaged file halts self-healing
> cluster-wide. Such a file is now logged, counted by `rutli_unreadable_key_files_total`, and
> skipped. Skipping is safe because absence from a listing never causes a delete (peers only push
> keys a listing lacks) and a push onto an unreadable local file still fails closed in
> `hosted_store` rather than overwriting it. The counter is the thing to alert on: a non-zero value
> means some key is not being replicated or repaired, and nothing else will say so.
>
> **Not shipped:** the `rewrap` ceremony that would make destruction real. Until it exists, "delete"
> means "unreferenced", and the disaster-recovery answer to a suspected master-secret compromise is
> still a full re-key, not a rewrap.

### API and driver routing

New Signer RPCs: `GenerateKey`, `PublicKey`, `KeyInfo`, `DeleteKey`, `Decrypt`, `SymmetricEncrypt`,
`SymmetricDecrypt`, `Capabilities` (+ `EcdhDerive` in v1.5). New Peer RPCs: `ReplicateKey`,
`FetchKey`, `ListKeys`, `PurgeKey`, `NodeInfo`. One `GenerateKey(key_id, spec, usage)` rather than
per-type generators; `key_id` is caller-supplied so retries are idempotent (leader repairs an
existing key rather than failing).

`Capabilities` lets the driver learn the cluster's supported specs at startup instead of hardcoding
them, which is what allows v1.5 to add `EcP256` without a driver release.

> **Shipped, minus `usage`; `EcdhDerive` shipped with v1.5.** Usage is carried by the spec instead
> (`ec-p256-ecies` is an encryption key; a P-256 signing key would get its own spec), so the API and
> the AAD needed no new field. `GenerateKey(key_id, spec)` is
> idempotent as designed: a repeat for an existing id returns the existing key with `created: false`
> and repairs replicas, and a repeat under a *different* spec is an error rather than a silent
> replacement. Every hosted-key Signer RPC is behind `signer_allowlist` except `Capabilities`,
> which joins `Health` as deliberately open: it reveals only which algorithm names this cluster
> supports, and the driver needs it before it can do anything else. Every Peer RPC is behind
> `peer_allowlist`, and `FetchKey` additionally derives the recipient from the client certificate
> rather than from the request body.

Driver: key-id prefixes `frost-` (threshold Ed25519) and `rutli-` (cluster-hosted) both route to the
cluster; anything else goes to the delegate. `delegate = "none"` becomes reachable. **No automatic
fallback to the delegate on `NOT_FOUND`** — that would silently re-create split custody and could
reproduce the incident class. Failover across endpoints stays restricted to `UNAVAILABLE` /
`DEADLINE_EXCEEDED`; read-repair is what makes `NOT_FOUND` authoritative.

> **Shipped, and exercised against a real participant** (see *What v1 is, concretely*).
> `FrostBackend` routes both prefixes, `frost.hosted-keys` gates it, and `delegate = "none"` is
> served by a `NoDelegateBackend` that fails loudly and names the key id — a key that is neither
> `frost-` nor `rutli-` is a routing bug, not something to paper over. `frost.delegate = "none"`
> without `hosted-keys = true` is refused at startup, since nothing would then serve the encryption
> keys. Failover stays restricted to `UNAVAILABLE`/`DEADLINE_EXCEEDED`, and there is no fallback to
> the delegate on `NOT_FOUND`.
>
> Two adaptations worth recording. Canton's SPI does not let a caller name a key, so the driver
> mints the `rutli-` id itself (kind, sanitized key name, UUID) — `GenerateKey` idempotency then
> covers a *retry of the same call*, not two independent calls, which is the property that matters.
> And `Capabilities` failing (older cluster, or the cluster unreachable at startup) falls back to
> the configured expectation rather than to "no hosted specs": silently advertising fewer specs to
> Canton would present as a config bug and could steer keys to the delegate unnoticed.

Relevant SPI facts (verified in Canton source): there is **no `encryptAsymmetric`** — Canton encrypts
in software with the public key, so only `decryptAsymmetric` is required. Asymmetric ciphertext in is
capped at 256 bytes and plaintext out at 190 (exactly RSA-2048-OAEP dimensions). The KMS symmetric
key's algorithm is opaque to Canton — the driver picks it, so AES-256-GCM is fine (Canton's *own*
internal `SymmetricKeyScheme` is AES-128-GCM; different concern).

### Rate limiting and auditing for decrypt

Decrypt is on the per-transaction hot path — unlike signing. Therefore: **no approval gating**
(`ApprovalGate` stays sign-only), **no per-op fsync journaling** (`SigningJournal.record` fsyncs per
call; fine at topology-signing rates, not at view-decryption rates). Do add a **cosigner-side**
per-key token bucket — the driver-side limiter is bypassable by anyone holding the Signer cert — to
bound a compromised cert's bulk-decryption throughput and to generate an alert signal.

Pre-existing hazard to measure first: `RutliDriver.audited` already wraps `decryptAsymmetric`, so
with `audit-log-path` set, every decrypt takes a synchronous hash-chain fsync today.

> **The two omissions shipped; the one addition did not.** Decrypt has no approval gating
> (`ApprovalGate` remains sign-only) and no per-op journaling, as designed. The cosigner-side
> per-key token bucket does **not** exist yet, so a stolen Signer certificate is currently bounded
> only by the driver-side limiter — which is precisely the limiter the design notes is bypassable
> by anyone holding that certificate. `rutli_hosted_key_ops_total{op,result}` gives the alerting
> signal, but nothing throttles. Highest-value security follow-up in this section.
>
> The `audited` fsync hazard is still unmeasured: no decrypt-path numbers in
> [`performance.md`](performance.md) yet.

## Roadmap

| Phase | Content | New crypto risk |
|---|---|---|
| **P0** | Peer-API allowlist ✅, type-aware reseal ✅, peer-channel deadlines (still open) | none |
| **v1** ✅ | Hosted RSA-2048 + AES-256-GCM, replicated + sealed; `delegate = "none"` possible. RSA decrypt via `aws-lc-rs`/OpenSSL, **not** the `rsa` crate | none — standard primitives |
| **v1.5** ✅ | `EcdhDerive` + hosted EC-P256 keys (still whole-key); driver-side DEM via BouncyCastle `IESEngine`. Advertise `EcP256`/ECIES to steer Canton off RSA | low — no new crypto in Rust |
| **v2** | **Threshold ECIES**: `frost-p256` DKG + Lagrange partial-point ECDH + DLEQ proofs. **Wire contract unchanged from v1.5** — server-side only | moderate, well-understood, no nonce state |
| **v3** | Threshold ECDSA (`cggmp21`, LFDT, Kudelski-audited) only if a synchronizer requires EC signing | per crate maturity |
| **never** | Threshold RSA — deprecate RSA in favour of ECIES where the synchronizer permits, and say so publicly | — |

The load-bearing property: **v1.5 and v2 share a wire contract**, so "replicated today, threshold
tomorrow" is a server upgrade and a config flag, not an API migration.

## Open questions

None of these blocked v1, and shipping v1 answered none of them. v1.5 answered the first two.

- Live Global Synchronizer `requiredEncryptionSpecs` — does it admit `EcP256`/ECIES? **Answered:
  yes.** Splice SVs use Canton's JCE defaults for static synchronizer parameters on every network
  (`apps/sv/.../LocalSynchronizerNode.scala:94`), which allow `EcP256` and `Rsa2048`, and DevNet and
  TestNet validators run ECIES keys today ([`roadmap-migration.md`](roadmap-migration.md)).
- Byte-exact BouncyCastle `ECIESwithSHA256andAES-CBC` framing. **Answered: interoperates.** Canton's
  own `JcePureCrypto` encrypts and the driver decrypts in the upstream conformance suite
  (`RutliDriverFrostConformanceTest`, `CONFORMANCE=1`) and on a live 3.6.1 participant
  (`scripts/e2e-ecies-hosted.sh`); `FrostEciesSpec` adds a BouncyCastle differential over every
  plaintext length up to Canton's 256-byte bound and a `Z` with a leading zero byte.
- Whether `owner_to_key_mappings.rotate_key` succeeds when the outgoing encryption key's private
  half is **missing** — the incident-recovery path depends on it. Test on a scratch participant.
  **Still open**, and now the *only* untested step in that path: sealed disk persistence, cluster
  hosting and the export artifact all reduce how often a key goes missing, none answers what
  recovery looks like once it has.
- `vsss-rs` audit claims (LIT/Turnkey-funded per its README) have no public report. **Still open**,
  but unblocking: v1 uses no secret sharing outside `frost-ed25519`, and the v2 sketch takes its
  Shamir shares from `frost-p256` rather than `vsss-rs`.

### Settled by the implementation

- **Write quorum default:** 2-of-3, with rollback below quorum, and the `rutli_key_replicas` alert
  the design made a condition of that default now shipped. The configured `write_quorum` is
  honoured.
- **Wrapping construction:** hand-rolled ephemeral X25519 → HKDF-SHA256 → AES-256-GCM rather than
  the `hpke` crate; versioned on the wire so it can be replaced.
- **Cluster identity for the AAD:** derived from the CA certificate, not a new config field.
- **Key usage:** dropped from the v1 API and AAD entirely, and v1.5 did not need it back: the spec
  name carries it (`ec-p256-ecies`), so `EcdhDerive` is refused for every key that is not an ECIES
  encryption key.
- **Where hosted keys live:** the same `data_dir/keys/` as FROST shares, tagged by `kind`, so
  `backup`/`restore` cover them and untagged legacy files still parse as shares.
- **Portability, which this design did not cover:** offline, passphrase-protected `export-key` /
  `import-key`, deliberately not an RPC — the two failures `backup` cannot cover are a lost seal
  master secret and a move to another cluster or KMS.
- **An unreadable key file:** logged, counted, skipped from the inventory — never fatal to the
  listing, because that would stop anti-entropy for every healthy key too.

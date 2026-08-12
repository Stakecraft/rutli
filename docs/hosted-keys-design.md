# Cluster-hosted keys (non-FROST key material) — design

**Status: design accepted, not yet implemented.** Written after the 2026-08-12 DevNet incident in
which a participant restart destroyed a heap-only RSA encryption key. Two independent design passes
plus a Rust threshold-crypto crate survey fed this document; where they disagreed, the resolution is
called out.

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

## Decision 3 — the ECIES lever (why the roadmap inverts)

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

Why derived rather than freshly generated: no first-boot ordering problem, and each node can
self-check at startup that its derived `dist_pubkey` matches the one pinned in config — catching a
wrong-secret/wrong-mount *before* any key is generated, which is exactly the class of failure that
caused the incident. Pinning `peers[].dist_pubkey` also becomes the first cryptographic binding of
material to a *specific* node identity in the system (today the shared `rutli-cosigner` SAN means
peer 2 is not distinguishable from peer 3 or from the driver).

Note a fact worth stating plainly in the threat model: `Sealer::from_master_secret` uses the node id
only as an HKDF *salt* over a **shared** master secret, so any node can already derive any peer's
DEK. Moving to per-node seal secrets upgrades this design's property with no code change.

**Write quorum: 2-of-3 by default, with anti-entropy mandatory.** The two passes split here (3/3 vs
2/3). Resolution: 3/3 would mean you cannot rotate an encryption key while any node is down, which
contradicts the cluster's own 2-of-3 fault model — but 2/3 is only safe with (a) a periodic
anti-entropy sweep that pushes *and* pulls, (b) on-demand read-repair before returning `NOT_FOUND`,
and (c) a `rutli_key_replicas < 3` alert. If any of those three is not shipped, default to 3/3.

**Hard rule, enforced in code: anti-entropy and `FetchKey` cover hosted keys ONLY, never FROST
shares.** Copying node 1's FROST share to node 3 would give two nodes the same share and silently
break the threshold scheme.

Hosted keys are **create-once-immutable**: a `key_id` maps to one key forever; Canton rotates by
minting a new id plus a topology transaction. That removes all conflict resolution from
anti-entropy — a key either exists or does not, and divergence is a hard error, not a merge.

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

### API and driver routing

New Signer RPCs: `GenerateKey`, `PublicKey`, `KeyInfo`, `DeleteKey`, `Decrypt`, `SymmetricEncrypt`,
`SymmetricDecrypt`, `Capabilities` (+ `EcdhDerive` in v1.5). New Peer RPCs: `ReplicateKey`,
`FetchKey`, `ListKeys`, `PurgeKey`, `NodeInfo`. One `GenerateKey(key_id, spec, usage)` rather than
per-type generators; `key_id` is caller-supplied so retries are idempotent (leader repairs an
existing key rather than failing).

`Capabilities` lets the driver learn the cluster's supported specs at startup instead of hardcoding
them, which is what allows v1.5 to add `EcP256` without a driver release.

Driver: key-id prefixes `frost-` (threshold Ed25519) and `rutli-` (cluster-hosted) both route to the
cluster; anything else goes to the delegate. `delegate = "none"` becomes reachable. **No automatic
fallback to the delegate on `NOT_FOUND`** — that would silently re-create split custody and could
reproduce the incident class. Failover across endpoints stays restricted to `UNAVAILABLE` /
`DEADLINE_EXCEEDED`; read-repair is what makes `NOT_FOUND` authoritative.

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

## Roadmap

| Phase | Content | New crypto risk |
|---|---|---|
| **P0** | Peer-API allowlist ✅ (shipped), peer-channel deadlines, type-aware reseal | none |
| **v1** | Hosted RSA-2048 + AES-256-GCM, replicated + sealed; `delegate = "none"` possible. RSA decrypt via `aws-lc-rs`/OpenSSL, **not** the `rsa` crate | none — standard primitives |
| **v1.5** | `EcdhDerive` + hosted EC-P256 keys (still whole-key); driver-side DEM via BouncyCastle `IESEngine`. Advertise `EcP256`/ECIES to steer Canton off RSA | low — no new crypto in Rust |
| **v2** | **Threshold ECIES**: `frost-p256` DKG + Lagrange partial-point ECDH + DLEQ proofs. **Wire contract unchanged from v1.5** — server-side only | moderate, well-understood, no nonce state |
| **v3** | Threshold ECDSA (`cggmp21`, LFDT, Kudelski-audited) only if a synchronizer requires EC signing | per crate maturity |
| **never** | Threshold RSA — deprecate RSA in favour of ECIES where the synchronizer permits, and say so publicly | — |

The load-bearing property: **v1.5 and v2 share a wire contract**, so "replicated today, threshold
tomorrow" is a server upgrade and a config flag, not an API migration.

## Open questions before implementation

- Live Global Synchronizer `requiredEncryptionSpecs` — does it admit `EcP256`/ECIES? Decides whether
  the v1.5/v2 lever is usable on mainnet at all.
- Byte-exact BouncyCastle `ECIESwithSHA256andAES-CBC` framing — components are confirmed
  (`ECDHBasicAgreement` + KDF2-SHA256 + HMAC-SHA256, IV prepended by Canton itself), but interop
  needs a JVM-encrypt → driver-decrypt differential test, not documentation.
- Whether `owner_to_key_mappings.rotate_key` succeeds when the outgoing encryption key's private
  half is **missing** — the incident-recovery path depends on it. Test on a scratch participant.
- `vsss-rs` audit claims (LIT/Turnkey-funded per its README) have no public report.

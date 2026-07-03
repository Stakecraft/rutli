# Architecture

Open-source, self-hosted **MPC-KMS for Canton Network / Splice authority keys**. The operator
runs everything; no SaaS, no mandatory cloud KMS. Positioning: the "Web3Signer/Teku of Canton".

**Product model: [Horcrux](https://github.com/strangelove-ventures/horcrux) for Canton.** Horcrux
is the battle-tested threshold signer for CometBFT validator keys: the validator node holds no key;
a t-of-n cosigner cluster signs on its behalf. This project is the same shape for Canton/Splice
nodes, with one forced difference: CometBFT exposes a network remote-signer protocol, Canton does
not — Canton's seam is the in-process KMS Driver SPI, so our "client side" is a jar inside the
participant JVM rather than a standalone daemon. Everything behind that seam is Horcrux-shaped.

Complementary, not competing: Splice **SV** nodes also run CometBFT, and stock Horcrux can likely
serve that consensus key as-is. Plain **validator** nodes (our v1 target) have no CometBFT — only
the Canton participant keys Horcrux cannot touch. Horcrux covers the SV consensus key; we cover the
Canton keys.

## Integration seam — no Canton fork

Canton exposes a public **KMS Driver SPI** (since v2.9, active package
`com.digitalasset.canton.crypto.kms.driver.api.v1`). A KMS is a Scala/JVM `.jar` that implements
two traits and is discovered via Java `ServiceLoader`. Canton calls the driver for every
private-key operation; the private key never enters the Canton process.

- `KmsDriverFactory` — entry point; produces a configured `KmsDriver`.
- `KmsDriver` — `generateSigningKeyPair`, `generateEncryptionKeyPair`, `generateSymmetricKey`,
  `sign`, `decryptAsymmetric`, `encryptSymmetric`, `decryptSymmetric`, `getPublicKey`,
  `keyExistsAndIsActive`, `deleteKey`, `health`, plus `supported*Specs` capability sets.

Enabled with `crypto.provider = kms` and **external key storage** mode (keys generated + held
entirely in the KMS; all sign/decrypt delegated — protects keys at rest *and* in use).

Reference material (OSS, `github.com/digital-asset/canton/community/`): `kms-driver-api` (the SPI),
`aws-kms-driver` (full example), `mock-kms-driver` (software reference impl), `kms-driver-testing`
(the `KmsDriverTest` / `KmsDriverFactoryTest` conformance suite — we get a free test harness).

## Component model

```
Canton node (crypto.provider = kms)
   │  loads our KmsDriver .jar via ServiceLoader
   ▼  KMS Driver SPI (in-JVM)
KMS Driver shim (Scala/JVM)  ── policy · M-of-N quorum · tamper-evident audit log
   │  routes by KEY TYPE
   ├── namespace/identity (Ed25519)      → FROST MPC cluster      [Phase 2]
   ├── protocol/sequencer (ECDSA P-256/384) → threshold ECDSA (DKLS23) or HSM  [Phase 4]
   └── encryption (ECIES-P256 / RSA-OAEP) → HSM / enclave (never threshold)     [Phase 1]
```

Everything runs inside the **operator-controlled environment**. The MPC cluster is `t`-of-`n`
shares across **isolated hosts/accounts/regions, all run by the single operator** (self-custody).

## The `KmsBackend` abstraction

The shim's one important internal seam. The `KmsDriver` implementation contains **no crypto** — it
enforces policy/quorum/audit, then delegates to a `KmsBackend`:

```
trait KmsBackend {
  def generateSigningKey(spec): KeyId
  def sign(keyId, data, algo): Signature
  def getPublicKey(keyId): PublicKey
  def decryptAsymmetric(keyId, ciphertext, algo): Plaintext
  ...
}
```

Backends, added over the phases:
- `SoftwareBackend` — Phase 0 only. In-process software crypto (BouncyCastle). Proves the Canton
  integration end-to-end. **Never for production.** ✅ done.
- `HsmBackend` (PKCS#11) — Phase 1. Keys sealed in an HSM/enclave (SoftHSM → YubiHSM / Securosys /
  Nitro Enclave). FIPS 140-3 story off-the-shelf. ✅ implemented, verified vs SoftHSM. See
  [phase-1-hsm.md](phase-1-hsm.md).
- `FrostBackend` — Phase 2. gRPC to the Rust FROST-ed25519 MPC cluster for the namespace key;
  delegates everything else to the HSM/software backend. ✅ implemented, live e2e verified against a
  3-node cluster (DKG + threshold sign, JDK-verified). mTLS is a follow-up. See
  [phase-2-frost.md](phase-2-frost.md).
- `DklsBackend` — Phase 4. Threshold ECDSA P-256/P-384 for protocol/sequencer keys.

Routing by key type lets each key sit on the right backend simultaneously (e.g. namespace key on
FROST, encryption key on HSM) behind one Canton-facing driver.

## Phase 2 MPC cluster — two Horcrux-informed decisions

**1. DKG, never key-sharding.** Horcrux shards an *existing* `priv_validator_key.json`
(trusted-dealer style) because Cosmos validators already have keys. That path is useless here:
Canton does not support migrating an existing node into KMS mode (the namespace root key cannot be
rotated), so keys must be **born inside the KMS**. The cluster therefore runs distributed key
generation (DKG) at node bootstrap — the full private key never exists anywhere, not even for a
moment at creation. Strictly stronger than sharding, and the only option Canton leaves open anyway.

**2. Cluster-side coordination (leader election), not a driver-side coordinator.** Horcrux's
cosigners elect a leader (Raft) and orchestrate signing rounds among themselves; the validator-facing
side is a dumb client. We adopt the same shape: the share nodes coordinate the FROST rounds
internally, and the `FrostBackend` in the driver just submits `sign(hash, keyId)` to the cluster and
awaits the aggregated signature. This keeps round orchestration and nonce-session state out of the
Canton JVM, survives driver/node restarts cleanly, and makes the cluster independently testable. A
compromised or crashed client can stall signing but never touches key material or nonce state.

## Crypto choices (with rationale)

| Canton key | Algo (format) | Backend | Why |
|---|---|---|---|
| Namespace / identity root | Ed25519 (`concat`, raw 64-byte R‖S) | **FROST-ed25519** (ZF `frost-ed25519`) | RFC 9591; emits standard RFC 8032 sig Canton verifies natively. Audited (NCC + Least Authority). The one key where "no node holds the whole secret" clearly earns MPC. |
| Protocol / sequencer auth | ECDSA P-256/P-384 (`der`) | **DKLS23** (Silence Labs) or HSM | OT-based, avoids the Paillier/TSSHOCK class that broke GG18/GG20/CGGMP. ToB-audited. **Pin DKLS23, not DKLS24** (2026 OT-count caveat). Confirm P-384 instantiation. |
| Asymmetric encryption | ECIES-P256 / RSA-2048-OAEP | **HSM / enclave — never MPC** | Threshold decryption matching Canton's exact OAEP/ECIES framing is research-grade + unaudited. HSM does it natively. |

Note: AWS KMS + YubiHSM now support Ed25519 natively, so MPC here is a **trust-distribution**
choice (no single trusted box/vendor), not an algorithm necessity. An all-HSM build is fully
Canton-compatible and FIPS-capable — which is exactly why Phase 1 ships on HSM.

## Hard constraints (design around these)

- **Namespace root key is NOT rotatable.** Migrating an existing node from DB-keys → KMS is
  unsupported by Canton. This product targets **freshly-deployed nodes** (or a full node rebuild).
- **Key loss = irrecoverable loss** of all Canton Coin for parties hosted under that namespace.
  No slashing in Canton, but compromise = "SV failure" that cuts the network BFT buffer until the
  SV is offboarded. DR / share backup is a first-class product concern, not an afterthought.
- **FROST nonce hygiene** is the top operational risk: never reuse a signing-nonce commitment,
  require good RNG, keep strict per-session nonce state, enforce canonical encoding of the group
  public key and `R` at the boundary. Not a verifier-compat risk — a discipline risk.

## Phased delivery

- **Phase 0** — spike: `SoftwareBackend` driver green against the conformance suite; Canton devnet
  node signs a topology transaction through the driver end-to-end. See `phase-0-spike.md`.
- **Phase 1** — production `KmsDriver` on `HsmBackend`; all key types; FIPS-capable.
- **Phase 2** — `FrostBackend`: Rust FROST-ed25519 MPC cluster for the namespace key; DKG,
  `t`-of-`n` signing, proactive share refresh.
- **Phase 3** — policy/quorum engine, RBAC/separation-of-duties, hash-chained audit log,
  replay/equivocation guards, share backup/restore + geo-distribution, key-ceremony runbook.
- **Phase 4** — `DklsBackend`: threshold ECDSA (P-256/P-384) for protocol/sequencer keys.
- **Phase 5** — Wallet Gateway signing-driver SPI (second seam); SOC2/ISO/DORA evidence pack;
  published third-party MPC audit.

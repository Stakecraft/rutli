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
   │  routes by KEY TYPE — in the driver, by key-id prefix
   ├── namespace/identity (Ed25519)  `frost-…` → cosigner cluster: THRESHOLD t-of-n  [Phase 2]
   ├── encryption (RSA-2048-OAEP)    `rutli-…` → cosigner cluster: REPLICATED keys   [hosted v1]
   ├── symmetric wrap (AES-256-GCM)  `rutli-…` → cosigner cluster: REPLICATED keys   [hosted v1]
   ├── protocol/sequencer (ECDSA P-256/384)    → threshold ECDSA (DKLS23) or HSM     [Phase 4]
   └── anything else                           → delegate: HSM (PKCS#11) | software  [Phase 1]
```

Two different protections now share one cluster, and the difference is not cosmetic. The namespace
key is a real `t`-of-`n` FROST share set — no node ever holds it. The hosted keys (`rutli-…`) are
**whole keys replicated to every cosigner**, sealed at rest per node, and any single node can serve
a decrypt: that is replication, not MPC. What it buys is covered below. The HSM delegate remains
available for both classes but is experimental (verified on SoftHSM only, outside the audit scope); with hosted keys enabled, `delegate = "none"` also becomes
reachable — no HSM, and no key material on the participant host at all.

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
- `SoftwareBackend` — Phase 0. In-process software crypto (BouncyCastle). Proves the Canton
  integration end-to-end. Since the 2026-08-12 DevNet incident its keys persist as sealed files
  (`software { dir, seal-secret-env }`) instead of living only in JVM heap — but it is still a
  development backend, not a production one. ✅ done.
- `HsmBackend` (PKCS#11) — Phase 1. Keys sealed in an HSM/enclave (SoftHSM → YubiHSM / Securosys /
  Nitro Enclave). FIPS 140-3 story off-the-shelf. ✅ implemented, verified vs SoftHSM. See
  [phase-1-hsm.md](phase-1-hsm.md).
- `FrostBackend` — Phase 2. gRPC to the Rust cosigner cluster. ✅ implemented, live e2e verified
  against a 3-node cluster (DKG + threshold sign, JDK-verified) — with mutual TLS across the mesh
  and from the driver, and driver-side failover. See [phase-2-frost.md](phase-2-frost.md).
  With `frost.hosted-keys = true` it routes **both** id prefixes to the cluster: `frost-` (threshold
  Ed25519) and `rutli-` (cluster-hosted encryption and symmetric keys); everything else goes to
  `frost.delegate` (`hsm` | `software` | `none`). ✅ shipped with the cosigner-side v1 below and
  verified end to end on a Canton 3.5.6 participant with no local key state
  ([`deploy/devnet/canton-hosted.conf`](../deploy/devnet/canton-hosted.conf)). The driver asks the
  cluster for its `Capabilities` at startup rather than hardcoding the spec list. There is
  deliberately **no automatic fallback to the delegate on `NOT_FOUND`** — that would silently create
  split custody and could reproduce the incident class. Endpoint failover never triggers on
  `NOT_FOUND` either: it covers a node that is down (`UNAVAILABLE` / `DEADLINE_EXCEEDED`) and, for
  operations safe to re-issue (sign, reads, decrypt, symmetric crypto), a leader that answers
  `INTERNAL` / `UNKNOWN`; read-repair is what makes `NOT_FOUND` authoritative.
- `DklsBackend` — Phase 4. Threshold ECDSA P-256/P-384 for protocol/sequencer keys.

Routing by key type lets each key sit on the right backend simultaneously (e.g. namespace key on
FROST threshold, encryption key cluster-hosted or on an HSM) behind one Canton-facing driver.

## Phase 2 MPC cluster — two Horcrux-informed decisions

**1. DKG by default; sharding only to migrate.** Horcrux shards an *existing*
`priv_validator_key.json` (trusted-dealer style) because Cosmos validators already have keys. For a
new Canton node we do better: keys are **born inside the KMS**. The cluster runs distributed key
generation (DKG) at node bootstrap — the full private key never exists anywhere, not even for a
moment at creation. That is strictly stronger than sharding and stays the recommended path.

Canton 3.5+ does document moving an existing participant onto a KMS: export its keys, start a new
participant under the same identity, register the keys by KMS id. Digital Asset documents this for
AWS/GCP KMS; carrying it to Rütli means splitting an existing namespace key into FROST shares
(trusted-dealer, Horcrux style). That path ships in v0.4.0 as the split ceremony —
[split-ceremony.md](split-ceremony.md). An imported key is weaker than a DKG key: it once lived
whole on a server and in that node's backups, and splitting it cannot undo that exposure.

**2. Cluster-side coordination, not a driver-side coordinator.** Horcrux's cosigners coordinate
signing among themselves and the validator-facing side is a dumb client. We adopt the same shape,
but deliberately **without** a Raft/consensus layer: the node the driver contacts leads that request
(static leader), the driver fails over to another cosigner if it's unreachable or cannot serve the
request (`INTERNAL` / `UNKNOWN` — never for a DKG ceremony), and the share nodes
coordinate the FROST rounds internally. FROST sessions are independent, so no replicated log is
needed (see phase-2-frost.md). The `FrostBackend` just submits `sign(hash, keyId)` and awaits the
aggregated signature. This keeps round orchestration and nonce-session state out of the
Canton JVM, survives driver/node restarts cleanly, and makes the cluster independently testable. A
compromised or crashed client can stall signing but never touches key material or nonce state.

## Crypto choices (with rationale)

| Canton key | Algo (format) | Backend | Why |
|---|---|---|---|
| Namespace / identity root | Ed25519 (`concat`, raw 64-byte R‖S) | **FROST-ed25519** (ZF `frost-ed25519`) | RFC 9591; emits standard RFC 8032 sig Canton verifies natively. Audited by NCC Group (public report, Oct 2023, v0.6.0; we pin 2.2.0). The one key where "no node holds the whole secret" clearly earns MPC. |
| Protocol / sequencer auth | ECDSA P-256/P-384 (`der`) | **DKLS23** (Silence Labs) or HSM | OT-based, avoids the Paillier/TSSHOCK class that broke GG18/GG20/CGGMP. ToB-audited. **Pin DKLS23, not DKLS24** (2026 OT-count caveat). Confirm P-384 instantiation. |
| Asymmetric encryption | RSA-2048-OAEP-SHA256 (Canton's KMS-mode default) | **Cluster-hosted (replicated, sealed)** or HSM delegate | **Not threshold — and for RSA that is permanent, not a roadmap item.** No Rust implementation of threshold RSA decryption exists (crates.io sweep found none; Shoup's construction lives in Go/C++/Java), and RUSTSEC-2023-0071 (Marvin timing side-channel, still unpatched in 2026) rules out the pure-Rust `rsa` crate for a network-facing decryptor — so the cluster holds a whole key and decrypts with `aws-lc-rs`. It performs the *full* OAEP decrypt: returning raw `c^d mod N` would hand the driver a Manger/Bleichenbacher oracle. |
| Asymmetric encryption (roadmap) | ECIES-P256 (`EciesHkdfHmacSha256Aes128Cbc`) | Cluster-hosted whole key (v1.5) → **threshold `frost-p256`** (v2) | ECDH *is* thresholdable where RSA is not: each node returns `λᵢ·dᵢ·R` and the leader adds the points — one round, stateless, no nonce hazard. Both versions share one wire contract (`EcdhDerive`), so promoting to real threshold is a server-side change. Gated on the synchronizer's `requiredEncryptionSpecs` admitting `EcP256`. |
| Symmetric wrapping | AES-256-GCM | **Cluster-hosted (replicated, sealed)** or HSM delegate | The algorithm is opaque to Canton — the driver picks it. Nothing here to threshold; the only question is where the key lives. |

Note: AWS KMS + YubiHSM now support Ed25519 natively, so MPC here is a **trust-distribution**
choice (no single trusted box/vendor), not an algorithm necessity. An all-HSM build is fully
Canton-compatible and FIPS-capable — which is exactly why Phase 1 ships on HSM.

## Cluster-hosted keys (non-FROST material) — replication, not MPC

Enabled per cosigner. It requires `share_seal`, and config validation refuses hosted keys without
it: a whole private key must never sit unsealed on disk.

```json
"hosted_keys": { "enabled": true, "write_quorum": 2, "anti_entropy_interval_secs": 300 }
```

A key is generated on one cosigner, wrapped per recipient, replicated to the others, and sealed at
rest on each node; any node can then serve a decrypt. The mechanics that carry the design (full
rationale in [hosted-keys-design.md](hosted-keys-design.md)):

- **Write quorum 2-of-3 by default**, matching the cluster's own fault model. Requiring all three
  would block key rotation whenever any node is down — worse than the single copy an HSM gives.
  Below quorum the write **rolls back** rather than leaving one lonely copy. 2-of-3 is only safe
  because anti-entropy and read-repair ship with it.
- **Wrapped on the wire, not merely inside mTLS.** A service-mesh sidecar terminating TLS would
  otherwise see plaintext private keys. Each replica is sealed to one recipient node: ephemeral
  X25519 → HKDF-SHA256 → AES-256-GCM, AAD-bound to cluster id, key id, spec and recipient. The
  recipient's static key is *derived* from the cluster master secret (the same secret used for share
  sealing), never generated or stored, which avoids a first-boot ordering problem. The startup
  self-check that derivation makes possible — pinning each peer's `dist_pubkey` in config so a
  wrong secret or wrong mount is caught *before* any key exists — is **not shipped**; today a wrong
  secret surfaces when an operation fails.
- **Anti-entropy and read-repair.** A sweep every 300 s pulls keys this node lacks and pushes keys a
  peer lacks; a request landing on a lagging replica pulls on demand. Hosted keys are
  create-once-immutable (Canton rotates by minting a new id plus a topology transaction), so a
  commitment mismatch between two nodes under one key id is a **hard error** — page-worthy, never
  auto-reconciled.
- **Same storage as FROST shares** (`data_dir/keys/`), so `rutli-cosigner backup` / `restore` cover
  hosted keys with no extra step. A sibling directory would have been silently skipped, which is
  precisely the failure class this work exists to remove.
- **Invariant, enforced in code: replication and anti-entropy apply to hosted keys ONLY.** A FROST
  share is never listed, fetched or copied between nodes — two nodes holding the same share would
  silently break the threshold scheme.

New Signer RPCs: `Capabilities`, `GenerateKey`, `PublicKey`, `KeyInfo`, `DeleteKey`, `Decrypt`,
`SymmetricEncrypt`, `SymmetricDecrypt`. New Peer RPCs (mesh only, gated by `peer_allowlist`):
`ReplicateKey`, `FetchKey`, `ListKeys`, `PurgeKey`, `NodeInfo`. New metrics: `rutli_hosted_keys`,
`rutli_hosted_key_ops_total{op,result}`, `rutli_anti_entropy_repairs_total`,
`rutli_key_replicas` (fewest cosigners holding any one key — the alert that makes a write quorum
below `n` safe), `rutli_unreadable_key_files_total` (a key file that could not be opened and was
skipped from the inventory, so it is neither replicated nor repaired) and
`rutli_anti_entropy_conflicts_total` — any increase in the last one is page-worthy.

Operator guide, including export/import of a hosted key: [hosted-keys.md](hosted-keys.md).

The honest framing, to be used wherever this tradeoff comes up:

- **The security tier matches the recoverability tier.** The one key Canton *cannot* rotate — the
  namespace key — stays in real threshold MPC. The keys that get only replication are exactly the
  ones Canton *can* rotate under that namespace key. A replicated-key compromise costs a topology
  transaction; a namespace-key compromise costs the node's identity.
- **The win is relocation, not a threshold property.** Key material moves off the busy,
  internet-adjacent Canton participant host onto three hardened, single-purpose, allowlisted nodes.
  Compromising one cosigner yields that key — three copies of it exist, by design.
- **The cost, stated plainly:** Canton's encryption keys protect per-view session keys, so an
  attacker who extracts one gains **retrospective** read access to any recorded traffic encrypted to
  it. Rotation fixes the future, not the past. There is no forward secrecy here.

## One cluster, several participants — `frost.key-prefix`

The driver derives FROST key ids **deterministically from Canton's key name** (`namespace` →
`frost-namespace`, `signing` → `frost-signing`), and hosted ids as `rutli-<kind>-<name>-<uuid>`. The
determinism is deliberate — a retry or a failover must ask for the *same* namespace key, never mint
a second one — but it means two participants pointed at the same cosigner cluster both ask for
`frost-namespace`. The cluster's create-once guard then refuses the second participant's DKG with
`ALREADY_EXISTS`. **That refusal is correct and stays:** the guard is what protects a live namespace
key from being overwritten, and it must never be relaxed to make sharing a cluster convenient. (The
2026-10-07 DevNet soak bring-up hit exactly this with a second validator; the only way out at the
time was retiring the old shares by hand on every cosigner.)

The fix is on the driver side. `frost.key-prefix` (default `""`) is prepended to **every** id the
driver mints or looks up — FROST and hosted alike — and every path that builds or recognises an id
goes through one helper, `FrostKeyIds`, so there is no second place a prefix can be forgotten:

```hocon
frost = {
  endpoints  = ["cosigner1:9101", "cosigner2:9102", "cosigner3:9103"]
  key-prefix = "soak1-"      # a different value on each participant sharing this cluster
}
```

With it, participant one births `soak1-frost-namespace` and participant two `soak2-frost-namespace`:
two keys, two DKGs, no collision. Rules:

- **Set a distinct prefix per participant** on a shared cluster. Without one, the second
  participant's DKG is refused by design — do not work around that by deleting shares.
- **Choose it before the participant's first bootstrap and never change it.** Canton stores the ids
  it was handed, and routing is strict on the full prefix: a driver started with `soak1-` does not
  recognise a bare `frost-namespace` (or `soak2-…`) as its own key and sends it to the delegate.
- **Leave it unset on existing deployments.** The empty default yields the ids earlier releases
  minted, byte for byte, so a cluster already holding `frost-namespace` keeps working unchanged.
- **Approval rules match the full id.** With a prefix, a rule's `key-id-prefix` must include it
  (`"soak1-frost-"`, not `"frost-"`); see [approval-quorum.md](approval-quorum.md).
- The alphabet is the cosigner keystore's, `[A-Za-z0-9_-]`; anything else fails at driver startup.
- **No routing tag inside the prefix** (since 0.4.0-rc.6): a prefix containing `frost-` or `rutli-`
  fails at driver startup. The cosigners do not know the prefix; they read an id's routing tag as the
  first `frost-` or `rutli-` in it and create hosted keys only under `rutli-` ids, so that no peer can
  park a hosted key on a FROST id before its DKG ([threat-model.md](security/threat-model.md)). A
  prefix without a tag keeps the first tag in every id equal to the one the driver routes on.
- Otherwise the cosigners treat ids as opaque strings. A prefix is a namespace, not an
  authorization boundary — any driver with a valid client certificate can address any id on the
  cluster, so participants sharing a cluster share a trust domain.

## Hard constraints (design around these)

- **Namespace root key is NOT rotatable.** It can be *moved* but never replaced: Canton 3.5+
  documents migrating an existing node from DB-keys → KMS by exporting the keys and starting a new
  participant under the same identity. Rütli's migration path (split an existing key into FROST
  shares) ships in v0.4.0 as the split ceremony, [split-ceremony.md](split-ceremony.md); the full
  node migration around it is [roadmap-migration.md](roadmap-migration.md). Freshly-deployed
  nodes with DKG keys remain the recommended path. A migrated namespace key is not as strong as a DKG
  key: it existed whole on the old node, in its database and in every backup of it. Migration
  protects against future compromise and key loss; it cannot un-expose the past.
- **Key loss = irrecoverable loss** of all Canton Coin for parties hosted under that namespace.
  No slashing in Canton, but compromise = "SV failure" that cuts the network BFT buffer until the
  SV is offboarded. DR / share backup is a first-class product concern, not an afterthought.
- **Cluster-hosted encryption keys have no forward secrecy.** They are whole keys on three nodes;
  extracting one yields plaintext for *recorded past* traffic encrypted to it, and rotation bounds
  only future exposure. Where a hardware boundary is a compliance requirement, keep the HSM
  delegate.
- **FROST nonce hygiene** is the top operational risk: never reuse a signing-nonce commitment,
  require good RNG, keep strict per-session nonce state, enforce canonical encoding of the group
  public key and `R` at the boundary. Not a verifier-compat risk — a discipline risk.

## Phased delivery

- **Phase 0** — spike: `SoftwareBackend` driver green against the conformance suite; Canton devnet
  node signs a topology transaction through the driver end-to-end. See `phase-0-spike.md`.
- **Phase 1** — production `KmsDriver` on `HsmBackend`; all key types; FIPS-capable.
- **Phase 2** — `FrostBackend`: Rust FROST-ed25519 MPC cluster for the namespace key; DKG,
  `t`-of-`n` signing, proactive share refresh.
- **Phase 3** — ✅ M-of-N approval / quorum engine (`approval`, cryptographic separation of duties;
  see `docs/approval-quorum.md`), ✅ hash-chained audit log (`audit-log-path`, offline-verifiable),
  ✅ signing journal (`signing-journal`, replay detection + rate limit — honest about the
  no-height-metadata limit), ✅ share backup/restore + DR runbook (`docs/disaster-recovery.md`),
  ✅ key-ceremony runbook (`docs/key-ceremony.md`).
- **Cluster-hosted keys** — a track of its own, off the phase numbering because it cuts across the
  backends; design and rationale in [hosted-keys-design.md](hosted-keys-design.md). ✅ **v1** in the
  cosigner cluster: hosted RSA-2048-OAEP-SHA256 + AES-256-GCM, replicated and sealed, with write
  quorum, anti-entropy, read-repair and offline `export-key`/`import-key`, plus the matching
  driver-side `rutli-` routing and `delegate = "none"` — both halves shipped and verified end to end
  on a real Canton participant. **v1.5**: `EcdhDerive` + hosted EC-P256 keys (still whole
  keys) with driver-side ECIES via BouncyCastle's `IESEngine`, advertising `EcP256` to steer
  deployments off RSA. **v2**:
  threshold ECIES via `frost-p256` — one stateless round, no nonce hazard — on the **same wire
  contract as v1.5**, so promoting is a server-side change plus a config flag. **Never**: threshold
  RSA.
- **Phase 4** — `DklsBackend`: threshold ECDSA (P-256/P-384) for protocol/sequencer keys.
- **Phase 5** — Wallet Gateway signing-driver SPI (second seam); SOC2/ISO/DORA evidence pack;
  published third-party MPC audit.

# Phase 2 — FROST-ed25519 MPC backend

> **Status:** the protocol core is implemented and tested — `frost/core` (`rutli-frost-core`):
> DKG state machine, two-round signing sessions, crash-safe single-use nonce store. 5 e2e tests
> prove a 2-of-3 DKG signs Canton's 34-byte payload into a 64-byte signature that
> `ed25519-dalek`'s **strict** verifier accepts under the group key, nonce reuse is refused across
> restarts, and below-threshold quorums cannot sign. Remaining: the cosigner daemon (gRPC/mTLS,
> leader election), the Scala `FrostBackend`, and the `deploy/frost` end-to-end Canton test.

The differentiator: the Canton **namespace / identity key** — the one whose compromise is
catastrophic and irreversible — is never held whole by any machine. A `t`-of-`n` cluster produces
standard Ed25519 signatures via FROST (RFC 9591). This is the "Horcrux for Canton" core.

> Prereq: Phase 1 `HsmBackend` ships first (HSM-first sequencing). Phase 2 slots a `FrostBackend`
> in behind the same `KmsBackend` seam — no change to the Canton-facing driver. Encryption keys stay
> on the HSM (threshold decryption is out of scope; see architecture.md).

## What the wire contract fixes for us

From `docs/wire-contract.md` (captured live):
- `sign` receives a **34-byte** payload (`0x1220 ‖ sha256(tx)`), returns a **64-byte** raw
  `R‖S` Ed25519 signature. Small, fixed-size — no streaming, trivial to ship through MPC rounds.
- Plain Ed25519 over those 34 bytes (not Ed25519ph). FROST's message = the 34-byte digest.
- Low frequency (bootstrap + topology changes). Multi-second round latency is acceptable.
- `getPublicKey` must return the group public key as 44-byte Ed25519 SPKI — the DKG output,
  encoded once at key-generation time.

## Crypto core

- **Library:** Zcash Foundation `frost-ed25519` (RFC 9591, MIT/Apache, audited by NCC Group +
  Least Authority). Emits canonical RFC 8032 signatures — byte-identical to single-signer Ed25519,
  which is exactly what Phase 0 proved Canton accepts.
- **Rust**, because the audited FROST implementations are Rust. The `FrostBackend` (Scala, in the
  driver) is a thin gRPC/mTLS client to the cluster; all FROST math lives in the Rust signer.
- **Key generation: DKG, never trusted-dealer sharding.** Canton cannot migrate an existing node
  into KMS mode (namespace root key is non-rotatable), so keys are born in the cluster via
  distributed key generation — the whole private key never exists anywhere. (Horcrux shards an
  existing Cosmos key; that path is closed to us, and DKG is strictly stronger.)

## Topology

```
RutliDriver (JVM)  ──FrostBackend──►  gRPC/mTLS  ──►  Cosigner cluster (Rust, n nodes)
                                                          ├─ cosigner 1  (share 1)   region/acct A
                                                          ├─ cosigner 2  (share 2)   region/acct B
                                                          └─ cosigner 3  (share 3)   region/acct C
```

- `n` cosigners, threshold `t` (e.g. 2-of-3). Each holds one FROST share, each on a separate
  host / cloud account / region — all operated by the single node operator (self-custody).
- Each share ideally sealed in an enclave/HSM ("MPC-of-HSM"): breach needs `t` enclaves.

## Coordination — cluster-side leader election (Horcrux-style)

The `FrostBackend` is a **dumb client**: it submits `{keyId, digest}` and awaits a 64-byte
signature. Round orchestration lives *inside* the cluster:

1. Cosigners elect a leader (Raft). The leader drives each signing session.
2. **Round 1 (commit):** leader collects nonce commitments `(Dᵢ, Eᵢ)` from ≥ `t` cosigners.
3. **Round 2 (sign):** leader sends the digest + commitment set; each cosigner returns a signature
   share `zᵢ`.
4. Leader aggregates → single `(R, s)` → returns to the client.

Why cluster-side, not a driver-side coordinator:
- Keeps nonce-session state and round logic out of the Canton JVM (which restarts independently).
- The client (and thus a compromised Canton host) never touches key material or nonce state — it
  can stall signing, never forge.
- The cluster is independently testable and deployable, exactly like Horcrux's cosigner set.

## The one dangerous failure mode: nonce reuse

Reusing a round-1 nonce commitment across two different messages **leaks the share's secret**. This
is *the* FROST footgun. Mitigations, all mandatory:
- Per-session fresh nonces from a CSPRNG; never derive deterministically from the key+message.
- Persist a nonce-session record **before** releasing a signature share; refuse to reuse a
  committed nonce even across process restarts (crash-safe single-use).
- Enforce canonical encoding of the group public key and `R` at the boundary.
- Lean on the audited ZF crate's nonce API rather than hand-rolling.

## Lifecycle

- **DKG** at namespace-key creation (`generateSigningKeyPair` for the namespace key routes to the
  cluster; the driver returns a `keyId` naming the group key).
- **Proactive refresh:** periodically re-randomize shares, same public key — an attacker must breach
  `t` cosigners within one epoch; old stolen shares become useless.
- **DR:** encrypted per-share backups (fast node replacement) + a cold Shamir backup held by
  custodians (last resort). Recovery = re-share from surviving shares; the full key is never
  reconstructed on a live host. This matters because the namespace key is non-rotatable and its
  loss is total.

## Interfaces to define (next steps)

1. gRPC service: `Dkg(keyName) -> {keyId, groupPublicKey}`, `Sign(keyId, digest) -> signature64`,
   `Refresh(keyId)`, `Health`. mTLS with cert pinning between driver↔cluster and cosigner↔cosigner.
2. `FrostBackend` (Scala) implementing `KmsBackend` — maps `generateSigningKeyPair`(Ed25519) and
   `sign` to the gRPC calls; every other op (encryption, symmetric, non-Ed25519 signing) delegates
   to the co-located `HsmBackend` (composite backend, routing by key type).
3. Rust cosigner: `frost-ed25519` + a Raft crate (e.g. `openraft`) + tonic (gRPC) + a crash-safe
   nonce store. Package as a small static binary + container.
4. `deploy/frost/` — docker-compose bringing up `n=3, t=2` cosigners + the devnet participant, for
   an end-to-end "namespace key signed by FROST, verified by Canton" integration test.

## Acceptance criteria (Phase 2)

- DKG produces a group Ed25519 key; `getPublicKey` returns its 44-byte SPKI.
- A Canton devnet participant using `backend = "frost"` for the namespace key initializes and signs
  its identity topology; Canton's verifier accepts the FROST-produced 64-byte signatures.
- Kill any single cosigner (with `t=2, n=3`): signing still succeeds.
- Nonce-reuse guard: a forced replay of a committed nonce is refused, verified by test.

# Phase 2 — FROST-ed25519 MPC backend

> **Status:** protocol core **and** cosigner daemon implemented and tested.
> - `frost/core` (`rutli-frost-core`): DKG, two-round signing, crash-safe single-use nonce store.
>   5 e2e tests — 2-of-3 DKG signs Canton's 34-byte payload into a 64-byte signature that
>   `ed25519-dalek`'s **strict** verifier accepts; nonce reuse refused across restarts;
>   below-threshold quorums cannot sign.
> - `frost/cosigner` (`rutli-cosigner`): gRPC `Signer` (client) + `Peer` (mesh) services, DKG/sign
>   orchestration, JSON keystore, config. 3 cluster tests — DKG across 3 nodes, threshold sign,
>   **survives a downed cosigner**, shares persist across reload. Runnable via `deploy/frost`
>   (Docker compose, 2-of-3).
>
> - `driver` `FrostBackend` (Scala): composite backend routing the Ed25519 namespace key to the
>   cluster over gRPC (checked-in grpc-java stubs from the shared proto) and delegating every other
>   key to the HSM/software backend. **Live e2e verified** (`FrostBackendIT`, gated on
>   `RUTLI_FROST_ENDPOINT`): against a real 3-node cluster it runs DKG for the namespace key,
>   threshold-signs a Canton 34-byte payload, and the **stock JDK Ed25519 verifier accepts** the
>   64-byte signature; non-Ed25519 keys fall through to the delegate. Config: `backend = "frost"`
>   + `frost { endpoints, delegate }` (plural — the full roster, for failover; see
>   `deploy/devnet/canton-frost.conf`).
>
> - **Canton ↔ FROST end-to-end: PASSED (2026-07-03).** A real Canton 3.5.6 participant booted with
>   `backend = "frost"` (`deploy/devnet/canton-frost.conf`): all three Ed25519 node keys (namespace,
>   sequencer-auth, signing) were born via cluster DKG, the identity topology transactions were
>   threshold-signed by the 2-of-3 quorum (`sign … inBytes=34 sigBytes=64 outcome=ok`), Canton's
>   verifier accepted them and the node reached `initialized`. Shares on disk per node; only the
>   signing quorum burned nonces. The participant's identity is the fingerprint of a key that never
>   exists whole anywhere.
>
> - **Mutual TLS: done.** Both hops (cosigner↔cosigner mesh, driver→cluster) authenticate with
>   mTLS against one cluster CA. Verified live: a 3-node mTLS cluster + driver runs DKG (over the
>   TLS mesh) and threshold-signs, 3/3; a plaintext client is refused at the handshake. Certs via
>   `scripts/gen-frost-certs.sh`; configs in `deploy/frost/config-tls`.
>
> - **Availability: driver-side failover (done).** The driver is configured with the full cosigner
>   roster (`frost.endpoints`) and fails over across them — any live cosigner leads a request; a
>   node is skipped only when unreachable (UNAVAILABLE/DEADLINE_EXCEEDED), never masking a real
>   application error. Verified: signing succeeds with a dead endpoint prepended to the roster.
>
> **On Raft:** we deliberately did **not** add a Raft/consensus layer. FROST signing sessions are
> independent (keyed by session id), shares are write-once at DKG then read-only, and the nonce
> store is per-node crash-safe — there is no replicated log to keep consistent, so "elect one
> leader" buys nothing here. Client-side failover fully closes the single-leader availability gap.
> A real consensus layer would only be warranted later if the cluster must self-manage membership or
> coordinate proactive refresh without an external trigger; revisit then, not before.
>
> - **Share sealing (software, done):** shares stored as AES-256-GCM envelopes, per-node key via
>   HKDF from an operator-injected secret (`share_seal.secret_env`). Closes the at-rest exposure;
>   enclave/HSM sealing (which also protects share memory during signing) plugs into the same seam.
>
> - **Proactive share refresh (done):** `Signer.Refresh` RPC / `rutli-cosigner refresh` — dealer-free
>   DKG-style re-randomization of all shares, group key (and node identity) unchanged, verified by
>   every node before persisting. Limits an attacker to one refresh epoch; pre-refresh shares are
>   dead afterwards (old+new shares cannot combine — tested).
>
> Remaining for Phase 2 hardening: enclave/HSM sealing ("MPC-of-HSM") and DR runbook per the
> production-readiness list.

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

1. The node the driver contacts is the leader for that request (static leader; the driver fails over
   to another cosigner if it's unreachable — no Raft, see the note above). The leader drives the session.
2. **Round 1 (commit):** leader collects nonce commitments `(Dᵢ, Eᵢ)` from ≥ `t` cosigners.
3. **Round 2 (sign):** leader sends the digest + commitment set; each cosigner returns a signature
   share `zᵢ`.
4. Leader aggregates → single `(R, s)` → returns to the client.

Why cluster-side, not a driver-side coordinator:
- Keeps nonce-session state and round logic out of the Canton JVM (which restarts independently).
- The client (and thus a compromised Canton host) never touches key material or nonce state — it
  can stall signing, never forge.
- The cluster is independently testable and deployable, exactly like Horcrux's cosigner set.

## Who can call the Signer API

mTLS restricts the cluster to holders of cluster-CA-signed certs, but a *cosigner* cert should not
be able to request arbitrary signatures. Set `signer_allowlist` (a list of client-cert Common Names,
typically just the driver's — `"driver"` from `gen-frost-certs.sh`) so only the driver may call the
sensitive Signer RPCs (`Dkg`/`Sign`/`Refresh`/`GroupKey`); `Health` stays open for liveness. The
mesh Peer API is unaffected. When `signer_allowlist` is unset the daemon warns and allows any
cluster cert (still behind the ceremony guard). The TLS example configs and the k8s ConfigMap set
`"signer_allowlist": ["driver"]`.

## Ceremony safety (DKG / refresh)

DKG and refresh rewrite a key's shares, so they must never overlap or clobber a live key:

- **DKG never overwrites a provisioned key.** `dkg_part1` refuses if the key already exists
  (`KeyExists`) — an accidental re-DKG (a failover retry, an ops mistake) would otherwise generate a
  brand-new key and **destroy the non-rotatable namespace key**.
- **One ceremony per key at a time.** Each node holds a per-key ceremony guard: a second DKG or
  refresh for the same key (a different ceremony id) is refused (`CeremonyInProgress`) until the
  first releases at part 3, or its guard expires (orphan timeout, for a leader that died
  mid-ceremony). This prevents two overlapping ceremonies from leaving nodes with shares on
  *different* sharing polynomials — which share the group key but cannot sign together (split-brain).
- **The driver never auto-retries DKG.** `FrostBackend` fails a DKG over to another endpoint only on
  a connection-level `UNAVAILABLE`, never on `DEADLINE_EXCEEDED` — a slow-but-succeeding ceremony
  must not be run a second time against a different leader.

- **A superseded ceremony cannot persist.** The guard has an orphan timeout (a leader that dies
  mid-ceremony is preempted after it). To close the window between preempting the old guard and
  clearing its session, every `part2`/`part3` re-checks that the calling ceremony still owns the
  key's guard; a superseded one is refused (`CeremonySuperseded`) and never writes — this is the
  load-bearing safety for refresh, which would otherwise split/clobber shares.
- **Signing is fenced during a ceremony.** A new `sign` for a key is refused while a DKG/refresh
  holds that key's guard (refresh rewrites the share and evicts the cached cosigner). A sign already
  past round 1 when a refresh lands fails cleanly at round 2 (its nonces went with the old cosigner)
  — never a silent bad signature. Operationally: don't refresh during a topology burst; drain first.

Concurrent ceremonies therefore fail closed (refused, retry later), never corrupt. Ordinary
signing is otherwise independent — each signature uses a fresh session id.

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
3. Rust cosigner: `frost-ed25519` + tonic (gRPC) + a crash-safe nonce store, packaged as a small
   static binary + container. (No Raft — static leader + driver-side failover; see the note above.)
4. `deploy/frost/` — docker-compose bringing up `n=3, t=2` cosigners + the devnet participant, for
   an end-to-end "namespace key signed by FROST, verified by Canton" integration test.

## Acceptance criteria (Phase 2)

- DKG produces a group Ed25519 key; `getPublicKey` returns its 44-byte SPKI.
- A Canton devnet participant using `backend = "frost"` for the namespace key initializes and signs
  its identity topology; Canton's verifier accepts the FROST-produced 64-byte signatures.
- Kill any single cosigner (with `t=2, n=3`): signing still succeeds.
- Nonce-reuse guard: a forced replay of a committed nonce is refused, verified by test.

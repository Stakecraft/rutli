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
>   key to the HSM/software backend — and, with `frost.hosted-keys = true`, routing
>   `rutli-`-prefixed ids to the cluster too so the delegate can be dropped entirely
>   (`delegate = "none"`; *Cluster-hosted keys*, below). **Live e2e verified** (`FrostBackendIT`,
>   gated on `RUTLI_FROST_ENDPOINT`): against a real 3-node cluster it runs DKG for the namespace
>   key, threshold-signs a Canton 34-byte payload, and the **stock JDK Ed25519 verifier accepts** the
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
> - **Cluster-hosted keys, v1 (done, both sides):** the cluster also holds the **non-FROST**
>   material Canton needs — RSA-2048-OAEP-SHA256 encryption keypairs and AES-256-GCM symmetric
>   keys — so a participant can run with no HSM and no local key state; the driver-side `rutli-`
>   routing and `delegate = "none"` shipped in the same release. These are **replicated whole keys,
>   not threshold shares**; the namespace key remains true 2-of-3 FROST and is untouched. 9 cluster
>   tests: replicate-and-decrypt on every node, read-repair, anti-entropy push, under-quorum
>   rollback, restart survival, and FROST/hosted non-interference. **Verified end to end
>   (2026-08-28)** on a Canton 3.5.6 participant with no local key state
>   (`deploy/devnet/canton-hosted.conf`): three Ed25519 keys born by cluster DKG and
>   threshold-signed, plus an RSA-2048 encryption key generated in the cluster and replicated to all
>   three cosigners on disk. See *Cluster-hosted keys* below.
>
> Remaining for Phase 2 hardening: enclave/HSM sealing ("MPC-of-HSM") per the production-readiness
> list. The DR runbook shipped — [`disaster-recovery.md`](disaster-recovery.md).

The differentiator: the Canton **namespace / identity key** — the one whose compromise is
catastrophic and irreversible — is never held whole by any machine. A `t`-of-`n` cluster produces
standard Ed25519 signatures via FROST (RFC 9591). This is the "Horcrux for Canton" core.

> Prereq: Phase 1 `HsmBackend` ships first (HSM-first sequencing). Phase 2 slots a `FrostBackend`
> in behind the same `KmsBackend` seam — no change to the Canton-facing driver. Threshold
> *decryption* remains out of scope (see architecture.md); encryption keys either stay on the HSM or,
> since cluster-hosted keys v1, live in the cluster as replicated whole keys — which is a
> durability and relocation property, not a threshold one. See *Cluster-hosted keys* below.

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
                                                             share i : distinct, never copied
                                                             hosted  : full replica on every node
```

- `n` cosigners, threshold `t` (e.g. 2-of-3). Each holds one FROST share, each on a separate
  host / cloud account / region — all operated by the single node operator (self-custody).
- Each share ideally sealed in an enclave/HSM ("MPC-of-HSM"): breach needs `t` enclaves.
- A node's keystore may also hold **cluster-hosted keys** (RSA encryption, AES symmetric), which are
  whole keys replicated to *every* node rather than split across them. The two kinds of material
  share a directory and a sealing key but nothing else — see *Cluster-hosted keys* below, and in
  particular the rule that replication never touches a FROST share.

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

## Who can call which API

mTLS proves *cluster membership*, not *role*: every cosigner cert **and the driver cert** are signed
by the same cluster CA. Two separate allowlists carry the role separation, and **both are required
when `tls` is enabled** — the daemon refuses to start without them (non-empty lists). Plaintext dev
may omit both.

- **`signer_allowlist`** — who may call the client-facing Signer RPCs (`Dkg`/`Sign`/`Refresh`/
  `GroupKey`). Typically just the driver's CN (`"driver"` from `gen-frost-certs.sh`). `Health` stays
  open for liveness.
- **`peer_allowlist`** — who may call the mesh Peer RPCs. The **cosigner CNs only**; the driver must
  *not* be listed.

Why the second one is load-bearing: the Peer API is the raw FROST protocol, below every policy check.
A caller that reaches `SignRound1`/`SignRound2` on `threshold` cosigners can assemble a signature
over **any** message, bypassing the leader, the 34-byte Canton-digest guard, the ceremony fence and
the driver's signing journal. Transport mTLS alone does not stop that, because the driver's cert
satisfies it. As defense in depth the digest-length check is also enforced in `Node::sign_round2`
(the function behind the Peer RPC), so the mesh path fails closed even with a misconfigured
allowlist. The TLS example configs, the k8s ConfigMap and the Helm chart set both lists (Helm derives
`peer_allowlist` as `cosigner1..N` when unset).

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
- **Signing is fenced cluster-wide during a ceremony.** Before any DKG/refresh crypto, the leader
  takes the per-key guard on **every** peer (`CeremonyFence`), so no node can start a new `sign`
  mid-ceremony — not just the leader. The reverse fence also applies: if any peer still holds
  in-flight sign nonces for that key, the fence fails (`SignInProgress`) and is rolled back
  cluster-wide. A sign already past round 1 when a refresh somehow lands still fails cleanly at
  round 2 (its nonces went with the old cosigner) — never a silent bad signature.

Concurrent ceremonies therefore fail closed (refused, retry later), never corrupt. Ordinary
signing is otherwise independent — each signature uses a fresh session id.

## The one dangerous failure mode: nonce reuse

Reusing a round-1 nonce commitment across two different messages **leaks the share's secret**. This
is *the* FROST footgun. Mitigations, all mandatory:
- Per-session fresh nonces from a CSPRNG; never derive deterministically from the key+message.
- Persist a nonce-session record **before** releasing a signature share; refuse to reuse a
  committed nonce even across process restarts (crash-safe single-use).
- Refuse a duplicate `round1` for a session id that is still in flight — overwriting live nonces
  would strand the first set and invites replay confusion; the leader must use a fresh id per attempt.
- Free in-flight nonces promptly: when a signature gives up (round-2 failure, or too few cosigners
  answered round 1) the leader best-effort tells each quorum member to abort the session, so a
  give-up doesn't pin round-1 nonces in RAM until the pending-TTL sweep. The per-session TTL remains
  the backstop if the abort can't be delivered.
- Enforce canonical encoding of the group public key and `R` at the boundary.
- Lean on the audited ZF crate's nonce API rather than hand-rolling.

## Cluster-hosted keys (non-FROST material in the same cluster)

The cluster also holds the key material FROST cannot produce: **RSA-2048-OAEP-SHA256** encryption
keypairs and **AES-256-GCM** symmetric keys. Before this, those keys were delegated to an HSM
(PKCS#11) or to the software backend, which kept them in JVM heap on the participant host — the
arrangement behind the 2026-08-12 DevNet incident, where a Splice 0.6.11→0.7.0 upgrade restarted the
participant, the heap-only RSA encryption key was gone, peers kept encrypting to the still-published
public key, and the resulting `KmsDecryptError` disconnected the node from the synchronizer. The key
was unrecoverable. Full rationale and the crate survey behind it:
[hosted-keys-design.md](hosted-keys-design.md).

**These are replicated whole keys, not threshold shares.** One cosigner generates the key, it is
replicated to the others, sealed at rest on each, and any node can serve a decrypt. There is no MPC
in that path and nothing here should be read as claiming otherwise. Threshold RSA is not a later
phase but permanently out of scope: no Rust implementation of threshold RSA decryption exists, and
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) (Marvin timing
side-channel, private-key recovery by a *network* attacker) is still unpatched in the pure-Rust
`rsa` crate — which is why the OAEP decrypt runs on `aws-lc-rs` instead.

So one cluster now holds two classes of material with deliberately different properties:

| | FROST namespace key | cluster-hosted keys |
|---|---|---|
| Scheme | 2-of-3 threshold Ed25519 (RFC 9591) | whole key, one replica per node |
| Whole key exists | **never, anywhere** | on every node, sealed |
| One cosigner compromised yields | nothing usable | that key |
| Canton can rotate it | **no** | yes, under the namespace key |
| Replicated / anti-entropy | **never** | yes |

**The security tier matches the recoverability tier.** The one key Canton *cannot* rotate stays in
real threshold MPC; the keys that get only replication are exactly the ones Canton *can* rotate
under that namespace key. The win is **relocation, not a threshold property** — key material moves
off the busy, internet-adjacent participant host onto three hardened, single-purpose, allowlisted
nodes. The cost, which must not be buried: Canton's encryption keys protect per-view session keys,
so an attacker who extracts one gains **retrospective** read access to any recorded traffic
encrypted to it. Rotation fixes the future, not the past; there is no forward secrecy here.

### The invariant: replication covers hosted keys only

**A FROST share is never listed, fetched, pushed or copied between nodes.** This is the
load-bearing rule of the whole feature, and it is enforced in code rather than by convention
because violating it fails *silently*. Two nodes holding the same share means the cluster no longer
has `n` distinct points on the sharing polynomial: a "2-of-3" quorum drawn from those two nodes is
really 1-of-3, one compromised host is enough to sign, and nothing about the resulting signature
looks wrong. Threshold security would be gone with no error and no alert — which is why this
invariant gets a hard boundary rather than a code comment.

Where it is enforced:

- `KeyStore::list_hosted` walks the key directory and returns hosted records only; FROST files are
  skipped. Every replication path — `Peer.ListKeys`, the anti-entropy sweep, read-repair — is built
  on that inventory, so a share has no way to enter one.
- The typed loads refuse the wrong kind in both directions: `load_hosted` on a share errors, and
  the FROST `load` on a hosted key errors. `Peer.FetchKey` and `Peer.ReplicateKey` go exclusively
  through the hosted path.
- `hosted_delete` re-reads the record before removing anything, so a `DeleteKey` naming the
  namespace key is refused rather than destroying a non-rotatable identity.
- An unreadable key file is logged at `error`, counted in `rutli_unreadable_key_files_total`, and
  **skipped** from the listing — not fatal to it. Failing the whole inventory (the first
  implementation) would stop anti-entropy for every *healthy* key too, turning one damaged file into
  a cluster-wide halt of self-healing. Skipping is safe because absence from a listing never causes
  a delete — peers only push keys a listing lacks — and a push onto an unreadable local file still
  fails closed in `hosted_store` rather than overwriting it. The counter is the compensating signal:
  a non-zero value means that key is neither pushed nor pulled until an operator resolves it.

Covered end-to-end by `hosted_keys_and_frost_shares_do_not_interfere`: DKG and hosted generation run
side by side in one keystore, threshold signing still verifies against the group key, the hosted
inventory contains only the hosted key, and the namespace key is neither loadable nor deletable
through the hosted API.

### One keystore, two record kinds

Hosted keys live in the **same** `data_dir/keys/` directory as FROST shares, one sealed file per
key, written through the same atomic path (tmp → fsync → rename → fsync dir). The sealed envelope's
plaintext is a tagged union: hosted records carry `"kind": "hosted"`, FROST shares carry no tag, so
files written before this feature existed parse unchanged.

Sharing the directory is deliberate, not incidental: `rutli-cosigner backup` / `restore` already
operate on it, so hosted keys are covered by the existing DR tooling for free. A sibling directory
would have been silently skipped by backup — the exact failure class the incident was about.

One honest limit: **delete does not claim secure erasure.** On copy-on-write filesystems,
wear-levelled SSDs and snapshotted volumes, removing a file does not destroy the bytes. Deleting
removes the only *referenced* copy; real destruction means rotating the seal master secret so every
old sealed blob — including the ones sitting in backups — becomes undecryptable.

### Replication wrapping, and why mTLS alone was judged insufficient

Replicating a hosted key means moving a *whole private key* across the mesh, a materially different
exposure from the FROST round packages that normally travel there. Transport mTLS does not cover it:

- A service-mesh sidecar (Istio, Linkerd) terminating TLS on the pod's behalf would see the
  plaintext private key. That is an ordinary, unremarkable Kubernetes deployment, not an exotic
  attack.
- The cluster CA also signs the **driver's** certificate, and every cosigner certificate carries the
  same shared `rutli-cosigner` SAN. As *Who can call which API* above puts it, the transport proves
  cluster membership, not identity — it cannot tell peer 2 from peer 3.

Key material is therefore sealed to **one specific recipient node** underneath the TLS, HPKE-style:

```text
esk, epk  ← ephemeral X25519 keypair, fresh per envelope
cek       = HKDF-SHA256(ikm  = X25519(esk, dist_pk_j),
                        info = "rutli-keywrap-v1" ‖ epk ‖ dist_pk_j)
envelope  = AES-256-GCM(cek, nonce, material,
                        aad = "rutli-kw-v1" ‖ j ‖ len-prefixed(cluster_id, key_id, spec))
```

The AAD binding is what makes an envelope non-transplantable: it cannot be replayed to a different
node, presented under a different key id, or relabelled as a different spec. Each of those is a
decryption failure, reported opaquely — wrong recipient, tampered AAD and corrupt ciphertext are all
just "this envelope is not for you or not intact". The `cluster_id` is derived from the CA
certificate (`sha256(ca_pem)[..8]`), so envelopes cannot cross trust domains and no new config field
was needed.

The recipient's static X25519 key is **derived, never generated or stored**:

```text
dist_sk_j = HKDF-SHA256(ikm  = cluster master secret,
                        salt = "rutli-dist/node-{j}",
                        info = "x25519-v1")
```

That is the same master secret as share sealing (`share_seal`). Deriving avoids a first-boot
ordering problem — there is no keypair to distribute before the cluster can talk — and it makes a
startup self-check *possible*: with each peer's `dist_pubkey` pinned in config, a node could confirm
its derived public key is the one its peers expect and catch a wrong secret or a wrong mount
*before* any key is generated, which is precisely the class of failure the incident belonged to.
**That pinning and the check are not shipped** — `peers[]` still carries only `identifier` and
`endpoint`, so a wrong secret is still discovered when an operation fails. It is the smallest useful
next step here. Under today's shared master secret any node can derive any peer's distribution key,
which is no worse than the status quo for share sealing; moving to per-node seal secrets makes the
binding real with no code change.

Two details that carry more weight than they look:

- On `FetchKey` — the pull side, where a node asks a peer for material — the recipient is taken
  from the **caller's client-certificate CN**, never from the request body. Otherwise any
  allowlisted peer could ask for key material wrapped to a node of its own choosing.
- A node's **commitment** to a key is a keyed digest: SHA-256 over a domain tag, that node's
  distribution public key, the spec and the private material. Two nodes can confirm they hold the
  same key without revealing anything about it, and the value is meaningless outside the cluster.

### Write quorum, anti-entropy and conflicts

A generate is fenced cluster-wide first, reusing the per-key ceremony guard from *Ceremony safety*
above (`kind = "genkey"`), so a concurrent generate for the same id on another leader serializes
behind it instead of racing. The leader then wraps and pushes the key to every peer.

- **Write quorum defaults to 2 of 3**, matching the cluster's own fault model. Requiring all three
  would mean you cannot mint or rotate an encryption key while any node is down — strictly worse
  than the single copy an HSM gives you. Below quorum the write **rolls back** (`PurgeKey` to every
  peer) instead of leaving one lonely copy, so the id stays free for a clean retry: one node holding
  the only copy is exactly the failure this feature exists to prevent. Validated range is `1..=n`.
- 2-of-3 is only safe *with* the two repair paths, which is why they shipped together. The
  **anti-entropy sweep** (`anti_entropy_interval_secs`, default 300) pulls keys this node is missing
  and pushes keys a peer is missing — pulling heals a node restored from a stale backup, pushing
  heals an under-quorum write. **Read-repair** pulls on demand when a request lands on a lagging
  replica; without it a decrypt there would return `NOT_FOUND`, and the driver deliberately does not
  fail over on `NOT_FOUND` because it is otherwise authoritative. Read-repair is what earns that
  assumption.
- **Generate is idempotent by `key_id`.** A client retry or driver failover repairs the replicas of
  the existing key rather than minting a second key under the same name; the same id requested with
  a *different* spec is refused outright.
- Hosted keys are **create-once-immutable** — a `key_id` maps to one key forever, and Canton rotates
  by minting a new id plus a topology transaction. That removes conflict *resolution* from
  anti-entropy entirely: a key either exists or it does not. Two nodes holding **different**
  material under one id is therefore a hard error — logged at `error`, counted in
  `rutli_anti_entropy_conflicts_total`, and never auto-reconciled, because reconciling would mean
  silently destroying material some node has already committed to. Any increase in that counter is
  page-worthy.

### Configuration

```json
"hosted_keys": { "enabled": true, "write_quorum": 2, "anti_entropy_interval_secs": 300 }
```

`share_seal` is a hard prerequisite: config validation refuses `hosted_keys.enabled` without it,
because a whole private key must never sit unsealed on disk — an unsealed replica would be strictly
worse than the HSM delegate it replaces — and the seal master secret is also what the distribution
keys derive from. The Peer RPCs that carry key material additionally require `peer_allowlist`: with
no allowlist there is no authenticated CN to identify the recipient, and the daemon refuses rather
than guessing.

### API surface and metrics

- **Signer** (client-facing, `signer_allowlist`): `Capabilities`, `GenerateKey`, `PublicKey`,
  `KeyInfo`, `DeleteKey`, `Decrypt`, `SymmetricEncrypt`, `SymmetricDecrypt`. `Capabilities` lets the
  driver learn the cluster's supported specs at startup instead of hardcoding them.
- **Peer** (mesh only, `peer_allowlist`): `ReplicateKey`, `FetchKey`, `ListKeys`, `PurgeKey`,
  `NodeInfo`. The reasoning in *Who can call which API* applies unchanged and with more force here:
  these RPCs move private key material, so the driver must not be on that list.
- **Metrics:** `rutli_hosted_keys` (gauge), `rutli_hosted_key_ops_total{op,result}`,
  `rutli_anti_entropy_repairs_total`, `rutli_key_replicas` (gauge — the fewest cosigners holding any
  one hosted key, recounted after each sweep repairs what it can; this is the alert that makes a
  write quorum below `n` safe), `rutli_unreadable_key_files_total`, and
  `rutli_anti_entropy_conflicts_total` — the last one alerts on *any* increase, since it signals a
  broken invariant rather than a transient. Runbook: [`observability.md`](observability.md).

### Driver routing

On the Scala side — shipped in the same release, and exercised against a real participant —
`FrostBackend` routes by key-id prefix: `frost-` to the FROST path, `rutli-` to the cluster-hosted
path, anything else to the delegate. With `frost.hosted-keys = true` the driver can run
`delegate = "none"` — a `NoDelegateBackend` that refuses every operation and names the key id, so a
key matching neither prefix is a loud routing bug rather than silent local crypto; the driver
rejects `delegate = "none"` without `hosted-keys = true` at startup. Supported specs come from the
cluster's `Capabilities` at startup instead of a hardcoded list. There is deliberately **no
automatic fallback to the delegate on `NOT_FOUND`**: quietly serving a key from a second custodian
is how split custody starts, and it could reproduce the incident class. Endpoint failover stays
restricted to `UNAVAILABLE` / `DEADLINE_EXCEEDED`.

### Where this goes next

**v1.5** adds `EcdhDerive` and hosted **EC-P256** keys — still whole keys — with the driver
completing ECIES (KDF2 → AES-128-CBC → HMAC) via BouncyCastle's own `IESEngine`, so the byte-exact
reference implementation stays in the JVM next to Canton's encryptor. **v2** makes that path
genuinely *threshold* via `frost-p256`: with Shamir shares `dᵢ` of `d`, each node returns `λᵢ·dᵢ·R`
and the leader sums the points — one stateless round, **no nonce state**, and therefore none of the
footgun documented above. The wire contract is identical for v1.5 and v2, so promoting a key class
from replicated to threshold is a server-side change plus a config flag, not an API migration.
**Threshold RSA: never** — see the top of this section.

## Lifecycle

- **DKG** at namespace-key creation (`generateSigningKeyPair` for the namespace key routes to the
  cluster; the driver returns a `keyId` naming the group key).
- **Proactive refresh:** periodically re-randomize shares, same public key — an attacker must breach
  `t` cosigners within one epoch; old stolen shares become useless.
- **DR:** encrypted per-share backups (fast node replacement) + a cold Shamir backup held by
  custodians (last resort). Recovery = re-share from surviving shares; the full key is never
  reconstructed on a live host. This matters because the namespace key is non-rotatable and its
  loss is total. Hosted keys sit in the same directory, so the same `backup`/`restore` covers them;
  a restored-from-stale-backup node is additionally healed by anti-entropy.
- **Hosted keys** are created on demand by the driver (`GenerateKey` with a caller-supplied
  `rutli-` id), never refreshed in place, and never re-shared: rotation means a new key id plus a
  Canton topology transaction, which is available precisely because these keys sit *under* the
  namespace key.

## Interfaces to define (next steps)

1. gRPC service: `Dkg(keyName) -> {keyId, groupPublicKey}`, `Sign(keyId, digest) -> signature64`,
   `Refresh(keyId)`, `Health` — plus the cluster-hosted key RPCs listed above. mTLS with cert
   pinning between driver↔cluster and cosigner↔cosigner.
2. `FrostBackend` (Scala) implementing `KmsBackend` — maps `generateSigningKeyPair`(Ed25519) and
   `sign` to the gRPC calls; every other op (encryption, symmetric, non-Ed25519 signing) delegates
   to the co-located `HsmBackend` (composite backend, routing by key type). With cluster-hosted keys
   enabled the encryption and symmetric ops route to the cluster instead and the delegate becomes
   optional (`delegate = "none"`); see *Cluster-hosted keys* above.
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
- Cluster-hosted keys: an RSA key generated on one cosigner decrypts on every other; the cluster
  survives a full restart and still decrypts; a write that cannot reach quorum rolls back rather
  than leaving one copy.
- The hosted/FROST boundary holds: with both kinds of key in one keystore, the hosted inventory
  lists only hosted keys, and the namespace key can be neither read nor deleted through the hosted
  API.

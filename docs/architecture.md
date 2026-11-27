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
   ├── namespace, protocol signing,
   │   sequencer auth (Ed25519)      `frost-…` → cosigner cluster: THRESHOLD t-of-n  [Phase 2]
   ├── encryption (ECIES P-256,
   │   RSA-2048-OAEP)                `rutli-…` → cosigner cluster: REPLICATED keys   [hosted v1/v1.5]
   ├── symmetric wrap (AES-256-GCM)  `rutli-…` → cosigner cluster: REPLICATED keys   [hosted v1]
   ├── protocol/sequencer (ECDSA P-256/384)    → threshold ECDSA (DKLS23) or HSM     [Phase 4]
   └── anything else                           → delegate: HSM (PKCS#11) | software  [Phase 1]
```

Two different protections now share one cluster, and the difference is not cosmetic. The Ed25519
keys (namespace, protocol signing, sequencer auth) are real `t`-of-`n` FROST share sets — no node
ever holds one. The hosted keys (`rutli-…`) are
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
  split custody and could reproduce the incident class. Endpoint failover covers a node that is down
  (`UNAVAILABLE` / `DEADLINE_EXCEEDED`) and, for operations safe to re-issue (sign, reads, decrypt,
  symmetric crypto), a leader that answers `INTERNAL` / `UNKNOWN`. Since 0.5.0 one cosigner's
  `NOT_FOUND` for a hosted key is confirmed with the other cosigners as well: read-repair makes it
  right in the normal case, but the driver does not rest a final "no such key" on one node
  ([hosted-keys.md](hosted-keys.md)).
- `DklsBackend` — Phase 4. Threshold ECDSA P-256/P-384 for protocol/sequencer keys.

Routing by key type lets each key sit on the right backend simultaneously (e.g. namespace key on
FROST threshold, encryption key cluster-hosted or on an HSM) behind one Canton-facing driver.

### Deadlines, keepalive and what Canton waits for

A cosigner that stops answering without closing its connections (its machine powered off, its
network cut) must cost one short deadline, not a minute. The driver has four settings in its `frost`
block:

| Setting | Default | What it bounds |
|---|---|---|
| `sign-attempt-timeout` | 5 s | One sign attempt at one cosigner. On the deadline the attempt is cancelled and the sign fails over to the next cosigner with the same signing intent. |
| `attempt-timeout` | 10 s | One attempt of any other call that fails over (reads, decrypt, symmetric crypto, hosted-key writes); at most one such deadline per cosigner. |
| `request-timeout` | 30 s | The whole driver call, every attempt included. A DKG's attempt gets all that is left of it; a DKG fails over only on a refused connection (no ceremony started), never on a deadline. |
| `keepalive-time` / `keepalive-timeout` | 10 s / 5 s | HTTP/2 pings on every cosigner channel, also while idle: a dead connection is torn down in about 15 s, and the next call fails over at once instead of waiting for a deadline. |

One attempt is in flight at a time. A failed-over sign keeps its request id. Each cosigner charges
its rate limit once per request id, and releases at most `signing_policy.max_shares_per_request`
shares for it, however many leaders the driver tries. In a node's sign journal a failed-over sign
shows as one more entry under the same `request_id`, with the same digest, from the leader that
completed it. A deadline takes the lead from that cosigner, so the next calls start at the next
one. After `leader-recovery` (60 s) the first endpoint in the list gets the lead back. If it still
fails, it loses the lead again, at the cost of one attempt. Each change of leader is logged at INFO
with the new leader order (`FROST: leader is now … ; leader order a > b > c`). The driver has no
metrics endpoint: that line and the `failover=` notes in the audit log show the order.

**A cosigner that restarted while another one led.** The driver keeps one channel per cosigner, and
with a sticky leader nothing is sent over the other channels while the leader serves. A cosigner
that restarts in that time leaves its channel without a connection, and where the cosigner came
back under another address (a pod under a new IP) the channel still has the address it resolved
when the connection closed. The first call over such a channel fails before the request is sent
(`UNAVAILABLE`), and only then does the channel resolve the name again and reconnect. So when a
call has failed at every cosigner, the driver can make one more attempt, at a cosigner its request
was never sent to: it waits for one of their channels to connect, at most one attempt deadline and
within `request-timeout`, and asks that cosigner once, with the usual attempt deadline. If no
channel connects in that time, the call fails as it would have; if the cosigner answers, its
answer is handled like any other (a refusal stands, an answer counts for the roster). This second
pass never repeats a request at a cosigner that may have seen it. (A sign that a cosigner
refuses for a stale cluster id is still repeated once from that cosigner, as before.) The lead
moves by the usual rules only, so the call after such a one may pay one failed attempt at the old
leader before the lead moves. The generation of a hosted key and calls on an EC hosted key have no
second pass. In the audit log it is one more `failover=` note, to a cosigner named earlier in the
same entry. A call that fails at every cosigner while the request to at least one of them could
not be sent (a cosigner that is down, a TLS handshake that fails) therefore takes up to one
attempt deadline longer to fail than before. The WARN line of each failed attempt names the exception under a transport
failure (`UNAVAILABLE: io exception; cause: … Connection refused: <host>/<address>`) and says when
the request was not sent.

**Which cosigner leads a sign (`frost.sign-leader`).**

| Value | Where each sign starts | Load for 2-of-3 |
|---|---|---|
| `sticky` (default) | The preferred leader, as before 0.5.0, or the next endpoint that has not answered another group key for that key. | While the preferred leader is healthy, it leads every sign and releases a share for all of them; the other two release one for half each. |
| `rotate` | The next endpoint in turn, among the healthy ones: not demoted within `leader-recovery`, and not a cosigner that answered another group key for that key. If none is healthy, the sticky choice. | Each node leads 1/3 of the signs. With the cosigners picking the second member by the request id, each node releases a share for 2/3 of them. |

Rotation changes where a sign starts, and a verified signature no longer moves the preferred
leader (under `sticky` it makes its cosigner the preferred leader; under `rotate` only a failure
moves the lead). One Canton call still has one attempt in flight, keeps its one signing intent
across failovers and stays within its budget. The rules for retryable and final errors above are
the same in both modes. Ceremonies (DKG) and every hosted-key call stay on the
preferred leader in both modes: a ceremony is bound to the leader that fenced it, a hosted-key
write is orchestrated by its leader, and the per-node decrypt limit assumes one leader.

Rotation exercises every node's leader path all the time, so a node that cannot lead shows up at
once instead of on the day a failover needs it. The cost: a node that is slow but still answers
inside the sign attempt deadline takes part in about 2/3 of the signs under `rotate`, against 1/2
under `sticky` with a healthy leader. A node slower than the deadline is demoted in both modes.
Under `rotate` it is then skipped as a sign start for `leader-recovery`, while another cosigner is
healthy. Under `sticky` the lead moves to the next cosigner, and `leader-recovery` only says when
the first endpoint gets the lead back.

**Per-node sign rate limits.** `signing_policy.sign_rate_limit_per_min` / `_per_day` and the
`rate_limits` rules are counted on each node, once per request id (failovers of one call share the
charge), for every signature the node takes part in. Under `sticky` the leading node takes part in
every signature and the other two in about half each. Under `rotate` each node takes part in about
2/3. Switching to `rotate` lowers the busiest node's count and raises the other two's, from 1/2 to
2/3 of the key's rate. A limit sized for the key's whole rate holds on every node in both modes. A
limit sized for the share a non-leading node used to see does not: check those before switching.

**The default.** `sticky` is the default in 0.5.0: leaving the setting unset keeps the policy of
earlier releases and does not switch rotation on. `rotate` is new in this release and has not yet
run on the two test stands for the two weeks asked of a default; it is switched on there by hand and
becomes the default in a later release. Operators who want it now set `sign-leader = rotate`, after
checking the per-node rate limits above.

**What Canton waits for.** Canton puts no deadline on a KMS driver call. It retries a *retryable*
failure forever, with a backoff up to 10 s (`KmsConfig.retries.failures`, Canton 3.6/3.7). The
driver reports as retryable only what clears by itself: "the cluster could not be reached in time"
(`UNAVAILABLE`, `DEADLINE_EXCEEDED`, the request budget spent, too few cosigners answering a
group-key query) and the cosigners' "not now" (`ABORTED`: a DKG or refresh ceremony holds the key,
the sign session is gone; also the same "ceremony … is already in progress" passed on as `INTERNAL`
by a leader that does not keep a member's status code). `ABORTED` for conflicting hosted-key material (`hosted-conflict`)
is final. A refusal (`PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, a bad request, an
unknown key), a signature that does not verify, a group key that differs from the pin, and
cosigners that disagree are not retryable, so Canton stops at once rather than retrying a
condition that will not clear.

**The confirmation window.** Above the KMS, time does matter. A participant's confirmation response
must be sequenced before `request time + confirmationResponseTimeout`, a dynamic synchronizer
parameter: **30 s in Canton's defaults**. Splice's value is not verified here. Read the live value
from the synchronizer's dynamic parameters, through the Canton console's
`topology.synchronizer_parameters` commands on the participant, as `confirmationResponseTimeout`.

With Canton's session signing keys off (the default), **every confirmation response is a threshold
signature through the cosigners**. The response must be signed and sequenced inside that window, so
the per-attempt deadline is what keeps one dead cosigner from costing a confirmation. At 5 s, two
failed attempts and a third that succeeds fit in about 11 s. A call that uses the whole 30 s budget
has missed the window anyway. Session signing keys (`crypto.session-signing-keys.enabled`) take the
cosigners off that path: the KMS key signs a short-lived session key, and the session key signs the
messages. The trade-off is that the session key's private half sits in the participant's memory
for its validity (5 minutes by default). Whether that is acceptable is the operator's decision;
Rütli does not set it either way.

### Peer liveness (between cosigners)

The same problem one layer down: a leader whose call to a peer hangs must not hold the driver's
5 s sign attempt. Since 0.5.0 each cosigner bounds and watches its own peer calls; nothing here is
configurable (the constants live in `frost/cosigner/src/peer.rs`).

**Channels.** Every peer channel runs HTTP/2 keepalive, also while idle: a PING after 5 s without
traffic, the connection closed when its PONG does not come within 3 s. A dead connection (a
partition, a pod replaced under a new address, a paused container whose kernel still answers TCP)
is gone at most 8 s after its last read, and the next call dials afresh. Below that, TCP keepalive
(10 s idle, 3 probes 3 s apart) and on Linux `TCP_USER_TIMEOUT` (10 s); a connection and its TLS
handshake must complete within 3 s.

**Deadlines.** Each peer call has a deadline on the leader's own clock, around the whole call
(queue, connect, RPC), sent to the peer as the call's `grpc-timeout` so it drops a handler nobody
waits for:

| Call | Deadline |
|---|---|
| Sign round 1 | 2 s (configurable: `peer_deadlines.sign_round1_ms`, 500 to 5000 ms) |
| Sign round 2 | 5 s (configurable: `peer_deadlines.sign_round2_ms`, 1000 to 9000 ms, under the 10 s per-call backstop) |
| Sign abort | 1 s |
| `NodeInfo`, `KeyEpoch`, `CeremonyStatus` | 3 s |
| Liveness probe (`NodeInfo`) | 2 s |
| Ceremony parts, fences, commits, hosted-key writes and reads | 10 s (unchanged) |

The two sign-round deadlines are configuration because a cluster readout under a 500-client burst
(issue #249) showed round 1 with 1.24x margin, short of the 3x the deadlines are meant to keep. Set
`[peer_deadlines]` (JSON: `"peer_deadlines": {"sign_round1_ms": 3000, "sign_round2_ms": 8000}`) on
every node, after every node runs a release that knows the section; round 1 plus round 2 must stay
under the 20 s sign budget. The abort and control deadlines stay constants.

When the Sign call carries a deadline (the driver's 5 s attempt does), the rounds fit inside it:
round 1 gets min(its deadline, time left − 1 s), round 2 likewise (2 s and 5 s unless configured), and no new subset
starts with less than 1 s left (the last attempt keeps no reserve). A deadline under 1 s is refused
at once with `DEADLINE_EXCEEDED`, before any round. Without one, a signature has 20 s. The client's
deadline only ever shortens the leader's work. A member that misses its deadline is excluded from
that signature; its session is aborted without waiting for it, the other members' in parallel, and
the leader tries the next subset without it — at most n − t + 1 attempts per signature (2 in 2-of-3,
3 in 3-of-5), as many as it takes to exclude every member that fails while t remain. A Sign that
runs out of attempts or time answers `UNAVAILABLE` with the `rutli-error: attempts-exhausted`
trailer (the members it excluded named to an authenticated client only); the driver fails over.

A member releases at most one share per attempt it is in (each attempt is a fresh session with
fresh nonces, and a session signs once), so one Sign call costs a member at most n − t + 1 of the
request's `max_shares_per_request` (8 by default), late shares of abandoned attempts included.

**Breaker.** Each leader keeps a state per peer: up, down (unreachable, stalled or refusing), or on
trial. It is fed only by the leader's own calls:

- *unreachable*: a connection that failed or closed under a call, a plain `UNAVAILABLE`, a
  `NodeInfo` call or probe past its deadline. `KeyEpoch` and `CeremonyStatus` read the peer's key
  store: past their deadline they open nothing. A `NodeInfo` probe every second brings it back.
- *stalled*: a sign round past its deadline while the peer's counters did not move. Every member
  reports `rutli-load: inflight=…; r1done=…; r2done=…; store=ok|down` on its sign and `NodeInfo`
  replies; a member that keeps completing rounds for anyone is busy, not stalled, and stays up.
  Round 1 does not touch the key store, so only completed round 2s count against a round-2 deadline.
  A member that reports no load (0.4.x) is never marked stalled.
- *refusing*: the peer answered with the `rutli-error: keystore-down` trailer.

A stalled or refusing peer gets a trial after a window of 2 s, doubling up to 30 s on every failed
trial: the next signature tries a subset with it first, and a successful round closes it. The trial
is taken only when that attempt starts (one signature per window per leader) and given back at once
if the attempt ends before it sent the peer a round, so a signature that does not contact the peer
never uses it up, and at most one signature per window pays a round deadline for it. A signature
that finds the trial taken still tries that subset in its tier's place. A probe whose
self-reported load shows round 2s completing again (or the store back) closes it too. Answered
refusals (policy, epoch, an unknown session, `sessions-full`, an invalid share) never open a
breaker.

**Which partners a leader signs with.** A leader always signs with itself. Its partners are the
next t − 1 cosigners on the ring of the others, starting at an offset taken from the intent's
request id: SHA-256 of a fixed tag and the request id, first 8 bytes, modulo n − 1. A leader
keeps one order for all its attempts, and a failover leader of the same driver call uses the same
offset over its own others. The driver draws request
ids at random, so over many signatures every cosigner takes part in the same share of them: about
half each besides a sticky leader in 2-of-3, about 60 % each in 3-of-5. Before 0.5.0 a leader
always signed with the lowest other identifier, so cosigner 1 took part in every signature and the
highest identifiers in few. A Sign without an intent, or with an empty request id, keeps that
roster order. The fallback subsets
after an excluded member follow the same rotated order.

The breaker only orders: subsets are sorted by their worst member (up, trial, down), and a down
peer is tried last, never skipped. Within its attempts a leader still reaches a subset of t members
that answer it, if there is one, so a false open costs a signature time, not the signature — unless
the time runs out first: each member tried and found failing costs up to one round deadline, and
the client's deadline (the driver's 5 s attempt) or the 20 s budget can end the Sign before the
last subset; the driver then tries another leader. Signing and
the anti-entropy sweep (which does not wait for an unreachable peer) consult it; DKG, refresh and
hosted-key writes do not. `rutli_peer_state`, `rutli_peer_breaker_transitions_total` and the
`RutliPeerDown` / `RutliPeerFlapping` alerts show it (`docs/observability.md`).

**Fast refusals.** A leader answers `UNAVAILABLE` at once, without contacting a member, when:

- fewer than t cosigners (itself included) are reachable from it — only unreachable peers count as
  missing, each asked once more within 1.5 s — with the `rutli-error: no-quorum` trailer. The
  message names the missing peers to an authenticated (mTLS) client only. An isolated leader
  refuses its first signature after two round-1 deadlines (about 4 s), then within the probe's
  answer, then at once;
- it leads more than 512 signatures at once, or its own round misses its deadline, with
  `rutli-error: overloaded`. It never excludes itself: the client moves to another leader.

Both count in `rutli_sign_fast_refusals_total{reason}`. The driver fails over on `UNAVAILABLE`
whatever the trailer.

**Member side.** A definite I/O error in a member's round-2 store work (EROFS, EIO, ENOSPC,
EACCES) marks its key store down at once instead of at the next probe; it then refuses with the
`keystore-down` trailer. Round-2 store work still running after 3 s starts a key-store probe at once,
so a hung volume is refused about 9 s after it hung instead of up to 21 s. The mark is not sticky:
the next readiness probe that finds the store working clears it, with no restart. A sign round that
waited for a blocking thread past its caller's deadline (the call's `grpc-timeout`) is not started:
the leader has stopped waiting and its abort may already have come and gone, so a round 1 opened
then would hold nonces until the TTL. A round 2 that was already in its store work when the leader
gave up finishes and journals its share once; the leader discards it. Such late shares are allowed
and bounded: the nonce is single use, and each counts against `max_shares_per_request`.

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
request (`INTERNAL` / `UNKNOWN` — never for a DKG ceremony; a sign fails over on every status except
`PERMISSION_DENIED`, `UNAUTHENTICATED`, `RESOURCE_EXHAUSTED` and `INVALID_ARGUMENT`, and on a signature
that does not verify against the pinned group key), and the share nodes
coordinate the FROST rounds internally. FROST sessions are independent, so no replicated log is
needed (see phase-2-frost.md). The `FrostBackend` just submits `sign(hash, keyId)` and awaits the
aggregated signature. This keeps round orchestration and nonce-session state out of the
Canton JVM, survives driver/node restarts cleanly, and makes the cluster independently testable. A
compromised or crashed client can stall signing but never touches key material or nonce state.

## Crypto choices (with rationale)

| Canton key | Algo (format) | Backend | Why |
|---|---|---|---|
| Namespace / identity root; protocol signing and sequencer auth when Ed25519 (Canton's default) | Ed25519 (`concat`, raw 64-byte R‖S) | **FROST-ed25519** (ZF `frost-ed25519`) | RFC 9591; emits standard RFC 8032 sig Canton verifies natively. Audited by NCC Group (public report, Oct 2023, v0.6.0; we pin 2.2.0). The one key where "no node holds the whole secret" clearly earns MPC. |
| Protocol / sequencer auth (roadmap, ECDSA keys) | ECDSA P-256/P-384 (`der`) | **DKLS23** (Silence Labs) or HSM | OT-based, avoids the Paillier/TSSHOCK class that broke GG18/GG20/CGGMP. ToB-audited. **Pin DKLS23, not DKLS24** (2026 OT-count caveat). Confirm P-384 instantiation. |
| Asymmetric encryption | RSA-2048-OAEP-SHA256 (Canton's KMS-mode default) | **Cluster-hosted (replicated, sealed)** or HSM delegate | **Not threshold — and for RSA that is permanent, not a roadmap item.** No Rust implementation of threshold RSA decryption exists (crates.io sweep found none; Shoup's construction lives in Go/C++/Java), and RUSTSEC-2023-0071 (Marvin timing side-channel, still unpatched in 2026) rules out the pure-Rust `rsa` crate for a network-facing decryptor — so the cluster holds a whole key and decrypts with `aws-lc-rs`. It performs the *full* OAEP decrypt: returning raw `c^d mod N` would hand the driver a Manger/Bleichenbacher oracle. |
| Asymmetric encryption | ECIES-P256 (`EciesHkdfHmacSha256Aes128Cbc`) | Cluster-hosted whole key (v1.5, shipped) → **threshold `frost-p256`** (v2, planned for release 2.0; not implemented) | ECDH *is* thresholdable where RSA is not: each node returns `λᵢ·dᵢ·R` and the leader adds the points — one round, stateless, no nonce hazard. Both versions share one wire contract (`EcdhDerive`), so promoting to real threshold is a server-side change. Gated on the synchronizer's `requiredEncryptionSpecs` admitting `EcP256`. |
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
  recipient's static key comes from its seal secret: the distribution seed in its per-node seal
  bundle (`share_seal.secret_file`), or, on the deprecated shared master (`secret_env`), a
  derivation from that master. With hosted keys on, a node on a seal bundle needs every other
  peer's public key pinned in config (`peers[].dist_public_key`). If its own entry also carries a
  pin, it refuses to start when that pin does not match its seal keys, so a wrong bundle or wrong
  mount is caught *before* any key exists. Without the own pin the mismatch shows only when peers
  refuse to replicate to it.
- **Anti-entropy and read-repair.** A sweep every 300 s pulls keys this node lacks; a request
  landing on a lagging replica pulls on demand. Since 0.5.0 a node stores a key it lacks only when
  two peers return the same copy, the sweep never pushes, and a peer's push into an id the node
  lacks is accepted only from the leader holding its generation fence (`docs/hosted-keys.md` §4). Hosted keys are
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
`EcdhDerive`, `SymmetricEncrypt`, `SymmetricDecrypt`, `HostedKeyStatus`. New Peer RPCs (mesh only, gated by `peer_allowlist`):
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
`frost-namespace`, `signing` → `frost-signing`), and hosted ids as `rutli-<kind>-<name>-<uuid>`.
Who names the key matters: a Splice validator calls it `namespace`, Canton's own auto-init calls
it `<node>-namespace` (so `frost-participant1-namespace`). Rules, ACLs and rate limits match ids by
prefix, so a rule written for one form never matches the other. Take the real id from the driver
log ("initiating distributed key generation for …") or `keys.secret.list()`. The
determinism is deliberate — a retry or a failover must ask for the *same* namespace key, never mint
a second one — but it means two participants pointed at the same cosigner cluster both ask for
`frost-namespace`. Before 0.4.0-rc.3 the cluster's create-once guard refused the second
participant's DKG with `ALREADY_EXISTS`. (The 2026-10-07 DevNet soak bring-up hit exactly this with
a second validator; the only way out at the time was retiring the old shares by hand on every
cosigner.) Since 0.4.0-rc.3 a DKG for an id that every node already holds from a DKG returns the
existing key, so that Canton's retry succeeds ([ceremonies.md](ceremonies.md#idempotent-dkg)). The
cluster cannot tell a retry from a second participant. Before 0.5.0, without a prefix, the second
participant was handed the first one's Ed25519 keys, and the two shared one identity root, with no
warning.

Since 0.5.0 the DKG reply says whether the key already existed (`existing`), and which DKG created
it (`origin_ceremony_id`, the ceremony the client's intent named) when the leader still holds that
ceremony's record: settled records are kept 30 days, and a refresh starts a new sharing, after
which no origin is named. The driver accepts an existing key only when that ceremony is one it
asked for itself in this process: Canton's retry after a timeout. Any other existing key is refused, naming `frost.key-prefix` and
`frost.adopt-existing-keys`. A driver that restarts in the middle of a bootstrap has forgotten its
own ceremony ids and is refused too, unless `frost.pin-dir` is set. With it, the driver writes
each ceremony id to the pin directory (`<key-id>.dkg`, fsynced) before the request goes out, and a
restart between request and reply adopts the key. The refusal says what to do. If another participant uses this cluster with the
same `frost.key-prefix`, the key is theirs: do not adopt it, give this participant its own prefix
and driver certificate. Otherwise it is this participant's own key from before the restart: list its
id in `frost.adopt-existing-keys`, restart the participant, and remove the entry once Canton has
registered the key. A DKG sent without an intent (no
TLS, `frost.sign-intents = off`) cannot be matched and is accepted with a warning, and so is a
reply from a leader older than 0.5.0, which leaves the field out.

The flag is the leader's word. A compromised leader can say `existing = false` for another
participant's key. The boundary that holds against it is the per-CN `signing_policy.signer_acl`,
which every cosigner checks on `Signer.Dkg`, together with the key prefix; the flag catches the
honest misconfiguration, which was silent before. Set the prefix before the first bootstrap, and give each participant its own
driver certificate with a `signing_policy.signer_acl` entry: the ACL is checked on `Signer.Dkg`
too, so a driver that asks for another participant's id is refused
([approval-quorum.md](approval-quorum.md)).

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
  participant's DKG returns the first one's keys and reports no error (since 0.4.0-rc.3; earlier
  releases refused it). The cluster refuses it only if that participant's driver CN has a
  `signer_acl` entry that does not cover the id.
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
  authorization boundary: a driver whose CN has no `signing_policy.signer_acl` entry can address
  any id on the cluster, so participants sharing a cluster without ACL entries share a trust
  domain. An entry limits that CN to the key-id prefixes it lists, on every key-scoped Signer RPC
  including `Signer.Dkg`; `signer_acl_required` refuses a CN that has no entry
  ([approval-quorum.md](approval-quorum.md)).

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
  on a real Canton participant. ✅ **v1.5**: `EcdhDerive` + hosted EC-P256 keys (still whole
  keys) with driver-side ECIES via BouncyCastle's `IESEngine`, advertising `EcP256` to steer
  deployments off RSA. **v2** (planned for release 2.0, [roadmap.md](roadmap.md)):
  threshold ECIES via `frost-p256` — one stateless round, no nonce hazard — on the **same wire
  contract as v1.5**, so promoting is a server-side change plus a config flag. **Never**: threshold
  RSA.
- **Phase 4** — `DklsBackend`: threshold ECDSA (P-256/P-384) for protocol/sequencer keys.
- **Phase 5** — Wallet Gateway signing-driver SPI (second seam); SOC2/ISO/DORA evidence pack;
  published third-party MPC audit.

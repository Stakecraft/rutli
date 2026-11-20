# Cluster-hosted keys — operator guide

The cosigner cluster can hold Canton's **non-FROST** key material as well as the Ed25519 keys:
RSA-2048-OAEP-SHA256 and EC P-256 (ECIES) encryption keypairs, and AES-256-GCM symmetric keys. A
participant configured this way needs **no HSM and no local key state**.

This page is the operational half — when to use it, how to turn it on, how the keys behave, and what
to do when the alerts fire. The rationale (why threshold RSA is permanently out of scope, why the
quorum and the replication wrapping look the way they do) is the design record in
[`hosted-keys-design.md`](hosted-keys-design.md); this page links to it rather than repeating it.

**State this plainly wherever it comes up:** hosted keys are **replicated whole keys, not threshold
shares**. They are generated on one cosigner, sealed at rest on every node, and any node can serve a
decrypt on its own. The FROST Ed25519 keys (namespace, protocol signing, sequencer authentication)
are unchanged and remain genuine 2-of-3 threshold MPC — no machine ever holds one whole. Section 5 states the cost of that difference.

## 1. What it is, and when to use it

Rütli's cluster serves the Ed25519 keys (namespace, protocol signing, sequencer authentication) as
FROST threshold keys. Everything else Canton needs — the asymmetric encryption keypair for
confidential views, the symmetric key that wraps its private key store — comes from one of three
places:

| | HSM delegate | software delegate (sealed) | **cluster-hosted** |
|---|---|---|---|
| Survives a participant restart | yes | yes (sealed on a durable volume) | yes — one sealed replica per cosigner |
| Where private material lives | inside the HSM | on the participant host | on the cosigners, sealed |
| Participant-host compromise yields | a decrypt oracle while the session lasts | **every key the host holds** | a decrypt oracle while the driver cert lasts |
| One cosigner compromise yields | — | — | that key's material (n copies exist) |
| Namespace key | unaffected — 2-of-3 FROST | unaffected — 2-of-3 FROST | **unaffected — 2-of-3 FROST** |
| Threshold? | no | no | **no — replicated** |
| Needs dedicated hardware | yes | no | no |

Choosing between them:

- **Keep the HSM delegate** if you already run one and its custody story is what your auditors
  signed off on. Hosted keys do not beat an HSM on key-extraction resistance; they beat it on not
  needing one.
- **Use cluster-hosted keys** when you have no HSM. The win is **relocation**: key material leaves
  the busy, internet-adjacent Canton participant host and lives on three hardened, single-purpose,
  allowlisted nodes that do nothing but hold keys. Durability improves as a side effect — n sealed
  replicas plus the existing backup tooling, instead of one directory on one host.
- **The sealed software delegate is for tests and for moving off it.** It keeps every encryption
  key on the participant host, so a compromise of that host yields them all. Do not plan production
  keys behind it; use cluster hosting or the HSM delegate. A node that still runs it must run the
  sealed form: on 2026-08-12 a heap-only software delegate lost an RSA encryption key across a
  Splice upgrade restart and the participant took a fatal `KmsDecryptError` → synchronizer
  disconnect. That incident and its recovery are
  [`disaster-recovery.md` §3b](disaster-recovery.md); cluster hosting removes the key from that host
  altogether.

## 2. Enabling it

### Cosigner

Add a `hosted_keys` block to each cosigner's JSON config (the shipped compose TLS examples carry it;
with Helm or `deploy/k8s` it is `hostedKeys.enabled` plus the pins below):

```json
{
  "share_seal": { "secret_file": "/run/rutli/seal/node.json" },
  "hosted_keys": {
    "enabled": true,
    "write_quorum": 2,
    "anti_entropy_interval_secs": 300
  }
}
```

On a seal bundle (`secret_file`, the per-node secret — see
[runbook-per-node-seal.md](runbook-per-node-seal.md)), each node also needs
`hosted_keys.commitment_key` and every peer's `dist_public_key` pinned in `peers[]`: the node holds
only its own distribution key. `rutli-cosigner seal split-legacy` (migrating) prints both; on a new
cluster `seal new-node` prints each node's distribution key, and the commitment key is one value
generated for the cluster (`openssl rand -hex 32`). The legacy `"share_seal": { "secret_env": "RUTLI_SEAL_SECRET" }` derives
them from the shared master instead.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Off unless set. Absent block = no hosted keys, no replication, no sweep. |
| `write_quorum` | `2` | How many cosigners must hold a new key before it is reported created. |
| `anti_entropy_interval_secs` | `300` | Reconciliation cadence (floor 10s). |
| `decrypt_rate_limit_per_min` | `6000` | Decryptions (`Decrypt`, `EcdhDerive`, `SymmetricDecrypt`) per key per minute, **on this node** (`0` disables). See below. |

**The decryption rate limit is per node, not per cluster.** Each cosigner enforces
`decrypt_rate_limit_per_min` with its own buckets; nodes share no limiter state. A stolen driver
certificate that calls every cosigner directly therefore gets **n ×** the configured budget per key
(18 000/min on a 3-node cluster at the default). The driver, by contrast, sends a key's traffic to
one preferred leader at a time, so the value must cover the **full** legitimate rate on a single
node. To size it: pick the cluster-wide ceiling you are willing to grant an attacker, set
`decrypt_rate_limit_per_min = cluster_budget / n`, and confirm that still clears your legitimate
per-key peak with headroom (the "approaching its rate limit" warning tells you when it does not). A
cluster-wide limiter was considered and not built: it would put a cross-node round trip on Canton's
decrypt hot path, and simply dividing a cluster budget by n on every node would cut legitimate
headroom n-fold because of that one-leader routing.

**`share_seal` is mandatory.** Config validation refuses to start a node with
`hosted_keys.enabled` and no `share_seal`: a hosted key is a *whole private key*, and one sitting
unsealed on disk would be strictly worse than the HSM delegate it replaces. The node's seal secret
does double duty — it seals the file at rest *and* holds (seal bundle) or derives (legacy master)
the node's X25519 distribution key used to wrap material for replication — so the daemon also
refuses to start if the referenced bundle file or environment variable is missing. A *wrong* secret is not silently tolerated either: sealed files fail
to open and the affected operation fails closed rather than the node serving a wrong or empty key.

**Write quorum is 2-of-3 by default, deliberately.** Requiring all three would mean you cannot mint
or rotate an encryption key while any cosigner is down — worse availability than the single copy an
HSM gives you, and a contradiction of the cluster's own 2-of-3 fault model. 2-of-3 is only safe
because anti-entropy and read-repair ship with it (section 4); do not disable the sweep. Below
quorum a write **rolls back** rather than leaving one lonely copy (section 3). A configured
`write_quorum` is honoured on the `GenerateKey` path — set it to `3` if you would rather a write
fail than commit while a cosigner is down. Since 0.5.0 a node that lacks a key pulls it only when
**two** peers hold the same copy, so automatic repair needs at least three cosigners and
`write_quorum` of at least 2; the daemon warns at startup otherwise.

**Run hosted keys only on a TLS cluster.** Replication rides the mesh Peer API, which is gated by
`peer_allowlist` (see [`phase-2-frost.md`](phase-2-frost.md) — the driver must never be on that
list). `FetchKey` wraps material to the *authenticated* caller, identified by its client-certificate
CN rather than by anything in the request body, so a plaintext cluster cannot pull a key at all. The
plaintext dev compose is not a supported configuration for hosted keys.

Key material never crosses the mesh in the clear, even inside mTLS — a service-mesh sidecar
terminating TLS would otherwise see plaintext private keys. Each replica is sealed to one recipient
with ephemeral X25519 → HKDF-SHA256 → AES-256-GCM, with the AAD binding cluster id, key id, spec and
recipient so an envelope cannot be replayed to another node, another key, or another deployment (the
cluster id is derived from the CA certificate). Note what this does *not* do: under the legacy shared
master secret every cosigner can derive every peer's distribution key, so this protects against a
TLS-terminating middlebox and against replay, not against another cosigner. On a seal bundle a node
holds only its own distribution key and wraps only to the key pinned for each peer.

### Driver

```hocon
config {
  backend = "frost"
  frost = {
    endpoints    = [
      { url = "cosigner1:9101", tls-name = "cosigner1" },
      { url = "cosigner2:9102", tls-name = "cosigner2" },
      { url = "cosigner3:9103", tls-name = "cosigner3" }
    ]
    hosted-keys  = true
    delegate     = "none"
    key-prefix   = ""        # set per participant when several share this cluster — see below
    tls = { ca-cert = "/certs/ca.crt", cert = "/certs/driver.crt", key = "/certs/driver.key" }
  }
}
```

Routing is by key-id prefix: `frost-` → threshold Ed25519 in the cluster, `rutli-` → cluster-hosted,
anything else → the delegate. With `delegate = "none"` there is no third path — the participant
holds no key material at all, and any key id matching neither prefix fails loudly and names the key
instead of silently doing local crypto. The cosigners hold the two namespaces apart too (since
0.4.0-rc.6): a node creates a hosted key — generated, replicated from a peer, pulled by
anti-entropy or read-repair, or imported — and records a tombstone or takes a hosted-key fence only
under an id whose first `frost-`/`rutli-` tag is `rutli-`, so no peer can park a hosted key on a
FROST key's id. A hosted record already under another id (squatted before 0.4.0-rc.6, or made by
hand) keeps serving on the nodes that hold it but is no longer replicated or repaired, nor restored
from a backup onto a node without it; it can still be deleted where it is — `DeleteKey` succeeds once
every node has answered, with a tombstone where the record was and "nothing here" elsewhere, so
success means the nodes report nothing hosted left under the id (a node that cannot read its file,
or cannot be reached, fails it; nothing anywhere is NOT_FOUND) — and `hosted-clear-tombstone` on
those nodes then frees the id.

**Several participants on one cluster:** FROST ids derive from Canton's key name, so a second
participant on the same cluster asks for the same `frost-namespace` and its DKG is refused with
`ALREADY_EXISTS` — by design, that guard protects the live key. Give each participant its own
`key-prefix` (`"soak1-"`, `"soak2-"`, …); it is prepended to every id, FROST and hosted, so the ids
stay disjoint. Choose it before first bootstrap and never change it; leave it unset on an existing
deployment, whose ids stay exactly as they are. Details and the rules that follow from it (approval
rule prefixes, trust domain) in [architecture.md](architecture.md#one-cluster-several-participants--frostkey-prefix).

Two deliberate absences:

- **No automatic fallback to the delegate on `NOT_FOUND`.** A fallback would silently re-create split
  custody — some keys in the cluster, some on the host — which is the shape of the August incident.
  Read-repair (section 4) is what makes `NOT_FOUND` authoritative: a node that lacks a key and
  cannot confirm it from two peers answers `UNAVAILABLE` (trailer `rutli-error: hosted-unconfirmed`),
  never `NOT_FOUND`, so the driver moves on to a node that holds it. Endpoint failover stays restricted
  to a node that is down or broken (`UNAVAILABLE` / `DEADLINE_EXCEEDED`, and `INTERNAL` / `UNKNOWN`
  for reads and decryptions), as for signing — with one exception, for EC keys only: a
  cosigner that predates `ec-p256-ecies` cannot read-repair one, so its "not found" is not
  authoritative and the driver asks the next cosigner (rollout order, below). Even then it never
  falls back to the delegate.
- **No hardcoded spec list.** The driver asks the cluster via `Capabilities` at startup, so adding a
  key type later (section 6) needs no driver release.

Keep `delegate = "hsm"` if you still need key types the cluster does not serve.

**Which encryption key type Canton mints is Canton's choice**, not the driver's: a KMS participant
defaults to RSA-2048 (`CryptoProvider.Kms`). To use an ECIES key — the type every JCE participant
already uses, and the one that can become a threshold key later (section 6) — set it in the
participant's crypto block.

**Rollout order for ECIES — cosigners first, all of them.** A cosigner older than `ec-p256-ecies`
cannot store or serve such a key, and would answer for it as if it did not exist (read-repair
skips what it cannot parse, `KeyInfo` says `exists: false`) — the shape that ends in a Canton
`KmsDecryptError`. Two guards keep a mixed-version cluster from ever holding one:

1. **Upgrade every cosigner.** A leader refuses `GenerateKey` for `ec-p256-ecies` with
   `FAILED_PRECONDITION` ("refusing to create an ec-p256-ecies key: cosigner N does not support it")
   unless every peer reports the spec in `NodeInfo` — and a peer that is down cannot be shown to
   be upgraded, so all of them must also be **up** to create an EC key. RSA/AES writes are
   unchanged and still commit at the write quorum with a node down.
2. **Then restart the participant with the two lines below.** The driver asks every configured
   cosigner for `Capabilities` at startup and advertises `EcP256` /
   `EciesHkdfHmacSha256Aes128Cbc` if **every cosigner that answers** reports `ec-p256-ecies`, and at
   least a majority of the roster answers (the driver does not know the threshold; for 2-of-3 and
   3-of-5 the majority is the threshold).
   - A cosigner that answers **without** it — an older release, or one that does not know
     `Capabilities` at all — vetoes ECIES: it is not advertised, and a participant configured for it
     refuses to start with `The configured default scheme EC-P256 not supported by the KMS`.
     Finish the upgrade.
   - A cosigner that does **not answer** (down, unreachable) does not veto, so a participant
     restarts with one node down. The driver retries silent nodes (up to 30 s, cut to 5 s once a
     majority has answered) and names them at WARN:
     `FROST: no capabilities answer from <endpoint> (UNAVAILABLE); 2 of 3 answered, a majority.
     Advertising what every answering cosigner serves: aes-256-gcm, ec-p256-ecies, …`
     — verified on 3.6.1 with one of three cosigners stopped (`scripts/e2e-ecies-hosted.sh`, phase D).
   - The residual risk — the silent node is old, and comes back — is covered at run time: for an EC
     hosted key, an answer that says "I do not have it" (UNIMPLEMENTED or NOT_FOUND from
     `EcdhDerive`, NOT_FOUND from `PublicKey`, `exists: false` from `KeyInfo`) sends the request to
     the next cosigner, and that node is not made the preferred leader. The audit entry carries
     `ec-failover=<from>→<to> reason=…`. RSA, AES and FROST keys keep the old rule: `NOT_FOUND` is
     authoritative. The driver re-asks `Capabilities` after 60 s while any node was silent, so a
     returning old node also stops new EC keys being routed to the cluster.
   - The same goes for a cosigner that holds the key id but **wrong EC material** (a stale or
     corrupt replica): its `EcdhDerive` succeeds with a well-formed but wrong shared secret, and the
     driver's MAC/padding check fails. An `EcdhDerive` only counts once its shared secret has
     opened the ciphertext, so the driver then asks the next cosigner (`ec-failover=… reason=
     ECIES_AFTER_ECDH`) and does not make the bad node the preferred leader; the decrypt fails
     (`ecies-failure=after-ecdh`) only if no cosigner's shared secret opens it. The cost of that,
     for a genuinely forged ciphertext, is bounded: at most **one `EcdhDerive` per roster entry**
     (n calls, never a retry loop), each charged to that node's decryption rate limit (section 5).
     A rate-limit refusal (`RESOURCE_EXHAUSTED`) is never routed around: it is surfaced at once.

```hocon
crypto {
  provider = kms
  kms { type = driver, name = "rutli", config = { backend = "frost", frost = { hosted-keys = true, … } } }
  encryption.keys.default       = ec-p-256
  encryption.algorithms.default = ecies-hkdf-hmac-sha-256-aes-128-cbc
}
```

The Global Synchronizer admits both: Splice SVs run Canton's JCE defaults for static synchronizer
parameters on every network, which allow `EcP256` and `Rsa2048` (see
[roadmap-migration.md](roadmap-migration.md), technical notes).

## 3. Key lifecycle

You rarely drive these RPCs by hand: Canton mints keys through the driver's
`generateEncryptionKeyPair` / `generateSymmetricKey` and uses them through `decryptAsymmetric`,
`encryptSymmetric`, `decryptSymmetric`. What follows is what happens underneath.

### Generate

`GenerateKey(key_id, spec, intent)` on any cosigner. That node leads.

**The client's generate intent** (since 0.5.0). The request carries a `SignedIntent` with purpose
`generate-key`: the cluster id, the key id, the spec (`hosted_spec`), the roster identifier of the
cosigner asked to lead (`leader`, which the driver reads from that endpoint's
`Capabilities.node_identifier`), a 16-byte request id and a validity of at most
`intent_max_lifetime_secs`. The driver signs it with its mTLS key, a fresh one for every endpoint it
tries. The generation's ceremony id is `genkey-<hex(request_id)>`. Every node checks the intent at
its fence, before it takes the guard, with the same rules as a DKG intent (`docs/ceremonies.md`,
"Ceremony intents"): the signer on `signer_allowlist` and within its `signer_acl`, its pin, the
cluster, the key, the spec, and that the cosigner fencing it is the leader the intent names. The
leader checks it first on `GenerateKey` (the signer must be the caller) and fences its own node
first, so it is verified there before anything is minted. A fence marks the ceremony id durably
(`keys/.ceremonies/.fenced/`, 24 h): the request id is spent on every node the fence reached, for any
leader. A push that would create a copy the node lacks is accepted only under the guard that fence
took, for the spec it declared; a push of the identical key the node already holds is a no-op and
succeeds without that check. Without a valid intent the leader answers `PERMISSION_DENIED`, and a
peer refuses the fence and any push that would create a copy.
Refusals count in `rutli_ceremony_intent_refusals_total{reason}` (`RutliCeremonyIntentRefused`) and
are logged with the asking peer and the key. The switch is `signing_policy.require_ceremony_intent`
(on by default with TLS); with it off, a generation without an intent is accepted, counted in
`rutli_ceremony_intent_absent_total` and warned about, and an intent that is present is still
verified in full.

Then:

1. Fences the key id on every peer, its own node first, so two concurrent generates for the same id
   serialize.
2. If it does not hold the id, asks its peers. Two that hold the same copy: it adopts that key
   (`created = false`) instead of minting a second one. One copy only, or copies that disagree: it
   refuses (`UNAVAILABLE` or `ABORTED`, below) and mints nothing.
3. Otherwise, and only when `n - write_quorum + 1` nodes (itself included) answered that they hold
   nothing under the id, generates a key, then wraps and pushes a replica to each peer. A silent
   node does not count as "not held": with 2-of-3 the leader and one peer are enough, so one node
   down still mints; with five nodes and `write_quorum: 2` four answers are needed, so one node down
   still mints and two down do not (`UNAVAILABLE`). A key the client was given sits on at least
   `write_quorum` nodes, so it cannot hide among the silent ones. A peer stores a key it
   lacks only from the caller holding its fence for the id, and only if no other peer it can reach
   holds different material.
4. Verifies each peer's commitment to the stored material matches its own.
5. Reports `created`, `replicas` and its own `commitment` to the material (since 0.5.0).

**The driver checks the reply** (since 0.5.0). The leader's answer is one cosigner's word. Before
the key id goes to Canton, the driver asks every endpoint for its own copy (`KeyInfo` with
`local_only`, no read-repair). It accepts the key only when at least two cosigners hold a copy with
the reply's commitment, spec and public key, and no cosigner reports other material under the id
(one for a single-endpoint dev roster). Silent endpoints (an error, a timeout, a call that never
completed), nodes without a copy, and nodes too old to send a commitment count neither way. Then:

- Too few confirmations only because endpoints were silent (they could have confirmed): the driver
  asks the next endpoint to lead the same id, under a fresh intent. That leader holds the key,
  adopts it from agreeing peers, or refuses; it never mints over a copy. Its reply is checked the
  same way. Each endpoint leads at most once per call. The log line is `hosted key <id> from
  <endpoint> not confirmed: … silent: <endpoints>`, the audit entry carries `hosted-check=unconfirmed`
  and a `failover=… reason=UNCONFIRMED` note. When no endpoint is left, the call fails, not
  retryable, with that message. The check uses what is left of the driver's `request-timeout`,
  keeping room for one more attempt; when no attempt could follow in time, the call also fails with
  that message, never with a spent request timeout.
- Anything else (absent copies where the leader reported a key, a wrong spec, an endpoint reporting
  other material): the call fails at once, not retryable. One endpoint that reports other material
  is enough. That is the endpoint's own statement and the driver cannot check it: a faulty or
  compromised node can make it falsely and so veto the generation, which it could also do at the
  cosigner level. The driver fails closed, as a cosigner does on a conflict (below).

Either way the key id never reaches Canton and the leader that answered loses the lead (the driver
log line is `hosted key <id> from <endpoint> REFUSED`, naming the endpoint that reported other
material; the audit entry carries `hosted-check=failed`). The same check applies when `GenerateKey`
returns an existing key. Leave such an id alone and compare the nodes with `verify-hosted`; Canton
generates its next key under a new id.

**A conflict aborts the generation** (since 0.5.0). A peer that holds other material under the id,
or answers with a commitment to other material, or refuses because another peer holds other
material, is never outvoted by the nodes that agree: the leader rolls the generation back and
answers `ABORTED` with the trailer `rutli-error: hosted-conflict`. The driver does not fail over on
it. `rutli_anti_entropy_conflicts_total` and
`rutli_hosted_replication_refusals_total{reason="generate-conflict"}` count it, the log line
(`hosted key generation ABORTED`) names the key and the peer, and `RutliHostedKeyConflict` pages.
Follow "When `rutli_anti_entropy_conflicts_total` increases" (section 4). Up to 0.4.0 such a peer
only failed to count toward the quorum, so the leader and one more node could report the key
created while a third served other material.

Supported specs:

| Spec | Use | Shape |
|---|---|---|
| `rsa-2048-oaep-sha256` | Canton's asymmetric encryption key (confidential views) | ciphertext exactly 256 bytes in, ≤ 190 bytes plaintext out |
| `ec-p256-ecies` | The same, as Canton's ECIES (`EciesHkdfHmacSha256Aes128Cbc`) | the cluster answers `EcdhDerive(V)` with `Z`; the driver completes the decryption (below) |
| `aes-256-gcm` | Canton's symmetric wrapping key | blob is `0x01 ‖ nonce(12) ‖ ciphertext‖tag` (versioned framing) |

**`key_id` is caller-supplied and generation is idempotent.** Repeating the request returns the
existing key with `created = false` instead of minting a second one, so a client retry or a driver
failover can never produce two different keys under one name. Requesting an existing id with a
*different* spec is a hard error, never a silent replacement.

**Below `write_quorum` the write rolls back.** The leader purges the partial copies and returns an
error, leaving the id free for a clean retry. Each node removes only a key it created in that very
generation while the generation still holds its fence — a `PurgeKey` without a delete intent is
nothing else, and only the generation's leader (the caller whose fence took the guard) may send it,
so a leader cannot use "rollback" to destroy an existing key, nor another peer a fresh copy — a
single node holding the only copy is precisely the failure this feature exists to prevent. Above
quorum but below n, the key is created, a warning is logged, and the missing node pulls the key at
its next sweep (two nodes hold it).

**A leader that dies mid-generation** leaves the copies it already wrote. Nothing rolls them
back, and its fences lapse after the orphan timeout (15 minutes). The leader writes a new key to its
own disk only after the write quorum holds it. What is left, step by step (2-of-3):

| The leader dies… | What is left | What a retry with the same id does |
|---|---|---|
| before any replica | nothing on any disk | mints a new key, cleanly |
| after one replica, before its own write | one copy on that peer, served there | if that peer answers: refuses (`UNAVAILABLE`), the driver moves to that peer, which returns the key and replicates it. If that peer and the first leader are both down: refuses (too few "not held" answers). **If that peer is down and the first leader is back (empty): mints a second key; when the peer returns, the id is forked** (paged as a conflict) |
| after its own write, before the reply | copies on the write quorum | returns or adopts that key, or refuses; never a second key (a mint needs `n - write_quorum + 1` "not held" answers, and the quorum cannot hide among the rest) |
| after a rollback that missed a node | that node's copy (`rutli_hosted_rollback_incomplete_total`, `RutliHostedRollbackIncomplete`) | as the second row |

The second and last rows are open: a copy written by a generation nobody confirmed is served by
the node holding it. Until a later release makes such replicas non-servable until the generation is
confirmed, act on `RutliHostedRollbackIncomplete` and on a conflict by hand (section 4). A key no
retry ever claims stays where it is; delete it with `DeleteKey` if it matters.

### Use

Any cosigner can serve a decrypt; the driver's normal endpoint failover applies. Two properties
worth knowing:

- The cluster performs the **whole** RSAES-OAEP-SHA256 decrypt, never returning raw `c^d mod N` for
  the driver to unpad — that would be a textbook Bleichenbacher/Manger oracle. Every decryption
  failure returns the same opaque error for the same reason.
- **ECIES is split between the cluster and the driver.** Canton's ciphertext is
  `iv(16) ‖ V(65) ‖ AES-128-CBC ‖ HMAC-SHA256 tag(32)`, at most 256 bytes. The driver checks that
  shape (and that `V` is an uncompressed point on P-256) before anything is sent, asks the cluster
  for `Z = x(d·V)` with `EcdhDerive`, and finishes in BouncyCastle's own `IESEngine` — the code
  Canton's encryptor uses — so no KDF or MAC is reimplemented anywhere. Only the ECDH needs the
  private key; the rest is public computation. The cluster accepts only a 65-byte uncompressed
  point and refuses one that is not on the curve, refuses `EcdhDerive` on any key that is not
  `ec-p256-ecies`, and charges it to the same per-key budget as `Decrypt`: for a recorded
  ciphertext, `Z` is as good as the plaintext.
- Decrypt is on Canton's per-transaction hot path, unlike topology signing, so it is deliberately
  **not** gated by [`approval-quorum.md`](approval-quorum.md) and not journalled per operation. Note
  that the driver's audit log, if enabled, does wrap `decryptAsymmetric` — that is a hash-chained
  fsync per decrypt. Measure it against your view volume before enabling it on a busy participant.

### Rotate

**Hosted keys are create-once-immutable**: a key id maps to one key forever. Rotation means minting
a *new* key id plus a Canton topology transaction, which is exactly what
`rotate_node_key(s)` already does — see [`key-rotation.md`](key-rotation.md). The driver mints the
replacement in the cluster; the topology transaction is signed by the namespace key, which is still
threshold-signed by the FROST quorum.

Never try to replace the material behind an existing id. Anti-entropy would read the result as a
conflict, and correctly refuse to reconcile it (section 4).

Rotation fixes the future, not the past — see section 5.

### Delete

A delete is a **tombstone**, authorized by the client (audit M2). Before this release `DeleteKey`
physically removed the key on every reachable node, best-effort: any driver-certificate holder (or
one cosigner, through `PurgeKey`) could purge every replica, and a node that was down during the
delete pushed the key back to everyone at its next anti-entropy sweep.

- **Who may delete:** only a client on the **delete role**, `hosted_keys.delete_allowlist` on every
  node — a role of its own. Being able to `Sign` or `Decrypt` does not make a client able to delete;
  the driver certificate cannot delete unless an operator lists its CN. Empty (the default): hosted
  keys cannot be deleted at all. `delete_acl` narrows a CN to key-id prefixes; a cosigner CN is
  refused by config validation.
- **How:** the client signs a delete intent (a `SignedIntent` with purpose `delete-key` and digest
  SHA-256(`"rutli-delete-key-v1\n"` ‖ key id)) with its mTLS key and sends it in `DeleteKey`. The leader
  checks it, fences the key, and forwards it in `PurgeKey`; **every node verifies it itself** — chain
  to the cluster CA, the delete role, pin, signature, cluster, key, digest, validity, ACL — and, with
  `delete_approval_threshold` > 0, counts approvals by its own `signing_policy.approvers` over the
  delete's request id — domain-separated from every signing approval (computed over `delete:<key
  id>`, audit F6; `docs/approval-quorum.md`), which `rutli-approve` shows as `DELETE hosted key <id>`. The delete succeeds once `write_quorum` nodes hold the
  tombstone; the rest get it from anti-entropy.
- **The operator command:** `rutli-cosigner --config <client config with a delete-role certificate>
  delete-hosted-key --key-id <id>`; with `--approvals-inbox <dir> --approvals <n>` it first writes a
  pending request into the same inbox `ApproveCli approve` serves and waits for `n` approvals. The
  driver signs a delete intent for Canton's `deleteKey` too (no approvals: if the cosigners require
  them, Canton's delete fails and the operator command is the way). Both paths are tested: the
  operator command with an approval inbox over mTLS (`frost/cosigner/tests/tombstones.rs`), and
  Canton 3.6.1's `keys.secret.delete` through the driver, with key-file v2 only, by
  `KEYFILE_V2_DELETES=1 scripts/e2e-ecies-hosted.sh` (phase E).
- **Default-deny does not break normal Canton operation** (audit F9). Canton 3.6 calls
  `KmsDriver.deleteKey` only from `KmsCryptoPrivateStore.removePrivateKey`, which only the operator
  console command `keys.secret.delete` reaches (`GrpcVaultService`); key rotation never deletes.
  Canton drops its own key metadata *before* calling the KMS, so with deletes disabled the operator
  gets an error and the hosted key stays on the cluster — unreferenced and harmless — until it is
  deleted with `delete-hosted-key`. FROST keys were never deletable through the driver.
- **What a tombstone is:** the key file replaced in place by a sealed tombstone record (key-file kind
  `tombstone`) holding the authorizing intent and, for `hosted_keys.delete_grace_secs` (default 7
  days), the key's material. Every read of the id answers NOT_FOUND; create, replicate and read-repair
  refuse it; it travels in `ListKeys` and **beats a live copy** in anti-entropy (the receiving node
  verifies the intent itself, as of the delete: the tombstone's deletion time must lie within the
  intent's validity window, and the intent must be issued no earlier than this node last saw the
  signer's delete capability change — granted, ACL, threshold or approvers, recorded in
  `data_dir/delete-policy.json` — so an intent refused when it was made cannot be replayed once the
  role is granted, audit F7; refusals count `rutli_delete_intent_refusals_total{reason="policy-changed"}`).
  The file is first written by the first start with hosted keys on (every CN on the role then
  counts as granted long ago): **start every node on this release once before granting a new delete
  role**, so the grant is recorded. A node restored from a backup taken before
  the delete is converted by its next sweep; a node holding the tombstone never pulls the key back.
  A tombstone never applies to a copy created or undeleted after its intent was issued.
- **Undelete** within the grace period: `rutli-cosigner hosted-undelete --key-id <id>` on every
  node, daemon stopped (`disaster-recovery.md` §3g). The break-glass "cleared intent" markers
  (`keys/.cleared/`) are in the backups (sidecar and `backup`), and `restore` merges them. **Reusing a deleted id** needs
  `hosted-clear-tombstone` on every node — a break-glass Canton never needs, since it mints fresh ids.
- The hosted delete path refuses FROST shares outright: the namespace key is non-rotatable, and
  deleting it destroys the node's identity.

Rollout: tombstones need every cosigner on this release before the first delete — an older node
ignores them (it reads a tombstone file as unreadable and lists a peer's tombstone as a key), so with
a mixed cluster a delete may not hold. Configure the same delete role on every node: a node with
deletes disabled refuses peers' tombstones too.

**Do not claim secure erasure.** The tombstone keeps the material for the grace period by design;
after it, on copy-on-write filesystems, wear-levelled SSDs and snapshotted volumes, the bytes may
survive, and any backup taken while the key existed still contains it. The honest statement is:
delete stops the key being served, cluster-wide and durably. Backups stop opening once the node's DEK
that sealed them is dropped (`seal rotate-dek`, then `seal drop-previous` — `disaster-recovery.md`
§3h).

## 4. Operations

### Anti-entropy

Every `anti_entropy_interval_secs` (default 300) each node lists its peers' inventories (at the
same time, 10 s each; a peer that does not answer is logged and the sweep goes on without it),
applies their tombstones, and **pulls** each key it lacks, once per sweep. It stores a key only
when **two peers return the same material and every other peer answers** with no other material,
no copy it cannot check, and no valid tombstone (a peer's tombstone is applied here instead).
**Only an answer counts**: a silent peer is unknown, never "does not hold it", so in five nodes a
pull waits for a node that is down (reads fail over meanwhile). One sweep pulls at most 256
missing ids, 64 per listing peer, ids more peers list first; the rest wait for the next sweep, and
the sweep logs `the pull bound of this sweep is reached`. A pull that fails is counted in
`rutli_anti_entropy_pull_failures_total`. The material is
unwrapped and checked on the pulling node, and the commitment computed there, never taken from the
peer. That heals a node that was down during a 2-of-3 write and a node rebuilt from a stale backup.
Pulls increment `rutli_anti_entropy_repairs_total` and are logged with the key id and the peers.

**The sweep never pushes** (since 0.5.0). Up to 0.4.0 a node also pushed every key a peer lacked,
and a node that pulled took the first peer whose copy opened; one compromised node could plant its
own material on a node that lacked a key, and the plant then spread. Now each node pulls for itself.

What the two-peer rule means in practice:

- One node down (2-of-3) is normal. A key the two live nodes hold is served by both; the third
  pulls it when it is back. A key only one *reachable* node holds is not pulled: the node that
  lacks it answers `UNAVAILABLE` for it (the driver fails over) and logs `a missing hosted key is
  not confirmed` each sweep, counted as
  `rutli_hosted_replication_refusals_total{reason="unconfirmed"}`, until a second holder is back.
  No node ever drops a key it holds.
- A key held by **one node only** (its other holders lost for good, or written with
  `write_quorum: 1`) is never copied automatically. `RutliHostedKeyCriticallyUnderReplicated` pages
  for it. Copy it by hand: `export-key` on the holder, `import-key` on a second node; the third then
  pulls it. Check with `verify-hosted`.
- Peers that hold **different** material: nothing is stored, the node answers `UNAVAILABLE` for the
  id, and the conflict is logged and counted (`reason="disagreement"`). Section 4, "When
  `rutli_anti_entropy_conflicts_total` increases".
- A deleted key is never pulled back: a node checks its own tombstone before it asks any peer.

**The sweep covers hosted keys only.** A FROST share is never listed, fetched or copied between
nodes — two cosigners holding the same share would silently break the threshold scheme. This is
enforced in code, not by convention; it is the single most important invariant on this path.

In steady state repairs sit at zero. A continuous trickle means writes are routinely failing to
reach a node: fix the mesh rather than relying on the sweep to cover for it.

One blind spot to know about: a key file the node cannot open (wrong seal secret after a rotation,
a partial restore, corruption) is logged, counted in `rutli_unreadable_key_files_total`, and
**skipped** from the inventory rather than failing the whole listing — failing it would stop the
sweep for every healthy key too. The cost is that the damaged key is invisible to replication in
both directions, so any non-zero value on that counter means some key is silently not being
replicated or repaired. Handling: [`observability.md`](observability.md).

### Read-repair

A hosted-key request that lands on a node missing that key pulls it *before* answering, rather than
returning `NOT_FOUND`. This is what lets the driver treat `NOT_FOUND` as authoritative and refuse to
fall back to a delegate. The same rule as the sweep applies, on every path that reads a key:
`PublicKey`, `KeyInfo`, `Decrypt`, `EcdhDerive`, `SymmetricEncrypt`, `SymmetricDecrypt`. A node
serves only material it holds or that its peers confirmed. Short of that it answers `UNAVAILABLE`
(`hosted-unconfirmed`). It answers `NOT_FOUND` only when `n - write_quorum + 1` nodes, itself
included, answered that they hold nothing under the id (with 2-of-3: itself and one peer), or a
node holds a tombstone for it.

Each node allows 20 read-repair fan-outs a second (burst 40); each asks every peer. Past that, a
request for a key the node lacks answers `UNAVAILABLE` without asking anyone (`reason="throttled"`)
— never `NOT_FOUND`, so the ceiling cannot hide a key: the driver fails over to a node that holds
it. Keys the node holds are served as always. There is no negative cache: one that answered
`NOT_FOUND` could hide a key created meanwhile on a node its generation could not reach.

`KeyInfo` with `local_only` (since 0.5.0) reports the node's own copy as it is — `commitment` and
the public key its private key derives, no read-repair, no replica count, `exists = false` when it
lacks the key — so a client can compare every node after a generation.

### Pushes a node refuses

A peer's `ReplicateKey` for an id the node lacks is accepted only from the caller that holds the
node's generation fence for that id under the ceremony id it names, and only if no other peer the
node can reach holds different material. Identical material over a held id is a no-op; different
material is refused (`ABORTED`, `hosted-conflict`). Every refusal is logged with the peer and the key
and counted in `rutli_hosted_replication_refusals_total{reason}`:

| reason | what was refused | what to do |
|---|---|---|
| `unfenced` | a push into an id this node lacks, from a caller without its generation fence | during a roll from 0.4.0: a 0.4.0 node's sweep push, stops once this node has pulled the key; otherwise suspect the peer in the log |
| `conflict` | a push of material that differs from this node's copy, or from another peer's | page (`RutliHostedKeyConflict`), section 4 |
| `disagreement` | a pull: peers hold different material | as `conflict` |
| `unconfirmed` | a pull: fewer than two peers hold the same copy | normal while a node is down; a single copy for good needs a hand copy (above) |
| `invalid` | material that does not open or validate (an RSA or EC key whose public half is not its own) | suspect the peer in the log |
| `timestamp` | a creation or undelete time in the future beyond `signing_policy.clock_skew_secs` | check that node's clock |
| `generate-conflict` | a generation this node led, aborted | as `conflict` |
| `unverifiable` | a push, while another peer answers with a copy this node cannot check | as `invalid` or `timestamp` for that peer |
| `throttled` | a read-repair, or a push's peer check, past this node's fan-out ceiling ("try again", never a conflict) | a client flooding lookups for keys this node lacks (check the driver certificate's use), or a peer fencing and pushing made-up ids (check the peer in the log) |
| `spec` | a push of another spec than the generation's fence declared on this node (0.5.0) | suspect the peer in the log |
| `intent` | a push under a fence taken without a generate intent, on a node that now requires one (0.5.0) | only after turning `require_ceremony_intent` back on mid-generation; otherwise suspect the peer |
| `mixed-version` | a generation this node led with a client intent, refused before fencing: a reachable cosigner is older than 0.5.0 (0.5.0) | finish the upgrade (below) |

A rollback that cannot reach a node it fenced is logged (`did not reach this cosigner`) and counted
in `rutli_hosted_rollback_incomplete_total` (`RutliHostedRollbackIncomplete`): that node may keep
a copy of a key nobody was given. Check with `verify-hosted` and quarantine the file by hand
(below).

A key **held here** with a time in the future (written before 0.5.0) is reported at startup and by
every sweep (`rutli_hosted_keys_future_timestamp`, `RutliHostedKeyFutureTimestamp`, log line `hosted
key with a time in the future`). It keeps serving, but every delete of it is refused as stale until
that time, and other nodes do not pull this copy. Check the clocks; if the copy is suspect, treat it
as a divergent replica (section 4).

### Upgrading from 0.4.0 (mixed versions)

Upgrade one cosigner at a time. **Do not create or delete hosted keys while the cluster is
mixed**; serving keys that exist keeps working. Upgraded nodes enforce the new rules on what *they*
accept and nothing more.

**Generate intents.** A 0.5.0 cosigner refuses a generation without a client generate intent, and
a 0.4.0 driver signs none. A 0.4.0 cosigner cannot verify one (it refuses a genkey fence that
carries an intent) and does not report its roster identifier. Two orders work:

*Driver first (recommended).*

1. Upgrade the driver (participant restart). Against 0.4.0 cosigners, signing, DKG, decryption and
   symmetric crypto are unchanged. Generating a hosted key is refused by the driver
   (`FAILED_PRECONDITION`, "does not report its roster identifier"): pause key creation (onboarding,
   rotation) from here.
2. Upgrade the cosigners one at a time, with the default `require_ceremony_intent`. While mixed,
   the driver refuses to generate through a 0.4.0 cosigner (above), and does not fail over on that.
   A 0.5.0 leader refuses while any cosigner it **can reach** is older (`FAILED_PRECONDITION`,
   message `ceremony refused: cosigner N speaks hosted-key protocol 0; a hosted-key generation with
   a client intent needs protocol 2 on every reachable cosigner …`, counted as
   `reason="mixed-version"`). A cosigner it cannot reach is skipped, as by the fence: with the 0.4.0
   node down (for example while it is being upgraded), a generation through a 0.5.0 leader
   completes on the upgraded nodes at the write quorum. That key was authorized by the client's
   intent; the old node pulls it later. So "do not create keys while mixed" is an operating rule,
   not something the cluster enforces. A 0.4.0 leader would send no intent; its 0.5.0 peers refuse
   that fence (`PERMISSION_DENIED`) and it aborts before writing anything.
3. Every cosigner on 0.5.0: generation works, with the intent.

*Cosigners first (the 0.4.0 driver stays for a while).*

1. Add `signing_policy.require_ceremony_intent: false` to each cosigner's config as you upgrade it
   (leave the 0.4.0 nodes' configs alone: on them the switch only governs DKG and refresh). The cost:
   that node accepts a DKG, refresh or hosted-key generation without a client intent, counted in
   `rutli_ceremony_intent_absent_total` (`RutliCeremonyIntentAbsent`), and a compromised cosigner
   can again create a hosted key nobody asked for (`docs/security/threat-model.md`). This is a
   cluster-wide matter, not a per-node one: one node with the opt-out and one compromised holder
   make two copies, which is the write quorum with `write_quorum: 2`, and the enforcing nodes then
   pull that key by the normal agreement rule. Treat the opt-out as a temporary state of the whole
   rollout, on every node or none, and end it (step 4) as soon as the driver is upgraded.
2. Upgrade the cosigners. Generations from the 0.4.0 driver work through either release of leader,
   as in 0.4.0.
3. Upgrade the driver. It signs generate intents from now on; a 0.5.0 leader refuses one while a
   reachable cosigner is 0.4.0, so finish step 2 first.
4. Remove the opt-out on every node (rolling restart). Check first that
   `rutli_ceremony_intent_absent_total` no longer grows after a key creation.

Without the opt-out in this order, the 0.4.0 driver's `GenerateKey` is refused (`PERMISSION_DENIED`)
by a 0.5.0 leader, and by a 0.5.0 peer at a 0.4.0 leader's fence. To roll the driver back below
0.5.0, set `require_ceremony_intent: false` on every cosigner first.

The other replication rules:

- **A 0.4.0 node** still accepts a push into an id it lacks from any peer, pulls the first copy
  that opens, accepts future timestamps and an RSA key whose public half is not its own, and, as a
  leader, writes its own copy first and treats a conflict as a failed replica. A 0.4.0 leader that
  dies after its own write can still fork the id with a retry.
- **Deletes:** a 0.4.0 node ignores `include_tombstone` and answers NOT_FOUND for a deleted key. So
  until every node is upgraded, a node that lacks a deleted key can pull it back from two old
  replicas that still hold it, and serves it until its next sweep applies the tombstone from the
  inventory.
- **A 0.5.0 leader with 0.4.0 peers**, for a generation without an intent (the opt-out above),
  fences and pushes as before (`ReplicateKey` and `FetchKey` are unchanged); a 0.4.0 peer's
  create-once refusal ("different material") aborts the generation. With an intent it refuses
  before fencing.
- **A 0.4.0 leader with a 0.5.0 peer:** only with the opt-out on that peer, which then accepts its
  fenced push after its own peer check; a 0.5.0 refusal is a failed replica to the 0.4.0 leader.
- **A 0.4.0 node's sweep** still pushes keys a peer lacks. A 0.5.0 node refuses the push
  (`unfenced`, `RutliHostedReplicationRefused`, and an `anti-entropy push failed` warning on the
  0.4.0 node) and pulls the key itself once its peers confirm it. Expect a few during the roll.

Before you start, check `rutli_anti_entropy_conflicts_total` and run `verify-hosted` for every
hosted key; a divergence from before the upgrade is handled below.

### Replica count

Expect every hosted key on every cosigner. `KeyInfo` and `GenerateKey` both report the live replica
count for one key. For monitoring, `rutli_key_replicas` is the direct signal: the **fewest**
cosigners holding any one hosted key, recounted after each sweep repairs what it can. The shipped
rules alert below the cluster size (`RutliHostedKeyUnderReplicated`, warning, 30 min) and below the
write quorum (`RutliHostedKeyCriticallyUnderReplicated`, critical, 10 min — one node holds the only
copy). There is no *per-key* gauge; take the key id from the sweep logs. `rutli_hosted_keys` is a
per-node count, refreshed at the end of that node's own sweep and whenever a peer lists its
inventory, so it lags by up to one interval; `RutliHostedKeyReplicaShortfall` watches those counts
diverging across the job for 20 minutes. Metrics and dashboards:
[`observability.md`](observability.md).

Two replicas survive one node loss. One survives none.

### Backup and restore

Hosted keys live in `data_dir/keys/` alongside the FROST shares, in the same sealed envelope format,
so the existing commands already cover them:

```sh
rutli-cosigner --config /etc/rutli/cosigner-2.json backup  --out /secure/backups/cosigner-2/$(date +%F)
rutli-cosigner --config /etc/rutli/cosigner-2.json restore --from /secure/backups/cosigner-2/2026-08-17
```

That shared directory is intentional — a sibling directory would be silently skipped by every
backup, which is the exact failure class hosted keys exist to prevent. The usual discipline from
[`disaster-recovery.md`](disaster-recovery.md) applies unchanged: backups are sealed, so the seal
secret is a separate recovery input and belongs in a different trust domain.

Two node-specific rules:

- **Back up and restore per node.** Never restore cosigner 1's backup onto cosigner 2 — it contains
  cosigner 1's FROST share, and two nodes holding the same share breaks the threshold silently.
- **A rebuilt node still needs its own FROST share** from backup (`disaster-recovery.md` §1/§2). Its
  hosted keys come back on their own: the next sweep pulls every key two peers hold, or the first
  request read-repairs it. A key only one other node holds does not come back on its own (section 4,
  "Anti-entropy").

### Export and import (portable copies)

`backup` and `export` are different tools for different failures, and the distinction matters:

| | `backup` | `export` |
|---|---|---|
| Artifact | sealed ciphertext, as stored on disk | the private key, passphrase-encrypted (or plaintext) |
| Opens with | the cluster seal secret + the *same node id* | the export passphrase alone |
| Restores into | that node, in that cluster | any node, **any cluster**, or another KMS |
| Covers | routine node/cluster loss | loss of the seal secret; migration off this cluster |
| If the artifact leaks | nothing — it is ciphertext keyed elsewhere | total: the file *is* the key |

Use `backup` for everything routine. Reach for `export` only for the two cases `backup` genuinely
cannot cover: **recovering after the seal master secret is lost**, and **moving a key to a different
cluster or KMS**. `import-key` has a third use, below: bringing an existing Canton node's ECIES
encryption key into the cluster.

```sh
# Export (node stopped). The passphrase comes from the environment, never the command line.
read -rs EXPORT_PASS && export EXPORT_PASS
rutli-cosigner --config /etc/rutli/cosigner-1.json export-key \
  --key-id rutli-enc-participant1-encryption-… \
  --out /media/offline/rutli-enc.export --passphrase-env EXPORT_PASS

# Import into a different cluster (daemon running or stopped, see "Why importing next to a running
# daemon is safe" below). Run it on every cosigner of that cluster: a node pulls a key only from two
# peers that hold the same copy, so a key imported on one node stays there.
rutli-cosigner --config /etc/rutli/cosigner-1.json import-key \
  --in /media/offline/rutli-enc.export --passphrase-env EXPORT_PASS
```

Properties worth knowing before you rely on them:

- **Offline only, by design.** There is no export or import RPC and there must never be one. An
  export RPC would turn a stolen driver certificate from an online, rate-limited, journalled decrypt
  *oracle* into permanent silent possession of the key. As a CLI command it needs host access **and**
  the seal secret — two inputs you already keep in separate trust domains.
- **Encrypted by default.** Argon2id (64 MiB, t=3) → AES-256-GCM, with the header bound in as AAD so
  an artifact cannot be relabelled to another key id or spec. Passphrases under 12 characters are
  refused: this is the *only* protection on a portable private key. `--unsafe-plaintext` exists for
  piping into another KMS's import tool on a trusted host, and logs a warning saying the file is the
  key.
- **Hosted keys only.** A FROST share is not a whole key — `export-key` refuses one, and there is
  still no way for a share to leave a node. The namespace key cannot leave the cluster, which is
  the entire point of it. The one way a FROST share *enters* a node from outside is the split
  ceremony's offline `import-share` ([split-ceremony.md](split-ceremony.md)), which installs a
  dealer share for a key migrated from an existing Canton node — also CLI-only, never an RPC.
- **Import never overwrites.** Hosted keys are create-once-immutable, so importing over an existing
  id with *different* material is refused; an identical re-import is a no-op. Rotate to a new key id
  instead.
- **The export file is written `0600` before any bytes land**, so it is never briefly world-readable.
  After the ceremony, treat it like key material: offline media, an HSM, or Shamir-split the
  passphrase — an export sitting on a laptop is a private key sitting on a laptop.
- **Both operations log at WARN** with the key id. That log line is often the only record that a
  portable copy exists; ship it somewhere you will notice.

#### Importing a Canton node's ECIES key (migration)

A node moving into the cluster ([roadmap-migration.md](roadmap-migration.md)) can keep its
encryption key instead of rotating it — discouraged, see [migration.md](migration.md), "Carrying
the signing and encryption keys". Export it on the old node (`keys.secret.download`, preview
commands enabled, and on Canton 3.7 `canton.parameters.enable-key-download = yes`; preferably with a password), then on every cosigner (on two, the third pulls it). A daemon may be running
(`kubectl exec` into the pod, the export copied onto a tmpfs and deleted afterwards) or stopped:

```sh
read -rs CANTON_EXPORT_PASSWORD && export CANTON_EXPORT_PASSWORD
rutli-cosigner --config /etc/rutli/cosigner-1.json import-key \
  --in /media/offline/participant-encryption.export --passphrase-env CANTON_EXPORT_PASSWORD \
  --key-id <frost.key-prefix>rutli-enc-imported-1 --expect-fingerprint 1220…
```

`--expect-fingerprint` is the key's fingerprint as the old node lists it (`keys.secret.list`), not
read from the file. The import refuses anything but an EC P-256 key whose Canton purpose is
encryption (a P-256 *signing* key is never made an ECDH key; Ed25519 keys go through the
[split ceremony](split-ceremony.md); RSA import is not supported, roadmap B3 was dropped), and refuses
unless the public key the
cluster will serve is byte-identical to Canton's encoding — that is what lets the new participant
register it by id and get the **same fingerprint** back:

```scala
val key = participant.keys.secret.register_kms_encryption_key("<prefix>rutli-enc-imported-1")
// key.fingerprint is the old node's encryption key fingerprint
```

The key id must be one the driver routes to hosted keys: `<frost.key-prefix>rutli-<name>` in
`[A-Za-z0-9_-]`, never containing `frost-`. Pass the participant's prefix as `--key-prefix` to have
it enforced (otherwise the inferred prefix is printed for you to check). Import into a cluster whose
cosigners are all upgraded (rollout order above): an older node cannot serve an EC key, and the
driver will not advertise ECIES while one remains. Import on every cosigner, or on two and let the
third pull it (within one `hosted_keys.anti_entropy_interval_secs` of a running daemon, or once a
stopped one starts; a node pulls only what two peers hold). Then, before registering it, check that
every node holds it and serves Canton's key — operator certificate, public values only:

```sh
rutli-cosigner --config <operator config> verify-hosted \
  --key-id <frost.key-prefix>rutli-enc-imported-1 --expect-fingerprint 1220…
```

It asks each node for its **own** copy (`HostedKeyStatus`, no read-repair; each node reports the
public key its private key derives, and refuses to answer for an inconsistent key file), and fails
unless all `n` hold it, the SPKI is byte-identical everywhere and its Canton fingerprint is the
expected one. These are the nodes' own reports: they catch replication gaps and divergent copies on
honest nodes, not a compromised node that lies about what it holds.

**Why importing next to a running daemon is safe.** The import is the key store's create-once
write, the same one `import-share` uses inside a live pod: a sealed temp file, fsynced, moved into
place with a no-replace rename (or link), then a directory fsync. The daemon sees either no file or
the whole sealed file, never a partial one, and nothing is ever replaced. The daemon keeps no
in-memory copy of hosted keys — every serve, listing and repair reads the file — so the key is
served from the next request on. The one concurrent writer is the daemon itself, pulling the same
id from two peers where it was imported first: exactly one create wins and the other compares,
identical material being a no-op on either side and different material a conflict on either side,
never an overwrite (`export::install_imported`; pinned by the test
`import_key_into_a_running_node_races_safely_with_anti_entropy`, both interleavings).

The exposure caveat of every migrated key applies: the old node's database and its backups hold
this key in the clear — purge them (`b0-cutover-spike.md`, `roadmap-migration.md`).

### When `rutli_anti_entropy_conflicts_total` increases

**This is a page, not a warning** (`RutliHostedKeyConflict`, severity critical). It means a node
saw *different material* under one key id: a peer holds other material than this node (the sweep,
log `hosted key CONFLICT`), peers it would pull from disagree (`reason="disagreement"`), it refused
a push over another copy (`reason="conflict"`), or a generation it led was aborted (`hosted key
generation ABORTED`). Hosted keys are create-once-immutable, so this cannot happen in normal
operation — it is an invariant violation, not replication lag. It is counted each time it is seen,
so an unresolved conflict adds to the counter at every sweep and the page stays on until about an
hour after it is resolved. Nothing reconciles it automatically:
picking a side could destroy the only copy that can decrypt already-recorded traffic. Each holder
keeps serving its own copy; a node that lacks the key answers `UNAVAILABLE` for it while the copies
disagree.

1. Find the key id and the peer — both are in the cosigner's error log.
2. Change nothing. Do not delete either copy, do not restore "a good backup" over one, do not rotate
   that key yet. Both copies are evidence, and one of them may be the only thing that can read
   traffic already on the wire.
3. Establish which copy is live: `verify-hosted --key-id <id> --expect-fingerprint <fp>`, with the
   fingerprint the participant actually publishes in its Canton topology, lists what each node
   reports for its copy (the public key its private key derives) and names the nodes that disagree.
   It is each node's self-report: a node that is itself compromised can report anything, so treat
   its answer as a claim to check, not as evidence.
4. Work backwards to the cause before repairing. In rough order of likelihood: a restore of a stale
   or foreign backup onto one node; nodes brought up with different seal master secrets; a key id
   reused after a delete that did not reach every node; or genuine tampering. Treat the last
   possibility as live until you have ruled it out.
5. Only once the live copy is identified: stop the divergent node, move that key's file out of its
   `data_dir/keys/` (one file per key id) into a quarantine directory, and restart it — the next
   sweep re-pulls the live material once two other nodes hold it. If only one other node holds the
   live copy, import it there by hand (`export-key` on the holder, `import-key` on the restarted
   node). For an AES key, a known Canton blob that decrypts on a node tells you that node holds the
   live copy. **Do not use `DeleteKey` for this.** It tombstones the key cluster-wide, including
   the copy you just decided was the good one.
6. Rotate the key through Canton topology afterwards if there is any chance the divergent material
   was ever used, and treat the interval since divergence as a confidentiality incident (section 5).

**A replica that diverged before 0.5.0** is handled the same way. 0.5.0 does nothing new to it at
startup: each holder keeps serving its own copy, every sweep logs the conflict and counts it, so the
page keeps firing until it is resolved. A node that lacks the key refuses to pull it while the
copies disagree. If you suspect a node may be compromised, rebuild it rather than only quarantining
the file.

## 5. Security model and limits

What hosted keys are, stated without varnish:

- **The security tier matches the recoverability tier.** The one key Canton *cannot* rotate — the
  namespace key, whose loss or compromise is terminal for the node's identity — stays in real 2-of-3
  threshold MPC. The keys that get only replication are exactly the ones Canton *can* rotate under
  that namespace key. A hosted-key compromise costs a topology transaction; a namespace-key
  compromise costs the node.
- **The win is relocation, not a threshold property.** Key material moves off an internet-adjacent
  Canton participant host onto three hardened, single-purpose, allowlisted, sealed nodes. That is a
  real reduction in exposure. It is not "MPC for all key types", and Rütli should never claim it is.
- **A single compromised cosigner yields the hosted keys.** All n nodes hold the same material; the
  attacker needs one, plus the seal secret that node's process has. The same attacker does **not**
  get the namespace key: that still requires breaching `t` cosigners within one refresh epoch.
- **The cost that must not be buried: retrospective decryption.** Canton's encryption keys protect
  per-view session keys. An attacker who extracts one gains *retrospective* read access to any
  recorded traffic encrypted to it. Rotation fixes the future, not the past — there is no forward
  secrecy here. Plan on the assumption that a hosted encryption key compromise is a confidentiality
  incident covering the whole lifetime of that key, and keep key lifetimes short enough that this
  bound means something.
- **Threshold RSA is permanently out of scope.** No Rust implementation of threshold RSA decryption
  exists, and the pure-Rust `rsa` crate still carries the unpatched
  [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) Marvin timing
  side-channel — private-key recovery by a *network* attacker, which is precisely this deployment.
  RSA decryption therefore runs on `aws-lc-rs` (FIPS-validated, constant-time), never that crate.
  Full reasoning: [`hosted-keys-design.md`](hosted-keys-design.md).

### Limits worth knowing

Properties to understand before you rely on hosted keys in production.

- **`Decrypt` and `EcdhDerive` are rate-limited per key, on each cosigner**, from one shared budget
  (`hosted_keys.decrypt_rate_limit_per_min`,
  default 6000 — 100/s sustained on a single key). The budget is **per node**: an attacker who
  calls every cosigner gets n × it (section 2 says how to size it). This is the bound on a stolen driver
  certificate: that certificate authorizes `Decrypt`, and retrospective decryption means whoever
  holds it can read everything ever encrypted to that key, so without a ceiling the only limit is
  how fast the cluster answers. The limiter has to live here rather than in the driver's signing
  journal, which runs on the Canton host and can simply be bypassed by not using the driver.
  It is not a load shaper: the default sits far above real traffic, the cosigner warns
  ("approaching its rate limit", with the key id) well before it starts refusing, and a refusal is
  `RESOURCE_EXHAUSTED` — which the driver deliberately does **not** fail over on, since every node
  enforces the same ceiling and retrying elsewhere would just spread an attacker's load. Alert on
  `rutli_decrypt_rate_limited_total` (`RutliDecryptRateLimited`); in normal operation it never
  moves. Set `0` to disable, and the daemon says so loudly at startup.
- **No approval gating on decrypt, deliberately.** M-of-N approval covers `sign`, not `Decrypt`:
  decryption is on Canton's per-transaction hot path, so a human gate there would stall the node.
  That is a design choice, not an oversight — but it does mean the audit trail, not an approval
  quorum, is what stands behind a decrypt.
- **`EcdhDerive` is a static Diffie-Hellman oracle** for whoever holds the driver certificate: it
  answers `x(d·V)` for any valid point. With points restricted to uncompressed encodings on P-256
  (prime order, cofactor 1) it leaks nothing about `d` beyond what the answers are, and the known
  static-DH speed-ups need far more queries than the rate limit allows. It is the same capability
  `Decrypt` gives for RSA, bounded the same way.
- **The shared secret `Z` is wiped where Rust controls it, not everywhere.** The cosigner keeps `Z`
  (and every decoded private key) in zeroizing buffers until the gRPC reply is built; the reply's
  own buffer and the driver's copy on the JVM (a protobuf `ByteString`, moved by the GC) cannot be
  wiped. Same as the plaintext `Decrypt` returns.
- **Canton's ECIES does not authenticate its IV.** The HMAC covers the CBC ciphertext, not the IV
  Canton prepends, so a changed IV changes the first plaintext block without failing the MAC.
  Canton's own decryptor behaves the same way and the driver matches it exactly; in practice the
  plaintext is a session key whose use fails authenticated decryption if it was altered. An upstream
  property, recorded so nobody rediscovers it as a Rütli bug.

- **Replication integrity rests on agreement between nodes and a client intent** (since 0.5.0,
  section 4): a node stores a key it lacks only when two peers agree, or from the generation leader
  that fenced it under a client generate intent naming that leader, and no other reachable peer
  contradicts. A compromised node can no longer create a key under an id nobody asked for. The
  leader the client asked still chooses the material and can refuse to finish; and a fenced push
  is not caught when every other holder is unreachable from the receiving node
  (`docs/security/threat-model.md`). With `require_ceremony_intent: false` the first point is open
  again. A replica written by a generation whose leader died is still served (section 3, "A leader
  that dies mid-generation").

Operational consequences worth writing into your runbook:

- Treat the cosigners as key-custody hosts, not as a service tier. Anyone with shell on one has the
  hosted keys.
- Guard the driver's client certificate like a key: it is what authorizes `Decrypt` on the Signer
  API. `signer_allowlist` restricts that API to the driver CN — set it.
- A hosted-key compromise is a rotation *and* a disclosure assessment. Rotating alone addresses only
  the traffic that has not happened yet.

## 6. What is not hosted yet, and the roadmap

Today the cluster serves `rsa-2048-oaep-sha256`, `ec-p256-ecies` and `aes-256-gcm`. Anything else —
EC signing keys for a synchronizer that requires ECDSA — still needs an `hsm` or `software`
delegate.

| Phase | Adds | Threshold? |
|---|---|---|
| **v1** (shipped) | hosted RSA-2048 + AES-256-GCM; `delegate = "none"` becomes possible | no — replicated |
| **v1.5** (shipped) | `EcdhDerive` + hosted EC-P256 keys; the driver completes ECIES with BouncyCastle | no — replicated |
| **v2** (planned for release 1.0, [roadmap.md](roadmap.md)) | threshold ECIES via `frost-p256` — one stateless round, no nonce hazard | **yes** |
| **never** | threshold RSA | — |

The load-bearing property of that table is that **v1.5 and v2 share a wire contract**: the cluster
performs only the ECDH and the driver completes the framing, so promoting ECIES from a replicated
whole key to a genuine threshold operation is a server-side change plus a config flag, not an API
migration. It also inverts the usual expectation — the scheme Canton's KMS mode defaults to (RSA) is
the one that cannot be thresholded, and the scheme that thresholds cleanly (ECIES over P-256) is one
a self-hosted KMS can advertise where a cloud KMS cannot.

The two questions the design record left open before ECIES could be relied on are answered: the
Global Synchronizer admits `EcP256`/ECIES (SV static parameters are Canton's JCE defaults on every
network), and Canton's ECIES framing interoperates byte for byte — Canton's `JcePureCrypto` encrypts
and the driver decrypts in the upstream conformance suite (`CONFORMANCE=1`) and on a live 3.6.1
participant (`scripts/e2e-ecies-hosted.sh`), with a generated key and with a key imported from a
Canton node.

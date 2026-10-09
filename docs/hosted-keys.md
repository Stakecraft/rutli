# Cluster-hosted keys — operator guide

The cosigner cluster can hold Canton's **non-FROST** key material as well as the namespace key:
RSA-2048-OAEP-SHA256 and EC P-256 (ECIES) encryption keypairs, and AES-256-GCM symmetric keys. A
participant configured this way needs **no HSM and no local key state**.

This page is the operational half — when to use it, how to turn it on, how the keys behave, and what
to do when the alerts fire. The rationale (why threshold RSA is permanently out of scope, why the
quorum and the replication wrapping look the way they do) is the design record in
[`hosted-keys-design.md`](hosted-keys-design.md); this page links to it rather than repeating it.

**State this plainly wherever it comes up:** hosted keys are **replicated whole keys, not threshold
shares**. They are generated on one cosigner, sealed at rest on every node, and any node can serve a
decrypt on its own. The FROST Ed25519 namespace key is unchanged and remains genuine 2-of-3
threshold MPC — no machine ever holds it whole. Section 5 states the cost of that difference.

## 1. What it is, and when to use it

Rütli's cluster serves the Ed25519 namespace/identity key. Everything else Canton needs — the
asymmetric encryption keypair for confidential views, the symmetric key that wraps its private key
store — comes from one of three places:

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
- **The sealed software delegate stays supported** and is still the right answer for a delegate that
  must serve key types the cluster does not (see section 6). It is not a downgrade — it is what
  closed the 2026-08-12 DevNet incident, in which a heap-only software delegate lost an RSA
  encryption key across a Splice upgrade restart and the participant took a fatal
  `KmsDecryptError` → synchronizer disconnect. That incident and its recovery are
  [`disaster-recovery.md` §3b](disaster-recovery.md); cluster hosting removes the key from that host
  altogether.

## 2. Enabling it

### Cosigner

Add a `hosted_keys` block to each cosigner's JSON config (the shipped TLS examples and the k8s
ConfigMap already carry it):

```json
{
  "share_seal": { "secret_env": "RUTLI_SEAL_SECRET" },
  "hosted_keys": {
    "enabled": true,
    "write_quorum": 2,
    "anti_entropy_interval_secs": 300
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Off unless set. Absent block = no hosted keys, no replication, no sweep. |
| `write_quorum` | `2` | How many cosigners must hold a new key before it is reported created. |
| `anti_entropy_interval_secs` | `300` | Reconciliation cadence (floor 10s). |

**`share_seal` is mandatory.** Config validation refuses to start a node with
`hosted_keys.enabled` and no `share_seal`: a hosted key is a *whole private key*, and one sitting
unsealed on disk would be strictly worse than the HSM delegate it replaces. The same operator master
secret does double duty — it seals the file at rest *and* derives the per-node X25519 distribution
key used to wrap material for replication — so the daemon also refuses to start if the referenced
environment variable is unset. A *wrong* secret is not silently tolerated either: sealed files fail
to open and the affected operation fails closed rather than the node serving a wrong or empty key.

**Write quorum is 2-of-3 by default, deliberately.** Requiring all three would mean you cannot mint
or rotate an encryption key while any cosigner is down — worse availability than the single copy an
HSM gives you, and a contradiction of the cluster's own 2-of-3 fault model. 2-of-3 is only safe
because anti-entropy and read-repair ship with it (section 4); do not disable the sweep. Below
quorum a write **rolls back** rather than leaving one lonely copy (section 3). A configured
`write_quorum` is honoured on the `GenerateKey` path — set it to `3` if you would rather a write
fail than commit while a cosigner is down.

**Run hosted keys only on a TLS cluster.** Replication rides the mesh Peer API, which is gated by
`peer_allowlist` (see [`phase-2-frost.md`](phase-2-frost.md) — the driver must never be on that
list). `FetchKey` wraps material to the *authenticated* caller, identified by its client-certificate
CN rather than by anything in the request body, so a plaintext cluster cannot pull a key at all. The
plaintext dev compose is not a supported configuration for hosted keys.

Key material never crosses the mesh in the clear, even inside mTLS — a service-mesh sidecar
terminating TLS would otherwise see plaintext private keys. Each replica is sealed to one recipient
with ephemeral X25519 → HKDF-SHA256 → AES-256-GCM, with the AAD binding cluster id, key id, spec and
recipient so an envelope cannot be replayed to another node, another key, or another deployment (the
cluster id is derived from the CA certificate). Note what this does *not* do: under today's shared
master secret every cosigner can derive every peer's distribution key, so this protects against a
TLS-terminating middlebox and against replay, not against another cosigner.

### Driver

```hocon
config {
  backend = "frost"
  frost = {
    endpoints    = ["cosigner1:9101", "cosigner2:9102", "cosigner3:9103"]
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
instead of silently doing local crypto.

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
  Read-repair (section 4) is what makes `NOT_FOUND` authoritative. Endpoint failover stays restricted
  to `UNAVAILABLE` / `DEADLINE_EXCEEDED`, as for signing.
- **No hardcoded spec list.** The driver asks the cluster via `Capabilities` at startup, so adding a
  key type later (section 6) needs no driver release.

Keep `delegate = "hsm"` (or `"software"`) if you still need key types the cluster does not serve.

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
   cosigner for `Capabilities` at startup (retrying for up to 30 s) and advertises `EcP256` /
   `EciesHkdfHmacSha256Aes128Cbc` only if **every one** reports `ec-p256-ecies`. If one is still old,
   or does not answer within 30 s, ECIES is not advertised and a participant configured for it
   fails to start, loudly — rather than starting against a cluster where one node would drop its
   decryptions. The trade-off to know: a participant configured for ECIES cannot (re)start while a
   cosigner is unreachable. Decryption itself is unaffected by a node being down; only the startup
   check is.

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

`GenerateKey(key_id, spec)` on any cosigner. That node leads:

1. Fences the key id on every peer, so two concurrent generates for the same id serialize.
2. Generates locally, then wraps and pushes a replica to each peer.
3. Verifies each peer's commitment to the stored material matches its own — a peer that stored
   something else does not count toward the quorum.
4. Reports `created` and `replicas`.

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
error, leaving the id free for a clean retry — a single node holding the only copy is precisely the
failure this feature exists to prevent. Above quorum but below n, the key is created, a warning is
logged, and anti-entropy repairs the missing replica.

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

`DeleteKey` purges the key on every reachable node, best-effort, and reports whether any node
deleted it. The hosted delete path refuses FROST shares outright: the namespace key is
non-rotatable, and deleting it destroys the node's identity.

**Do not claim secure erasure.** On copy-on-write filesystems, wear-levelled SSDs and snapshotted
volumes, removing a file does not destroy the bytes, and any backup taken while the key existed
still contains it. The honest statement is: delete removes the referenced copies. True destruction
requires rotating the cluster master secret so that every old sealed blob — including the ones in
your backups — becomes undecryptable.

## 4. Operations

### Anti-entropy

Every `anti_entropy_interval_secs` (default 300) each node compares inventories with its peers,
**pulls** keys it lacks and **pushes** keys a peer lacks. Pushing heals an under-quorum write;
pulling heals a node rebuilt from a stale backup. Repairs increment
`rutli_anti_entropy_repairs_total` and are logged with the key id and the peer.

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

A hosted-key request that lands on a node missing that key pulls it from a peer *before* answering,
rather than returning `NOT_FOUND`. This is what lets the driver treat `NOT_FOUND` as authoritative
and refuse to fall back to a delegate.

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
rutli-cosigner --config /etc/rutli/cosigner-2.json restore --from /secure/backups/cosigner-2/2026-08-17 --force
```

That shared directory is intentional — a sibling directory would be silently skipped by every
backup, which is the exact failure class hosted keys exist to prevent. The usual discipline from
[`disaster-recovery.md`](disaster-recovery.md) applies unchanged: backups are sealed, so the seal
secret is a separate recovery input and belongs in a different trust domain.

Two node-specific rules:

- **Back up and restore per node.** Never restore cosigner 1's backup onto cosigner 2 — it contains
  cosigner 1's FROST share, and two nodes holding the same share breaks the threshold silently.
- **A rebuilt node still needs its own FROST share** from backup (`disaster-recovery.md` §1/§2). Its
  hosted keys come back on their own: the next sweep pulls them, or the first request read-repairs
  them.

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

# Import into a different cluster (node stopped). Start the daemon afterwards; anti-entropy
# replicates the key to the rest of that cluster on its own.
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
encryption key instead of rotating it. Export it on the old node (`keys.secret.download`, preview
commands enabled, preferably with a password), then on one cosigner, stopped:

```sh
read -rs CANTON_EXPORT_PASSWORD && export CANTON_EXPORT_PASSWORD
rutli-cosigner --config /etc/rutli/cosigner-1.json import-key \
  --in /media/offline/participant-encryption.export --passphrase-env CANTON_EXPORT_PASSWORD \
  --key-id <frost.key-prefix>rutli-enc-imported-1 --expect-fingerprint 1220…
```

`--expect-fingerprint` is the key's fingerprint as the old node lists it (`keys.secret.list`), not
read from the file. The import refuses anything but an EC P-256 key whose Canton purpose is
encryption (a P-256 *signing* key is never made an ECDH key; Ed25519 keys go through the
[split ceremony](split-ceremony.md); RSA import is roadmap B3), and refuses unless the public key the
cluster will serve is byte-identical to Canton's encoding — that is what lets the new participant
register it by id and get the **same fingerprint** back:

```scala
val key = participant.keys.secret.register_kms_encryption_key("<prefix>rutli-enc-imported-1")
// key.fingerprint is the old node's encryption key fingerprint
```

The key id must be one the driver routes to hosted keys: `<frost.key-prefix>rutli-<name>` in
`[A-Za-z0-9_-]`, never containing `frost-`. Pass the participant's prefix as `--key-prefix` to have
it enforced (otherwise the inferred prefix is printed for you to check). Import into a cluster whose
cosigners are all upgraded (rollout order above): anti-entropy cannot push an EC key to an older
node, and the driver will not advertise ECIES while one remains. Start the cosigner afterwards; anti-entropy and read-repair spread the key. The exposure caveat of every
migrated key applies: the old node's database and its backups hold this key in the clear — purge
them (`b0-cutover-spike.md`, `roadmap-migration.md`).

### When `rutli_anti_entropy_conflicts_total` increases

**This is a page, not a warning** (`RutliHostedKeyConflict`, severity critical). It means two nodes
hold *different material* under the same key id. Hosted keys are create-once-immutable, so this
cannot happen in normal operation — it is an invariant violation, not replication lag. The sweep
deliberately refuses to reconcile: picking a side automatically could destroy the only copy that can
decrypt already-recorded traffic.

1. Find the key id and the peer — both are in the cosigner's error log.
2. Change nothing. Do not delete either copy, do not restore "a good backup" over one, do not rotate
   that key yet. Both copies are evidence, and one of them may be the only thing that can read
   traffic already on the wire.
3. Establish which copy is live: compare each node's `PublicKey` for that id against the public key
   the participant actually publishes in its Canton topology.
4. Work backwards to the cause before repairing. In rough order of likelihood: a restore of a stale
   or foreign backup onto one node; nodes brought up with different seal master secrets; a key id
   reused after a delete that did not reach every node; or genuine tampering. Treat the last
   possibility as live until you have ruled it out.
5. Only once the live copy is identified: stop the divergent node, move that key's file out of its
   `data_dir/keys/` (one file per key id) into a quarantine directory, and restart it — the next
   sweep re-pulls the live material. **Do not use `DeleteKey` for this.** It purges cluster-wide,
   including the copy you just decided was the good one.
6. Rotate the key through Canton topology afterwards if there is any chance the divergent material
   was ever used, and treat the interval since divergence as a confidentiality incident (section 5).

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

- **`Decrypt` and `EcdhDerive` are rate-limited per key, on the cosigner**, from one shared budget
  (`hosted_keys.decrypt_rate_limit_per_min`,
  default 6000 — 100/s sustained on a single key). This is the bound on a stolen driver
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
| **v2** | threshold ECIES via `frost-p256` — one stateless round, no nonce hazard | **yes** |
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

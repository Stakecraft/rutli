# Cluster-hosted keys — operator guide

The cosigner cluster can hold Canton's **non-FROST** key material as well as the namespace key:
RSA-2048-OAEP-SHA256 encryption keypairs and AES-256-GCM symmetric keys. A participant configured
this way needs **no HSM and no local key state**.

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
quorum a write **rolls back** rather than leaving one lonely copy (section 3).

> v1 applies the default quorum of 2 on the `GenerateKey` path. The field is parsed and validated
> against the roster size, but a non-default value is not yet plumbed through to the Signer service.

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
    tls = { ca-cert = "/certs/ca.crt", cert = "/certs/driver.crt", key = "/certs/driver.key" }
  }
}
```

Routing is by key-id prefix: `frost-` → threshold Ed25519 in the cluster, `rutli-` → cluster-hosted,
anything else → the delegate. With `delegate = "none"` there is no third path — the participant
holds no key material at all, and any key id matching neither prefix fails loudly and names the key
instead of silently doing local crypto.

Two deliberate absences:

- **No automatic fallback to the delegate on `NOT_FOUND`.** A fallback would silently re-create split
  custody — some keys in the cluster, some on the host — which is the shape of the August incident.
  Read-repair (section 4) is what makes `NOT_FOUND` authoritative. Endpoint failover stays restricted
  to `UNAVAILABLE` / `DEADLINE_EXCEEDED`, as for signing.
- **No hardcoded spec list.** The driver asks the cluster via `Capabilities` at startup, so adding a
  key type later (section 6) needs no driver release.

Keep `delegate = "hsm"` (or `"software"`) if you still need key types the cluster does not serve.

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

### Read-repair

A hosted-key request that lands on a node missing that key pulls it from a peer *before* answering,
rather than returning `NOT_FOUND`. This is what lets the driver treat `NOT_FOUND` as authoritative
and refuse to fall back to a delegate.

### Replica count

Expect every hosted key on every cosigner. `KeyInfo` reports the live replica count for one key.
There is no per-key replica gauge; `rutli_hosted_keys` is per node, and it refreshes when a peer
lists this node's inventory — i.e. about once per sweep — so it lags by up to one interval. The
shipped alert `RutliHostedKeyReplicaShortfall` watches for the counts diverging across the job for
20 minutes, which means healing is failing rather than lagging. Metrics and dashboards:
[`observability.md`](observability.md).

Two replicas survive one node loss. One survives none.

### Backup and restore

Hosted keys live in `data_dir/keys/` alongside the FROST shares, in the same sealed envelope format,
so the existing commands already cover them:

```sh
rutli-cosigner backup  --config /etc/rutli/cosigner-2.json --out /secure/backups/cosigner-2/$(date +%F)
rutli-cosigner restore --config /etc/rutli/cosigner-2.json --from /secure/backups/cosigner-2/2026-08-17 --force
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
cluster or KMS**.

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
- **Hosted keys only.** A FROST share is not a whole key — `export-key` refuses one. The namespace
  key cannot leave the cluster, which is the entire point of it.
- **Import never overwrites.** Hosted keys are create-once-immutable, so importing over an existing
  id with *different* material is refused; an identical re-import is a no-op. Rotate to a new key id
  instead.
- **The export file is written `0600` before any bytes land**, so it is never briefly world-readable.
  After the ceremony, treat it like key material: offline media, an HSM, or Shamir-split the
  passphrase — an export sitting on a laptop is a private key sitting on a laptop.
- **Both operations log at WARN** with the key id. That log line is often the only record that a
  portable copy exists; ship it somewhere you will notice.

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

Operational consequences worth writing into your runbook:

- Treat the cosigners as key-custody hosts, not as a service tier. Anyone with shell on one has the
  hosted keys.
- Guard the driver's client certificate like a key: it is what authorizes `Decrypt` on the Signer
  API. `signer_allowlist` restricts that API to the driver CN — set it.
- A hosted-key compromise is a rotation *and* a disclosure assessment. Rotating alone addresses only
  the traffic that has not happened yet.

## 6. What is not hosted yet, and the roadmap

Today the cluster serves `rsa-2048-oaep-sha256` and `aes-256-gcm`. Anything else — EC signing keys
for a synchronizer that requires ECDSA, EC-P256 encryption keys — still needs an `hsm` or `software`
delegate.

| Phase | Adds | Threshold? |
|---|---|---|
| **v1** (now) | hosted RSA-2048 + AES-256-GCM; `delegate = "none"` becomes possible | no — replicated |
| **v1.5** | `EcdhDerive` + hosted EC-P256 keys; the driver completes ECIES with BouncyCastle | no — replicated |
| **v2** | threshold ECIES via `frost-p256` — one stateless round, no nonce hazard | **yes** |
| **never** | threshold RSA | — |

The load-bearing property of that table is that **v1.5 and v2 share a wire contract**: the cluster
performs only the ECDH and the driver completes the framing, so promoting ECIES from a replicated
whole key to a genuine threshold operation is a server-side change plus a config flag, not an API
migration. It also inverts the usual expectation — the scheme Canton's KMS mode defaults to (RSA) is
the one that cannot be thresholded, and the scheme that thresholds cleanly (ECIES over P-256) is one
a self-hosted KMS can advertise where a cloud KMS cannot.

Two things to verify before betting on v2 for a given deployment, both open in the design record:
whether the Global Synchronizer's `requiredEncryptionSpecs` admits `EcP256`/ECIES at all, and a
byte-exact JVM-encrypt → driver-decrypt interop test for BouncyCastle's ECIES framing.

# Disaster recovery runbook

The Canton **namespace / identity key is non-rotatable** and its loss is total — losing control of it
means losing every party and Canton Coin balance hosted under that node's namespace, permanently.
There is no "generate a new one". So for a FROST-backed node, DR is existential and must be planned
before go-live, not after an incident.

Rütli holds that key as a `t`-of-`n` FROST sharing: no machine ever holds the whole key, and the key
survives the loss of up to `n − t` cosigners with no action at all. This runbook covers the cases
beyond that.

The cluster can also hold **non-FROST key material** — the RSA-2048 encryption keypair and AES-256-GCM
symmetric keys ("cluster-hosted keys"). Those are **replicated whole keys, not threshold shares**:
generated on one cosigner, replicated to all, sealed at rest per node, and any node can serve a
decrypt on its own. That difference runs through this runbook in both directions — hosted keys are
much easier to recover than a share (§3c), and a single compromised cosigner yields one of them
outright (`docs/hosted-keys-design.md`). Losing them is also not existential: unlike the namespace
key, Canton can rotate them.

## Threat/loss matrix

| Event | Recoverable? | Procedure |
|---|---|---|
| Up to `n − t` cosigners down | Yes, automatically | Signing continues; the driver fails over to live cosigners. Rebuild the lost nodes at leisure (below). |
| A cosigner's disk lost, share backup exists | Yes | **Restore from backup** (§1). |
| A cosigner's disk lost, no backup | Yes, if ≥ `t` others survive | **Repair the share** from survivors (§2). |
| More than `n − t` cosigners lost simultaneously | Only from backups | **Restore ≥ `t` shares** from cold backups (§3). Without backups this is unrecoverable — which is why §4 is mandatory. |
| Suspected key compromise (≥ `t` shares may be exposed) | Mitigate, not undo | The key cannot be rotated. **Proactively refresh** (invalidates pre-refresh shares) and escalate to a governance decision on the node's future. See `docs/phase-2-frost.md`. |
| A cosigner rebuilt, its **cluster-hosted** keys gone with it | Yes, automatically | It pulls them back from a peer — read-repair on demand, anti-entropy within one sweep (§3c). No backup needed while ≥ 1 cosigner still holds the key. |
| Every copy of a **cluster-hosted** key lost (whole cluster, no backup) | Only from backups | Restore **one** node's own backup onto that node (§3); the cluster re-replicates from it. With no backup the key is gone — rotate in Canton and accept §3b's bounded data gap. |
| Seal **master secret** lost (backups intact but unopenable) | Only from an export | A sealed backup is useless without the master secret. An `export-key` artifact taken beforehand is the only recovery — see §3d. Without either, the key is gone: rotate in Canton and accept §3b's bounded gap. |
| A **cluster-hosted** encryption key exposed | Mitigate, not undo | Rotate the key in Canton topology (the namespace key signs it; node identity is untouched). Rotation protects future traffic only — recorded traffic encrypted to the old key stays readable to whoever holds it. |
| **Cluster CA private key** lost | Yes, no key material at risk | Nothing breaks until the certificates expire, but no certificate can be issued (operator, replacement, new node, renewal). **Rotate the CA** with a dual-CA overlap (§3f, [ca-rotation.md](ca-rotation.md)). Shares, hosted keys, backups and exports do not depend on the CA. |

## §1 Restore a single cosigner from backup

Shares are encrypted at rest (see share sealing), so backups carry no plaintext key material.

```sh
# routine, per cosigner, on a schedule — with the node stopped or the share dir quiesced:
rutli-cosigner --config /etc/rutli/cosigner-2.json backup  --out /secure/backups/cosigner-2/$(date +%F)

# recover a wiped node:
rutli-cosigner --config /etc/rutli/cosigner-2.json restore --from /secure/backups/cosigner-2/2026-07-01 --force
# then start the daemon; it rejoins with its old share (same group key).
```

Store backups **off the node's host** and, ideally, geographically separated. Because the shares are
sealed, the backup is only usable together with the node's seal secret (which lives in your secret
manager, not on disk) — keep the two recovery inputs in separate trust domains.

**On Kubernetes: never mount a cosigner volume into another pod.** A cosigner's `data` PVC is
mounted by that cosigner's pod and by nothing else, ever — not a backup Job, not a debug pod, not a
sidecar. On 2026-10-07 the DevNet soak lost all signing for five minutes (54 failed signs) because a
backup CronJob bound `cosigner-0`'s ReadWriteOnce claim into a second pod: the extra mount left
`data_dir/keys` unreadable to the running cosigner, whose health check does not touch the key store,
so it stayed in rotation and answered every Sign with `INTERNAL` — and the driver deliberately does
not fail over on `INTERNAL`, so a sick leader at position 0 blocked the participant until the pod was
restarted (`soak-2026-10-devnet.md`, incident #1).

Since 0.4.0-rc.2 the backup runs **in the cosigner's own pod**: with `topology: perNode` and
`backup.enabled=true` (the Helm chart; `deploy/k8s` renders the same), each pod has a `backup`
sidecar that mounts the pod's own data volume **read-only** (same pod, so no second mount of the
claim) and copies that node's sealed `keys/*.json` daily to **that node's** destination — a per-node
backup PVC by default, or a script with per-node credentials. The sidecar never mounts the seal
bundle or the TLS key, and there is no CronJob, ServiceAccount or `pods/exec` RBAC any more: the
exec-based backup Job of earlier releases could exec into every cosigner and read every node's seal
secret, i.e. it held the whole key (audit C3). `scripts/check-deploy-policy.sh` refuses such RBAC.

```sh
# what ran (one line per run):
kubectl -n rutli logs rutli-cosigner-n2-0 -c backup | grep BACKUP_
# restore onto a rebuilt node 2 (empty data volume), through the cosigner's own container:
kubectl -n rutli exec rutli-cosigner-n2-0 -c backup -- cat /backup/node-2-<stamp>.tar > node-2.tar
kubectl -n rutli exec -i rutli-cosigner-n2-0 -c cosigner -- mkdir -p /tmp/restore
kubectl -n rutli exec -i rutli-cosigner-n2-0 -c cosigner -- tar -C /tmp/restore -xf - < node-2.tar
kubectl -n rutli exec rutli-cosigner-n2-0 -c cosigner -- rutli-cosigner --config /config/cosigner-2.json restore --from /tmp/restore --force
kubectl -n rutli delete pod rutli-cosigner-n2-0   # the daemon reopens its key store with the restored share
```

These `kubectl exec` calls are a human operator's, made for a restore; no standing principal may
hold `pods/exec`. A restore needs the node's seal bundle as well (Secret `rutli-seal-node-2`), which
is never in the backup path — keep the two in separate trust domains.

A CSI volume snapshot is fine (it is the storage layer, not a second mount). A second mount is not,
whatever its access mode or `fsGroup`.

Cluster-hosted keys live in the same `data_dir/keys/` directory (one sealed file per key id), so
these two commands already cover them — there is no second backup procedure and no sibling directory
to forget. Two properties follow from the sealing: a node's backup restores onto **that node**
(the sealing DEK is derived from the master secret, salted by node id), and hosted keys minted after
the backup was taken are re-acquired from the peers on their own, so a stale backup is not a stale
key set. See §3c for what that self-healing does and does not cover.

## §2 Repair a lost share from survivors (no backup)

If a cosigner is destroyed and its share was never backed up, `t` surviving cosigners can rebuild
exactly its old share via the Repairable Threshold Scheme — without any of them, or the recovered
node, ever learning the group secret. The group key is unchanged. The cryptographic primitive is
implemented and tested (`rutli-frost-core::repair`); the networked cosigner-mesh ceremony that drives
it over gRPC is the current build's follow-up. Until it ships, prefer §1 (keep backups) as the
first-line recovery.

## §3 Catastrophic restore (below threshold lost at once)

If more than `n − t` cosigners are lost at the same time, live signing stops (you're below
threshold) but the key is **not** lost as long as you hold **≥ `t` share backups**:

1. Provision fresh cosigner hosts.
2. `rutli-cosigner restore` at least `t` shares from cold backups onto them (with their seal
   secrets).
3. Start the daemons; the cluster reaches threshold and signs again (verified group key unchanged).
4. Rebuild the remaining cosigners (§1 restore, or re-add and repair once §2 ships) to return to full
   `n`, then **proactively refresh** so the temporarily-assembled quorum's shares are rotated.

Cluster-hosted keys have a lower bar here: every node holds the whole key, so **one** restored
backup is enough (from the node it was taken on), and anti-entropy pushes each key to the rebuilt
nodes within one sweep. Shares are the part that needs `≥ t` distinct backups.

## §3b Lost delegate encryption key (software backend without persistence)

**Symptom:** after a participant restart, fatal crash on catch-up:
`KmsDecryptError: key not found: enc-encryption-…` → `SYNC_SERVICE_SYNCHRONIZER_DISCONNECTED` →
`FATAL UnrecoverableError`. FROST signing keys are fine (they live in the cluster); the RSA/ECIES
encryption key served by a heap-only software delegate died with the old JVM.

**Why this is unrecoverable in place:** Canton publishes the encryption *public* key in topology;
peers encrypt views to it, and the catch-up stream already contains ciphertext under it. A freshly
generated key cannot decrypt that history, and rotation only changes *future* traffic. The private
key was never persisted — no backup contains it.

**Recovery (accept a bounded data gap):**
1. Do not reconnect yet. Enable repair commands on the participant and use
   `participant.repair.ignore_events` over the poison sequencer range (the `first/last sequencing
   timestamp` values in the fatal log). Those events' effects are lost for this participant.
2. Reconnect. If the node hits further decrypt misses for the same key id, repeat step 1 for the
   new range — iterate until clean. (Traffic addressed to the dead key keeps arriving until
   rotation propagates.)
3. Rotate the encryption key via Canton topology (console: generate a new encryption key and
   register it; the transaction is signed by the namespace key, which the FROST cluster still
   holds — node identity is untouched). New traffic becomes decryptable.
4. **Before the next restart**, make the replacement key durable — see prevention below.

**Prevention:** never run a real node with a heap-only software delegate. Three durable options,
best first for a deployment without an HSM.

**(a) Host the encryption key in the cluster.** The cosigners hold the RSA-2048 encryption keypair
and the AES-256-GCM symmetric key themselves, so no key material sits on the participant host at all:

```json
{
  "share_seal": { "secret_file": "/run/rutli/seal/node.json" },
  "hosted_keys": { "enabled": true, "write_quorum": 2, "anti_entropy_interval_secs": 300 }
}
```

on every cosigner (config validation refuses `hosted_keys` without `share_seal` — a whole private key
must never sit unsealed on disk), and on the driver side `frost.hosted-keys = true`, which routes key
ids prefixed `rutli-` to the cluster alongside `frost-`. With that, `delegate = "none"` becomes
possible: no HSM, no local key state, nothing on the participant to lose across a restart.

What this is and is not: these are **replicated whole keys, not threshold shares** — three sealed
copies, any one of which decrypts alone. So one compromised cosigner yields that key, and because
Canton's encryption keys protect per-view session keys, an attacker who extracts one gains
**retrospective** read access to any recorded traffic encrypted to it; rotating afterwards fixes the
future, not the past. The security tier matches the recoverability tier: the key Canton *cannot*
rotate (the namespace key) stays real 2-of-3 threshold, and the keys that get only replication are
exactly the ones Canton *can* rotate under it. The win over a heap-only or single-disk delegate is
relocation plus redundancy — key material moves off the busy, internet-adjacent participant host onto
three hardened single-purpose nodes, and the loss of any one of them costs nothing (§3c).

Note for this failure mode specifically: the driver does **not** fall back to the delegate on
`NOT_FOUND`. That is deliberate — a silent fallback would split custody between cluster and delegate
and could reproduce exactly this incident. A missing key is reported, not worked around.

**(b) Sealed disk persistence for the software delegate** — when the keys must stay on the
participant:

```hocon
config {
  backend = "frost"
  software = {
    dir             = "/rutli-state/softkeys"   # durable volume (PVC on k8s)
    seal-secret-env = "RUTLI_SOFT_SEAL_SECRET"  # openssl rand -hex 32, from a secret manager
  }
  frost = { delegate = "software", … }
}
```

(the driver refuses `dir` without a seal secret, and fails loudly on a wrong secret rather than
starting keyless). Include the `softkeys/` directory and its secret in the same backup discipline as
cosigner shares — this is one copy on one host, so the backup is the whole safety net.

**(c) An HSM delegate** — durable and non-exportable, but still one copy on one appliance next to the
participant, and one more thing to run and back up per the vendor's procedure.

## §3c Cluster-hosted keys: what recovers itself, what does not

Hosted keys are stored in `data_dir/keys/` alongside FROST shares — one sealed file per key id — so
`rutli-cosigner backup`/`restore` cover them with no new procedure (§1). The more important
operational fact is that for a single-node loss you usually will not need the backup at all.

**Automatic.** A rebuilt cosigner re-acquires hosted keys from its peers by two mechanisms:

- **read-repair** — a request for a key this node lacks pulls it from a peer before answering, so a
  lagging replica does not return `NOT_FOUND` to Canton. (The driver deliberately does not fail over
  on `NOT_FOUND`, so that answer has to be trustworthy.)
- **anti-entropy** — every `anti_entropy_interval_secs` (default 300) each node pulls keys it lacks
  and pushes keys a peer lacks. The first sweep runs one interval *after* startup, not at boot.

A node that comes back with an empty `keys/` directory is therefore serving hosted-key traffic again
within one sweep — or immediately, on the first request that needs a key. This is also why
`write_quorum` defaults to 2 of 3: a write that reaches only two nodes is a transient the sweep
heals, whereas requiring all three would block key rotation whenever any node is down. Below quorum
the write is **rolled back** (a best-effort purge on every node) rather than left as one lonely copy,
and the key id stays free for a clean retry — generation is idempotent by key id, so a retry repairs
replicas instead of minting a second key under the same name.

**Preconditions.** A rebuilt node that misses one of these repairs nothing — it logs the failure
rather than silently continuing with a wrong or empty key set:

- the **same node identifier** and the **same master seal secret**: the X25519 key peers wrap
  material to is derived from that secret (HKDF, salted by node id), and every envelope is addressed
  to one recipient — a wrong secret means peers wrap to a key this node cannot open;
- the **same cluster CA**: envelopes are AAD-bound to a cluster id derived from the CA certificate,
  so material cannot cross trust domains;
- the rebuilt node's certificate CN present in every peer's `peer_allowlist` — replication runs over
  the mesh Peer API, which is allowlisted;
- **at least one live cosigner that still holds the key.**

**Not automatic, by design.**

- **FROST shares are never listed, fetched or copied between nodes.** Replication, `FetchKey` and
  anti-entropy cover hosted keys *only*; two nodes holding the same share would silently break the
  threshold scheme, so this is enforced in code rather than left to configuration. A rebuilt node's
  share still comes from §1 (backup) or §2 (the repair ceremony).
- **Nothing reconstructs a hosted key once every copy is gone.** Hosted keys are
  create-once-immutable — a key id maps to one key forever, and Canton rotates by minting a new id.
  If the whole cluster is lost, recovery is restoring one node's own backup (§3). With no backup at
  all you are back in §3b: rotate in Canton and accept the bounded data gap.
- **Divergence is never merged.** If two nodes hold different material under one key id, the sweep
  logs an error and increments `rutli_anti_entropy_conflicts_total` instead of picking a winner. Any
  increase is page-worthy — it means something wrote outside the create-once discipline.

**Two hazards to write into your runbook.**

- **A stale backup can resurrect a deleted key.** The sweep treats "a peer does not have this key" as
  something to fix, and cannot distinguish it from "this key was deleted cluster-wide while this node
  was down". Restoring an old backup will therefore push a since-deleted hosted key back to every
  node. After a cluster-wide delete, prune the key from the backups — or simply re-issue the delete
  once the restored node has rejoined.
- **Delete is not erasure.** Deleting a hosted key removes the only referenced copy; it does not
  destroy bytes on a COW filesystem, a wear-levelled SSD, a volume snapshot, or an existing backup.
  True destruction requires rotating the master secret and re-sealing every live key.

## §3d Recovering with an exported key (seal secret lost, or moving clusters)

`backup` cannot help in two cases: the seal master secret is gone (every sealed file is ciphertext
you can no longer open), or you need the key in a *different* cluster. An export artifact covers
both, because it is protected by its own passphrase rather than by the cluster's seal secret.

This only works if the export was taken **in advance**. Decide during the key ceremony whether you
want one; there is no way to produce it after the seal secret is lost.

```sh
# On any node of the target cluster, stopped:
read -rs EXPORT_PASS && export EXPORT_PASS
rutli-cosigner --config /etc/rutli/cosigner-1.json import-key \
  --in /media/offline/rutli-enc.export --passphrase-env EXPORT_PASS
# Start the daemon; anti-entropy replicates the key to the rest of the cluster.
```

Verify before declaring recovery: the participant's published encryption public key in Canton
topology must match `PublicKey` for that key id on the cluster. If it does not, the node is
advertising a key the cluster cannot serve, and you are in §3b instead.

Applies to hosted keys only. A FROST share cannot be exported, so the namespace key's recovery path
remains §1/§2/§3 — backups or repair from survivors. Full mechanics and the security tradeoff:
[`hosted-keys.md`](hosted-keys.md) §4.

## §3e Keys imported by the split ceremony

A namespace key moved in from an existing Canton node ([split-ceremony.md](split-ceremony.md)) is,
once installed and refreshed, an ordinary FROST key: §1–§3 apply unchanged, `backup`/`restore` carry
its share (provenance included, inside the sealed file), and `verify-key` is the post-recovery check.
Three things differ:

- **Founding backups come after the first refresh, never before.** Suspend the backup CronJob for
  the ceremony window: a backup taken between `import-share` and the refresh holds the *dealt*
  shares, and `t` of those plus the seal secret are the key as the dealer produced it. Any such
  backup goes on the ceremony's destruction list. The daemon logs a startup WARN for every imported
  key that has never been refreshed.
- **A failed ceremony is backed out with `abort-import`**, per node:
  `rutli-cosigner --config … abort-import --key-id <id> --ceremony-id <id> [--yes-delete-installed-share]`.
  It deletes the pending recipient secret, and deletes an installed share only if it came from that
  ceremony, was never refreshed, and the flag is given — it cannot touch a DKG key or a live
  (refreshed) imported key. There is no generic key-destroy command.
- **The old copies are part of the threat model, not of recovery.** Until destruction (runbook
  Step 9) the old database and its backups are the rollback path for the cutover; after it, they
  must be gone. They are never a recovery source for the cluster key — restoring the key from them
  would mean another dealer run and a new ceremony.

## §3f Loss of the CA private key

The cluster CA (`tls.ca_cert`) is the only trust anchor of the mesh and of the driver → cluster
hop. Its private key exists only to **issue** certificates: an operator certificate for
`verify-key`, a replacement cosigner or driver certificate, a certificate for an added node, and
renewals. Losing it (the DevNet soak, found 2026-10-09) does not stop anything that is running.

**What is at risk, and what is not**

- **No key material.** Sealed shares, hosted keys at rest, their commitments, `backup`/`restore`
  files and `export-key` artifacts contain nothing derived from the CA. Nothing needs re-sealing or
  re-importing.
- **The cluster id.** Unless pinned, it is a hash of the CA *file* (`wrap::cluster_id_from_ca`), and
  it is bound into hosted-key replication envelopes and split-ceremony requests and bundles. Those
  are in flight, not at rest. The only persisted holders are a pending recipient
  (`data_dir/ceremony/*.recipient`) and the dealer's files during a ceremony. Pin it (`cluster_id`,
  chart `clusterId`) to its current value before the CA file changes ([ca-rotation.md](ca-rotation.md) §2).
  Each node also records the id it runs under in `data_dir/cluster-id` and refuses to start under
  another (`cluster id mismatch`): a dropped pin stops a pod instead of splitting the cluster. The
  file is not in `backup` (which copies `data_dir/keys`); a node restored onto a fresh volume
  records its id again at first start, so restore its config with the pin first.
- **A deadline.** When the leaves expire (soak: 2028-10-19, together with the CA), every handshake
  fails and the cluster stops signing. Rotate well before that. An expired **CA** bites first at a
  restart: a cosigner (and the driver) refuses a trust file holding an expired CA, so every pod
  that restarts after the CA's notAfter stays down. `tls.allow_expired_ca` (chart
  `tls.allowExpiredCa`, driver `frost.tls.allow-expired-ca`) is the emergency override for the
  rotation away from it. Each cosigner logs `trust anchor … not_after=…` at startup and warns from
  30 days before.
- **If the key may be exposed rather than lost**, it is a security incident. Whoever holds it can
  mint a certificate with CN `driver` and use the Signer API: the allowlists match CNs, not issuers.
  Rotate immediately, drop the old CA from cosigners and driver without waiting for a planned
  restart ([ca-rotation.md](ca-rotation.md) §6), and treat `Sign` calls in that window as suspect
  (driver audit log).

**Recovery:** a zero-downtime CA rotation. Pin the cluster id, have the cosigners trust old + new,
give the driver the bundle and a new leaf (one participant restart), swap the cosigner leaves, then
drop the old CA. Every intermediate state is mutually compatible, so a rolling restart never splits
the mesh. Exact commands, per-step gates and rollback: [ca-rotation.md](ca-rotation.md).

**Prevention (§4):** escrow the new CA key encrypted in two independent locations, test the restore
by comparing public keys, and record where it lives in the key-ceremony record.

## §4 What you MUST have in place before go-live

- **≥ `t` cosigner share backups**, encrypted (sealed) and stored in ≥ 2 separated locations. This is
  the difference between "recoverable" and "irrecoverable" for the catastrophic case.
- **Seal secrets** for those shares in a secret manager, in a different trust domain from the backups.
- On Kubernetes, the job that takes those backups runs `kubectl exec` **inside** each cosigner.
  **Never mount a cosigner volume into another pod** — it took the DevNet soak's signing down on
  2026-10-07 (§1).
- A **documented, rehearsed** restore drill (test §1 and §3 on a devnet with the same tooling — the
  cluster test `a_lost_node_recovers_from_a_share_backup_and_the_cluster_signs` is the automated
  analogue).
- The **cluster CA private key escrowed**: encrypted with a strong KDF (`openssl pkcs8 -topk8 -v2
  aes-256-cbc -iter 600000`, or `age`; not `openssl pkey -aes256`), in ≥ 2 independent locations,
  restore tested (`openssl pkey -pubout` of the restored key equals the CA certificate's public
  key), and the plaintext shredded right after. It is the
  only way to issue operator, replacement, renewal or new-node certificates; losing it forces a CA
  rotation (§3f). Record the CA's sha256 and the leaves' expiry date, and keep the cluster id pinned
  (`cluster_id`) so the CA file can change without touching it.
- A **proactive-refresh schedule** so a share exposed at any point has a bounded useful lifetime.
- A decision, recorded, on whether to take an **`export-key` artifact** for each hosted key. It is
  the only recovery from a lost seal master secret, and it cannot be produced retroactively — but it
  is also a portable copy of a private key, so storing one is a deliberate tradeoff, not a default.
- A **key-ceremony record**: who ran DKG, the `t`/`n` chosen, cosigner host/account/region for each
  share, and where each backup + seal secret lives. Keep it with your BCP documentation. For an
  imported key, the split-ceremony record and the signed destruction record instead
  ([split-ceremony.md](split-ceremony.md) §8), and founding backups taken **after** its first
  refresh (§3e).
- **If hosted keys are enabled:** the same backup discipline covers them for free, but the input that
  actually decides recoverability is the **master seal secret** — without it a rebuilt node can
  neither open its own backup nor accept a replica from a peer. Rehearse a rebuild with an empty
  `keys/` directory and confirm the node re-acquires its hosted keys (the cluster tests
  `a_node_that_missed_a_write_is_repaired_and_then_serves_decrypts` and
  `anti_entropy_pushes_a_key_to_a_node_that_missed_it` are the automated analogues), and confirm the
  same drill does *not* hand it a FROST share — that one still needs §1 or §2.

## Verifying a recovery

After any restore/repair, confirm the node identity did not change:

```sh
# the group verifying key (and therefore the Canton namespace) must be identical to before
rutli-cosigner --config … refresh --key-id frost-<node>-namespace   # prints the group key; compare
# or, read-only, every node at once: present, same package, own verifying share consistent
# (operator cert; add --sign-test for an imported key: every t-subset of cosigners signs)
rutli-cosigner --config … verify-key --key-id frost-<node>-namespace --expect-fingerprint 1220…
# and confirm the participant still reports the same PAR::…::<fingerprint> identity in the Canton console.
```

With hosted keys enabled, also confirm the rebuilt node caught up rather than quietly serving a
short key set:

- `rutli_key_replicas` (gauge) — the fewest cosigners holding any one hosted key — is back at the
  cluster size. It is recounted at the end of each sweep, so give it one sweep interval before
  reading it;
- `rutli_hosted_keys` (gauge) reports the same count on every cosigner. It is refreshed at the end
  of that node's own sweep and whenever a peer lists it, so the same one-interval wait applies; a
  node stuck below the others is not repairing — usually a wrong seal secret or a missing
  `peer_allowlist` entry;
- `rutli_unreadable_key_files_total` is **flat**. A rising counter means a key file on that node
  cannot be opened and is being skipped from the inventory, so it is neither replicated nor repaired
  — a restore that looks complete but is not;
- `rutli_anti_entropy_conflicts_total` is **0** everywhere. It is not a lagging-replica signal; a
  non-zero value means two nodes disagree about the material behind one key id, which no sweep will
  resolve for you;
- `rutli_hosted_key_ops_total{result="error"}` is flat after the node rejoins.

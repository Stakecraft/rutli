# Threat model (after the audit remediation, batches A–C)

What each realistic adversary can and cannot do to a Rütli cluster once every fix of the audit
remediation is deployed **and switched on**. It replaces the per-feature notes scattered through
the other documents as the single place an auditor or an operator reads first. Where a control is
only as good as a setting, the setting is named; where something is not defended, it says so.

## Scope and assumptions

The statements below hold for a cluster where:

- every cosigner and the driver run the release that completes batch C (Unreleased in
  `CHANGELOG.md`), on a cluster uniformly upgraded **before** any DKG or refresh
  (`ceremony_protocol` 2 on every node);
- the enforcement switches are on, identically, on every node: `signing_policy.require_intent`,
  `signer_acl_required`, `signer_may_refresh: false`, `require_epoch_match` (`docs/approval-quorum.md`,
  "Switching enforcement on");
- key files are written in format v2 (`keyfile.write_version: 2`, `cluster_uuid` set) and the
  legacy shared seal master has been retired: per-node seal bundles, DEKs rotated
  (`seal rotate-dek`), the master escrowed offline and then destroyed (decision P1);
- the Helm `perNode` topology (one StatefulSet per node, per-node seal and TLS Secrets mounted as
  files, the backup sidecar, no `pods/exec` RBAC — `scripts/check-deploy-policy.sh` passes);
- hosted-key deletes, if enabled at all, are restricted to a delete role
  (`hosted_keys.delete_allowlist`) with approvals (`delete_approval_threshold` ≥ 1, decision P8).

The cluster is `t`-of-`n` (2-of-3 in every example). "Signature" means a FROST Ed25519 signature
under a group key; "hosted key" means a replicated whole key (RSA-2048, EC P-256, AES-256-GCM —
`docs/hosted-keys-design.md`).

## Assets

| Asset | Where it lives | Consequence of loss of control |
|---|---|---|
| Namespace / protocol FROST keys | One share per node, sealed in `keys/<id>.json` | Existential for the namespace key (non-rotatable). `t` shares = the key |
| Hosted keys | Whole key on every node, sealed | Retrospective decryption of traffic encrypted to it; rotatable in Canton |
| Seal bundle (per node) | Per-node Secret, file-mounted into the cosigner container only | That node's DEK: opens that node's sealed files (one share, every hosted key) |
| Node TLS key | Per-node Secret | Impersonation of that node on the mesh |
| Driver TLS key | The participant | Signer-role requests (bounded below) |
| Sign journals | `data_dir/journal` per node | The independent record of every share released |

## Trust domains

Each cosigner is meant to be its own trust domain: its share, DEK, TLS key and memory compromise
that node and nothing else. **One Kubernetes cluster administered by one team is a single trust
domain for its cluster-admin (decision P10, documented limitation).** The perNode topology removes
the *routine* principals that used to collapse the domains — the shared seal Secret, the
exec-capable backup job — but anyone who can read every Secret in the namespace, exec into every
pod or read every node's volume holds `n` shares and every DEK. For mainnet, put the cosigners in
separate clusters or cloud accounts administered by different people; nothing in Rütli can
substitute for that.

## Adversaries

### A compromised leader (any one node, as the node the driver happens to call)

**Cannot:**
- learn another node's share in DKG or refresh — round-2 packages travel node to node over mTLS
  and the leader only coordinates (audit C1, ceremony protocol 2);
- equivocate round 1 — every delivery carries the sender's digest of the round-1 map, so showing
  nodes different maps makes all of them abort;
- commit mixed epochs or wedge a key id — commit needs every node's durable yes-vote, confirmed
  directly between nodes (H1/M5; the guarantee holds for crash faults — a lying *participant* is
  below);
- obtain a signature over a digest of its choosing — every participant verifies a driver-signed
  intent for exactly that digest before it commits to a nonce, binds the session to it, and
  re-checks it before it releases its share (C2);
- delete a hosted key, or purge one through a "rollback" — deletes need a delete-role intent every
  node verifies; a rollback purge removes only a key the peer created in the same still-fenced
  generation (M2).

**Can:** abort ceremonies and signatures it leads (the driver fails over), burn round-1 nonces,
and refuse to forward. Availability, not integrity.

### A single compromised cosigner (its share, DEK, TLS key, memory)

**Cannot:** reconstruct a key (it holds one share), impersonate another node (per-peer TLS server
names and exact client CNs, M3), make an honest peer release a share without a valid intent, forge
a tombstone, roll a peer back to an old epoch, or get a peer to accept a key file it planted (v2
headers bind cluster, node, key id and kind; plaintext is refused, M4).

**Can:** read every hosted key (inherent to replicated whole keys — `docs/hosted-keys-design.md`),
refuse or corrupt its own contributions (routed around by t-subset retry, flagged by
`RutliInvalidSignatureShare`), re-use an intent it has seen for another signature over the *same*
digest within its validity (harmless, capped by `max_shares_per_request`), and refuse to propagate
tombstones (its own copy of a deleted key stays readable to it — it already had it).

It can also **split a DKG or refresh it takes part in** (audit F3): ceremony votes are reported
unsigned, so it can tell one honest node STAGED and the other ABORTED; one commits, the other aborts,
and every signature then needs the liar (a refresh meant to evict it does not). With n = 3, f = 1
this is not preventable without Byzantine agreement — **a documented residual for n = 3: an
availability attack, never a key compromise**. It is detected (`rutli_ceremony_equivocations_total`,
`RutliCeremonySplit`) and recoverable: the aborted node's staged share is quarantined, and
`ceremony recover-commit` commits it once a peer proves the sharing committed and live
(`docs/ceremonies.md`). It can make each peer write at most a bounded number of no-vote records by
asking about made-up ceremony ids (F2), stall a key's signing for up to the 15-minute orphan timeout
at a time by fencing it for a refresh it leads (any peer may lead one; renewable — a residual,
visible as fenced-key refusals), and open at most 1024 waiting sign sessions per key (round 1 is
refused beyond).

### Holder of the driver certificate and key (bypassing the driver)

**Can:** sign with non-gated keys inside its `signer_acl` prefixes, within the per-node rate limits,
with every share journaled on every participating node (`audit-cross-check` exposes signatures the
driver audit log lacks); decrypt with hosted keys within `decrypt_rate_limit_per_min` per node.

**Cannot:** sign a gated key without `M` approver signatures; refresh (`signer_may_refresh: false`);
use another tenant's prefixes; delete hosted keys (unless an operator put the driver CN on
`hosted_keys.delete_allowlist`, which is off by default — and then only recoverably, within the
grace period, and with approvals if `delete_approval_threshold` is set). Revocation without the CA:
replace the SPKI pin (`signing_policy.signer_pins`).

### Holder of the refresher certificate

Can trigger refreshes (`Refresh`, `KeyStatus`). A refresh re-randomizes shares under the same group
key; it can be used to cause load or to abort, not to learn anything or change the key. Cannot sign.

### Holder of the operator certificate

`KeyStatus`, `HostedKeyStatus`, `CeremonySignTest` (fixed, server-computed test digest, rate
limited): public values and test signatures only. If the operator CN is also on the delete role, it
can delete hosted keys — recoverably, and subject to delete approvals.

### Holder of a delete-role certificate

Can tombstone hosted keys matching its `delete_acl`, with `delete_approval_threshold` approver
signatures. The material stays sealed in the tombstone for `delete_grace_secs` (default 7 days) and
`hosted-undelete` restores it on each node. Cannot touch FROST shares (never tombstoned), cannot
make a deleted id reusable (break-glass on every node only).

### The backup ServiceAccount / a per-node backup destination

The backup runs as a sidecar in the cosigner's own pod with the data volume mounted read-only, no
seal bundle and no TLS key (enforced by `check-deploy-policy.sh`). A destination holds one node's
sealed key files and its sign journals — below threshold, unreadable without that node's DEK.
Destination **plus** that node's DEK = that node's share for every retained backup epoch (still one
share). Retention of old epochs in backups is an operator decision (P2b); a restore never rolls a
live share back (below).

### Kubernetes cluster-admin / a reader of every Secret in the namespace (P10)

**Holds the cluster.** Every DEK, every TLS key, and with exec or node access every volume. This is
the documented single-trust-domain limitation; the mitigation is organisational (separate clusters
or accounts per cosigner), not technical.

### Host root on one Kubernetes node

That node's share, DEK, TLS key, journals and process memory. Below threshold.

### A TLS-terminating service mesh between cosigners (decision P3)

**Not supported.** Round-2 DKG/refresh packages, hosted-key envelopes aside, are protected by the
node-to-node mTLS session itself; Rütli does not add an application-layer encryption (HPKE) on top.
A sidecar proxy that terminates TLS between cosigners (Istio/Linkerd in mTLS-terminating mode, an
L7 load balancer) sees every round-2 package of every ceremony and therefore every new share — i.e.
the keys. **Deploy with no TLS-terminating mesh on the cosigner-to-cosigner path**; exclude the
cosigner pods from mesh injection, or use pass-through (L4) mode. Hosted-key replication is
additionally wrapped to the recipient's X25519 key and is not exposed this way.

### VM or container memory snapshot, clone or live migration (audit L7, T4)

Round-1 nonces live only in process memory. A snapshot restored twice (CRIU checkpoint/restore, a
VM snapshot cloned or rolled back, some live-migration implementations) yields two processes
holding the same nonces; a leader that then asks each copy for round 2 over different messages can
solve for the node's share. Rütli cannot detect this from inside the process. **Never snapshot,
clone, checkpoint or live-migrate a running cosigner VM or container**; stop the cosigner first (a
cold snapshot is safe — the nonces of a stopped process are gone, and its burned-session markers
are on disk). Disable live migration for cosigner VMs where the platform allows it.

### Clock skew

Intents carry `issued_at`/`not_after`. A node whose clock is off by more than
`signing_policy.clock_skew_secs` (default 120 s) refuses every intent — fail closed: an outage of
that node, never a bypass (`RutliSignPolicyRefusals{reason="expiry"}`). Tombstones propagated by
anti-entropy ignore expiry by design (the delete was valid when made) but still refuse an intent
issued in the future, a tombstone whose deletion time lies outside its intent's validity window, and
an intent issued before this node last saw its signer's delete capability change (audit F7: an
intent refused when made — the driver signs one for every Canton `deleteKey` — cannot be replayed
into a delete once the role is granted later; `data_dir/delete-policy.json`). Keep NTP healthy on
the participant and every cosigner.

### Stale backups, snapshot rollbacks, planted files (audit M1, M4)

A restored or rolled-back share on an older epoch is detected at startup and every few minutes by
the stale-share check and refused for signing (`RutliStaleShare`); `restore` itself refuses an older
epoch, another sharing, or a hosted key over its tombstone even with `--force`, short of a per-key
break-glass. A key file renamed to another id, copied from another node or cluster, or of another
kind fails its v2 header check; a plaintext file under sealing stops the daemon. A genuine older
file of the same key and node (a rollback) passes the AEAD — the epoch checks are what catch it.

**M4 is closed only once `keyfile.accept_v1: false` on every node** (audit F10). Until then any v1
file sealed under the node's DEK is accepted (only its in-plaintext key id and the FROST identifier
check limit swaps), and even with v2 a rollback to an older genuine file of the same key and node is
accepted — including a tombstone swapped back for the hosted-key file it replaced, which resurrects
a deleted key for anyone with write access to the volume (the restore path refuses that; a raw file
copy does not).

### Earlier releases: DKG and refresh output is leader-exposed (decision P9)

Every key generated by DKG, and every refresh, on a release **without direct round-2 delivery** —
up to and including 0.4.0-rc.2, i.e. any cosigner that does not report `ceremony_protocol` 2 — sent
every round-2 package through the leader, which could therefore compute the shares and, for a DKG
key, the group secret. Refresh on a fixed release re-isolates the shares of a dealt (split-ceremony)
key but cannot repair a DKG key whose secret was exposed: the secret does not change. **Generate or
split keys that matter only on a release with C1, on a uniformly upgraded cluster.** DevNet soak
keys stay test material.

## Residual risks, stated plainly

- Single trust domain under one Kubernetes administration (P10).
- Hosted keys are whole keys on every node: one compromised node reads them all, and rotation
  protects future traffic only.
- A driver-key thief signs non-gated keys within the ACL and rate limits (bounded and journaled,
  not prevented).
- No defence against a TLS-terminating mesh (P3) or a memory snapshot of a running cosigner (L7).
- Deletion is not erasure: tombstones retain material for the grace period by design, and old
  backups keep every key they captured until the DEK that sealed them is dropped.
- Keys from earlier releases are leader-exposed (P9).
- One Byzantine cosigner can split a DKG/refresh (n = 3, f = 1): availability, detected and
  operator-recoverable, never the key (F3).
- Until `keyfile.accept_v1: false`, v1 key files and same-key rollbacks are accepted (F10).

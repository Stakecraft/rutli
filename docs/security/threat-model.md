# Threat model (after the audit remediation, batches A–C)

What each realistic adversary can and cannot do to a Rütli cluster once every fix of the audit
remediation is deployed **and switched on**. It replaces the per-feature notes scattered through
the other documents as the single place an auditor or an operator reads first. Where a control is
only as good as a setting, the setting is named; where something is not defended, it says so.
The findings these controls answer, with their canonical `DS-` IDs and status, are listed in
[internal-review-2026-10.md](internal-review-2026-10.md).

## Scope and assumptions

The statements below hold for a cluster where:

- every cosigner and the driver run the release that completes batch C (Unreleased in
  `CHANGELOG.md`), on a cluster uniformly upgraded **before** any DKG or refresh
  (`ceremony_protocol` 2 on every node);
- the enforcement switches are on, identically, on every node: `signing_policy.require_intent`,
  `require_ceremony_intent` (on by default since 0.4.0-rc.6, unless opted out with `false`),
  `signer_acl_required`, `signer_may_refresh: false`, `require_epoch_match`
  (`docs/approval-quorum.md`, "Switching enforcement on");
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

It also **cannot park a hosted key on a FROST key's id** (since 0.4.0-rc.6). FROST ids are
deterministic (`<prefix>frost-<name>`), and a peer's `ReplicateKey` needs no client authorization,
so up to rc.5 it could push a hosted key under, say, `frost-namespace` before its DKG (or list one
and let anti-entropy pull it): every node then refused that DKG, and a push after part 3 staged
left that node STAGED while the others committed. The two kinds of key now have disjoint ids: a
node creates a hosted key — generated, pushed, pulled or imported — or records a tombstone, or
takes a hosted-key fence, only under an id whose first routing tag is `rutli-`, and the driver
refuses a `frost.key-prefix` that contains either tag. A hosted record already sitting under
another id (squatted before rc.6) can still be deleted where it is; `hosted-clear-tombstone` then
frees the id.

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
asking about made-up ceremony ids (F2), and open at most 1024 waiting sign sessions per key (round 1
is refused beyond). It **cannot pause signing** by fencing a key for a ceremony (since 0.4.0-rc.4: a
DKG/refresh guard no longer blocks sign round 1, see `docs/ceremonies.md`, "Signing during a
ceremony"). Up to rc.3 it could, and with no time limit: a fence that was never followed by part 1
stopped that key's signing on the fenced nodes until they restarted. That was earlier documented as
"≤ 15 min", which was wrong.

It **cannot start a DKG or refresh** that no client asked for (since 0.4.0-rc.4, with
`require_ceremony_intent` on). Every node verifies, at the fence and at part 1, a client-signed
ceremony intent before it takes the guard or opens a session. The intent must be signed by the
driver for a DKG, or by the refresher for a refresh (the driver only while `signer_may_refresh`). It
names the ceremony id, so one intent runs at most one ceremony (`docs/ceremonies.md`, "Ceremony
intents"). The cosigner holds no key that can sign one, cannot alter one, and cannot replay one into
a second ceremony or onto another key, kind or cluster. A ceremony that fails, even at the fence,
spends its id on every node it reached, and a second leader for one id is refused at the fence. So
it can no longer split the key or churn epochs at will. The ceremony records it can make an honest
node write are still the no-votes for unknown ids (`CeremonyStatus`/`Abort`/`Commit`), bounded by
the per-asker and total caps (F2). What remains:

- it can split (above) a DKG or refresh that a client **did** ask for and that it takes part in;
- it can stop a requested ceremony: by refusing (n-of-n), or by presenting its intent as a second
  leader, which fails and spends the id;
- it cannot take a requested ceremony over (since 0.4.0-rc.6). Every node binds the ceremony to the
  leader whose fence took its guard (the caller's certificate CN, or the node itself) and accepts
  parts 1–3, a second fence, an abort of the live ceremony and the release of that fence only from
  that leader; under `require_ceremony_intent`, part 1 never takes the guard without a fence. The
  leader fences its own node first, before any peer has seen the intent, so a peer that races the
  remaining fences can bind only the other nodes to itself: that stops the ceremony, but every
  ceremony needs the leader's node. And a node fences a client intent's ceremony at most once: the
  fence writes a durable fence mark for the id (kept 24 h, longer than any intent is valid), and a
  mark refuses every later fence under the id, and any part 1 that would take a new guard for it.
  The guard that binds the leader is in memory; the mark is what keeps the id closed when the guard
  goes — released by the leader's rollback while it waits on a stalling peer, preempted, or lost in
  a restart — and it does not depend on the capped no-votes a peer can exhaust. Up to rc.5 it could
  take one over: a fenced peer sees the intent, so it could delay its fence reply, run parts 1–3 on
  both honest nodes under the leader's ceremony id, and choose its own round-1 commitments after
  seeing theirs (a bias of the DKG output, never knowledge of the key; round-1 equivocation was
  still caught);
- nor can it lead a requested ceremony whose leader died or whose nodes restarted: every node the
  leader fenced keeps the id's fence mark, the leader fences its own node first, and every ceremony
  needs all nodes. (Up to the rc.6 review, a leader that died before spending the id, with the
  fenced nodes restarted, left the id free: within the intent's validity it could then fence the
  honest nodes itself, choose its round-1 commitments after theirs and bias the key the driver
  adopts.) Only if both honest nodes lost their marks with their volumes, while the intent is still
  valid, would this reopen;
- like any participant, it can veto every ceremony, onboarding DKGs included, by refusing to take
  part (n-of-n);
- hosted-key genkey/delkey fences are not intent-gated: it can block a hosted id's generation or
  deletion, as it can by refusing;
- a ceremony it binds to itself on an honest node by racing the leader's fence (above) stays on that
  node until it gives it up or the orphan timeout (15 min) passes: the leader's abort cannot end
  another leader's ceremony. That blocks only the key's ceremonies, which it can veto anyway.

The intent's validity bounds the **start** of a ceremony, not its finish: it is checked at the
fence and at part 1, where a node decides to take part, and not again at parts 2–3 or the commit,
which may complete after `not_after`. That is deliberate. Finishing late cannot produce anything the
client did not ask for: a DKG is create-once (a node refuses one over any existing record, and
commits only what it staged for that ceremony id), a refresh is a compare-and-swap from the sharing
the leader announced at the fence (a node aborts if its share changed meanwhile), and a refresh never
changes the group key. A session that stalls is bounded by the orphan timeout, not by the intent.

With `require_ceremony_intent: false` (the opt-out; before 0.4.0-rc.6, the default), a ceremony
without an intent is still accepted and counted (`RutliCeremonyIntentAbsent`), and the residual is as
on rc.3. Any peer can then lead a DKG or refresh at will, split it, and hold off other ceremonies for
60 s with a bare fence or 15 min with a session at a time.

### Holder of the driver certificate and key (bypassing the driver)

**Can:** sign with non-gated keys inside its `signer_acl` prefixes, within the per-node rate limits,
with every share journaled on every participating node (`audit-cross-check` exposes signatures the
driver audit log lacks); decrypt with hosted keys within `decrypt_rate_limit_per_min` per node.

**Can also** run a DKG of a new id inside its `signer_acl` prefixes (it signs the ceremony intent
every node verifies).

**Cannot:** sign a gated key without `M` approver signatures; refresh (`signer_may_refresh: false`,
checked by every node on the ceremony intent);
use another tenant's prefixes; delete hosted keys (unless an operator put the driver CN on
`hosted_keys.delete_allowlist`, which is off by default — and then only recoverably, within the
grace period, and with approvals if `delete_approval_threshold` is set). Revocation without the CA:
replace the SPKI pin (`signing_policy.signer_pins`); for ceremony intents, every node checks the pin,
not only the node it calls.

### Holder of the refresher certificate

Can trigger refreshes (`Refresh`, `KeyStatus`; each refresh needs a ceremony intent signed with this
certificate, verified by every node). A refresh re-randomizes shares under the same group key; it can
be used to cause load or to abort, not to learn anything or change the key. Together with a
compromised cosigner, every refresh it requests is a split opportunity (DS-CR4). Cannot sign, cannot
run a DKG. Revoked by replacing its SPKI pin or removing its CN from `refresh_allowlist`. There is no
per-key refresh ACL (follow-up).

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
- With n = 3, a compromised cosigner can split (DS-CR4) any DKG or refresh it takes part in, but
  with `require_ceremony_intent` on only one a client asked for. It can veto every ceremony,
  onboarding DKGs included (n-of-n). Not bound into a refresh intent yet: the expected
  `(epoch, PKP digest)` (follow-up).
- Deletion is not erasure: tombstones retain material for the grace period by design, and old
  backups keep every key they captured until the DEK that sealed them is dropped.
- Keys from earlier releases are leader-exposed (P9).
- One Byzantine cosigner can split a DKG/refresh (n = 3, f = 1): availability, detected and
  operator-recoverable, never the key (F3).
- Until `keyfile.accept_v1: false`, v1 key files and same-key rollbacks are accepted (F10).

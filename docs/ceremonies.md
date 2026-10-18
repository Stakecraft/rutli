# DKG and refresh ceremonies (ceremony protocol 2)

How a Rütli cluster generates (DKG) and re-randomizes (refresh) a FROST key, what each node
stores while it does, and what an operator does when a ceremony does not finish on its own.
Fixes audit C1 (the leader saw every round-2 secret share), H1 (an interrupted refresh left mixed
epochs) and M5 (a partial DKG wedged a deterministic key id).

## Protocol

The node the request reaches leads, but it only coordinates. Every node — the leader included,
as a participant — does the following:

1. **Fence.** Take the per-key guard; refuse a ceremony id this node already holds a record for,
   a ceremony for a key that has one staged and unresolved, a DKG over an existing key, or a
   refresh whose leader saw a different `(epoch, PKP digest)` than this node holds. Refuse a leader
   below ceremony protocol 2. The guard serializes ceremonies for the key; it does **not** pause
   signing (see [Signing during a ceremony](#signing-during-a-ceremony)).
2. **Part 1.** Check that the roster the leader names is exactly this node's own roster; return
   the round-1 package (public).
3. **Part 2.** Check the leader's round-1 map: exactly the roster, and this node's own package
   unchanged. Compute `D = digest(ceremony, key, kind, n, t, old epoch, old PKP digest, map)`.
   Compute the round-2 packages and **deliver each directly to its recipient** over the mTLS mesh
   (`Peer.CeremonyDeliver`), dialling the recipient under its own TLS name `cosigner<id>`. Each
   delivery carries `D`. The leader gets back only `D` and the list of recipients.
4. **Deliver (recipient side).** The sender is the caller's certificate CN, mapped exactly to a
   roster identifier; a delivery claiming another sender, addressed to another node, or a second
   different package from the same sender (equivocation) is refused — the last one aborts.
5. **Part 3.** Require a delivery from every other roster node, each carrying a `D` equal to this
   node's own, and the leader's `D` equal too. Otherwise vote no. Then compute the new share,
   **stage** it (`keys/.staged/<key>.<ceremony>.json`, sealed, fsynced) and record a durable
   **STAGED** vote (`keys/.ceremonies/<ceremony>.json`). The old share stays live.
6. **Commit.** A node commits only after asking **every** roster node directly
   (`Peer.CeremonyStatus`) and finding a STAGED or COMMITTED vote for the identical outcome
   `(key, kind, new epoch, new PKP digest, D)`. It then promotes the staged share (create-once for
   DKG; for refresh an atomic replace, only if the live share is still the one the refresh started
   from) and records COMMITTED. It aborts only on direct evidence: a node voted ABORTED, or staged
   a different outcome. A recorded vote never leaves COMMITTED or ABORTED.

### Signing during a ceremony

Since 0.4.0-rc.4, signing goes on while a DKG or refresh runs, from the fence through commit. Up to
rc.3 any held guard refused sign round 1 for the key, and a refresh was refused while a node had
sign nonces in flight. That was a leftover of ceremony protocol 1, where part 3 overwrote the live
share. Under protocol 2 it is not needed:

* The fence and parts 1–3 never touch the live share or the loaded signing state. Part 3 reads the
  live share and writes only the staged share and the STAGED vote.
* The live share changes only at commit, and the guard is already released by then. Signing across
  a commit was therefore always possible, and it is handled. The commit evicts the loaded share.
  Round 1 checks the leader's `(epoch, PKP digest)`. A sign whose round 1 ran before the commit
  ends one of two ways. If every member's round 2 had already picked up the old signing state, the
  shares are all from the old sharing and combine into a valid signature under the unchanged group
  key. If a member's round 2 starts after the commit, it fails cleanly, because the new signing
  state has no session for it. The leader's retries in that same sign still name the sharing it
  saw before the commit, so round 1 refuses them, and the sign fails with UNAVAILABLE. The next
  sign (the driver's failover, or the client's retry) uses fresh sessions on the new sharing.
* Nonces are never reused. Round-1 nonces live only in memory with the share that made them and
  are dropped with it, and each session burns a durable marker.
* A DKG has no live key to sign with.

What this means for operators: a weekly refresh no longer pauses signing, so there is no need to
drain topology traffic first. Expect a few leader-side retries (`rutli_sign_aborts_total`) on a
busy key around the moment a refresh commits.

### Guard timeouts

Each guard is timed from the moment its ceremony first takes it. If the same ceremony id fences
again or runs its own part 1, the timer keeps running from that first moment. Up to rc.3, re-fencing
under the same id restarted the timer, so the guard could be held forever. A guard that has timed out
is *orphaned*: the next ceremony for the key preempts it and drops its session. A preempted ceremony
can never stage, because part 2 and part 3 check that it still owns the guard.

| Guard | Orphaned after |
|---|---|
| DKG/refresh fence never followed by part 1 (leader died, or a peer fenced on its own) | 60 s |
| DKG/refresh with a session (part 1 created it) | 15 min |
| Hosted-key genkey/delkey | 15 min |

Part 1 marks the guard as having a session under the same lock, and at the same moment, as it
creates the session. A part 1 that fails before that point leaves the leader's fence as it found it
(fence-only, 60 s; the leader's abort releases it sooner), and releases a guard it took itself
because no fence preceded it. Likewise, when a node rebuilds its ceremony state after a request
panicked while holding it (the in-memory sessions are dropped, as on a restart), every DKG/refresh
guard that had a session goes back to fence-only. The leader's next part fails on that node, and
the leader's abort releases the fence. If the leader is dead, the fence timeout frees the key.

The guard is released at part 3, or when the ceremony fails cleanly, so in practice these timeouts
only matter for a leader that died. Up to rc.3 a fence that was never followed by part 1 had no
timeout at all for signing: until the pod restarted, that node refused to sign with the key.

### Votes on unknown and orphaned ceremonies

A node that is asked about a ceremony it has neither a session nor a record for durably votes
ABORTED before answering, so its answer can never change later. A session orphaned past the
15-minute orphan timeout (its leader is gone) does the same. The leader's `CeremonyAbort` drops
only in-memory sessions; it is never evidence for a STAGED node.

Those no-votes are **bounded** (audit F2), because any mesh peer can ask about made-up ids: at most
256 per asking peer (its certificate CN) and 1024 in total for unknown ids, 1024 for failed or
orphaned sessions, and at most 64 sessions in memory. Beyond a cap the node **refuses**
(RESOURCE_EXHAUSTED, `rutli_ceremony_unknown_refused_total`): it records and answers nothing. That
keeps the commit rule safe — a node answers ABORTED only from a durable record and never starts that
id again; a refusal is no vote, the asker treats it as unknown and waits (it never commits without
this node's yes-vote, and never aborts on a refusal), and the node may still take part in that id
later without contradicting anything it said. The cost is liveness only, and only once a peer
spent its quota: a STAGED node asking about a ceremony another node really lost waits (or uses
`--assume-lost`) instead of aborting. Unknown-id no-votes are garbage-collected after 30 days.

What a malicious leader can and cannot do:

* It never holds a round-2 package (no peer API returns one), so it cannot reconstruct the key.
* Showing nodes different round-1 maps makes their digests differ; every honest node refuses at
  part 3. Substituting a node's own package is caught by that node at part 2.
* It cannot make one node commit while another aborts **as the leader**: commit needs every node's
  own durable yes-vote, confirmed node to node.
* It can still refuse to finish (denial of service), as any participant can.

**"No two nodes resolve one ceremony differently" holds for crash faults** — nodes that crash,
restart, lose messages or are unreachable. It does **not** hold against a *participant* that lies
about its own vote (audit F3): votes are reported unsigned, so a Byzantine cosigner can answer
STAGED to one honest node and ABORTED to the other. The first commits, the second aborts, and the
two can no longer sign together — every signature then needs the liar, and the refresh did not
evict its share. With n = 3, f = 1 this cannot be prevented without Byzantine agreement; it is a
documented residual that costs **availability, never the key** (no node ever holds shares of a
sharing it should not). It is detected and recoverable instead — see [Split ceremonies](#a-split-ceremony-byzantine-cosigner).

The mesh must not run through a TLS-terminating proxy (Istio/Linkerd sidecars in mTLS-terminating
mode): round-2 packages are protected by the node-to-node TLS session only.

### Epochs

Every share records its `epoch`: 1 after DKG, +1 per committed refresh. A share written before
epochs existed, or installed by the split ceremony, reads as 0. `verify-key` reports each node's
epoch and flags a mix. A refresh is refused unless every node reports the same epoch and PKP
digest (`Peer.KeyEpoch`).

### Signing across epochs

Shares of different sharings never combine, so signing is epoch-aware (audit H1, M1):

* **Round 1 names the sharing.** The leader sends its own `(epoch, PKP digest)` for the key in
  `SignRound1`. A node whose committed share differs refuses with FAILED_PRECONDITION and the
  trailer `rutli-error: epoch-mismatch` (carrying its own `rutli-epoch` / `rutli-pkp-digest`),
  counts `rutli_epoch_mismatch_total` and logs an ERROR. It never signs from a mismatched epoch.
  A leader on a release before epochs sends no sharing: the check is skipped with a warning and
  `rutli_epoch_check_skipped_total`, unless `signing_policy.require_epoch_match` is set (then it
  is refused). Turn that flag on once every cosigner runs this release.
* **Stale-share check.** At startup and every 5 minutes (every 30 s while a peer has not
  answered) each node compares its sharing of every FROST key with its peers' (`Peer.KeyEpoch`).
  It marks a key **stale** when its own COMMITTED ceremony record names a newer epoch than its
  share, or when a peer holds the same group key at a newer committed epoch, no peer holds this
  node's sharing, and this node has no staged vote for the newer one. A stale node refuses every
  round 1 for the key (`rutli-error: stale-share`), refuses to lead it (UNAVAILABLE, so the driver
  fails over), and reports `stale` in `KeyEpoch`, `KeyStatus` and `verify-key`; the gauge
  `rutli_stale_share{key}` is 1. This catches a restore from an old backup, a volume snapshot
  rollback and backup mix-ups. A node that is only waiting to commit (it voted for the newer
  sharing) is not stale: its resolver commits it. Recovery is restoring a current backup of that
  node (daemon stopped) or re-enrolling it; the mark clears by itself once the share is current.
* **Quorum selection with retry.** The leader tries t-subsets of the roster, itself first, then
  by identifier. Each attempt is a fresh session: a new session id and fresh round-1 commitments
  from every member, never reused across subsets. A member that fails round 1 or round 2, or whose
  signature share fails verification at aggregation (frost's cheater detection names it;
  `rutli_invalid_signature_shares_total`), is excluded for the rest of the request; the session is
  aborted on the members still holding nonces, and the next subset without an excluded member is
  tried (`rutli_sign_retries_total`). At most 10 attempts within 45 s. If `t` peers report one
  sharing that is not older than the leader's, the leader is the odd one out and answers
  UNAVAILABLE so the driver fails over to a node on the cluster's sharing. When no subset can
  sign, the answer is UNAVAILABLE (`could not reach signing threshold`).
* **Session binding.** Round 1 also declares the message and the attempt's signer set; each node
  binds its nonces to them (and to the key). A round 2 for that session with another message,
  another commitment set, or the node's own round-1 commitment altered is refused
  (FAILED_PRECONDITION) **before** the nonce marker burns, and the session's nonces are dropped,
  so no share is ever released for it. Signing intents (audit C2) bind into the same hook. A
  leader that predates binding declares nothing, and nothing beyond frost's own checks applies.

### Idempotent DKG

`Signer.Dkg` for a key id first asks every node (`KeyEpoch`):

| Cluster state | Reply |
|---|---|
| no node holds it | a fresh DKG |
| every node committed it, same sharing, DKG origin | the existing group key (Canton's retry succeeds) |
| a ceremony for it is staged somewhere | every node is asked to resolve; UNAVAILABLE (retry) |
| some nodes hold it (a legacy partial key) | FAILED_PRECONDITION naming `discard-partial-key` |
| an imported or hosted key under the id | ALREADY_EXISTS |

### Detached orchestration

The leader runs the ceremony as its own task. A Dkg/Refresh RPC whose caller gives up (driver
deadline, killed CronJob pod) does not cut it between nodes; the ceremony finishes or aborts
everywhere. A refresh that is staged everywhere but could not reach a node for the commit returns
UNAVAILABLE; the nodes' resolvers complete it.

## Resolver

Every node runs a resolver at startup and every 30 s while it holds a STAGED vote, and on every
`Peer.CeremonyCommit` (sent by the leader after part 3). It applies the commit/abort rule above.
While a node is STAGED it keeps signing with the old share. Metrics:

* `rutli_ceremonies_staged` — STAGED votes not yet resolved on this node. Alert if > 0 for more
  than a few minutes: a peer is unreachable or a session is orphaned.
* `rutli_ceremony_resolutions_total{result="committed|aborted|recovered"}`.
* `rutli_ceremonies_split` — ceremonies this node aborted while a peer reports them COMMITTED with
  this node's outcome (alert `RutliCeremonySplit`, critical).
* `rutli_ceremony_equivocations_total` — COMMITTED and ABORTED reported for one ceremony.
* `rutli_ceremony_unknown_refused_total`, `rutli_ceremony_unknown_no_votes` — the no-vote caps above.

An abort that contradicts a peer's yes-vote (one peer ABORTED, another STAGED/COMMITTED for this
node's outcome) is applied only after the votes are gathered again 2 s later (audit F3). With crash
faults that merely delays the abort. Every resolver abort **quarantines** the staged share instead
of deleting it (the record says `"quarantined": true`): it is deleted once every peer is seen in a
terminal state with nobody COMMITTED for this outcome — then no honest node can commit it any more —
or after 7 days without a split.

Records of settled ceremonies (every peer seen terminal) are deleted after 30 days; a record whose
share is still quarantined is kept.

## Operator procedures

All of these run on one node with **its daemon stopped** (they take the instance lock) and talk to
the other cosigners over the mesh with that node's certificate (`--config` = the node's config). On
Kubernetes (Helm `topology: perNode`), set `maintenanceNodes: [<id>]`: that node's cosigner
container then idles without a daemon, and the commands run with `kubectl exec <pod> -c cosigner`.

### Resolve now

```
rutli-cosigner --config node.json ceremony resolve --ceremony-id <id>
```

Same rule as the background resolver. Ceremony ids are in the node's log
(`ceremony staged …`, `ceremony still STAGED …`) and in `keys/.ceremonies/`.

### A node is permanently lost (break-glass)

If a node died after staging and its disk is gone, the others wait for it forever. On each
surviving STAGED node:

```
rutli-cosigner --config node.json ceremony resolve --ceremony-id <id> --assume-lost <lost id>[,<id>…]
```

It commits if any reachable node already COMMITTED (that node saw every yes-vote, the lost one
included), otherwise aborts (nobody reachable committed, and the lost node's share is gone). Every
roster node not named must answer. **Never name a node that may come back**: if it had committed,
it would hold a share nobody else can combine with. Rebuild a lost node by restoring its backup or
re-enrolling it, not by bringing back an old disk after this.

### A split ceremony (Byzantine cosigner)

Alert `RutliCeremonySplit` / log `SPLIT: this node aborted a ceremony a peer reports COMMITTED`: this
node aborted ceremony `<id>` while a peer committed it with this node's outcome. With crash faults
that is impossible (a node commits only after every yes-vote, and a node that voted yes then never
sees a no-vote), so **a cosigner equivocated**. With three nodes the suspect is one of the two
peers: the one that reported ABORTED to this node (most likely — it told the committed node STAGED),
or the one reporting COMMITTED (if it lies about having committed). Compare both peers' logs, their
records (`keys/.ceremonies/<id>.json`) and `verify-key` before acting. Signing continues where a
quorum shares a sharing; until recovered, every signature needs the node(s) on the committed
sharing.

Recover on the aborted node, daemon stopped:

```
rutli-cosigner --config node.json ceremony recover-commit --ceremony-id <id>
```

It commits the quarantined staged share and records COMMITTED (`"recovered": true`) only if some
peer reports the ceremony COMMITTED with exactly this node's outcome **and** holds that sharing live
(`Peer.KeyEpoch`: the new epoch and PKP digest), no peer reports a yes-vote for another outcome, and
the normal commit rules hold (a refresh replaces exactly the sharing it started from). This is
key-safe: an honest COMMITTED node committed only after confirming every node's yes-vote for that
outcome, so it is a complete sharing of the same group key. A *lying* COMMITTED report could at
worst move this node onto a sharing the other honest node does not hold — availability, as before
— so confirm the committed node is not the suspect first. Then run `verify-key`, and replace the
compromised node (re-enrol it, then refresh).

If the share should not be recovered (the committed node is the suspect, or the key will be rebuilt
anyway), drop it and clear the alert:

```
rutli-cosigner --config node.json ceremony drop-quarantine --ceremony-id <id>
```

### A legacy partial DKG key (from before protocol 2)

A DKG interrupted between nodes on a release before ceremony protocol 2 could leave the key file on
some nodes only; every retry of its id then fails. With protocol 2 this cannot happen any more. To
clear such a key, on **each** holder:

```
rutli-cosigner --config node.json discard-partial-key --key-id <id> --confirm-group-key <hex>
```

It refuses unless: this node's file is a DKG share at epoch 0 with that group key; no node holds the
key at an epoch ≥ 1 or has a ceremony for it staged or committed; every other node answers and
fewer than all hold it; and the key never signed on this node (no nonce markers). A 2-of-3 key held
by two nodes **can sign**: discard it only if Canton never registered it.

## Rolling upgrades

Signing works across versions. A leader of this release sends its sharing in round 1; an older
node ignores it (and does not check epochs), and a node of this release accepts round 1 from an
older leader with a warning while `signing_policy.require_epoch_match` is off (the default in this
release). A stale node refuses round 1 from leaders of either release. **DKG and refresh do not**: a leader refuses a ceremony unless every
node reports ceremony protocol ≥ 2 (`Peer.NodeInfo`), and an upgraded node refuses the protocol-1
RPCs (`DkgPart*`/`RefreshPart*`, which handed round-2 shares to the leader). Upgrade every cosigner
before running a DKG or refresh; pause any refresh CronJob and onboarding DKGs during the roll.

Every key generated or refreshed on a release before ceremony protocol 2 must be treated as
exposed to that ceremony's leader (audit C1). A post-upgrade refresh re-isolates the shares of a
dealt (split-ceremony) key; it cannot repair a DKG key, whose secret the leader could compute.

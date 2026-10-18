# Internal security review, October 2026 (double-sign lens)

Canonical list of findings from the internal review of Rütli run on 2026-10-16 against
v0.4.0-rc.1 (commit 903d318). The review used a third-party audit of cosmos/kms (a CometBFT
remote signer; double-signing/equivocation) as its lens and translated each of that audit's bug
classes into Rütli's threat model: FROST nonce reuse, unauthorized signing with the namespace key,
permanent key loss, cluster-wide signing outage, silent use of a wrong or rolled-back key epoch.
Two independent passes (Claude Opus, OpenAI Codex) were cross-checked against the code; every
finding below was confirmed by reading the code.

## Identifier namespace

IDs in this document carry the prefix **`DS-`**. In CHANGELOG and runbooks they appear as
"audit C1", "audit M1", etc. (same numbering), and Codex's pass used `RUTLI-01..08` (mapped below).

**Not the same namespace:** "review M1", "review M2", "review L2/L7/L8/L9" in CHANGELOG
0.4.0-rc.2 refer to the separate CA-rotation review (trust files, cluster-id pin). They are
unrelated to the `DS-` IDs.

## Findings and status

Status: **fixed in 0.4.0-rc.2** = PR #29 (batches A and B); **batch C** = the batch C PR (fixed on
merge; target 0.4.0 before the external audit). "Residual" = accepted and documented.

| ID | Sev. | Codex alias | Finding | Status |
|---|---|---|---|---|
| DS-C1 | CRITICAL | — | DKG and refresh round-2 packages (secret share evaluations) relayed through the leader in plaintext; the leader can reconstruct the whole key, refresh gives no protection against it; round-1 broadcast unauthenticated. | batch C: direct peer-to-peer round-2 delivery over mTLS, round-1 digest echo, relay RPCs refused, ceremony protocol gating. **Keys DKG'd or refreshed on ≤ 0.4.0-rc.2 are leader-exposed.** |
| DS-C2 | CRITICAL | RUTLI-01, RUTLI-02 | No cosigner-side signing policy: a holder of the driver cert or one compromised cosigner (driving Peer SignRound1/2 on an honest peer) obtains namespace-key signatures over arbitrary digests, bypassing approvals, journal and rate limit (driver-only). | batch C: driver-signed SignedIntent verified by every cosigner in round 1 and round 2; per-node approvals, rate limit, durable sign journal; refresher role; signer ACLs; SPKI pins. Enforced once `require_intent` is on. |
| DS-C3 | CRITICAL (deploy) | — | Backup ServiceAccount with `pods/exec` on every cosigner + one shared `RUTLI_SEAL_SECRET` env = whole key. | fixed in 0.4.0-rc.2: per-node seal bundles, `perNode` topology, exec-free backup sidecar, RBAC removed, CI deploy-policy gate. Removed on the soak 2026-10-16. |
| DS-H1 | HIGH | RUTLI-03 | Refresh not atomic: partial persistence leaves mixed epochs; sign never routes around them; shares carry no epoch. | batch C: two-phase commit with durable votes and resolver; epochs; epoch-checked round 1; t-subset retry. |
| DS-H2 | HIGH | — | Driver trusted one cosigner for the group key and never verified signatures. | fixed in 0.4.0-rc.2: ≥2 agreeing cosigners + pin; every signature verified (strict RFC 8032). |
| DS-M1 | MEDIUM | — | Stale/rolled-back shares undetectable; `restore --force` revives old epochs; old epochs kept in on-volume backups. | batch C: stale-share check, epoch-checked atomic restore with exact break-glass. |
| DS-M2 | MEDIUM | — | Hosted-key delete has no tombstone (anti-entropy resurrects deleted keys); one peer or the driver cert can purge every replica. | batch C: authorized tombstones (signed delete intents verified by every node), grace + undelete, delete role (default: no deletes). |
| DS-M3 | MEDIUM | — | Shared `rutli-cosigner` SAN: mesh server identity not bound to the peer identifier. | fixed in 0.4.0-rc.2: per-peer TLS server names `cosigner<id>`, exact CN→identifier map. |
| DS-M4 | MEDIUM | RUTLI-04 | Sealed files not bound (no AAD) to key id/node/epoch; plaintext accepted under sealing. | batch C: key-file v2 with header as AEAD AAD, plaintext refused. **Closed only once `keyfile.accept_v1=false`.** |
| DS-M5 | MEDIUM | — | Partial DKG / driver timeout permanently wedges a deterministic FROST key id. | batch C: idempotent DKG, `discard-partial-key`. |
| DS-M6 | MEDIUM | — | Driver journal rate limit: future-timestamp poisoning, check/add race, fail-open recovery. | fixed in 0.4.0-rc.2. |
| DS-M7 | LOW-MED | — | Approvers signed an opaque requestId not bound to the displayed digest. | fixed in 0.4.0-rc.2 (`ApproveCli` recomputes). |
| DS-L1 | LOW | RUTLI-05 | Audit log: torn tail blocked startup; no directory fsync; tail truncation undetectable. | fixed in 0.4.0-rc.2 (torn tail, dir fsync, full-chain verify); batch C: `audit-cross-check` against cosigner journals detects truncation. |
| DS-L2 | LOW | RUTLI-08 | Config gaps: duplicate peer ids/endpoints, signer/peer allowlist overlap. | fixed in 0.4.0-rc.2. |
| DS-L3 | LOW | — | `std::sync::Mutex` poisoning could cascade into a node-wide outage. | batch C: poison recovery per lock with metric. |
| DS-L4 | LOW | — | Nonce markers unbounded; no cosigner-side sign limit. | batch C: marker pruning (round 2 refuses sessions older than the TTL), cosigner rate limit. |
| DS-L5 | LOW | — | Decrypt limiter bucket map unbounded. | fixed in 0.4.0-rc.2. |
| DS-L6 | LOW | RUTLI-07 | Two live instances on one share set (RWO, no instance lock). | fixed in 0.4.0-rc.2: `flock` on `data_dir`, ReadWriteOncePod default. |
| DS-L7 | INFO | — | VM/container memory snapshot could duplicate in-RAM nonces. | residual, documented (threat model). |
| DS-X1 | MEDIUM | RUTLI-06 | `SoftKeyStore` swallowed directory-fsync failures. | fixed in 0.4.0-rc.2. |
| DS-X2 | HIGH | — | Driver journal fsynced after a single `FileChannel.write` (short write → torn record of a released signature). Found in review of PR #29. | fixed in 0.4.0-rc.2 (`WriteFully`). |

### Findings from the review of batch C itself

| ID | Sev. | Finding | Status |
|---|---|---|---|
| DS-CR1 | MEDIUM | Cosigner rate limit amortized by reusing one request id across different digests. | batch C: charge id binds the intent digest. |
| DS-CR2 | MEDIUM | Sign journal self-corrupted after an I/O error (torn line / forked chain). | batch C: rollback + reopen. |
| DS-CR3 | MEDIUM | Any peer could flood durable no-vote records for unknown ceremony ids. | batch C: per-peer and total caps. |
| DS-CR4 | MED/LOW | A Byzantine cosigner can split a 2PC ceremony (n=3, f=1). | batch C: detection, quarantine, `ceremony recover-commit`. **Residual:** availability, not key compromise. |
| DS-CR5 | LOW | Startup repair could delete a staged share whose vote it could not read. | batch C. |
| DS-CR6 | LOW | Driver trusted one cosigner's cluster id for intents. | batch C: majority agreement, re-learn, off switch. |
| DS-CR7 | LOW | Delete approvals not domain-separated from sign approvals. | batch C. |
| DS-CR8 | LOW | Propagated tombstones ignored expiry (old delete intent replay). | batch C: grant-time rule, `.cleared` backed up. |
| DS-CR9 | INFO | Recipient error text forwarded to the ceremony leader. | batch C. |
| DS-CR10 | LOW | `audit-cross-check` keyed on the bare request id. | batch C. |

### Residuals (accepted, documented in docs/security/threat-model.md)
- ~~A compromised cosigner can fence a key with kind "refresh" and stall its signing (≤ 15 min, renewable).~~ Corrected and fixed: on 0.4.0-rc.3 the stall had no time limit. A fence never followed by part 1 never expired, and a re-fence under the same id restarted its timer, so signing on that key stayed down on the fenced nodes until a pod restart. Fixed in 0.4.0-rc.4 (L1): a DKG/refresh guard no longer blocks signing, a fence alone is orphaned after 60 s, and re-fencing never extends a guard. Still open until ceremony intents (step 2): a compromised cosigner can lead ceremonies no client asked for, which lets it split the key (DS-CR4) at will and hold off other ceremonies.
- Byzantine ceremony split for n=3 (DS-CR4): availability only.
- One Kubernetes cluster and cluster-admin for all cosigners is a single trust domain (decision P10).
- No HPKE layer on round-2 delivery: no TLS-terminating service mesh may sit between cosigners (decision P3).
- A stolen driver key can still sign non-gated keys within its ACL and rate limits (journaled on every node; detectable by `audit-cross-check`; revocable by SPKI pin).

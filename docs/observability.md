# Observability

Each cosigner can serve a Prometheus `/metrics` endpoint. It is opt-in, plaintext HTTP, and
carries **operation counts, latencies, and in-flight gauges only** — never key material, digests,
or session ids. Keep the port inside your trusted network anyway (the deploy bundles already do).

## Enabling

Add to the cosigner's JSON config:

```json
{ "metrics_listen": "0.0.0.0:9200" }
```

Absent → no endpoint. The TLS compose (`deploy/frost/docker-compose.tls.yml`, host ports
9201–9203) and the k8s bundle (container port `metrics`/9200, `prometheus.io/*` scrape
annotations, NetworkPolicy ingress for pods labelled `rutli.io/scraper: "true"`) ship with it on.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `rutli_sign_requests_total` | counter | `result`=ok\|error | Leader-side `Signer.Sign` outcomes |
| `rutli_sign_duration_seconds` | histogram | `result` | Leader-side `Signer.Sign` latency. Buckets (s): 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.25, 0.5, 1, 2.5, 5, 10 — see [Sign latency histogram](#sign-latency-histogram) |
| `rutli_ceremony_requests_total` | counter | `kind`=dkg\|refresh, `result` | Key-ceremony outcomes (rare; any `error` needs investigation before retrying) |
| `rutli_ceremonies_staged` | gauge | — | Two-phase DKG/refresh ceremonies staged on this node and not yet resolved (the resolver is waiting on a peer). Non-zero for up to a minute during a ceremony; must be 0 before the next ceremony or rollout step |
| `rutli_ceremonies_split` | gauge | — | Ceremonies this node aborted while a peer reports them COMMITTED with this node's outcome, staged share still quarantined (audit F3). Must be 0; > 0 means a cosigner equivocated — `docs/ceremonies.md`, "A split ceremony" |
| `rutli_ceremony_equivocations_total` | counter | — | Ceremonies a peer reported COMMITTED while another reported ABORTED (impossible with crash faults) |
| `rutli_ceremony_unknown_refused_total` | counter | — | No-votes for unknown ceremony ids or orphaned sessions this node refused to record because a cap was reached (audit F2) — a peer asking about many made-up ceremonies |
| `rutli_ceremony_unknown_no_votes` | gauge | — | No-votes held for ceremony ids peers asked about that this node never knew (capped, garbage-collected after 30 days) |
| `rutli_epoch_mismatch_total` | counter | — | Sign round-1 refusals because the leader signs with another sharing (epoch, PKP digest) of the key than this node committed (audit H1/M1): two nodes hold different epochs of one key |
| `rutli_stale_share` | gauge | `key` | `1` while this node's share of `key` is older than a committed sharing a peer holds (typically a restore from an old backup); the node refuses to sign or lead for that key. Else `0` |
| `rutli_nonce_markers` | gauge | — | Burned-session nonce markers on this node after the last prune pass (audit L4); each costs an inode on the key volume, bounded by the sign rate over the retention window |
| `rutli_sign_round1_skips_total` | counter | — | Peers skipped in sign round 1 — the quorum-margin canary: skips mean you are signing with less headroom than you deployed |
| `rutli_sign_aborts_total` | counter | — | Given-up signatures (leader aborted the in-flight session on the quorum) |
| `rutli_pending_sign_sessions` | gauge | — | In-flight round-1 sessions held on this node; hovers near 0 in a healthy cluster |
| `rutli_keystore_unreadable` | gauge | — | `1` while this node's key store (`data_dir/keys`) fails its readiness probe — cannot be listed or written, or not one key file in it opens, or the probe has hung for 6s (a stalled mount) — else `0`. Re-probed every 15s by a watchdog thread and on `Signer.Health` (cached 5s, one probe at a time); primed to `0` |
| `rutli_hosted_keys` | gauge | — | Cluster-hosted keys held by this node |
| `rutli_decrypt_rate_limited_total` | counter | — | Hosted-key decryptions refused by the per-key rate limit (enforced by each node on its own, so read it per instance). Never moves in normal operation: either a node outgrew its ceiling, or someone with the driver certificate is bulk-decrypting |
| `rutli_unreadable_key_files_total` | counter | — | Key files present on disk that could not be unsealed (wrong seal secret, partial restore, corruption) and were therefore skipped from the hosted-key inventory, or could not even be opened (ownership/permissions) by the key-store probe while the rest of the store could |
| `rutli_hosted_key_ops_total` | counter | `op`=generate\|decrypt\|ecdh_derive\|symmetric_encrypt\|symmetric_decrypt\|delete, `result`=ok\|error | Signer-side hosted-key operation outcomes |
| `rutli_anti_entropy_repairs_total` | counter | — | Hosted keys a sweep pulled to this node or pushed to a peer that lacked them |
| `rutli_key_replicas` | gauge | — | Fewest cosigners holding any one hosted key, as of the last anti-entropy sweep (`NaN` until a sweep sees a hosted key, so comparisons never fire on an idle cluster). Below the cluster size means a write has not healed yet |
| `rutli_anti_entropy_conflicts_total` | counter | — | Hosted keys found with *different* material on this node and a peer under the same key id — an invariant violation, never auto-reconciled |
| `rutli_sign_intent_absent_total` | counter | — | Signatures this node took part in without a client-signed intent (accepted only while `signing_policy.require_intent` is off). Must stop growing once the driver signs intents; never moves on an enforcing cluster |
| `rutli_sign_policy_refusals_total` | counter | `reason`=missing\|malformed\|certificate\|signer\|pin\|signature\|cluster\|purpose\|key\|expiry\|acl\|approval\|role\|… | Signatures this node refused by its signing policy (audit C2). `missing`/`approval`/`expiry` are rollout and NTP issues; `signer`/`certificate`/`signature`/`pin`/`cluster`/`key` mean something presented an intent this node does not accept |
| `rutli_sign_rate_limited_total` | counter | — | Signatures refused by the per-key sign rate limit (per node; charged once per signed intent — its request id and digest — or per session without one) |
| `rutli_signer_acl_absent_total` | counter | — | Key operations by a Signer client CN with no `signer_acl` entry, allowed while `signer_acl_required` is off |
| `rutli_sign_journal_entries_total` | counter | — | Shares this node journaled before releasing them |
| `rutli_sign_journal_errors_total` | counter | — | Journal appends or opens that failed; the node refuses to release a share it cannot journal |
| `rutli_delete_intent_refusals_total` | counter | `reason`=disabled\|role\|missing\|signer\|certificate\|signature\|cluster\|purpose\|key\|malformed\|expiry\|acl\|approval\|stale\|rollback\|policy-changed | Hosted-key deletes and peer tombstones this node refused (audit M2) — on `DeleteKey`, a peer's `PurgeKey`, and a tombstone a peer lists in anti-entropy |
| `rutli_hosted_tombstones_written_total` | counter | `how`=converted\|recorded | Tombstones this node wrote: a live copy deleted (directly or from a peer's tombstone), or a tombstone recorded for a key it did not hold |
| `rutli_hosted_tombstones` | gauge | `retained`=true\|false | Deleted hosted keys on this node, split by whether the tombstone still retains the material (grace period) — refreshed by the anti-entropy sweep |
| `rutli_keyfiles` | gauge | `format`=v1\|v2\|plaintext, `dek`=current\|previous\|unknown\|none | This node's key files at start-up (audit M4): a v2 migration watches `format="v1"` reach 0, a DEK rotation watches `dek="previous"` reach 0 before the previous DEK leaves the seal bundle; `dek="unknown"` files do not open on this node |

Leader-side metrics (`sign_*`, `ceremony_*`) appear on whichever node served the driver's request —
with driver failover that can be any of them, so always aggregate across instances (`sum(...)`).

Hosted-key metrics appear on every node, because hosted keys are **replicated whole keys, not FROST
shares**: each node holds the same material, serves its own decrypts, and counts them locally. (The
FROST share itself is never listed, replicated or counted per-key — two nodes holding one share
would silently break the threshold.) No hosted-key id is ever used as a label (only
`rutli_stale_share` carries a key id: a FROST key, a handful per cluster); the label sets above are
exhaustive. Three collection details matter when writing rules:

- `rutli_hosted_keys` is refreshed at the end of this node's own anti-entropy sweep and whenever a
  **peer** enumerates its keys, so after a `GenerateKey` it can trail the truth by up to one
  `anti_entropy_interval_secs` (default 300). Compare it across instances over long windows, not
  between scrapes.
- `rutli_anti_entropy_repairs_total` counts **sweep** repairs only. On-demand read-repair — the
  pull that happens when a request lands on a lagging replica — is logged but not counted here.
- `rutli_unreadable_key_files_total` counts **listings and probes that hit a bad file**, not
  distinct files: the inventory is walked on every sweep and on every peer `ListKeys`, and the
  key-store probe opens every key file every 15s, so one damaged file makes the counter climb
  steadily for as long as it sits there. Alert on a sustained increase rather
  than on a single bump, and read the key id out of the logs — it is never a label.

`rutli_hosted_keys`, `rutli_unreadable_key_files_total` and both `anti_entropy_*` counters are
primed to zero at startup, so they exist even where hosted keys are disabled; `rutli_key_replicas`
is primed to `NaN` for the same reason (zero would page an idle cluster instantly).
`rutli_hosted_key_ops_total` has no fixed label set and its series appear on first use: alert on its
rate, never on its absence.

The signing-policy, delete and tombstone series are not primed: they first appear when they first
count, so their rules (`deploy/monitoring/prometheus-rules.yml`: `RutliSignPolicyRefusals`,
`RutliSignIntentAbsent`, `RutliSignRateLimited`, `RutliSignerAclAbsent`, `RutliSignJournalErrors`,
`RutliDeleteIntentRefused`, `RutliHostedKeyDeleted`, `RutliCeremonyIntentRefused`,
`RutliCeremonyIntentAbsent`) alert on increases. `rutli_keyfiles` is set
once per start (`RutliKeyFilesUnopenable`, `RutliKeyFileMigrationPending`).

Published latency snapshots and how to reproduce them: [`performance.md`](performance.md).

### Sign latency histogram

`rutli_sign_duration_seconds` is a true Prometheus histogram: `_bucket{le="…"}` series plus
`_sum` and `_count`, so `histogram_quantile()` works over any window and aggregates across
instances. The bounds bracket a 50–150 ms cross-region FROST round trip at ~25 ms resolution,
and include the soak gate's 1 s threshold as an exact bound. They extend to 10 s, past the 5 s
`RutliSignLatencyHigh` threshold. That last bound matters: when a quantile lands in the `+Inf`
bucket, `histogram_quantile()` returns the highest finite bound. With 5 s as the top bound,
a `> 5` rule could never fire.

**Cosigners up to and including 0.3.1 export a *summary* instead** (`{quantile="…"}` series, no
`_bucket`). The exporter does that for any histogram without configured buckets, so on those
versions the latency alert and the dashboard's latency panel have no data. Upgrade every
cosigner. Mid-rollout, `histogram_quantile()` covers only the upgraded leaders; the soak gate
(`deploy/soak/soak-check.sh`) says how many summary-only leaders it left out, and falls back to
the 24 h mean from `_sum`/`_count` when no leader exports buckets yet. For an ad-hoc mean on any
version:

```promql
sum(rate(rutli_sign_duration_seconds_sum{result="ok"}[1h]))
  / sum(rate(rutli_sign_duration_seconds_count{result="ok"}[1h]))
```

## Prometheus + Grafana

- Scrape config: any job name works, but the shipped alert rules assume `job: rutli-cosigner`.
- Alert rules: [`deploy/monitoring/prometheus-rules.yml`](../deploy/monitoring/prometheus-rules.yml)
  — cosigner down (critical: at 2-of-3 one loss means zero margin), key store unreadable
  (critical: the same loss while `up` stays 1), sign errors, p99 latency, round-1 skips,
  pending-session growth, ceremony failure (critical), repeated aborts, hosted-key op errors, a
  hosted key under-replicated (below the cluster size) or critically under-replicated (a single
  copy — critical), hosted-key counts diverging across the job, unreadable key files, hosted-key
  conflict (critical). CI runs `promtool check rules` (pinned `prom/prometheus` image) on this file
  and on the rendered PrometheusRule, and fails if the render is stale:
  `scripts/ci-prometheus-rules.sh` (set `PROMTOOL=` to use a local binary instead of docker).
- Dashboard: import
  [`deploy/monitoring/grafana-dashboard.json`](../deploy/monitoring/grafana-dashboard.json)
  (uid `rutli-cosigner`) — cosigners up, *Key store readiness* (a state timeline of
  `rutli_keystore_unreadable` per instance: green readable, red unreadable, grey not scraped),
  round-1 skips as `increase(…[5m])` per leader (the counter climbs on the healthy nodes, so the
  instance that stays flat while a readiness row is red is the one being skipped around),
  throughput, p50/p95/p99 latency (`histogram_quantile` over the buckets — empty for cosigners
  up to 0.3.1, see above), pending sessions, aborts, ceremonies. Three rows for the audit
  remediation series: *Signing policy & sign journal* (policy refusals by reason, signs without an
  intent or `signer_acl` entry, rate-limited shares, journal errors), *Ceremonies & share epochs*
  (staged and split ceremonies, equivocations, a per-(node, key) share-freshness timeline from
  `rutli_stale_share`, epoch mismatches), and *Key store* (`rutli_keyfiles` by format and DEK,
  `rutli_nonce_markers`). Each panel's description names the alert that fires on it. CI parses
  every dashboard query with promtool (`scripts/ci-prometheus-rules.sh`).

## What to watch (2-of-3 cluster)

1. **`up` on every cosigner** — one down cosigner still signs, but with zero margin. Treat as an
   incident, not a warning.
2. **`rutli_sign_round1_skips_total` increasing** — same signal one layer up: a peer is
   unreachable or refusing (e.g. mid-ceremony) while signing continues.
3. **Any `rutli_ceremony_requests_total{result="error"}`** — a failed DKG/refresh never corrupts
   shares (it fails closed), but do not blindly retry: read the logs of all nodes first.
4. **`rutli_pending_sign_sessions` climbing** — sessions are being opened faster than
   completed/aborted; the TTL sweep will cap it, but sustained growth means a flapping peer or a
   stuck driver.
5. **`rutli_hosted_key_ops_total{op=~"decrypt|ecdh_derive",result="error"}` sustained** — Canton has no
   software fallback for a KMS decrypt: a persistent failure surfaces as `KmsDecryptError` and
   disconnects the participant from the synchronizer. Read the error before assuming replication:
   an error on a node that simply lacks the key is a lag/repair problem, an error on a node that
   holds it is a sealing or backend problem. `generate` and `delete` errors are less urgent but
   block key rotation, which is the whole recoverability story for hosted keys.
   **Blind spot for ECIES:** the cosigner only does the ECDH, so `op="ecdh_derive",result="ok"`
   counts every request that produced a shared secret — including forged or corrupted
   ciphertexts, whose MAC check then fails in the driver. The driver has no metrics endpoint;
   those failures show up in its log instead: a WARN `ECIES decryption failed after a successful
   EcdhDerive for <key>` and, with `audit-logging = true` (or `audit-log-path`), the operation's
   audit entry `AUDIT decryptAsymmetric … algo=EciesHkdfHmacSha256Aes128Cbc ecies-failure=after-ecdh
   … outcome=failed` (`ecies-failure=shape` when the blob was refused before any cluster call).
   Alert on the log, e.g. in Loki:
   `sum(count_over_time({app="canton-participant"} |= "AUDIT decryptAsymmetric" |= "outcome=failed" [10m])) > 0`.
   A trickle is someone sending malformed ciphertexts; anything sustained is a page, as for (5).
   Audit entries with `ec-failover=` mean a cosigner answered "not found"/UNIMPLEMENTED for an EC
   key and the driver went to the next one: a cosigner on an old release, or one missing a
   replica. Either way, find it — it is carrying no ECIES traffic. `reason=ECIES_AFTER_ECDH` means
   that cosigner's shared secret did not open the ciphertext. On a decrypt that then **succeeded**
   via another node, that cosigner holds wrong EC material under the key id (stale or corrupt
   replica) — investigate it as for `rutli_anti_entropy_conflicts_total`. On a decrypt that failed
   anyway (`ecies-failure=after-ecdh`), every node's secret was refused: the ciphertext is the
   suspect, and it cost one `EcdhDerive` per cosigner.
6. **`rutli_key_replicas` below the cluster size** (or `rutli_hosted_keys` differing across
   instances, the same signal seen sideways) — a key exists on fewer nodes than the cluster is
   configured for. Writes commit at `write_quorum` (default 2 of 3) and roll back below it, so a
   node that was down during a `GenerateKey` legitimately lags until anti-entropy heals it;
   `rutli_anti_entropy_repairs_total` should tick when it does. A shortfall that persists past
   several sweep intervals means healing is failing, and the cluster is running with less
   redundancy than it reports: two replicas survive one node loss, one survives none. The gauge is
   a cluster-wide minimum with no key id — take that from the sweep logs.
7. **Any `rutli_anti_entropy_conflicts_total` increase** — two nodes hold *different* material
   under the same key id. Hosted keys are create-once-immutable, so this is not lag and not a
   merge conflict; it is an invariant violation (a reused key id, a restore from a foreign
   cluster's backup, or storage corruption). The sweep deliberately refuses to reconcile it —
   picking a side automatically could destroy the only copy that can decrypt already-recorded
   traffic. Page, freeze rotation for that key, and resolve it by hand.
8. **`rutli_unreadable_key_files_total` non-zero** — a key file is present on disk but cannot be
   unsealed, so it is logged at error level, counted, and *skipped* from the hosted-key inventory
   (or cannot be opened at all — wrong ownership/permissions on that one file — which the
   key-store probe counts and logs at warn level; fix the file's ownership).
   Skipping is deliberate: failing the whole listing would stop anti-entropy for every healthy key
   too, turning one damaged file into a cluster-wide halt of self-healing. The cost is that the
   damaged key is invisible to replication — it is neither pushed to peers nor pulled back from
   them, and (6) stays even across the cluster while that key has fewer copies than you think.
   Usual causes: a seal master secret rotated without re-sealing the existing files, a partial
   restore or one taken from a foreign cluster, disk corruption. None of these self-heal; the file
   will sit there until an operator resolves it. Take the key id from the log line, then either
   restore the seal secret that file was written under, restore a good copy of the file
   (`rutli-cosigner restore`, or `import-key` from an export — see
   [`disaster-recovery.md`](disaster-recovery.md) §3d), or, once you have confirmed a readable copy
   on another cosigner, remove the file and let anti-entropy replace it.
9. **`rutli_keystore_unreadable` = 1** (alert `RutliKeystoreUnreadable`, critical) — the node can
   no longer list or write its key store, or open any key file in it: the *volume* failed, not one
   file (that is (8)). The node answers `UNAVAILABLE` to Sign, Dkg, Refresh and every key
   operation (only in the first ~15s, before its first failed probe, can an uncached share still
   surface as `INTERNAL`), reports `Signer.Health` `ok=false`
   (`NOT_SERVING: keystore … unreadable: …`), drops to `READY 0/1` (`rutli-cosigner health` is the
   readiness probe), and refuses to join other leaders' quorums and ceremonies — expect (2) to
   climb. The driver fails over away from it; signing continues on the other two, with zero margin
   and no ceremonies possible. The 2026-10-07 DevNet outage had exactly this shape: a backup
   job remounted the pod's RWO volume and `/data/keys` returned `Permission denied`. Check
   `kubectl exec <pod> -- ls -la /data/keys`, the mount flags (`mount | grep /data`) and whatever
   else touched the PVC; the cosigner logs the path and OS error once, at error level, when the
   probe first fails, and once at info when it recovers. Fix the volume rather than restarting the
   pod — a restart does not repair it and throws away the evidence. The gauge clears by itself
   within ~15s of the store becoming readable again. A full data disk does *not* trip it (a sign
   only needs to create an empty nonce marker) — watch volume usage separately.

   **The other shape: `NOT_SERVING: keystore … unresponsive`** — the probe did not fail, it never
   returned: a dead NFS/CSI mount, or a volume frozen by a snapshot hook (`fsfreeze`). A probe that
   errors (EACCES, EROFS, EIO, ESTALE…) trips the gauge at once; a hung one only after 6s (two
   probe timeouts, logged at warn after the first), so a short freeze that hits all three PVCs at
   once does not stop signing cluster-wide. The node stays responsive throughout — Health answers
   within 3s, the gRPC server and `/metrics` keep serving — because every key-store access runs
   off the async workers and the probe loop is its own thread; threads stuck on the dead mount
   are parked, not lost work. Check `cat /proc/mounts` and `dmesg` on the node for
   `nfs: server … not responding` / CSI errors, and whatever runs snapshots on the volume. It
   clears by itself when the stuck probe returns.

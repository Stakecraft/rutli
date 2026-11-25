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
| `rutli_ceremony_resolutions_total` | counter | `result`=committed\|aborted\|recovered | Two-phase ceremonies this node resolved |
| `rutli_ceremony_equivocations_total` | counter | — | Ceremonies a peer reported COMMITTED while another reported ABORTED (impossible with crash faults) |
| `rutli_ceremony_unknown_refused_total` | counter | — | No-votes for unknown ceremony ids or orphaned sessions this node refused to record because a cap was reached (audit F2) — a peer asking about many made-up ceremonies |
| `rutli_ceremony_unknown_no_votes` | gauge | — | No-votes held for ceremony ids peers asked about that this node never knew (capped, garbage-collected after 30 days) |
| `rutli_epoch_mismatch_total` | counter | — | Sign round-1 refusals because the leader signs with another sharing (epoch, PKP digest) of the key than this node committed (audit H1/M1): two nodes hold different epochs of one key |
| `rutli_epoch_check_skipped_total` | counter | — | Sign round-1 requests from a leader that sent no sharing (a release before epochs), so the epoch check was skipped. Expected only during a rolling upgrade |
| `rutli_key_epoch_proven` | gauge | `key` | `1` while the live epoch of the FROST key has a `keyfile prove` marker for the live sharing (an operator's statement that `verify-key --sign-test` passed, `docs/ceremonies.md#proving-an-epoch`), else `0`. Only keys with a v2 key file |
| `rutli_key_epoch_age_seconds` | gauge | `key` | Seconds since the live key file of `key` was written: since the epoch was installed, or the file was last re-sealed |
| `rutli_stale_share` | gauge | `key` | `1` while this node's share of `key` is older than a committed sharing a peer holds (typically a restore from an old backup); the node refuses to sign or lead for that key. One cosigner's claim alone can set it while no peer holding this node's sharing answers; the log's stale reason then says "unconfirmed" and the mark clears on the next pass that reaches such a peer, at most 30 s later. Else `0` |
| `rutli_nonce_markers` | gauge | — | Burned-session nonce markers on this node after the last prune pass (audit L4); each costs an inode on the key volume, bounded by the sign rate over the retention window |
| `rutli_nonce_markers_pruned_total` | counter | — | Burned-session nonce markers removed past their retention |
| `rutli_sign_round1_skips_total` | counter | — | Peers skipped in sign round 1 — the quorum-margin canary: skips mean you are signing with less headroom than you deployed |
| `rutli_sign_round2_unknown_session_total` | counter | — | Sign round 2 requests refused as an unknown signing session: the node holds no round-1 nonces for it, because it restarted or committed a ceremony between the two rounds, or the session outlived its 5-minute TTL. The peer answers `ABORTED` and the leader signs with the others. One or two at a restart or a refresh are expected; a steady rate is not (`RutliSignUnknownSessions`: more than 3 in 15 minutes). The same with a signing policy: a session the node holds no nonces for is counted here, not as a policy refusal |
| `rutli_sign_session_owner_refusals_total` | counter | `call`=round2\|abort | Sign round 2s and aborts this node refused because another caller opened the session (since 0.5.0 a session belongs to the peer whose certificate CN opened it, or to this node's own leader). No other peer can abort or advance the session. A correct cosigner never does this: any increase names a peer to investigate (`RutliSignSessionOwnerRefused`); the log line names the caller and the owner |
| `rutli_sign_sessions_refused_total` | counter | `cap`=key\|opener\|request | Sign round 1s refused because too many sessions wait for round 2: `opener` = one opener holds 256 for the key, `request` = one opener holds 20 for one signing request, `key` = all openers together hold 1024. Answered `UNAVAILABLE`. Only `key` stops other leaders, and it needs four openers at their caps. An honest leader holds about as many as it has signs in flight (normally a few, up to about 128 on a large participant host) and aborts the sessions of calls the driver gave up on. A leader that hears this answer tries other cosigners and does not exclude this one. Without TLS no peer is identified: all remote leaders share one opener's room, so one filler takes it all (`RutliSignSessionCapReached`); the log line names the opener |
| `rutli_sign_aborts_total` | counter | — | Given-up signatures (leader aborted the in-flight session on the quorum) |
| `rutli_sign_retries_total` | counter | — | Sign attempts beyond the first within one `Signer.Sign`: a t-subset failed and the leader retried with another |
| `rutli_invalid_signature_shares_total` | counter | — | Signature shares that failed verification at aggregation (attributed to a cosigner and routed around). Any increase means a cosigner returned a bad share (`RutliInvalidSignatureShare`) |
| `rutli_pending_sign_sessions` | gauge | — | In-flight round-1 sessions held on this node; hovers near 0 in a healthy cluster |
| `rutli_keystore_unreadable` | gauge | — | `1` while this node's key store (`data_dir/keys`) fails its readiness probe — cannot be listed or written, or not one key file in it opens, or the probe has hung for 6s (a stalled mount) — else `0`. Re-probed every 15s by a watchdog thread and on `Signer.Health` (cached 5s, one probe at a time); primed to `0` |
| `rutli_hosted_keys` | gauge | — | Cluster-hosted keys held by this node |
| `rutli_decrypt_rate_limited_total` | counter | — | Hosted-key decryptions refused by the per-key rate limit (enforced by each node on its own, so read it per instance). Never moves in normal operation: either a node outgrew its ceiling, or someone with the driver certificate is bulk-decrypting |
| `rutli_ceremony_sign_test_rate_limited_total` | counter | — | Split-ceremony `CeremonySignTest` calls refused by the per-key rate limit. A `verify-key --sign-test` run never trips it |
| `rutli_unreadable_key_files_total` | counter | — | Key files present on disk that could not be unsealed (wrong seal secret, partial restore, corruption) and were therefore skipped from the hosted-key inventory, or could not even be opened (ownership/permissions) by the key-store probe while the rest of the store could |
| `rutli_hosted_key_ops_total` | counter | `op`=generate\|decrypt\|ecdh_derive\|symmetric_encrypt\|symmetric_decrypt\|delete, `result`=ok\|error | Signer-side hosted-key operation outcomes |
| `rutli_anti_entropy_repairs_total` | counter | — | Hosted keys a sweep pulled to this node, each confirmed by two peers (since 0.5.0 the sweep pushes nothing; up to 0.4.0 it also counted pushes) |
| `rutli_key_replicas` | gauge | — | Fewest cosigners holding any one hosted key, as of the last anti-entropy sweep (`NaN` until a sweep sees a hosted key, so comparisons never fire on an idle cluster). Below the cluster size means a write has not healed yet |
| `rutli_anti_entropy_conflicts_total` | counter | — | *Different* material seen under one hosted key id: this node and a peer (the sweep), peers this node would pull from, a push refused over another copy, or a generation this node led aborted — an invariant violation, never auto-reconciled |
| `rutli_hosted_replication_refusals_total` | counter | `reason`=unfenced\|conflict\|disagreement\|unconfirmed\|invalid\|timestamp\|generate-conflict\|unverifiable\|throttled\|spec\|intent\|mixed-version | Hosted key material this node refused to store, or a generation it aborted or refused (0.5.0; reasons in `docs/hosted-keys.md`, section 4, "Pushes a node refuses"). `unconfirmed` is normal while a node is down; `mixed-version` while the cluster is being upgraded from 0.4.0 |
| `rutli_anti_entropy_pull_failures_total` | counter | — | Missing hosted keys a sweep tried to pull and did not (unconfirmed, conflicting, or an error); the key id is in the debug log, refusals also by reason |
| `rutli_hosted_rollback_incomplete_total` | counter | — | Nodes the rollback of an aborted hosted-key generation did not reach; each may keep a copy nobody was given (0.5.0) |
| `rutli_hosted_keys_future_timestamp` | gauge | — | Hosted keys held here whose creation or undelete time lies in the future beyond the clock skew allowance (they refuse every delete until then); set at startup and by every sweep |
| `rutli_sign_intent_absent_total` | counter | — | Signatures this node took part in without a client-signed intent (accepted only where `signing_policy.require_intent` is off: set to false, or a node without TLS; on by default with TLS). Must stop growing once the driver signs intents; never moves on an enforcing cluster |
| `rutli_ceremony_intent_absent_total` | counter | — | DKG/refresh fences and part 1s, and hosted-key generation fences (0.5.0), this node accepted without a client-signed intent (accepted only while `signing_policy.require_ceremony_intent` is off) |
| `rutli_ceremony_intent_refusals_total` | counter | `reason`=missing\|malformed\|certificate\|signer\|pin\|signature\|cluster\|purpose\|key\|spec\|leader\|expiry\|acl\|ceremony-id | DKG/refresh ceremony intents and hosted-key generate intents (0.5.0) this node refused: at the fence or part 1 of a ceremony a peer leads, at the fence of a generation, or as leader on `Signer.Dkg`/`Signer.Refresh`/`Signer.GenerateKey`. A refusal on the peer path means a leader asked for a ceremony or a key no authorized client requested; `leader` means a cosigner presented a generate intent the client signed for another cosigner |
| `rutli_refresh_interval_refusals_total` | counter | — | Refreshes this node refused because it took part in a refresh of the same key less than `signing_policy.refresh_min_interval_secs` ago (as leader before contacting a peer, at a fence, or at part 1). Outside a documented incident nobody refreshes that often: check who holds the refresher (and, while `signer_may_refresh` is on, the driver) certificate (`RutliRefreshRefused`; docs/ceremonies.md, "Refresh interval") |
| `rutli_refresh_interval_waived_total` | counter | — | Refreshes this node let through the interval because of `signing_policy.refresh_interval_waived_at`, the operator's incident path: one per key after the waiver time |
| `rutli_refreshes_6d` | gauge | `key` | Refreshes of the FROST key this node committed in the last 6 days (by commit time), read from its ceremony records (survives a restart). The shipped schedule is weekly and the window a day shorter, so scheduler jitter never puts two weekly runs in it: above 1 means a refresh outside the schedule (`RutliRefreshOffSchedule`) |
| `rutli_sign_policy_refusals_total` | counter | `reason`=missing\|malformed\|certificate\|signer\|pin\|signature\|cluster\|purpose\|key\|expiry\|acl\|approval\|role\|… | Signatures this node refused by its signing policy (audit C2). `missing`/`approval`/`expiry` are rollout and NTP issues; `signer`/`certificate`/`signature`/`pin`/`cluster`/`key` mean something presented an intent this node does not accept |
| `rutli_sign_rate_limited_total` | counter | — | Signatures refused by the per-key sign rate limit (per node; charged once per signed intent — its request id and digest — or per session without one) |
| `rutli_signer_acl_absent_total` | counter | — | Key operations by a Signer client CN with no `signer_acl` entry, allowed while `signer_acl_required` is off |
| `rutli_sign_journal_entries_total` | counter | — | Shares this node journaled before releasing them |
| `rutli_sign_journal_errors_total` | counter | — | Journal appends or opens that failed; the node refuses to release a share it cannot journal |
| `rutli_sign_journal_over_cap_total` | counter | — | Journal retention runs that left a key above `signing_policy.journal_max_mib_per_key`, because its oldest segment holds entries of the last 24 h (the size cap keeps them; the rate limit is rebuilt from them after a restart). Steady growth means the cap is too small for the key's daily volume |
| `rutli_sign_journal_chain_restarts_total` | counter | — | Journal segments found on open that start the hash chain afresh although they are not the key's first segment. The journal still opens; check that key's journal with `rutli-cosigner audit-cross-check` |
| `rutli_delete_intent_refusals_total` | counter | `reason`=disabled\|role\|missing\|signer\|certificate\|signature\|cluster\|purpose\|key\|malformed\|expiry\|acl\|approval\|stale\|rollback\|policy-changed | Hosted-key deletes and peer tombstones this node refused (audit M2) — on `DeleteKey`, a peer's `PurgeKey`, and a tombstone a peer lists in anti-entropy |
| `rutli_hosted_tombstones_written_total` | counter | `how`=converted\|recorded | Tombstones this node wrote: a live copy deleted (directly or from a peer's tombstone), or a tombstone recorded for a key it did not hold |
| `rutli_hosted_tombstones` | gauge | `retained`=true\|false | Deleted hosted keys on this node, split by whether the tombstone still retains the material (grace period) — refreshed by the anti-entropy sweep |
| `rutli_keyfiles` | gauge | `format`=v1\|v2\|plaintext, `dek`=current\|previous\|unknown\|none | This node's key files at start-up (audit M4): a v2 migration watches `format="v1"` reach 0, a DEK rotation watches `dek="previous"` reach 0 before the previous DEK leaves the seal bundle; `dek="unknown"` files do not open on this node |
| `rutli_fd_limit` | gauge | — | Soft open-file limit after the start-up raise to the hard limit |
| `rutli_grpc_connections` | gauge | — | Open gRPC connections, TLS handshake done or under way |
| `rutli_grpc_connection_limit` | gauge | — | Most gRPC connections served at once (soft open-file limit less 256, or half of it under a limit below 512, at most 4096); past it new connections wait in the listen backlog (`RutliGrpcConnectionsNearLimit`) |
| `rutli_grpc_accept_errors_total` | counter | — | Failed accepts that needed a backoff, usually the process out of file descriptors; the loop retries (`RutliGrpcAcceptErrors`) |
| `rutli_grpc_handshake_timeouts_total` | counter | — | Connections cut for not finishing the TLS handshake within 5 s of accept (without TLS: for sending nothing). Clients that open TCP and then send nothing count here; a probe that connects and closes does not |
| `rutli_lock_poison_recoveries_total` | counter | `lock` | Locks recovered after a panicking request poisoned them (audit L3). The node kept serving; the panic is a bug (`RutliLockPoisonRecovered`) |
| `rutli_peer_call_duration_seconds` | histogram | `call`=sign_round1\|sign_round2\|abort\|control\|local_share | How long this node's peer calls took, at the caller, whatever their outcome (a call past its deadline records the deadline). `local_share` is this leader's own round 2. Buckets (s): 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.33, 0.5, 0.67, 1, 1.67, 2, 3, 5, 10 — 0.33, 0.67 and 1.67 are a third of the abort, round-1 and round-2 deadlines, so "p99.9 below that edge" reads as a 3× margin (`docs/architecture.md`, "Peer liveness") |
| `rutli_sign_round1_duration_seconds` | histogram | `result` | One sign round 1 on this node as a member (for a remote leader or its own): the key-store gate, caps, epoch check, intent verification and commitments. Not the wait for a blocking-pool thread before it. Buckets (s): 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.67, 1, 1.67, 2.5, 5, 10 |
| `rutli_sign_round2_duration_seconds` | histogram | `result` | One sign round 2 on this node as a member: policy and binding checks, journal append, nonce marker, share. Buckets as round 1 |
| `rutli_sign_journal_append_duration_seconds` | histogram | `result` | One sign journal append, the wait for the key's journal lock included; `error` is a rate-limit refusal or a failed append. Buckets (s): 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 |
| `rutli_sign_journal_fsync_duration_seconds` | histogram | — | The `sync_data` of one journal append alone. Buckets as the journal append |
| `rutli_nonce_marker_duration_seconds` | histogram | `result` | One nonce marker write (create, fsync of the file and of the directory); `error` includes a session already burned. Buckets as the journal append |
| `rutli_intent_verify_duration_seconds` | histogram | `result` | Verification of a signing intent, on the leader (`Signer.Sign`) and on each member (round 1); `error` is a refused intent. Buckets (s): 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1, 0.25, 1 |
| `rutli_signs_in_flight` | gauge | — | Signatures this node leads right now, raised as each starts and lowered as each ends |
| `rutli_runtime_workers` | gauge | — | Worker threads of the async runtime |
| `rutli_runtime_alive_tasks` | gauge | — | Tasks alive on the async runtime |
| `rutli_runtime_global_queue_depth` | gauge | — | Tasks waiting in the async runtime's global queue |
| `rutli_runtime_busy_milliseconds_total` | counter | — | Milliseconds the runtime's workers spent busy, all together, since start. Busy ratio: `rate(rutli_runtime_busy_milliseconds_total[5m]) / 1000 / rutli_runtime_workers`. The `rutli_runtime_*` metrics are sampled every 15 s by the key-store watchdog thread, which keeps running when the runtime is saturated |
| `rutli_peer_state` | gauge | `peer` (roster number), `state`=up\|down\|trial | 1 for the liveness state this node holds for that peer, 0 for the others; set for every peer when the node starts. Down peers are tried last in every signature. One node seeing a peer down is a link; every node seeing it down is the peer (`RutliPeerDown`) |
| `rutli_peer_breaker_transitions_total` | counter | `peer`, `to`=down\|trial\|up, `reason`=unreachable\|stalled\|refusing\|window\|probe\|call | Liveness transitions: to `down` (why), to `trial` (a window passed), to `up` (after a probe or a successful call). Primed at 0 per peer. Zero in steady state and under load; many in a short time is a flapping link (`RutliPeerFlapping`) |
| `rutli_sign_fast_refusals_total` | counter | `reason`=no-quorum\|overloaded | Sign calls this node refused as leader without a signature, `UNAVAILABLE` with a `rutli-error` trailer: fewer than t cosigners reachable from it, or overloaded (too many signatures in flight, or its own round missed its deadline). Primed at 0. No-quorum on two or more nodes at once is a cluster that cannot sign (`RutliNoQuorum`, critical) |
| `rutli_background_loop_restarts_total` | counter | `loop` (`anti_entropy`, `ceremony_resolver`, `epoch_check`, `nonce_pruner`) | Background loops restarted 30 s after a panic in a pass (`anti_entropy` then also waits its own interval before the next sweep). The loop runs again; the panic is a bug (`RutliBackgroundLoopRestarted`) |

Not covered by the sign-phase metrics: the blocking-pool queue depth and the per-worker poll
times of the async runtime (unstable tokio APIs), and a per-peer split of the leader's calls (see
`rutli_peer_call_duration_seconds` by call class).

Leader-side metrics (`sign_*`, `ceremony_*`) appear on whichever node served the driver's request —
with driver failover that can be any of them, so always aggregate across instances (`sum(...)`).

Hosted-key metrics appear on every node, because hosted keys are **replicated whole keys, not FROST
shares**: each node holds the same material, serves its own decrypts, and counts them locally. (The
FROST share itself is never listed, replicated or counted per-key — two nodes holding one share
would silently break the threshold.) No hosted-key id is ever used as a label (only
`rutli_stale_share`, `rutli_key_epoch_proven`, `rutli_key_epoch_age_seconds` and `rutli_refreshes_6d` carry a key id: a FROST key, a handful per cluster); the label sets above are
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

`rutli_hosted_keys`, `rutli_unreadable_key_files_total`, both `anti_entropy_*` counters,
`rutli_hosted_keys_future_timestamp` and every `reason` of `rutli_hosted_replication_refusals_total`
are primed to zero at startup, so they exist even where hosted keys are disabled; `rutli_key_replicas`
is primed to `NaN` for the same reason (zero would page an idle cluster instantly).
`rutli_hosted_key_ops_total` is primed for every `op` and `result`.

The signing-policy, ceremony-intent, delete, tombstone and lock-poison series are primed to zero
for every label value they can carry, so the first event moves a series from 0 to 1 and the rules
that alert on increases see it (`deploy/monitoring/prometheus-rules.yml`:
`RutliSignPolicyRefusals`, `RutliSignIntentAbsent`, `RutliSignRateLimited`, `RutliSignerAclAbsent`,
`RutliSignJournalErrors`, `RutliDeleteIntentRefused`, `RutliHostedKeyDeleted`,
`RutliCeremonyIntentRefused`, `RutliCeremonyIntentAbsent`, `RutliLockPoisonRecovered`,
`RutliBackgroundLoopRestarted`), and so are `rutli_refresh_interval_refusals_total` and
`rutli_refresh_interval_waived_total` (`RutliRefreshRefused`).
`rutli_sign_fast_refusals_total` is primed for both reasons (`RutliNoQuorum`), and
`rutli_peer_state` / `rutli_peer_breaker_transitions_total` for every peer and label pair when the
node builds its mesh (`RutliPeerDown`, `RutliPeerFlapping`).
`rutli_sign_round2_unknown_session_total` is primed too (`RutliSignUnknownSessions`), and so are
the sign-session refusal counters for every `call` and `cap` (`RutliSignSessionOwnerRefused`,
`RutliSignSessionCapReached`).
`rutli_stale_share`, `rutli_key_epoch_proven` and `rutli_key_epoch_age_seconds` carry a key id and cannot be primed; `rutli_refreshes_6d` is set from the
ceremony records every resolver pass (30 s), for every key with a refresh record. `rutli_keyfiles` is set
once per start (`RutliKeyFilesUnopenable`, `RutliKeyFileMigrationPending`).

Since 0.5.0 each member of a sign attempt gets its own session id, so the same signature shows a
different session id in each node's log and journal. To follow one attempt across nodes, run the
leader at `debug`: its `sign attempt: one session id per member` line gives an attempt id and the
members' identifiers, and its round failure lines name the attempt and the member. It does not log
the members' session ids (each member's id is kept from the others), and the attempt id is never
sent to a peer. The journals and
`audit-cross-check` match signatures by key, request id and digest, not by session id.

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
  conflict (critical), hosted key material refused (`RutliHostedReplicationRefused`: unfenced,
  invalid, timestamp, unverifiable, throttled, spec, intent, mixed-version), a held hosted key with a time in the future
  (`RutliHostedKeyFutureTimestamp`), an aborted generation's rollback that missed a node
  (`RutliHostedRollbackIncomplete`), a peer held down for 5 minutes (`RutliPeerDown`), a peer
  marked down again and again (`RutliPeerFlapping`), no-quorum refusals on two or more nodes
  (`RutliNoQuorum`, critical). CI runs `promtool check rules` (pinned `prom/prometheus` image) on this file
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
   unreachable or refusing (e.g. mid-ceremony) while signing continues. `rutli_peer_state` on each
   instance says which peer and why (`rutli_peer_breaker_transitions_total{reason}`), and whether
   it is one link or the peer itself.
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
   `unconfirmed=<endpoint> reason=UNAVAILABLE|DEADLINE_EXCEEDED` on a failed entry means a
   cosigner answered "not found" (or another key, or that it cannot sign) while `<endpoint>` could
   not be reached or did not answer within the attempt deadline: the driver reported a retryable
   error, not a final one, and logged `FROST: <call>: the cosigners that answered said <answer>,
   but <endpoint> did not serve the call`. It clears when that cosigner is back. It cannot go on
   for a key that exists nowhere: once enough cosigners gave the answer that the rest could not
   use the key (all but one: 2 of 3, 4 of 5), it is final. Repeated
   entries therefore mean most of the cluster is unreachable from this participant.
   **A hosted key the driver did not accept** (0.5.0): after `GenerateKey` the driver asks every
   cosigner for its own copy and gives the key id to Canton only when at least two hold the
   material the leader reported and none reports other material. If it is short only because
   cosigners were silent, it asks the next cosigner to lead the same id (WARN `not confirmed`,
   `hosted-check=unconfirmed`); when none is left, Canton gets a non-retryable error naming the
   silent endpoints. Otherwise it logs an ERROR `hosted key <id> from <endpoint> REFUSED: …` with
   every node's answer, the audit entry carries `hosted-check=failed`, and Canton gets a
   non-retryable error. That is the leader or another cosigner holding material nobody confirmed,
   or a cosigner falsely claiming so (its statement is not checked): page, compare the nodes with
   `rutli-cosigner verify-hosted --key-id <id>`, and treat a node that disagrees as for
   `rutli_anti_entropy_conflicts_total`. Loki:
   `sum(count_over_time({app="canton-participant"} |= "hosted-check=failed" [10m])) > 0`.
6. **`rutli_key_replicas` below the cluster size** (or `rutli_hosted_keys` differing across
   instances, the same signal seen sideways) — a key exists on fewer nodes than the cluster is
   configured for. Writes commit at `write_quorum` (default 2 of 3) and roll back below it, so a
   node that was down during a `GenerateKey` legitimately lags until its own sweep pulls the key
   from two peers; `rutli_anti_entropy_repairs_total` should tick when it does. A key held by one
   node only is never copied automatically (`rutli_hosted_replication_refusals_total{reason=
   "unconfirmed"}` climbs on the nodes that lack it): copy it by hand (`docs/hosted-keys.md`,
   section 4). A shortfall that persists past
   several sweep intervals means healing is failing, and the cluster is running with less
   redundancy than it reports: two replicas survive one node loss, one survives none. The gauge is
   a cluster-wide minimum with no key id — take that from the sweep logs.
7. **Any `rutli_anti_entropy_conflicts_total` increase** — two nodes hold *different* material
   under the same key id, or a node refused a push or aborted a generation because of it. Hosted
   keys are create-once-immutable, so this is not lag and not a merge conflict; it is an invariant
   violation (a reused key id, a restore from a foreign cluster's backup, storage corruption, or a
   compromised cosigner planting a key). Nothing reconciles it automatically — picking a side could
   destroy the only copy that can decrypt already-recorded traffic. Page, freeze rotation for that
   key, and resolve it by hand (`docs/hosted-keys.md`, section 4).
   `rutli_hosted_replication_refusals_total` says which path saw it; the log line names the key
   and the peer. The counter goes up every time the conflict is seen, so one unresolved conflict
   adds to it at every sweep; the alert stays on until about an hour after it is resolved.
8. **`rutli_unreadable_key_files_total` non-zero** — a key file is present on disk but cannot be
   unsealed, so it is logged at error level, counted, and *skipped* from the hosted-key inventory
   (or cannot be opened at all — wrong ownership/permissions on that one file — which the
   key-store probe counts and logs at warn level; fix the file's ownership).
   Skipping is deliberate: failing the whole listing would stop anti-entropy for every healthy key
   too, turning one damaged file into a cluster-wide halt of self-healing. The cost is that the
   damaged key is invisible to replication — peers do not see this node's copy, and this node
   does not pull it back, and (6) stays even across the cluster while that key has fewer copies than you think.
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
10. **`rutli_refresh_interval_refusals_total` increasing, or `rutli_refreshes_6d` above 1**
    (alerts `RutliRefreshRefused`, `RutliRefreshOffSchedule`) — someone asks for refreshes more
    often than the weekly schedule. Each node takes part in at most one refresh of a key per
    `refresh_min_interval_secs` (72 h), so the limit holds, but every refresh leaves older backups
    unable to restore a node: if the refresh was not yours, find who holds the refresher
    certificate (and the driver certificate while `signer_may_refresh` is on) and replace its pin;
    check that every node's backup sidecar logged `BACKUP_TRIGGER` and `BACKUP_OK` after the commit.
    A refusal right after a manual run is expected
    (docs/ceremonies.md, "Refresh interval").
11. **A cosigner's working set above 80 % of its memory limit** (alert
    `RutliCosignerMemoryNearLimit`, Kubernetes, from cAdvisor and kube-state-metrics) — at the limit
    the kernel kills the cosigner in the middle of signing. Memory follows the sign sessions in
    flight (`rutli_pending_sign_sessions`, about 75 KB each at peak) and stays near its peak
    afterwards, so one burst can leave a node close to the limit. If sessions are stuck
    (`RutliPendingSessionsGrowing`), find the peer or driver holding them. Otherwise raise
    `resources.limits.memory` as [performance.md](performance.md), "Memory", describes.

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

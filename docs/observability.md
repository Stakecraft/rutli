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
| `rutli_sign_duration_seconds` | histogram | `result` | Leader-side `Signer.Sign` latency |
| `rutli_ceremony_requests_total` | counter | `kind`=dkg\|refresh, `result` | Key-ceremony outcomes (rare; any `error` needs investigation before retrying) |
| `rutli_sign_round1_skips_total` | counter | — | Peers skipped in sign round 1 — the quorum-margin canary: skips mean you are signing with less headroom than you deployed |
| `rutli_sign_aborts_total` | counter | — | Given-up signatures (leader aborted the in-flight session on the quorum) |
| `rutli_pending_sign_sessions` | gauge | — | In-flight round-1 sessions held on this node; hovers near 0 in a healthy cluster |
| `rutli_hosted_keys` | gauge | — | Cluster-hosted keys held by this node |
| `rutli_unreadable_key_files_total` | counter | — | Key files present on disk that could not be opened (wrong seal secret, partial restore, corruption) and were therefore skipped from the hosted-key inventory |
| `rutli_hosted_key_ops_total` | counter | `op`=generate\|decrypt\|symmetric_encrypt\|symmetric_decrypt\|delete, `result`=ok\|error | Signer-side hosted-key operation outcomes |
| `rutli_anti_entropy_repairs_total` | counter | — | Hosted keys a sweep pulled to this node or pushed to a peer that lacked them |
| `rutli_key_replicas` | gauge | — | Fewest cosigners holding any one hosted key, as of the last anti-entropy sweep (`NaN` until a sweep sees a hosted key, so comparisons never fire on an idle cluster). Below the cluster size means a write has not healed yet |
| `rutli_anti_entropy_conflicts_total` | counter | — | Hosted keys found with *different* material on this node and a peer under the same key id — an invariant violation, never auto-reconciled |

Leader-side metrics (`sign_*`, `ceremony_*`) appear on whichever node served the driver's request —
with driver failover that can be any of them, so always aggregate across instances (`sum(...)`).

Hosted-key metrics appear on every node, because hosted keys are **replicated whole keys, not FROST
shares**: each node holds the same material, serves its own decrypts, and counts them locally. (The
FROST share itself is never listed, replicated or counted per-key — two nodes holding one share
would silently break the threshold.) No key id is ever used as a label; the label sets above are
exhaustive. Three collection details matter when writing rules:

- `rutli_hosted_keys` is refreshed at the end of this node's own anti-entropy sweep and whenever a
  **peer** enumerates its keys, so after a `GenerateKey` it can trail the truth by up to one
  `anti_entropy_interval_secs` (default 300). Compare it across instances over long windows, not
  between scrapes.
- `rutli_anti_entropy_repairs_total` counts **sweep** repairs only. On-demand read-repair — the
  pull that happens when a request lands on a lagging replica — is logged but not counted here.
- `rutli_unreadable_key_files_total` counts **listings that hit a bad file**, not distinct files:
  the inventory is walked on every sweep and on every peer `ListKeys`, so one damaged file makes
  the counter climb steadily for as long as it sits there. Alert on a sustained increase rather
  than on a single bump, and read the key id out of the logs — it is never a label.

`rutli_hosted_keys`, `rutli_unreadable_key_files_total` and both `anti_entropy_*` counters are
primed to zero at startup, so they exist even where hosted keys are disabled; `rutli_key_replicas`
is primed to `NaN` for the same reason (zero would page an idle cluster instantly).
`rutli_hosted_key_ops_total` has no fixed label set and its series appear on first use: alert on its
rate, never on its absence.

Published latency snapshots and how to reproduce them: [`performance.md`](performance.md).

## Prometheus + Grafana

- Scrape config: any job name works, but the shipped alert rules assume `job: rutli-cosigner`.
- Alert rules: [`deploy/monitoring/prometheus-rules.yml`](../deploy/monitoring/prometheus-rules.yml)
  — cosigner down (critical: at 2-of-3 one loss means zero margin), sign errors, p99 latency,
  round-1 skips, pending-session growth, ceremony failure (critical), repeated aborts,
  hosted-key op errors, a hosted key under-replicated (below the cluster size) or critically
  under-replicated (a single copy — critical), hosted-key counts diverging across the job,
  unreadable key files, hosted-key conflict (critical).
- Dashboard: import
  [`deploy/monitoring/grafana-dashboard.json`](../deploy/monitoring/grafana-dashboard.json)
  (uid `rutli-cosigner`) — throughput, latency quantiles, skips, pending sessions, aborts,
  ceremonies.

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
5. **`rutli_hosted_key_ops_total{op="decrypt",result="error"}` sustained** — Canton has no
   software fallback for a KMS decrypt: a persistent failure surfaces as `KmsDecryptError` and
   disconnects the participant from the synchronizer. Read the error before assuming replication:
   an error on a node that simply lacks the key is a lag/repair problem, an error on a node that
   holds it is a sealing or backend problem. `generate` and `delete` errors are less urgent but
   block key rotation, which is the whole recoverability story for hosted keys.
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
   opened, so it is logged at error level, counted, and *skipped* from the hosted-key inventory.
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

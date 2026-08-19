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
| `rutli_hosted_key_ops_total` | counter | `op`=generate\|decrypt\|symmetric_encrypt\|symmetric_decrypt\|delete, `result`=ok\|error | Signer-side hosted-key operation outcomes |
| `rutli_anti_entropy_repairs_total` | counter | — | Hosted keys a sweep pulled to this node or pushed to a peer that lacked them |
| `rutli_key_replicas` | gauge | — | Fewest cosigners holding any one hosted key, as of the last anti-entropy sweep (absent until the first sweep sees a hosted key). Below the cluster size means a write has not healed yet |
| `rutli_anti_entropy_conflicts_total` | counter | — | Hosted keys found with *different* material on this node and a peer under the same key id — an invariant violation, never auto-reconciled |

Leader-side metrics (`sign_*`, `ceremony_*`) appear on whichever node served the driver's request —
with driver failover that can be any of them, so always aggregate across instances (`sum(...)`).

Hosted-key metrics appear on every node, because hosted keys are **replicated whole keys, not FROST
shares**: each node holds the same material, serves its own decrypts, and counts them locally. (The
FROST share itself is never listed, replicated or counted per-key — two nodes holding one share
would silently break the threshold.) No key id is ever used as a label; the label sets above are
exhaustive. Two collection details matter when writing rules:

- `rutli_hosted_keys` is refreshed when a **peer** enumerates this node's keys during its sweep, so
  after a `GenerateKey` it can trail the truth by up to one `anti_entropy_interval_secs`
  (default 300). Compare it across instances over long windows, not between scrapes.
- `rutli_anti_entropy_repairs_total` counts **sweep** repairs only. On-demand read-repair — the
  pull that happens when a request lands on a lagging replica — is logged but not counted here.

`rutli_hosted_keys` and both `anti_entropy_*` counters are primed to zero at startup, so they exist
even where hosted keys are disabled. `rutli_hosted_key_ops_total` has no fixed label set and its
series appear on first use: alert on its rate, never on its absence.

Published latency snapshots and how to reproduce them: [`performance.md`](performance.md).

## Prometheus + Grafana

- Scrape config: any job name works, but the shipped alert rules assume `job: rutli-cosigner`.
- Alert rules: [`deploy/monitoring/prometheus-rules.yml`](../deploy/monitoring/prometheus-rules.yml)
  — cosigner down (critical: at 2-of-3 one loss means zero margin), sign errors, p99 latency,
  round-1 skips, pending-session growth, ceremony failure (critical), repeated aborts,
  hosted-key op errors, hosted-key replica shortfall, hosted-key conflict (critical).
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
6. **`rutli_hosted_keys` differing across instances** — a key exists on fewer nodes than the
   cluster is configured for. Writes commit at `write_quorum` (default 2 of 3) and roll back below
   it, so a node that was down during a `GenerateKey` legitimately lags until anti-entropy heals
   it; `rutli_anti_entropy_repairs_total` should tick when it does. Divergence that persists past
   several sweep intervals means healing is failing, and the cluster is running with less
   redundancy than it reports: two replicas survive one node loss, one survives none.
7. **Any `rutli_anti_entropy_conflicts_total` increase** — two nodes hold *different* material
   under the same key id. Hosted keys are create-once-immutable, so this is not lag and not a
   merge conflict; it is an invariant violation (a reused key id, a restore from a foreign
   cluster's backup, or storage corruption). The sweep deliberately refuses to reconcile it —
   picking a side automatically could destroy the only copy that can decrypt already-recorded
   traffic. Page, freeze rotation for that key, and resolve it by hand.

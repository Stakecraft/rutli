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

Leader-side metrics (`sign_*`, `ceremony_*`) appear on whichever node served the driver's request —
with driver failover that can be any of them, so always aggregate across instances (`sum(...)`).

## Prometheus + Grafana

- Scrape config: any job name works, but the shipped alert rules assume `job: rutli-cosigner`.
- Alert rules: [`deploy/monitoring/prometheus-rules.yml`](../deploy/monitoring/prometheus-rules.yml)
  — cosigner down (critical: at 2-of-3 one loss means zero margin), sign errors, p99 latency,
  round-1 skips, pending-session growth, ceremony failure (critical), repeated aborts.
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

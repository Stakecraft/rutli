# Performance

Measured latency and throughput of the Rütli FROST cosigner cluster under real Canton traffic.
Numbers below are **operator evidence**, not a marketing SLA — always re-run on your topology.

## What we measure

| Signal | Source | Meaning |
|---|---|---|
| **Sign latency** | `rutli_sign_duration_seconds` (leader) | Full `Signer.Sign` RPC: round-1 + round-2 FROST over mTLS, until the Ed25519 signature is returned |
| **Sign success / errors** | `rutli_sign_requests_total{result=…}` | Outcomes on the leading cosigner |
| **DKG / refresh count** | `rutli_ceremony_requests_total` | Ceremony outcomes (no duration histogram yet — see below) |
| **Degraded margin** | `rutli_sign_round1_skips_total`, `rutli_sign_aborts_total` | Peer skips / aborted sessions |
| **Driver audit** | participant log `AUDIT sign … outcome=ok` | End-to-end proof Canton got a FROST signature |

Leader-side metrics live on whichever cosigner the driver dialed. Aggregate across pods
(`sum by (…)`) when scraping all three.

How to scrape: see [`observability.md`](observability.md).

## DevNet reference (multi-region k8s)

**Captured:** 2026-07-20 · image `ghcr.io/stakecraft/rutli-cosigner:0.2.1` · threshold **2-of-3**  
**Topology:** three cosigners on Hetzner agents in **HEL / NBG / FSN** (separate AZs), mTLS + sealed
shares; Splice DevNet participant in HEL driving the cluster (`stakecraft-devnet-rutli-01`).

| Metric | Value |
|---|---|
| Successful threshold signs | **9 249** (`result="ok"`) |
| Sign errors | **0** |
| Round-1 peer skips | **0** |
| Sign aborts | **0** |
| DKG ceremonies | **2** OK (`frost-namespace`, `frost-signing`) |
| Mean Sign RPC latency | **≈ 99.5 ms** (`sum / count`) |
| Summary quantiles (exporter) | p50–p99 ≈ **70 ms**, max ≈ **73 ms**\* |
| Pending sign sessions | **0** (steady state) |

\*Captured on 0.2.1, whose exporter rendered `rutli_sign_duration_seconds` as a **summary**
(as every release through 0.3.1 does). Its quantiles are approximate sliding-window
estimates, which is why the mean from `sum/count` is the headline number here. Later cosigners
export a true histogram (buckets in [`observability.md`](observability.md#sign-latency-histogram)),
so re-captures should report p50/p95/p99 from `histogram_quantile()` over the run window.

**How to read this:** ~100 ms mean for a **cross-region** 2-of-3 FROST sign (HEL leader ↔ NBG/FSN
peers) is the realistic multi-DC figure. Same-rack / single-AZ lab clusters will be faster; do not
cite DevNet numbers as co-located latency.

### Reproduce

```sh
# Per-cosigner (leader holds the counters)
kubectl -n rutli port-forward pod/rutli-cosigner-0 9200:9200
curl -s localhost:9200/metrics | grep -E '^rutli_sign_|^rutli_ceremony_'

# Mean latency (seconds → ms)
# mean_ms = 1000 * rutli_sign_duration_seconds_sum{result="ok"}
#              / rutli_sign_duration_seconds_count{result="ok"}

# p99 over the run (cosigners after 0.3.1; PromQL)
# histogram_quantile(0.99, sum by (le) (increase(rutli_sign_duration_seconds_bucket{result="ok"}[24h])))
```

Participant-side confirmation:

```sh
kubectl -n <validator-ns> logs deploy/participant --tail=5000 \
  | grep -E 'Loaded driver rutli|AUDIT sign keyId=frost'
```

## Benchmarks worth publishing next

Add these when you want grant/audit-grade tables (script + freeze a row in this doc per run):

| Benchmark | Why it matters |
|---|---|
| **Healthy 2-of-3 sign** (above) | Baseline under live Canton digests (34-byte) |
| **Degraded 2-of-2** (one cosigner stopped) | Prove quorum margin; expect modest latency bump, zero errors |
| **Co-located vs multi-region** | Separate “lab” vs “production topology” columns |
| **DKG wall time** | Bootstrap UX; needs a `rutli_ceremony_duration_seconds` histogram (not shipped yet) |
| **Refresh wall time** | Share rotation cost under traffic |
| **Sustained rate** | Signs/sec until p99 regresses (driver + Canton often bottleneck before FROST) |
| **Driver e2e** | Time inside `RutliDriver.sign` (JVM) vs cosigner RPC — splits network vs crypto |
| **Cold start** | Pod restart → first successful sign (share unseal + peer dial) |

Suggested soak gates (already in spirit of [`testnet-soak.md`](testnet-soak.md)):

- `rutli_sign_requests_total{result="error"}` flat over the window  
- p99 Sign &lt; **1 s** sustained (alert fires at 5 s)  
- At least one live refresh with group key unchanged  

## What we deliberately do *not* claim

- Throughput of the Canton participant or Splice validator-app (those dominate wall-clock for many flows).  
- Encryption-key latency (software/HSM delegate — not FROST).  
- MainNet or audited production SLOs — DevNet evidence only until soak + audit close.

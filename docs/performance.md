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

How to scrape: see [`observability.md`](observability.md). Load tests on one machine (latency
under load, a cosigner killed under load, the limits): see [`load-testing.md`](load-testing.md).

## DevNet reference (multi-region k8s)

**Captured:** 2026-07-20 · image `ghcr.io/stakecraft/rutli-cosigner:0.2.1` · threshold **2-of-3**  
**Topology:** three cosigners in three separate data centers (separate AZs), mTLS + sealed
shares; a Splice DevNet participant in the same region as one of them driving the cluster.

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

**How to read this:** ~100 ms mean for a **cross-region** 2-of-3 FROST sign (leader ↔ peers in
two other data centers) is the realistic multi-DC figure. Same-rack / single-AZ lab clusters will
be faster; do not cite DevNet numbers as co-located latency.

### Reproduce

```sh
# Per-cosigner (leader holds the counters)
kubectl -n rutli port-forward pod/rutli-cosigner-n1-0 9200:9200   # pod names of deploy/k8s
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

## Micro-benchmarks

The DevNet numbers above measure a whole `Sign` RPC on 0.2.1. Since then every share a cosigner
releases also costs an intent verification, a sign-journal entry and the checks around them. The
micro-benchmarks time those steps one by one, in process, with no network:

```sh
scripts/bench.sh                    # a few minutes; writes frost/target/bench/bench.json
scripts/bench.sh --quick            # a smoke run, too noisy to compare
RUTLI_BENCH_DIR=/var/lib/rutli-bench scripts/bench.sh --out bench-$(git rev-parse --short HEAD).json
```

| Metric | What one operation is | Paid |
|---|---|---|
| `frost/round1` | `Cosigner::round1`: marker lookup, nonces and commitments (and dropping the session again, one map removal) | per cosigner, per signature |
| `frost/round2` | `Cosigner::round2`: binding checks, the nonce marker (file fsync + directory fsync), the share | per cosigner, per signature |
| `frost/nonce_marker_burn` | the nonce marker alone | part of `frost/round2` |
| `frost/aggregate` | the leader combines two shares and verifies the signature | once per signature |
| `intent/verify_p256` | certificate chain, ECDSA P-256 signature and fields of a signing intent | per cosigner, per signature |
| `journal/append_fsync` | one hash-chained sign-journal line, fsynced, and the rate-limit ledger | per cosigner, per signature |
| `seal/seal_v1`, `seal/unseal_v1`, `seal/seal_v2`, `seal/unseal_v2` | AES-256-GCM over a FROST share record, both key-file formats | first use of a key after a restart; ceremonies |

The output file maps each metric to its mean in nanoseconds per operation (`metrics`), with the
median and the confidence interval next to it (`detail`), the commit and the compiler.

How to read them:

- `frost/round2`, `frost/nonce_marker_burn` and `journal/append_fsync` each wait for the disk.
  They measure the volume under `RUTLI_BENCH_DIR` (default: the system temporary directory) far
  more than the code, and they are the largest part of a cosigner's work for one signature: two
  file fsyncs and one directory fsync per released share. Point `RUTLI_BENCH_DIR` at the volume
  type the cosigners run on; a laptop SSD, a network volume and a local NVMe disk differ by an
  order of magnitude here.
- Compare two runs only on the same machine and the same volume. There is no CI gate on these
  numbers yet.
- Latency of a whole `Sign` under load, the limits and failover need a running cluster and are
  not measured here.

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
- Encryption-key latency (delegate or cluster-hosted keys — not FROST).  
- MainNet or audited production SLOs — DevNet evidence only until soak + audit close.

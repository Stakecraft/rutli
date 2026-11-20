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

## Cluster suite on three locations, 2026-11-20

The first run of the [cluster suite](cluster-suite.md) on a real Kubernetes cluster: three
cosigners on separate nodes in three locations, 2 dedicated vCPU each. **The load profile was a
placeholder and the cosigners ran the `lab` profile.** It is one short run, not a baseline and not a
guarantee: read the numbers as what this cluster did once, and see "Not measured" below before you
quote any of them. The next run is planned from `main`, with a diagnostic pass for the checks that
failed.

| | |
|---|---|
| Date | 2026-11-20, 14:07 UTC start, about an hour in all |
| Code | commit `95f82903db4a`, the head of the branch of PR #115 (refresh interval) before it merged; the cosigner image was built from that commit for the suite. Not a release |
| Cluster | Three cosigners, each on its own node in a different location, all three locations in one region. **2 dedicated vCPU per cosigner.** Installed by the suite from the Helm chart, as in [cluster-suite.md](cluster-suite.md). Threshold 2-of-3 |
| Profile | The chart's `lab` profile, not `production` |
| Load | `scripts/perf/profiles/placeholder.json`: 20 signatures a second for 60 s as the steady stream, a baseline of 1 signature and 0.2 ECDH a second for the ramp, SLO p99 below 1 s. The generator calls the Signer API directly over gRPC from inside the cluster and signs one intent per request. No Canton participant and no driver in the path |
| Suites | `upgrade`, `scenarios`, `keys`, `ramp`, `disrupt` |

Latencies are the load generator's, in milliseconds, for 2-of-3 signatures.

| Scenario | What ran | p50 | p99 | Result |
|---|---|---|---|---|
| steady | 20 signatures a second for 60 s | 59 | 123 | 1 200 of 1 200 ok |
| clients | several clients at once | 116 | 183 | 4 056 of 4 056 ok |
| burst | 200 signatures asked for at the same moment | 5 637 | 10 460 | 200 of 200 ok; |
| restart | one cosigner killed (SIGKILL) and started again under load | 109 | 9 218 | 800 of 800 ok |
| cold-cache | one cosigner restarted under load | 473 | 10 467 | 300 of 300 ok |
| keys: 1, 10, 100 FROST keys (and as many hosted keys) | signing over all of them | 61, 61, 78 | 123, 152, 161 | all ok; the slowest cosigner's mean `ListKeys` time was 167, 181 and 289 ms |
| ramp, baseline × 1 to × 30 (1 to 30 signatures a second, 300 s each) | signing, plus ECDH at a fifth of the signing rate | 58 to 64 | 123 to 170 | every request ok. ECDH p50 4 to 7 ms, p99 26 to 90 ms |
| ramp, × 100 (100 signatures and 20 ECDH a second, 300 s) | | 93 | 887 | 29 997 of 29 997 ok, just under the 1 s SLO; ECDH p50 4.4 ms, p99 26 ms |
| ramp, × 300 (300 signatures a second) | | 24 572 | 85 936 | stopped: 30 731 of 89 985 ok; the rest `CLIENT_SATURATED`, `DEADLINE_EXCEEDED` or `UNAVAILABLE` |
| DKG | 80 distinct key generations in the ceremony-limit scenario | 4 309 | 7 435 | 80 of 80 ok |

The suite's headroom factor was **100** against the placeholder baseline. With a placeholder
baseline that number says nothing about a real participant.

Under disruption, with the steady stream running:

| Disruption | p50 | p99 | Requests | Recovery |
|---|---|---|---|---|
| a cosigner's node lost | 57 | 30 090 | 2 400 of 2 400 ok | 1.5 s |
| a cosigner's data volume lost | 108 | 20 178 | 2 400 of 2 400 ok | 1.6 s |
| partition between two cosigners | 73 | 194 | 2 400 of 2 400 ok | 1.7 s |
| one cosigner cut off from both others | 53 | 30 076 | 2 400 of 2 400 ok | 22.8 s |
| 50 ms of delay on every cosigner | 307 | 371 | 2 400 of 2 400 ok | 1.5 s |

Every signature completed, but the p99 of the first, second and fourth rows is 20 to 30 s: a few
requests wait for a timeout before another cosigner leads. Related open issues:
[#176](https://github.com/Stakecraft/rutli/issues/176),
[#174](https://github.com/Stakecraft/rutli/issues/174),
[#153](https://github.com/Stakecraft/rutli/issues/153). The suite's check "every cosigner is
healthy afterwards" failed for the node-loss and volume-loss runs (cosigner 3 and cosigner 2); this
page does not know why.

**Upgrade.** The suite upgraded the chart under a stream of 5 signatures a second, from 0.4.1 to the
build above. All three cosigners restarted together: 54 of 750 signatures failed with `UNAVAILABLE`,
every request in seconds 12 to 21 of the run failed (an outage of about 11 s), and the keys were
unchanged ([issue #173](https://github.com/Stakecraft/rutli/issues/173),
[upgrading-to-0.5.md](upgrading-to-0.5.md)).

**Limits.** The rate, ceremony, decryption and session limits refused what they should have, with
`RESOURCE_EXHAUSTED`, `FAILED_PRECONDITION` or `UNAVAILABLE` (for example, 4 816 of 12 000
decryptions in `limit-decrypt`, and the second refresh of a key within the interval).

### Not measured, and what failed

- **The run failed its own checks.** Exit status 1, three problems: the `ecies` scenario's load
  generator ended when the connection of the `kubectl` session that ran it was reset (no ECIES
  figure from that scenario; the ramp's ECDH figures above are separate), and the two health checks
  above. There was no earlier run to compare with.
- **Placeholder load profile.** The steady rate and the baseline are not a participant's load. The
  1 s SLO is the placeholder's. Replace both with numbers from the soak cluster before you read
  "headroom" as a statement about a real node.
- **`lab`, not `production`.** The production profile was not on. A production run may differ.
- **2 dedicated vCPU per cosigner.** A larger node will do more; the ramp's limit is about this
  size of node, and the × 300 step may have hit the load generator as much as the cosigners
  (`CLIENT_SATURATED`).
- **No Canton participant, no driver.** The numbers exclude the JVM driver, its audit log and the
  participant's own latency.
- **One short run** (`duration: short`), one cluster, one region. No soak, no repeat, no network
  outside the region.
- **The build was a branch head, not a release.**

## Benchmarks worth publishing next

Add these when you want grant/audit-grade tables (script + freeze a row in this doc per run). The
2026-11-20 run above covers, once and with a placeholder load, the degraded cluster, cold start,
sustained rate and the client-side DKG time; none of them is a baseline yet.

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

# Load testing

`scripts/perf-load.sh` builds the working tree, starts the three-cosigner mTLS cluster of
`deploy/frost` under Docker Compose, and drives it with `rutli-loadgen` (`frost/loadgen`) through
a fixed list of scenarios. One run writes one JSON file; `scripts/perf/compare.py` compares it
with an earlier run.

It answers three questions: how long a `Sign` takes under load, whether the cluster keeps signing
when a cosigner dies, and whether its limits refuse what they should without the nodes falling
over. It does not replace the soak ([`testnet-soak.md`](testnet-soak.md)): everything runs on one
machine, so there is no network latency between the cosigners, and the disk is the runner's.

The latency measured on DevNet, across data centers, is in [`performance.md`](performance.md).
The same scenarios on a real Kubernetes cluster, with scale and disruption tests: see
[`cluster-suite.md`](cluster-suite.md).

## Running it

```sh
scripts/perf-load.sh                                    # about ten minutes after the image build
scripts/perf-load.sh --steady-secs 7200                 # a release candidate: two hours of steady signing
scripts/perf-load.sh --previous last-week/load.json     # and fail on a regression
```

Needs Docker with the compose plugin, `openssl` and `python3`. No port is bound on the host and
nothing is published. Results go to `perf-out/`: `load.json`, `compare.md` (the report, also
printed) and each cosigner's log.

The script writes a throwaway CA and certificates to `deploy/frost/certs` and removes them
afterwards. Outside CI it refuses to start if that directory exists.

## The load generator

`rutli-loadgen` behaves like the Canton KMS driver:

- mutual TLS with the `driver` certificate, which is also the key that signs its intents;
- one signed intent per request, and one signed ceremony intent per DKG or refresh, so every
  cosigner verifies an intent for each signature, as it does behind a current driver;
- a sticky leader per client, and failover to the next cosigner when the contacted one does not
  serve (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, a broken connection), with the same intent, so the
  cosigners charge the request once;
- every answer is checked: a signature with `verify_strict` against the key's group key, an ECDH
  secret against one computed locally. An answer that does not verify is never a success.

It reports the client's view (outcomes by gRPC code, p50/p95/p99 of the successful requests, a
per-second timeline) and the cosigners' own: it scrapes every `/metrics` page before and after
the run and reports what changed, with p50/p95/p99 from `rutli_sign_duration_seconds`.

It is a test tool. It is not in the cosigner image and not in a release; the load tests use their
own image (`frost/Dockerfile.perf`), which holds the cosigner built exactly as the release image
builds it, plus the generator.

## Scenarios

| Scenario | Load | Passes when |
|---|---|---|
| `steady` | 20 signatures a second for 60 s (`--rate`, `--steady-secs`), four clients | every request succeeds |
| `burst` | 200 signatures asked for at the same moment | every request succeeds |
| `clients` | 16 clients on two keys, each sending its next request when the last is answered | every request succeeds |
| `ecies` | 50 `EcdhDerive` a second on a hosted ECIES key | every request succeeds, every secret is the right one |
| `restart` | the steady stream while one cosigner is killed (`SIGKILL`) and started again | every request still succeeds: clients fail over, leaders sign with the other member |
| `cold-cache` | one cosigner restarted, then 300 signatures at once through it | every request succeeds and no cosigner loses a session between the two rounds (`rutli_sign_round2_unknown_session_total` does not move) |
| `limit-rate` | 400 signatures on a key limited to 120 a minute | at least 120 and at most 180 succeed (each is charged on the two nodes that signed it), the rest are `RESOURCE_EXHAUSTED` |
| `limit-ceremony` | 80 DKGs at once (a node holds 64 ceremony sessions), then 10 DKGs of one key at once, each client retrying `ABORTED` up to six times with jittered backoff (`--retry-aborted 6`), two refreshes back to back with the refresher's certificate (as a refresh job runs them; the load-test configs list it in `refresh_allowlist`) | the 80: refusals only with the codes a busy or refusing node gives; the contested key: every client ends with the one group key or `ALREADY_EXISTS` pointing at it (the generator asks `GroupKey`), never two keys; a refresh leaves the group key unchanged |
| `limit-decrypt` | 12 000 `EcdhDerive` on a key limited to 6 000 a minute | no more than the bucket and its refill succeed, the surplus is `RESOURCE_EXHAUSTED` |
| `limit-sessions` | 1 500 signatures of one key asked of one leader at the same moment | refusals and timeouts are allowed, wrong answers are not; the nodes stay up |
| `recovery` | a short stream on both keys after all of the above | every request succeeds |

Every scenario also fails if a cosigner process died and was started again during it (unless
the scenario restarts it on purpose), if a cosigner is unhealthy afterwards, if its peak resident memory
exceeds 512 MiB (`--max-rss-mib`), or if it holds over 64 more file descriptors than before the
scenario (`--max-fd-growth`). Both are read from `/proc` inside the container.

When a scenario fails on a code it does not allow, the check's detail starts with a verdict on
whose side gave out: `handshake timeouts N > 0` (the cosigners cut handshakes that took over
5 s), `the rig` (the load generator was throttled over 5 % of the time, or held over 90 % of its
descriptor limit), or `undecided`. The readings follow it: the cosigners' accept-path counters
and connections, the generator's CPU throttling (read from its pod's cgroup on Kubernetes, not
available under Compose) and its peak descriptors (`fd_peak` of the generator's report), and the
most frequent error messages.

`limit-rate` and `limit-decrypt` also fail if the limit is never reached, or if more passes than
the limit allows: a limit test that hit no limit proves nothing. `limit-ceremony` and
`limit-sessions` do not require a refusal: whether 80 DKGs or 1 500 signatures are ever in
flight at the same moment depends on the machine. They show that the nodes survive the attempt
and answer nothing wrong.

The cluster runs the example configs of `deploy/frost/config-tls` with one change: the sign rate
limit (300 a minute per key by default, below what the scenarios send) is lifted, except for keys
named `perf-limited*`, which get 120 a minute. The session caps, the ceremony limits and the
decryption limit are the defaults. Like any TLS cluster, each node pins the TLS key of every
cosigner: `gen-frost-certs.sh` writes the pins of the certificates of the run into the copies
(`RUTLI_PIN_CONFIGS`).

## The result

`load.json` holds, per scenario: the load generator's reports (`loads`), each cosigner's memory
and descriptors before and after (`resources`), the checks with their verdicts (`checks`), and
`passed`. `failed` at the top lists the scenarios that did not pass.

`scripts/perf/compare.py PREVIOUS CURRENT` prints a table and exits 1 when

- a p95 or p99 is more than 20 % above the previous run's (`--threshold`), for the scenarios
  `steady`, `burst`, `clients` and `ecies`, on the client side or in the cosigners' histogram,
  where both runs sent the same load for the same length of time.
  A difference under 2 ms is not counted (`--floor-ms`). The histogram's percentiles are
  interpolated inside its buckets (10, 25, 50, 75, 100 ms, …), so they move in steps;
- or the current run has a failed scenario.

Compare runs from the same machine only. Latencies of the limit scenarios are never compared:
they are the latencies of refusals.

## In CI

`.github/workflows/load.yml` runs the scenarios

- every Monday at 02:00 UTC on `main`, compared with the last green run; a regression or a failed
  scenario fails the run and opens an issue (or comments on the one that is open);
- by hand (`workflow_dispatch`), with the length of the steady stream as input: 7200 to 14400
  seconds for a release candidate;
- on a pull request that changes the load test itself, without a comparison.

The result, the report and the cosigners' logs are the run's `load-result` artifact.

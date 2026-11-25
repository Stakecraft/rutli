# Cluster suite

Load, scale and disruption tests of Rütli on a real Kubernetes cluster, with the Helm chart as
operators install it. The suite brings no cluster of its own: **bring a kubeconfig** and a
namespace. It installs three cosigners and a load generator there, runs the suites, writes one
JSON file, and compares it with a previous run.

For the same scenarios on one machine under Docker Compose, see [`load-testing.md`](load-testing.md).

## What you need

- A cluster with at least three schedulable nodes (the chart places each cosigner on its own
  node) and a fourth for the load generator if you want it apart. `KUBECONFIG` pointing at it.
- A namespace the suite may use, or the right to create one. Inside it: create secrets, pods,
  NetworkPolicies, `kubectl exec` into pods, and install a Helm release (StatefulSets, Services,
  a ConfigMap, a PodDisruptionBudget, PersistentVolumeClaims, NetworkPolicies). Nothing outside
  the namespace is touched, except that the node-loss fallback cordons a node (see below).
- A storage class for the cosigners' volumes (`ReadWriteOnce`).
- The suite's image, built from this repository and pushed where the cluster may pull from:

  ```sh
  docker build -f frost/Dockerfile.perf -t <registry>/rutli-perf:<tag> frost
  docker push <registry>/rutli-perf:<tag>
  ```

  It holds the cosigner, built exactly as the release image builds it, and the load generator.
  It is never published by this project.
- `kubectl`, `helm` and `openssl` where you run the suite, and `python3`.

### Placement

Where the cosigners sit changes the signing latency. A signature needs two of the three
cosigners, so with one site far from the other two, a fair partner order puts the far site in
two thirds of the signatures; which cosigner sits there decides which signatures wait for it.
For runs to be compared, every run should have the same shape:

- label the node for cosigner `<id>` with `rutli-perf/cosigner=<id>` (1, 2, 3), each on its own
  site. The deploy pins each cosigner to its node through the chart's per-node `nodeSelector`.
  Label before the first deploy: a volume bound in one zone keeps its pod there;
- `rutli-perf/role=cosigner` and `rutli-perf/role=loadgen` still select the pools, as before:
  where the `role=cosigner` pool exists, a pinned node needs both labels.

A cosigner whose label is on no node is placed by the scheduler, so label all three or none.
Either way `cluster.json` records under `placement` the node, zone and region (the nodes'
`topology.kubernetes.io/*` labels) of each cosigner and of the load generator once the cosigners
are healthy, and the report prints the cosigners' zones. If a pod moved by the end of the run (a
disruption), `placement_end` holds where they were then, and the report says so.

## Running it

```sh
export KUBECONFIG=...
scripts/perf/k8s-deploy.sh install --namespace rutli-perf --previous \
  --image <registry>/rutli-perf:<tag> --work ./perf-work [--storage-class NAME] [--pull-secret NAME] [--values extra.yaml]

scripts/perf/cluster.py --namespace rutli-perf --profile scripts/perf/profiles/production.json \
  --upgrade-image <registry>/rutli-perf:<tag> --work ./perf-work --env-name <name> --out perf-out/cluster.json

scripts/perf/compare.py last-week/cluster.json perf-out/cluster.json   # exit 1 on a regression
scripts/perf/k8s-deploy.sh uninstall --namespace rutli-perf
```

`--previous` starts the cosigners on the previous release (the chart's default image, or
`--previous-image`), so that the upgrade suite moves live keys to the build under test. Leave
both out, and `upgrade` out of `--suites`, to test one build only.

`--work` receives the throwaway CA, certificates, seal bundles and chart values of the test
installation. Keep it until `uninstall`; delete it afterwards.

`--values` adds chart values after the suite's own: resources, tolerations, node selection,
anything your cluster requires. `--env-name` labels the result; runs are only compared with runs
of the same name.

## Suites

| Suite | What happens | Fails when |
|---|---|---|
| `migration` | first: an existing Canton namespace key brought in by the split ceremony, as [migration.md](migration.md) and [split-ceremony.md](split-ceremony.md) do it (see "The migration suite" below); the imported key is then the first tenant's namespace-class key for every later suite | a step of the ceremony fails or is refused, a check of `scripts/e2e-migration.sh` fails, or the imported key does not sign within the driver's deadlines |
| `upgrade` | `helm upgrade` from the previous release to `--upgrade-image` under 5 signatures a second | a key is missing or changed afterwards, or does not sign; signatures that fail while the cosigners restart are counted, not forbidden (the chart restarts all three at once) |
| `scenarios` | the scenarios of [`load-testing.md`](load-testing.md): steady stream, burst, several clients, ECIES, a cosigner pod killed under load, the cold-cache restart, and the limits | as described there |
| `connect` | N new clients connecting at the same moment (`connect.clients` of the profile: 50, 200, 500), one signature each, with each client's connection time recorded apart from its request (`rutli-loadgen --eager-connect`) and the cosigners' `rutli_grpc_handshake_timeouts_total` | never: a measurement of what many clients connecting together costs, for example every driver reconnecting after a cosigner restart |
| `disrupt` | under the steady stream: a node lost, a data volume lost, a partition between two cosigners' nodes (`partition`), one cosigner cut off from both others (`partition-isolated`, as when a data centre loses its links), added network delay on every cosigner's node (`--net-delay-ms`, default 50 and 150 ms); afterwards, rounds of signatures until the cluster signs within the SLO again (`recovery_secs`) | a signature fails, a cosigner is not healthy afterwards, or the cluster does not sign normally again within `--settle-secs` (600); a step without its hook is reported as skipped |
| `keys` | for each key count of the profile (1, 10, 100): that many FROST keys and hosted keys over ten tenant prefixes (`perf-t<n>-…`), sign latency over all of them, and each cosigner's Peer API `ListKeys` time | a setup, signature or listing fails |
| `upgrade`, `disrupt` (key classes) | with a profile that has `classes` (`production`): during each disruption and during the upgrade's rollout, one signature with each tenant's namespace-class key and one decryption (ECDH) with its hosted key, under the driver's deadlines (5 s a sign attempt, 10 s another call, 30 s a call) | one of them fails or runs out of time: a topology change or a decryption during an incident is the case that matters |
| `key-classes` | last, with `classes`: the same spot checks at rest, then twice the namespace-class key's per-minute limit plus five at once | a spot check fails, fewer than the limit or more than one and a half times it pass, or the rest is not refused with `RESOURCE_EXHAUSTED` |
| `ramp` | the profile's baseline load × each factor (1, 3, 10, 20, 30, 45, 70, 100, 150, 200, 300 in `devnet-validator`); a step runs the baseline's phases one after another (average, busiest minute, burst), each × the factor | never: the last factor at which every phase passed is the **headroom factor**. A phase over the SLO or with an error drops out and the ramp goes on with the others, so each part of the real load gets its own headroom (`real_load_headroom`) |

They run in the order `migration`, `upgrade`, `scenarios`, `connect`, `keys`, `ramp`, `disrupt` (disruption last, so that
what it leaves behind cannot skew the measurements of the others), then `key-classes` when the
profile has classes; `--suites` picks a subset. With several tenants, every ramp step runs the
shape for each tenant at once, each on its own keys with its own driver certificate.
Every scenario also checks that no cosigner restarted unless the scenario did it, and that their
memory and file descriptors stay within bounds. A cosigner a disruption restarts on purpose is not
judged by its health the moment the load ends but by `time_to_healthy_secs`: the seconds from the
end of the disruption (a node's reboot included) until every cosigner answers Health ok again. It
fails when they are not healthy within `--settle-secs` of the end of the recovery step. After a
rig failure in a disruption (a hook or `kubectl` error), what follows in that scenario is counted
as the rig's too.

The load generator runs detached in its pod: `scripts/perf/k8s_loadgen.py` starts each run with a
short `kubectl exec`, polls for its end, and fetches the report afterwards, retrying each call, so
no stream to the API server is held open for the length of a run.

## Diagnostic pass

`cluster.py --diagnose` answers what limits the throughput, instead of running the suites. In order
of what each step tells for its cost:

1. **Flush cost.** On each cosigner's own data volume, before any load, in a dot-directory removed
   afterwards: 100 writes with `O_DSYNC` (the device), and 50 rounds of what one released share
   does (append a line and `fdatasync`, create a file and `fsync` it, `fsync` its directory), with
   the shell's own cost subtracted: milliseconds per share on each node. A leader signs with itself
   and the `t - 1` cosigners after an offset that a hash of the request id picks among the others,
   so with requests spread evenly over the leaders, every cosigner releases a share for `t / n` of
   the signatures: two thirds each in a 2-of-3 cluster (cosigners before 0.5.0 signed with the
   lowest other identifier, so cosigner 1 served every signature). The lowest of
   `1000 / (ms × fraction)` over the nodes is what the flushes alone would allow
   (`predicted_ceiling_signs_per_sec`): the slowest volume sets it. An upper bound to hold against
   the measured plateau.
2. **Fine ramp around the knee** (`diagnose.factors` of the profile, `step_secs` each), signing only
   unless `diagnose.with_ecdh` is set, spread over every load generator pod. Readings bracket the
   middle of each step (not the generators' start and end). Per step and per container, from
   cgroup v2 (the container's own cgroup, from `/proc/self/cgroup`): CPU cores used, the share
   of time throttled by the CPU limit, CPU and IO pressure (the share of time tasks waited), writes
   per second, memory; the achieved rate against the offered one, requests never sent, the
   cosigners' p99, errors by code and message (so a session-cap refusal is told from another
   `UNAVAILABLE`), and CPU milliseconds per signature. A step where a generator used most of its
   CPU limit, or requests were not sent while no cosigner waited for CPU or IO, is marked
   `generator_bound`; such a step, or one without every cosigner's readings, gives no verdict and
   cannot be the knee. The ramp stops one step past the knee.
3. **Keys.** The knee's (overloaded) rate over 2, 20 and 200 keys (`diagnose.key_counts`; without
   a knee, the highest step's rate, `keys_rate_from`):
   throughput rising with the key count means a per-key lock; flat means a limit shared by all
   keys (the volume, the CPU).

Install with `k8s-deploy.sh --generators 2` (or more) so that no step is generator-bound. To size
the flush cost directly, install a second time with `--diagnostic-tmpfs` and run `--diagnose`
again, into a namespace that does not exist yet: the cosigners then keep their data on an
in-memory volume, with a 512 Mi memory limit to hold it. **That is a diagnostic only, never a
configuration**: everything is lost on any restart, the namespace and every result are
labelled `diagnostic: tmpfs`, `compare.py` never uses such a run as a baseline, and the upgrade
and disrupt suites refuse to run there. The chart has no value for it: the suite patches the
StatefulSets of that test installation.

A bigger cosigner node type is the cluster's choice; compare a run on it with one on the smaller
type: throughput that scales with the cores means CPU, flat means a lock or the volume.

## The client's deadlines

By default the load generator gives every attempt at one cosigner 30 s and has no budget across
attempts: a cosigner that stops answering costs a request 30 s before it moves on. With
`--driver-deadlines` it follows the driver's policy instead: 5 s per attempt of a signature, on
whose deadline it moves to the next cosigner with the same intent, and 10 s per attempt of ECDH,
one attempt at a time, within 30 s for the whole call (`frost.sign-attempt-timeout`,
`frost.attempt-timeout`, `frost.request-timeout`); `--sign-attempt-timeout-secs`,
`--attempt-timeout-secs` and `--request-timeout-secs` set other values.
Ceremonies keep one attempt with the full timeout, as the driver runs them. The policy is recorded
in the result (`client_policy`), and runs under different policies are not compared. Use it when
the numbers should say what a driver would see, for example in `node-kill` and `partition-isolated`.

`--sign-leader rotate|sticky` sets where a signature starts, as the driver's `frost.sign-leader`;
`--driver-deadlines` implies `rotate` (the driver's own default is `sticky`). Under `sticky`, every call starts at
the client's leader and moves it on a failover. Under `rotate`, each signature starts at the next
cosigner in turn that has not failed to serve in the last 60 s (`frost.leader-recovery`), or at
the sticky leader when none qualifies. Failover then walks the ring as before; a signature never
moves the sticky leader, a failure does. ECDH and ceremonies stay sticky in both. The driver also
skips a cosigner that answered another group key for that key; the load generator pins no group
keys, so it has no such case. The policy is part of `client_policy`.

### Slow node

With `HOOK_NET_DELAY`, `disrupt` also slows one cosigner down without stopping it: the hook adds
delay on that cosigner's Kubernetes node alone, under the steady stream, with the driver's
deadlines and each leader policy of `--slow-node` (default `2500:sticky,2500:rotate,6000:rotate`).
Each scenario records the slow cosigner, the policy and every cosigner's share of the signatures
it led and took part in (`node_shares`, from `rutli_sign_requests_total` and
`rutli_sign_journal_entries_total`), and the failovers by code.

- At 2.5 s, under the 5 s sign-attempt deadline, nothing demotes the slow cosigner. Under
  `rotate` it takes part in about 2/3 of the signatures, against about 1/2 under a healthy sticky
  leader: the trade-off of rotating.
- At 6 s, every signature that starts at the slow cosigner fails over after 5 s and demotes it
  for 60 s. Then one signature in each recovery period tries it again.

Every signature must still succeed.

## Provider hooks

What only the infrastructure can do — power a machine off, detach a disk, cut the network — goes
through hook executables named by environment variables. Each is called with `start` once the
scenario's load runs, and then with `stop`, also when `start` or the load failed, with
`KUBECONFIG` and `RUTLI_NAMESPACE` set. Both must exit 0:

| Variable | Arguments | Expected effect |
|---|---|---|
| `HOOK_KILL_NODE` | `start\|stop NODE` | the Kubernetes node stops answering / runs again |
| `HOOK_DETACH_VOLUME` | `start\|stop NODE NAMESPACE/PVC` | the volume behind the claim disappears from the node / comes back |
| `HOOK_PARTITION` | `start\|stop NODE_A NODE_B` | no traffic between the two nodes / restored |
| `HOOK_NET_DELAY` | `start\|stop MS NODE...` | MS milliseconds added to the nodes' traffic / removed |

Each disruption's result splits the latency by the cosigner that answered (`by_leader`), which
shows which leaders waited on the disruption.

Without `HOOK_KILL_NODE` the suite falls back to Kubernetes alone (`node-cordon`): it cordons the
cosigner's node and deletes its pod, which then stays Pending (its volume and the other cosigners
keep it off the other nodes) until the node is uncordoned at the end of the scenario. That is a
cosigner gone for the length of the scenario, not a machine that stops answering: its peers see
refused connections, not timeouts. The other three are skipped and listed under `skipped` in the
result.

`scripts/perf/hooks/` holds examples for kind (pausing a node's container; iptables rules in the
node containers between the two cosigner pods), which CI uses. Hooks for a real provider live with the cluster's own tooling.

## The load profile

[`scripts/perf/profiles/devnet-validator.json`](../scripts/perf/profiles/devnet-validator.json) is
the load of a DevNet validator, measured over 7 days from its cosigners' metrics:

| Measure | Value |
|---|---|
| Signatures a day | 5 470 (0 errors) |
| Average rate | 0.063 /s |
| 1-minute rate: median / p99 / max | 0.044 / 0.44 / 0.87 /s |
| Shortest burst seen | 2.3 /s |
| Sign sessions open at once, max | 7 |
| Sign latency at the leader, p50 / p99 | 88 ms / 212 ms |
| Hosted-key operations (ECDH, decrypt) | none |

x1 is the shape of that load: each ramp step runs the average for 120 s, the busiest minute for
60 s and the burst for 10 s, every rate times the step's factor.

```json
{
  "name": "devnet-validator",
  "slo": { "p99_ms": 1000 },
  "steady": { "sign_per_sec": 20, "secs": 60 },
  "real": [
    { "name": "average", "per_sec": 0.063, "min_secs": 60 },
    { "name": "busiest minute", "per_sec": 0.87, "min_secs": 60 },
    { "name": "burst", "per_sec": 2.3, "min_secs": 0 }
  ],
  "baseline": {
    "sign_keys": 2, "ecdh_keys": 0,
    "phases": [
      { "name": "average", "sign_per_sec": 0.063, "secs": 120 },
      { "name": "busiest-minute", "sign_per_sec": 0.87, "secs": 60 },
      { "name": "burst", "sign_per_sec": 2.3, "secs": 10 }
    ]
  },
  "factors": [1, 3, 10, 20, 30, 45, 70, 100, 150, 200, 300],
  "keys": { "counts": [1, 11, 100], "sign_per_sec": 5, "secs": 60 },
  "connect": { "clients": [50, 200, 500] },
  "diagnose": { "sign_per_sec": 1, "factors": [30, 50, 70, 100, 130, 160, 200, 250, 300], "step_secs": 120, "key_counts": [2, 20, 200] },
  "max_rss_mib": 256
}
```

The run reports headroom three ways:

- the **headroom factor**: how many times the whole shape the cluster carries within the SLO and
  without an error. The burst gives out first, so this is about the burst's headroom;
- `real_load_headroom`, against each measure in `real`: the highest signing rate that passed in a
  phase long enough to stand for it (`min_secs`: a busiest minute needs a phase of a minute or
  more, a burst does not), divided by the measure's rate. `lower_bound` marks a measure whose
  phases never failed (the factors ran out first);
- with `--diagnose`, `plateau_vs_real`: the diagnosis's highest throughput divided by each measure.

One quiet validator is a floor, not a forecast: a validator with busy applications, or a super
validator, signs more. The steady stream of the disruption suite (20 /s) is far above this load on
purpose, so that a recovery is measured in signatures, not in seconds of silence. Without
`phases`, a profile's `baseline` is one phase of `step_secs` with its own rates.

[`synthetic-ecdh.json`](../scripts/perf/profiles/synthetic-ecdh.json) is **not** a measurement:
signing plus hosted-key ECDH, for clusters that host encryption keys. The measured validator sends
no ECDH. The hosted-key decryption limit is per key and node
(`hosted_keys.decrypt_rate_limit_per_min`, 6000 by default): spread a high decryption rate over
enough `ecdh_keys`, or the ramp measures the limit. `scripts/perf/profiles/smoke.json` is the short
profile CI uses; its numbers mean nothing.

## The migration suite

The cosigner half of a migration, on the cluster under test, run by `scripts/e2e-migration.sh` itself
(`E2E_ENV=k8s E2E_STAGES=ceremony`), so the cluster runs the same procedure and the same checks
as the Compose end-to-end test, not a second copy:

1. **The key.** B1's Canton 3.6.1 namespace key, exported with a password by
   `keys.secret.download_to` (`frost/canton-key/testdata/vectors`), stands for Step 2's export:
   there is no participant on the cluster. Its key id is `perf-mig<run>-frost-import-cb0e86a9`,
   with a new prefix every run, because an imported id can never be deleted.
2. **Recipient requests and Gate 0.** `share-recipient` and `recipient-sas` run in each cosigner
   pod (`kubectl exec … -c cosigner`, never a second mount of its volume). The SAS of each request
   must equal the one read back from the node's sealed state.
3. **The dealer** runs in a pod of its own, `rutli-perf-dealer`:
   - no service account token, no network (a NetworkPolicy denies every connection), its work
     directory in memory, a new pod every run;
   - the NetworkPolicy holds only where the network plugin enforces policies, and other policies
     in the namespace add to it. Before anything is copied in, the pod tries to reach cosigner 1,
     the API service, its nameserver and `1.1.1.1:443`, and to
     resolve a name through its resolver; only a timeout or no answer on every one counts as
     isolated, and anything reachable fails the suite. The kind
     job passes `--allow-unisolated-dealer`: kind's default plugin enforces no policies, and its
     key is the public test vector. The result records `dealer_isolated`;
   - the cosigner pods' and the load generator's `/tmp`, where the requests, bundles and founding
     backups go, must be memory-backed, or the suite stops before copying anything;
   - after the ceremony (or a timeout, or a SIGTERM to the suite) the suite deletes the dealer pod
     and waits until it is gone, and removes the ceremony's files from the cosigners' `/tmp` and
     its local work dir, even when the script was killed; the pod also has a 30-minute deadline of
     its own, and the next run first deletes what a killed run left;
   - a run that passed but could not remove its files from the pods' `/tmp` (or the dealer's
     NetworkPolicy) fails; after a failed run, a node that had installed its share keeps it, under
     the run's own key id;
   - a failure is recorded as the step it happened in and the exit code, never the script's
     output; to see that, run `scripts/e2e-migration.sh` by hand with `E2E_ENV=k8s KEEP=1`;
   - one suite run per namespace: two runs share the cosigners and their `/tmp`;
   - the export password reaches the dealer through stdin, never in a command line;
   - files reach it and leave it through the machine that runs the suite;
   - it must refuse a wrong password, no password and a wrong fingerprint, then split with
     `--confirm-sas`.
4. **Gates A to C** (all checks of `scripts/e2e-migration.sh`):
   - a dry run on every node, then the install; an identical re-import is accepted;
   - `verify-key --sign-test` with the operator certificate, from the load generator pod, every
     2-of-3 quorum signing;
   - a refresh with the refresher certificate;
   - `verify-key` again: same group key, new digest, refresh count 1;
   - the dealt bundles refused after the refresh;
   - founding backups.
5. **Step 8, the cosigner half.** The export copy, the dealer output and the request files are
   shredded on the suite's machine, and the dealer pod and its memory go. Then: no recipient
   secret left on any node, the founding backups still there, no copy of the export left (by
   sha256), and `verify-key --sign-test` still passing.
6. **The Signer API.** The imported key signs under the driver's deadlines. With the production
   profile, it becomes the first tenant's namespace-class key: it signs during every disruption
   and during the upgrade, and the namespace rate limit (`perf-mig*`, 10 a minute) is checked on
   it.

**Dealer and cosigners from one release.** With the upgrade suite, the cosigners start on the
previous release (`k8s-deploy.sh --previous`). The dealer must then be of that release:
`--dealer-image` names an image built from that tag's sources with `frost/Dockerfile.dealer`, as
the kind job does. Without it, the migration suite is skipped and says why. Without the upgrade
suite, the dealer is the load generator's image (`frost/Dockerfile.perf` builds `rutli-dealer`
too).

**Covered only by the Compose end-to-end test** (`scripts/e2e-migration.sh`, Canton 3.6.1):
- the export from a live participant;
- Steps 4 to 7 in Canton (the new participant, `register_kms_signing_key`, the identity and the
  OTK, the rollback before the point of no return, party hosting, commitments, the driver's
  audit);
- the participant database's destruction.

**Covered nowhere automated:**
- Step 6 (the Splice re-onboarding);
- Step 2.1 on Canton 3.7;
- the destruction of database backups, WAL and object storage.

These differ from [migration.md](migration.md) on purpose:
- a public test key, not a live one;
- a key prefix per run;
- the dealer in a pod on the same cluster, not on an air-gapped host;
- the SAS read back by the script, with no witnesses;
- founding backups in the pods' memory, not shipped;
- one refresh.

## The production profile

`k8s-deploy.sh` installs Rütli with `profile: production`
([production-profile.md](production-profile.md)), so every suite runs on the configuration
operators are told to run; the rendered config passes `check-config` with no required finding.
What it sets, per throwaway installation:

- two tenants, as on a cluster serving two validators: driver certificates `driver` and `driver-b`,
  each pinned (`signer_pins`) and limited to its key prefixes (`signer_acl`: `perf-` and
  `rutli-perf-`, `tenantb-`);
- the operator and refresher roles, `signer_may_refresh: false` (`limit-ceremony` refreshes with
  the refresher's certificate), intents required, `require_epoch_match`;
- key-file v2 with a fresh `cluster_uuid`, `accept_v1: false`, and `clusterId` pinned to the id
  derived from the run's CA;
- rate limits: far above any real load for signing keys (a million a minute per key: production
  refuses 0, and the ramp must measure the cluster, not the brake), 10 a minute and 200 a day for
  the namespace-class keys (`perf-frost-namespace`, `tenantb-frost-namespace`), 120 a minute for
  `perf-limited*`.

One advisory finding remains on purpose: no `quorum` approval rule for the namespace keys. Such a
rule makes every namespace signature wait for human approvals, which an unattended run cannot
give.

[`scripts/perf/profiles/production.json`](../scripts/perf/profiles/production.json) is the
matching load profile: the measured shape of `devnet-validator` for each tenant's signing keys,
and three key classes. On a DevNet cluster serving two validators, practically all signatures
are made with protocol signing keys (DKG keys); a namespace key signs a handful of times a month,
and a hosted encryption key served 9 operations in 30 days. So the signing class carries the
ladder and the disruption load, and the other two get the spot checks above, where a failure
means a topology change or a decryption that does not happen during an incident.

The previous release that `--previous` installs reads the same values: it understands every
setting above except `profile` and the peer pins, which it ignores.

## On a hardened cluster

The chart's pods already run under Pod Security `restricted`, with a read-only root file system,
no service account token, and their own NetworkPolicies:

- **Cosigners, ingress**: gRPC (9101) from each other and from pods labelled `rutli.io/client=true`
  in namespaces labelled `rutli.io/client-ns=true`; metrics (9200) from pods labelled
  `rutli.io/scraper=true` in any namespace.
- **Cosigners, egress**: each other on 9101, and DNS.

The suite adds one NetworkPolicy for its load generator
([`scripts/perf/k8s/loadgen.yaml`](../scripts/perf/k8s/loadgen.yaml)): no ingress; egress to the
cosigners on 9101 and 9200 and to DNS. The pod itself is `restricted` too, with a read-only root
file system and a small in-memory `/tmp`.

`k8s-deploy.sh` labels the namespace `rutli.io/client-ns=true` and
`pod-security.kubernetes.io/enforce=restricted`, and annotates it `rutli-perf/installed=true`:
`uninstall` refuses a namespace without that annotation, and deletes only objects labelled
`rutli-perf/suite=1` (the cosigners' volumes included) and the release. The seal bundles are
generated in a short-lived pod of the image the cosigners start on, the previous release with
`--previous`. Where the suite may not label namespaces, the
namespace's owner sets both before the install.

If the cluster's policies restrict DNS to the cluster DNS pods, or admit only signed or
allow-listed images, adjust them for the namespace; that is site policy, not something the suite
can know.

The load generator mounts a cosigner certificate of the test installation, to call the Peer API's
`ListKeys` for the key-count suite. It is a throwaway certificate of a throwaway CA; never point
the suite at a namespace that holds real keys.

## Load through a Canton participant

Today the load generator drives the cosigners' Signer API directly, as the driver does.
`--load-path canton` is the entry point for load through a Canton participant with the driver: set
`CANTON_LOAD_CMD` to a command that takes the arguments of `rutli-loadgen ... sign` (`--key`,
`--rate`, `--clients`, `--duration-secs`, `--count`, `--name`) and prints the same JSON report
(`LoadReport` in `frost/loadgen/src/main.rs`). Every suite then sends its signatures that way;
the rest of the suite is unchanged. No such command exists yet.

## The result

`cluster.json` holds the scenarios (as in `load-testing.md`), `skipped`, `keys` (per key count:
sign latency, server-side histogram, `ListKeys` per cosigner), `ramp` (per step: rates, p95/p99
per operation, why it stopped), and these top-level numbers: `headroom_factor`; per
disruption, `time_to_healthy_secs` (until every cosigner answered Health ok again) and
`recovery_secs` (until the cluster signed within the SLO again), both from the end of the
disruption.

`peer_calls` lists every place the run read the cosigners' `rutli_peer_call_duration_seconds`:
each scenario (from its first load), each ramp step's phase and each diagnosis step. Per call
class (`sign_round1`, `sign_round2`, `abort`, `control`, `local_share`) it gives the count, the
p50/p99/p99.9 interpolated in the buckets, the deadline, and the share of calls within a third of
it. That share is read at the bucket edge there, so it is exact. `margin_3x` holds when at least
99.9 % of the calls finished within a third of the deadline: the rule by which a deadline stays a
constant (#249). The report prints the table and flags every call without that margin. A flag is
a readout, not a failure: it does not change the exit code.

`failed` lists what Rütli failed: a check about the cluster's behaviour. `rig_failed` lists what
only the test rig failed: a load generator that could not be started, reached or read, a hook or
`kubectl` error; such a scenario says nothing about Rütli and should be run again. `cluster.py`
exits 1 when Rütli failed something, 3 when only the rig did, 0 otherwise. A rig failure inside
the ramp stops it without a verdict on that step; its headroom factor is then a lower bound
(`headroom_is_lower_bound`).

`scripts/perf/compare.py PREVIOUS CURRENT` fails on

- a p95 or p99 more than 20 % above the previous run's, for the latency scenarios, each ramp step
  both runs passed, and each key count (sign latency and the slowest cosigner's `ListKeys`);
- a lower headroom factor than the previous run's (with the same profile);
- any failed scenario of the current run.

It does not compare the latency of two runs whose cosigners were placed differently (another zone,
or another node where a zone is not labelled, for any cosigner id; the load generator does not
count): the report says `NOT COMPARED` with both placements and ends with "Latency NOT
COMPARED" instead of "No regression". A run that did not record its placement, or a cosigner's
node, compares only with another run without one: the first run after this change is not compared
with older ones. A comparison not made does not change the exit code.

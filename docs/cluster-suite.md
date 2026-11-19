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

## Running it

```sh
export KUBECONFIG=...
scripts/perf/k8s-deploy.sh install --namespace rutli-perf --previous \
  --image <registry>/rutli-perf:<tag> --work ./perf-work [--storage-class NAME] [--pull-secret NAME] [--values extra.yaml]

scripts/perf/cluster.py --namespace rutli-perf --profile scripts/perf/profiles/placeholder.json \
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
| `upgrade` | `helm upgrade` from the previous release to `--upgrade-image` under 5 signatures a second | a key is missing or changed afterwards, or does not sign; signatures that fail while the cosigners restart are counted, not forbidden (the chart restarts all three at once) |
| `scenarios` | the scenarios of [`load-testing.md`](load-testing.md): steady stream, burst, several clients, ECIES, a cosigner pod killed under load, the cold-cache restart, and the limits | as described there |
| `disrupt` | under the steady stream: a node lost, a data volume lost, a partition between two cosigners' nodes, added network delay; afterwards, rounds of signatures until the cluster signs within the SLO again (`recovery_secs`) | a signature fails, a cosigner is not healthy afterwards, or the cluster does not sign normally again within `--settle-secs` (600); a step without its hook is reported as skipped |
| `keys` | for each key count of the profile (1, 10, 100): that many FROST keys and hosted keys over ten tenant prefixes (`perf-t<n>-…`), sign latency over all of them, and each cosigner's Peer API `ListKeys` time | a setup, signature or listing fails |
| `ramp` | the profile's baseline load × 1, 3, 10, 30, 100, … for `step_secs` each | never: the ramp stops at the first step over the SLO or with an error, and reports the last step that passed as the **headroom factor** |

They run in the order `upgrade`, `scenarios`, `keys`, `ramp`, `disrupt` (disruption last, so that
what it leaves behind cannot skew the measurements of the others); `--suites` picks a subset.
Every scenario also checks that no cosigner restarted unless the scenario did it, and that their
memory and file descriptors stay within bounds.

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

Without `HOOK_KILL_NODE` the suite falls back to Kubernetes alone (`node-cordon`): it cordons the
cosigner's node and deletes its pod, which then stays Pending (its volume and the other cosigners
keep it off the other nodes) until the node is uncordoned at the end of the scenario. That is a
cosigner gone for the length of the scenario, not a machine that stops answering: its peers see
refused connections, not timeouts. The other three are skipped and listed under `skipped` in the
result.

`scripts/perf/hooks/` holds examples for kind (pausing a node's container; iptables rules in the
node containers between the two cosigner pods), which CI uses. Hooks for a real provider live with the cluster's own tooling.

## The load profile

A JSON file ([`scripts/perf/profiles/placeholder.json`](../scripts/perf/profiles/placeholder.json)):

```json
{
  "name": "placeholder",
  "slo": { "p99_ms": 1000 },
  "steady": { "sign_per_sec": 20, "secs": 60 },
  "baseline": { "sign_per_sec": 1, "sign_keys": 2, "ecdh_per_sec": 0.2, "ecdh_keys": 1 },
  "step_secs": 300,
  "factors": [1, 3, 10, 30, 100, 300],
  "keys": { "counts": [1, 10, 100], "sign_per_sec": 5, "secs": 60 },
  "max_rss_mib": 256
}
```

`baseline` is the load of one participant: signatures and ECIES decryptions per second, and over
how many keys. The shipped numbers are placeholders; real ones come from the soak cluster's
metrics (`rutli_sign_requests_total`, `rutli_hosted_key_ops_total`). The hosted-key decryption
limit is per key and node (`hosted_keys.decrypt_rate_limit_per_min`, 6000 by default): spread a
high decryption rate over enough `ecdh_keys`, or the ramp measures the limit.
`scripts/perf/profiles/smoke.json` is the short profile CI uses.

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
per operation, why it stopped) and `headroom_factor` at the top.

`scripts/perf/compare.py PREVIOUS CURRENT` fails on

- a p95 or p99 more than 20 % above the previous run's, for the latency scenarios, each ramp step
  both runs passed, and each key count (sign latency and the slowest cosigner's `ListKeys`);
- a lower headroom factor than the previous run's (with the same profile);
- any failed scenario of the current run.

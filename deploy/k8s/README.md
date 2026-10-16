# Rütli on Kubernetes

Runs the FROST cosigner cluster as one single-replica StatefulSet per node, with mutual TLS, sealed
shares under a **per-node seal bundle**, per-pod durable storage, per-pod backup sidecars and a
locked-down network. The Rütli *driver* itself is not a workload here — it runs in-process inside
your Canton participant (a jar on its classpath); §4 shows how to point it at this cluster.

```
namespace.yaml         rutli namespace (Pod Security: restricted)
cosigner.yaml          GENERATED from the Helm chart (scripts/render-k8s.sh + values.yaml):
                       per node a StatefulSet rutli-cosigner-n<id>, a Service rutli-node-<id>, a data
                       PVC and a backup PVC; the config, headless Service, NetworkPolicy, PDB
values.yaml            the chart values cosigner.yaml is rendered with
client-config.yaml     client configs for the operator CLI Jobs (driver / operator role)
cronjob-refresh.yaml   opt-in, NOT YET: weekly proactive share refresh (driver cert only)
job-verify-key.example.yaml  split ceremony: one-off verify-key with a temporary operator cert
secrets.example.yaml   shape of the Secrets you create out-of-band (never commit real ones)
kustomization.yaml     applies namespace + cosigner.yaml + client-config.yaml
```

Do not edit `cosigner.yaml` by hand: change `values.yaml` (or the chart) and run
`scripts/render-k8s.sh`; CI fails when the file is stale, and runs
`scripts/check-deploy-policy.sh` on the kustomize build.

Prereqs: a NetworkPolicy-enforcing CNI (Calico/Cilium), a default StorageClass, and a registry you
can push to.

## 1. Build & push the cosigner image

```sh
docker build -t ghcr.io/stakecraft/rutli-cosigner:$(git rev-parse --short HEAD) -f frost/Dockerfile frost
docker push ghcr.io/stakecraft/rutli-cosigner:$(git rev-parse --short HEAD)
# set the tag in kustomization.yaml (images:) to what you pushed
```

## 2. Create the Secrets (mTLS + per-node seal bundles)

```sh
kubectl create namespace rutli
scripts/gen-frost-certs.sh 3 ./certs          # CA + per-cosigner certs (CN/SAN cosigner<id>)

kubectl -n rutli create secret generic rutli-cosigner-ca --from-file=ca.crt=certs/ca.crt
for i in 1 2 3; do                            # one kubernetes.io/tls Secret per cosigner
  kubectl -n rutli create secret tls rutli-cosigner-tls-$i \
    --cert=certs/cosigner$i.crt --key=certs/cosigner$i.key
done

for i in 1 2 3; do                            # one seal bundle per node, on a workstation
  rutli-cosigner seal new-node --node $i --out node-$i.json
  kubectl -n rutli create secret generic rutli-seal-node-$i --from-file=node.json=node-$i.json
  shred -u node-$i.json 2>/dev/null || rm -f node-$i.json
done
```

Each bundle holds one node's share DEK and hosted-key distribution seed and nothing else. Keep the
CA key in your secret manager, and keep each node's bundle in a **different trust domain** from that
node's backups (see `docs/disaster-recovery.md`).

## 3. Deploy

```sh
kubectl apply -k deploy/k8s
for i in 1 2 3; do kubectl -n rutli rollout status statefulset/rutli-cosigner-n$i; done
kubectl -n rutli get pods -l app.kubernetes.io/name=rutli-cosigner   # rutli-cosigner-n{1,2,3}-0 Running
kubectl -n rutli logs rutli-cosigner-n1-0 -c cosigner | grep -E 'mutual TLS enabled|share sealing enabled \(bundle node=1\)'
```

No key exists yet — DKG runs when the key is first requested (§4). Other `t`-of-`n`: set
`replicaCount`/`threshold` in `values.yaml`, re-render, and add certs and bundles.

## 4. Point the Canton driver at the cluster

The driver runs inside the Canton participant. In that pod: put `rutli-driver.jar` on the classpath
(`EXTRA_CLASSPATH`), label the pod `rutli.io/client: "true"` (so the NetworkPolicy admits it), and
use a `crypto.kms` config like:

```hocon
canton.participants.participant1.crypto {
  provider = kms
  kms {
    type = driver
    name = "rutli"
    config = {
      backend = "frost"
      frost = {
        # One entry per node: its Service, and the certificate name it must present.
        endpoints = [
          { url = "rutli-node-1.rutli.svc.cluster.local:9101", tls-name = "cosigner1" },
          { url = "rutli-node-2.rutli.svc.cluster.local:9101", tls-name = "cosigner2" },
          { url = "rutli-node-3.rutli.svc.cluster.local:9101", tls-name = "cosigner3" }
        ]
        delegate = "hsm"            # non-namespace keys; "software" only for testing
        tls = { ca-cert = "/certs/ca.crt", cert = "/certs/driver.crt", key = "/certs/driver.key" }
      }
      audit-log-path = "/var/rutli/audit.jsonl"
      # tighten to `approval { … }` for the namespace key after the key ceremony (docs/key-ceremony.md)
    }
  }
  signing.keys.default = ec-curve-25519
  signing.algorithms.default = ed-25519
}
```

Mount the driver client cert (`driver.crt/key` from step 2's `gen-frost-certs.sh`) into the Canton
pod. On the participant's first init it runs the DKG across the cluster and the namespace key is born
distributed — do this as the witnessed **key ceremony** (`docs/key-ceremony.md`).

## 5. Cluster-hosted keys (optional)

**Cluster-hosted keys** put the RSA-2048-OAEP encryption keypair and the AES-256-GCM symmetric key
Canton needs in the cluster rather than on an HSM or in the driver's software backend. They are off
in `values.yaml`, because they need two per-cluster public values a checked-in manifest cannot know:
one `hostedKeys.commitmentKey` for the cluster (`openssl rand -hex 32`) and each node's
`distPublicKey` (printed by `seal new-node`, or `rutli-cosigner seal inspect --in node-<i>.json`).
Put them into `values.yaml` and re-render, or install the chart with them:

```yaml
hostedKeys:
  enabled: true
  commitmentKey: "<64 hex>"
nodes:
  - { id: 1, distPublicKey: "<64 hex>" }
  - { id: 2, distPublicKey: "<64 hex>" }
  - { id: 3, distPublicKey: "<64 hex>" }
```

A node on a seal bundle knows its peers' distribution keys only by these pins, checks its own at
startup, and never wraps key material to a peer reporting a different one.

These are **replicated whole keys, not threshold shares**: generated on one cosigner, wrapped per
recipient and copied to the others, sealed at rest on each PV, and any node can serve a decrypt. The
Ed25519 namespace key is unchanged — still 2-of-3 FROST, never replicated between pods. One
compromised cosigner yields the hosted keys, and because they protect Canton's per-view session
keys, an attacker who extracts one gains *retrospective* read access to recorded traffic encrypted
to it; rotation fixes the future, not the past. The gain is relocation — key material leaves the
participant pod for three hardened single-purpose pods.

Then in the driver config from §4, add `hosted-keys = true` to the `frost` block; once no local key
state is wanted at all, `delegate = "none"` replaces `delegate = "hsm"`. There is deliberately no
fallback to the delegate on `NOT_FOUND` — that would silently split custody.

Ops notes: hosted keys land in the same `/data/keys` directory as the shares, so the backup
sidecar and a `restore` already cover them. Alert on `rutli_anti_entropy_conflicts_total` — any
increase means two pods disagree about the same key id, which is never auto-reconciled and always
needs a human.

See [`docs/hosted-keys.md`](../../docs/hosted-keys.md).

## Secrets: what each pod sees

Each cosigner holds one mTLS identity (which also signs split-ceremony recipient requests) and one
seal bundle, so one node must not be able to act as, or decrypt for, another.

- **The pod of node `<id>` references only `rutli-cosigner-ca`, `rutli-cosigner-tls-<id>` and
  `rutli-seal-node-<id>`**, mounted as files. The seal bundle is mounted into the `cosigner`
  container only; there is no seal env var and no init container that sees other nodes' material.
  Kubernetes' node authorizer therefore lets a kubelet read only the Secrets of the pods it runs:
  root on one host yields one node's keys, below threshold (audit C3).
- **Residual risk, stated plainly:** anyone with `get secrets` in this namespace, or cluster-admin,
  still reads every node's Secret. Restrict `secrets` RBAC to the people who could run the ceremony
  anyway; for genuinely separate trust domains run each cosigner in its own cluster/account.
- The refresh CronJob mounts only the driver's cert (`rutli-driver-tls`); the operator cert for
  `verify-key` is never a standing Secret (`job-verify-key.example.yaml` creates and deletes it).
- Each node verifies each peer under the peer's own TLS name (`cosigner<id>`) and identifies a mesh
  caller by its exact client CN (audit M3); the driver does the same per endpoint (§4).
- Certificates and bundles are read at startup: after rotating a Secret, restart that pod.

### Migrating an earlier install

The previous manifests in this directory (StatefulSet `cosigner`, pods `cosigner-0..2`, shared
`rutli-seal` env master, exec-based backup CronJob) are replaced. Moving an install without losing
its shares follows the same steps as the Helm migration in
[`docs/runbook-per-node-seal.md`](../../docs/runbook-per-node-seal.md): split the master offline
with `rutli-cosigner seal split-legacy` (each node keeps its DEK — nothing is re-sealed), create the
per-node Secrets, and render `values.yaml` with `nodes[].existingClaim` set to the old claims
(`data-cosigner-0..2`). Then delete the old StatefulSet `cosigner` (its claims stay: a StatefulSet
does not delete its claims by default), so the old pods release the volumes, and apply. Expect a
short full signing gap while the volumes re-attach.

### Migrating from the shared TLS Secret (≤ 0.3.x layout)

Earlier manifests mounted one Secret `rutli-cosigner-tls` (`ca.crt` + every `cosigner<i>.{crt,key}`)
into every pod. The per-node layout needs one `kubernetes.io/tls` Secret per node; create them from
the old Secret without changing any certificate:

```sh
umask 077; d=$(mktemp -d)                    # tmpfs if you have one; delete afterwards
kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > $d/ca.crt
kubectl -n rutli create secret generic rutli-cosigner-ca --from-file=ca.crt=$d/ca.crt
for i in 1 2 3; do
  kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath="{.data.cosigner$i\.crt}" | base64 -d > $d/c.crt
  kubectl -n rutli get secret rutli-cosigner-tls -o jsonpath="{.data.cosigner$i\.key}" | base64 -d > $d/c.key
  kubectl -n rutli create secret tls rutli-cosigner-tls-$i --cert=$d/c.crt --key=$d/c.key
done
rm -rf $d
```

Then, once every pod is Ready and signing, delete `rutli-cosigner-tls`. If you run the refresh
CronJob, create `rutli-driver-tls` from the driver's cert first. The `ca.crt` bytes must not change
(the split ceremony's cluster id is a hash of them), which copying it as above guarantees.


## Never mount a cosigner volume into another pod

A cosigner's data PVC is mounted by that cosigner's pod and by nothing else, ever — not a backup
Job, not a debug pod. On 2026-10-07 the DevNet soak lost all signing for five minutes (54 failed
signs) because a backup CronJob bound `cosigner-0`'s ReadWriteOnce claim into a second pod on the
same node: the extra mount left `/data/keys` unreadable to the running cosigner, which stayed in
rotation and answered every Sign with `INTERNAL` until the pod was restarted
(`docs/soak-2026-10-devnet.md`, incident #1). The backup sidecar runs **in the cosigner's own pod**
and mounts the same volume read-only. A CSI volume snapshot is fine (storage layer, no second mount).

## Day-2 operations

- **Backup**: each pod's `backup` sidecar copies that node's sealed `keys/*.json` daily (03:17 UTC,
  and once at pod start) to that node's backup PVC `rutli-cosigner-backup-n<id>`, keeping the newest
  14. It mounts the data volume read-only and never sees the seal bundle or the TLS key. Check it:
  `kubectl -n rutli logs rutli-cosigner-n1-0 -c backup | grep BACKUP_`. For an off-cluster
  destination, render with `backup.destination.type: script` and per-node credentials (chart
  README, "Backups"). There is no backup CronJob and no `pods/exec` RBAC: the exec-based backup of
  earlier releases could read every node's seal secret (audit C3).
- **Proactive refresh**: **not until the ceremony fixes ship** (audit C1/H1 — see
  `docs/runbook-per-node-seal.md`). Then: `rutli-cosigner --config /config/client-driver.json refresh --key-id frost-<participant>-namespace`
  with the driver's identity (a cosigner cert is not on `signer_allowlist`) — same key, rotated
  shares. Example CronJob: `cronjob-refresh.yaml` (set `KEY_ID`; mounts only `rutli-driver-tls`).
  Refresh fences signing cluster-wide; avoid topology bursts mid-refresh.
- **Restore** a replaced node: its data PVC is empty → copy the newest tar out of its backup PVC
  and restore through the cosigner's own container (`docs/disaster-recovery.md`), then delete the
  pod so the daemon reopens its key store. Or (once shipped) repair from `t` survivors.
- **Monitoring**: pods expose Prometheus `/metrics` on port 9200 (`prometheus.io/*` annotations set;
  label your scraper pod `rutli.io/scraper: "true"` for the NetworkPolicy). Alert rules + Grafana
  dashboard in `deploy/monitoring/`; metric reference in `docs/observability.md`.
- **PDB**: one PodDisruptionBudget over every node's pod keeps `minAvailable: 2` so voluntary drains cannot drop below threshold.
- **Probes**: readiness is `rutli-cosigner … health` (exec): the key store under `/data/keys` must
  be listable, openable and writable and the gRPC port open, so a pod whose volume breaks shows
  `READY 0/1` (and counts against the PDB / holds a rollout) instead of looking healthy while it
  fails every Sign. It does **not** take the pod out of the driver's `frost.endpoints`:
  the per-node Services publish not-ready addresses because the mesh needs them during DKG, so routing
  around a sick node is the driver's failover plus the node itself answering `UNAVAILABLE` to
  anything that needs its key store and refusing to join other leaders' quorums. Liveness stays a
  TCP check on purpose — a restart does not fix a volume and discards the evidence. Alert:
  `RutliKeystoreUnreadable`. `health` exists since 0.3.1; the probe calls it without a fallback,
  so the image pin must be ≥ 0.3.1.

## Notes / hardening

- Image tag defaults to `0.4.0-rc.1`. After you push, pin by digest:
  `kustomize edit set image ghcr.io/stakecraft/rutli-cosigner@sha256:…`
- Required pod anti-affinity + zone topology spread are in every node's StatefulSet (on the shared
  labels, so they apply across nodes).
- Label the Canton **namespace** `rutli.io/client-ns=true` and the participant pod
  `rutli.io/client=true` (NetworkPolicy requires both).
- For genuinely separate trust domains, run each cosigner in a **separate cluster/account/region**,
  not just separate nodes; then this manifest is the per-domain unit and the peer endpoints are
  cross-cluster addresses.
- Consider sealing each share in an enclave/HSM (the `share_seal` seam) once available.

# Rütli on Kubernetes

Runs the FROST cosigner cluster as a StatefulSet with mutual TLS, sealed shares, per-pod durable
storage, and a locked-down network. The Rütli *driver* itself is not a workload here — it runs
in-process inside your Canton participant (a jar on its classpath); §4 shows how to point it at this
cluster.

```
namespace.yaml         rutli namespace (Pod Security: restricted)
cosigner-config.yaml   per-node cosigner configs (mTLS, sealing, headless-DNS peers)
service.yaml           headless service -> stable pod DNS (cosigner-0.rutli-cosigner …)
statefulset.yaml       3 cosigners, 1 durable PVC each, non-root + read-only rootfs
networkpolicy.yaml     signing port reachable only from the mesh + the Canton driver
pdb.yaml               minAvailable 2 — voluntary drains cannot drop below threshold
cronjob-backup.yaml    opt-in: nightly `backup` run INSIDE each cosigner via kubectl exec, shipped off-cluster
cronjob-refresh.yaml   opt-in: weekly proactive share refresh (driver cert only)
job-verify-key.example.yaml  split ceremony: one-off verify-key with a temporary operator cert
secrets.example.yaml   shape of the Secrets you create out-of-band (never commit real ones)
kustomization.yaml     applies everything except the Secrets and the opt-in CronJobs
```

Prereqs: a NetworkPolicy-enforcing CNI (Calico/Cilium), a default StorageClass, and a registry you
can push to.

## 1. Build & push the cosigner image

```sh
docker build -t ghcr.io/stakecraft/rutli-cosigner:$(git rev-parse --short HEAD) -f frost/Dockerfile frost
docker push ghcr.io/stakecraft/rutli-cosigner:$(git rev-parse --short HEAD)
# set the tag in kustomization.yaml (images:) to what you pushed
```

## 2. Create the Secrets (mTLS + seal master)

```sh
kubectl create namespace rutli
scripts/gen-frost-certs.sh 3 ./certs          # CA + per-cosigner certs (shared `rutli-cosigner` SAN)

kubectl -n rutli create secret generic rutli-cosigner-ca --from-file=ca.crt=certs/ca.crt
for i in 1 2 3; do                            # one kubernetes.io/tls Secret per cosigner
  kubectl -n rutli create secret tls rutli-cosigner-tls-$i \
    --cert=certs/cosigner$i.crt --key=certs/cosigner$i.key
done

kubectl -n rutli create secret generic rutli-seal \
  --from-literal=RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"   # from your secret manager in prod
```

Keep the CA key and the seal master in your secret manager; keep the seal master in a **different
trust domain** from your share backups (see `docs/disaster-recovery.md`).

## 3. Deploy

```sh
kubectl apply -k deploy/k8s
kubectl -n rutli rollout status statefulset/cosigner
kubectl -n rutli get pods -l app.kubernetes.io/name=rutli-cosigner   # cosigner-0/1/2 Running
kubectl -n rutli logs cosigner-0 | grep -E 'mutual TLS enabled|share sealing enabled'
```

No key exists yet — DKG runs when the key is first requested (§4). Scale/threshold: edit `replicas`
and every config's `threshold` (and add config entries + certs) for other `t`-of-`n`.

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
        endpoints = [
          "cosigner-0.rutli-cosigner.rutli.svc.cluster.local:9101",
          "cosigner-1.rutli-cosigner.rutli.svc.cluster.local:9101",
          "cosigner-2.rutli-cosigner.rutli.svc.cluster.local:9101"
        ]
        delegate = "hsm"            # non-namespace keys; "software" only for testing
        tls = { ca-cert = "/certs/ca.crt", cert = "/certs/driver.crt", key = "/certs/driver.key", domain = "rutli-cosigner" }
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

`cosigner-config.yaml` enables **cluster-hosted keys** on each node, so the RSA-2048-OAEP encryption
keypair and the AES-256-GCM symmetric key Canton needs live in the cluster rather than on an HSM or
in the driver's software backend:

```json
"hosted_keys": { "enabled": true, "write_quorum": 2, "anti_entropy_interval_secs": 300 }
```

It requires `share_seal` (already set here) — a node with hosted keys enabled and sealing off
refuses to start, because a whole private key must never sit unsealed on a PV. Delete the block to
keep those keys on an HSM. With the Helm chart the same switch is `hostedKeys.enabled=true`.

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
CronJob and a `restore` already cover them. Alert on `rutli_anti_entropy_conflicts_total` — any
increase means two pods disagree about the same key id, which is never auto-reconciled and always
needs a human.

See [`docs/hosted-keys.md`](../../docs/hosted-keys.md).

## TLS material: what each pod sees

Each cosigner holds one mTLS identity, and since the split ceremony that identity also signs
recipient requests (`docs/split-ceremony.md`), so one node must not be able to act as another.

- **The cosigner container of pod `cosigner-<o>` sees only `ca.crt` and its own
  `cosigner<o+1>.{crt,key}`.** The `tls-select` init container copies them from the projected
  `tls-src` volume (the CA Secret + every `rutli-cosigner-tls-<i>`) into an in-memory `certs`
  volume; `tls-src` is mounted into the init container only. A compromise of the long-running,
  network-facing cosigner process does not hand over the other nodes' keys.
- **Why not more:** a StatefulSet has one pod template, and Kubernetes cannot mount a different
  Secret per ordinal, so every pod *spec* still references every node's Secret, the kubelet
  materialises all of them for each pod, and the (short, network-less) init container reads them.
  Full per-pod isolation needs one single-replica StatefulSet per node (different pod and PVC
  names — not a drop-in change), or a CSI secrets driver with per-pod identity.
- **Residual risk, stated plainly:** anyone with `get secrets` in this namespace, root on a node
  running a cosigner, or the ability to create pods that mount these Secrets has **every** node's
  key. Restrict `secrets` RBAC in the namespace to the people who could run the ceremony anyway.
- The refresh CronJob mounts only the driver's cert (`rutli-driver-tls`); the operator cert for
  `verify-key` is never a standing Secret (`job-verify-key.example.yaml` creates and deletes it).
- Certificates are read at startup: after rotating a Secret, restart the pods.

### Migrating from the shared TLS Secret (≤ 0.3.x layout)

Earlier manifests mounted one Secret `rutli-cosigner-tls` (`ca.crt` + every `cosigner<i>.{crt,key}`)
into every pod. To move an existing install (e.g. the DevNet soak) without changing any
certificate:

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
kubectl apply -k deploy/k8s                   # rolls the pods one at a time (PDB minAvailable 2)
kubectl -n rutli exec cosigner-0 -c cosigner -- ls /certs   # ca.crt cosigner1.crt cosigner1.key
```

Then, once every pod is Ready and signing, delete `rutli-cosigner-tls`. If you run the refresh
CronJob, create `rutli-driver-tls` from the driver's cert first. The `ca.crt` bytes must not change
(the split ceremony's cluster id is a hash of them), which copying it as above guarantees.

## Never mount a cosigner volume into another pod

A cosigner's `data` PVC is mounted by that cosigner's pod and by nothing else, ever — not a backup
Job, not a debug pod, not a "read-only" sidecar. On 2026-10-07 the DevNet soak lost all signing for
five minutes (54 failed signs) because a backup CronJob bound `cosigner-0`'s ReadWriteOnce claim into
a second pod on the same node: the extra mount left `/data/keys` unreadable to the running cosigner,
whose gRPC health check does not touch the key store, so it stayed in rotation and answered every
Sign with `INTERNAL: io: Permission denied` — and because the driver deliberately does not fail over
on `INTERNAL`, position 0 in `frost.endpoints` blocked the participant until the pod was restarted
(`docs/soak-2026-10-devnet.md`, incident #1). Anything that needs a cosigner's files goes through
`kubectl exec` into the cosigner's own container, which is what `cronjob-backup.yaml` does. A CSI
volume snapshot is fine (storage layer, no second mount); a second mount is not.

## Day-2 operations

- **Backup** each share from *inside* its cosigner — one `kubectl exec` per ordinal, never a second
  mount of its volume:
  `kubectl -n rutli exec cosigner-0 -c cosigner -- rutli-cosigner --config /config/cosigner-1.json backup --out /data/backup-$(date -u +%u)`
  then stream it out:
  `kubectl -n rutli exec cosigner-0 -c cosigner -- tar -C /data -cf - backup-$(date -u +%u) > cosigner-0.tar`.
  `cronjob-backup.yaml` does exactly that nightly for all three pods (a ServiceAccount with `get` +
  `pods/exec` on those pods only, a seven-day rotation under `/data/backup-<weekday>`) and hands the
  tars to `ship.sh` in ConfigMap `rutli-backup-destination` — point that script at your off-cluster
  destination before enabling the file in `kustomization.yaml`; the placeholder fails the Job on
  purpose. Keep the tars in a different trust domain from `rutli-seal`. See `docs/disaster-recovery.md`.
- **Proactive refresh**: `rutli-cosigner --config /config/client-driver.json refresh --key-id frost-<participant>-namespace`
  with the driver's identity (a cosigner cert is not on `signer_allowlist`) — same key, rotated
  shares. Example CronJob: `cronjob-refresh.yaml` (set `KEY_ID`; mounts only `rutli-driver-tls`).
  Refresh fences signing cluster-wide; avoid topology bursts mid-refresh.
- **Restore** a replaced pod: its PVC is empty → stream the tar back in and restore, again through
  the cosigner's own container:
  `kubectl -n rutli exec -i cosigner-1 -c cosigner -- tar -C /tmp -xf - < cosigner-1.tar`, then
  `kubectl -n rutli exec cosigner-1 -c cosigner -- rutli-cosigner --config /config/cosigner-2.json restore --from /tmp/backup-<weekday> --force`
  and `kubectl -n rutli delete pod cosigner-1` so the daemon reopens its key store. Or (once
  shipped) repair from `t` survivors.
- **Monitoring**: pods expose Prometheus `/metrics` on port 9200 (`prometheus.io/*` annotations set;
  label your scraper pod `rutli.io/scraper: "true"` for the NetworkPolicy). Alert rules + Grafana
  dashboard in `deploy/monitoring/`; metric reference in `docs/observability.md`.
- **PDB**: `pdb.yaml` keeps `minAvailable: 2` so voluntary drains cannot drop below threshold.
- **Probes**: readiness is `rutli-cosigner … health` (exec): the key store under `/data/keys` must
  be listable, openable and writable and the gRPC port open, so a pod whose volume breaks shows
  `READY 0/1` (and counts against the PDB / holds a rollout) instead of looking healthy while it
  fails every Sign. It does **not** take the pod out of the driver's `frost.endpoints`:
  `service.yaml` publishes not-ready addresses because the mesh needs them during DKG, so routing
  around a sick node is the driver's failover plus the node itself answering `UNAVAILABLE` to
  anything that needs its key store and refusing to join other leaders' quorums. Liveness stays a
  TCP check on purpose — a restart does not fix a volume and discards the evidence. Alert:
  `RutliKeystoreUnreadable`. `health` exists since 0.3.1; the probe calls it without a fallback,
  so the image pin must be ≥ 0.3.1.

## Notes / hardening

- Image tag defaults to `0.3.2`. After you push, pin by digest:
  `kustomize edit set image ghcr.io/stakecraft/rutli-cosigner@sha256:…`
- Required pod anti-affinity + zone topology spread are in the StatefulSet.
- Label the Canton **namespace** `rutli.io/client-ns=true` and the participant pod
  `rutli.io/client=true` (NetworkPolicy requires both).
- For genuinely separate trust domains, run each cosigner in a **separate cluster/account/region**,
  not just separate nodes; then this manifest is the per-domain unit and the peer endpoints are
  cross-cluster addresses.
- Consider sealing each share in an enclave/HSM (the `share_seal` seam) once available.

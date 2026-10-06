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
secrets.example.yaml   shape of the two Secrets you create out-of-band (never commit real ones)
kustomization.yaml     applies everything except the Secrets
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

kubectl -n rutli create secret generic rutli-cosigner-tls \
  --from-file=ca.crt=certs/ca.crt \
  --from-file=cosigner1.crt=certs/cosigner1.crt --from-file=cosigner1.key=certs/cosigner1.key \
  --from-file=cosigner2.crt=certs/cosigner2.crt --from-file=cosigner2.key=certs/cosigner2.key \
  --from-file=cosigner3.crt=certs/cosigner3.crt --from-file=cosigner3.key=certs/cosigner3.key

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

Ops notes: hosted keys land in the same `/data/keys` directory as the shares, so the existing
`backup`/`restore` CronJobs already cover them. Alert on `rutli_anti_entropy_conflicts_total` — any
increase means two pods disagree about the same key id, which is never auto-reconciled and always
needs a human.

See [`docs/hosted-keys.md`](../../docs/hosted-keys.md).

## Day-2 operations

- **Backup** each share to storage in that pod's trust domain:
  `kubectl -n rutli exec cosigner-0 -- rutli-cosigner --config /config/cosigner-1.json backup --out /data/backup`
  then copy `/data/backup` off-cluster. Example CronJob: `cronjob-backup.yaml` (set the PVC
  `claimName` per ordinal). See `docs/disaster-recovery.md`.
- **Proactive refresh**: `rutli-cosigner --config /config/cosigner-1.json refresh --key-id frost-<participant>-namespace`
  against any pod — same key, rotated shares. Example CronJob: `cronjob-refresh.yaml` (set `KEY_ID`).
  Refresh fences signing cluster-wide; avoid topology bursts mid-refresh.
- **Restore** a replaced pod: its PVC is empty → restore its share with `rutli-cosigner … restore --from <backup> --force`, or (once shipped) repair from `t` survivors.
- **Monitoring**: pods expose Prometheus `/metrics` on port 9200 (`prometheus.io/*` annotations set;
  label your scraper pod `rutli.io/scraper: "true"` for the NetworkPolicy). Alert rules + Grafana
  dashboard in `deploy/monitoring/`; metric reference in `docs/observability.md`.
- **PDB**: `pdb.yaml` keeps `minAvailable: 2` so voluntary drains cannot drop below threshold.

## Notes / hardening

- Image tag defaults to `0.3.0`. After you push, pin by digest:
  `kustomize edit set image ghcr.io/stakecraft/rutli-cosigner@sha256:…`
- Required pod anti-affinity + zone topology spread are in the StatefulSet.
- Label the Canton **namespace** `rutli.io/client-ns=true` and the participant pod
  `rutli.io/client=true` (NetworkPolicy requires both).
- For genuinely separate trust domains, run each cosigner in a **separate cluster/account/region**,
  not just separate nodes; then this manifest is the per-domain unit and the peer endpoints are
  cross-cluster addresses.
- Consider sealing each share in an enclave/HSM (the `share_seal` seam) once available.

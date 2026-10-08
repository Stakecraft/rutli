# Helm chart: rutli-cosigner

Deploys a `t`-of-`n` FROST cosigner StatefulSet with mTLS, sealed shares, PDB, and NetworkPolicy.
Default image: `ghcr.io/stakecraft/rutli-cosigner:0.3.2` pinned by multi-arch digest
(`sha256:af38fd04fdc2446dbfa7478ed65a3296d1cc24ba337f24ceb1e43940fc6d7d3f`). Also tagged `latest` on GHCR.

## Prerequisites

- Kubernetes 1.25+ with a NetworkPolicy-capable CNI (for production)
- Helm 3.8+
- Secrets created **before** install (TLS + seal) — the chart does not generate key material

## Install

```sh
# 1. Certs
scripts/gen-frost-certs.sh 3 ./certs

# 2. Namespace + secrets
kubectl create namespace rutli
kubectl -n rutli label namespace rutli \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite

kubectl -n rutli create secret generic rutli-cosigner-tls \
  --from-file=ca.crt=certs/ca.crt \
  --from-file=cosigner1.crt=certs/cosigner1.crt --from-file=cosigner1.key=certs/cosigner1.key \
  --from-file=cosigner2.crt=certs/cosigner2.crt --from-file=cosigner2.key=certs/cosigner2.key \
  --from-file=cosigner3.crt=certs/cosigner3.crt --from-file=cosigner3.key=certs/cosigner3.key

kubectl -n rutli create secret generic rutli-seal \
  --from-literal=RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"

# 3. Install (values already pin the v0.3.2 digest)
helm upgrade --install rutli deploy/helm/rutli-cosigner -n rutli
```

If the GHCR package is private, create a pull secret and set `imagePullSecrets`.
Package visibility is managed in GitHub → Packages → `rutli-cosigner` (org API may require
`admin:org` / packages admin to flip public).

## Values (highlights)

| Key | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/stakecraft/rutli-cosigner` | |
| `image.tag` | `0.3.2@sha256:af38fd…6d7d3f` | Digest-pinned |
| `replicaCount` / `threshold` | `3` / `2` | Must match cert count |
| `fullnameOverride` | `rutli-cosigner` | Peer DNS base |
| `tlsSecretName` / `sealSecretName` | `rutli-cosigner-tls` / `rutli-seal` | Pre-created |
| `signerAllowlist` | `[driver]` | Required under TLS |
| `hostedKeys.enabled` | `false` | Cluster-hosted RSA/AES keys — replicated whole keys, not threshold shares |
| `backup.enabled` | `false` | Nightly `backup` via `kubectl exec` inside each cosigner; needs `backup.ship` |

See [`values.yaml`](values.yaml) for the full set.

## Probes

Readiness execs `rutli-cosigner --config … health`: ready only while the key store under
`/data/keys` can be listed, opened and written **and** the gRPC port accepts connections. (A
kubelet `grpc:` probe cannot be used — the port is mTLS.) A pod whose volume breaks therefore shows
`READY 0/1` and counts against the PDB instead of looking healthy while every Sign fails. The
headless Service still publishes not-ready addresses (the mesh needs them during DKG), so the
driver keeps resolving the pod; its own failover — the sick node answers `UNAVAILABLE` to anything
that needs its key store — and the node refusing to join other leaders' quorums route around it.
Liveness stays `tcpSocket` deliberately — restarting does not fix a volume and discards the
evidence. `health` exists since 0.3.1 and the probe calls it without a fallback, so the image
pin must be ≥ 0.3.1.

## Backups

`backup.enabled=true` adds a CronJob (default 03:17 UTC) that runs `rutli-cosigner backup` **inside
each cosigner** — one `kubectl exec` per ordinal, from a ServiceAccount whose Role grants only `get`
and `pods/exec` on exactly those pods. Each run leaves a seven-day rotation on the node's own volume
(`/data/backup-<weekday>`, what the "wipe `keys/`, restore" drill uses), streams every result out as
`<fullname>-N.tar`, and hands the directory of tars to `backup.ship`, a shell body you supply. The
default body exits 1, so an unconfigured destination is a failed Job you will notice, not a silent
gap:

```sh
helm upgrade --install rutli deploy/helm/rutli-cosigner -n rutli \
  --set backup.enabled=true \
  --set-file backup.ship=./ship.sh   # e.g. rclone/aws to object storage; creds via backup.extraEnv,
                                     # a destination PVC of the Job's own via backup.extraVolumes
```

Keep the tars in a different trust domain from `rutli-seal`, ideally one destination per cosigner
(`docs/disaster-recovery.md` §4). Restore onto a rebuilt pod: stream the tar into the pod's `/tmp`
(`kubectl exec -i <pod> -c cosigner -- tar -C /tmp -xf - < <pod>.tar`), run
`rutli-cosigner --config /config/cosigner-<ordinal+1>.json restore --from /tmp/backup-<weekday> --force`
there, then delete the pod so the daemon reopens its key store.

**Never mount a cosigner volume into another pod.** The StatefulSet's `data-<fullname>-N` claims
are for the cosigner pod only — no backup Job, no debug pod, no sidecar. On 2026-10-07 a backup Job
that bound a cosigner's ReadWriteOnce claim left `/data/keys` unreadable to the live cosigner, which
stayed healthy to its probe and failed every Sign: a total signing outage on the DevNet soak until
the pod was restarted (`docs/soak-2026-10-devnet.md`, incident #1). No template in this chart mounts
a cosigner's claim anywhere but its own pod, and the chart refuses a `backup.extraVolumes` entry that
names one.

## Relation to raw manifests

[`deploy/k8s/`](../../k8s/) remains the kustomize reference. This chart is the supported install path
for the same topology with parameterized `n`/`t` and image pin.

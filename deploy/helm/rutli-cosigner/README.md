# Helm chart: rutli-cosigner

Deploys a `t`-of-`n` FROST cosigner StatefulSet with mTLS, sealed shares, PDB, and NetworkPolicy.
Default image: `ghcr.io/stakecraft/rutli-cosigner:0.2.1` pinned by multi-arch digest
(`sha256:92e68eac64bcfea88147749719fa4c34fe91c3af368e2bce06f67ac686a05ef4`). Also tagged `latest` on GHCR.

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

# 3. Install (values already pin the v0.2.1 digest)
helm upgrade --install rutli deploy/helm/rutli-cosigner -n rutli
```

If the GHCR package is private, create a pull secret and set `imagePullSecrets`.
Package visibility is managed in GitHub → Packages → `rutli-cosigner` (org API may require
`admin:org` / packages admin to flip public).

## Values (highlights)

| Key | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/stakecraft/rutli-cosigner` | |
| `image.tag` | `0.2.1@sha256:92e68e…a05ef4` | Digest-pinned |
| `replicaCount` / `threshold` | `3` / `2` | Must match cert count |
| `fullnameOverride` | `rutli-cosigner` | Peer DNS base |
| `tlsSecretName` / `sealSecretName` | `rutli-cosigner-tls` / `rutli-seal` | Pre-created |
| `signerAllowlist` | `[driver]` | Required under TLS |
| `hostedKeys.enabled` | `false` | Cluster-hosted RSA/AES keys — replicated whole keys, not threshold shares |

See [`values.yaml`](values.yaml) for the full set.

## Relation to raw manifests

[`deploy/k8s/`](../../k8s/) remains the kustomize reference. This chart is the supported install path
for the same topology with parameterized `n`/`t` and image pin.

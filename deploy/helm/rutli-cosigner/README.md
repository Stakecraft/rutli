# Helm chart: rutli-cosigner

Deploys a `t`-of-`n` FROST cosigner cluster with mTLS, sealed shares, PDB, and NetworkPolicy.
Default image: `ghcr.io/stakecraft/rutli-cosigner:0.4.0-rc.4` pinned by multi-arch digest
(`sha256:03485f479d3d662a8256dc46917a85a09aeed473bda85d34954b9f30c955dd63`). Also tagged `latest` on GHCR.

Two layouts (`topology`):

- **`perNode`** (default): one StatefulSet (replicas 1) and one Service `rutli-node-<id>` per node.
  Each pod spec references **only its own** seal-bundle Secret and TLS Secret, mounted as files, so
  the kubelet's node authorizer lets a host read only the secrets of the node it runs, and no pod
  spec, init container or ServiceAccount ever sees two nodes' keys (audit C3). Sealing uses a
  per-node seal bundle (`share_seal.secret_file`); there is no seal env var. Backups are a per-pod
  sidecar (below); there is no exec RBAC.
- **`legacy`** (deprecated): the ≤ 0.4.0-rc.1 single StatefulSet, whose one pod template references
  every node's TLS Secret and injects the shared seal master `RUTLI_SEAL_SECRET` into every pod. It
  exists so an existing install upgrades in place (the DevNet soak pins it in
  `deploy/soak/cosigner-values.yaml`) until it migrates with
  [`docs/runbook-per-node-seal.md`](../../../docs/runbook-per-node-seal.md). It fails
  `scripts/check-deploy-policy.sh` by design.

## Prerequisites

- Kubernetes 1.25+ with a NetworkPolicy-capable CNI (for production)
- Helm 3.8+
- Secrets created **before** install (TLS + seal bundles) — the chart does not generate key material
- `rutli-cosigner` on an operator workstation, for `seal new-node` / `seal split-legacy`

## Install (topology perNode)

```sh
# 1. Certs (each cosigner cert carries only its own names: CN/SAN cosigner<id>)
scripts/gen-frost-certs.sh 3 ./certs

# 2. Namespace + secrets — one Secret per node, nothing shared but the CA
kubectl create namespace rutli
kubectl -n rutli label namespace rutli \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite

kubectl -n rutli create secret generic rutli-cosigner-ca --from-file=ca.crt=certs/ca.crt
for i in 1 2 3; do        # one kubernetes.io/tls Secret per cosigner (cert-manager can write these)
  kubectl -n rutli create secret tls rutli-cosigner-tls-$i --cert=certs/cosigner$i.crt --key=certs/cosigner$i.key
done

# Seal bundles: on a workstation, one per node, each into its own Secret, then delete the files.
for i in 1 2 3; do
  rutli-cosigner seal new-node --node $i --out node-$i.json        # prints its dist_public_key
  kubectl -n rutli create secret generic rutli-seal-node-$i --from-file=node.json=node-$i.json
  shred -u node-$i.json 2>/dev/null || rm -f node-$i.json
done

# 3. Install (values already pin the image digest)
helm upgrade --install rutli deploy/helm/rutli-cosigner -n rutli
```

With `hostedKeys.enabled=true` the chart also needs `hostedKeys.commitmentKey` (one random value
for the cluster: `openssl rand -hex 32`) and every node's `nodes[].distPublicKey` (printed by
`seal new-node`, or later by `rutli-cosigner seal inspect --in node-<i>.json`) — a node on a seal
bundle knows its peers' hosted-key distribution keys only by these pins.

Point the Canton driver at the per-node Services, each with its own TLS name (`helm` prints this):

```hocon
endpoints = [
  { url = "rutli-node-1.rutli.svc.cluster.local:9101", tls-name = "cosigner1" },
  { url = "rutli-node-2.rutli.svc.cluster.local:9101", tls-name = "cosigner2" },
  { url = "rutli-node-3.rutli.svc.cluster.local:9101", tls-name = "cosigner3" }
]
```

If the GHCR package is private, create a pull secret and set `imagePullSecrets`.
Package visibility is managed in GitHub → Packages → `rutli-cosigner` (org API may require
`admin:org` / packages admin to flip public).

## Values (highlights)

| Key | Default | Notes |
|---|---|---|
| `topology` | `perNode` | `perNode` or `legacy` (deprecated; see above) |
| `image.repository` | `ghcr.io/stakecraft/rutli-cosigner` | |
| `image.tag` | `0.4.0-rc.4@sha256:03485f…55dd63` | Digest-pinned |
| `replicaCount` / `threshold` | `3` / `2` | Must match cert count (and `nodes`, if set) |
| `nodes` | `[]` (= 1..replicaCount) | perNode roster: `id`, `existingClaim` (reuse a PVC, e.g. the legacy `data-rutli-cosigner-<id-1>`), `sealSecret`, `tlsSecret`, `distPublicKey`, `backupClaim`, `backupSecret` |
| `perNode.servicePrefix` | `rutli-node-` | Per-node Service `<prefix><id>` |
| `seal.perNodeSecretPrefix` / `seal.secretKey` | `rutli-seal-node-` / `node.json` | perNode: each node's seal bundle Secret |
| `hostedKeys.commitmentKey` | `""` | perNode + hosted keys: required (64 hex) |
| `fullnameOverride` | `rutli-cosigner` | Workload / headless Service base name |
| `tls.layout` | `perNode` | legacy topology only: `perNode` (`rutli-cosigner-ca` + `rutli-cosigner-tls-1..N`) or `shared` (one `tlsSecretName`). topology perNode always uses `rutli-cosigner-ca` + the node's own `tlsSecret` |
| `tls.allowExpiredCa` | `false` | Accept an expired/not-yet-valid CA in `ca.crt` (never a non-CA). Emergency rotation away from an already-expired CA only |
| `sealSecretName` | `rutli-seal` | legacy topology only: the shared master (deprecated) |
| `signerAllowlist` | `[driver]` | Required under TLS |
| `clusterId` | `""` | Cluster id pin (16 lowercase hex). Empty = derived from `ca.crt`'s bytes. Set it to the current derived id before changing `ca.crt` — see "Rotating the cluster CA". Never copy it to another cluster |
| `clusterIdChangeAllowed` | `false` | Let the cosigners start under a different cluster id than the one each recorded in `data_dir/cluster-id`. Deliberate changes only, for one rollout |
| `operatorAllowlist` | `[]` | Operator role for `verify-key` and `verify-hosted` (KeyStatus + HostedKeyStatus + CeremonySignTest only), e.g. `[operator]` |
| `refreshAllowlist` | `[]` | Refresher role for the refresh job (Refresh + KeyStatus only, never Sign), e.g. `[refresher]`; may be `[operator]` until a refresher cert exists |
| `signingPolicy` | `{}` | Cosigner signing policy (audit C2), rendered verbatim as `signing_policy`: `require_intent`, `require_ceremony_intent`, `signer_acl_required`, `signer_may_refresh`, `signer_acl`, `signer_pins`, rate limits, journal retention, approval `rules`/`approvers` — see `docs/approval-quorum.md`. Empty = verify-if-present defaults |
| `hostedKeys.enabled` | `false` | Cluster-hosted RSA/AES keys — replicated whole keys, not threshold shares |
| `hostedKeys.deleteAllowlist` | `[]` | Delete role (audit M2): client CNs whose signed delete intents tombstone hosted keys. Empty = no deletes; never a cosigner CN. `deleteAcl`, `deleteApprovalThreshold` (≥ 1 in production), `deleteGraceSecs` (604800) — `docs/hosted-keys.md`, Delete |
| `keyfile` | `{}` | Key-file format (audit M4), rendered verbatim as `keyfile`: `cluster_uuid`, `write_version` (1 or 2), `accept_v1` — `docs/disaster-recovery.md` §3h |
| `maintenanceNodes` | `[]` | perNode only: node ids whose cosigner container runs no daemon (`sleep infinity`, never Ready), for `restore`, `keyfile`, `hosted-undelete` and the ceremony tools, which take the instance lock |
| `backup.enabled` | `false` | perNode only: per-pod backup sidecar to a per-node destination (below) |

See [`values.yaml`](values.yaml) for the full set.

## TLS and seal material: what each pod sees

**topology perNode:** the pod of node `<id>` references exactly the CA Secret, its own
`rutli-cosigner-tls-<id>` and its own `rutli-seal-node-<id>`, mounted as files (mode 0440: Secret
files are root-owned, and the non-root cosigner reads them through `fsGroup`). The seal bundle is
mounted into the `cosigner` container only. No init container copies anything, and no other pod
spec names these Secrets, so the node authorizer keeps every other kubelet away from them.
**Residual risk:** anyone with `get secrets` in the namespace, or cluster-admin, still reads every
node's Secret — for separate trust domains run each cosigner in its own cluster/account.

**topology legacy:** a `tls-select` init container copies the node's TLS files out of a volume that
references every node's TLS Secret, and the shared seal master reaches every pod as an env var, so
every kubelet running a cosigner can read every node's TLS key and the master (audit C3). Migrate.

Mesh identity: each cosigner dials each peer under that peer's own TLS name (`cosigner<id>`), and
identifies a mesh caller by an exact match on its configured client CN — so one cosigner's
certificate can no longer stand in for another (audit M3). Certificates from earlier releases also
carry a shared `rutli-cosigner` SAN; nothing verifies it any more, and new ones do not have it.
Certificates are read at startup: restart the pods after rotating a Secret.

### Rotating the cluster CA

`ca.crt` may hold several CA certificates; every cosigner trusts all of them. It must hold
**only** CA certificates that are valid now: a cosigner refuses to start on a leaf, a private key or
an expired CA in it (each certificate would be a full mTLS trust anchor) and logs every anchor's
subject, notAfter and SHA-256 at startup (`trust anchor`). A zero-downtime
rotation runs a bundle of the old and the new CA during the overlap, swaps each node's leaf, then
drops the old CA — [`docs/ca-rotation.md`](../../../docs/ca-rotation.md). Because the default
cluster id is a hash of `ca.crt`'s bytes, first pin it to the current value
(`--set-string clusterId=$(shasum -a 256 certs/ca.crt | cut -c1-16)`) and confirm every pod logs
`cluster id <id> (pinned in config)`; an image without `cluster_id` support ignores the value.

Keep the pin in every later upgrade: `helm upgrade` without `--reuse-values` or `-f <saved values>`
resets `clusterId` to `""`. Each cosigner records the id it runs under in `data_dir/cluster-id`
and refuses to start under a different one (`cluster id mismatch`), so a dropped pin stops the
rollout at the first pod instead of splitting the cluster; put the value back and roll again.

### Migrating from the shared TLS Secret (≤ 0.3.x installs)

Legacy topology only. Two options; neither changes a certificate.

1. **Keep the old Secret for now:** `helm upgrade … --set tls.layout=shared`.
2. **Move to per-node Secrets:** create `rutli-cosigner-ca` and `rutli-cosigner-tls-1..N` from the
   existing `rutli-cosigner-tls` (commands in [`deploy/k8s/README.md`](../../k8s/README.md)), then
   `helm upgrade` with `tls.layout=perNode`. Copy `ca.crt` byte for byte: the split ceremony's
   cluster id is its hash.

### Migrating legacy → perNode

[`docs/runbook-per-node-seal.md`](../../../docs/runbook-per-node-seal.md): split the shared master
into per-node bundles offline (`rutli-cosigner seal split-legacy`, which keeps every node's existing
DEK so nothing is re-sealed), create the per-node Secrets, and `helm upgrade` with
`topology: perNode` and `nodes[].existingClaim` pointing at the legacy claims.

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

`backup.enabled=true` (topology perNode) adds a `backup` sidecar to each cosigner pod. Once a day
(`backup.dailyAtUtc`, default 03:17 UTC; plus once at pod start) it tars that node's **sealed**
`keys/*.json` — never dotfiles, nonce markers or temps — and its sign journals (`journal/`), and
hands the tar to that node's destination:

- `backup.destination.type: pvc` (default): a per-node backup PVC `<fullname>-backup-n<id>` (or
  `nodes[].backupClaim`), mounted in that node's sidecar only; the newest `backup.destination.keep`
  tars are kept. Protects against a wiped or corrupted data volume. For the loss of the storage
  backend, also ship off-cluster.
- `backup.destination.type: script`: `backup.destination.ship` runs with `$1` = the tar and `$2` =
  the node id, with that node's own credentials Secret (`nodes[].backupSecret`) at `/backup-creds`;
  allow the endpoint with `backup.egress` (the pod shares one network namespace, so the cosigner
  process gets the same egress — keep it to that one endpoint).

The sidecar mounts the data volume **read-only** in the cosigner's own pod (no second mount of the
claim) and never mounts the seal bundle or the TLS key — nothing in the backup path holds a DEK, and
one node's destination yields one node's sealed files, below threshold. Each run logs one
`BACKUP_OK node=<id> files=<n> bytes=<n> …` or `BACKUP_FAILED node=<id> reason=…` line; the sidecar
never exits non-zero (a crashing sidecar would make the pod unready and eat the PDB), so alert on the
log line or the destination's newest object.

There is **no backup CronJob and no `pods/exec` RBAC** any more. Earlier releases ran
`rutli-cosigner backup` inside each cosigner via `kubectl exec` from a ServiceAccount whose Role
could exec into every cosigner — and so read every node's seal secret from its environment: the
whole key in one principal (audit C3). `backup.mode: exec` now fails at template time.
`scripts/check-deploy-policy.sh` (run in CI on this chart and on `deploy/k8s`) fails on any
`pods/exec` RBAC, any `RUTLI_SEAL_SECRET` env, a pod spec naming more than one node's seal or TLS
Secret, and a seal Secret mounted outside the `cosigner` container.

Restore onto a rebuilt node: see [`docs/disaster-recovery.md`](../../../docs/disaster-recovery.md).

**Never mount a cosigner volume into another pod.** A node's data claim is for its own pod only —
no backup Job, no debug pod. On 2026-10-07 a backup Job that bound a cosigner's ReadWriteOnce claim
left `/data/keys` unreadable to the live cosigner, which stayed healthy to its probe and failed every
Sign: a total signing outage on the DevNet soak until the pod was restarted
(`docs/soak-2026-10-devnet.md`, incident #1). The sidecar is in the same pod, on the same mount.

**Volume access mode.** New installs default to `ReadWriteOncePod`, so the kernel refuses a second
pod on a share volume (the cosigner also holds a `flock` on its data dir, which stops a second
process on one node). `volumeClaimTemplates` are immutable: an install created with the old
`ReadWriteOnce` default must pin `persistence.accessModes: [ReadWriteOnce]` or `helm upgrade` is
rejected. `deploy/soak/cosigner-values.yaml` does this for the DevNet soak.

## Relation to raw manifests

[`deploy/k8s/`](../../k8s/) is this chart rendered with `topology: perNode`
(`scripts/render-k8s.sh`, values in `deploy/k8s/values.yaml`); CI fails if the two drift.

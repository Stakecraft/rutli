# Runbook: per-node seal secrets on the DevNet soak (legacy → perNode)

Moves the soak cosigner cluster (Helm release `rutli`, namespace `rutli`) off the one shared seal
master and the single StatefulSet, onto **one StatefulSet, one seal bundle and one TLS Secret per
node**, and removes the exec-based backup. It closes audit **C3** on the soak: today every pod gets
`RUTLI_SEAL_SECRET` (which derives every node's DEK) through its environment, every kubelet running a
cosigner can read every node's TLS key, and the backup Role can exec into every cosigner — each of
these alone is the whole key.

**Nothing is re-sealed.** `rutli-cosigner seal split-legacy` derives each node's *existing* DEK and
hosted-key distribution seed from the master with the same derivations the cosigners use today, so
every sealed share and hosted key opens unchanged, and rolling back is a plain `helm rollback` until
the master is deleted (step 7).

**Every cluster step below is for the operator (the user) to run.** Nothing here was run against
the cluster while preparing it. Commands marked `# [MUTATES]` change the cluster.

> **Do NOT run `refresh` (or enable any refresh CronJob) until the ceremony fixes ship** (audit C1:
> the leader sees every round-2 package of a DKG/refresh; H1: a refresh interrupted between nodes
> can leave the nodes on mixed share epochs). This migration does not touch either.

## Prerequisites

- All three cosigners **and** the soak participant's driver run **0.4.0-rc.2 or later** (per-peer
  TLS names, `share_seal.secret_file`, per-endpoint `tls-name` in the driver), on the legacy
  topology with `deploy/soak/cosigner-values.yaml` (`topology: legacy`).
- `rutli-cosigner` 0.4.0-rc.2+ built on the operator workstation (`cargo build --release -p
  rutli-cosigner` in `frost/`), `kubectl` access to the soak cluster, `helm` 3, `openssl`, `jq`.
- The operator client config used for `verify-key` in B4 (`client-operator.json`, operator cert),
  or the driver cert.
- A maintenance window: step 5 has a **full signing gap** of roughly 30–90 s while the hcloud
  volumes re-attach. Topology signs are rare; Canton retries. Avoid the backup minute (03:17 UTC).

Work in a private, short-lived directory (tmpfs if you have one) and keep it off shared storage:

```sh
umask 077
D=$(mktemp -d /dev/shm/rutli-pernode.XXXXXX 2>/dev/null || mktemp -d)
cd <repo>   # this repository, at the release you are deploying
```

## 0. Pre-checks (read-only)

```sh
# Release, revision (for rollback) and the values it was installed with.
helm -n rutli history rutli | tail -3                       # note the current REVISION as $REV_LEGACY
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
cat $D/rutli-values.exported.yaml                           # expect hostedKeys.enabled: true, storageClassName, operatorAllowlist

# The cosigners run rc.2 on the legacy topology.
kubectl -n rutli get pods -o wide                           # rutli-cosigner-0/1/2, 3/3 Ready, three hosts
kubectl -n rutli logs rutli-cosigner-0 -c cosigner | grep -E 'verified under its own server name|legacy SHARED master'

# Each node's certificate carries its own name. Expect, for i = 1..3:
#   subject=CN = cosigner<i>, O = rutli   and   DNS:cosigner<i> among the SANs
for i in 1 2 3; do
  echo "== rutli-cosigner-tls-$i"
  kubectl -n rutli get secret rutli-cosigner-tls-$i -o jsonpath='{.data.tls\.crt}' | base64 -d \
    | openssl x509 -noout -subject -ext subjectAltName
done
```

Stop if any certificate lacks `DNS:cosigner<i>` or has another CN: rc.2 dials each peer, and the
driver each endpoint, under `cosigner<i>`. (Every certificate `scripts/gen-frost-certs.sh` issued
since the first mTLS commit carries it; the soak's CA key is lost, so a missing SAN means a
certificate re-issue under the CA-rotation runbook first.)

```sh
# The data claims the new StatefulSets will reuse, and their volumes.
kubectl -n rutli get pvc                                    # data-rutli-cosigner-0/1/2, Bound, RWO, hcloud-volumes
kubectl get pv $(kubectl -n rutli get pvc -o jsonpath='{.items[*].spec.volumeName}') \
  -o custom-columns=NAME:.metadata.name,CLAIM:.spec.claimRef.name,RECLAIM:.spec.persistentVolumeReclaimPolicy

# No refresh scheduled; note the exec backup objects removed in step 7.
kubectl -n rutli get cronjob,role,rolebinding,serviceaccount
```

Baseline the keys with `verify-key` (port-forward each pod; the operator config's endpoints are
`https://127.0.0.1:1910{1,2,3}` for identifiers 1–3, exactly as in B4). Record each key's PKP
digest and fingerprint — step 6 must show the same:

```sh
kubectl -n rutli port-forward pod/rutli-cosigner-0 19101:9101 &
kubectl -n rutli port-forward pod/rutli-cosigner-1 19102:9101 &
kubectl -n rutli port-forward pod/rutli-cosigner-2 19103:9101 &
for k in frost-namespace frost-signing; do   # plus the B4 imported key, if still present
  rutli-cosigner --config $D/client-operator.json verify-key --key-id $k --expect-fingerprint <1220…> --json \
    | jq '{ok, pkp_digest, group_verifying_key}'
done
kill %1 %2 %3
```

Take a last copy of each node's **sealed** key files, off-cluster, in a different place from the
master (it is useless without it, and the master is useless without it):

```sh
for o in 0 1 2; do
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data -cf - keys > $D/pre-pernode-node$((o+1))-keys.tar
done
```

## 1. Stable per-node endpoints (before the swap)

After the swap the pods are named `rutli-cosigner-n<id>-0`, so the driver must stop dialling the
headless pod names first. Create the per-node Services now, selecting the **legacy** pods by name,
with Helm's ownership metadata so the step-5 upgrade adopts them and repoints their selectors:

```sh
for i in 1 2 3; do cat <<EOF; echo ---; done > $D/interim-services.yaml
apiVersion: v1
kind: Service
metadata:
  name: rutli-node-$i
  namespace: rutli
  labels: { app.kubernetes.io/managed-by: Helm, app.kubernetes.io/part-of: rutli, rutli.io/node: "$i" }
  annotations: { meta.helm.sh/release-name: rutli, meta.helm.sh/release-namespace: rutli }
spec:
  type: ClusterIP
  publishNotReadyAddresses: true
  selector: { statefulset.kubernetes.io/pod-name: rutli-cosigner-$((i-1)) }
  ports: [{ name: grpc, port: 9101, targetPort: grpc }]
EOF
kubectl apply -f $D/interim-services.yaml                                  # [MUTATES]
kubectl -n rutli get endpoints rutli-node-1 rutli-node-2 rutli-node-3      # one address each
```

Switch the soak participant's driver config (`frost` block) to the Services, each with its own TLS
name, and restart the participant (schedule it):

```hocon
endpoints = [
  { url = "rutli-node-1.rutli.svc.cluster.local:9101", tls-name = "cosigner1" },
  { url = "rutli-node-2.rutli.svc.cluster.local:9101", tls-name = "cosigner2" },
  { url = "rutli-node-3.rutli.svc.cluster.local:9101", tls-name = "cosigner3" }
]
tls = { ca-cert = "/rutli-certs/ca.crt", cert = "/rutli-certs/driver.crt", key = "/rutli-certs/driver.key" }   # no domain
```

Check: the participant starts without the `has no tls-name` warning, Grafana shows signs succeeding,
and `rutli_sign_requests_total{result="error"}` stays flat. (This also proves the CNI's
NetworkPolicy evaluates after the Service DNAT.) Do the same for any other participant on this
cluster (the B4 scratch validator, if it still runs).

## 2. Seal bundles (operator workstation)

```sh
export RUTLI_SEAL_SECRET="$(kubectl -n rutli get secret rutli-seal -o jsonpath='{.data.RUTLI_SEAL_SECRET}' | base64 -d)"
rutli-cosigner seal split-legacy --nodes 1,2,3 --out-dir $D/bundles | tee $D/split-legacy.out
unset RUTLI_SEAL_SECRET
```

It writes `node-1.json … node-3.json` (0600; each is **one node's** DEK and distribution seed —
treat each as that node's secret) and prints the public values to pin: `hosted_keys.commitment_key`
and each node's `dist_public_key`, plus a ready Helm snippet. They are public; the output never
contains the master. Cross-check: `rutli-cosigner seal inspect --in $D/bundles/node-2.json` prints
node 2 and the same key as `split-legacy.out`.

Create one Secret per node from its own bundle, then destroy the local bundle files:

```sh
for i in 1 2 3; do
  kubectl -n rutli create secret generic rutli-seal-node-$i --from-file=node.json=$D/bundles/node-$i.json   # [MUTATES]
done
shred -u $D/bundles/node-*.json 2>/dev/null || rm -f $D/bundles/node-*.json
```

## 3. Values

```sh
cp deploy/soak/cosigner-values-pernode.example.yaml deploy/soak/cosigner-values-pernode.yaml
# fill commitmentKey and the three distPublicKey values from $D/split-legacy.out (public; commit the file)
helm template rutli deploy/helm/rutli-cosigner -n rutli \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values-pernode.yaml > $D/pernode.render.yaml
scripts/check-deploy-policy.sh $D/pernode.render.yaml                       # deploy policy: OK
yq -N 'select(.kind == "StatefulSet") | .metadata.name + " -> " + (.spec.template.spec.volumes[] | select(.name == "data") | .persistentVolumeClaim.claimName)' $D/pernode.render.yaml
#   rutli-cosigner-n1 -> data-rutli-cosigner-0   (n2 -> -1, n3 -> -2)
helm -n rutli diff upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values-pernode.yaml 2>/dev/null || true   # if the helm-diff plugin is installed
```

The render must contain no PVC named `data-rutli-cosigner-n*` (the existing claims are reused), the
three backup PVCs `rutli-cosigner-backup-n*`, and no `RUTLI_SEAL_SECRET`.

## 4. Protect the volumes

```sh
for pv in $(kubectl -n rutli get pvc data-rutli-cosigner-0 data-rutli-cosigner-1 data-rutli-cosigner-2 -o jsonpath='{.items[*].spec.volumeName}'); do
  kubectl patch pv $pv -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'    # [MUTATES]
done
```

Nothing in this runbook deletes a claim; this makes even an accidental claim deletion recoverable.

## 5. Workload swap (signing gap starts here)

Stop the legacy pods first, so no new pod ever waits on, or shares, a volume an old pod holds:

```sh
kubectl -n rutli delete statefulset rutli-cosigner --wait                    # [MUTATES] claims are kept
kubectl -n rutli wait --for=delete pod/rutli-cosigner-0 pod/rutli-cosigner-1 pod/rutli-cosigner-2 --timeout=180s
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values-pernode.yaml   # [MUTATES]
for i in 1 2 3; do kubectl -n rutli rollout status statefulset/rutli-cosigner-n$i --timeout=300s; done
```

Helm creates `rutli-cosigner-n{1,2,3}` on the same claims, adopts `rutli-node-{1,2,3}` and points
them at `rutli.io/node`, and adds the backup sidecars and their PVCs. The driver reconnects through
the Services by itself.

## 6. Verify

```sh
kubectl -n rutli get pods -o wide            # rutli-cosigner-n{1,2,3}-0 Ready 2/2, three different hosts
for i in 1 2 3; do
  kubectl -n rutli logs rutli-cosigner-n$i-0 -c cosigner | grep -E "share sealing enabled \(bundle node=$i\)|cluster-hosted keys enabled"
  kubectl -n rutli logs rutli-cosigner-n$i-0 -c cosigner | grep -c 'legacy SHARED master'   # 0
  kubectl -n rutli logs rutli-cosigner-n$i-0 -c backup | grep BACKUP_                       # BACKUP_OK node=<i> …
done
kubectl -n rutli get statefulset -o yaml | scripts/check-deploy-policy.sh -                 # deploy policy: OK
kubectl -n rutli get endpoints rutli-node-1 rutli-node-2 rutli-node-3
```

Keys: re-run the step-0 `verify-key`, port-forwarding the new pods (`pod/rutli-cosigner-n1-0` →
19101, `-n2-0` → 19102, `-n3-0` → 19103), now **with `--sign-test`**: every 2-subset signs once,
the leader rotating, so each node leads one signature and every pair of shares is exercised. The PKP
digests and fingerprints must equal the step-0 baseline.

Live traffic: the soak participant signs (Grafana error rate flat, `rutli-soak-check` PASS next
run); hosted keys still decrypt (`rutli_hosted_key_ops_total{result="error"}` flat, no
`anti-entropy` conflict lines in any cosigner log, `rutli_anti_entropy_conflicts_total` unchanged).

## Rollback (until step 7)

The shares were never re-sealed, so going back is safe in either direction:

```sh
kubectl -n rutli delete statefulset rutli-cosigner-n1 rutli-cosigner-n2 rutli-cosigner-n3 --wait   # [MUTATES] claims kept
helm -n rutli rollback rutli $REV_LEGACY                                    # [MUTATES] legacy StatefulSet re-adopts data-rutli-cosigner-0/1/2
kubectl apply -f $D/interim-services.yaml                                   # [MUTATES] the rollback removed the per-node Services
```

The driver keeps using `rutli-node-<i>`. Anything written in perNode mode (a new hosted key) is
sealed under the same per-node DEKs and opens under the master. Only after step 7 does a rollback
need the master back from escrow.

## 7. Retire the master, the exec backup and the old backup copies

Only after step 6 passed (ideally after a day of clean soak-check):

1. **Exec backup** (if the rc.2 rollout has not removed it already). The repo no longer ships it,
   but the live objects stay until deleted:
   ```sh
   kubectl -n rutli delete cronjob rutli-cosigner-backup                    # [MUTATES]
   kubectl -n rutli delete rolebinding rutli-backup role rutli-backup serviceaccount rutli-backup   # [MUTATES]
   kubectl -n rutli get role,rolebinding -o yaml | scripts/check-deploy-policy.sh -   # no pods/exec left
   ```
2. **The master.** Delete the shared Secret:
   ```sh
   kubectl -n rutli delete secret rutli-seal                                # [MUTATES]
   ```
   The master can still derive every node's DEK, so it still opens every backup ever taken with it.
   **Product decision P1 (yours):** escrow it offline (sealed envelope / offline HSM, two-person
   access, never on a networked host) for as long as backups taken under it are kept, then destroy
   it — or destroy it now and accept that pre-migration backups are only restorable through the
   per-node bundles (which they are: same DEKs). Record which, and when. A later DEK rotation (the
   key-file v2 work) moves each node to a fresh random DEK, after which the master protects nothing
   new.
3. **Old on-volume backups.** The exec backup left up to seven `/data/backup-<weekday>` copies on
   each node's volume — older share epochs next to the live one (audit M1). The sidecar mounts the
   volume read-only, so remove them through the cosigner container:
   ```sh
   for i in 1 2 3; do
     kubectl -n rutli exec rutli-cosigner-n$i-0 -c cosigner -- sh -c 'ls -d /data/backup-* 2>/dev/null; rm -rf /data/backup-*'   # [MUTATES]
   done
   ```
   (`/data/retired-2026-07/` holds the July validator's dead shares; delete it too unless the soak
   log says otherwise.)
4. Delete `$D` (`rm -rf "$D"`), after moving the pre-migration key tars to their off-cluster home.

## Afterwards

- `deploy/soak/cosigner-values-pernode.yaml` replaces `deploy/soak/cosigner-values.yaml` for every
  later `helm upgrade` of the soak; record the change in the soak log.
- Backups now land on each node's own backup PVC (newest 14). To ship them off-cluster, switch
  `backup.destination.type` to `script` with per-node credentials (`nodes[].backupSecret`) and an
  egress rule (chart README, "Backups").
- Still **no refresh** until the C1/H1 fixes ship. Treat every key DKG'd or refreshed on ≤ rc.2 as
  exposed to the then-leader's memory (P9); DevNet soak keys stay test material.

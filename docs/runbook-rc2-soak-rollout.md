# Runbook: upgrade the DevNet soak to 0.4.0-rc.2 (in place, legacy topology)

The plain upgrade of the soak to the audit-remediation release (batches A and B), **without** the
per-node seal migration: the cosigner cluster (Helm release `rutli`, namespace `rutli`) stays on the
legacy StatefulSet and the shared seal master, and the soak participant's driver jar moves to rc.2.
It is the prerequisite of [runbook-per-node-seal.md](runbook-per-node-seal.md), which then moves
the cluster to one seal bundle and one StatefulSet per node.

**Every cluster step below is for the operator (the user) to run.** Commands marked `# [MUTATES]`
change the cluster or the participant.

> **Do NOT run `refresh` (or enable a refresh CronJob) until batch C ships** (audit C1: the leader
> sees every round-2 package of a DKG/refresh; H1: an interrupted refresh can leave mixed share
> epochs). rc.2 does not change refresh.

What changes for the soak:

| | Behaviour after rc.2 |
|---|---|
| Cosigner mesh | each peer dialled under its own TLS name `cosigner<id>`; a mesh caller identified by its exact CN; stricter config validation |
| Cosigner sealing | unchanged (shared master), plus a deprecation warning in the log |
| Driver `getPublicKey` / DKG | needs **≥ 2 cosigners that agree** on the group key (and none that disagrees); the key is pinned and every signature verified against it before it is returned |
| Driver signing journal / audit log | **fail closed** at startup on a malformed line or a broken hash chain (a torn final line is still truncated with a warning) |
| Backups | the exec-based backup CronJob is gone from the repo; its live objects are deleted in step 6 |

## Prerequisites

- rc.2 images published: the cosigner image (multi-arch, digest-pinned in the chart's
  `values.yaml` by the release commit) and `rutli-driver.jar` (`sbt driver/assembly`).
- `rutli-cosigner` rc.2 on the operator workstation; Java 17 for the driver state check; `kubectl`,
  `helm` 3, `openssl`, `jq`.
- All three cosigners Ready. Work in a private directory:

```sh
umask 077
D=$(mktemp -d /dev/shm/rutli-rc2.XXXXXX 2>/dev/null || mktemp -d)
cd <repo>   # at the rc.2 release commit
```

## 1. Cosigner pre-checks (read-only)

```sh
helm -n rutli history rutli | tail -3                          # note the current REVISION as $REV_RC1
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
helm -n rutli get manifest rutli > $D/live.yaml
kubectl -n rutli get pods -o wide                              # rutli-cosigner-0/1/2, 3/3 Ready
```

**Each node's certificate carries its own name** — rc.2 verifies peer `<i>` as `cosigner<i>`.
Expect `subject=CN = cosigner<i>, O = rutli` and `DNS:cosigner<i>` for i = 1..3; stop otherwise:

```sh
for i in 1 2 3; do
  kubectl -n rutli get secret rutli-cosigner-tls-$i -o jsonpath='{.data.tls\.crt}' | base64 -d \
    | openssl x509 -noout -subject -ext subjectAltName
done
```

**The render changes nothing but the image** (no topology, PVC or ConfigMap change):

```sh
helm template rutli deploy/helm/rutli-cosigner -n rutli \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml > $D/rc2.yaml
diff <(grep -v '^#' $D/live.yaml) <(grep -v '^#' $D/rc2.yaml)
```

Expected differences: the image (`0.4.0-rc.1@sha256:16b7a0…` → `0.4.0-rc.2@sha256:dfb5c8…`, in both the
`tls-select` init container and the cosigner container) and the chart/app version labels
(`helm.sh/chart`, `app.kubernetes.io/version`). Anything else — a new StatefulSet, a changed
`volumeClaimTemplates`, a PVC, a ConfigMap change — means the values are wrong: stop.
(`deploy/soak/cosigner-values.yaml` pins `topology: legacy` and `ReadWriteOnce`; CI checks the soak
render keeps the legacy StatefulSet.)

**The running configs pass rc.2's stricter validation** (signer `[driver]`, peer
`cosigner1..3`, operator `[operator]`, no duplicates):

```sh
kubectl -n rutli get configmap rutli-cosigner-config -o json > $D/cm.json
for i in 1 2 3; do
  jq -r ".data[\"cosigner-$i.json\"]" $D/cm.json | sed 's#"/data"#"/nonexistent"#' > $D/c$i.json
  jq -c '{signer_allowlist, peer_allowlist, operator_allowlist}' $D/c$i.json
  rutli-cosigner --config $D/c$i.json health      # must say "not ready: keystore …" — a config error here means stop
done
```

## 2. Driver pre-check: the participant's state parses under fail-closed recovery (read-only)

Copy the driver's audit log and signing journal out of the participant (paths as in its `config`:
`audit-log-path`, `signing-journal.dir`; on the soak `/rutli-state/audit.jsonl` and
`/rutli-state/journal`) and check the **copy** with the rc.2 jar:

```sh
PNS=<participant namespace>; PPOD=<participant pod>
mkdir -p $D/rutli-state
kubectl -n $PNS exec $PPOD -- tar -C /rutli-state -cf - audit.jsonl journal | tar -C $D/rutli-state -xf -
java -cp rutli-driver-0.4.0-rc.2.jar com.stakecraft.rutli.tools.StateCheck \
  --audit-log $D/rutli-state/audit.jsonl --journal-dir $D/rutli-state/journal
```

`StateCheck` never writes. Exit 0 (`OK, n entries, hash chain intact`; a torn final line is reported
and will be truncated at startup — expected after a crash) means the new driver will start. Exit 1
names the file and line the new driver would refuse: **stop** and investigate — do not hand-edit an
audit log (that is what the chain exists to detect); a malformed journal line is a real loss of the
signing record and needs a decision, not a workaround.

## 3. Upgrade the cosigners

```sh
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml       # [MUTATES]
kubectl -n rutli rollout status statefulset/rutli-cosigner --timeout=600s
```

The pods roll one at a time (the PDB keeps two up). rc.1 and rc.2 nodes interoperate during the
roll: old nodes verify peers under `rutli-cosigner`, new ones under `cosigner<id>`, and the soak
certificates carry both. Expect single `UNAVAILABLE` failovers on the participant, no errors.

Verify:

```sh
for o in 0 1 2; do
  kubectl -n rutli logs rutli-cosigner-$o -c cosigner | grep -E 'verified under its own server name|legacy SHARED master|cluster-hosted keys enabled'
done
```

Each node logs the per-peer-name line and the (expected, until the per-node migration) shared-master
deprecation warning. Then `verify-key` from the workstation with the operator config over three
port-forwards (endpoints `https://127.0.0.1:1910{1,2,3}`, as in B4) — `KeyStatus` everywhere and one
signature led by each node:

```sh
kubectl -n rutli port-forward pod/rutli-cosigner-0 19101:9101 &
kubectl -n rutli port-forward pod/rutli-cosigner-1 19102:9101 &
kubectl -n rutli port-forward pod/rutli-cosigner-2 19103:9101 &
for k in frost-namespace frost-signing; do
  rutli-cosigner --config $D/client-operator.json verify-key --key-id $k --expect-fingerprint <1220…> --sign-test
done
kill %1 %2 %3
```

## 4. Upgrade the driver

Replace `rutli-driver.jar` on the participant's `EXTRA_CLASSPATH` with rc.2. In the same change,
name each endpoint's certificate, so the driver stops verifying every cosigner under the shared
`rutli-cosigner` name (audit M3; the per-node migration later moves these to per-node Services):

```hocon
endpoints = [
  { url = "rutli-cosigner-0.rutli-cosigner.rutli.svc.cluster.local:9101", tls-name = "cosigner1" },
  { url = "rutli-cosigner-1.rutli-cosigner.rutli.svc.cluster.local:9101", tls-name = "cosigner2" },
  { url = "rutli-cosigner-2.rutli-cosigner.rutli.svc.cluster.local:9101", tls-name = "cosigner3" }
]
tls = { ca-cert = "/rutli-certs/ca.crt", cert = "/rutli-certs/driver.crt", key = "/rutli-certs/driver.key" }
```

(Keeping the bare strings and `domain = "rutli-cosigner"` also works with the soak certificates;
the driver then warns at startup for each endpoint.) Restart the participant (`# [MUTATES]`,
schedule it). With rc.2, `getPublicKey` needs two cosigners that agree — keep all three up while
the participant starts.

Verify:

- The participant starts — no `IllegalStateException` naming the audit log or the signing journal.
- Its log shows `FROST: pinned group key for <key id> = …` for the namespace and signing keys, and
  `FROST: mutual TLS channel to … (server name cosigner<i>)` per endpoint.
- Signs succeed (Grafana: `rutli_sign_requests_total{result="error"}` flat; `rutli-soak-check`
  PASS on its next run), and hosted-key decrypts keep working.
- No signature was withheld: the audit log has no `sig-verify=failed` note, and the driver log no
  `did NOT verify against the pinned group key` line:
  ```sh
  kubectl -n $PNS exec $PPOD -- grep -c 'sig-verify=failed' /rutli-state/audit.jsonl   # 0 (grep exits 1 on 0 matches)
  ```
- A fresh copy of the state still passes `StateCheck` (step 2), with more entries.

### Signing intents (audit C2) on the soak

rc.2 cosigners start in verify-if-present mode, and the rc.2 driver signs an intent for every FROST
sign. After step 4, check on Grafana or `/metrics` that `rutli_sign_intent_absent_total` stops
growing on all three nodes, and that the journals hold the driver's signs:

```sh
for o in 0 1 2; do kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- sh -c 'tail -qn1 /data/journal/*/*.jsonl'; done
# each line: "purpose":"sign", a request_id, "signer_cn":"driver"
```

Then, as a separate change once the soak has run clean on intents, set `signingPolicy` in
`deploy/soak/cosigner-values.yaml` (`docs/approval-quorum.md`, "Switching enforcement on"). The CA key
is lost, so **pin the driver key** (`signer_pins`, the only revocation the soak has). Give the soak's
key prefix an ACL (`signer_acl`). If an operator certificate Secret exists, add it to
`operatorAllowlist` and `refreshAllowlist` and run refreshes with it. Otherwise keep
`signer_may_refresh` on until the CA rotation issues a `refresher` certificate. Flip `require_intent`
last, with a rolling restart (`# [MUTATES]`, user only).

## 5. Rollback

- Cosigners: `helm -n rutli rollback rutli $REV_RC1` (`# [MUTATES]`). Shares, config and sealing are
  unchanged by rc.2, so nothing else is needed.
- Driver: put the rc.1 jar and the previous `frost` block back and restart the participant. The
  audit-log and journal formats are unchanged; anything rc.2 appended stays readable. An rc.1 driver
  sends no signing intents, so roll `signingPolicy.require_intent` back to false first.
- Key files: an older cosigner reads only v1. Leave `keyfile` unset during the soak's first weeks on
  this release (it then writes v1); once `keyfile.write_version: 2` is on, a cosigner rollback needs
  `rutli-cosigner keyfile downgrade` on each node first (daemon stopped) and `write_version: 1`.
  The legacy topology has no `maintenanceNodes` (perNode only): stop a node's daemon for the offline
  commands by scaling the StatefulSet only during a full maintenance window, or migrate to perNode
  first (next section).

## 6. Remove the exec-based backup (the user runs this)

The repo no longer ships `deploy/soak/k8s/cosigner-backup-exec-cronjob.yaml`: its Role could exec
into every cosigner and read the shared seal master from any pod's environment — the whole key in
one ServiceAccount (audit C3). Deleting the file does not delete the live objects:

```sh
kubectl -n rutli delete cronjob rutli-cosigner-backup                                    # [MUTATES]
kubectl -n rutli delete rolebinding rutli-backup role rutli-backup serviceaccount rutli-backup   # [MUTATES]
kubectl -n rutli get role,rolebinding -o yaml | scripts/check-deploy-policy.sh -        # deploy policy: OK
```

Until the per-node migration adds the backup sidecar, take sealed-file copies by hand after any
change to the keys (a human's `kubectl exec`, not a standing principal):

```sh
for o in 0 1 2; do
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data -cf - keys > $D/node$((o+1))-keys-$(date -u +%F).tar
done
```

Keep them off-cluster and apart from the seal master. Copy the sign journals too
(`tar -C /data -cf - keys journal`): they are the evidence `audit-cross-check` needs. Restoring one
of these needs the daemon stopped (`restore` takes the instance lock and refuses to roll a share
back, `docs/disaster-recovery.md` §1).

## Next

[runbook-per-node-seal.md](runbook-per-node-seal.md): per-node seal bundles, one StatefulSet per
node, per-node Services for the driver, and the backup sidecar. Record this upgrade in the soak log.

Then the rest of batch C, in the order `CHANGELOG.md` gives ("Rollout order across batch C"): flip
the signing-policy switches; key-file v2 (`keyfile.cluster_uuid`, then `write_version: 2`); a DEK
rotation per node (`docs/disaster-recovery.md` §3h) — the soak's legacy master then goes to offline
escrow until every node's previous DEK is dropped and the backups sealed under it have aged out, and
is destroyed after (decision P1); hosted-key deletes stay disabled on the soak unless a test needs
them. Every DKG/refresh output from before ceremony protocol 2 on the soak is leader-exposed test
material (P9).

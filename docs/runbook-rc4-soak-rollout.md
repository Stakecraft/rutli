# Runbook: ceremony intents on the DevNet soak (0.4.0-rc.3 → 0.4.0-rc.4, legacy topology)

Moves the soak to 0.4.0-rc.4 (ceremony-fence hardening, client-signed ceremony intents for DKG and
refresh, plain cosigner logs) in the order `CHANGELOG.md` gives ("Rollout (ceremony intents)"):
every cosigner, then the driver, then `signing_policy.require_ceremony_intent` on every node. It
follows [runbook-rc3-soak-rollout.md](runbook-rc3-soak-rollout.md) (phases 1–5 done 2026-10-18 →
2026-10-20) and reuses its conventions.

**Every cluster step below is for the operator (the user) to run.** Nothing here was run against the
cluster while writing it. Commands marked `# [MUTATES]` change the cluster or the participant;
everything else is read-only.

## The soak as it stands (2026-10-22)

| | |
|---|---|
| Cosigners | Release `rutli`, namespace `rutli`, `topology: legacy` (StatefulSet `rutli-cosigner`, pods `rutli-cosigner-0/1/2` = nodes 1/2/3, container `cosigner`). **Rev 11** = `0.4.0-rc.3@sha256:f4d92758…31e8` with batch C enforced: `require_intent`, `signer_acl_required`, `require_epoch_match` on, `signer_may_refresh` off, `signer_acl { driver: [frost-, rutli-] }`, `signer_pins { driver: [1c20597e…76fe] }`, `rate_limits`. Rollback chain: rev 10 (phase 3), 9 (rc.3 defaults), 8 (rc.2) |
| Overlay | [`deploy/soak/cosigner-values-batch-c.yaml`](../deploy/soak/cosigner-values-batch-c.yaml) holds exactly rev 11's batch C settings |
| Participant | Namespace `stakecraft-devnet-rutli-01`, `deploy/participant` (`Recreate`), Helm **rev 8**. Driver rc.3: `rutli-driver.jar` sha256 `8cc421fb…e421` on PVC `rutli-kms-bundle` (beside it `.rc2`, `.0.3.1-backup`), `frost.cluster-id = "453bb4aea2088bb5"`, no `key-prefix`, `sign-intents` default (on) |
| Ceremonies | None scheduled. No CronJob in `rutli`; nobody can refresh (`signer_may_refresh` off, no refresher certificate until [ca-rotation.md](ca-rotation.md)) |
| Audit | `audit-cross-check` weekly, manual (rc.3 runbook phase 5) |
| Monitoring | CronJob `rutli-soak-check` (`monitoring`, daily **08:00 UTC**, filter `^Rutli`: any firing Rütli alert of any severity is a FAIL), Prometheus `prometheus-kube-prometheus-prometheus.monitoring.svc:9090` |

## What rc.4 changes for the soak

- **Signing is wire-identical.** `SignRequest`/`SignIntent` gain no field (the proto diff only
  re-documents `purpose`), `IntentVerifier::verify` is unchanged, and the rc.4 driver changes only
  its DKG request (`FrostBackend.scala`, `dkgRequest()`). rc.4 cosigners sign for the rc.3 driver
  under the enforced `require_intent`, and a mixed rc.3/rc.4 cluster signs during the roll.
- **New proto fields are optional** (`DkgRequest.intent`, `RefreshRequest.intent`,
  `CeremonyFenceRequest.intent`, `CeremonyPart1Request.intent`), with no ceremony protocol bump.
- **`require_ceremony_intent` defaults to `false`** (`config.rs`, `SigningPolicyConfig::default`).
  It gates only DKG and refresh, at the leader's `Signer.Dkg`/`Refresh` and at every node's fence
  and part 1. It has no effect on sign, decrypt, hosted-key generate/delete (those fences are not
  intent-gated: `service.rs`, an intent there is `INVALID_ARGUMENT`), `CeremonySignTest`, or the
  split ceremony's offline `share-recipient`/`import-share` (CLI only, no RPC, no ceremony).
- **The chart templates are unchanged since rc.3.** An rc.4 render carries no config field rc.3
  does not know, and the only new field this runbook adds (`require_ceremony_intent`) is ignored by
  rc.3: its `SigningPolicyConfig` has no `deny_unknown_fields`. An image rollback to rc.3 with an
  rc.4-rendered ConfigMap starts, but it does not enforce the flag. rc.4 changes no on-disk format
  (key files, journals, ceremony records), so rc.3 reads everything rc.4 writes.
- **Logs are plain outside a TTY** (`main.rs`, `ansi_enabled`): no ANSI stripping needed once a
  pod runs rc.4. The `clog` helper below keeps the `sed` for any rc.3 pod (before phase 1, after a
  rollback); on rc.4 it is a no-op.
- **New metrics and alerts:** `rutli_ceremony_intent_refusals_total{reason}`,
  `rutli_ceremony_intent_absent_total`; `RutliCeremonyIntentRefused` (warning, `for: 0m`,
  `increase(…[15m]) > 0`) and `RutliCeremonyIntentAbsent` (info, `for: 0m`, `increase(…[1h]) > 0`).
  They need `kubectl apply -k deploy/monitoring` (phase 1). The dashboard is unchanged.

## Phases and where they can be undone

| Phase | What | Undo |
|---|---|---|
| 0 | Pre-flight (read-only) | — |
| 1 | Cosigners rc.3 → rc.4, flag off (image roll) + alert rules | `helm rollback rutli 11` |
| 2 | Driver rc.3 → rc.4 (jar swap, participant restart) | `.rc3` jar + restart |
| 3 | `require_ceremony_intent: true` (rolling restart, canary) | `helm rollback` to phase 1's revision + restarts |
| 4 | `audit-cross-check` | — |

Nothing here is irreversible.

## Scheduling

- **Phases 1 → 2 in one window**, finished at least an hour before the 08:00 UTC soak-check. Never
  start a restart between 07:45 and 08:15.
- **Phase 3 on a later day, right after a clean soak-check on rc.4.** Nothing forces the gap,
  because the flag does not touch signing. Its negative test may fire `RutliCeremonyIntentRefused`
  for up to 15 minutes, so never run it in the 20 minutes before 08:00. Phase 4 follows phase 3
  directly.
- **No DKG, refresh or onboarding** from phase 1 until phase 3 is verified. That covers the B8
  split/import, a Canton key rotation and a new participant. A ceremony on a mixed rc.3/rc.4
  cluster is accepted without an intent while the flag is off: it is counted, and
  `RutliCeremonyIntentAbsent` fires for an hour.
- No new alert has a `for: 1h` window. Expect `RutliHostedKeyReplicaShortfall` to go *pending*
  after each cosigner restart: `rutli_hosted_keys` reads 0 until the first anti-entropy pass
  (≈ 5 min), and the alert has `for: 20m`. Stop only if a node is still short after 20 minutes.
- Record every phase in [soak-2026-10-devnet.md](soak-2026-10-devnet.md) (time, revision,
  results).

## Prerequisites

- rc.4 published: image `ghcr.io/stakecraft/rutli-cosigner:0.4.0-rc.4@sha256:03485f479d3d662a8256dc46917a85a09aeed473bda85d34954b9f30c955dd63`;
  driver jar sha256 `ea20dcba024e5bde83a40436696e1a8dace9d76d4ed018f5ba83d3797180f8c3` at
  `~/b8-drill/release/rutli-driver-0.4.0-rc.4.jar`; rc.4 CLI at `~/rc4-rollout/bin/rutli-cosigner`.
- **The chart must pin the rc.4 image.** The `v0.4.0-rc.4` release commit's
  `deploy/helm/rutli-cosigner/values.yaml` still pins **rc.3**, and an upgrade from it renders the
  rc.3 image (no roll at all). Merge the pin PR (#54, `chore/pin-0.4.0-rc.4`) first and work on
  `main` after it. Do not use `--set image.tag=…`: it would become a user-supplied value of the
  release and pin rc.4 against every later chart.
- Java 17, `kubectl`, `helm` 3, `jq`, `yq`, `curl`, `openssl`, `grpcurl`. All three cosigners
  Ready, the participant healthy, the last soak-check PASS.

Shell setup (every shell you use):

```bash
umask 077
D=$(mktemp -d /dev/shm/rutli-rc4.XXXXXX 2>/dev/null || mktemp -d); echo "D=$D"
PNS=stakecraft-devnet-rutli-01
cd <repo>                                     # main, with PR #54 merged
RC=~/rc4-rollout/bin/rutli-cosigner
JAR4=~/b8-drill/release/rutli-driver-0.4.0-rc.4.jar
IMG3=0.4.0-rc.3@sha256:f4d92758cc1b7f8036fdabe67aab79ac60bce6499e549f853ca160efb1b631e8
IMG4=0.4.0-rc.4@sha256:03485f479d3d662a8256dc46917a85a09aeed473bda85d34954b9f30c955dd63
SHA3=8cc421fb7d0c5285baae4908b8afe06066175d374c68399170991e16bf29e421
SHA4=ea20dcba024e5bde83a40436696e1a8dace9d76d4ed018f5ba83d3797180f8c3
FP_NS=12203286ffe27c94c35ee0aa24a359d41e73f4df6e88d2aab2b72860df79ce8f22ea   # frost-namespace (party namespace)
FP_SIGN=122060d65c8fd0bc7712ddfc73ae799206b126bff81de132d4ebd8e244a0e708d198 # frost-signing
VALS=(-f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml)
```

The driver client config for `verify-key` and the negative test (as in the rc.3 runbook): the
participant's own certificate, whose key is the pinned one.

```bash
mkdir -p $D/tls $D/client-data && chmod 700 $D/tls
for f in ca.crt driver.crt driver.key; do
  kubectl -n "$PNS" exec deploy/participant -c participant -- cat /rutli-certs/$f > $D/tls/$f
done
jq -n --arg d "$D" '{
  identifier: 1, listen: "127.0.0.1:0", threshold: 2, data_dir: ($d + "/client-data"),
  peers: [ {identifier:1, endpoint:"https://127.0.0.1:19101"},
           {identifier:2, endpoint:"https://127.0.0.1:19102"},
           {identifier:3, endpoint:"https://127.0.0.1:19103"} ],
  tls: {ca_cert: ($d + "/tls/ca.crt"), cert: ($d + "/tls/driver.crt"), key: ($d + "/tls/driver.key"),
        domain: "rutli-cosigner"},
  signer_allowlist: ["driver"], peer_allowlist: ["cosigner1","cosigner2","cosigner3"],
  operator_allowlist: ["operator"] }' > $D/client-driver.json
```

`$D/tls/driver.key` is the **live driver private key**. Keep it in `$D` only for this session.
Delete it when done and before leaving the workstation (`rm -P` on macOS, `shred -u` on Linux),
then `rm -rf "$D"`.

Helpers (port-forwards die with their pod: run `pf_start` again after every restart):

```bash
pf_start() { pf_stop; for o in 0 1 2; do
  kubectl -n rutli port-forward pod/rutli-cosigner-$o 1910$((o+1)):9101 1920$((o+1)):9200 >/dev/null 2>&1 & done; sleep 3; }
pf_stop() { pkill -f 'port-forward pod/rutli-cosigner-' 2>/dev/null; true; }
m() { for i in 1 2 3; do printf 'node%s: ' $i; curl -s http://127.0.0.1:1920$i/metrics | grep -E "^$1(\{| )" | tr '\n' ' '; echo; done; }
kubectl -n monitoring port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 >/dev/null 2>&1 &
pq() { curl -sf --get http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$1" \
  | jq -r '.data.result[] | "\(.metric.pod // .metric.instance // "-") \(.metric.reason // "") \(.value[1])"'; }
soakcheck() { local j=rc4-$1-$(date -u +%m%d%H%M)
  kubectl -n monitoring create job --from=cronjob/rutli-soak-check $j \
    && kubectl -n monitoring wait --for=condition=complete job/$j --timeout=300s; kubectl -n monitoring logs job/$j | tail -20; }
clog() { kubectl -n rutli logs rutli-cosigner-$1 -c cosigner | sed 's/\x1b\[[0-9;]*m//g'; }   # $1 = ordinal 0/1/2
restart_node() { kubectl -n rutli delete pod rutli-cosigner-$1 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-$1 --timeout=300s && kubectl -n rutli get pods; }
```

(`pf_stop` matches only the cosigner forwards, so the Prometheus forward survives.)

---

## Phase 0 — Pre-flight (read-only)

### 0.1 Release state

```bash
helm -n rutli history rutli | tail -2                 # REVISION 11 deployed
kubectl -n rutli get pods -o wide                     # 3/3 Ready, three hosts
for o in 0 1 2; do kubectl -n rutli get pod rutli-cosigner-$o -o jsonpath='{.status.containerStatuses[?(@.name=="cosigner")].imageID}{"\n"}'; done   # …@sha256:f4d92758…
helm -n $PNS history participant | tail -2            # REVISION 8 deployed
kubectl -n rutli get cronjob                          # No resources found
soakcheck p0                                          # PASS
yq '.image.tag' deploy/helm/rutli-cosigner/values.yaml   # must equal $IMG4
```

**Stop if** the cosigner revision is not 11, a pod is not Ready, a CronJob exists in `rutli`,
soak-check fails, or the chart does not pin `$IMG4` (merge PR #54 first).

### 0.2 Capture what a rollback needs

```bash
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
helm -n rutli get manifest rutli > $D/live.yaml
kubectl -n rutli get configmap rutli-cosigner-config -o json > $D/cm.rev11.json
yq '.image // "unset"' $D/rutli-values.exported.yaml          # unset
helm -n $PNS get values participant -o yaml > $D/participant-values.yaml      # may hold secrets: $D only
yq '.additionalEnvVars[] | select(.name == "ADDITIONAL_CONFIG_RUTLI_KMS") | .value' $D/participant-values.yaml \
  | grep -nE 'cluster-id|sign-intents|key-prefix|approval'
```

Expect `cluster-id = "453bb4aea2088bb5"`, and no `sign-intents`, `key-prefix` or `approval`.
**Stop if** the exported values pin `image` (it would override the chart's rc.4 pin), or the HOCON
sets `sign-intents = off`. The rc.4 driver gates DKG intents like signing intents, so with it off
every DKG would go without one.

### 0.3 The overlay in git is what runs

```bash
git diff --exit-code origin/main -- deploy/soak/cosigner-values-batch-c.yaml && echo "overlay = main"
for i in 1 2 3; do jq -r --arg k cosigner-$i.json '.data[$k]' $D/cm.rev11.json | jq -c '.signing_policy | del(.rate_limits)'; done
```

Expect, on all three nodes, `require_intent`, `signer_acl_required` and `require_epoch_match`
true, `signer_may_refresh` false, the ACL and the pin, and **no** `require_ceremony_intent`.

### 0.4 Driver artifacts and state

```bash
shasum -a 256 $JAR4                                   # = $SHA4
mkdir -p $D/state-pre
kubectl -n $PNS exec deploy/participant -- tar -C /rutli-state -cf - audit.jsonl journal | tar -C $D/state-pre -xf -
java -cp $JAR4 com.stakecraft.rutli.tools.StateCheck --audit-log $D/state-pre/audit.jsonl --journal-dir $D/state-pre/journal
```

Expect exit 0: `audit log …: OK, <n> entries, hash chain intact`, with more entries than the 29 514
of 2026-10-20. **Stop if** exit 1, and do not edit the audit log.

### 0.5 Cosigner health

```bash
pf_start
m rutli_ceremonies_staged                  # 0 on all three
m rutli_stale_share                        # 0 or absent
m rutli_sign_journal_errors_total          # 0
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[24h]))'   # empty
for k in frost-namespace frost-signing; do fp=$([ $k = frost-namespace ] && echo $FP_NS || echo $FP_SIGN)
  $RC --config $D/client-driver.json verify-key --key-id $k --expect-fingerprint $fp --json | jq -c '{key_id, ok, epoch, problems}'; done
```

**Stop if** anything is staged or stale, `verify-key` is not `ok`, or refusals appear.

### 0.6 Sealed-key backup (precaution)

```bash
for o in 0 1 2; do
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data --exclude='*.nonces' -cf - keys journal > $D/pre-rc4-node$((o+1)).tar
  echo "node$((o+1)): $(tar -tf $D/pre-rc4-node$((o+1)).tar | grep -c '^keys/[^/]*\.json$') key files"   # 6 each
done
```

Move the tars off-cluster, apart from the seal master.

---

## Phase 1 — Cosigners rc.3 → rc.4 (flag off)

### 1.1 Render: image and labels only

```bash
helm template rutli deploy/helm/rutli-cosigner -n rutli "${VALS[@]}" > $D/rc4.yaml
diff <(grep -v '^#' $D/live.yaml) <(grep -v '^#' $D/rc4.yaml) | grep '^[<>]' \
  | grep -vE 'helm.sh/chart: rutli-cosigner-0\.4\.0-rc\.[34]$|app.kubernetes.io/version: "0\.4\.0-rc\.[34]"$|image: ghcr.io/stakecraft/rutli-cosigner:0\.4\.0-rc\.[34]@sha256:[0-9a-f]{64}$'
```

The last command must print **nothing**. Without the filter, the diff shows only the image
`$IMG3` → `$IMG4` (the `tls-select` init container and the `cosigner` container) and the chart
and version labels on every object. The ConfigMap does not change: no template changed since rc.3,
and `delete_grace_secs` has been rendered since rc.3. **Stop if** anything else differs.

### 1.2 Upgrade (image roll, one pod at a time)

```bash
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner "${VALS[@]}"          # [MUTATES]
kubectl -n rutli rollout status statefulset/rutli-cosigner --timeout=900s
helm -n rutli history rutli | tail -1                                         # REV_P1 (expect 12)
REV_P1=12
```

The StatefulSet rolls ordinals 2 → 1 → 0 (node 3, node 2, node 1): the leader goes last. Expected
during the roll: single `UNAVAILABLE` failovers on the participant and no sign errors. Mixed
versions sign normally. Both releases send and check the sharing, so `require_epoch_match` is
unaffected.

### 1.3 Verify every node

```bash
for o in 0 1 2; do
  echo "== node $((o+1))"
  kubectl -n rutli get pod rutli-cosigner-$o -o jsonpath='{.status.containerStatuses[?(@.name=="cosigner")].imageID}{"\n"}'   # …@sha256:03485f47…
  kubectl -n rutli logs rutli-cosigner-$o -c cosigner | grep -c $'\x1b\['                                                     # 0: plain logs
  clog $o | grep -E 'signing policy|cluster id |require_ceremony_intent is off|require_intent is off|require_epoch_match is off|plaintext|refus' | head
done
```

Each node shows:

- the rc.4 digest and 0 escape sequences;
- `signing policy require_intent=true require_ceremony_intent=false signer_acl_required=true
  signer_may_refresh=false acl_entries=1 pinned_cns=1 …`;
- `cluster id 453bb4aea2088bb5`;
- the warning `signing_policy.require_ceremony_intent is off: a DKG or refresh without a
  client-signed ceremony intent is accepted …` (expected until phase 3);
- **no** `require_intent is off` and **no** `require_epoch_match is off`.

```bash
pf_start
m rutli_ceremony_intent_absent_total       # present and 0 on all three (rc.4 primes it)
m rutli_ceremonies_staged                  # 0
m rutli_stale_share                        # 0 / absent
m rutli_sign_journal_errors_total          # 0
for k in frost-namespace frost-signing; do fp=$([ $k = frost-namespace ] && echo $FP_NS || echo $FP_SIGN)
  $RC --config $D/client-driver.json verify-key --key-id $k --expect-fingerprint $fp --json \
    | jq -c '{key_id, ok, epoch, problems, nodes: [.nodes[] | {identifier, epoch, stale, pkp_digest}]}'; done
```

`verify-key`: `ok: true`, one epoch, one `pkp_digest`, no stale node. After 15 minutes of
traffic:

```bash
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[15m]))'   # 0
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[15m]))'    # empty / 0
pq 'sum by (pod) (increase(rutli_sign_rate_limited_total[15m]))'              # 0
pq 'sum by (pod) (increase(rutli_epoch_check_skipped_total[15m]))'            # 0
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 3'   # outcome=ok, intent=<hex>
```

**Stop and roll back (1.5)** on another digest, a refusal, sign errors, a stale node or a
`verify-key` problem.

### 1.4 Monitoring: the two ceremony-intent alerts

```bash
kubectl diff -k deploy/monitoring       # only PrometheusRule rutli: + RutliCeremonyIntentRefused, + RutliCeremonyIntentAbsent
kubectl apply -k deploy/monitoring      # [MUTATES]
pq 'count by (alertname, alertstate) (ALERTS{alertname=~"RutliCeremonyIntent.*"})'   # empty
```

If `kubectl diff` shows more than those two rules (the dashboard ConfigMap, other rules), the live
monitoring is older than rc.3's phase 1: read the diff before applying. Neither new alert has a
`for` window: `Absent` fires for an hour after any intent-less DKG/refresh (none expected), and
`Refused` fires for 15 minutes after a refusal.

### 1.5 Rollback (phase 1)

```bash
pq 'max by (pod) (rutli_ceremonies_staged)'                 # must be 0 first
helm -n rutli rollback rutli 11                             # [MUTATES] image + rev 11 ConfigMap; pods roll
kubectl -n rutli rollout status statefulset/rutli-cosigner --timeout=900s
```

Safe at any point in this runbook. rc.4 writes no format rc.3 cannot read. Rev 11's ConfigMap has
no `require_ceremony_intent`. An rc.4 driver (phase 2) works against rc.3 cosigners: they ignore
the DKG intent field. After phase 3, also reset the overlay in git (3.6), or the next upgrade turns
the flag on again.

---

## Phase 2 — Driver rc.3 → rc.4 (participant restart)

The rc.4 driver differs from rc.3 only in DKG: it signs a ceremony intent (purpose `dkg`) for every
DKG, fresh per failover attempt. Signing, deletes, hosted keys, the audit log and the journal are
unchanged, and so are the HOCON keys. The participant values stay as they are, and only the jar
changes.

### 2.1 Stage the rc.4 jar; keep the rc.3 jar as `.rc3`

```bash
NODE=$(kubectl -n $PNS get pod -l app=participant -o jsonpath='{.items[0].spec.nodeName}'); echo $NODE
kubectl -n $PNS run rutli-kms-rc4 --restart=Never --image=docker.io/library/busybox:1.36 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"'$NODE'"},"containers":[{"name":"p","image":"docker.io/library/busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"b","mountPath":"/bundle"}]}],"volumes":[{"name":"b","persistentVolumeClaim":{"claimName":"rutli-kms-bundle"}}]}}'   # [MUTATES] helper pod
kubectl -n $PNS wait --for=condition=Ready pod/rutli-kms-rc4 --timeout=180s
kubectl -n $PNS exec rutli-kms-rc4 -- sh -c 'cd /bundle && { [ -e rutli-driver.jar.rc3 ] || cp -p rutli-driver.jar rutli-driver.jar.rc3; }'   # [MUTATES] rollback copy
kubectl cp $JAR4 $PNS/rutli-kms-rc4:/bundle/rutli-driver.jar.rc4                                           # [MUTATES] new file only
kubectl -n $PNS exec rutli-kms-rc4 -- sh -c 'cd /bundle && ls -ln && sha256sum rutli-driver.jar rutli-driver.jar.rc3 rutli-driver.jar.rc4'
```

**Stop if** `rutli-driver.jar` or `.rc3` is not `$SHA3`, or `.rc4` is not `$SHA4`. The rc.3 swap
renamed its staged file into place, so no `.rc3` existed before this step. Keep the helper pod for
2.2.

### 2.2 Swap and restart  `# [MUTATES]`, signing gap ≈ the participant's start (≈ 20 s on 2026-10-18)

```bash
kubectl -n $PNS exec rutli-kms-rc4 -- sh -c 'cd /bundle && mv rutli-driver.jar.rc4 rutli-driver.jar && sha256sum rutli-driver.jar'   # [MUTATES] = $SHA4
kubectl -n $PNS delete pod rutli-kms-rc4                                     # [MUTATES]
kubectl -n $PNS rollout restart deploy/participant                           # [MUTATES] Recreate: old pod stops first
kubectl -n $PNS rollout status deploy/participant --timeout=900s
date -u +%FT%TZ                                                              # record as T4
```

Never overwrite the jar in place: the `mv` is an atomic rename, and the running JVM keeps the old
inode until it stops. Use `rollout restart` and not `kubectl delete pod`. With `Recreate` it stops
the old participant before starting the new one, while a deleted pod is replaced at once and two
participants would briefly share the database. Helm stays at rev 8, and the `restartedAt` template
annotation is harmless drift.

### 2.3 Verify

```bash
kubectl -n $PNS logs deploy/participant | grep -E 'Loaded driver rutli|FROST: (pinned group key|signing intents are signed by)|IllegalStateException|DIFFERENT cluster ids|WITHOUT' | head -20
```

Expect `Loaded driver rutli (API v1) build 0.4.0-rc.4`, `FROST: signing intents are signed by
O=rutli,CN=driver …`, `FROST: pinned group key for …`, and no `IllegalStateException`,
`DIFFERENT cluster ids` or `WITHOUT`. Signs carry intents, and the cosigners see no difference:

```bash
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 3'   # outcome=ok, msg=…, intent=<hex>
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 100 | grep -c -e "intent=none" -e "intent=off"'   # 0 (exit 1 on 0)
kubectl -n $PNS exec deploy/participant -- grep -c 'sig-verify=failed' /rutli-state/audit.jsonl                          # 0 (exit 1 on 0)
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[15m]))'   # empty, 15+ min after T4
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[15m]))'  # 0
mkdir -p $D/state-post
kubectl -n $PNS exec deploy/participant -- tar -C /rutli-state -cf - audit.jsonl journal | tar -C $D/state-post -xf -
java -cp $JAR4 com.stakecraft.rutli.tools.StateCheck --audit-log $D/state-post/audit.jsonl --journal-dir $D/state-post/journal   # exit 0, more entries than 0.4
```

Hosted-key decrypts keep working (`rutli_hosted_key_ops_total{result="error"}` flat). A DKG-path
check is not possible without creating a key (2.5). **Stop and roll back** if the participant does
not start, signs fail, `intent=none` appears, or `StateCheck` fails.

### 2.4 Rollback (phase 2)

```bash
# helper pod as in 2.1 (kubectl run … rutli-kms-rc4 …, wait), then:
kubectl -n $PNS exec rutli-kms-rc4 -- sh -c 'cd /bundle && cp -p rutli-driver.jar.rc3 rutli-driver.jar.rollback && mv rutli-driver.jar.rollback rutli-driver.jar && sha256sum rutli-driver.jar'   # [MUTATES] = $SHA3
kubectl -n $PNS delete pod rutli-kms-rc4                                     # [MUTATES]
kubectl -n $PNS rollout restart deploy/participant && kubectl -n $PNS rollout status deploy/participant --timeout=900s   # [MUTATES]
```

Signing works with the rc.3 driver in every phase. Once phase 3 is on, an rc.3 driver's DKG is
refused (`missing`). Roll phase 3 back first if a DKG may be needed (a Canton key rotation, B8).

### 2.5 What the first real DKG will show (not part of this rollout)

The participant logs `FROST: DKG for <id> carries ceremony intent (ceremony dkg-<32 hex>)`. Every
cosigner logs `dkg fence: ceremony intent verified` with `requested_by="driver"`, and
`rutli_ceremony_intent_absent_total` stays flat.

---

## Phase 3 — `require_ceremony_intent: true` on every node

From the moment the last node enforces, no node takes part in a DKG or refresh unless an
authorized client signed an intent for exactly that ceremony. A compromised cosigner can then no
longer start one. Signing and hosted keys are unaffected.

### 3.1 Pre-checks

```bash
for o in 0 1 2; do kubectl -n rutli get pod rutli-cosigner-$o -o jsonpath='{.status.containerStatuses[?(@.name=="cosigner")].imageID}{"\n"}'; done   # all rc.4
kubectl -n $PNS logs deploy/participant | grep -m1 'Loaded driver rutli'           # build 0.4.0-rc.4
pq 'sum by (pod) (increase(rutli_ceremony_intent_absent_total[24h]))'               # 0 (CHANGELOG: must have stopped growing)
pq 'max by (pod) (rutli_ceremonies_staged)'                                         # 0
kubectl -n rutli get cronjob                                                        # No resources found: no refresh client to upgrade
```

**Stop if** a node or the driver is not on rc.4, or anything is non-zero.

### 3.2 Overlay, render, upgrade (ConfigMap only)

```bash
yq -i '.signingPolicy.require_ceremony_intent = true' deploy/soak/cosigner-values-batch-c.yaml
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
helm template rutli deploy/helm/rutli-cosigner -n rutli "${VALS[@]}" > $D/p3.yaml
diff <(helm -n rutli get manifest rutli | grep -v '^#') <(grep -v '^#' $D/p3.yaml)   # only the three cosigner-<i>.json lines
for i in 1 2 3; do yq "select(.kind == \"ConfigMap\" and .metadata.name == \"rutli-cosigner-config\") | .data[\"cosigner-$i.json\"]" $D/p3.yaml \
  | jq -c '.signing_policy | {require_ceremony_intent, require_intent, signer_acl_required, signer_may_refresh, require_epoch_match}'; done
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner "${VALS[@]}"                  # [MUTATES] ConfigMap only, restarts nothing
helm -n rutli history rutli | tail -1                                                # REV_P3 (expect 13)
```

Each rendered config: `require_ceremony_intent: true`, with the other four switches as before
(`true, true, false, true`). `signing_policy` ignores unknown keys, so the spelling is checked here
and again in the startup line.

### 3.3 Canary restarts: node 2 → node 3 → node 1

The legacy StatefulSet has no config checksum. Restart one pod at a time and check 3/3 Ready
before the next delete (`kubectl delete pod` bypasses the PDB).

```bash
restart_node 1                                                               # [MUTATES] node 2
clog 1 | grep -E 'signing policy|require_ceremony_intent is off'
#   signing policy require_intent=true require_ceremony_intent=true … — and NO "require_ceremony_intent is off"
```

Wait 5 minutes and run `pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[5m]))'`
(expect 0). Then:

```bash
restart_node 2                                                               # [MUTATES] node 3
restart_node 0                                                               # [MUTATES] node 1
for o in 0 1 2; do clog $o | grep 'signing policy'; clog $o | grep -c 'require_ceremony_intent is off'; done   # all require_ceremony_intent=true; counts 0
```

A pod that fails to start here has a config error: `require_ceremony_intent` needs TLS
(`config.rs`), and the soak has it. Roll back (3.6).

### 3.4 Positive checks: nothing else changed

```bash
pf_start
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 3'   # outcome=ok after the restarts
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="ok"}[30m]))'      # > 0
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[30m]))'   # 0
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[30m]))'    # empty
m rutli_ceremony_intent_refusals_total                                         # absent (not primed; appears at the first refusal)
$RC --config $D/client-driver.json verify-key --key-id frost-signing --expect-fingerprint $FP_SIGN --json | jq -c '{ok, epoch, problems}'
```

Hosted-key decrypts keep working (`rutli_hosted_key_ops_total{result="error"}` flat).

### 3.5 Negative test: an intent-less DKG is refused by every node, and nothing is created

Send `Signer.Dkg` **without an intent** with the driver certificate to each node as leader. Use the
key id `frost-import-rc4-negative-test`. It is inside the driver's ACL (`frost-`), so the request
reaches the intent check. It also carries the split ceremony's reserved marker `frost-import-`,
which no DKG can ever mint. Either way no state is written:

- **Enforcing node:** `Signer.Dkg` checks the caller (allowlist and pin), then the ACL, then the
  ceremony intent (`service.rs`, `dkg` → `check_ceremony_intent`). It refuses `missing` before
  `run_dkg_with_intent`, so there is no fence, guard, ceremony record or key.
- **Non-enforcing node (the test failed):** `run_dkg_attached` refuses the reserved id
  (`ReservedKeyId`, `ALREADY_EXISTS`) before it contacts any peer: before
  `require_ceremony_protocol`, `key_views` and `fence_all` (`orchestrator.rs`). Every peer would
  refuse it at part 1 too (`node.rs`).

Nothing touches `frost-namespace` or `frost-signing`.

```bash
pf_start
CERT=$(jq -r '.tls.cert' $D/client-driver.json); KEY=$(jq -r '.tls.key' $D/client-driver.json); CA=$(jq -r '.tls.ca_cert' $D/client-driver.json)
for i in 1 2 3; do
  echo "== node $i as leader"
  grpcurl -cacert "$CA" -cert "$CERT" -key "$KEY" -servername cosigner$i \
    -import-path frost/cosigner/proto -proto cosigner.proto \
    -d '{"key_id":"frost-import-rc4-negative-test"}' \
    127.0.0.1:1910$i rutli.cosigner.v1.Signer/Dkg
done
m rutli_ceremony_intent_refusals_total        # each node: {reason="missing"} 1
m rutli_ceremonies_staged                     # 0
```

Each node must answer `Code: PermissionDenied` with `ceremony intent refused: dkg of
frost-import-rc4-negative-test carries no ceremony intent and this node requires one
(signing_policy.require_ceremony_intent) — upgrade the driver (DKG) or run rutli-cosigner refresh
from this release`.

**Stop and roll back** if a node answers `AlreadyExists … is reserved for imported keys`: it does
not enforce, so check its startup line and restart it. Also stop on any other refusal: `not pinned`
or an ACL refusal means the workstation config is wrong, so fix it and repeat.

The test cannot exercise the mesh path (fence and part 1 at the peers): that needs a cosigner
certificate. A refresh variant is impossible on the soak. The driver is refused at
`authorize_refresh` (`signer_may_refresh` off) before any intent check, and no refresher
certificate exists.

**Alert note.** `rutli_ceremony_intent_refusals_total` is not pre-registered (`metrics.rs`,
`prime()` primes only the `absent` counter). The first refusal per node and reason therefore
creates the series at 1, and `increase()` may read 0. `RutliCeremonyIntentRefused` may stay
silent for this test, so judge it by the `m` output above. Schedule the test as if the alert fires
for 15 minutes, and note it in the soak log.

### 3.6 Rollback (phase 3)

```bash
helm -n rutli rollback rutli $REV_P1                                         # [MUTATES] ConfigMap only
for o in 1 2 0; do restart_node $o; done                                     # [MUTATES]
yq -i '.signingPolicy.require_ceremony_intent = false' deploy/soak/cosigner-values-batch-c.yaml   # keep git = cluster
```

Turn the flag off **before** any rollback of the cosigner image or the driver that is meant to
keep DKG working (CHANGELOG: "Rollback: turn the flag off first"). Helm merges maps across `-f`
files, so set the key to `false`: deleting the line would not turn the flag off.

---

## Phase 4 — `audit-cross-check`

Read-only and offline, with the rc.4 CLI. Copy the journals **first** and the driver audit log
**second**:

```bash
rm -rf $D/xc && mkdir -p $D/xc/journals
for o in 0 1 2; do kubectl -n rutli cp -c cosigner rutli-cosigner-$o:/data/journal $D/xc/journals/cosigner$((o+1)); done
kubectl -n $PNS exec deploy/participant -- cat /rutli-state/audit.jsonl > $D/xc/audit.jsonl
$RC audit-cross-check --driver-audit $D/xc/audit.jsonl \
  --journal $D/xc/journals/cosigner1 --journal $D/xc/journals/cosigner2 --journal $D/xc/journals/cosigner3 \
  --min-journals 2
echo "exit $?"
```

Expect exit 1 with **only** the known rollout-window lines from 2026-10-18 (rc.3 phase 5): node 1
and node 2 each `81 signature(s) with key frost-signing without a signing intent (…09:12:50… ..
…09:49:55…)` and node 3 `2 …` (`09:11:12 .. 09:11:20`), all before T2 (09:49:59Z). Any other
`DISCREPANCY:` line, or a no-intent range that ends later, is a finding
(`docs/audit-cross-check.md`). A sign in flight during the copy can show once (`in 1 of the supplied
journals` for the newest entry): copy again and rerun. Exit 2 means an unreadable file or a broken
chain: keep the evidence. Record the counts in the soak log. The weekly manual run continues
unchanged.

---

## What can go wrong

| Symptom | Cause | What to do |
|---|---|---|
| Pods keep the rc.3 image after the phase 1 upgrade; the render diff shows only labels | The chart still pins rc.3 (PR #54 not merged) | Stop. Merge #54, re-render (1.1), upgrade again |
| A pod is in `ImagePullBackOff` during the roll | The rc.4 digest is not reachable from the node | `helm rollback rutli 11`; check the GHCR package and pull secret |
| Signs fail with `reason="pin"`/`"acl"`/`"missing"` after phase 1 | Not caused by rc.4 (the sign path is unchanged): the config changed | Compare `cm.rev11.json` with the live ConfigMap; roll back (1.5) |
| `RutliCeremonyIntentAbsent` fires | A DKG/refresh ran without an intent (rc.3 driver or client, or a cosigner leading on its own) while the flag is off | Find it: participant logs, cosigner `… without a ceremony intent accepted` warnings. None is scheduled on the soak |
| `RutliCeremonyIntentRefused`, reason `missing` | Phase 3 negative test (expected), or an rc.3 driver or CLI attempting a DKG/refresh | Expected only after 3.5. Otherwise finish the driver upgrade, or roll back phase 3 if a DKG is needed now |
| `…Refused`, reason `signer` | A refresh by the driver with `signer_may_refresh` off, or an intent replayed through another client's connection | The soak cannot refresh until the CA rotation (rc.3 runbook 0.8). A replay is a finding |
| `…Refused`, reason `pin`/`acl` on a DKG | The DKG client uses an unpinned key or a prefix outside `signer_acl` (e.g. `b8-`) | Add the prefix and pin in a policy rollout (rc.3 runbook phase 3), then retry |
| `…Refused`, reason `expiry` | Clock skew between the client and a node (> `clock_skew_secs`) | Fix NTP |
| Cosigner log `ceremony fence refused` / `ceremony part 1 refused` naming an asker | A peer led a DKG/refresh nobody signed for (or an rc.3 leader dropped the intent) | Finish the rollout; if every node runs rc.4, investigate that peer as compromised (`docs/ceremonies.md`) |
| The flag "set" but logs show `require_ceremony_intent=false` | Pod not restarted (legacy: no config checksum), or a misspelt key (ignored) | Check the rendered JSON and the startup line; restart |
| `rutli_ceremonies_staged` > 0 | A ceremony was interrupted (none should run here) | Let the resolver finish (30 s retries); never roll back with a staged ceremony |

## Final checklist

- [ ] Revisions recorded: cosigners `REV_P1` (rc.4, flag off) and `REV_P3` (flag on); rollback targets 11 / `REV_P1`.
- [ ] Every cosigner on `0.4.0-rc.4@sha256:03485f47…dd63` with plain logs, and `signing policy require_intent=true require_ceremony_intent=true signer_acl_required=true signer_may_refresh=false acl_entries=1 pinned_cns=1`. No `is off` notices.
- [ ] `deploy/monitoring` applied: `RutliCeremonyIntentRefused` and `RutliCeremonyIntentAbsent` exist in the PrometheusRule.
- [ ] Driver: `build 0.4.0-rc.4`, jar `ea20dcba…f8c3`, `.rc3` (`8cc421fb…e421`) kept in the bundle PVC; signs `outcome=ok` with intents; `StateCheck` OK on a fresh copy; T4 recorded.
- [ ] Negative test: all three nodes refuse an intent-less DKG with `carries no ceremony intent`; `rutli_ceremonies_staged` 0; no new key id on any node (`ls /data/keys` unchanged from 0.6).
- [ ] `verify-key` ok for both FROST keys; sign errors, policy refusals and `rate_limited` flat; `rutli_ceremony_intent_absent_total` 0.
- [ ] `audit-cross-check`: only the pre-T2 rollout-window lines.
- [ ] `deploy/soak/cosigner-values-batch-c.yaml` (`require_ceremony_intent: true`) committed with the soak-log entry.
- [ ] soak-check PASS on the next scheduled run; `$D` cleaned up (`driver.key` securely deleted).

## Next: B8 under ceremony intents

- **Dealer split/import needs no ceremony intent.** `share-recipient`, `import-share` and
  `abort-import` are offline CLI commands run in each pod; there is no RPC and no DKG. The B8
  ids `b8-…frost-import-…` cannot be DKG'd anyway. `verify-key --sign-test` (`CeremonySignTest`)
  is not intent-gated either.
- **Before B8**, in a policy rollout like rc.3 phase 3, add `b8-` to `signer_acl.driver` and a
  tight `rate_limits` rule for B8's namespace key.
- **The B8 participant's driver must be rc.4 or later**, with `frost.cluster-id` set and
  `sign-intents` on, and its `driver` certificate key must be in `signer_pins`. Every DKG it runs
  (Canton generating its other FROST keys) must carry an intent signed by that pinned key within
  `b8-`. An rc.3 driver is refused `missing`, an unpinned key `pin`, and a missing prefix `acl`.
- **A post-import refresh of the dealt key** (which retires the dealt shares, `split-ceremony.md`)
  needs a refresh intent. It can come from a `refresh_allowlist` certificate (after the CA
  rotation), or from the driver certificate while `signer_may_refresh` is temporarily back on, via
  the rc.4 `rutli-cosigner refresh` (which signs one with its client certificate). A pre-rc.4 CLI
  is refused.

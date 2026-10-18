# Runbook: batch C on the DevNet soak (0.4.0-rc.2 → 0.4.0-rc.3, legacy topology)

Rolls audit-remediation **batch C** (ceremony protocol 2, epochs, cosigner-enforced signing
intents, rate limits, sign journals, key-file v2, DEK rotation, hosted-key tombstones) out to the
DevNet soak, in the order `CHANGELOG.md` gives ("Rollout order across batch C", steps 0–9) and
`docs/approval-quorum.md` ("Switching enforcement on"). It follows
[runbook-rc2-soak-rollout.md](runbook-rc2-soak-rollout.md), done 2026-10-16.

**Every cluster step below is for the operator (the user) to run.** Nothing here was run against the
cluster while writing it. Commands marked `# [MUTATES]` change the cluster or the participant;
everything else is read-only. Release values not known at writing time are placeholders:
`0.4.0-rc.3`, `sha256:f4d92758cc1b7f8036fdabe67aab79ac60bce6499e549f853ca160efb1b631e8` (cosigner image index digest), `8cc421fb7d0c5285baae4908b8afe06066175d374c68399170991e16bf29e421` (sha256 of the rc.3
`rutli-driver.jar`).

## The soak as it stands (2026-10-16, after rc.2)

| | |
|---|---|
| Cosigners | Helm release `rutli`, namespace `rutli`, **rev 8** = `0.4.0-rc.2@sha256:dfb5c859…b2c4` (rev 7 = rc.1). `topology: legacy`: one StatefulSet `rutli-cosigner`, pods `rutli-cosigner-0/1/2` (node ids 1/2/3), container `cosigner`, RWO PVCs `data-rutli-cosigner-0/1/2`. 2-of-3 |
| Cosigner config | ConfigMap `rutli-cosigner-config`, keys `cosigner-1.json` … `cosigner-3.json`, mounted at `/config`. `signer_allowlist: ["driver"]`, `peer_allowlist: ["cosigner1","cosigner2","cosigner3"]`, **no `operator_allowlist`**. Sealing: `share_seal.secret_env = RUTLI_SEAL_SECRET` (the legacy shared master, Secret `rutli-seal`) |
| TLS | Secrets `rutli-cosigner-tls-1..3` (CN `cosigner<i>`), CA Secret `rutli-cosigner-ca` (sha256 `453bb4ae…c663`), cluster id `453bb4aea2088bb5`. **The CA private key is lost**: no new certificate of any kind (driver, operator, refresher) can be issued until [ca-rotation.md](ca-rotation.md) runs |
| Keys on the cosigners | soak: `frost-namespace`, `frost-signing` (DKG on 0.3.0, 2026-10-07), one hosted ECIES/RSA key `rutli-enc-…`; B4 leftovers (B4 is offboarded): `b4-frost-import-17bc38d7`, `b4-frost-signing`, `b4-rutli-enc-encryption-be578c92-…`. List the exact ids with `ls /data/keys` (phase 0) |
| Participant | Namespace `stakecraft-devnet-rutli-01`, `deploy/participant` (`strategy: Recreate`, node `agent-cx33-fsn-vkh`, label `app=participant`), Splice `splice-participant` chart 0.9.0, Helm rev 5. Validator UID `stakecraft-rutli-soak-1-b0`, party `stakecraft-rutli-soak-1::12203286…22ea` |
| Driver | 0.4.0-rc.2. Jar on PVC `rutli-kms-bundle` (subPath → `/app/rutli-driver.jar`; `rutli-driver.jar.rc2` and `rutli-driver.jar.0.3.1-backup` beside it), certs subPath `certs` → `/rutli-certs`. State PVC `rutli-driver-state` → `/rutli-state/audit.jsonl`, `/rutli-state/journal`. HOCON in env `ADDITIONAL_CONFIG_RUTLI_KMS` (participant Helm value `additionalEnvVars`): `backend = "frost"`, bare-string endpoints `rutli-cosigner-<o>.rutli-cosigner.rutli.svc.cluster.local:9101`, `domain = "rutli-cosigner"`, `hosted-keys = true`, `delegate = "none"`, **no `key-prefix`**, no `approval` block (check in phase 0) |
| Backups | **None automatic.** The exec CronJob was deleted (audit C3); the per-node backup sidecar arrives with [runbook-per-node-seal.md](runbook-per-node-seal.md). This runbook takes manual sealed-file copies before phases 1, 6 and 7 |
| Load | `frost-signing` ≈ 4.8–5.5 k signs / 24 h, bursty; ECIES decrypts a few per day; namespace signs rare |
| Monitoring | CronJob `rutli-soak-check` (namespace `monitoring`, daily 08:00 UTC, alert filter `^Rutli`), Grafana dashboard `rutli-cosigner`, Prometheus `prometheus-kube-prometheus-prometheus.monitoring.svc:9090` |

## Phases and where they can be undone

| Phase | What | Undo |
|---|---|---|
| 0 | Pre-flight (read-only) + `rate_limits` from measured traffic | — |
| 1 | Cosigners rc.2 → rc.3, defaults (verify-if-present) + rate limits | `helm rollback` to rev 8 |
| 2 | Driver rc.2 → rc.3, `frost.cluster-id` pinned (participant restart) | old jar + `helm rollback participant` |
| 3 | Uniform policy: `signer_acl`, `signer_pins` (rolling restart) | `helm rollback` + restart |
| 4 | Enforcement: `require_intent`, `signer_acl_required`, `signer_may_refresh: false`, `require_epoch_match` (rolling restart) | `helm rollback` + restart; a driver rollback needs this undone first |
| 5 | First `audit-cross-check`, then weekly | — |
| — | **Gate:** [runbook-per-node-seal.md](runbook-per-node-seal.md) (recommended before 6, **required** before 7) | its own rollback |
| 6 | Key-file v2 (`keyfile.cluster_uuid`, `write_version: 2`); later `accept_v1: false` | `write_version: 1`; to go below rc.3: `keyfile downgrade` per node, daemon stopped |
| 7 | DEK rotation per node (per-node seal bundles only) | **POINT OF NO RETURN per node** at `seal drop-previous` |
| 8 | P9: fresh keys under ceremony protocol 2 — **operator decision**, outlined only | — |
| 9 | Hosted-key deletes: stay disabled | — |

Nothing in phases 0–6 is irreversible. Phase 7's `drop-previous` is (old backups of that node stop
opening, unless the previous bundle is escrowed). Phase 8, if chosen, creates a new Canton identity
or rotates a protocol key; it is not a rollback-able config change.

## Scheduling

- **Phases 1 → 2 → 3 in one window**, ideally finished at least two hours before the 08:00 UTC
  `rutli-soak-check` run. Between phase 1 and phase 3 the new batch C alerts `RutliSignIntentAbsent`
  (until the driver is on rc.3) and `RutliSignerAclAbsent` (until `signer_acl` is set) can fire
  (`for: 1h` each), and `soak-check` counts every firing `^Rutli` alert as a FAIL — a lost clean day.
- **Phase 4 on a later day**, after a clean `soak-check` on phases 1–3. Its negative test fires
  `RutliSignPolicyRefusals` for 15 minutes: run it right after a `soak-check`, never in the 15 minutes
  before one.
- **No DKG, refresh or onboarding** (B8 split/import, a Canton key rotation, a new participant) from
  phase 1 until phase 1's uniformity check passes: ceremonies are refused on a mixed cluster
  (`docs/ceremonies.md`, "Rolling upgrades").
- Avoid the old backup minute (03:17 UTC) out of habit; nothing runs there today.
- Record every phase in [soak-2026-10-devnet.md](soak-2026-10-devnet.md) (time, Helm revision,
  verification results).

## Two things that differ from the rc.2 rollout

1. **On the legacy topology a config-only `helm upgrade` restarts nothing.** The legacy StatefulSet
   template carries no config checksum: an upgrade that changes only `signingPolicy` / `keyfile`
   rewrites the ConfigMap, and the running daemons keep the old config until their pods restart.
   Every config phase below therefore restarts the pods explicitly, **one at a time, in canary
   order** node 2 → node 3 → node 1 (`rutli-cosigner-1`, `-2`, `-0`). Node 1 goes last because the
   driver lists `rutli-cosigner-0` first, so node 1 leads almost every signature, and a *leader*
   refusing an intent answers PERMISSION_DENIED, which the driver does not fail over on. A *member*
   that refuses is only excluded from that signature and the leader tries the next 2-subset
   (`orchestrator.rs`), so a misconfigured node 2 shows up as refusals + retries, not as failed signs.
   `kubectl delete pod` bypasses the PDB: always check 3/3 Ready before the next delete. A
   `helm rollback` of a config-only change needs the same restarts.
2. **`signing_policy` accepts unknown keys silently** (`SigningPolicyConfig` has no
   `deny_unknown_fields`), so a misspelt flag is ignored, not refused. Each config phase checks the
   rendered JSON *and* the `signing policy` line every daemon logs at start (`require_intent`,
   `signer_acl_required`, `signer_may_refresh`, `acl_entries`, `pinned_cns`, …). `keyfile` is
   strict (`deny_unknown_fields`): a typo there stops the pod at start, which the canary catches.

Helm merges maps across `-f` files: a key removed from an overlay survives from the exported values.
To undo a phase use `helm rollback`, or set the flag explicitly to its old value; never just delete
the line.

## Prerequisites

- rc.3 published: cosigner image `ghcr.io/stakecraft/rutli-cosigner:0.4.0-rc.3@sha256:f4d92758cc1b7f8036fdabe67aab79ac60bce6499e549f853ca160efb1b631e8`
  (digest-pinned in `deploy/helm/rutli-cosigner/values.yaml` by the release commit) and
  `rutli-driver.jar` (sha256 `8cc421fb7d0c5285baae4908b8afe06066175d374c68399170991e16bf29e421`).
- This repository checked out **at the v0.4.0-rc.3 release commit**; `rutli-cosigner` 0.4.0-rc.3 built
  on the workstation (`cargo build --release -p rutli-cosigner` in `frost/`); Java 17; `kubectl`,
  `helm` 3, `openssl`, `jq`, `yq`, `curl`; `grpcurl` for the phase-4 negative test.
- A client config with the **driver** certificate for `verify-key` (the soak has no operator
  certificate), endpoints `https://127.0.0.1:19101..19103` for identifiers 1–3. The workstation no
  longer holds a driver key or `client-driver.json`: fetch the material from the participant pod and
  build the config as shown after the shell setup below. It ends up as `$D/client-driver.json`.
- The Canton fingerprints of the two FROST keys: `<FP_NAMESPACE>` (`12203286…22ea`, the party's
  namespace) and the soak's `frost-signing` key, fingerprint
  `122060d65c8fd0bc7712ddfc73ae799206b126bff81de132d4ebd8e244a0e708d198` (also in
  `participant.keys.secret.list()` and the soak records).
- All three cosigners Ready; the participant healthy; last `soak-check` PASS.

Work in a private, short-lived directory, and set the shared variables in every shell you use:

```bash
umask 077
D=$(mktemp -d /dev/shm/rutli-rc3.XXXXXX 2>/dev/null || mktemp -d)
PNS=stakecraft-devnet-rutli-01
cd <repo>                                   # at the v0.4.0-rc.3 release commit
echo "D=$D"                                 # keep it: later phases reuse files in $D
```

The driver client certificate comes from the participant pod (still under the `umask 077` above,
into `$D` only):

```bash
mkdir -p $D/tls $D/client-data
for f in ca.crt driver.crt driver.key; do
  kubectl -n "$PNS" exec deploy/participant -c participant -- cat /rutli-certs/$f > $D/tls/$f
done
# JSON, so absolute paths ($D is expanded here by jq --arg, not by the CLI)
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

`$D/tls/driver.key` is the **live driver private key** (it signs on the soak). Keep it in `$D` only
for this session, never commit or copy it elsewhere, and delete it securely when you are done (and
before leaving the workstation): `rm -P $D/tls/driver.key` on macOS, `shred -u $D/tls/driver.key` on
Linux, then remove `$D`. `$D/client-driver.json` holds only paths and endpoints. The field names are
those of `Config` in `frost/cosigner/src/config.rs` (same template as `docs/ca-rotation.md`
`client_cfg`).

Helpers used throughout (port-forwards die when a pod restarts: run `pf_start` again after each):

```bash
pf_start() {
  for o in 0 1 2; do
    kubectl -n rutli port-forward pod/rutli-cosigner-$o 1910$((o+1)):9101 1920$((o+1)):9200 >/dev/null 2>&1 &
  done
  sleep 3
}
pf_stop() { kill $(jobs -p) 2>/dev/null; }
# m <metric>: the metric's lines from each node's /metrics (node1..node3)
m() { for i in 1 2 3; do printf 'node%s: ' $i; curl -s http://127.0.0.1:1920$i/metrics | grep -E "^$1(\{| )" | tr '\n' ' '; echo; done; }
# pq <promql>: one line per series from the soak Prometheus (needs the port-forward below)
kubectl -n monitoring port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 >/dev/null 2>&1 &
pq() { curl -sf --get http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$1" \
  | jq -r '.data.result[] | "\(.metric.pod // .metric.instance // "-") \(.metric.reason // "") \(.value[1])"'; }
# soakcheck <tag>: a manual soak-check run
soakcheck() { local j=rc3-$1-$(date -u +%m%d%H%M)
  kubectl -n monitoring create job --from=cronjob/rutli-soak-check $j \
    && kubectl -n monitoring wait --for=condition=complete job/$j --timeout=300s; kubectl -n monitoring logs job/$j | tail -20; }
```

The cosigner (≤ rc.3) writes ANSI colour codes between log fields even in k8s, so every `kubectl logs …
| grep` of cosigner fields below first strips them with `sed 's/\x1b\[[0-9;]*m//g'` (otherwise `grep -o
'acl_entries=…'` and `grep -m1 'cluster id '` can miss or return escape bytes). From the next release logs are
plain when stdout is not a TTY (`NO_COLOR` is honoured), and the `sed` is then a harmless no-op.

---

## Phase 0 — Pre-flight (read-only)

### 0.1 Health and release state

```bash
helm -n rutli history rutli | tail -3                  # current REVISION must be 8 (rc.2); note it as REV_RC2
kubectl -n rutli get pods -o wide                      # rutli-cosigner-0/1/2, 3/3 Ready, three hosts
helm -n $PNS history participant | tail -3             # note the current REVISION as REV_P_RC2 (it was 7 on 2026-10-18: the rc.2 rollout added 6 and 7)
kubectl -n $PNS get deploy participant -o jsonpath='{.spec.strategy.type}{"\n"}'   # Recreate
soakcheck p0                                           # PASS
```

**Stop if** the cosigner revision is not rc.2, a pod is not Ready, the participant strategy is not
`Recreate`, or `soak-check` fails.

```bash
REV_RC2=8          # or what history showed
REV_P_RC2=<n>      # the participant revision history showed; phase 2 rolls back to it
```

### 0.2 Capture everything a rollback needs

```bash
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
helm -n rutli get manifest rutli > $D/live.yaml
kubectl -n rutli get configmap rutli-cosigner-config -o json > $D/cm.rc2.json
helm -n $PNS get values participant -o yaml > $D/participant-values.rc2.yaml   # may hold secrets: stays in $D only
yq '.image // "unset"' $D/rutli-values.exported.yaml                            # unset
yq '.clusterId // "unset"' $D/rutli-values.exported.yaml                        # unset, or 453bb4aea2088bb5
yq '.signingPolicy // "unset", .keyfile // "unset", .refreshAllowlist // "unset"' $D/rutli-values.exported.yaml   # all unset
```

**Stop if** the exported values pin `image` (it would override the rc.3 chart's pin — remove that key
from the file and re-check the render below), or carry a `clusterId` other than `453bb4aea2088bb5`.

### 0.3 The soak's keys, and no plaintext key file

rc.3 refuses to start on a plaintext key file when sealing is on (audit M4). Every file must start
with `{"v":1,"sealed":true`:

```bash
for o in 0 1 2; do
  echo "== node $((o+1))"
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- sh -c \
    'ls /data/keys; for f in /data/keys/*.json; do printf "%s  " "${f##*/}"; head -c 20 "$f"; echo; done'
done
```

Expect the same key ids on all three nodes (`frost-namespace.json`, `frost-signing.json`, the soak's
`rutli-enc-….json`, the three `b4-…` files), each line ending `{"v":1,"sealed":true`. Record the
hosted key's exact id. **Stop if** any file does not start that way: seal a genuine one with
`rutli-cosigner keyfile migrate-plaintext --key-id <id>` (offline, `CHANGELOG.md` upgrade notes)
before going further.

### 0.4 The driver's config: no approvals, no prefix, no cluster id yet

```bash
yq '.additionalEnvVars[] | select(.name == "ADDITIONAL_CONFIG_RUTLI_KMS") | .value' $D/participant-values.rc2.yaml > $D/driver-hocon.rc2.conf
grep -nE 'approval|key-prefix|cluster-id|sign-intents|domain|endpoints' $D/driver-hocon.rc2.conf
```

Expect `domain = "rutli-cosigner"` and the three bare-string endpoints; **no** `approval`,
`key-prefix`, `cluster-id` or `sign-intents`. If an `approval { rules, approvers }` block exists,
phase 3 must copy it to the cosigners (see 3.2). **Stop if** a `key-prefix` is set: the ACL in phase
3 assumes the unprefixed ids `frost-…` / `rutli-…`.

### 0.5 Driver state parses under the rc.3 driver (StateCheck)

```bash
mkdir -p $D/state-pre
kubectl -n $PNS exec deploy/participant -- tar -C /rutli-state -cf - audit.jsonl journal | tar -C $D/state-pre -xf -
java -cp rutli-driver-0.4.0-rc.3.jar com.stakecraft.rutli.tools.StateCheck \
  --audit-log $D/state-pre/audit.jsonl --journal-dir $D/state-pre/journal
```

Exit 0 (`OK, n entries, hash chain intact`; more entries than the 19 015 / 18 989 of 2026-10-16).
**Stop if** exit 1: do not edit the audit log; investigate as in the rc.2 runbook §2.

### 0.6 Measure each key's sign rate and write the rate-limit rules (audit F8)

From step 1 every cosigner enforces **300/min and 20 000/day per key, per node** by default, and a
refusal (RESOURCE_EXHAUSTED) is **final**: the driver does not fail over and Canton sees the sign
fail. Until the driver runs rc.3 (phase 2) signs carry no intent, so **every t-subset attempt and
every failover is a separate charge**. Measure from the copy taken in 0.5 (commands from the rc.2
runbook §1):

```bash
jq -r 'select(.op == "sign") | [(.detail | capture("keyId=(?<k>[^ ]+)").k), .ts[0:16], .ts[0:10]] | @tsv' \
  $D/state-pre/audit.jsonl > $D/signs.tsv
awk -F'\t' '{ m[$1 FS $2]++; d[$1 FS $3]++ }
  END { for (k in m) { split(k, a, FS); if (m[k] > pm[a[1]]) pm[a[1]] = m[k] }
        for (k in d) { split(k, a, FS); if (d[k] > pd[a[1]]) pd[a[1]] = d[k] }
        for (k in pm) printf "%-40s busiest minute %6d   busiest day %8d\n", k, pm[k], pd[k] }' $D/signs.tsv
grep -c 'failover=' $D/state-pre/audit.jsonl          # failovers in the whole log (each is an extra charge without intents)
```

The days at the start and end of the log are partial; read the busiest *full* day. Size the rules
with generous headroom (a false refusal is an outage, a loose limit only a weaker bound):

| Key | Rule | Sizing |
|---|---|---|
| `frost-namespace` (first: the first matching prefix wins) | tight | `per_min: 10`, `per_day: 200` — raise only if the measured busiest minute exceeds 3 or the busiest day exceeds 60 (then 3× the measurement) |
| `frost-signing` | sized to traffic | `per_min` = max(600, 10 × busiest minute), `per_day` = max(100 000, 10 × busiest day), rounded up. At ≈ 5.5 k/day the default 20 000/day is within a factor of 3, so this rule is **required** |
| every other key (`b4-…`, hosted keys) | default 300 / 20 000 | B4 is offboarded; hosted keys do not sign |

Write the soak's batch C overlay. It is the one place the soak's batch C settings live from now on;
it holds no secret (a pin and a UUID are public identifiers) — commit it with the soak-log entry:

```bash
cat > deploy/soak/cosigner-values-batch-c.yaml <<'EOF'
# Batch C settings for the LIVE DevNet soak (release rutli, namespace rutli), added phase by phase
# by docs/runbook-rc3-soak-rollout.md. Pass it LAST:
#   -f <exported values> -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml
signingPolicy:
  rate_limits:   # the FIRST matching prefix wins: the namespace key's rule goes first
    - { key_id_prefix: "frost-namespace", per_min: 10, per_day: 200 }
    - { key_id_prefix: "frost-signing", per_min: <RL_MIN>, per_day: <RL_DAY> }
EOF
$EDITOR deploy/soak/cosigner-values-batch-c.yaml       # fill <RL_MIN>/<RL_DAY> from the table above
```

### 0.7 Clocks, refresh, ceremonies

Intents are refused by a node whose clock is more than `clock_skew_secs` (120 s) off the driver's:

```bash
date -u +%s
for o in 0 1 2; do kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- date -u +%s; done
kubectl -n $PNS exec deploy/participant -- date -u +%s
kubectl -n rutli get cronjob                             # No resources found: no refresh CronJob, no backup CronJob
```

**Stop if** any two values differ by more than ~10 s (allowing for `exec` latency): fix NTP on that
host first. **Stop if** any CronJob exists in `rutli` (a refresh CronJob must stay absent: a refresh
on a mixed cluster is refused, and with `signer_may_refresh: false` from phase 4 nobody may refresh).

### 0.8 Refresh capability after phase 4 — decide now

No `refresher` or `operator` certificate exists and none can be issued (CA key lost). So:

- `refreshAllowlist` stays **empty** on the soak (`[operator]` would name a certificate nobody has).
- After phase 4 sets `signer_may_refresh: false`, **nobody can refresh any key** until the CA
  rotation issues a refresher certificate. A refresh is then only possible by turning
  `signer_may_refresh` back on for the duration (a config change + rolling restart, as in phase 4).
- If you want the week-1 "proactive refresh mid-traffic" drill on rc.3, its window is **between
  phase 1's uniformity check and phase 4** (optional step 2.6).

(If you do hold a certificate with CN `operator` issued by this CA — `openssl verify -CAfile ca.crt
operator.crt` says OK — you may add `operatorAllowlist: [operator]` and `refreshAllowlist: [operator]`
to the overlay in phase 3 and keep refresh possible with it. The 2026-10-16 facts say there is none.)

### 0.9 Manual backup of every node's sealed keys

```bash
for o in 0 1 2; do
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data -cf - keys > $D/pre-rc3-node$((o+1))-keys.tar
  tar -tf $D/pre-rc3-node$((o+1))-keys.tar | grep -c '\.json$'      # = the number of key files from 0.3
done
```

`tar` may print `file changed as we read it` for the `*.nonces` directories and exit 1. That is
expected: round-2 nonce markers churn while signing, and the sealed `keys/*.json` files are what
matter. The markers are not needed for restore (`rutli-cosigner backup` copies only the key files
and journals, `docs/disaster-recovery.md` §1; a lost or old nonce store cannot cause nonce reuse,
`docs/phase-2-frost.md`), so it is safe to leave them out (the `kubectl exec` line of the loop above becomes):

```bash
kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data --exclude='*.nonces' -cf - keys > $D/pre-rc3-node$((o+1))-keys.tar
```

(If the image's `tar` has no `--exclude`, keep the form above and accept the exit 1.) Either way,
check that the archive lists every key file, comparing with the count on the pod:

```bash
tar -tf $D/pre-rc3-node1-keys.tar | grep -c '\.json$'
kubectl -n rutli exec rutli-cosigner-0 -c cosigner -- sh -c 'ls /data/keys/*.json | wc -l'     # same number
```

Move the three tars off-cluster, apart from the seal master. **Stop if** a tar is empty or its
`.json` count differs from the pod's.

---

## Phase 1 — Cosigners rc.2 → rc.3 (defaults: verify-if-present)

### 1.1 The render changes the image, labels and two config fields — nothing else

```bash
helm template rutli deploy/helm/rutli-cosigner -n rutli \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml > $D/rc3.yaml
diff <(grep -v '^#' $D/live.yaml) <(grep -v '^#' $D/rc3.yaml)
```

Expected differences only:

- the image `0.4.0-rc.2@sha256:dfb5c859…` → `0.4.0-rc.3@sha256:f4d92758cc1b7f8036fdabe67aab79ac60bce6499e549f853ca160efb1b631e8` in the `tls-select` init
  container and the `cosigner` container;
- the chart/app version labels (`helm.sh/chart`, `app.kubernetes.io/version`);
- in each `cosigner-<i>.json`: `"delete_grace_secs": 604800` appended to `hosted_keys` (the rc.3
  template always renders it; rc.2 ignores the field) and a new `"signing_policy": {"rate_limits": …}`.

**Stop if** anything else differs: a new StatefulSet, `volumeClaimTemplates`, a PVC, a Service, a
`RUTLI_SEAL_SECRET` change, `cluster_id`, `operator_allowlist`, `refresh_allowlist`, `keyfile`.

### 1.2 Upgrade (rolling, one pod at a time)

```bash
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml   # [MUTATES]
kubectl -n rutli rollout status statefulset/rutli-cosigner --timeout=900s
helm -n rutli history rutli | tail -1          # note as REV_P1 (expect 9)
```

The image change rolls the pods (ordinal 2, then 1, then 0). Expected during the roll: signing keeps
working across versions (single `UNAVAILABLE` failovers on the participant, no errors);
`rutli_epoch_check_skipped_total` grows on rc.3 nodes while rc.2's `rutli-cosigner-0` still leads;
DKG/refresh would be refused (mixed cluster) — none is scheduled.

### 1.3 Verify every node

```bash
for o in 0 1 2; do
  echo "== node $((o+1))"
  kubectl -n rutli get pod rutli-cosigner-$o -o jsonpath='{.status.containerStatuses[?(@.name=="cosigner")].imageID}{"\n"}'   # …@sha256:f4d92758cc1b7f8036fdabe67aab79ac60bce6499e549f853ca160efb1b631e8
  kubectl -n rutli logs rutli-cosigner-$o -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'signing policy|cluster id |key-file format|legacy SHARED master|require_intent is off|require_epoch_match is off|plaintext|refus' | head -20
done
```

Each node: the rc.3 digest; a `signing policy` line with `require_intent=false
signer_acl_required=false signer_may_refresh=true acl_entries=0 pinned_cns=0 rate_per_min=300
rate_per_day=20000`; `cluster id 453bb4aea2088bb5 (derived from tls.ca_cert)` (or `pinned in
config`); `key-file format write_version=1 accept_v1=true cluster_uuid=<unset>`; the expected
legacy-shared-master warning and the `require_intent is off` / `require_epoch_match is off` notices.
**Stop if** a node runs another digest, logs another cluster id, or names a plaintext/refused key
file.

After a cosigner restart `rutli_hosted_keys` reads 0 until the first anti-entropy pass (~5 min), so
`RutliHostedKeyReplicaShortfall` goes pending. It has `for: 20m`, so it should not fire: expected,
don't stop. Stop only if it is still short after ~20 min.

`rate_per_min=300` / `rate_per_day=20000` in that line are the defaults for keys that no rule
matches. The `rate_limits` prefix rules are separate config and are not echoed in the line: verify
them in the rendered config JSON instead.

The rendered config carries the rate rules:

```bash
for i in 1 2 3; do kubectl -n rutli exec rutli-cosigner-$((i-1)) -c cosigner -- cat /config/cosigner-$i.json | jq -c '.signing_policy'; done
```

**Uniformity — ceremony protocol 2 everywhere.** `ceremony_protocol` is reported only on the mesh
API (`Peer.NodeInfo`), which no operator or driver certificate can call; it is a constant of the
binary (2 in rc.3). The operator check is therefore: every pod runs the rc.3 digest (above) and
logs the batch C `signing policy` line. Then:

```bash
pf_start
m rutli_ceremonies_staged                  # 0 on all three
m rutli_stale_share                        # 0 for every key (or absent)
m rutli_keyfiles                           # format="v1",dek="current" only; no plaintext/unknown/previous
m rutli_sign_journal_errors_total          # 0
for k in frost-namespace frost-signing; do
  fp=$([ $k = frost-namespace ] && echo '<FP_NAMESPACE>' || echo '122060d65c8fd0bc7712ddfc73ae799206b126bff81de132d4ebd8e244a0e708d198')
  rutli-cosigner --config $D/client-driver.json verify-key --key-id $k --expect-fingerprint $fp --json \
    | jq '{key_id, ok, epoch, pkp_digest, problems, nodes: [.nodes[] | {identifier, epoch, stale, pkp_digest}]}'
done
```

Expect `ok: true`, one `epoch` for the cluster (0 for these keys: shares written before epochs read
as 0), the same `pkp_digest` on every node, `stale: false`, no `problems`. (Do not pass
`--sign-test` for these keys: the ceremony sign test signs only split-ceremony imported keys and
refuses DKG keys — `node.rs`, `ceremony_test_message`.)

**Stop if** `rutli_ceremonies_staged` ≠ 0, any node is stale, epochs or digests differ, or a key-file
or journal error appears.

### 1.4 Monitoring: batch C rules and dashboard rows

```bash
kubectl diff -k deploy/monitoring | head -50       # PrometheusRule gains the batch C alerts, dashboard gains three rows
kubectl apply -k deploy/monitoring                 # [MUTATES]
pq 'count(ALERTS{alertname=~"Rutli.*"})'          # firing/pending Rütli alerts (expect none yet)
```

Then, after ~10 minutes of traffic:

```bash
pq 'sum by (pod) (increase(rutli_sign_rate_limited_total[10m]))'      # 0 everywhere — MUST stay 0
pq 'sum by (pod) (increase(rutli_sign_intent_absent_total[10m]))'     # > 0: expected until phase 2 (rc.2 driver)
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[10m]))'   # 0
m rutli_sign_journal_entries_total                                     # growing on the nodes that sign
```

Journal entries from the rc.2 driver are `"purpose":"no-intent"`:

```bash
kubectl -n rutli exec rutli-cosigner-0 -c cosigner -- sh -c 'tail -qn1 /data/journal/frost-signing/*.jsonl'
```

**Stop and roll back** if `rutli_sign_rate_limited_total` moves on any node, or sign errors appear.

### 1.5 Rollback (phase 1)

```bash
helm -n rutli rollback rutli $REV_RC2                                      # [MUTATES] image change: pods roll back
kubectl -n rutli rollout status statefulset/rutli-cosigner --timeout=900s
```

Safe while nothing below has run: rc.3 writes v1 key files by default and re-seals nothing under the
same DEK; rc.2 ignores `data_dir/journal`, `keys/.staged`, `keys/.ceremonies` and the unknown config
fields. **Before** a rollback after any ceremony on rc.3: `rutli_ceremonies_staged` must be 0
(`docs/ceremonies.md`). After phase 6 a cosigner rollback needs phase 6's downgrade first.

---

## Phase 2 — Driver rc.2 → rc.3 (participant restart)

The rc.3 driver signs an intent for every FROST sign (and every delete) with its mTLS key. It names
the cluster id; pin it (`frost.cluster-id`, `RutliConfig.scala`) so no cosigner's answer decides it.

> **A wrong `frost.cluster-id` breaks signing already in this phase**: in verify-if-present mode an
> intent that is *present* is verified in full and refused if it names another cluster
> (`rutli_sign_policy_refusals_total{reason="cluster"}`). The emergency switch `frost.sign-intents =
> off` works only while no node sets `require_intent`.

### 2.1 Read the cluster id from the cosigners

```bash
for o in 0 1 2; do
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- cat /data/cluster-id
  kubectl -n rutli logs rutli-cosigner-$o -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep -m1 'cluster id '
done
kubectl -n rutli get secret rutli-cosigner-ca -o jsonpath='{.data.ca\.crt}' | base64 -d | shasum -a 256 | cut -c1-16
```

All seven values must be `453bb4aea2088bb5` (`data_dir/cluster-id`, the startup log, and the id
derived from the CA file, `wrap::cluster_id_from_ca` = the first 16 hex of sha256(ca.crt)). This is
the value every cosigner returns in `Capabilities.cluster_id`. **Stop if** they differ.

```bash
CLUSTER_ID=453bb4aea2088bb5
```

(`clusterId` in the cosigner values may still be unset: then the id is derived from `ca.crt`, and
[ca-rotation.md](ca-rotation.md) §2 pins it to this same value before the CA file changes, so
`frost.cluster-id` stays right across the rotation.)

### 2.2 Stage the rc.3 jar next to the running one

```bash
NODE=$(kubectl -n $PNS get pod -l app=participant -o jsonpath='{.items[0].spec.nodeName}'); echo $NODE   # agent-cx33-fsn-vkh
kubectl -n $PNS run rutli-kms-rc3 --restart=Never --image=docker.io/library/busybox:1.36 \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"'$NODE'"},"containers":[{"name":"p","image":"docker.io/library/busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"b","mountPath":"/bundle"}]}],"volumes":[{"name":"b","persistentVolumeClaim":{"claimName":"rutli-kms-bundle"}}]}}'   # [MUTATES] helper pod
kubectl -n $PNS wait --for=condition=Ready pod/rutli-kms-rc3 --timeout=180s
kubectl cp rutli-driver-0.4.0-rc.3.jar $PNS/rutli-kms-rc3:/bundle/rutli-driver.jar.rc3              # [MUTATES] new file only
kubectl -n $PNS exec rutli-kms-rc3 -- sh -c 'cd /bundle && ls -ln && sha256sum rutli-driver.jar rutli-driver.jar.rc2 rutli-driver.jar.rc3'
```

**Stop if** `rutli-driver.jar.rc3` is not `8cc421fb7d0c5285baae4908b8afe06066175d374c68399170991e16bf29e421`, or `rutli-driver.jar` and
`rutli-driver.jar.rc2` differ (the rollback copy must be the jar that runs now, `04d3a19b…`). Keep
the helper pod for 2.4.

### 2.3 The participant values: one added line

```bash
cp $D/participant-values.rc2.yaml $D/participant-values.rc3.yaml
$EDITOR $D/participant-values.rc3.yaml
#   inside ADDITIONAL_CONFIG_RUTLI_KMS, in the `frost = { … }` block, add exactly one line:
#     cluster-id = "453bb4aea2088bb5"
diff $D/participant-values.rc2.yaml $D/participant-values.rc3.yaml       # exactly one added line
```

Leave the endpoints, `domain` and everything else unchanged (per-endpoint `tls-name` is optional
here; the per-node migration moves the endpoints to per-node Services with `tls-name` anyway). Do not
set `sign-intents` (default `on`).

### 2.4 Swap and restart  `# [MUTATES]`, signing gap ≈ the participant's start time

```bash
kubectl -n $PNS exec rutli-kms-rc3 -- sh -c 'cd /bundle && mv rutli-driver.jar.rc3 rutli-driver.jar && sha256sum rutli-driver.jar'   # [MUTATES] = 8cc421fb7d0c5285baae4908b8afe06066175d374c68399170991e16bf29e421
kubectl -n $PNS delete pod rutli-kms-rc3                                                                  # [MUTATES]
helm -n $PNS upgrade participant oci://ghcr.io/digital-asset/decentralized-canton-sync/helm/splice-participant \
  --version 0.9.0 -f $D/participant-values.rc3.yaml                                                       # [MUTATES] restarts the participant (Recreate)
kubectl -n $PNS rollout status deploy/participant --timeout=900s
helm -n $PNS history participant | tail -1                                                                # note as REV_P_RC3
```

The `mv` is an atomic rename: the running participant keeps the old jar's inode through its subPath
bind mount until it stops; the new pod mounts the new file. Never overwrite the jar in place under a
running JVM. Keep all three cosigners up while the participant starts (`getPublicKey` needs two that
agree).

### 2.5 Verify

```bash
kubectl -n $PNS logs deploy/participant | grep -E 'Loaded driver rutli|FROST: (pinned group key|signing intents are signed by|cluster id|mutual TLS)|IllegalStateException|DIFFERENT cluster ids|WITHOUT an intent' | head -20
```

Expect `Loaded driver rutli (API v1) build 0.4.0-rc.3`, `FROST: signing intents are signed by
CN=driver…`, `FROST: pinned group key for …` for the namespace and signing keys, no
`IllegalStateException` (audit log / journal), no `DIFFERENT cluster ids`, no `signing WITHOUT an
intent`.

Signs carry intents and name their message (`msg=`, the batch C follow-up):

```bash
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 3'
#   {"seq":…,"op":"sign","detail":"keyId=frost-signing algo=… inBytes=34 msg=<64 hex> intent=<32 hex> … outcome=ok",…}
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 100 | grep -c -e "intent=none" -e "intent=off"'   # 0 once 100 signs passed the restart
kubectl -n $PNS exec deploy/participant -- grep -c 'sig-verify=failed' /rutli-state/audit.jsonl                                # 0 (grep exits 1 on 0 matches)
```

Cosigners now journal `"purpose":"sign"` with a request id and `"signer_cn":"driver"`, and the
intent-absent counter stops growing:

```bash
for o in 0 1 2; do kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- sh -c 'tail -qn1 /data/journal/frost-signing/*.jsonl' | tail -n1; done
pq 'sum by (pod) (increase(rutli_sign_intent_absent_total[15m]))'        # 0 on every node, 15+ min after the restart
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[15m]))'   # empty / 0
pq 'sum by (pod) (increase(rutli_sign_rate_limited_total[1h]))'          # 0
```

A fresh copy of the driver state passes `StateCheck` with the rc.3 jar (as 0.5, with more entries),
and hosted-key decrypts keep working (`rutli_hosted_key_ops_total{result="error"}` flat). Record the
restart time as **T2** (UTC): every journal entry without an intent must be older than T2 (phase 5).

**Stop and roll back** on any `reason="cluster"` refusal, sign errors, `intent=none` after the
restart, or a participant that does not start.

### 2.6 Optional: refresh drill on rc.3 (operator decision, before phase 4 only)

With every node on ceremony protocol 2 and `signer_may_refresh` still on, the driver certificate may
run one refresh to exercise the two-phase commit (drill calendar week 1). It does **not** repair P9 for
these DKG keys (the secret does not change). Skip it unless you want the drill.

```bash
pf_start
rutli-cosigner --config $D/client-driver.json refresh --key-id frost-signing          # [MUTATES] new sharing, same group key
m rutli_ceremonies_staged                                                             # back to 0 within ~1 min
rutli-cosigner --config $D/client-driver.json verify-key --key-id frost-signing --expect-fingerprint 122060d65c8fd0bc7712ddfc73ae799206b126bff81de132d4ebd8e244a0e708d198 --json | jq '{ok, epoch, pkp_digest}'   # epoch 1, one digest
for o in 0 1 2; do kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data -cf - keys journal > $D/post-refresh-node$((o+1)).tar; done   # the old tars now hold an older epoch
```

### 2.7 Rollback (phase 2)

Only while no node sets `require_intent` (true until phase 4; after phase 4, roll phase 4 back first):

```bash
# helper pod as in 2.2, then:
kubectl -n $PNS exec rutli-kms-rc3 -- sh -c 'cd /bundle && cp -p rutli-driver.jar.rc2 rutli-driver.jar.rollback && mv rutli-driver.jar.rollback rutli-driver.jar && sha256sum rutli-driver.jar'   # [MUTATES] = 04d3a19b…
kubectl -n $PNS delete pod rutli-kms-rc3                                    # [MUTATES]
helm -n $PNS rollback participant $REV_P_RC2                                # [MUTATES] drops cluster-id, restarts the participant
```

The audit-log and journal formats are compatible both ways (rc.2 lines lack `msg=`; the rc.2 driver
fails closed only on malformed lines, which rc.3 does not write).

---

## Phase 3 — Uniform policy on every node (ACL, pins)

Identical on all three nodes (Helm renders one `signingPolicy` into every `cosigner-<i>.json`). This
phase already **enforces** two things for the driver certificate: its key must be pinned, and it
may use only its key prefixes. A wrong pin is an outage at the leader, hence the canary order.

### 3.1 The driver key's SPKI pin

The cosigner pins `SHA-256(DER SubjectPublicKeyInfo of the leaf)` (`intent.rs`: `Caller::from_leaf_der`,
`Sha256::digest(cert.public_key().raw)`; `request_auth.rs` the same for the Signer caller). Compute it
from the certificate the participant actually mounts, and from the one on the workstation:

```bash
kubectl -n $PNS exec deploy/participant -- cat /rutli-certs/driver.crt > $D/driver.participant.crt
openssl x509 -in $D/driver.participant.crt -noout -subject -enddate          # subject: CN = driver …
pin() { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}'; }
pin $D/driver.participant.crt
pin "$(jq -r '.tls.cert' $D/client-driver.json)"                             # the workstation's driver cert (verify-key)
```

This is exactly the pipeline the enforcing e2e tests pin with (`scripts/e2e-ecies-hosted.sh`,
`scripts/e2e-carry-protocol-keys.sh`). Both lines must print the same 64-hex value. If they differ,
pin both (the list takes several keys) or `verify-key` from the workstation stops working. Any other
holder of a `driver` certificate (the B8 participant later) must use one of the pinned keys. A pin is
the soak's **only** revocation for the driver key: to revoke, replace the pin (no CA needed, but a
replacement certificate does need the rotated CA).

```bash
DRIVER_PIN=$(pin $D/driver.participant.crt); echo $DRIVER_PIN
```

### 3.2 The overlay

```bash
yq -i '.signingPolicy.signer_acl = {"driver": ["frost-", "rutli-"]}' deploy/soak/cosigner-values-batch-c.yaml
yq -i ".signingPolicy.signer_pins = {\"driver\": [\"$DRIVER_PIN\"]}" deploy/soak/cosigner-values-batch-c.yaml
cat deploy/soak/cosigner-values-batch-c.yaml
```

- `signer_acl: { driver: ["frost-", "rutli-"] }` — the unprefixed soak driver's ids are `frost-<name>`
  (FROST) and `rutli-<kind>-…` (hosted), `FrostKeyIds.scala`. This also takes the offboarded `b4-…`
  keys away from the driver certificate. **Before B8** (split/import under its own prefix with the
  same `driver` CN) add that prefix, e.g. `"b8-"`, plus a tight `rate_limits` rule for its namespace
  key, in a separate rollout like this one.
- `signer_pins: { driver: ["<DRIVER_PIN>"] }` (plus the workstation's pin if it differs).
- Approvals: the soak driver has no `approval` block (0.4), so `rules`/`approvers` stay empty. If it
  has one, copy it: each driver `{ key-id-prefix, mode, threshold }` becomes `{ key_id_prefix, mode,
  threshold }`, each approver's `public-key-base64` becomes `public_key_spki_b64`
  (`docs/approval-quorum.md`, "Configure").
- `refreshAllowlist` stays unset (0.8).

The resulting overlay:

```yaml
signingPolicy:
  rate_limits:
    - { key_id_prefix: "frost-namespace", per_min: 10, per_day: 200 }
    - { key_id_prefix: "frost-signing", per_min: <RL_MIN>, per_day: <RL_DAY> }
  signer_acl: { driver: ["frost-", "rutli-"] }
  signer_pins: { driver: ["<DRIVER_PIN>"] }
```

### 3.3 Render, upgrade (restarts nothing), canary restarts

```bash
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml        # refresh the export
helm template rutli deploy/helm/rutli-cosigner -n rutli \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml > $D/p3.yaml
diff <(helm -n rutli get manifest rutli | grep -v '^#') <(grep -v '^#' $D/p3.yaml)   # only signing_policy in the three cosigner-<i>.json
yq 'select(.kind == "ConfigMap" and .metadata.name == "rutli-cosigner-config") | .data["cosigner-1.json"]' $D/p3.yaml | jq '.signing_policy'
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml   # [MUTATES] ConfigMap only
helm -n rutli history rutli | tail -1                                         # note as REV_P3
```

Restart node 2 first and watch it for 15 minutes:

```bash
kubectl -n rutli delete pod rutli-cosigner-1                                   # [MUTATES] node 2
kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-1 --timeout=300s
kubectl -n rutli logs rutli-cosigner-1 -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'signing policy'  # acl_entries=1 pinned_cns=1, require_intent=false
```

During those 15 minutes, node 2 takes part in most signatures (the leader's first 2-subset is
{1, 2}):

```bash
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[15m]))'   # empty / 0 — reason="pin" or "acl" means stop
pq 'sum by (pod) (increase(rutli_sign_retries_total[15m]))'                    # ≈ 0 (a refusing node 2 shows up here)
pq 'sum by (pod) (increase(rutli_signer_acl_absent_total[15m]))'               # 0 on node 2
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[15m]))'   # 0
```

Then node 3, then node 1 (the leader), each followed by the same checks:

```bash
kubectl -n rutli delete pod rutli-cosigner-2 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-2 --timeout=300s   # [MUTATES] node 3
kubectl -n rutli get pods                                                     # 3/3 Ready before the next one
kubectl -n rutli delete pod rutli-cosigner-0 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-0 --timeout=300s   # [MUTATES] node 1
for o in 0 1 2; do kubectl -n rutli logs rutli-cosigner-$o -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep 'signing policy'; done   # all: acl_entries=1 pinned_cns=1
pf_start
rutli-cosigner --config $D/client-driver.json verify-key --key-id frost-namespace --expect-fingerprint <FP_NAMESPACE> --json | jq '{ok, problems}'   # still ok: the workstation key is pinned
```

After each restart `rutli_hosted_keys` reads 0 until the first anti-entropy pass (~5 min) and
`RutliHostedKeyReplicaShortfall` goes pending; it has `for: 20m` so it should not fire — expected,
don't stop; stop only if it is still short after ~20 min.

Hosted keys still decrypt (`rutli_hosted_key_ops_total{result="error"}` flat) — the `rutli-` ACL
entry covers them. **Stop and roll back** on any `reason="pin"`/`"acl"` refusal, sign or decrypt
errors, or a `verify-key` refusal naming the pin.

### 3.4 Rollback (phase 3)

```bash
helm -n rutli rollback rutli $REV_P1                                          # [MUTATES] ConfigMap only
for o in 1 2 0; do kubectl -n rutli delete pod rutli-cosigner-$o && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-$o --timeout=300s; done   # [MUTATES]
```

---

## Phase 4 — Flip enforcement on every node

On a later day, after a clean `soak-check` with phases 1–3 (and ≥ 24 h of journals showing
`"purpose":"sign"` only since T2). From the moment the **last** node enforces, nothing signs without a
journaled, driver-signed intent, the driver key cannot sign outside its ACL or rate limits, and it
cannot refresh.

### 4.1 Pre-checks

```bash
pq 'sum by (pod) (increase(rutli_sign_intent_absent_total[24h]))'      # 0 on every node — any signer without intents would be cut off
pq 'sum by (pod) (increase(rutli_signer_acl_absent_total[24h]))'       # 0
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[24h]))'   # empty
pq 'max by (pod) (rutli_ceremonies_staged)'                            # 0
```

Repeat the clock check of 0.7 — with `require_intent` a skewed **leader** (node 1) refuses every
sign finally. **Stop if** any value is non-zero or the clocks are off.

### 4.2 Overlay, render, upgrade

```bash
yq -i '.signingPolicy.require_intent = true | .signingPolicy.signer_acl_required = true | .signingPolicy.signer_may_refresh = false | .signingPolicy.require_epoch_match = true' \
  deploy/soak/cosigner-values-batch-c.yaml
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
helm template rutli deploy/helm/rutli-cosigner -n rutli \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml > $D/p4.yaml
yq 'select(.kind == "ConfigMap" and .metadata.name == "rutli-cosigner-config") | .data["cosigner-1.json"]' $D/p4.yaml \
  | jq '.signing_policy | {require_intent, signer_acl_required, signer_may_refresh, require_epoch_match, signer_acl, signer_pins, rate_limits}'
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml   # [MUTATES] ConfigMap only
helm -n rutli history rutli | tail -1                                         # note as REV_P4
```

The config validation refuses `signer_acl_required` without an ACL entry for every
`signer_allowlist` CN (`config.rs`), so a node with a broken overlay fails at start (the canary).

### 4.3 Canary restarts (node 2 → node 3 → node 1)

```bash
kubectl -n rutli delete pod rutli-cosigner-1 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-1 --timeout=300s   # [MUTATES]
kubectl -n rutli logs rutli-cosigner-1 -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'signing policy|require_intent is off|require_epoch_match is off|signer_may_refresh is on'
#   signing policy … require_intent=true signer_acl_required=true signer_may_refresh=false …
#   and NONE of the three "is off"/"is on" notices
pq 'sum by (pod, reason) (increase(rutli_sign_policy_refusals_total[15m]))'   # empty after 15 min
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="error"}[15m]))'   # 0
kubectl -n rutli delete pod rutli-cosigner-2 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-2 --timeout=300s   # [MUTATES]
kubectl -n rutli get pods
kubectl -n rutli delete pod rutli-cosigner-0 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-0 --timeout=300s   # [MUTATES]
for o in 0 1 2; do kubectl -n rutli logs rutli-cosigner-$o -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep 'signing policy'; done
```

### 4.4 Positive test: real signs succeed

```bash
kubectl -n $PNS exec deploy/participant -- sh -c 'grep "\"op\":\"sign\"" /rutli-state/audit.jsonl | tail -n 5'   # outcome=ok, intent=<hex>, after the restarts
pq 'sum by (pod) (increase(rutli_sign_requests_total{result="ok"}[30m]))'      # > 0
pq 'sum by (pod) (increase(rutli_epoch_check_skipped_total[30m]))'             # 0
```

If traffic is idle, a wallet Tap through the soak validator (as on 2026-10-09) produces a protocol
signature on demand.

### 4.5 Negative test: an intent-less Sign is refused by every node

No `rutli-cosigner` subcommand sends a raw `Sign`, so use `grpcurl` with the workstation's driver
certificate against each node as leader. The key id `frost-rc3-negative-test` lies inside the ACL
prefix and **does not exist**, so nothing can be signed whatever happens: an enforcing node refuses
the missing intent **before** looking up the key (`service.rs`, `check_intent` runs before
`sign_with_intent`); a non-enforcing node would answer NotFound (`unknown key id`).

```bash
pf_start
CERT=$(jq -r '.tls.cert' $D/client-driver.json); KEY=$(jq -r '.tls.key' $D/client-driver.json); CA=$(jq -r '.tls.ca_cert' $D/client-driver.json)
MSG=$(head -c 34 /dev/zero | base64)
for i in 1 2 3; do
  echo "== node $i as leader"
  grpcurl -cacert "$CA" -cert "$CERT" -key "$KEY" -servername cosigner$i \
    -import-path frost/cosigner/proto -proto cosigner.proto \
    -d "{\"key_id\":\"frost-rc3-negative-test\",\"message\":\"$MSG\"}" \
    127.0.0.1:1910$i rutli.cosigner.v1.Signer/Sign
done
```

Each node must answer `Code: PermissionDenied` with `signing intent refused: Sign for
frost-rc3-negative-test carries no signing intent and this node requires one
(signing_policy.require_intent)`. **Stop and roll back** if any node answers `NotFound` / `unknown
key id` (it does not enforce) or refuses for another reason (`not pinned` = the workstation key is not
pinned: fix that, then repeat). This test fires `RutliSignPolicyRefusals{reason="missing"}` for 15
minutes; note it in the soak log.

A refresh with the driver certificate is now refused too (`client "driver" may not call Refresh`):
that is expected, and on the soak nothing else can refresh until the CA rotation (0.8).

### 4.6 Rollback (phase 4)

Turning a flag off is immediate (restart). Fast path, all three nodes:

```bash
helm -n rutli rollback rutli $REV_P3                                          # [MUTATES] ConfigMap only
for o in 1 2 0; do kubectl -n rutli delete pod rutli-cosigner-$o && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-$o --timeout=300s; done   # [MUTATES]
```

A driver rollback (2.7) after this phase needs this rollback first, or every sign is refused.

---

## Phase 5 — `audit-cross-check`: first run and schedule

Offline and read-only. Copy the journals **first**, the driver audit log **second**
(`docs/audit-cross-check.md`). On the legacy topology the journals are at
`rutli-cosigner-<o>:/data/journal` (the image ships `tar`, so `kubectl cp` works):

```bash
mkdir -p $D/xc/journals
for o in 0 1 2; do
  kubectl -n rutli cp -c cosigner rutli-cosigner-$o:/data/journal $D/xc/journals/cosigner$((o+1))
done
kubectl -n $PNS exec deploy/participant -- cat /rutli-state/audit.jsonl > $D/xc/audit.jsonl
rutli-cosigner audit-cross-check --driver-audit $D/xc/audit.jsonl \
  --journal $D/xc/journals/cosigner1 --journal $D/xc/journals/cosigner2 --journal $D/xc/journals/cosigner3 \
  --min-journals 2 --allow-no-intent
echo "exit $?"
```

`--min-journals 2` = the threshold, since every node's journal is supplied. Exit 0 = consistent;
1 = `DISCREPANCY:` lines; 2 = an unreadable file or a broken chain (keep the evidence). A sign still
in flight during the copy can show once as a discrepancy: run again.

`--allow-no-intent` is for this first run only: the journals hold the `no-intent` signatures of the
phase 1 → 2 window. Run it once more **without** it:

```bash
rutli-cosigner audit-cross-check --driver-audit $D/xc/audit.jsonl \
  --journal $D/xc/journals/cosigner1 --journal $D/xc/journals/cosigner2 --journal $D/xc/journals/cosigner3 \
  --min-journals 2
```

Expected: exit 1 with one line per (journal, key) `… N signature(s) with key K without a signing
intent (<first> .. <last>)`. Accept them only if every `<last>` is before **T2** (phase 2). Any other
`DISCREPANCY:` line, or a no-intent range ending after T2, is an unexplained signature: investigate
(`docs/audit-cross-check.md` table). The tool has no time-window option, so these rollout-window lines
appear in every run until journal retention (`journal_retention_days`, 90) drops them.

**Schedule:** weekly and after any incident touching the participant host or the driver certificate,
as a **manual operator task** (calendar entry, results in the soak log). Do not automate it with a
CronJob that `kubectl exec`s / `kubectl cp`s into the cosigners: a standing `pods/exec` principal is
exactly what audit C3 removed and `scripts/check-deploy-policy.sh` refuses. After the per-node
migration the backup sidecar's tars carry `journal/` too; the weekly run can then use the latest
backup per node instead of `kubectl cp`.

---

## Gate — per-node seal migration

[runbook-per-node-seal.md](runbook-per-node-seal.md) (written for rc.2, valid for rc.3: it carries the
release's values through `helm get values`). Do it **before phase 7** (DEK rotation exists only for
per-node seal bundles: `seal rotate-dek --in <bundle>`; there is nothing to rotate under the shared
`secret_env` master) and preferably **before phase 6**: undoing v2 below rc.3 needs `keyfile
downgrade` with the daemon stopped, and only `topology: perNode` has `maintenanceNodes` for that; on
the legacy StatefulSet a single node's daemon cannot be stopped cleanly. Notes for running it after
this runbook:

- Pass the batch C overlay too: `-f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values-pernode.yaml -f deploy/soak/cosigner-values-batch-c.yaml`.
- Its `verify-key` steps use `$D/client-driver.json` (no operator certificate); drop `--sign-test`
  for the DKG keys (it signs imported keys only).
- Its driver change (per-node Services with `tls-name`) keeps `cluster-id` in the HOCON. The pins,
  ACL, journals (`/data/journal`), `data_dir/cluster-id` and the key files stay on the same PVCs.
- From then on the pods are `rutli-cosigner-n<i>-0`, the configs `/config/cosigner-<i>.json`, and the
  journals for phase 5 `rutli-cosigner-n<i>-0:/data/journal`.

---

## Phase 6 — Key-file v2

Binds each sealed file's header (cluster, node, key id, kind, epoch, digest, DEK id) into the AEAD
(audit M4). Works on the legacy master too (`seal.rs`: the master-derived DEK has a `dek_id`), but see
the gate above for why perNode first. Do it only once no cosigner rollback below rc.3 is wanted.

### 6.1 Backup, then generate the cluster UUID once

```bash
for o in 0 1 2; do
  kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- tar -C /data -cf - keys journal > $D/pre-v2-node$((o+1)).tar   # perNode: pod rutli-cosigner-n<i>-0
done
CLUSTER_UUID=$(uuidgen | tr 'A-Z' 'a-z'); echo $CLUSTER_UUID      # record it in the soak log: one value for the cluster, never changed
```

`keyfile.cluster_uuid` is a configured identity, deliberately **not** the CA-derived cluster id (a CA
rotation must not make key files unreadable). Validation: lowercase hyphenated UUID; `write_version:
2` needs it and needs sealing (`config.rs`, `KeyFileConfig::validate`).

### 6.2 Overlay, upgrade, canary restarts

Setting `cluster_uuid` and `write_version: 2` in one rollout is equivalent to the CHANGELOG's two
steps: each node gets both at its restart, and a node only binds its own files.

```bash
yq -i ".keyfile = {\"cluster_uuid\": \"$CLUSTER_UUID\", \"write_version\": 2}" deploy/soak/cosigner-values-batch-c.yaml
helm -n rutli get values rutli -o yaml > $D/rutli-values.exported.yaml
helm template rutli deploy/helm/rutli-cosigner -n rutli \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml \
  | yq 'select(.kind == "ConfigMap" and .metadata.name == "rutli-cosigner-config") | .data["cosigner-1.json"]' | jq '.keyfile'
helm -n rutli upgrade rutli deploy/helm/rutli-cosigner \
  -f $D/rutli-values.exported.yaml -f deploy/soak/cosigner-values.yaml -f deploy/soak/cosigner-values-batch-c.yaml   # [MUTATES]
helm -n rutli history rutli | tail -1                                         # note as REV_P6
```

(After the per-node migration use its values file instead of `deploy/soak/cosigner-values.yaml`. The
perNode StatefulSets carry no config checksum either, so a config-only upgrade restarts nothing there
too: delete `rutli-cosigner-n<i>-0` one at a time, node 2 → node 3 → node 1, with the same checks.)

Per node, in the order node 2 → node 3 → node 1:

```bash
o=1; i=$((o+1))                                                               # then o=2, then o=0
kubectl -n rutli delete pod rutli-cosigner-$o && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-$o --timeout=300s   # [MUTATES]
kubectl -n rutli logs rutli-cosigner-$o -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'key-file format|re-sealed key files'   # write_version=2 cluster_uuid=<uuid>; re-sealed count=<n files>
kubectl -n rutli exec rutli-cosigner-$o -c cosigner -- rutli-cosigner --config /config/cosigner-$i.json keyfile status
#   node <i> — writes v2 (cluster_uuid <uuid>), current DEK <id>
#   … every file "v2, current DEK" … "<n> file(s): 0 not yet v2, 0 under a previous DEK"
```

`keyfile status` is read-only and takes no instance lock, so it runs beside the daemon. After all
three: `m rutli_keyfiles` shows only `format="v2",dek="current"`; `RutliKeyFilesUnopenable` quiet;
signing and decrypts unaffected. Take a fresh backup (as 6.1) — v2 tars are the ones that will still
restore after `accept_v1: false`.

### 6.3 Later: `accept_v1: false` (M4 closed only from here)

Once no rollback below rc.3 is wanted and every node's `keyfile status` shows `0 not yet v2`:

```bash
yq -i '.keyfile.accept_v1 = false' deploy/soak/cosigner-values-batch-c.yaml
# render check, helm upgrade, canary restarts exactly as 6.2; each node logs accept_v1=false
```

Until `accept_v1: false` is on **every** node, any v1 file sealed under the node's DEK is accepted, and
even then a rollback to an older genuine v2 file of the same key and node passes the AEAD (the epoch
checks catch shares; `docs/security/threat-model.md`). Backups taken before 6.2 (v1) no longer
restore after this.

### 6.4 Rollback / downgrade (phase 6)

- Staying on rc.3: set `keyfile.write_version: 1` (and `accept_v1: true`) — rc.3 keeps reading the v2
  files; new files are v1. Nothing else needed.
- Going below rc.3 (rc.2 reads only v1): on **each** node, daemon stopped, `rutli-cosigner --config
  /config/cosigner-<i>.json keyfile downgrade` with `write_version: 1` already in its config, then
  the image rollback. On perNode: `maintenanceNodes: [<i>]`, one node at a time
  (`docs/disaster-recovery.md` §3h). On legacy there is no supported way to stop one node's daemon:
  migrate first (gate above).

---

## Phase 7 — DEK rotation, per node (perNode topology only)

**Prerequisite: the per-node seal migration.** `seal rotate-dek` takes a node's seal bundle file
(`share_seal.secret_file`); the legacy `secret_env` master has nothing to rotate, and rotating it would
mean re-deriving every node's DEK from one secret again. After the migration each node's bundle lives
in Secret `rutli-seal-node-<i>`, key `node.json`, and the bundles hold the master-derived DEKs (`seal
split-legacy` keeps them so nothing is re-sealed) — this phase moves each node to a fresh random DEK,
after which the legacy master protects nothing new (decision P1, CHANGELOG step 8).

One node at a time; the other two keep signing. For node `i` (pods `rutli-cosigner-n<i>-0`):

### 7.1 Backup, rotate, deploy

```bash
i=2                                                                          # then 3, then 1
kubectl -n rutli exec rutli-cosigner-n$i-0 -c cosigner -- tar -C /data -cf - keys journal > $D/pre-dek-node$i.tar
kubectl -n rutli get secret rutli-seal-node-$i -o jsonpath='{.data.node\.json}' | base64 -d > $D/node-$i.json
rutli-cosigner seal inspect --in $D/node-$i.json                             # node <i>, share_dek id <OLD> (+0 previous)
rutli-cosigner seal rotate-dek --in $D/node-$i.json --out $D/node-$i-rotated.json
rutli-cosigner seal inspect --in $D/node-$i-rotated.json                     # node <i>, share_dek id <NEW> (+1 previous), same dist_public_key
kubectl -n rutli create secret generic rutli-seal-node-$i --from-file=node.json=$D/node-$i-rotated.json \
  --dry-run=client -o yaml | kubectl apply -f -                              # [MUTATES]
kubectl -n rutli delete pod rutli-cosigner-n$i-0 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-n$i-0 --timeout=300s   # [MUTATES]
```

### 7.2 Verify the re-seal

```bash
kubectl -n rutli logs rutli-cosigner-n$i-0 -c cosigner | sed 's/\x1b\[[0-9;]*m//g' | grep -E 're-sealed key files|share sealing enabled'
kubectl -n rutli exec rutli-cosigner-n$i-0 -c cosigner -- rutli-cosigner --config /config/cosigner-$i.json keyfile status
#   current DEK <NEW>; every file "v2, current DEK"; "0 under a previous DEK — the previous DEK(s) can be dropped … after a backup"
```

**Stop if** any file is still `PREVIOUS DEK` or `UNKNOWN DEK`. Signing and decrypts continue;
`RutliKeyFilesUnopenable` quiet.

### 7.3 Backup under the new DEK

Backups taken before 7.1 open only with the previous DEK. Wait for a `BACKUP_OK node=<i> … stamp=…`
from the sidecar with a stamp **after** the 7.2 check (the daily run; the run-on-start backup may race
the re-seal), or take a manual one:

```bash
kubectl -n rutli logs rutli-cosigner-n$i-0 -c backup | grep BACKUP_ | tail -2
kubectl -n rutli exec rutli-cosigner-n$i-0 -c cosigner -- tar -C /data -cf - keys journal > $D/post-dek-node$i.tar   # alternative
```

### 7.4 **POINT OF NO RETURN (this node):** drop the previous DEK

```bash
rutli-cosigner seal drop-previous --in $D/node-$i-rotated.json --out $D/node-$i-final.json
rutli-cosigner seal inspect --in $D/node-$i-final.json                       # share_dek id <NEW> (+0 previous)
kubectl -n rutli create secret generic rutli-seal-node-$i --from-file=node.json=$D/node-$i-final.json \
  --dry-run=client -o yaml | kubectl apply -f -                              # [MUTATES]
kubectl -n rutli delete pod rutli-cosigner-n$i-0 && kubectl -n rutli wait --for=condition=Ready pod/rutli-cosigner-n$i-0 --timeout=300s   # [MUTATES]
kubectl -n rutli exec rutli-cosigner-n$i-0 -c cosigner -- rutli-cosigner --config /config/cosigner-$i.json keyfile status   # current DEK <NEW>, nothing previous/unknown
```

From here this node's backups from before 7.3 no longer open on it. Escrow `$D/node-$i.json` (the
pre-rotation bundle) offline for as long as those backups are kept, or record that they are given up
(P1); then `shred -u $D/node-$i*.json`. Repeat 7.1–7.4 for the next node.

**Retiring the legacy master** (CHANGELOG step 8): it stays escrowed offline until all three nodes
passed 7.4 **and** every backup sealed under a master-derived DEK (every tar before 7.1, including
`$D/pre-rc3-node*-keys.tar`) has aged out; then it is destroyed (decision P1).

---

## Phase 8 — P9: fresh keys under ceremony protocol 2 (operator decision)

`frost-namespace` and `frost-signing` were generated by DKG on **0.3.0** (2026-10-07), a release
without direct round-2 delivery: each was exposed to its ceremony's leader, which could compute the
group secret. A refresh cannot repair a DKG key (the secret does not change). The threat model
accepts this for DevNet: **soak keys are test material** (`docs/security/threat-model.md`, "Earlier
releases"). Nothing in this runbook destroys or replaces them. Options, as a rehearsal of what a
production cutover would need:

- **Protocol key (`frost-signing`): rotate it.** Canton rotates staged with no signing gap
  (`docs/key-rotation.md`): `participant.keys.secret.rotate_node_key(122060d65c8fd0bc7712ddfc73ae799206b126bff81de132d4ebd8e244a0e708d198, "<new name>")`
  makes the driver run a fresh DKG under ceremony protocol 2 (new id `frost-<new name>`) and Canton
  signs the OwnerToKeyMapping change with the namespace key. Before it: the new id must be inside the
  ACL (`frost-` covers it) and should match a `rate_limits` rule — name it `signing-…` so
  `frost-signing` still matches, or add a rule first (otherwise the 300/min, 20 000/day default
  applies, below the measured traffic headroom). Check `rutli_ceremonies_staged` = 0 after, and
  `verify-key` on the new key (epoch 1). The old key stays on the cosigners (no FROST delete path).
- **Namespace key (`frost-namespace`): not rotatable.** It *is* the identity. A fresh namespace means a
  **new party / validator identity** (a new `stakecraft-rutli-soak-…::<new fingerprint>`), i.e. a fresh
  onboarding as a new validator — B0 kept the namespace, so a B0-style cutover does not help. On DevNet
  that is a new soak validator, a new traffic budget and a new soak clock; the old party's holdings stay
  with the old identity.
- **Do nothing (default for DevNet):** keep running on the exposed keys and record P9 in the soak log.

Mainnet keys are generated or split only on a uniformly upgraded cluster on this release or later.

---

## Phase 9 — Hosted-key deletes: stay disabled

The default `hosted_keys.delete_allowlist` is empty (Helm `hostedKeys.deleteAllowlist: []`): every
`DeleteKey` is refused (PERMISSION_DENIED), including Canton's `keys.secret.delete`. Normal Canton
operation never deletes (key rotation does not; `docs/hosted-keys.md`, audit F9). Leave it so on the
soak. The B4 `b4-…` keys stay as unreferenced cleanup candidates; FROST shares have no delete path.

To enable later (every node on rc.3, every node has **started once** on rc.3 with hosted keys on so
`data_dir/delete-policy.json` records the grant time, audit F7):

```yaml
hostedKeys:
  deleteAllowlist: [<delete-role CN>]        # never a cosigner CN; the driver's CN only if Canton must delete
  deleteAcl: { <CN>: ["<prefix>"] }          # optional
  deleteApprovalThreshold: 1                 # ≥ 1 recommended (decision P8); needs signingPolicy.approvers
  deleteGraceSecs: 604800                    # material kept in the tombstone for hosted-undelete
```

The same on every node, rolled out like phase 3. On the soak a delete-role certificate other than
`driver` needs the CA rotation first. The operator command is `rutli-cosigner --config <client config
with the delete-role certificate> delete-hosted-key --key-id <id> [--approvals-inbox <dir> --approvals
<n>]`.

---

## What can go wrong

| Symptom | Cause | What to do |
|---|---|---|
| Canton sign fails with RESOURCE_EXHAUSTED; `rutli_sign_rate_limited_total` > 0; `RutliSignRateLimited` | A per-key rate limit (default or `rate_limits` rule) too low. **Final**: the driver does not fail over, Canton sees a failed sign | Raise the rule in the overlay, `helm upgrade`, restart the pods. A restart does not reset the window (rebuilt from the journal). Re-measure (0.6) |
| `rutli_sign_policy_refusals_total{reason="expiry"}`; one node refuses every intent | Clock skew > `clock_skew_secs` (120 s) between driver and that node | Fix NTP on that host. A skewed member is excluded (signing continues on the other pair); a skewed **leader** (node 1) refuses every sign finally once intents are present |
| DKG/refresh answers FAILED_PRECONDITION during a roll | Mixed versions: a leader refuses a ceremony unless every node reports ceremony protocol 2; upgraded nodes refuse the old `DkgPart*`/`RefreshPart*` | Finish the roll (phase 1); no ceremony on a mixed cluster |
| `rutli_ceremonies_staged` > 0 for minutes after an interrupted roll | A ceremony staged on some nodes, a peer unreachable | Each node's resolver retries every 30 s: bring the peer back and wait. `ceremony resolve --ceremony-id <id>` needs the daemon stopped (perNode: `maintenanceNodes`). Never downgrade with a staged ceremony. `--assume-lost` only for a node whose disk is gone (`docs/ceremonies.md`) |
| `reason="cluster"` refusals; driver logs `DIFFERENT cluster ids` or re-learns the id | `frost.cluster-id` ≠ the cosigners' cluster id (or a cosigner on another id) | Correct `frost.cluster-id` (2.1) and restart the participant. While `require_intent` is off, `frost.sign-intents = off` is the emergency switch |
| A cosigner pod stays down with `cluster id mismatch` | `clusterId` dropped or changed by an upgrade without the saved values | Upgrade again with `-f <exported values>`; never set `clusterIdChangeAllowed` for this |
| `reason="pin"` refusals; driver or `verify-key` refused as `not pinned` | The certificate key is not in `signer_pins` | Fix the pin (3.1) or roll back phase 3 |
| `reason="acl"` refusals, or hosted decrypts refused | A key id outside `signer_acl` (a new prefix, e.g. B8) | Add the prefix; roll out like phase 3 |
| `reason="missing"` refusals after phase 4 | A signer without intents: an rc.2 driver, `frost.sign-intents = off`, a driver that lost the cluster id | Phase 4 rollback, then fix the driver |
| A node refuses one key, `rutli_sign_journal_errors_total` > 0 | Its sign journal for that key is unreadable/corrupt | The other nodes keep signing; investigate the journal, do not delete it (`docs/audit-cross-check.md`) |
| `rutli_stale_share{key}` = 1, `RutliStaleShare` | That node's share is behind a committed sharing (old restore, snapshot rollback) | It refuses to sign/lead the key; restore a current backup with the daemon stopped (`docs/disaster-recovery.md` §1) |
| rc.3 pod refuses to start naming key files | A plaintext key file under sealing, or a file bound to another key/node | 0.3; `keyfile migrate-plaintext` for a genuine plaintext file |
| A flag "set" in the overlay has no effect | `signing_policy` ignores unknown keys; or the pod was not restarted (legacy: no config checksum) | Check the rendered JSON and the `signing policy` startup line on every node |
| `soak-check` FAIL on `RutliSignerAclAbsent` / `RutliSignIntentAbsent` / `RutliSignPolicyRefusals` | Rollout windows (see Scheduling) | Expected only inside the windows; outside them, a real finding |

## Final verification checklist

- [ ] `helm -n rutli history rutli`: rc.3 revisions for phases 1, 3, 4 (and 6) recorded; rollback targets known.
- [ ] Every cosigner pod runs `0.4.0-rc.3@sha256:f4d92758cc1b7f8036fdabe67aab79ac60bce6499e549f853ca160efb1b631e8` and logs `signing policy … require_intent=true signer_acl_required=true signer_may_refresh=false acl_entries=1 pinned_cns=1`, no `require_epoch_match is off`.
- [ ] Rendered config on every node: `signing_policy.rate_limits` (namespace first), `signer_acl.driver = ["frost-","rutli-"]`, `signer_pins.driver = [<DRIVER_PIN>]`, the four switches; no `refresh_allowlist`; `hosted_keys` without `delete_allowlist`.
- [ ] `verify-key` for `frost-namespace` and `frost-signing`: `ok`, one epoch, one PKP digest, no stale node.
- [ ] `rutli_ceremonies_staged` 0, `rutli_stale_share` 0, `rutli_sign_journal_errors_total` 0, `rutli_sign_rate_limited_total` flat, `rutli_sign_intent_absent_total` flat, `rutli_signer_acl_absent_total` flat, `rutli_epoch_check_skipped_total` flat.
- [ ] Driver: `build 0.4.0-rc.3`, `frost.cluster-id = "453bb4aea2088bb5"`, audit sign lines carry `msg=` and `intent=<hex>`, no `intent=none`, `sig-verify=failed` 0, `StateCheck` OK on a fresh copy.
- [ ] Negative test: all three nodes refuse an intent-less Sign with `carries no signing intent`.
- [ ] `audit-cross-check --min-journals 2`: only pre-T2 no-intent ranges; weekly calendar entry exists.
- [ ] Batch C alerts and dashboard rows applied (`kubectl apply -k deploy/monitoring`); `soak-check` PASS on the next scheduled run.
- [ ] (After the per-node migration) phase 6: `keyfile status` all `v2, current DEK` on every node; `rutli_keyfiles{format="v1"}` 0; `accept_v1: false` decision recorded.
- [ ] (After the per-node migration) phase 7 per node: new DEK, backup after rotation, previous DEK dropped, pre-rotation bundles escrowed or given up (P1).
- [ ] `deploy/soak/cosigner-values-batch-c.yaml` committed; soak log updated (times, revisions, `CLUSTER_UUID`, T2, P9 decision, refresh disabled until CA rotation).
- [ ] `$D` cleaned up (`rm -rf "$D"`) after the key tars moved off-cluster.

## Next

- [ca-rotation.md](ca-rotation.md): a new CA unlocks a `refresher` certificate (then `refreshAllowlist:
  [refresher]` and refreshes again), an operator certificate, and replacement driver certificates
  (a new pin per new key).
- B8 (split/import after rc.3): its prefix into `signer_acl`, a namespace `rate_limits` rule for it,
  before the ceremony.

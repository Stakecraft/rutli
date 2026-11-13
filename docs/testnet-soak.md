# Testnet soak — running a Splice DevNet validator on Rütli

The soak is the trust-building exercise between "CI-green" and "production authority keys": a real
Splice validator on Canton Network **DevNet**, its Ed25519 namespace/identity keys served by a
live 2-of-3 FROST cluster, run for **at least 14 days** with scheduled failure drills. The soak
tooling is in [`deploy/soak/`](../deploy/soak/). It serves two ways of running the soak (see
*Topology*): a single-host Docker Compose harness, and Kubernetes, which is how the live DevNet
soak runs.

> **Why DevNet, not TestNet:** DevNet onboarding is self-serve (mint a secret from any SV, plus an
> egress-IP allowlist); TestNet needs Tokenomics-Committee approval and a sponsor-issued secret.
> Start on DevNet; a TestNet re-run can follow with the identical setup once approved. The
> versions the DevNet soak runs are in the [soak log](soak-2026-10-devnet.md); the TestNet run
> starts with the v0.4.0 tag.

## Topology

| | Compose harness (one host) | Kubernetes (the live DevNet soak) |
|---|---|---|
| Cosigners | `deploy/soak/docker-compose.yml` (includes `deploy/frost/docker-compose.tls.yml`) | Helm chart `deploy/helm/rutli-cosigner`, release values `deploy/soak/cosigner-values*.yaml` |
| Monitoring | Prometheus + Grafana in the same compose file | kube-prometheus-stack + `kubectl apply -k deploy/monitoring` |
| Daily gate | `soak-check.sh` from cron | CronJob `rutli-soak-check`: `kubectl apply -k deploy/soak -n monitoring` |
| Validator | Splice compose bundle + `deploy/soak/validator/` | Splice participant Helm chart, driver jar on `EXTRA_CLASSPATH` ([`deploy/k8s/README.md`](../deploy/k8s/README.md) §4) |
| Share backups | `rutli-cosigner backup`, node stopped | per-pod `backup` sidecar (`topology: perNode`) |

The live soak's setup, versions and changes are in the
[soak log](soak-2026-10-devnet.md). Its cosigners still run the chart's `legacy` topology
(`deploy/soak/cosigner-values.yaml`), so they have no backup sidecar yet; see *Backups* below.

**Compose harness.** One host (≥ 4 vCPU / 32 GB / SSD) runs both halves on one docker network:

- **KMS half** — `deploy/soak/docker-compose.yml`: the mTLS + sealed-shares cosigner cluster
  (from `deploy/frost`) plus Prometheus (45-day retention, alert rules loaded) and Grafana
  (dashboard pre-provisioned, anonymous read-only).
- **Validator half** — the stock Splice compose validator bundle, with two Rütli additions
  (`deploy/soak/validator/`): a thin derived participant image that puts `rutli-driver.jar` on the
  Canton classpath via `EXTRA_CLASSPATH` (the same seam Splice itself uses for its CometBFT
  sequencer driver), and a compose overlay injecting the `crypto.provider = kms` block through the
  participant's `ADDITIONAL_CONFIG_*` mechanism. No Splice images are forked.

A single-host soak proves the KMS, not trust-domain separation — production still means one
cosigner per host/account/region (see `deploy/k8s/README.md`).

## Day 0 — bring-up

Steps 1–4 are the Compose harness. On Kubernetes, install the cosigners with the Helm chart
([`deploy/helm/rutli-cosigner/README.md`](../deploy/helm/rutli-cosigner/README.md)) and point the
participant at them ([`deploy/k8s/README.md`](../deploy/k8s/README.md) §4). The fresh-participant
and `key-prefix` rules of step 4 apply unchanged, and so does step 5.

1. **KMS stack up:**
   ```sh
   scripts/gen-frost-certs.sh 3 deploy/frost/certs
   export RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"     # store in your secret manager
   docker compose -f deploy/soak/docker-compose.yml up -d --build
   PROM=http://localhost:9090 deploy/soak/soak-check.sh   # expect FAIL only on "signatures" (no traffic yet)
   ```
2. **Driver + derived participant image:**
   ```sh
   sbt driver/assembly
   cd deploy/soak/validator
   cp ../../../driver/target/scala-2.13/rutli-driver.jar .
   mkdir -p certs && cp ../../frost/certs/{ca.crt,driver.crt,driver.key} certs/
   # IMAGE_REPO/IMAGE_TAG from the Splice bundle's .env — versions must match the bundle
   docker build -f Dockerfile.participant --build-arg IMAGE_REPO=… --build-arg IMAGE_TAG=… \
     -t rutli-canton-participant:… .
   ```
3. **Splice bundle** (validator docs: `docs.dev.sync.global`, *Compose validator*):
   download the `…_splice-node.tar.gz` release, verify the participant node key in the base
   image's `app.conf` matches the overlay (see the note in `compose-rutli-kms.yaml`), and — since
   DevNet runs a newer Canton patch than the driver was built against — run the driver conformance
   suite once against that participant version (`sbt driver/test` against the bundle's Canton
   API jars) before onboarding.
4. **Onboard** (fresh participant only — `crypto.provider = kms` cannot be retrofitted):
   ```sh
   # DevNet self-serve secret (valid 1 h):
   curl -X POST "$SPONSOR_SV_URL/api/sv/v0/devnet/onboard/validator/prepare"
   ./start.sh -s "$SPONSOR_SV_URL" -o "$SECRET" -p <org>-soak-1 -m <migration_id> \
              -n soak_default …    # -n joins the Rütli stack's docker network
   # apply deploy/soak/validator/compose-rutli-kms.yaml as an additional -f overlay
   ```
   Your host needs a network-allowlisted egress IP (give it to the sponsor SV) — the validator is
   outbound-only, no public ingress.

   **A second participant on the same cluster** needs its own `frost.key-prefix` in the overlay
   (e.g. `"soak2-"`), set *before* its first bootstrap. Without it, its DKG asks the cluster for the
   first participant's `frost-namespace`. Before 0.4.0-rc.3 that was refused with `ALREADY_EXISTS`
   (2026-10-07 bring-up); since then a DKG for a committed key returns it, so the second
   participant would be handed the first one's keys unless a `signer_acl` refuses its driver. See
   `docs/architecture.md` → *One cluster, several participants*.
5. **Acceptance:** participant boots, driver health OK in its log, its Ed25519 keys born via cluster DKG: a Splice
   validator has two, `frost-namespace` and `frost-signing`
   (`rutli_ceremony_requests_total{kind="dkg",result="ok"}` summed over the cosigners `== 2`),
   validator visible on Scan,
   `soak-check.sh` fully green within 24 h.

## Day 1–14+ — the soak proper

**Daily gate.** Compose harness, from cron:
```cron
0 8 * * *  PROM=http://localhost:9090 RUTLI_AUDIT_LOG=<driver state>/audit.jsonl /path/to/deploy/soak/soak-check.sh >> soak.log 2>&1
```
Kubernetes: the `rutli-soak-check` CronJob runs the same script daily at 08:00 UTC, metrics checks
only; read the verdict with `kubectl logs -n monitoring -l app=rutli-soak-check --tail=20`. The
audit log sits on the participant's volume, so check it by hand, e.g. weekly (the commands are in
[`deploy/soak/k8s/soak-check-cronjob.yaml`](../deploy/soak/k8s/soak-check-cronjob.yaml)).

**Backups** of each cosigner's sealed key files, on a schedule and after every key change (`restore`
refuses a share older than the live one, so a backup from before a refresh is no use). Keep them off the
node's host ([`disaster-recovery.md`](disaster-recovery.md#1-restore-a-single-cosigner-from-backup)).

- Compose harness: `rutli-cosigner backup` runs with the node stopped. One node at a time, so the
  other two keep signing:
  ```sh
  C="docker compose -f deploy/soak/docker-compose.yml"; D=backup-$(date +%F)
  $C stop cosigner1
  $C run --rm --no-deps cosigner1 --config /config/cosigner1.json backup --out /data/$D
  $C start cosigner1
  $C cp cosigner1:/data/$D ./cosigner1-$D     # then ship it off the host
  ```
- Kubernetes: with `topology: perNode` and `backup.enabled=true` a `backup` sidecar in each cosigner
  pod tars that node's sealed files daily to that node's destination; each run logs `BACKUP_OK` or
  `BACKUP_FAILED` ([chart README, *Backups*](../deploy/helm/rutli-cosigner/README.md#backups)). No
  backup Job, no second mount of a cosigner volume. The live soak runs the `legacy` topology without
  it and relies on manual copies of the sealed files (soak log) until the per-node migration
  (`deploy/soak/cosigner-values-pernode.example.yaml` turns the sidecar on).

**Drill calendar — each drill during live traffic, each verified by metrics + a green
`soak-check.sh` after:**

| Week | Drill | Pass signal |
|---|---|---|
| 1 | Kill one cosigner 30 min, restart | signing uninterrupted (2-of-3); `RutliCosignerDown` fires + resolves; skips counter only if the dead node was tried |
| 1 | Proactive refresh mid-traffic: `rutli-cosigner --config client-refresher.json refresh --key-id <key>` (note 1) | group key unchanged; `kind="refresh",result="ok"`; signing continues after |
| 2 | Full cosigner-cluster restart (one node at a time) | no sign errors; shares reload from sealed disk |
| 2 | Restore drill: wipe one cosigner's data dir, `restore` from backup (note 2) | node rejoins, cluster signs; group key unchanged |
| 3+ | Participant restart + host reboot | validator recovers; journal + audit chain intact across restart |

1. `client-refresher.json` is a client config with the refresher certificate
   (`scripts/gen-frost-certs.sh` issues `refresher.{crt,key}`), whose CN is on every cosigner's
   `refresh_allowlist`; `deploy/k8s/client-config.yaml` has one. The Compose configs in
   `deploy/frost/config-tls/` set no `refresh_allowlist`: add it before the drill. Since
   0.4.0-rc.6 the cosigners require a ceremony intent by default; the command signs one with that
   certificate ([ceremonies.md](ceremonies.md#ceremony-intents), [key-rotation.md](key-rotation.md)).
   On the live soak the drill waits for the CA rotation (soak log).
2. Procedure: [disaster-recovery.md §1](disaster-recovery.md#1-restore-a-single-cosigner-from-backup),
   daemon stopped. On Kubernetes it needs the backup sidecar, so on the live soak it waits for the
   per-node migration.

## Exit criteria (all required)

- [ ] ≥ 14 consecutive days on DevNet, validator live on Scan the whole time
- [ ] Zero KMS-attributable sign errors (`rutli_sign_requests_total{result="error"}` flat)
- [ ] p99 sign latency < 1 s sustained
- [ ] ≥ 1 live proactive refresh — group key unchanged, signing uninterrupted
- [ ] ≥ 1 cosigner outage + recovery with no signing gap; alerts fired and resolved correctly
- [ ] ≥ 1 backup→wipe→restore drill passed
- [ ] Audit hash-chain verifies end-to-end (`HashChainedAuditLog.verify`) over the full soak window
- [ ] Signing-journal history complete; replay flags explainable (Canton legitimately re-signs)
- [ ] Every alert that fired maps to a drill or a real event — no false silence, no unexplained noise

Record findings (dates, incidents, metric snapshots) in the soak log; the summary feeds the
security-audit scope. **A green soak plus the third-party audit are the two gates left before
production authority keys** (see README → Status).

## Incidents

Signing outage = incident even on DevNet (practice like production). A failed ceremony
(`result="error"`) is never retried blind: collect all three cosigner logs first — the guard
fails closed, so state is safe, but the cause must be understood. Escalation, key-loss and
compromise procedures: `docs/disaster-recovery.md`.

### 2026-10-07 — one unreadable key store, total signing outage

**What happened.** A backup job remounted cosigner-0's RWO data volume and `/data/keys` became
unreadable to the daemon (`Permission denied (os error 13)`). The pod stayed `READY 1/1` — the
probes were TCP-only and `Signer.Health` always answered ok — and every `Sign`/`Dkg` it led failed
with `INTERNAL`. The driver only failed over on UNAVAILABLE / DEADLINE_EXCEEDED and cosigner-0 was
first in `frost.endpoints`, so all 54 signs in the window failed while cosigners 1 and 2 were
healthy. No key material was at risk; the outage was pure availability.

**What the investigation added.** Driver failover alone would not have restored signing. A
cosigner that has signed since start-up keeps its share cached, so after its volume broke it still
passed round 1 (`NonceStore::is_consumed` read EACCES as "not burnt") and failed in round 2 on the
nonce-marker write — and with peers tried in identifier order it sat in *every* leader's quorum.
Any leader, not just cosigner-0, would have failed.

**What changed.** Driver: a leader-side `INTERNAL`/`UNKNOWN` is "this leader is sick" for
operations that are safe to re-issue through another leader (sign, public-key and key-exists
reads, hosted-key decrypt/symmetric reads) — never for DKG, hosted key generation or delete; each
hop is logged at WARN and recorded as `failover=<from>→<to> reason=<CODE>` in the operation's
audit entry; the driver keeps leading from the last node that answered. Cosigner: the nonce lookup
fails closed, and a node whose key-store probe last failed refuses round 1 and declines to lead
`Sign`/`Dkg`/`Refresh` with `UNAVAILABLE`, so leaders sign around it with the other two. Its
`Health` and the new `rutli-cosigner health` readiness probe fail when the key store cannot be
listed, opened or written; `rutli_keystore_unreadable` / `RutliKeystoreUnreadable` (critical)
page on it, and `rutli_sign_round1_skips_total` climbs on the healthy leaders.

**If it fires again.** `kubectl -n rutli get pods` (the sick node shows `READY 0/1`), then
`kubectl exec … -- ls -la /data/keys` and `mount | grep /data` on that pod; find what touched the
PVC (CronJobs, operators). Signing continues on the other two nodes but the margin is zero: fix
the volume before anything else, and do not run a ceremony until all three are ready. Grep the
audit log for `failover=` to see exactly which operations were re-issued and where.

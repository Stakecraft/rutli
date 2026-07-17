# Testnet soak — running a Splice DevNet validator on Rütli

The soak is the trust-building exercise between "CI-green" and "production authority keys": a real
Splice validator on Canton Network **DevNet**, its Ed25519 namespace/identity keys served by a
live 2-of-3 FROST cluster, run for **at least 14 days** with scheduled failure drills. Everything
below is scripted in [`deploy/soak/`](../deploy/soak/).

> **Why DevNet, not TestNet:** DevNet onboarding is self-serve (mint a secret from any SV, plus an
> egress-IP allowlist); TestNet needs Tokenomics-Committee approval and a sponsor-issued secret.
> Start on DevNet; a TestNet re-run can follow with the identical setup once approved.

## Topology

One host (≥ 4 vCPU / 32 GB / SSD) runs both halves on one docker network:

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
5. **Acceptance:** participant boots, driver health OK in its log, namespace key born via cluster
   DKG (`rutli_ceremony_requests_total{kind="dkg",result="ok"} == 1`), validator visible on Scan,
   `soak-check.sh` fully green within 24 h.

## Day 1–14+ — the soak proper

**Daily (cron):**
```cron
0 8 * * *  PROM=http://localhost:9090 RUTLI_AUDIT_LOG=<driver state>/audit.jsonl /path/to/deploy/soak/soak-check.sh >> soak.log 2>&1
30 3 * * * docker exec soak-cosigner1-1 rutli-cosigner --config /config/cosigner1.json backup --out /data/backup-$(date +\%u)
```
(rotate the same backup cron across all three cosigners; ship `/data/backup-*` off-host.)

**Drill calendar — each drill during live traffic, each verified by metrics + a green
`soak-check.sh` after:**

| Week | Drill | Pass signal |
|---|---|---|
| 1 | Kill one cosigner 30 min, restart | signing uninterrupted (2-of-3); `RutliCosignerDown` fires + resolves; skips counter only if the dead node was tried |
| 1 | Proactive refresh mid-traffic: `rutli-cosigner refresh --key-id <key>` | group key unchanged; `kind="refresh",result="ok"`; signing continues after |
| 2 | Full cosigner-cluster restart (one node at a time) | no sign errors; shares reload from sealed disk |
| 2 | Restore drill: wipe one cosigner's data dir, restore from backup | node rejoins, cluster signs; group key unchanged |
| 3+ | Participant restart + host reboot | validator recovers; journal + audit chain intact across restart |

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

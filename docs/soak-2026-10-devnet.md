# Soak log — Splice DevNet, October 2026

Running record for the soak described in [testnet-soak.md](testnet-soak.md). Dates/times UTC.

## Setup

| | |
|---|---|
| Network | Canton Network **DevNet**, migration id 1, Splice 0.9.0, Canton 3.6.1 |
| Validator | `stakecraft-rutli-soak-1::12203286ffe2…` (fresh identity; sponsor: Global Synchronizer Foundation, `sv.sv-1.dev.global.canton.network.sync.global`, self-served DevNet secret) |
| Participant | Splice `splice-participant` 0.9.0 chart, `rutli-driver.jar` **0.3.0** on `EXTRA_CLASSPATH`, `backend = "frost"`, `hosted-keys = true`, `delegate = "none"` — **no local key material at all** |
| Cosigners | 3 × `rutli-cosigner:0.3.0` (Helm chart 0.3.0), 2-of-3, mTLS, sealed shares, `peer_allowlist`, `hosted_keys` on, one per Hetzner location (hel / nbg / fsn) |
| Keys | `frost-namespace`, `frost-signing` (FROST DKG); `rutli-enc-encryption-d625b676…` (RSA-2048, cluster-hosted, replicated 3/3) |
| Monitoring | cluster kube-prometheus-stack via `deploy/monitoring` (3/3 targets, 14 rules), daily `rutli-soak-check` CronJob in `monitoring`, Grafana dashboard ["Rütli FROST Cosigner"](https://monitoring.prod.cloud.stakecraft.com/d/rutli-cosigner/ruetli-frost-cosigner?orgId=1&var-datasource=prometheus) (StakeCraft login; fallback `kubectl -n monitoring port-forward svc/prometheus-grafana 3000:80`). Its *Sign Latency* panel stays empty while the cosigners run ≤ 0.3.1, which export a summary instead of a histogram ([#6](https://github.com/Stakecraft/rutli/pull/6)) |
| Prometheus retention | **10 d** (stack default) — shorter than the 45 d the soak doc asks for; daily verdicts are kept in the CronJob history instead |

## Day 0 — 2026-10-07

**Bring-up.** Cosigner cluster upgraded 0.2.1 → 0.3.0 in place (shares on PVCs reloaded;
the July `frost-namespace`/`frost-signing` shares of the previous, dead validator were moved to
`/data/retired-2026-07/` on every node first — the DKG refused to overwrite them, as designed).
Splice charts 0.7.0 → 0.9.0 with a fresh participant identity (old databases kept as
`zz_old_*`). Three bring-up blockers, all configuration:

1. the 0.9.0 participant chart requests 16 GiB; the node also hosts two other DevNet validators
   — set 4 GiB / 8 GiB like them;
2. the cosigner NetworkPolicy admits only pods labelled `rutli.io/client=true` — the chart's
   `pod.labels` must carry it or every FROST call is `UNAVAILABLE`;
3. retired shares (above).

06:03:08 DKG `frost-namespace` ok · 06:03:09 DKG `frost-signing` ok · 06:03:11 hosted RSA key
generated and replicated · 06:04 first threshold signatures · 06:14:35 `ValidatorLicense …
is visible` — onboarded. Validator visible on sv-1 Scan.

**Incident #1 — signing outage, 08:48:15 → 08:53:37 (last failed sign; node restarted 09:00),
54 failed signs, 0 after.**

- *Cause:* a first version of the cosigner backup CronJob mounted cosigner-0's data PVC into a
  second pod on the same node. After that mount, `data_dir/keys` was no longer readable by the
  running cosigner (the job pod carried no `fsGroup`; the volume's group ownership was not
  what the StatefulSet's `fsGroup: 10001` had established). The cosigner kept serving — its
  gRPC health check does not touch the key store — and answered every Sign with
  `INTERNAL: io: Permission denied`.
- *Why it became an outage rather than a degradation:* cosigner-0 is first in the driver's
  `frost.endpoints`, so it led every signing session; the driver fails over only on
  `UNAVAILABLE`/`DEADLINE_EXCEEDED` (deliberately — a real application error must not be
  masked), so a sick-but-answering leader at position 0 blocked all signing although 2-of-3
  healthy nodes were available.
- *Detection:* `rutli_sign_requests_total{result="error"}` + `RutliSignAborts` firing; the
  participant audit log (`outcome=failed … INTERNAL`); cosigner-0's own
  `anti-entropy sweep failed error=io: Permission denied`.
- *Fix:* deleted the backup jobs; restarted cosigner-0 (the StatefulSet's `fsGroup` re-applied
  ownership on mount); verified `data_dir/keys` readable and signing green.
- *Follow-ups filed:* (a) driver: fail over sign/read operations on a leader's `INTERNAL`/
  `UNKNOWN`, loudly, never for ceremonies; (b) cosigner: readiness must reflect key-store
  readability so Kubernetes pulls a broken node out of rotation; (c) backups via
  `kubectl exec` into the running cosigner, never a second mount of its volume.
- *Soak impact:* day 0 is not a clean day — exit criterion "zero KMS-attributable sign errors"
  restarts its count from the fix. The incident is operator-inflicted, not a KMS defect, but
  (a) and (b) are genuine resilience gaps it exposed.

**Day-0 `soak-check`:** cosigners 3/3, signatures flowing (140 in the window), ceremony
failures 0, pending sessions 0, peer skips 0; FAIL on sign errors (54, incident #1) and the
`RutliSignAborts` alert — both expected to clear from the 24 h window on day 1.

**Planned event — rollout to 0.3.1, 21:14:56 → 21:16:10 (participant down 75 s).**
Release [v0.3.1](https://github.com/Stakecraft/rutli/releases/tag/v0.3.1) carries the fixes for
incident #1 (driver failover on a sick leader, cosigner key-store readiness + `health`
subcommand, hung-volume hardening). Cosigners first: `helm upgrade` to the 0.3.1 digest, rolling
one pod at a time, readiness now `rutli-cosigner health` (answered `ready`, exit 0, on every
node); signing continued on 2-of-3 throughout. Then the participant: scaled to 0, driver jar
0.3.1 swapped on the bundle volume through a temporary pod (only ever while the participant is
down — never a second mount beside a running consumer, incident #1's lesson), scaled back;
`Loaded driver rutli (API v1) build 0.3.1`, mTLS channels and capabilities re-established within
a second of start. Old jars kept on the volume as `rutli-driver-0.2.1.jar` /
`rutli-driver-0.3.0.jar`. Monitoring re-applied earlier the same evening (15 rules incl.
`RutliKeystoreUnreadable`, readiness panel on the dashboard). This is the first planned restart
of the soak; the week-3 "participant restart" drill will repeat it under observation.

**Planned event — cosigners to 0.3.2, 2026-10-09 09:01:52 → 09:04:51 UTC (no participant restart).**
Release [v0.3.2](https://github.com/Stakecraft/rutli/releases/tag/v0.3.2) fixes hosted-key pull
replication and read-repair over gRPC (every cosigner had computed its identifier as 0) and moves the
sign latency to a histogram. Cosigners only: `helm upgrade` to chart 0.3.2 (revision 4) with the
saved values; a server-side dry-run diff showed only the image and the chart labels changing. Rolling,
one pod at a time; `health` answered `ready` on all three afterwards, and each node logged its own
identifier (1, 2, 3) at start. The driver stayed on 0.3.1 (the only driver change in 0.3.2 is the
optional `frost.key-prefix`). During the roll, one sign hit the restarting cosigner-0 and failed over
to cosigner-1 (`reason=UNAVAILABLE`, `outcome=ok`); 8/8 signs ok in the window, no participant errors.
Rollback path kept: `helm -n rutli rollback rutli 3`.

**Planned event: B0 cutover drill, 2026-10-09 11:59 → 13:09 UTC (party unhosted 7 s, wallet down ~25 min).**
The soak validator moved to a **new participant UID in the same FROST namespace**: the migration shape for
existing nodes ([b0-cutover-spike.md](b0-cutover-spike.md), [roadmap-migration.md](roadmap-migration.md) B0).
- Pre-flight: Splice 0.9.0 chart/images verified; identities dump held KMS ids only (`hasKeyPair: false` ×3).
  Baselines: wallet 120.3228663581 CC, ACS 5, purchased traffic 1.2 M. Manual `pg_dumpall` 10:59 (1.4 G,
  sha `362f18c6…`, S3 OK, 0 private-key rows) + cosigner backup.
- 12:13 old participant disconnected, reference ACS exported (`END_OLD` 921659), scaled to 0; old DB untouched.
- 12:26 new participant on `participant_b0` (needed `enableParticipantDbConflictCheck=false`). The three cluster
  keys were registered by KMS id, fingerprints identical (G1); `init_id` as `stakecraft-rutli-soak-1-b0`
  under namespace `12203286…22ea`; OTK signed by `frost-namespace` + `frost-signing` (12:35, G2).
- 12:37 trust certificate signed by `frost-namespace`; member onboarded; it processed ~850 k bootstrap topology
  events and caught up at 12:47 (G3).
- 13:03:14 **PNR** (`Preparing to remove domain trust certificate…`); 13:04:51 old party mapping removed;
  13:04:54 old trust certificate removed; 13:04:58 party hosted on `-b0`; 13:05:04 ACS imported from Scan;
  13:07:33 validator initialised, `ValidatorLicense found => already onboarded` (no onboarding secret used).
- G6: balance unchanged (120.3228663581 CC); the validator's top-up automation immediately ran a Tap
  (+581.36 CC) and an Extra Traffic Purchase (−581.36 CC) through the new participant, so signing and
  confirmation work end to end. A manual wallet Tap at 13:14:48 UTC (+8.0744789943 CC, 1 USD) also
  succeeded, so user-initiated submissions work too. No restarts, no ERROR in either app.
- Cost: the old member's 1.2 M purchased traffic is stranded; old member `PAR::stakecraft-rutli-soak-1` is
  offboarded for good. Old DB `participant` and `cantonnet_validator` kept for forensics.
- Gaps: participant stdout runs at DEBUG and rotated within minutes, so the per-sign driver audit for the
  window survives only in the driver's file audit log; one SV sequencer (C7) flapped throughout (not ours).

**Planned event: B4 cutover rehearsal, 2026-10-14 16:14 → 17:11 UTC (B4 wallet down ~52 min). Soak participant unaffected.**
Runbook: [b4-rehearsal.md](b4-rehearsal.md); pilot runbook: [migration.md](migration.md). Verification G1–G7 is green; the
verdict is **GO pending** (destruction and teardown below are still open).
- Source: scratch JCE validator `stakecraft-rutli-b4-1::122017bc…c859` (`NS_FP` = the part after `::`), one hosted party,
  `ACS_COUNT_PRE=5`. Pre-cutover `pg_dumpall` at 16:09 (820 MB, local only, see Gaps).
- Export: ExportKeyPair with password (Phase 2 of the plan).
- Split ceremony `b4-2026-10-13`: KEY_ID `b4-frost-import-17bc38d7`; dealer on the operator laptop (macOS, `--allow-swap`; DevNet relaxation, not air-gapped); Gate 0 SAS ×3; Gate B (3 quorums) ✓; refresh → Gate C ✓
  (pkp digest `4253c1a7…` → `c726bdad…`, group key unchanged).
- Cutover: validator stopped 16:14:52 (`T_START`), old participant disconnected and stopped, `T_STOP` 16:22:53 (`END_OLD` 988392).
  New participant `participant_b4`, driver 0.4.0-rc.1 loaded 16:25:03. G1 `b4-frost-import-17bc38d7` → `NS_FP` ✓.
  Fresh keys `b4-frost-signing` (FROST DKG) + `b4-rutli-enc-encryption-be578c92-…` (EC-P256, ECIES). `init_id`
  `PAR::stakecraft-rutli-b4-1-mig::122017bc…c859` 16:29:42; trust certificate 16:30:45, connected and healthy by 16:43 (G3).
  G2b: ECIES ping to the soak participant took 14 s, `decryptAsymmetric` ok, ecies failures 0.
- PNR 17:05:01 (an earlier attempt before the PNR failed on Helm 4 server-side-apply conflicts with `kubectl patch` probes;
  fixed with `--force-conflicts`). Old trust certificate removed 17:07:01, party hosted on `-mig` 17:07:04, ACS import
  complete 17:07:13, primary party set 17:07:14. Validator normalised (helm rev 5, already onboarded, no re-migration), dump
  Secret deleted, dump JSON shredded, `pg_dumpall` CronJob resumed.
- G4: the party is hosted only on `-mig` (Submission, serial 3), old trust certificate gone, 3 keys, all KMS. G5: ACS 5 → 6
  (+1 `ValidatorRewardCoupon`, the rest identical), 38 commitments persisted over 60 min, **0 mismatches**.
  G6: balance after migration 234.8027 CC; wallet-UI Tap of 10 USD = +85.667 CC, transfer out of 5 CC to the soak validator
  and in of 2 CC both accepted. G7: `decryptAsymmetric` ok during a real transfer, ecies failures 0, B4 driver audit non-ok 0
  (signing ok 92 at the first check); soak participant 0 rutli WARN/ERROR over 3 h.
- Old member's OTK removed (serial 2 Remove, signed by the namespace key via FROST); it needed
  `force = ForceFlags(ForceFlag.AlienMember)`.
- Destruction (5.4): **pending**, not before 2026-10-15 17:11Z, after GO and two green `soak-check` runs.
- **GO 2026-10-15 18:04Z** after a 24 h window: G4–G7 green, soak-check 2026-10-15 08:00Z PASS and a manual run 17:19Z
  PASS (p99 0.14 s, 0 errors). (The 2026-10-14 08:00Z run, before the cutover, had failed on p99 latency 1.75 s with
  0 errors; not caused by B4.)
- **Destruction 2026-10-15** (operator ran every irreversible step): `DROP DATABASE participant_1` (3 plaintext key
  rows) and `cantonnet_validator`; WAL checkpoint + switch; 4 `pg_dumpall` files + 1 checksum removed from the backup
  PVC, the next dump verified free of `participant_1` (0 rows in `common_crypto_private_keys`); S3: no objects (the
  uploads never succeeded); the password-protected export file was the only copy (sha256 scan) and was removed.
  Residue: not provable erasure on SSD/Hetzner volumes; dealer ran on the operator laptop (`--allow-swap`, encrypted swap).
- **Teardown 2026-10-16:** the `-mig` member offboarded at 10:08Z (trust certificate removed, signed by the carried
  namespace key through FROST — its 10th and last signature); `destroy.sh --teardown-all` at 13:16Z removed the
  namespace, its volumes, the three Auth0 apps and the wallet user. The `b4-` keys stay on the cosigners (no delete path).
- Gaps: the 4-hourly `pg_dumpall` CronJob in the B4 namespace fails its S3 upload (`InvalidAccessKeyId`: the namespace's
  `aws-credentials` Secret holds a key that no longer exists). Operator decision: local dump only for the scratch namespace;
  the dumps hold the old JCE key rows and are on the destruction list. The wallet API with the validator M2M token returns
  `No wallet found`, so G6 used the wallet UI; the M2M app also lacks a client grant for the Validator API audience.
- Deltas to the pilot runbook: [migration.md](migration.md), "Lessons from the B4 rehearsal (2026-10-14)".

**Planned event: soak to 0.4.0-rc.2 (audit remediation batches A+B), 2026-10-16 14:54 → 15:12 UTC.** Runbook
[runbook-rc2-soak-rollout.md](runbook-rc2-soak-rollout.md), legacy topology.
- Pre-checks: node certificates carry `CN=cosigner<i>` / `DNS:cosigner<i>`; the rc.2 render against the live values plus
  `deploy/soak/cosigner-values.yaml` differs from the live manifest only in the image and the version labels; the
  running configs pass rc.2 validation; `StateCheck` on a copy of the participant's state: audit 18 838 entries, chain
  intact; journal 18 812 entries.
- Cosigners: `helm upgrade` → rev 8, image `0.4.0-rc.2@sha256:dfb5c859…b2c4`, rolled one pod at a time (14:55–14:57Z).
  Each node logs per-peer TLS names (M3) and the expected legacy-shared-master warning. One sign failover on the
  participant (`UNAVAILABLE` → next cosigner), 0 errors. Rollback kept: `helm -n rutli rollback rutli 7`.
- Driver: soak participant moved from **0.3.1** straight to 0.4.0-rc.2 (jar sha `04d3a19b…`, 0.3.1 kept as
  `rutli-driver.jar.0.3.1-backup` in the bundle PVC); config unchanged (shared `domain`, per-endpoint names come with
  the per-node migration). After the restart: `pinned group key for frost-signing`, 27 signs ok, `sig-verify=failed` 0;
  `StateCheck` again OK (19 015 / 18 989 entries); manual soak-check 15:12Z PASS (p99 0.13 s, 0 errors).
- **Audit C3 closed on the soak:** the exec-based backup CronJob, its Role, RoleBinding and ServiceAccount deleted. No
  automatic share backup until the per-node migration adds the sidecar; manual sealed-file copies after key changes.
- Still open from the audit: C1 (DKG/refresh round 2 via the leader) and C2 (no cosigner-side signing policy) — batch C.
  The soak's DKG-born keys are treated as leader-exposed; **no refresh** until batch C.

**Planned event: soak to 0.4.0-rc.3 (audit batch C), phases 1–3, 2026-10-18 09:10 → 13:57 UTC.** Runbook
[runbook-rc3-soak-rollout.md](runbook-rc3-soak-rollout.md), legacy topology. Batch C settings live in
[`deploy/soak/cosigner-values-batch-c.yaml`](../deploy/soak/cosigner-values-batch-c.yaml).
- Pre-flight (07:45Z): cosigners rev 8 (rc.2), participant rev 7 (not 5: two upgrades on 2026-10-16); all 6 key files
  per node `v1`/sealed (3 are the offboarded `b4-` keys); driver config without approvals, prefix or cluster id;
  `StateCheck` with the rc.3 jar OK (23 434 / 23 408 entries); soak-check PASS; clocks within 3 s; no CronJob in
  `rutli`; manual sealed-key tars of all three nodes taken off-cluster.
- Sign rates from the audit log (2026-10-07..18): `frost-signing` busiest minute 42, busiest full day 2 801;
  `frost-namespace` 3 / 7. Rules: namespace 10/min, 200/day; signing 600/min, 100 000/day.
- Phase 1 (09:10Z): `helm upgrade` → rev 9, image `0.4.0-rc.3@sha256:f4d92758…31e8`, rolled 2 → 1 → 0. Every node:
  cluster id `453bb4aea2088bb5` (derived from `ca.crt`), `key-file format write_version=1 accept_v1=true`,
  `ceremonies_staged` 0, no stale share, journal errors 0, `verify-key` ok for both FROST keys (epoch 0, one
  `pkp_digest`). Two `epoch check skipped` on node 3 during the roll (rc.2 leader), as expected. Monitoring
  re-applied with the batch C rules and dashboard rows (09:47Z); `rate_limited` 0.
- Phase 2 (T2 = 09:49:59Z): driver jar `8cc421fb…e421` swapped in by atomic rename (rc.2 jar kept as
  `rutli-driver.jar.rc2`), `frost.cluster-id = "453bb4aea2088bb5"` added, participant rev 8 (start ≈ 20 s). Logs:
  `Loaded driver rutli (API v1) build 0.4.0-rc.3`, `signing intents are signed by O=rutli,CN=driver`; signs carry
  `msg=` and `intent=`; cosigners journal `purpose:"sign"`, `signer_cn:"driver"`; 15 min later intent-absent 0,
  policy refusals 0, sign errors 0, `sig-verify=failed` 0; `StateCheck` OK (23 681 / 23 655).
- Phase 3 (10:15Z → 13:57Z): `signer_acl { driver: [frost-, rutli-] }` and `signer_pins { driver: [1c20597e…76fe] }`
  (the participant's and the workstation's driver certificate share the key) → rev 10 (ConfigMap only); canary
  restarts node 2 (watched 15 min: refusals 0, retries 0, errors 0) → node 3 → node 1. All nodes
  `acl_entries=1 pinned_cns=1`; `verify-key` from the workstation still ok (pinned).
- Alerts: `RutliSignIntentAbsent` (≈10:48–10:50Z) and `RutliSignerAclAbsent` (10:47Z → ≈14:57Z, the node 1/3 restarts
  were delayed) fired as the runbook predicts (1 h window, `for: 1h`). `RutliHostedKeyReplicaShortfall` went pending
  after the node 1 restart: `rutli_hosted_keys` reads 0 until the node's first anti-entropy pass (≈ 5 min), then 2.
- Rollback points: cosigners `helm -n rutli rollback rutli 9` (phase 3) / `8` (phase 1); participant rev 7 + the
  `.rc2` jar. Next: phase 4 (`require_intent`, `signer_acl_required`, `signer_may_refresh: false`) on a later day after
  a clean soak-check, then phase 5 (`audit-cross-check`).

**Planned event: rc.3 phase 4 — enforcement on every node, 2026-10-20 20:48 → 22:40 UTC.** Runbook
[runbook-rc3-soak-rollout.md](runbook-rc3-soak-rollout.md) §4, after clean soak-checks on 2026-10-19 and 2026-10-20.
- Pre-checks (24 h): `intent_absent`, `signer_acl_absent`, `rate_limited` 0 on every node, no policy refusals, no
  staged ceremony, clocks within 3 s; since T2 the journals hold only `"purpose":"sign"` (node 1: 5 588, node 2: 5 589;
  node 3 has 2 `no-intent` entries from the phase 1 roll, before T2 — it is outside the leader's first pair).
- `require_intent`, `signer_acl_required`, `require_epoch_match` on and `signer_may_refresh` off → rev 11 (ConfigMap
  only; the render from main carries no field rc.3 does not know). Canary: node 2 (20:49Z, watched 15 min: refusals 0,
  errors 0, retries 0, 32 signs through the leader, node 2 journaling `sign`/`driver`) → node 3 → node 1 (≈22:36Z).
  All three log `require_intent=true signer_acl_required=true signer_may_refresh=false` and none of the "is off" notices.
- Positive: participant signs after the restarts `outcome=ok` with intents; nodes 1 and 2 journal `sign`/`driver`;
  `epoch_check_skipped` 0, sign errors 0; `verify-key` ok for both FROST keys from the pinned workstation certificate.
- Negative (22:38Z): an intent-less `Sign` for `frost-rc3-negative-test` sent to each node as leader with the driver
  certificate is refused by all three with `PermissionDenied … carries no signing intent and this node requires one`
  (`rutli_sign_policy_refusals_total{reason="missing"}` = 1 on each node). **Correction (2026-10-22):** the alert
  `RutliSignPolicyRefusals` did NOT fire — Prometheus has no `ALERTS` series for it in 22:30–23:30Z. The counter is not
  primed at start, so the first refusal per node and reason creates the series at 1 and `increase()` reads 0: a
  monitoring gap, filed for a code fix (prime the refusal counters).
- From now on the soak's driver key signs only with a journaled intent, only under `frost-`/`rutli-`, within the rate
  limits, and nobody can refresh until the CA rotation. Rollback: `helm -n rutli rollback rutli 10` + restarts 1 → 2 → 0.
  Next: phase 5 (`audit-cross-check`).
- Phase 5, first `audit-cross-check` (22:45Z, journals copied first, then the driver audit log): driver audit 29 514
  entries, 29 488 signs, 5 859 with an intent and a message digest; journals node 1 5 938, node 2 5 941, node 3 3
  entries. The first copy showed one `signed ok but is in 1 of the supplied journals` for the newest audit entry (a
  sign in flight during the copy); a fresh copy: `--allow-no-intent` exit 0. Strict run: exit 1 with only the
  rollout-window lines — node 1 and node 2 81 no-intent signatures each (2026-10-18 09:12:50Z .. 09:49:55Z), node 3 two
  (09:11:12Z .. 09:11:20Z), all before T2 (09:49:59Z): accepted. These lines repeat until journal retention (90 days)
  drops them. Schedule: weekly manual run, results in this log.

**Planned event: soak to 0.4.0-rc.4 (ceremony intents), 2026-10-22 12:48 → 22:10 UTC.** Runbook
[runbook-rc4-soak-rollout.md](runbook-rc4-soak-rollout.md), legacy topology.
- Pre-flight: cosigners rev 11 (rc.3, batch C enforced), participant rev 8, no CronJob, soak-check PASS; the chart pins
  `0.4.0-rc.4@sha256:03485f47…55dd63`; `StateCheck` with the rc.4 jar OK (33 182 / 33 156); `verify-key` ok; sealed-key
  tars taken (6 files per node).
- **Tooling lesson:** `kubectl exec`/`kubectl cp` streams from this cluster now drop after ≈ 2–10 MB (`unexpected EOF`),
  silently truncating copies. State files were fetched in 1 MiB `tail -c | head -c` chunks and the 35 MB driver jar was
  uploaded in sha-checked 2 MiB chunks (`~/rc4-rollout/stage-jar.sh`). The runbook's sha256 checks caught nothing bad,
  but plain `tar | tar` copies would have.
- Phase 1 (16:10Z): `helm upgrade` → rev 12, image rolled 2 → 1 → 0. Every node: rc.4 digest, plain logs (0 escape
  bytes), `require_intent=true require_ceremony_intent=false …`, cluster id `453bb4ae…`, the expected
  `require_ceremony_intent is off` warning; `ceremony_intent_absent` 0, nothing staged or stale, `verify-key` ok (one
  epoch, one `pkp_digest`). 15 min: sign errors 0, refusals 0, rate-limited 0, epoch skips 0. Monitoring re-applied:
  `RutliCeremonyIntentRefused` and `RutliCeremonyIntentAbsent` added.
- Phase 2 (T4 = 21:24:17Z): rc.3 jar kept as `rutli-driver.jar.rc3`, rc.4 jar `ea20dcba…f8c3` renamed into place,
  `kubectl rollout restart` (Recreate; participant up in ≈ 20 s; Helm stays rev 8). `Loaded driver rutli (API v1) build
  0.4.0-rc.4`, intents signed by `CN=driver`; signs `outcome=ok` with intents, no `intent=none`, no `sig-verify=failed`;
  15 min: refusals 0, errors 0; `StateCheck` OK (34 029 / 34 002). The first staging helper pod (`sleep 3600`) had
  exited before the swap; it was recreated and the staged jar re-verified (`sha256sum -c`) before the rename.
- Phase 3 (21:44Z → 22:01Z): `require_ceremony_intent: true` → rev 13 (ConfigMap only); canary node 2 (5 min: errors 0)
  → node 3 → node 1, all `require_ceremony_intent=true` with no "is off" warning. Positive: signs ok with intents,
  `verify-key` ok. Negative (22:02Z): an intent-less `Signer/Dkg` for `frost-import-rc4-negative-test` sent to each node
  as leader is refused `PermissionDenied … carries no ceremony intent and this node requires one`;
  `rutli_ceremony_intent_refusals_total{reason="missing"}` = 1 per node, `ceremonies_staged` 0 — nothing created. (The
  refusal counter is unprimed in rc.4, so `RutliCeremonyIntentRefused` may not have fired; primed from #56 on.)
- Phase 4 (22:08Z): `audit-cross-check` strict — driver audit 34 075 entries, 34 049 signs (10 420 with intent and
  digest); only the 2026-10-18 rollout-window no-intent lines (81/81/2, all before T2) plus one in-flight sign (the
  newest audit entry, seen in 1 journal at copy time, in 2 journals a minute later): accepted.
- Now: DKG and refresh need a client-signed ceremony intent on every node; refresh stays impossible until the CA
  rotation. Rollback: `helm -n rutli rollback rutli 12` + restarts 1 → 2 → 0 (flag off), then 11 (image) / the
  `.rc3` jar.

## Drill calendar

| Week | Drill | Status |
|---|---|---|
| 1 | Kill one cosigner 30 min, restart | pending |
| 1 | Proactive refresh mid-traffic | pending |
| 2 | Full cluster restart, one node at a time | pending |
| 2 | Restore drill: wipe one cosigner's keys, restore from backup | pending (needs exec-based backups first) |
| 3+ | Participant restart + host reboot | pending |

## Exit criteria tracking

See [testnet-soak.md](testnet-soak.md#exit-criteria-all-required). Clean-day counter starts
2026-10-08.

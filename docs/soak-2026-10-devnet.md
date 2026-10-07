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
| Monitoring | cluster kube-prometheus-stack via `deploy/monitoring` (3/3 targets, 14 rules), daily `rutli-soak-check` CronJob in `monitoring`, Grafana dashboard "Rütli FROST Cosigner" |
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

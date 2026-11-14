# Rütli on Splice 0.10 / Canton 3.7

**Status:** 2026-11-14. Read against the Splice 0.10.0 and 0.10.1 release notes, the Canton 3.7.0 release notes, the Canton
source (tags v3.6.1 to v3.7.3) and the Splice 0.10.1 charts and source. **Not yet run live:** the driver on a Splice 0.10.1
participant. The DevNet canary is next; this page is updated after it.

Splice 0.10.0 ships Canton 3.7.1 and 0.10.1 ships Canton 3.7.2. Canton 3.7 adds protocol version 37, which a network adopts
through a Logical Synchronizer Upgrade (LSU). A validator must run 0.10.x before its network's LSU.

## Summary

| Area | Change for Rütli |
|---|---|
| Driver code | None. The driver SPI is unchanged |
| Upgrading a Rütli validator 0.9.x → 0.10.x | No values change. Back up first; participant before validator; never `--atomic` |
| Key export during a migration | Needs `enable-key-download` on the old participant (new in 3.7) |
| Party migration (Flow 2b), disaster recovery, console repair commands | Need `enable-repair-commands` on the participant (new in 3.7) |
| Key rotation | Pass `synchronizerId` while two synchronizers are registered; keep an owner under 20 signing keys |
| Health probes | Now HTTP. A cosigner outage cannot fail liveness |

## Driver: no change

- `kms-driver-api` and `kms-driver-testing` are byte-identical from v3.6.1 to v3.7.3 (`git diff` is empty). The driver jar
  built against v3.6.1 loads on 3.7.x, and the conformance suite has no new checks. Driver loading (`DriverLoader`) and the
  `crypto.kms` driver config are unchanged.
- Canton's jar comes first on the classpath, so the driver runs on Canton's libraries:

  | Library | Canton 3.6.1 | Canton 3.7.2 | Rütli builds and tests with |
  |---|---|---|---|
  | BouncyCastle | 1.85 | 1.86 | 1.85 |
  | grpc-java | 1.81.0 | 1.85.0 | 1.82.1 |
  | protobuf-java | 4.35.1 | 4.35.1 | stubs generated with 4.29.3 (older gencode on a newer runtime of the same major is allowed) |
  | Scala | 2.13.18 | 2.13.18 | 2.13.18 |

  Canton's own ECIES code is unchanged between the tags. The ECIES path completes in BouncyCastle's `IESEngine`, so it now
  runs on 1.86.
- Session signing keys stay off by default in 3.7 and in the Splice 0.10 charts.

## Upgrading a Rütli validator from 0.9.x to 0.10.x

Rendering the `splice-participant` and `splice-validator` 0.10.1 charts with a Rütli validator's 0.9.0 values changes only
the images, the probes (gRPC on 5061 → HTTP on 5071, plus the env var that starts Canton's HTTP health server) and the
`pg-init` image (`postgres:14` → `postgres:18.6-trixie`; `psql` 18 works against an older server). No value was removed or
renamed. `additionalEnvVars`, `extraVolumes` and `extraVolumeMounts` (driver jar, TLS material, state volume) still pass
through, and the `kms` block is unchanged. Render both versions and diff them yourself before you upgrade.

1. **Back up the participant and validator databases.** On first start, Canton 3.7 migrates the participant schema, and
   3.6 will not start on it afterwards. From then on, rollback means a database restore.
2. **Before the network's topology freeze, not just before its LSU.** On start, the validator vets the 0.10 DARs. That is a
   topology transaction signed by the namespace key, through the cluster, and it cannot land during the freeze.
3. **Participant first.** Wait until it is Ready: readiness now waits for the database migrations. Liveness stays up while
   they run. Check `Loaded driver rutli … build <version>` in the log and fresh `"op":"sign"` lines with `outcome=ok` in the
   driver audit log. Reconnecting to the sequencers signs with the protocol key. Then upgrade the validator.
4. **No `helm upgrade --atomic`, and no `--wait` with a rollback attached.** A timeout during the schema migration would
   roll back to a 3.6 image on a 3.7 schema.
5. Rehearsal records in this repo pin `--version 0.9.0` ([b0-cutover-spike.md](b0-cutover-spike.md),
   [b4-rehearsal.md](b4-rehearsal.md), [runbook-rc3-soak-rollout.md](runbook-rc3-soak-rollout.md),
   [runbook-migration-inplace.md](runbook-migration-inplace.md)). Never re-run them as written against a participant that
   has run 0.10.x. Use the chart version `helm list` shows.

The LSU itself needs nothing from Rütli. The participant moves to the successor synchronizer by itself, and the driver sees
only the usual sequencer-authentication signatures. No topology transaction is re-signed: PV 37 stores still accept v30
topology transactions. Watch the driver audit log and the participant log across the LSU anyway.

## Key export during a migration (Flow 2a and 2b)

In Canton 3.7, `VaultService.ExportKeyPair` (console `keys.secret.download` / `download_to`) is served only if
`canton.parameters.enable-key-download = yes` (default off). Before 3.7, the server-side gate was
`canton.features.enable-preview-commands`. The console commands still need preview commands in the **console's** config.

- On a Splice 0.10 participant chart: `enableKeyDownload: true` for the export window only, then remove it. Without it,
  the export fails with `FAILED_PRECONDITION` ("Remote export of private keys only allowed when explicitly enabled").
- Applies to [migration.md](migration.md) Step 2, [runbook-migration-inplace.md](runbook-migration-inplace.md) Phase 2,
  [b4-rehearsal.md](b4-rehearsal.md) 2.1 and the ECIES import in [hosted-keys.md](hosted-keys.md).
- A Rütli participant cannot export its keys whatever the flag: its key store is a KMS store, and the export fails with
  "does not support exporting of private keys". A Rütli participant's identities dump still holds key ids only, and a
  start from such a dump still registers them by id. D8 in [b4-rehearsal.md](b4-rehearsal.md) is unchanged.

## Repair service: party migration, disaster recovery, console repair commands

In Canton 3.7, the participant serves the repair admin API only if `canton.features.enable-repair-commands = yes` (default
off). Splice's party migrator (`migrateValidatorParty`, used by [migration.md](migration.md) Step 6 and by Splice's
disaster recovery) imports the party's ACS through that API, **after the point of no return**. A remote console's
`repair.*` commands (the reference ACS exports in the migration runbooks) call the same API.

- On a Splice 0.10 participant chart: `enableRepairCommands: true` before the step that needs it. Check it before the
  point of no return (`helm get values participant`), and remove it once the migration is normalised.
- The canton-participant images 0.10.0 to 0.10.2 still enable it in `/app/additional-config.conf`, marked as a TODO to
  remove. Do not rely on that.

## Key rotation

- `keys.secret.rotate_node_key(s)`, `rotate_kms_node_key` and `topology.owner_to_key_mappings.add_key(s)` / `remove_key` /
  `rotate_key` take an optional `synchronizerId`. Auto-detection only works with exactly one registered and connected
  synchronizer, so it fails in an LSU window, where the predecessor and the successor are both registered. Pass the id, or
  do not rotate during the window.
- PV 37 limits an owner to 20 signing keys (`max_signing_keys_per_entity`, in `OwnerToKeyMapping` and the party key
  mappings). Rotation removes the old key from the mapping, so the count stays flat. An `add_key` without a matching
  `remove_key` makes it grow. See [key-rotation.md](key-rotation.md).

## Health probes

The Splice 0.10 participant chart probes `GET /health/live` and `/health/ready` on port 5071 (`httpHealthProbes: false`
restores the gRPC probes).

- **Liveness has no dependencies** (`LivenessHealthService.alwaysAlive`). A cosigner outage, or a driver reporting `Fatal`,
  does not fail liveness, so Kubernetes does not restart-loop the participant.
- **Readiness** depends on storage and crypto. The crypto health is the KMS health, and it turns NOT_SERVING only on a
  `Failed` dependency. `Degraded` still serves.
- The driver reports `Ok` when **any** cosigner answers, even below the signing threshold, and `Degraded` when none
  answers (`FrostBackend.health`). A pod therefore stays Ready through a cluster outage. That is intended, since a restart
  would not help, but it means readiness does not tell you about quorum: alert on the cosigner metrics instead
  ([observability.md](observability.md)). Quorum-aware health is a possible follow-up.

## Optional: `splice-topology-key-monitor`

A new Splice chart. It polls the synchronizer's topology transactions over a participant's admin API and logs a WARN for
each one signed by a fingerprint it tracks. Track the namespace fingerprint and compare its hits with the driver audit log
and the cosigner journals. A hit with no matching Rütli signature means another copy of the key signed: for example, a
copy the migration's destruction step missed. It has no TLS or auth settings, so it needs a plaintext route to the admin
API.

## Postgres

PostgreSQL 14 reached end of life on 2026-11-12. Splice 0.10 defaults its Compose bundles to PostgreSQL 18, with a new data
volume mount. Splice does not support KMS on Compose. The `splice-postgres` chart is deprecated, so plan a move to a
managed Postgres (CloudNativePG, for example).

# Compatibility

Which Canton and Splice versions each Rütli release was built against and run with. Every cell is taken from this
repository: the build pins at the release tag, the CI workflows at the tag, `CHANGELOG.md` and the
[soak log](soak-2026-10-devnet.md). A cell without such a record says **not tested**. The row for a new release is part
of its release pull request ([releasing.md](releasing.md)).

Three things are kept apart:

- **Built against**: the Canton tag whose `kms-driver-api` the driver jar is compiled with (`CANTON_TAG` in
  `.github/workflows/ci.yml`; `build.sbt` explains the `-SNAPSHOT` coordinates).
- **Tested**: in CI, or on the two DevNet validators that run Rütli (the soak log). The upstream conformance suite
  (`KmsDriverTest`) runs weekly on `main` against the pinned Canton tag, not on each release tag. The end-to-end
  workflow runs on every release candidate tag, from `0.5.0-rc.1` on.
- **Expected to work, not tested**: there is a stated reason, but no run of that release on that version.

## Releases

| Rütli | Built against | Tested in CI | Tested on DevNet validators | Expected to work, not tested |
|---|---|---|---|---|
| `0.5.0-rc.1` (2026-11-25) | Canton v3.6.1 | Conformance suite on Canton 3.6.1. End to end on the tag: carried keys, hosted ECIES keys and the migration on Canton 3.6.1; the migration again on Canton 3.7.2 | **not tested** (no soak record yet) | Splice 0.10.x / Canton 3.7.0–3.7.3 with protocol version 37; Canton 3.5.x |
| `0.4.1` (2026-11-20) | Canton v3.6.1 | Conformance suite on Canton 3.6.1 | Cosigners: Splice 0.10.1 / Canton 3.7.2, protocol version 37, since 2026-11-20. Driver jar: **not tested** ¹ | Splice 0.9.0 / Canton 3.6.1 (0.4.0 ran there); Canton 3.7.0, 3.7.1, 3.7.3; Canton 3.5.x |
| `0.4.0` (2026-11-14) | Canton v3.6.1 | Conformance suite on Canton 3.6.1 | Cosigners, with the `0.4.0-rc.6` driver jar ¹: Splice 0.9.0 / Canton 3.6.1 on 2026-11-14 and 15; Splice 0.10.1 / Canton 3.7.2 from 2026-11-15 to 2026-11-20, across DevNet's upgrade to protocol version 37 on 2026-11-18 | Canton 3.7.0, 3.7.1, 3.7.3; Canton 3.5.x |
| `0.3.2` (2026-10-09) | Canton v3.6.1 | Conformance suite on Canton 3.6.1 | Cosigners: Splice 0.9.0 / Canton 3.6.1 from 2026-10-09 to 2026-10-16. Driver jar: **not tested** (the validator kept the 0.3.1 jar) | Canton 3.5.x. Splice 0.10.x / Canton 3.7.x: **not tested**, no statement |
| `0.3.1` (2026-10-07) | Canton v3.6.1 | Conformance suite on Canton 3.6.1 | Splice 0.9.0 / Canton 3.6.1: cosigners from 2026-10-07 to 2026-10-09, driver jar from 2026-10-07 to 2026-10-16 | Canton 3.5.x. Splice 0.10.x / Canton 3.7.x: **not tested**, no statement |
| `0.3.0` (2026-10-06) | Canton v3.5.6 | Conformance suite on Canton 3.5.6 | Splice 0.9.0 / Canton 3.6.1 on 2026-10-07, for 15 hours (replaced by 0.3.1 the same day) | Splice 0.10.x / Canton 3.7.x: **not tested**, no statement |

¹ The validators' driver jar has been `0.4.0-rc.6` since 2026-11-12. `0.4.0` is that candidate's code with the version
changed, and the `0.4.1` driver differs from `0.4.0` only in its version number (`CHANGELOG.md`). The jars published as
`0.4.0` and `0.4.1` were not loaded on a validator.

Also recorded:

- `0.3.0`: hosted keys were checked end to end by hand on a Canton 3.5.6 participant (`CHANGELOG.md`, 0.3.0).
- `0.4.0` and `0.4.1` had no end-to-end workflow in CI. The end-to-end scripts for Canton 3.6.1 were written during the
  0.4.0 candidates (`CHANGELOG.md`), but the repository has no record of a run on the `0.4.0` or `0.4.1` tag.
- Release candidates of 0.4.0 ran on the DevNet validators on Splice 0.9.0 / Canton 3.6.1 from 2026-10-16 to
  2026-11-14 (`rc.2`, `rc.3`, `rc.4`, `rc.6`; the soak log has each rollout).

## Why "expected to work"

- **Canton 3.7.x.** `kms-driver-api` and `kms-driver-testing` are byte-identical from Canton v3.6.1 to v3.7.3, so a jar
  built against v3.6.1 loads on 3.7.x and the conformance suite has no new checks ([splice-0.10.md](splice-0.10.md)).
  Of these, only 3.7.2 has been run.
- **Canton 3.5.x.** `kms-driver-api` is byte-identical between v3.5.6 and v3.6.1 (`build.sbt`). Since 0.3.1 the driver
  is compiled with Scala 2.13.18 and no release after 0.3.0 was run on 3.5.x.
- **Canton 3.4 and earlier: not supported.** Driver-based KMS arrived in Canton 3.5.
- **Splice.** Rütli plugs into the participant and has no Splice dependency of its own; what matters is the Canton
  version a Splice release ships. Splice 0.9.0 ships Canton 3.6.1, 0.10.0 ships 3.7.1, 0.10.1 ships 3.7.2.
  Splice 0.10.0 itself was not run. Operator changes for 0.10: [splice-0.10.md](splice-0.10.md).

## Other versions

| Item | Version | Source |
|---|---|---|
| Canton KMS driver SPI | `v1` (`com.digitalasset.canton.crypto.kms.driver.api.v1`); the participant logs `Loaded driver rutli (API v1)` | `driver/`, soak log |
| JVM for the driver | Java 17 (bytecode pinned to 17) | `build.sbt` |
| Scala | 2.13.18 since 0.3.1 (2.13.16 in 0.3.0) | `build.sbt` |
| Kubernetes, minimum | 1.29 since 0.4.0 (the chart requests `ReadWriteOncePod` volumes); 1.25 for 0.3.x | `deploy/helm/rutli-cosigner/README.md` at each tag |
| Helm, minimum | 3.8 | the same file |
| Helm, used | 3.16.4 checks the chart in CI; the Splice 0.10.1 upgrade of 2026-11-15 was done with Helm 4 | `scripts/perf/install-tools.sh`, soak log |
| Kubernetes, tested | **not recorded**: the repository does not state the Kubernetes version of the DevNet validators' cluster | |
| Canton protocol version | 37 on DevNet since 2026-11-18. The protocol version before that date is **not recorded** here | soak log |

Version rules between the driver and the cosigners, and the upgrade order from 0.4.x to 0.5.0, are in the
[README](../README.md#compatibility) and in [upgrading-to-0.5.md](upgrading-to-0.5.md).

## Keeping this page current

In the release pull request, add the row for the new release:

1. **Built against**: `CANTON_TAG` in `.github/workflows/ci.yml` at the release commit.
2. **Tested in CI**: the Canton versions of the conformance suite and of the end-to-end workflow, and whether the
   end-to-end run on the candidate tag was green.
3. **Tested on DevNet validators**: only what the soak log records for this release or its candidates, with dates and
   the Splice and Canton versions. If the driver jar and the cosigners ran different versions, say so.
4. **Expected to work, not tested**: the reason, or "not tested".

Then update the short table in the README (the latest three releases). When a stand moves to a new Splice or Canton
version between releases, add that to the row of the release it runs, in the same pull request as the soak log entry.

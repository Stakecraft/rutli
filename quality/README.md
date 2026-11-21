# Quality metrics

CI (`.github/workflows/quality.yml`) measures every language in the repository and compares the
numbers with `quality/baseline.json`. Old debt does not block a change; new debt does not get in.

| When | What runs | On a regression |
|---|---|---|
| Pull request | The areas the change touches (`scripts/quality/changed-areas.sh`), without coverage | The PR fails |
| Push to `main` | Every area, with Rust and Scala coverage | An issue is opened (or commented on) |
| Nightly, 02:00 UTC | `cargo audit`, trivy scan of the released image | An issue is opened (or commented on) |
| Monday, 06:00 UTC | Report: last release tag against `main` | — (artifact and job summary) |
| Manual, `base` + `head` | Report for any two refs | — |

| File | What it is |
|---|---|
| `baseline.json` | The metrics that runs are compared with |
| `reports/` | Release-to-release comparisons (`scripts/quality-report.sh`) |
| `../scripts/quality/metrics.json` | Every metric: label, direction, gated or not, tolerance |
| `../scripts/quality/tools.txt` | Pinned tool versions and sha256 sums |

## Running it locally

```bash
scripts/quality/install-tools.sh ~/.cache/rutli-quality-tools
QUALITY_TOOLS_DIR=~/.cache/rutli-quality-tools scripts/quality/collect.sh --out /tmp/current.json
scripts/quality/render.sh quality/baseline.json /tmp/current.json
scripts/quality/ratchet.sh quality/baseline.json /tmp/current.json
```

`--only rust,shell,...` runs a subset. `QUALITY_COVERAGE=0` skips the coverage runs and
`QUALITY_SCALA_BUILD=0` the sbt build (it needs the Canton artifacts, see `CONTRIBUTING.md`). A
metric that could not be measured is `null`, with the reason under `notes`; one that was turned
off for the run is listed under `skipped`.

## The ratchet

- Counts (warnings, findings, unsafe uses, unformatted files, advisories) must not grow: no
  tolerance.
- Coverage may drop by up to 0.5 percentage points, the rustqual score by 0.1.
- A gated metric that has no value now (tool failed, build broken), an area that crashed, a gated
  metric missing from the baseline, or a baseline key `metrics.json` does not know: all fail.
- Areas a run did not cover, and metrics it skipped, are not compared.
- Tests, lines of code, `clippy::pedantic` and the rustqual dimensions are reported, not gated.

When a change improves a gated metric, the ratchet says so: update `baseline.json` in the same
change to lock the gain in. When a change has to make a metric worse (a new dependency with an
advisory, a deliberate breaking proto change), update `baseline.json` in that change and say why in
the PR description.

## Updating the baseline

Take the `quality-metrics` artifacts of a Quality run on `main` (a manual run without inputs does
the same) and of a nightly run, and merge their `current.json`:

```bash
scripts/quality/update-baseline.sh main-current.json nightly-current.json
```

A run with coverage also puts the driver's scoverage report into the artifact
(`scoverage.xml.gz`: every statement with its file, line and hit count), for a look at what the
tests do not reach.

A local run lacks what needs CI's toolchain (coverage, the sbt build), so do not use one. At each
release the baseline moves to the release (`docs/release-process.md`).

## Release reports

```bash
scripts/quality-report.sh v0.4.0 v0.5.0-rc.1 --json report.json >report.md
```

or the Quality workflow run by hand with `base` and `head` set, which measures every metric with
CI's toolchain. Reports go to `quality/reports/`.

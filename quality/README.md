# Quality metrics

CI (`.github/workflows/quality.yml`) measures every language in the repository and compares the
numbers with **main as main last measured itself**: the `quality-metrics` artifact of the last
successful Quality run on `main` (`scripts/quality/fetch-baseline.sh`). Old debt does not block a
change; new debt does not get in. Nobody edits a baseline file in a pull request.

| When | What runs | On a regression |
|---|---|---|
| Pull request | The areas the change touches (`scripts/quality/changed-areas.sh`), without coverage or advisories, against main's run for the PR's base commit | The PR fails |
| Push to `main` | Every area, with Rust and Scala coverage, against main's previous successful run | The run is red; "Main status" opens "main is red" |
| Nightly, 02:00 UTC | `cargo audit`, trivy scan of the released image, against the previous night | An issue is opened (or commented on), once per new advisory |
| Monday, 06:00 UTC | Report: last release tag against `main` | — (artifact and job summary) |
| Manual, `base` + `head` | Report for any two refs | — |
| Manual, `accept` | As a push to main, but a regression does not fail: the run becomes the baseline | — |

| File | What it is |
|---|---|
| `baseline.json` | The floor recorded at the last release; used only when no run on main has an artifact (first run, expired artifacts) |
| `reports/` | Release-to-release comparisons (`scripts/quality-report.sh`) |
| `../scripts/quality/metrics.json` | Every metric: label, direction, gated or not, tolerance |
| `../scripts/quality/tools.txt` | Pinned tool versions and sha256 sums |

## Running it locally

```bash
scripts/quality/install-tools.sh ~/.cache/rutli-quality-tools
QUALITY_TOOLS_DIR=~/.cache/rutli-quality-tools scripts/quality/collect.sh --out /tmp/current.json
scripts/quality/render.sh quality/baseline.json /tmp/current.json      # or a run's current.json
scripts/quality/ratchet.sh quality/baseline.json /tmp/current.json
```

`--only rust,shell,...` runs a subset. `QUALITY_COVERAGE=0` skips the coverage runs and
`QUALITY_SCALA_BUILD=0` the sbt build (it needs the Canton artifacts, see `CONTRIBUTING.md`). A
metric that could not be measured is `null`, with the reason under `notes`; one that was turned
off for the run is listed under `skipped`.

## The ratchet

- Counts (warnings, findings, unsafe uses, unformatted files, advisories) must not grow: no
  tolerance. typos findings are reported, not gated: most are identifiers and encoded data.
- Coverage may drop by up to 0.5 percentage points, the rustqual score by 0.1.
- A gated metric that has no value now (tool failed, build broken), an area that crashed, a gated
  metric this run measured that the baseline lacks, or a baseline key `metrics.json` does not know:
  all fail.
- Areas a run did not cover, and metrics it skipped, are not compared.
- Tests, lines of code, `clippy::pedantic` and the rustqual dimensions are reported, not gated.

## How the baseline moves

- **An improvement** locks itself in: after the merge, main's run measures the better number and the
  next pull request is compared with it. Nothing to edit.
- **A deliberate regression** (a new dependency with an advisory, a breaking proto change, an
  accepted drop in coverage): say why in the PR. A maintainer merges it despite the red check, then
  runs the Quality workflow by hand on `main` with `accept` ticked. That run is green and becomes
  the baseline.
- **Main went red** because something got in that the pull request run could not see (coverage is
  measured on main only): fix it, or accept it as above. Until then pull requests are compared with
  the last good run on main.
- **At a release** the floor in `quality/baseline.json` moves to the release, from the artifacts of a
  run on main and of a nightly run:

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

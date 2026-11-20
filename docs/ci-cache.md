# CI cache and runner variables

How CI uses the GitHub Actions cache, what to prune, and which repository variables decide where
jobs run. For the self-hosted runners themselves see [deploy/ci-runner/README.md](../deploy/ci-runner/README.md).

## Runner variables

| Variable | Used by | Meaning |
| --- | --- | --- |
| `CI_RUNNER` | `ci.yml`, `e2e.yml`, `proptest.yml` (and the load test when `PERF_RUNNER` is unset) | label of the self-hosted runner for this repository's own branches; empty = GitHub-hosted `ubuntu-latest` |
| `PERF_RUNNER` | `load.yml` (scheduled and manual runs) | label of the runner for **measured** runs; empty = follows `CI_RUNNER`; both empty = hosted `ubuntu-24.04` |

Fork and Dependabot pull requests always run on hosted runners, whatever these say.

**Moving CI, e2e and the nightly property tests to hosted runners** is one repository setting, in this
order, by the owner:

1. Set `PERF_RUNNER` to the runner label (the load test then stays on that hardware).
2. Check the cache (below): `scripts/cache-usage.sh` must report less than 8 GB.
3. Clear `CI_RUNNER`. Roll back by setting it again.

A measured run compares with the last green scheduled run only when both ran on the same kind of
runner (`runner.txt` in the `load-result` artifact; results from before it existed count as
self-hosted). After a change of runner kind the first run has no baseline and says so.
No other workflow measures time against a stored baseline: `scripts/bench.sh` is run by hand (no workflow
calls it); a workflow added later that does must use `PERF_RUNNER` too.

## Cache keys

| Workflow | Cache | Key (prefix) | Saved by |
| --- | --- | --- | --- |
| `ci.yml` job FROST core | `Swatinem/rust-cache`, workspace `frost` | `v0-rust-frost-Linux-x64-<toolchain>-<Cargo.lock hash>` | main only (`save-if`) |
| `e2e.yml` | `Swatinem/rust-cache` | `v0-rust-e2e-Linux-x64-…` | main only |
| `proptest.yml` | `Swatinem/rust-cache` | `v0-rust-proptest-…` | the nightly run on main |
| `ci.yml`, `e2e.yml` | `setup-java` with `cache: sbt` | `setup-java-Linux-x64-sbt-<build files hash>` | any ref (about 60 MB) |
| `ci.yml`, `e2e.yml` | `actions/cache` Canton API | `canton-api-<os>-<arch>-<tag>-v1` | any ref (1 MB) |
| `e2e.yml` | `actions/cache` Canton release | `canton-release-<os>-<version>-<sha256>` | any ref (about 300 MB) |

A pull request reads the caches of its base branch (main) and its own; two pull requests never see
each other's. Before `save-if`, every pull request that changed a dependency saved its own 440 MB
copy of the Rust cache: on 2026-11-20 the 15 pull-request entries held 6.2 GB of the 10.4 GB.

## Size check

`scripts/cache-usage.sh` (workflow "Cache usage", Mondays 07:00 UTC and on demand) prints the table
by cache family and ref kind, warns at 8 GB and fails at 9.5 GB. A red run is the signal to prune.

## Prune (owner; needs write access to Actions)

Pull-request caches are never read by anyone else once the PR is merged or closed, so they can go at
any time:

```bash
gh cache list --limit 200 --json id,ref,sizeInBytes --jq '.[] | select(.ref | startswith("refs/pull/")) | .id' \
  | xargs -n1 gh cache delete
```

Old `main` entries of the same family (an earlier `Cargo.lock` hash) are evicted by GitHub when they
have not been read for seven days; to free them sooner, delete all but the newest entry of each
family. After a prune the next run on a pull request restores main's cache and rebuilds only what
changed.

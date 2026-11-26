# Release process

How a Rütli release goes from `main` to a tag: who decides what, and when. Written for `0.5.0`, the
version the external audit reviews; later releases follow the same steps. The mechanics of tagging,
pinning the image digest and the release assets are in [releasing.md](releasing.md).

## 1. Development

Work lands on `main` through pull requests (see [CONTRIBUTING.md](../CONTRIBUTING.md)). Each PR keeps the
quality ratchet from getting worse. The release milestone lists what is planned. Tests run on the
schedule at the end of this page.

## 2. Feature freeze

- Announce the freeze date. After it, `main` takes only fixes, tests, docs and release work.
- Everything in the milestone is merged, moved to the next milestone, or marked `prio:p0` with an
  owner and a date.
- Open `prio:p0` issues block the release candidate.

## 3. Release candidate

- A maintainer tags `vX.Y.Z-rc.N` from `main`. CI builds, signs and attests the image.
- The quality report for the candidate is generated and compared with the previous release (step 6).

## 4. QA

Run in parallel, each with its own owner, against the candidate. Every problem becomes an issue
with the `release:qa` label and a priority. `prio:p0` means a new candidate.

| Track | What is checked |
|---|---|
| Rust | Coverage gaps in `frost/core` and `frost/cosigner`; `cargo mutants` on the signing, DKG and sealing paths; fuzzing of parsers and wire decoding |
| Driver | Scala tests and coverage gaps; the Canton conformance suite (`CONFORMANCE=1`) |
| Deploy | Helm and kustomize render cleanly; LocalNet `up.sh` + smoke; TLS cluster smoke; upgrade from the previous release with existing keys |
| Security | Independent review of the full diff since the previous release by at least two reviewers who did not write it; dependency and image scans |
| Docs | Follow QUICKSTART and the runbooks as written on a fresh LocalNet; every step must work without outside knowledge |

## 5. Soak

The candidate runs on the DevNet soak validators. Minimum soak time before go/no-go: 7 days with no
unexplained failed sign or DKG, no alert left uninvestigated, and a restart of each cosigner during
the window.

## 6. Quality report

`scripts/quality-report.sh` collects the metrics of the candidate and of the previous release tag:

- Rust: `rustqual` score per dimension, clippy findings, `unsafe` count, advisories, coverage,
  mutation score, tests, lines of code;
- Scala: compiler warnings, coverage, tests;
- other languages: findings per linter (shellcheck, ruff, hadolint, actionlint, buf, kubeconform);
- security: open findings by severity, image CVEs.

The report goes with the release notes, so each release shows what improved and what got worse.

## 7. Go/no-go

This decides whether the software is released. It does not put an authority key into production.
Before a key goes live, the operator's own gates in
[audit-prep.md](audit-prep.md#operator-go-live-gates-post-audit) apply, among them one cosigner per
separate cluster or cloud account. The DevNet soak runs in one cluster, which is fine for a release
candidate and is not a production topology.

All of these hold, or the release waits:

- [ ] No open `prio:p0`; every `release:qa` issue triaged
- [ ] CI green on the candidate commit, including the weekly conformance run
- [ ] Soak criteria in step 5 met
- [ ] Quality report: no metric worse than the previous release without a written reason
- [ ] `CHANGELOG.md` assembled from the fragments (`scripts/changelog.py assemble`, see [releasing.md](releasing.md)), `changelog.d/` empty apart from its README; upgrade notes for any config or wire change
- [ ] SECURITY.md supported-versions table updated
- [ ] The release's row is in the compatibility matrix ([compatibility.md](compatibility.md)) and in the README's short table: built against, tested, not tested
- [ ] Third-party license files regenerated
- [ ] Release notes, chart defaults and examples do not present a single-cluster deployment as a
  production setup; the go-live gates in `audit-prep.md` match what the release can enforce

## 8. Tag and publish

A maintainer tags `vX.Y.Z` and follows [releasing.md](releasing.md): image digest pinned in the
docs and the tag's commit recorded next to it ("Release records"), release assets attached. The release notes carry the quality report. The baseline for the
quality ratchet moves to the new tag.

## Test schedule

Fast, deterministic checks gate every pull request; slow ones run on a schedule, outside working
hours, so the two self-hosted runners stay free for pull requests. A test that is flaky in the gate
is fixed or moved to the nightly run.

| When | What | If it fails |
|---|---|---|
| Before pushing | `cargo test` and `clippy` for the crates touched; `sbt driver/test` if the driver changed | Do not push |
| Every pull request | Unit tests, clippy, cargo-deny, deploy policy, alert rules, TLS cluster smoke, DCO; the quality ratchet (linters for every language, formatting, Semgrep, gitleaks); property tests at a low case count; the three e2e ceremony scripts (split, carry, ECIES hosted) when the cosigner, the driver or the scripts change. Jobs are filtered by path | The pull request does not merge |
| Every push to `main` | Everything above with no path filter, plus coverage for Rust and Scala and the image build check | `prio:p0` issue: `main` stays green |
| Nightly, 02:00 UTC | Fuzzing, 10 minutes per target; property tests at a high case count; `cargo audit` against the latest advisories; image scan | `type:test` `prio:p1` issue |
| Weekly, Monday 06:00 UTC | Canton conformance suite; `cargo mutants` on the signing path (nonces, sign sessions, sign policy, intents, sealing); `buf breaking` against the last release; the weekly quality report | `prio:p1` issue |
| Release candidate | All of the above on the candidate tag, plus fuzzing for one hour per target, the full mutation run and the QA tracks in step 4 | `prio:p0` means a new candidate |
| Soak | The candidate on the DevNet soak validators, step 5 | No go/no-go until it passes |

Scheduled failures open an issue automatically; the issue gets an owner the same day.

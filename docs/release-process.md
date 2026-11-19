# Release process

How a Rütli release goes from `main` to a tag. Written for `0.5.0`, the version the external audit
reviews; later releases follow the same steps.

## 1. Development

Work lands on `main` through PRs (see [CONTRIBUTING.md](../CONTRIBUTING.md)). Each PR keeps the
quality ratchet from getting worse. The release milestone lists what is planned.

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

All of these hold, or the release waits:

- [ ] No open `prio:p0`; every `release:qa` issue triaged
- [ ] CI green on the candidate commit, including the weekly conformance run
- [ ] Soak criteria in step 5 met
- [ ] Quality report: no metric worse than the previous release without a written reason
- [ ] `CHANGELOG.md` complete; upgrade notes for any config or wire change
- [ ] SECURITY.md supported-versions table updated
- [ ] Third-party license files regenerated

## 8. Tag and publish

A maintainer tags `vX.Y.Z`, publishes the GitHub release with notes and the quality report, and
pins the image digest in the docs. The baseline for the quality ratchet moves to the new tag.

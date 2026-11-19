# Contributing to Rütli

Rütli holds authority keys. Every change is treated as security-relevant, so the process below is
stricter than for a typical project. It applies to maintainers and outside contributors alike.

## Security problems

Do not open a public issue or pull request for a vulnerability. Report it privately, see
[SECURITY.md](SECURITY.md). Maintainers track such findings in draft GitHub security advisories
until the fix is released. A fix PR describes the change, not how to exploit the old behaviour.

## Where work is tracked

- **Issues** with the `v0.5.0` milestone are the plan for the next release.
- Labels: `area:*` (frost, driver, deploy, ci, docs), `type:*` (bug, hardening, feature, test,
  chore, quality), `prio:p0` (blocks the release), `prio:p1`, `prio:p2`.
- `status:in-progress` means someone is working on it; the issue has a comment saying who and on
  which branch. Check this, and open PRs, before you start, so two people do not fix the same thing.

## One change, one PR

- One issue → one branch → one PR. Branch names: `fix/…`, `feat/…`, `security/…`, `docs/…`,
  `ci/…`, `test/…`, `chore/…`.
- Keep a PR to one concern. A refactor that a fix needs goes in its own commit, or its own PR.
- The PR body says `Closes #N` when there is a public issue.
- Every commit is signed off (`git commit -s`, [DCO](https://developercertificate.org/)).
- User-visible changes get a line in `CHANGELOG.md` under `Unreleased`.

## What a PR needs before merge

1. CI green: tests, lints and the quality ratchet (below).
2. New behaviour has a test; a bug fix has a test that fails without the fix.
3. Changes to signing, DKG, sealing, key storage, the wire protocol or the approval gate get an
   independent second review, by someone who did not write the change.
4. No infrastructure details (hosts, IPs, cluster names, credentials) in code, docs or PR text.

Only maintainers merge, and only maintainers push `v*` tags.

## Quality gates

CI checks each language in the repository. New checks start as a ratchet: the current state on
`main` is recorded as a baseline, and a PR fails only if it makes a metric worse. Old debt does not
block a PR; new debt does not get in. The baseline moves forward when debt is paid off.

| Area | Checks |
|---|---|
| Rust (`frost/`) | `cargo fmt`, `clippy -D warnings`, tests, `cargo deny`, `cargo audit`, `cargo geiger` (unsafe count), `rustqual` score, coverage (`cargo llvm-cov`) |
| Scala (`driver/`) | tests, `scalafmt`, compiler warnings, coverage (`scoverage`) |
| Shell (`scripts/`, `deploy/`) | `shellcheck`, `shfmt` |
| Python | `ruff` |
| Helm / k8s | `helm lint`, render + `scripts/check-deploy-policy.sh`, `kubeconform` |
| Dockerfiles, images | `hadolint`, `trivy` |
| GitHub Actions | `actionlint`, `zizmor`, pinned actions |
| Protobuf | `buf lint`, `buf breaking` against the last release |
| Alert rules | `promtool` |
| Repository | `gitleaks`, `typos`, link check |

Running a check locally before pushing saves a CI round: see the job definitions in
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## Releases

See [docs/release-process.md](docs/release-process.md): freeze, release candidate, QA, soak,
go/no-go, tag.

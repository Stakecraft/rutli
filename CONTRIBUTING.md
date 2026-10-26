# Contributing to Rütli

Thanks for your interest. Rütli holds the keys that define a Canton node's identity, so every change
is reviewed as security-critical. This page explains how to get a change in.

## Security issues first

**Do not report vulnerabilities in issues, pull requests or discussions.** Follow
[SECURITY.md](SECURITY.md) and use private vulnerability reporting.

## Before you start

- **Small fixes** (typos, docs, an obvious bug with a test): open a pull request directly.
- **Anything larger**, or anything touching the FROST protocol, nonce handling, sealing, intents,
  key ceremonies or the driver's key routing: open an issue first and describe the problem and the
  approach. Design changes in these areas need agreement before code.
- Read [docs/architecture.md](docs/architecture.md) and
  [docs/security/threat-model.md](docs/security/threat-model.md) before changing anything on the
  key path.

## Development setup

Prerequisites (details in [QUICKSTART.md](QUICKSTART.md)):

- **JDK 17** and **sbt**, for the driver;
- **Rust stable** with `clippy`, for the cosigner, dealer and FROST core;
- **Docker** with the compose plugin, for the TLS cluster smoke test;
- **Helm 3**, `kubectl`, `yq` v4 and `jq`, for the deployment policy checks.

The Canton KMS driver API is not on Maven Central. Publish it into your local ivy repository once:

```bash
scripts/publish-canton-deps.sh v3.6.1
```

## Running the checks

CI runs these on every pull request; please run the ones your change touches before you push.

Driver unit tests and the jar:

```bash
sbt -batch driver/test driver/assembly
```

FROST core, cosigner and dealer (tests and lints):

```bash
cd frost && cargo test --locked && cargo clippy --all-targets -- -D warnings
```

Deployment manifests (Helm lint, render, and the policy that forbids `pods/exec` RBAC, seal
secrets in env and shared secrets):

```bash
scripts/ci-deploy-policy.sh
```

Prometheus alert rules:

```bash
scripts/ci-prometheus-rules.sh
```

Three-node mTLS cluster smoke test (DKG and signing over Docker Compose):

```bash
scripts/ci-frost-tls-smoke.sh
```

The Canton conformance suite is heavy and runs weekly in CI. To run it locally, publish the full
module closure first (`scripts/publish-canton-deps.sh --full v3.6.1`), then:

```bash
CONFORMANCE=1 CANTON_AUTOMATIC_PROTOCOL_VERSION=1 sbt -batch driver/test
```

## What a good pull request contains

- **One logical change**, with tests that fail without it. A bug fix comes with the test that
  reproduces the bug.
- **No real key material.** Tests generate their keys at run time or use the published test
  vectors. Never commit a key, certificate private key, seal secret or token, even a "throwaway" one.
- **Docs kept true.** If behaviour, configuration or a runbook step changes, update the docs in the
  same pull request.
- **A changelog entry** under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user
  or operator would notice. Security-relevant changes go under `### Security` and say what an
  attacker could do before and cannot do after.
- **Compatibility stated.** Say whether the change needs every cosigner upgraded first, changes a
  wire format, a key-file format or a configuration default, and how to roll back.
- **Third-party notices regenerated** when a dependency is added, removed or upgraded:
  `scripts/third-party-licenses.sh` (needs `cargo-about`; CI checks it, and `cargo deny` rejects
  copyleft licenses in the Rust workspace). Only permissive licenses are accepted for bundled code;
  see `frost/deny.toml` and `scripts/third-party-licenses-jvm.py`.
- **An SPDX header** on new source files, the same as the existing ones:
  ```
  // Copyright 2026 StakeCraft
  // SPDX-License-Identifier: Apache-2.0
  ```
  (`#` comments in shell and YAML).

## Commits and the DCO

Commit messages follow the style already in the history: `type(scope): summary`, for example
`fix(cosigner): …`, `feat(driver): …`, `docs(soak): …`, `test(…)`, `ci: …`, `chore(…)`. Explain the
why in the body.

Every commit must carry a **Developer Certificate of Origin** sign-off. By signing off you certify
the [DCO 1.1](https://developercertificate.org/): you wrote the change or otherwise have the right
to submit it under the project's license. Add it with `-s`:

```bash
git commit -s -m "fix(driver): …"
```

This appends `Signed-off-by: Your Name <you@example.com>`, matching your Git identity. Pull requests
without sign-offs cannot be merged. To fix the last commit, run `git commit --amend -s`; for a whole
branch, `git rebase --signoff main`.

## Review and merge

- CI for pull requests from forks runs on GitHub-hosted runners, and a maintainer approves the first
  workflow run. The project's self-hosted runners only run the repository's own branches.
- A maintainer reviews every pull request. Changes to the key path (FROST, nonces, sealing,
  intents, ceremonies, key routing, TLS) get a second, independent review and may wait for the next
  audit window.
- Pull requests are merged by rebase, so keep the branch history clean.

## License

Rütli is licensed under the [Apache License, Version 2.0](LICENSE). By submitting a contribution
you agree that it is licensed under the same terms (Apache-2.0, section 5). There is no separate
contributor license agreement; the DCO sign-off is the record.

## Conduct

Be respectful and assume good faith. Harassment or personal attacks are not tolerated; maintainers
may remove comments or block participants who cross that line.

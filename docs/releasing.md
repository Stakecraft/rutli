# Releasing

What a Rütli release consists of and what has to ship with each artifact. Tagging `v*` runs
`.github/workflows/publish-image.yml` on GitHub-hosted runners (never the self-hosted CI runners):
it builds the cosigner image for amd64 and arm64 natively, pushes the multi-arch index, signs it
with cosign (keyless) and attests its build provenance. `.github/workflows/release-assets.yml` does
the same for the driver jar and the dealer binary (build, SBOM, signature, provenance) and attaches
them to the GitHub release (see "Release assets").

## Before tagging

1. Versions bumped consistently: `build.sbt` (`ThisBuild / version`), `frost/Cargo.toml`
   (`workspace.package.version`), the Helm chart.
2. `scripts/third-party-licenses.sh --check` passes (CI runs it). After any dependency change, and
   after every version bump (the Rust notices list the workspace's own crates with their version),
   regenerate and commit both `THIRD-PARTY-LICENSES.txt` files first.
3. `CHANGELOG.md`: run `python3 scripts/changelog.py assemble <version> <YYYY-MM-DD>`. It writes the
   `## [<version>] — <date>` section above the previous release from the fragments in `changelog.d/`
   and from whatever is still under `[Unreleased]`, adds the release link at the bottom, and deletes
   the fragments. Read the result, edit the wording, and add the upgrade notes. For a release
   candidate add `--keep`: the fragments stay for the final release, and you fold or delete the rc
   section by hand when you assemble the final one. The release pull request carries the label
   `no-changelog` (it changes the version files and `CHANGELOG.md` itself).
4. "Latest release" references name the new version: `SECURITY.md` (status and supported-versions
   table) and the version placeholder in `.github/ISSUE_TEMPLATE/bug_report.yml`.
5. Tag only after the release PR is merged, and tag the merge commit by its SHA
   (`git tag -a v<version> -m v<version> <sha>`), never a branch head that still carries the old versions.
6. The "Image build check" workflow is green on `main` (it builds both platforms the way the release
   does, without pushing; run it by hand if its last run is old).

## Upgrading a cluster to a release

A per-node install does not restart its cosigners on `helm upgrade` (`updateStrategy: OnDelete`):
run `scripts/upgrade-cosigners.sh` afterwards, which restarts them one at a time and waits for each.
Never restart all three at once; with threshold 2 of 3 nothing can sign until two are back. See the
chart README, "Upgrading: one cosigner at a time".

## After the image is built: pin it by digest

The tag commit still points the deploy files at the previous image. Once `publish-image.yml` has
pushed the new one, read the multi-arch index digest
(the workflow run's summary prints it, or `docker buildx imagetools inspect
ghcr.io/stakecraft/rutli-cosigner:<version>`), verify it with the commands in
[SECURITY.md, "Verify the image"](../SECURITY.md#verify-the-image), and only then pin
`<version>@sha256:<index digest>` in one PR, in every place a default image lives:

- `deploy/helm/rutli-cosigner/values.yaml` (`image.tag`) and its `README.md`;
- `deploy/k8s/kustomization.yaml` (`newTag` + `digest`), `deploy/k8s/cosigner.yaml` (re-render with
  `scripts/render-k8s.sh`), `deploy/k8s/cronjob-refresh.yaml`, `deploy/k8s/job-verify-key.example.yaml`
  and the "currently" version in `deploy/k8s/README.md`;
- `deploy/frost/docker-compose.yml`, `deploy/frost/docker-compose.tls.yml` and `deploy/frost/README.md`.

`git grep` the previous version afterwards: no default should still name it.

### When the run fails part-way

The `index` job pushes the version tags before the `sign` job signs, so a failure in `sign`
(signing, attestation or the final verification) leaves tags that point at an index that does not
verify. Until it is fixed, an operator who pulls `<version>` gets that index, `cosign verify` reports
that no signature matches the expected identity, and `gh attestation verify` finds no attestation:
the documented check fails closed. Do not pin anything until a run has finished green.

- **Re-run failed jobs** in the same run: the failed job and the jobs after it run again, and the
  jobs that succeeded keep their outputs (the platform digests, the index digest), so the same
  images are signed. Use this first.
- **A new `workflow_dispatch` on the tag** (the tag as the ref) when the whole run must be
  repeated: it builds new platform images, assembles and signs a new index and moves the tags to
  it; pin the digest of that run. "Re-run all jobs" does the same.

With required reviewers on the `release` environment, each of these waits for an approval. An image
built with `scripts/local-publish-image.sh` is not signed and does not verify; it is for when
GitHub Actions is unavailable, and the release notes must say so.

## Bumping the Rust compiler

By hand, both in one pull request: `channel` in `frost/rust-toolchain.toml` and the `rust:` image in
`frost/Dockerfile` (tag and multi-arch index digest, `docker buildx imagetools inspect
rust:<version>-slim`). CI and the release image then build with the new version; the image build
check fails if the two differ. Dependabot does not propose Rust image updates for this reason; it
refreshes only the runtime base image digest.

## Release assets

`.github/workflows/release-assets.yml` runs on the same `v*` tag as `publish-image.yml`, on
GitHub-hosted runners (never the self-hosted ones), after its own approval on the `release`
environment. It builds the assets from the tag, signs them and attaches them to the release for the
tag: an existing release gets the files, a missing one is created as a **draft** that the maintainer
completes (notes, quality report) and publishes. `scripts/release-assets.sh` holds every step;
`release-assets-check.yml` runs the same script on pull requests with a throwaway key, so a broken
step shows before tag day.

| Asset | Contents | License files |
|---|---|---|
| `rutli-driver-<version>.jar` | `sbt driver/assembly` | Inside the jar: `META-INF/rutli/LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES.txt` |
| `rutli-dealer-<version>-linux-x86_64`, `-linux-aarch64` | `cargo build --release --locked -p rutli-cosigner --bin rutli-dealer`, each on a native runner | `THIRD-PARTY-LICENSES-rust.txt` (a copy of `frost/THIRD-PARTY-LICENSES.txt`) and `LICENSE`, attached by the workflow |
| `rutli-driver-<version>.spdx.json`, `rutli-dealer-<version>.spdx.json` | SPDX SBOMs: the driver's from the assembled jar, the dealer's from `frost/Cargo.lock` | — |
| `SHA256SUMS` | `sha256sum` of every file above (not of the bundles) | — |
| `<file>.sigstore.json` | the keyless cosign signature of `<file>`, one bundle per file above, `SHA256SUMS` included | — |
| `ghcr.io/stakecraft/rutli-cosigner:<version>` | `publish-image.yml` | In the image: `/usr/share/doc/rutli-cosigner/THIRD-PARTY-LICENSES.txt` |

The workflow also stores a GitHub build provenance attestation for every file (from `SHA256SUMS`).
Release builds use no build cache. A binary for another platform (for example macOS) is not built by
the workflow: if the maintainer attaches one by hand it is unsigned and the notes say so. A binary
without its license file next to it is not a complete release: the MIT and BSD licenses of the
bundled crates require their notices to travel with the binary.

What the release workflow may do beyond `publish-image.yml`: the `build` jobs have `contents: read`;
the `sign` job has `id-token: write` (keyless signing) and `attestations: write` (the provenance
attestation) and checks that the build artifacts are exactly the expected files before it hashes
or signs anything; the `publish` job has `contents: write` (attach the signed set to the release,
create a missing release as a draft) and no signing identity. `publish-image.yml` keeps its
permissions.

### Verify the release assets

Download the files you use and their `.sigstore.json` bundles from the release. You need cosign 3 or
newer and, for the second check, the GitHub CLI (`gh`, 2.103 or newer).

```bash
TAG=v0.5.0
ID="https://github.com/Stakecraft/rutli/.github/workflows/release-assets.yml@refs/tags/$TAG"
FILE=rutli-dealer-0.5.0-linux-x86_64        # or rutli-driver-0.5.0.jar, an .spdx.json (SHA256SUMS: signature only)

# Signature: made by release-assets.yml in Stakecraft/rutli, run on that tag
cosign verify-blob --bundle "$FILE.sigstore.json" \
  --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$FILE"

# Provenance: same workflow and tag, built on a GitHub-hosted runner
gh attestation verify "$FILE" --repo Stakecraft/rutli \
  --signer-workflow Stakecraft/rutli/.github/workflows/release-assets.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners

# The checksums of all files (verify SHA256SUMS itself with the first command)
sha256sum --check --ignore-missing SHA256SUMS
```

The release workflow runs the first command for every file and the second for the jar and both
dealer binaries before it uploads anything, so a file that does not verify is not released. The
SBOMs are signed like every other file; to read one, `jq '.packages[].name' rutli-dealer-<version>.spdx.json`.
The container image is verified as described in [SECURITY.md](../SECURITY.md#verify-the-image).

The files are always one set. The builds are not reproducible, so a repeated run (`workflow_dispatch`)
would sign a second set; it refuses to touch a release that already carries `SHA256SUMS` unless it is
started with `replace_published`, and then it replaces every file. The provenance names the tagged
workflow file, whose jobs all run on the hosted runners that file lists; `--deny-self-hosted-runners`
checks the runner of the signing job.

The dealer binaries are built on `ubuntu-24.04`, so they need glibc 2.39 or newer (Ubuntu 24.04,
Debian 13, RHEL 10). On an older system, build them from the tag (`cargo build --release --locked -p
rutli-cosigner --bin rutli-dealer` in `frost/`) or run the cosigner image. On macOS replace the last
command with `shasum -a 256 -c --ignore-missing SHA256SUMS`.

## Tag-day order

1. Tag. Two runs wait for approval on the `release` environment: `publish-image.yml` and
   `release-assets.yml`; approve both.
2. When both are green, pin the image digest (above), complete and publish the draft release.

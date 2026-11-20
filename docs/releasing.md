# Releasing

What a Rütli release consists of and what has to ship with each artifact. Tagging `v*` runs
`.github/workflows/publish-image.yml` on GitHub-hosted runners (never the self-hosted CI runners):
it builds the cosigner image for amd64 and arm64 natively, pushes the multi-arch index, signs it
with cosign (keyless) and attests its build provenance. The other assets are attached to the GitHub
release by the maintainer.

## Before tagging

1. Versions bumped consistently: `build.sbt` (`ThisBuild / version`), `frost/Cargo.toml`
   (`workspace.package.version`), the Helm chart.
2. `scripts/third-party-licenses.sh --check` passes (CI runs it). After any dependency change, and
   after every version bump (the Rust notices list the workspace's own crates with their version),
   regenerate and commit both `THIRD-PARTY-LICENSES.txt` files first.
3. `CHANGELOG.md`: run `python3 scripts/changelog.py assemble <version> <YYYY-MM-DD>`. It writes the
   `## [<version>] — <date>` section above the previous release from the fragments in `changelog.d/`
   and from whatever is still under `[Unreleased]`, adds the release link at the bottom, and deletes
   the fragments. Read the result, edit the wording, and add the upgrade notes. The release pull
   request carries the label `no-changelog` (it changes the version files and `CHANGELOG.md` itself).
4. "Latest release" references name the new version: `SECURITY.md` (status and supported-versions
   table) and the version placeholder in `.github/ISSUE_TEMPLATE/bug_report.yml`.
5. Tag only after the release PR is merged, and tag the merge commit by its SHA
   (`git tag -a v<version> -m v<version> <sha>`), never a branch head that still carries the old versions.
6. The "Image build check" workflow is green on `main` (it builds both platforms the way the release
   does, without pushing; run it by hand if its last run is old).

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

| Asset | Contents | License files |
|---|---|---|
| `rutli-driver-<version>.jar` | `sbt driver/assembly` | Inside the jar: `META-INF/rutli/LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES.txt` |
| `rutli-dealer-<version>-<os>-<arch>` | `cargo build --release -p rutli-cosigner --bin rutli-dealer` | **Attach next to it:** `THIRD-PARTY-LICENSES-rust.txt` (a copy of `frost/THIRD-PARTY-LICENSES.txt`) and `LICENSE` |
| `SHA256SUMS` | `sha256sum` of every other asset | — |
| `ghcr.io/stakecraft/rutli-cosigner:<version>` | `publish-image.yml` | In the image: `/usr/share/doc/rutli-cosigner/THIRD-PARTY-LICENSES.txt` |

A binary without its license file next to it is not a complete release: the MIT and BSD
licenses of the bundled crates require their notices to travel with the binary.

```bash
cp frost/THIRD-PARTY-LICENSES.txt THIRD-PARTY-LICENSES-rust.txt
```

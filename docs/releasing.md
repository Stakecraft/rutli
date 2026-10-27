# Releasing

What a Rütli release consists of and what has to ship with each artifact. Tagging `v*` runs
`.github/workflows/publish-image.yml`, which builds and pushes the cosigner image; the other assets
are attached to the GitHub release by the maintainer.

## Before tagging

1. Versions bumped consistently: `build.sbt` (`ThisBuild / version`), `frost/Cargo.toml`
   (`workspace.package.version`), the Helm chart.
2. `scripts/third-party-licenses.sh --check` passes (CI runs it). After any dependency change, and
   after every version bump (the Rust notices list the workspace's own crates with their version),
   regenerate and commit both `THIRD-PARTY-LICENSES.txt` files first.
3. `CHANGELOG.md`: move `[Unreleased]` under the new version.
4. "Latest release" references name the new version: `SECURITY.md` (status and supported-versions
   table) and the version placeholder in `.github/ISSUE_TEMPLATE/bug_report.yml`.
5. Tag only after the release PR is merged, and tag the merge commit by its SHA
   (`git tag -a v<version> -m v<version> <sha>`), never a branch head that still carries the old versions.

## After the image is built: pin it by digest

The tag commit still points the deploy files at the previous image. Once `publish-image.yml` has
pushed the new one, read the multi-arch index digest
(`docker buildx imagetools inspect ghcr.io/stakecraft/rutli-cosigner:<version>`) and pin
`<version>@sha256:<index digest>` in one PR, in every place a default image lives:

- `deploy/helm/rutli-cosigner/values.yaml` (`image.tag`) and its `README.md`;
- `deploy/k8s/kustomization.yaml` (`newTag` + `digest`), `deploy/k8s/cosigner.yaml` (re-render with
  `scripts/render-k8s.sh`), `deploy/k8s/cronjob-refresh.yaml`, `deploy/k8s/job-verify-key.example.yaml`;
- `deploy/frost/docker-compose.yml`, `deploy/frost/docker-compose.tls.yml` and `deploy/frost/README.md`.

`git grep` the previous version afterwards: no default should still name it.

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

# Releasing

What a Rütli release consists of and what has to ship with each artifact. Tagging `v*` runs
`.github/workflows/publish-image.yml`, which builds and pushes the cosigner image; the other assets
are attached to the GitHub release by the maintainer.

## Before tagging

1. Versions bumped consistently: `build.sbt` (`ThisBuild / version`), `frost/Cargo.toml`
   (`workspace.package.version`), the Helm chart.
2. `scripts/third-party-licenses.sh --check` passes (CI runs it). After any dependency change,
   regenerate and commit both `THIRD-PARTY-LICENSES.txt` files first.
3. `CHANGELOG.md`: move `[Unreleased]` under the new version.

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

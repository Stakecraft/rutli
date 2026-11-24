#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# The release assets that are not the container image: the driver jar and the dealer binary, with an
# SBOM for each, a SHA256SUMS file, and a cosign signature (a bundle) for every file. The release
# workflow (.github/workflows/release-assets.yml) and its dry run (image-build-check.yml) run the same
# commands, so a step that would fail on a tag fails on a pull request first.
#
#   scripts/release-assets.sh install-tools          cosign and syft, from their releases, checked by sha256
#   scripts/release-assets.sh version-check [TAG]    build.sbt and frost/Cargo.toml agree (and with TAG)
#   scripts/release-assets.sh build-jar OUT          sbt driver/assembly -> OUT/rutli-driver-<version>.jar
#   scripts/release-assets.sh build-dealer OUT       cargo build --release -> OUT/rutli-dealer-<version>-<os>-<arch>
#   scripts/release-assets.sh licenses OUT           LICENSE and THIRD-PARTY-LICENSES-rust.txt next to the binary
#   scripts/release-assets.sh sbom OUT               SPDX SBOMs: rutli-driver-<version>.spdx.json, rutli-dealer-<version>.spdx.json
#   scripts/release-assets.sh sums OUT               SHA256SUMS of every file in OUT (not the bundles)
#   scripts/release-assets.sh sign OUT               a cosign bundle OUT/<file>.sigstore.json for every file
#   scripts/release-assets.sh verify OUT             the commands a user runs, against every file
#
# sign and verify are keyless by default (the workflow's GitHub identity; verify needs
# RELEASE_CERT_IDENTITY). With COSIGN_KEY (a private key; COSIGN_PASSWORD set, possibly empty) and
# COSIGN_PUBKEY they use that key and never touch the public transparency log: that is the dry run.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Tools installed by install-tools. To bump: take the sha256 of the asset from the release page (the
# asset's `digest` in the API: gh api repos/<owner>/<repo>/releases/tags/<tag>).
COSIGN_VERSION="v3.1.4"
COSIGN_SHA256_AMD64="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"
SYFT_VERSION="1.57.2"
SYFT_SHA256_AMD64="ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b"

die() { echo "release-assets: $*" >&2; exit 1; }

sbt_version() {
  sed -n 's/^ThisBuild \/ version *:= *"\([^"]*\)".*/\1/p' "$REPO/build.sbt" | head -n 1
}
cargo_version() {
  awk '/^\[workspace\.package\]/ {on = 1; next} /^\[/ {on = 0} on && /^version *=/ {gsub(/[" ]/, "", $0); sub(/^version=/, "", $0); print; exit}' "$REPO/frost/Cargo.toml"
}
version() {
  local v
  v="$(sbt_version)"
  [ -n "$v" ] || die "cannot read the version from build.sbt"
  printf '%s\n' "$v"
}

need_out() {
  [ -n "${1:-}" ] || die "usage: $0 <command> OUT"
  mkdir -p "$1"
}

cmd_install_tools() {
  [ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || die "install-tools supports linux-x86_64 only (the release runner)"
  local tmp bin
  tmp="$(mktemp -d)"
  bin="$HOME/.local/bin"
  mkdir -p "$bin"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/cosign" \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
  echo "${COSIGN_SHA256_AMD64}  ${tmp}/cosign" | sha256sum -c -
  install -m 0755 "$tmp/cosign" "$bin/cosign"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/syft.tar.gz" \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
  echo "${SYFT_SHA256_AMD64}  ${tmp}/syft.tar.gz" | sha256sum -c -
  tar -xzf "$tmp/syft.tar.gz" -C "$tmp" syft
  install -m 0755 "$tmp/syft" "$bin/syft"
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$bin" >> "$GITHUB_PATH"; fi
  PATH="$bin:$PATH" cosign version
  PATH="$bin:$PATH" syft version
}

cmd_version_check() {
  local tag="${1:-}" s c
  s="$(sbt_version)"
  c="$(cargo_version)"
  [ -n "$s" ] && [ -n "$c" ] || die "cannot read the versions (build.sbt: '${s}', frost/Cargo.toml: '${c}')"
  [ "$s" = "$c" ] || die "build.sbt says ${s}, frost/Cargo.toml says ${c}"
  if [ -n "$tag" ]; then
    [ "$tag" = "v${s}" ] || die "the tag is ${tag}, the versions in the tree are ${s}"
  fi
  echo "OK: version ${s}${tag:+ matches ${tag}}"
}

cmd_build_jar() {
  need_out "${1:-}"
  local v
  v="$(version)"
  (cd "$REPO" && sbt -batch driver/assembly)
  cp "$REPO/driver/target/scala-2.13/rutli-driver.jar" "$1/rutli-driver-${v}.jar"
  ls -l "$1/rutli-driver-${v}.jar"
}

cmd_build_dealer() {
  need_out "${1:-}"
  local v os arch
  v="$(version)"
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  (cd "$REPO/frost" && cargo build --release --locked -p rutli-cosigner --bin rutli-dealer)
  cp "$REPO/frost/target/release/rutli-dealer" "$1/rutli-dealer-${v}-${os}-${arch}"
  ls -l "$1/rutli-dealer-${v}-${os}-${arch}"
}

cmd_licenses() {
  need_out "${1:-}"
  cp "$REPO/LICENSE" "$1/LICENSE"
  cp "$REPO/frost/THIRD-PARTY-LICENSES.txt" "$1/THIRD-PARTY-LICENSES-rust.txt"
}

cmd_sbom() {
  need_out "${1:-}"
  local v jar dealers
  v="$(version)"
  jar="$1/rutli-driver-${v}.jar"
  [ -f "$jar" ] || die "no $jar: run build-jar first"
  # The jar: syft reads the Maven metadata inside the assembled archive.
  syft scan "file:${jar}" -o "spdx-json=$1/rutli-driver-${v}.spdx.json" -q
  # The dealer: the crates it is built from, as locked in frost/Cargo.lock (the binary is one for
  # every platform; the lock file is the same).
  dealers="$(find "$1" -maxdepth 1 -name "rutli-dealer-${v}-*" ! -name '*.json' ! -name '*.spdx.json' | wc -l | tr -d ' ')"
  [ "$dealers" -ge 1 ] || die "no dealer binary in $1: run build-dealer first"
  syft scan "dir:${REPO}/frost" -o "spdx-json=$1/rutli-dealer-${v}.spdx.json" -q
  local f
  for f in "$1/rutli-driver-${v}.spdx.json" "$1/rutli-dealer-${v}.spdx.json"; do
    jq -e '.spdxVersion != null and ((.packages // []) | length) > 0' "$f" >/dev/null \
      || die "$(basename "$f") is not an SPDX document with packages"
  done
  echo "OK: SBOMs for the driver jar ($(jq '.packages | length' "$1/rutli-driver-${v}.spdx.json") packages) and the dealer ($(jq '.packages | length' "$1/rutli-dealer-${v}.spdx.json") packages)"
}

cmd_sums() {
  need_out "${1:-}"
  local tmp
  tmp="$(mktemp)"
  (cd "$1" && find . -maxdepth 1 -type f ! -name '*.sigstore.json' ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum) > "$tmp"
  mv "$tmp" "$1/SHA256SUMS"
  cat "$1/SHA256SUMS"
}

assets() { # every file to sign or verify in $1
  find "$1" -maxdepth 1 -type f ! -name '*.sigstore.json' -printf '%P\n' | LC_ALL=C sort
}

cmd_sign() {
  need_out "${1:-}"
  [ -f "$1/SHA256SUMS" ] || die "no SHA256SUMS in $1: run sums first"
  local f
  while read -r f; do
    if [ -n "${COSIGN_KEY:-}" ]; then
      cosign sign-blob --yes --key "$COSIGN_KEY" --tlog-upload=false --bundle "$1/$f.sigstore.json" "$1/$f" >/dev/null
    else
      cosign sign-blob --yes --bundle "$1/$f.sigstore.json" "$1/$f" >/dev/null
    fi
    echo "signed $f"
  done < <(assets "$1")
}

cmd_verify() {
  need_out "${1:-}"
  local f n=0
  if [ -z "${COSIGN_PUBKEY:-}" ]; then
    [ -n "${RELEASE_CERT_IDENTITY:-}" ] || die "RELEASE_CERT_IDENTITY (the workflow identity) is not set"
  fi
  while read -r f; do
    [ -f "$1/$f.sigstore.json" ] || die "no signature bundle for $f"
    if [ -n "${COSIGN_PUBKEY:-}" ]; then
      cosign verify-blob --key "$COSIGN_PUBKEY" --insecure-ignore-tlog=true --bundle "$1/$f.sigstore.json" "$1/$f" >/dev/null
    else
      cosign verify-blob --bundle "$1/$f.sigstore.json" \
        --certificate-identity "$RELEASE_CERT_IDENTITY" \
        --certificate-oidc-issuer "$OIDC_ISSUER" "$1/$f" >/dev/null
    fi
    n=$((n + 1))
  done < <(assets "$1")
  # The checksums cover every asset: a file that does not match its line is a changed file.
  (cd "$1" && sha256sum --check --strict SHA256SUMS)
  echo "OK: ${n} files verified (signature bundle and SHA256SUMS)"
}

main() {
  local c="${1:-}"
  [ -n "$c" ] || die "usage: $0 install-tools|version-check|build-jar|build-dealer|licenses|sbom|sums|sign|verify [args]"
  shift
  case "$c" in
    install-tools) cmd_install_tools ;;
    version-check) cmd_version_check "$@" ;;
    build-jar) cmd_build_jar "$@" ;;
    build-dealer) cmd_build_dealer "$@" ;;
    licenses) cmd_licenses "$@" ;;
    sbom) cmd_sbom "$@" ;;
    sums) cmd_sums "$@" ;;
    sign) cmd_sign "$@" ;;
    verify) cmd_verify "$@" ;;
    *) die "unknown command '$c'" ;;
  esac
}

main "$@"

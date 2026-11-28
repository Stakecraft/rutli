#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# The release assets that are not the container image: the driver jar, the dealer binary and the
# cosigner binary, with an SBOM for the jar and one for the Rust workspace, a SHA256SUMS file, and a cosign signature (a bundle) for every file. The release
# workflow (.github/workflows/release-assets.yml) and its dry run (release-assets-check.yml) run the same
# commands, so a step that would fail on a tag fails on a pull request first.
#
#   scripts/release-assets.sh install-tools [cosign|syft]   the tools (both by default), from their releases, checked by sha256
#   scripts/release-assets.sh version-check [TAG]    build.sbt and frost/Cargo.toml agree (and with TAG)
#   scripts/release-assets.sh build-jar OUT          sbt driver/assembly -> OUT/rutli-driver-<version>.jar
#   scripts/release-assets.sh build-dealer OUT       cargo build --release -> OUT/rutli-dealer-<version>-<os>-<arch>
#   scripts/release-assets.sh build-cosigner OUT     cargo build --release -> OUT/rutli-cosigner-<version>-<os>-<arch>
#   scripts/release-assets.sh glibc-floor FILE [MAX] the newest glibc symbol version FILE needs; fails if above MAX
#   scripts/release-assets.sh licenses OUT           LICENSE and THIRD-PARTY-LICENSES-rust.txt next to the binary
#   scripts/release-assets.sh sbom OUT               SPDX SBOMs: rutli-driver-<version>.spdx.json, rutli-dealer-<version>.spdx.json
#   scripts/release-assets.sh gather SRC OUT         copy each build artifact (SRC/asset-<kind>/) into OUT, one expected file from each
#   scripts/release-assets.sh gather-sbom SRC OUT    copy the two SBOMs (SRC/asset-sbom/) into OUT
#   scripts/release-assets.sh digest OUT KIND        the GITHUB_OUTPUT line sha256=<hex> of the file of KIND in OUT
#   scripts/release-assets.sh check-digests OUT KIND=SHA256...  each file of KIND in OUT has that digest
#   scripts/release-assets.sh check-set OUT STAGE    OUT holds exactly the expected files: STAGE built|ready|signed
#   scripts/release-assets.sh check-sboms OUT        both SBOMs in OUT are SPDX with a plausible package count
#   scripts/release-assets.sh manifest-digest OUT    sha256=<hex> over every file in OUT (bundles included)
#   scripts/release-assets.sh check-manifest OUT SHA256   OUT is exactly the signed files the signing job stated
#   scripts/release-assets.sh release-state TAG      none | listed | unlisted (SHA256SUMS on the release or not)
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

die() {
  echo "release-assets: $*" >&2
  exit 1
}

sbt_version() {
  sed -n 's/^ThisBuild \/ version *:= *"\([^"]*\)".*/\1/p' "$REPO/build.sbt" | head -n 1
}
cargo_version() {
  awk '/^\[workspace\.package\]/ {on = 1; next} /^\[/ {on = 0} on && /^version *=/ {split($0, a, "\""); print a[2]; exit}' "$REPO/frost/Cargo.toml"
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
  local which="${1:-both}" tmp bin
  case "$which" in
    both | cosign | syft) ;;
    *) die "install-tools: cosign, syft or nothing" ;;
  esac
  tmp="$(mktemp -d)"
  bin="$HOME/.local/bin"
  mkdir -p "$bin"
  if [ "$which" != syft ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/cosign" \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    echo "${COSIGN_SHA256_AMD64}  ${tmp}/cosign" | sha256sum -c -
    install -m 0755 "$tmp/cosign" "$bin/cosign"
    PATH="$bin:$PATH" cosign version
  fi
  if [ "$which" != cosign ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/syft.tar.gz" \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
    echo "${SYFT_SHA256_AMD64}  ${tmp}/syft.tar.gz" | sha256sum -c -
    tar -xzf "$tmp/syft.tar.gz" -C "$tmp" syft
    install -m 0755 "$tmp/syft" "$bin/syft"
    PATH="$bin:$PATH" syft version
  fi
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$bin" >>"$GITHUB_PATH"; fi
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

# The cosigner daemon as a file, for hosts without a container runtime. The same
# crate and lock file as the dealer, so the workspace SBOM (rutli-dealer-<version>.spdx.json, made
# from frost/Cargo.lock) covers it.
cmd_build_cosigner() {
  need_out "${1:-}"
  local v os arch
  v="$(version)"
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  (cd "$REPO/frost" && cargo build --release --locked -p rutli-cosigner --bin rutli-cosigner)
  cp "$REPO/frost/target/release/rutli-cosigner" "$1/rutli-cosigner-${v}-${os}-${arch}"
  ls -l "$1/rutli-cosigner-${v}-${os}-${arch}"
}

# The newest glibc symbol version a binary asks for, which is the oldest glibc it starts on. With
# MAX (for example 2.35) a newer requirement is an error: the release builds the cosigner on an older
# distribution on purpose, and a build that silently needs a newer glibc would not start on the
# distributions docs/releasing.md names.
cmd_glibc_floor() {
  [ -f "${1:-}" ] || die "usage: $0 glibc-floor FILE [MAX]"
  local need
  need="$(objdump -T "$1" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -V | tail -n 1)"
  [ -n "$need" ] || die "glibc-floor: no GLIBC symbol versions in $1 (not a dynamically linked glibc binary?)"
  echo "$(basename "$1") needs glibc ${need} or newer"
  if [ -n "${2:-}" ]; then
    [ "$(printf '%s\n%s\n' "$need" "$2" | sort -V | tail -n 1)" = "$2" ] \
      || die "$(basename "$1") needs glibc ${need}, above the limit ${2}"
  fi
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
  # The dealer and the cosigner: the crates of frost/Cargo.lock (the whole workspace, dev
  # dependencies included; both binaries come from it, on every platform, and the lock file is the
  # same). One SBOM for both, under the dealer's name since 0.5.0. A copy of the lock file alone, so
  # a build directory next to it cannot change the result.
  dealers="$(find "$1" -maxdepth 1 -name "rutli-dealer-${v}-*" ! -name '*.json' ! -name '*.spdx.json' | wc -l | tr -d ' ')"
  [ "$dealers" -ge 1 ] || die "no dealer binary in $1: run build-dealer first"
  local lockdir
  lockdir="$(mktemp -d)"
  cp "$REPO/frost/Cargo.lock" "$lockdir/Cargo.lock"
  syft scan "dir:${lockdir}" -o "spdx-json=$1/rutli-dealer-${v}.spdx.json" -q
  check_sboms "$1"
}

# Both SBOMs are SPDX documents with a plausible number of packages. Run where they are made and again
# where they are signed, so a wrong file from the SBOM job is not signed.
check_sboms() { # OUT
  local v
  v="$(version)"
  local f
  for f in "$1/rutli-driver-${v}.spdx.json" "$1/rutli-dealer-${v}.spdx.json"; do
    jq -e '.spdxVersion != null and ((.packages // []) | length) > 0' "$f" >/dev/null \
      || die "$(basename "$f") is not an SPDX document with packages"
  done
  # The jar's SBOM comes from the Maven metadata kept inside the assembled jar (build.sbt keeps
  # META-INF/maven); a handful of packages means that metadata is gone.
  [ "$(jq '.packages | length' "$1/rutli-driver-${v}.spdx.json")" -ge 5 ] \
    || die "the driver jar's SBOM lists fewer than 5 packages: is META-INF/maven in the jar?"
  [ "$(jq '.packages | length' "$1/rutli-dealer-${v}.spdx.json")" -ge 20 ] \
    || die "the dealer's SBOM lists fewer than 20 packages: is Cargo.lock being read?"
  echo "OK: SBOMs for the driver jar ($(jq '.packages | length' "$1/rutli-driver-${v}.spdx.json") packages) and the dealer ($(jq '.packages | length' "$1/rutli-dealer-${v}.spdx.json") packages)"
}

# The files the release consists of, nothing else: the build jobs' artifacts are trusted by the job
# that signs them, so an unexpected or missing file stops the run before anything is hashed or signed.
# RELEASE_ARCHS: the dealer and cosigner builds to expect (default both architectures; the dry run
# builds on one machine).
expected_files() { # STAGE
  local v a
  v="$(version)"
  local built=("rutli-driver-${v}.jar")
  for a in ${RELEASE_ARCHS:-x86_64 aarch64}; do built+=("rutli-dealer-${v}-linux-${a}" "rutli-cosigner-${v}-linux-${a}"); done
  local extra=(LICENSE THIRD-PARTY-LICENSES-rust.txt "rutli-driver-${v}.spdx.json" "rutli-dealer-${v}.spdx.json" SHA256SUMS)
  case "$1" in
    built) printf '%s\n' "${built[@]}" ;;
    ready) printf '%s\n' "${built[@]}" "${extra[@]}" ;;
    signed)
      local f
      for f in "${built[@]}" "${extra[@]}"; do printf '%s\n%s\n' "$f" "$f.sigstore.json"; done
      ;;
    *) die "check-set: stage must be built, ready or signed" ;;
  esac | LC_ALL=C sort
}

cmd_check_set() {
  [ -d "${1:-}" ] || die "usage: $0 check-set OUT built|signed"
  local want have
  want="$(expected_files "${2:-}")"
  # Everything in OUT, any type: a directory, a link or a stray file is a difference.
  have="$(find "$1" -mindepth 1 -printf '%P\n' | LC_ALL=C sort)"
  if [ "$want" != "$have" ]; then
    echo "release-assets: the files in $1 are not the expected set (${2}):" >&2
    diff <(echo "$want") <(echo "$have") >&2 || true
    exit 1
  fi
  if [ -n "$(find "$1" -mindepth 1 ! -type f)" ]; then die "$1 holds something that is not a regular file"; fi
  echo "OK: $1 holds exactly the expected ${2} files"
}

# Each build artifact is read from its own directory and may hold exactly the one file that build job
# makes: the jar job cannot supply a dealer, a dealer job cannot supply a cosigner, the other
# architecture or the jar. Nothing is merged before this check.
cmd_gather() {
  [ -d "${1:-}" ] || die "usage: $0 gather SRC OUT"
  need_out "${2:-}"
  local v kind want n a kinds=(jar)
  v="$(version)"
  for a in ${RELEASE_ARCHS:-x86_64 aarch64}; do kinds+=("dealer-${a}" "cosigner-${a}"); done
  for kind in "${kinds[@]}"; do
    case "$kind" in
      jar) want="rutli-driver-${v}.jar" ;;
      dealer-*) want="rutli-dealer-${v}-linux-${kind#dealer-}" ;;
      cosigner-*) want="rutli-cosigner-${v}-linux-${kind#cosigner-}" ;;
    esac
    [ -d "$1/asset-${kind}" ] || die "no build artifact asset-${kind} in $1"
    n="$(find "$1/asset-${kind}" -mindepth 1 | wc -l | tr -d ' ')"
    [ "$n" = 1 ] && [ -f "$1/asset-${kind}/${want}" ] && [ ! -L "$1/asset-${kind}/${want}" ] \
      || die "asset-${kind} must hold exactly the file ${want}"
    cp "$1/asset-${kind}/${want}" "$2/${want}"
  done
  echo "OK: ${#kinds[@]} build artifacts, one expected file each"
}

# The SBOM job (no signing identity) makes the two SBOMs from the built files; the signing job takes
# them from their own artifact, exactly these two files.
cmd_gather_sbom() {
  [ -d "${1:-}" ] || die "usage: $0 gather-sbom SRC OUT"
  need_out "${2:-}"
  local v f n
  v="$(version)"
  [ -d "$1/asset-sbom" ] || die "no build artifact asset-sbom in $1"
  n="$(find "$1/asset-sbom" -mindepth 1 | wc -l | tr -d ' ')"
  [ "$n" = 2 ] || die "asset-sbom must hold exactly the two SBOMs"
  for f in "rutli-driver-${v}.spdx.json" "rutli-dealer-${v}.spdx.json"; do
    [ -f "$1/asset-sbom/$f" ] && [ ! -L "$1/asset-sbom/$f" ] || die "asset-sbom lacks the file $f"
    cp "$1/asset-sbom/$f" "$2/$f"
  done
  echo "OK: the two SBOMs"
}

# KIND names a file of the release: jar, dealer-<arch>, cosigner-<arch>, sbom-driver, sbom-dealer.
kind_file() { # KIND
  local v
  v="$(version)"
  case "$1" in
    jar) echo "rutli-driver-${v}.jar" ;;
    dealer-x86_64 | dealer-aarch64) echo "rutli-dealer-${v}-linux-${1#dealer-}" ;;
    cosigner-x86_64 | cosigner-aarch64) echo "rutli-cosigner-${v}-linux-${1#cosigner-}" ;;
    sbom-driver) echo "rutli-driver-${v}.spdx.json" ;;
    sbom-dealer) echo "rutli-dealer-${v}.spdx.json" ;;
    *) die "unknown kind '$1'" ;;
  esac
}

# The job that makes a file states its digest as a job output; the jobs that read the file compare.
# An artifact can be replaced by any job of the run (they share the artifact token); a job's outputs
# cannot be changed by another job.
cmd_digest() {
  [ -d "${1:-}" ] && [ -n "${2:-}" ] || die "usage: $0 digest OUT KIND"
  local f
  f="$1/$(kind_file "$2")"
  [ -f "$f" ] || die "no $f"
  echo "sha256=$(sha256sum "$f" | cut -d' ' -f1)"
}

cmd_check_digests() {
  [ -d "${1:-}" ] || die "usage: $0 check-digests OUT KIND=SHA256..."
  local out="$1" pair kind want f have n=0
  shift
  [ $# -gt 0 ] || die "check-digests: no digests given"
  for pair in "$@"; do
    kind="${pair%%=*}"
    want="${pair#*=}"
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "check-digests: no valid digest for ${kind} (got '${want}')"
    f="$out/$(kind_file "$kind")"
    [ -f "$f" ] || die "check-digests: no $f"
    have="$(sha256sum "$f" | cut -d' ' -f1)"
    [ "$have" = "$want" ] || die "$(basename "$f") is not the file its job made (sha256 ${have}, the job stated ${want})"
    n=$((n + 1))
  done
  echo "OK: ${n} files are the ones their jobs made"
}

# A digest over the whole signed release (every file, bundles included), stated by the signing job as
# a job output and compared by the job that uploads: the artifact between the two could be replaced by
# any job of the run, the output cannot.
manifest() { # OUT
  (cd "$1" && find . -maxdepth 1 -type f -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1
}

cmd_manifest_digest() {
  [ -d "${1:-}" ] || die "usage: $0 manifest-digest OUT"
  echo "sha256=$(manifest "$1")"
}

cmd_check_manifest() {
  [ -d "${1:-}" ] || die "usage: $0 check-manifest OUT SHA256"
  [[ "${2:-}" =~ ^[0-9a-f]{64}$ ]] || die "check-manifest: no valid digest (got '${2:-}')"
  local have
  have="$(manifest "$1")"
  [ "$have" = "$2" ] || die "the files in $1 are not the ones the signing job signed (manifest ${have}, stated $2)"
  (cd "$1" && sha256sum --check --strict --quiet SHA256SUMS)
  echo "OK: $1 is the signed release the signing job stated"
}

# Whether the release for TAG exists and carries SHA256SUMS. Fails closed: an error that is not "no
# such release", or an answer that is neither true nor false, stops the run.
cmd_release_state() {
  [ -n "${1:-}" ] || die "usage: $0 release-state TAG"
  local out err
  err="$(mktemp)"
  if out="$(gh release view "$1" --json assets --jq '[.assets[].name] | index("SHA256SUMS") != null' 2>"$err")"; then
    case "$out" in
      true) echo listed ;;
      false) echo unlisted ;;
      *) die "unexpected answer about the release $1: ${out}" ;;
    esac
  elif grep -q 'release not found' "$err"; then
    echo none
  else
    die "cannot read the release $1: $(cat "$err")"
  fi
}

cmd_sums() {
  need_out "${1:-}"
  local tmp
  tmp="$(mktemp)"
  (cd "$1" && find . -maxdepth 1 -type f ! -name '*.sigstore.json' ! -name SHA256SUMS -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum) >"$tmp"
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
      # cosign 3 uses a signing config by default, which always uploads to the log: a key signature
      # that must stay out of the public log needs the config off (flag deprecated, still working).
      cosign sign-blob --yes --key "$COSIGN_KEY" --use-signing-config=false --tlog-upload=false \
        --bundle "$1/$f.sigstore.json" "$1/$f" >/dev/null </dev/null
    else
      cosign sign-blob --yes --bundle "$1/$f.sigstore.json" "$1/$f" >/dev/null </dev/null
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
      cosign verify-blob --key "$COSIGN_PUBKEY" --insecure-ignore-tlog=true --bundle "$1/$f.sigstore.json" "$1/$f" >/dev/null </dev/null
    else
      cosign verify-blob --bundle "$1/$f.sigstore.json" \
        --certificate-identity "$RELEASE_CERT_IDENTITY" \
        --certificate-oidc-issuer "$OIDC_ISSUER" "$1/$f" >/dev/null </dev/null
    fi
    n=$((n + 1))
  done < <(assets "$1")
  # The checksums cover every asset: a file that does not match its line is a changed file.
  (cd "$1" && sha256sum --check --strict SHA256SUMS)
  echo "OK: ${n} files verified (signature bundle and SHA256SUMS)"
}

main() {
  local c="${1:-}"
  [ -n "$c" ] || die "usage: $0 install-tools|version-check|build-jar|build-dealer|build-cosigner|glibc-floor|licenses|sbom|gather|gather-sbom|digest|check-digests|check-set|check-sboms|manifest-digest|check-manifest|release-state|sums|sign|verify [args]"
  shift
  case "$c" in
    install-tools) cmd_install_tools "$@" ;;
    version-check) cmd_version_check "$@" ;;
    build-jar) cmd_build_jar "$@" ;;
    build-dealer) cmd_build_dealer "$@" ;;
    build-cosigner) cmd_build_cosigner "$@" ;;
    glibc-floor) cmd_glibc_floor "$@" ;;
    licenses) cmd_licenses "$@" ;;
    sbom) cmd_sbom "$@" ;;
    gather) cmd_gather "$@" ;;
    gather-sbom) cmd_gather_sbom "$@" ;;
    digest) cmd_digest "$@" ;;
    check-digests) cmd_check_digests "$@" ;;
    check-set) cmd_check_set "$@" ;;
    check-sboms) check_sboms "$@" ;;
    manifest-digest) cmd_manifest_digest "$@" ;;
    check-manifest) cmd_check_manifest "$@" ;;
    release-state) cmd_release_state "$@" ;;
    sums) cmd_sums "$@" ;;
    sign) cmd_sign "$@" ;;
    verify) cmd_verify "$@" ;;
    *) die "unknown command '$c'" ;;
  esac
}

main "$@"

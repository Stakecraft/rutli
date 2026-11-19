#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Install the pinned quality tools listed in scripts/quality/tools.txt into DIR/bin.
#
#   scripts/quality/install-tools.sh DIR [TOOL...]
#
# Release binaries are downloaded and checked against the sha256 in tools.txt; a mismatch aborts.
# Crates without release binaries are built with `cargo install --locked` (needs cargo); Python
# tools go into a virtualenv from a hash-pinned requirements file (needs python3 >= 3.10); rule
# sets are fetched from git at a pinned commit.
# DIR can be cached between runs: downloads, pip's cache and cargo builds are reused, and binaries
# are checked again on each run (see the functions below).
# With TOOL arguments only those tools are installed. PYTHON overrides the python3 used for venvs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="$HERE/tools.txt"

[ $# -ge 1 ] || {
  echo "usage: $0 DIR [TOOL...]" >&2
  exit 2
}
DIR="$(mkdir -p "$1" && cd "$1" && pwd)"
shift
mkdir -p "$DIR/bin" "$DIR/stamps" "$DIR/downloads" "$DIR/venvs"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) PLATFORM=linux-x86_64 ;;
  Darwin-arm64) PLATFORM=darwin-arm64 ;;
  *)
    echo "unsupported platform $(uname -s)-$(uname -m); install the tools by hand" >&2
    exit 1
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

wanted() {
  [ ${#ONLY[@]} -eq 0 ] && return 0
  local t
  for t in "${ONLY[@]}"; do [ "$t" = "$1" ] && return 0; done
  return 1
}
ONLY=("$@")

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP:?}"' EXIT

# Release binaries: the archive is kept in DIR/downloads, checked against its sha256 on every run
# and extracted again, so a cached DIR cannot hand back a binary that differs from the pinned one.
install_binary() {
  local tool="$1" version="$2" sum="$3" url="$4"
  local file work="$TMP/$tool" got bin
  file="$DIR/downloads/$(basename "$url")"
  mkdir -p "$work"
  if [ ! -f "$file" ] || [ "$(sha256 "$file")" != "$sum" ]; then
    curl -fsSL --retry 3 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  got="$(sha256 "$file")"
  if [ "$got" != "$sum" ]; then
    rm -f "$file"
    echo "sha256 mismatch for $tool $version: expected $sum, got $got" >&2
    exit 1
  fi
  case "$file" in
    *.tar.gz | *.tgz) tar -xzf "$file" -C "$work" ;;
    *.zip) unzip -q "$file" -d "$work" ;;
    *) cp "$file" "$work/$tool" ;;
  esac
  bin="$(find "$work" -type f -name "$tool" | head -1)"
  [ -n "$bin" ] || {
    echo "no $tool binary in $url" >&2
    exit 1
  }
  install -m 0755 "$bin" "$DIR/bin/$tool"
  echo "$tool $version"
}

# Crates: cargo checks the crate checksums against the crates.io index when it builds them. The
# built binary is reused while the version is unchanged (a cache restored in CI is written only by
# this repository's own workflow runs).
install_crate() {
  local tool="$1" version="$2" crate="$3"
  local stamp="$DIR/stamps/$tool"
  if [ -x "$DIR/bin/$tool" ] && [ "$(cat "$stamp" 2>/dev/null)" = "crate $version" ]; then
    echo "$tool $version (cargo install, cached)"
    return 0
  fi
  cargo install --locked --quiet --force --root "$DIR" --version "$version" "$crate"
  echo "crate $version" >"$stamp"
  echo "$tool $version (cargo install)"
}

# Python tools: the virtualenv is rebuilt on every run; pip checks every distribution, downloaded
# or taken from its cache in DIR/pip-cache, against the sha256 in the requirements file.
install_pip() {
  local tool="$1" version="$2" req="$HERE/$3"
  local venv="$DIR/venvs/$tool"
  rm -rf "${DIR:?}/venvs/${tool:?}"
  "${PYTHON:-python3}" -m venv "$venv"
  PIP_CACHE_DIR="$DIR/pip-cache" "$venv/bin/pip" install --quiet --disable-pip-version-check \
    --require-hashes --no-deps -r "$req"
  # A wrapper, not a symlink: semgrep's launcher runs its helpers from PATH.
  rm -f "$DIR/bin/$tool"
  cat >"$DIR/bin/$tool" <<EOF
#!/bin/sh
PATH="$venv/bin:\$PATH" exec "$venv/bin/$tool" "\$@"
EOF
  chmod 0755 "$DIR/bin/$tool"
  echo "$tool $version (pip, hash-pinned)"
}

# Rule sets: checked out at the pinned commit on every run, with anything else in the directory
# removed.
install_git() {
  local name="$1" commit="$2" repo="$3"
  local dest="$DIR/$name"
  if ! git -C "$dest" cat-file -e "$commit^{commit}" 2>/dev/null; then
    rm -rf "${DIR:?}/${name:?}"
    git init --quiet "$dest"
    git -C "$dest" fetch --quiet --depth 1 "$repo" "$commit"
  fi
  git -C "$dest" checkout --quiet --force --detach "$commit"
  git -C "$dest" clean --quiet -fdx
  [ "$(git -C "$dest" rev-parse HEAD)" = "$commit" ] || {
    echo "$name: checked out $(git -C "$dest" rev-parse HEAD), expected $commit" >&2
    exit 1
  }
  echo "$name at $commit"
}

while read -r first a b c d; do
  case "$first" in '' | '#'*) continue ;; esac
  if [ "$first" = crate ]; then
    wanted "$a" && install_crate "$a" "$b" "$c"
  elif [ "$first" = pip ]; then
    wanted "$a" && install_pip "$a" "$b" "$c"
  elif [ "$first" = git ]; then
    wanted "$a" && install_git "$a" "$b" "$c"
  elif [ "$b" = "$PLATFORM" ]; then
    wanted "$first" && install_binary "$first" "$a" "$c" "$d"
  fi
done <"$LIST"
echo "tools in $DIR/bin"

#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate the third-party license files that ship with Rütli's release artifacts:
#   frost/THIRD-PARTY-LICENSES.txt   Rust crates in rutli-cosigner (image) and rutli-dealer (binary)
#   driver/THIRD-PARTY-LICENSES.txt  JVM jars bundled into rutli-driver.jar (META-INF/rutli/)
#
# Usage: scripts/third-party-licenses.sh [--check] [rust|jvm|all]   (default: all)
#   --check  regenerate into a temporary file and fail if the committed file differs (CI).
#
# Needs: cargo-about (rust); sbt with the Canton API published locally (jvm, see CONTRIBUTING.md).
# Run it after any dependency change and commit the result.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
check=0
if [[ "${1:-}" == "--check" ]]; then check=1; shift; fi
what="${1:-all}"
case "$what" in rust | jvm | all) ;; *) echo "usage: $0 [--check] [rust|jvm|all]" >&2; exit 2 ;; esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

finish() { # <generated> <committed>
  if [[ $check -eq 1 ]]; then
    if ! diff -u "$2" "$1" >"$TMP/diff"; then
      head -40 "$TMP/diff" >&2
      echo "ERROR: ${2#"$ROOT"/} is out of date; run scripts/third-party-licenses.sh and commit it" >&2
      exit 1
    fi
    echo "OK: ${2#"$ROOT"/} is up to date"
  else
    cp "$1" "$2"
    echo "wrote ${2#"$ROOT"/}"
  fi
}

if [[ "$what" == rust || "$what" == all ]]; then
  (cd "$ROOT/frost" && cargo about generate about.hbs -o "$TMP/rust.txt")
  finish "$TMP/rust.txt" "$ROOT/frost/THIRD-PARTY-LICENSES.txt"
fi

if [[ "$what" == jvm || "$what" == all ]]; then
  # The classpath is the one output line with jars on it. No colour codes (CI forces them on), and
  # nothing else on stdout may be mistaken for it.
  (cd "$ROOT" && sbt -batch -Dsbt.log.noformat=true -Dsbt.color=false \
    "export driver/Runtime/dependencyClasspath") >"$TMP/sbt.out" 2>&1 || true
  sed $'s/\x1b\\[[0-9;]*m//g' "$TMP/sbt.out" | grep '\.jar' | grep -v '^\[' | tail -n 1 >"$TMP/cp.txt" || true
  if ! grep -q '\.jar' "$TMP/cp.txt"; then
    tail -30 "$TMP/sbt.out" >&2
    echo "ERROR: could not read the driver classpath from sbt (output above)" >&2
    exit 1
  fi
  python3 -I "$ROOT/scripts/third-party-licenses-jvm.py" "$TMP/cp.txt" "$TMP/jvm.txt"
  finish "$TMP/jvm.txt" "$ROOT/driver/THIRD-PARTY-LICENSES.txt"
fi

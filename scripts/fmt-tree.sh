#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Format (or check) every Rust file of the repository with the pinned toolchain's rustfmt: the
# frost/ workspace and the separate frost/fuzz crate.
#
#   scripts/fmt-tree.sh            rewrite the files (what the format commit and a branch's catch-up run)
#   scripts/fmt-tree.sh --check    exit 1 if any file would change (CI)
#   scripts/fmt-tree.sh --count    print how many files and hunks would change; change nothing
#
# rustfmt does not reach a fixed point in one pass on a few constructs (a `match` inside a `let`,
# two hunks on the tree of 2026-11-21): a second pass settles them. The write mode therefore runs
# until a pass changes nothing (at most four), so `--check` is clean afterwards. Use the toolchain of
# frost/rust-toolchain.toml; another rustfmt version formats a few lines differently.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-write}"

crates=("$REPO/frost" "$REPO/frost/fuzz")

# frost/fuzz pins a nightly compiler for libFuzzer (frost/fuzz/rust-toolchain.toml); its sources are
# formatted with the toolchain of the workspace, like the rest, and a nightly may not have rustfmt.
toolchain="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$REPO/frost/rust-toolchain.toml")"
if [ -n "$toolchain" ] && command -v rustup >/dev/null 2>&1; then
  export RUSTUP_TOOLCHAIN="$toolchain"
fi

check() { # dir
  (cd "$1" && cargo fmt --all -- --check >/dev/null 2>&1)
}

case "$mode" in
  --check)
    bad=0
    for c in "${crates[@]}"; do
      if ! (cd "$c" && cargo fmt --all -- --check); then bad=1; fi
    done
    if [ "$bad" != 0 ]; then
      echo "scripts/fmt-tree.sh: not formatted. Run scripts/fmt-tree.sh and commit the result." >&2
      exit 1
    fi
    echo "rustfmt: the tree is formatted"
    ;;
  --count)
    # The two crates overlap (the fuzz sources are included by cosigner tests): count unique hunks.
    all=""
    for c in "${crates[@]}"; do
      all+="$(cd "$c" && cargo fmt --all -- --check 2>/dev/null || true)"$'\n'
    done
    hunks="$(printf '%s' "$all" | sed -n 's/^Diff in \(.*\):$/\1/p' | sort -u)"
    files="$(printf '%s\n' "$hunks" | sed 's/:[0-9]*$//' | sort -u | grep -c . || true)"
    echo "rustfmt would change $files file(s) in $(printf '%s\n' "$hunks" | grep -c . || true) hunk(s) (first pass; a second pass settles a few more)"
    ;;
  write)
    for c in "${crates[@]}"; do
      for _ in 1 2 3 4; do
        (cd "$c" && cargo fmt --all)
        if check "$c"; then break; fi
      done
      check "$c" || {
        echo "scripts/fmt-tree.sh: $c did not settle after four passes" >&2
        exit 1
      }
    done
    echo "rustfmt: formatted"
    ;;
  *)
    echo "usage: $0 [--check | --count]" >&2
    exit 2
    ;;
esac

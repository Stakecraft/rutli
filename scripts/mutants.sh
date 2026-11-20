#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# Mutation-test one module of the signing path with cargo-mutants.
#
#   scripts/mutants.sh MODULE [cargo-mutants options...]
#   scripts/mutants.sh --list-modules
#
# MODULE is one of the names below. Each module runs the tests that exercise it — not the whole
# suite, whose other integration tests never reach it and only cost link time per mutant. Set
# MUTANTS_TESTS to override the cargo test arguments (e.g. leave out tests that bind TCP ports
# where that is not allowed). The weekly workflow (.github/workflows/mutants.yml) runs every module
# through this script. See docs/mutation-testing.md.
set -euo pipefail

modules="nonce_store session sign_policy journal intent seal"

if [ "${1:-}" = "--list-modules" ]; then
  echo "$modules"
  exit 0
fi
module="${1:?usage: scripts/mutants.sh MODULE [cargo-mutants options...] (MODULE: $modules)}"
shift

policy_tests="--lib --test signing_policy --test ceremony_intent --test tombstones"
case "$module" in
  nonce_store) file=core/src/nonce_store.rs;     pkg=rutli-frost-core; tests="" ;;
  session)     file=core/src/session.rs;         pkg=rutli-frost-core; tests="" ;;
  sign_policy) file=cosigner/src/sign_policy.rs; pkg=rutli-cosigner;   tests="$policy_tests" ;;
  journal)     file=cosigner/src/journal.rs;     pkg=rutli-cosigner;   tests="$policy_tests --test audit_cross_check" ;;
  intent)      file=cosigner/src/intent.rs;      pkg=rutli-cosigner;   tests="$policy_tests" ;;
  seal)        file=cosigner/src/seal.rs;        pkg=rutli-cosigner
               tests="--lib --test seal_cli --test keyfile_cli --test restore --test export_import --test ceremony_store --test cluster --test tombstones" ;;
  *) echo "unknown module '$module' (one of: $modules)" >&2; exit 1 ;;
esac
tests="${MUTANTS_TESTS-$tests}"

cd "$(dirname "$0")/../frost"
# shellcheck disable=SC2086 # $tests is a list of cargo test arguments
exec cargo mutants --no-shuffle --file "$file" --test-package "$pkg" "$@" -- --locked $tests

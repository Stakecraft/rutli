#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Rust metrics for frost/: clippy, rustfmt, tests, coverage, cargo deny, cargo geiger, rustqual.
# cargo audit is its own area (audit.sh), run nightly. Run by collect.sh. QUALITY_COVERAGE=0 skips
# the coverage run (it builds and runs the whole test suite instrumented, the slowest step).
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init rust
W="$Q_WORK/rust"

KEYS=(rust.clippy.warnings rust.clippy.pedantic rust.fmt.unformatted_files rust.tests
  rust.coverage.lines rust.coverage.functions rust.deny.errors rust.deny.warnings
  rust.clippy.unwrap_used rust.clippy.indexing_slicing
  rust.unsafe.exprs rust.unsafe.items
  rust.rustqual.score rust.rustqual.iosp rust.rustqual.complexity rust.rustqual.dry
  rust.rustqual.srp rust.rustqual.coupling rust.rustqual.test_quality
  rust.rustqual.architecture rust.rustqual.functions)

if [ ! -f "$Q_ROOT/frost/Cargo.toml" ]; then
  for k in "${KEYS[@]}"; do q_null "$k" "no frost/Cargo.toml"; done
  exit 0
fi
cd "$Q_ROOT/frost"
q_need cargo "${KEYS[@]}" || exit 0
# The tree may pin its own toolchain (frost/rust-toolchain.toml, profile minimal). In CI, make
# sure that toolchain has what the collectors use; rustup installs the toolchain itself if needed.
if [ "${QUALITY_RUSTUP_COMPONENTS:-0}" = 1 ] && command -v rustup >/dev/null 2>&1; then
  rustup component add clippy rustfmt llvm-tools-preview >&2 || q_log "rustup component add failed"
fi
q_tool rustc rustc --version

# Unique warnings in cargo's JSON message stream. A lint fires once per target (lib, test, ...),
# so warnings are de-duplicated by lint, file, line and column.
count_warnings() {
  jq -r 'select(.reason == "compiler-message") | .message
         | select(.level == "warning" and (.spans | length) > 0)
         | [(.code.code // ""), .spans[0].file_name, .spans[0].line_start, .spans[0].column_start]
         | @tsv' "$1" | sort -u | wc -l | tr -d ' '
}

# --- clippy ---------------------------------------------------------------------------------
q_tool clippy cargo clippy --version
if cargo clippy --workspace --all-targets --locked --message-format=json \
  >"$W/clippy.json" 2>"$W/clippy.err"; then
  q_metric rust.clippy.warnings "$(count_warnings "$W/clippy.json")"
else
  tail -20 "$W/clippy.err" >&2
  q_null rust.clippy.warnings "cargo clippy failed"
fi
if cargo clippy --workspace --all-targets --locked --message-format=json -- -W clippy::pedantic \
  >"$W/pedantic.json" 2>"$W/pedantic.err"; then
  q_metric rust.clippy.pedantic "$(count_warnings "$W/pedantic.json")"
else
  q_null rust.clippy.pedantic "cargo clippy failed"
fi

# unwrap() and unchecked indexing in non-test code (lib and bin targets: #[cfg(test)] modules and
# tests/ are not compiled). Counted, not denied.
if cargo clippy --workspace --lib --bins --locked --message-format=json -- \
  -W clippy::unwrap_used -W clippy::indexing_slicing >"$W/panics.json" 2>"$W/panics.err"; then
  for lint in unwrap_used indexing_slicing; do
    q_metric "rust.clippy.$lint" "$(jq -r --arg c "clippy::$lint" 'select(.reason == "compiler-message") | .message
      | select(.code.code == $c and (.spans | length) > 0)
      | [.spans[0].file_name, .spans[0].line_start, .spans[0].column_start] | @tsv' "$W/panics.json" | sort -u | wc -l)"
  done
else
  q_null rust.clippy.unwrap_used "cargo clippy failed"
  q_null rust.clippy.indexing_slicing "cargo clippy failed"
fi

# --- rustfmt --------------------------------------------------------------------------------
if cargo fmt --version >/dev/null 2>&1; then
  q_tool rustfmt cargo fmt --version
  rc=0
  cargo fmt --all -- --check --files-with-diff >"$W/fmt.out" 2>"$W/fmt.err" || rc=$?
  if [ "$rc" -le 1 ]; then
    q_metric rust.fmt.unformatted_files "$(q_grep -E '\.rs$' "$W/fmt.out" | sort -u | wc -l)"
  else
    q_null rust.fmt.unformatted_files "cargo fmt failed (exit $rc)"
  fi
else
  q_null rust.fmt.unformatted_files "rustfmt not installed"
fi

# --- tests (listed, not run: the count does not depend on the machine) -----------------------
if cargo test --workspace --locked -- --list --format terse >"$W/tests.out" 2>"$W/tests.err"; then
  q_metric rust.tests "$(grep -c ': test$' "$W/tests.out" || true)"
else
  tail -20 "$W/tests.err" >&2
  q_null rust.tests "cargo test --list failed"
fi

# --- coverage -------------------------------------------------------------------------------
if [ "${QUALITY_COVERAGE:-1}" = 0 ]; then
  q_skip rust.coverage.lines "coverage off in this run (QUALITY_COVERAGE=0)"
  q_skip rust.coverage.functions "coverage off in this run (QUALITY_COVERAGE=0)"
elif ! cargo llvm-cov --version >/dev/null 2>&1; then
  q_null rust.coverage.lines "cargo-llvm-cov not installed"
  q_null rust.coverage.functions "cargo-llvm-cov not installed"
elif ! (rustup component list --installed 2>/dev/null || true) | grep '^llvm-tools' >/dev/null; then
  # cargo-llvm-cov would otherwise offer to install it, interactively.
  q_null rust.coverage.lines "rustup component llvm-tools-preview not installed"
  q_null rust.coverage.functions "rustup component llvm-tools-preview not installed"
else
  q_tool cargo-llvm-cov cargo llvm-cov --version
  # --ignore-run-fail: a failing test is the test job's business; coverage is still reported.
  if cargo llvm-cov --workspace --locked --ignore-run-fail --summary-only --json \
    --output-path "$W/cov.json" >"$W/cov.out" 2>"$W/cov.err"; then
    q_metric rust.coverage.lines "$(jq '.data[0].totals.lines.percent * 100 | round / 100' "$W/cov.json")"
    q_metric rust.coverage.functions "$(jq '.data[0].totals.functions.percent * 100 | round / 100' "$W/cov.json")"
  else
    tail -20 "$W/cov.err" >&2
    q_null rust.coverage.lines "cargo llvm-cov failed"
    q_null rust.coverage.functions "cargo llvm-cov failed"
  fi
fi

# --- cargo deny -----------------------------------------------------------------------------
if q_need cargo-deny rust.deny.errors rust.deny.warnings; then
  q_tool cargo-deny cargo deny --version
  cargo deny --format json check >/dev/null 2>"$W/deny.json" || true
  # Diagnostics are the findings; an ERROR log line means the check itself could not run
  # (advisory database fetch, lock file, config).
  broken="$(jq -rR 'fromjson? | select(.type == "log" and .fields.level == "ERROR") | .fields.message' "$W/deny.json" | head -1)"
  if [ -n "$broken" ]; then
    q_null rust.deny.errors "cargo deny could not run: $broken"
    q_null rust.deny.warnings "cargo deny could not run"
  elif [ "$(jq -R 'fromjson? | select(.type == "summary")' "$W/deny.json" | jq -s length)" = 0 ]; then
    # cargo deny prints its JSON diagnostics and a summary on stderr; no summary means the run did
    # not finish or the output format changed, not that there are no findings.
    q_null rust.deny.errors "no cargo deny JSON output"
    q_null rust.deny.warnings "no cargo deny JSON output"
  else
    q_metric rust.deny.errors "$(jq -R 'fromjson? | select(.type == "diagnostic" and .fields.severity == "error")' "$W/deny.json" | jq -s length)"
    q_metric rust.deny.warnings "$(jq -R 'fromjson? | select(.type == "diagnostic" and .fields.severity == "warning")' "$W/deny.json" | jq -s length)"
  fi
fi

# --- cargo geiger (own crates only) ---------------------------------------------------------
# geiger scans one package and its dependencies; run it per workspace member until every member
# has been seen, keep the path (non-registry) packages, and sum the unsafe code they use.
if q_need cargo-geiger rust.unsafe.exprs rust.unsafe.items; then
  q_tool cargo-geiger cargo geiger --version
  : >"$W/geiger.jsonl"
  ok=1
  while read -r name manifest; do
    grep -q "\"n\":\"$name\"" "$W/geiger.jsonl" && continue
    if cargo geiger --manifest-path "$manifest" --output-format Json >"$W/geiger-$name.json" 2>"$W/geiger-$name.err"; then
      jq -c '.packages[] | select((.package.id.source | type) == "object" and (.package.id.source | has("Path")))
             | {n: .package.id.name, u: .unsafety.used}' "$W/geiger-$name.json" >>"$W/geiger.jsonl"
    else
      tail -5 "$W/geiger-$name.err" >&2
      ok=0
    fi
  done < <(cargo metadata --no-deps --format-version 1 --locked | jq -r '.packages[] | "\(.name) \(.manifest_path)"')
  if [ "$ok" = 1 ] && [ -s "$W/geiger.jsonl" ]; then
    q_metric rust.unsafe.exprs "$(jq -s 'unique_by(.n) | map(.u.exprs.unsafe_) | add' "$W/geiger.jsonl")"
    q_metric rust.unsafe.items "$(jq -s 'unique_by(.n) | map(.u.functions.unsafe_ + .u.methods.unsafe_ + .u.item_impls.unsafe_ + .u.item_traits.unsafe_) | add' "$W/geiger.jsonl")"
    q_info rust.unsafe.exprs "$(jq -rs 'unique_by(.n) | map("\(.n) \(.u.exprs.unsafe_)") | join(", ")' "$W/geiger.jsonl")"
  else
    q_null rust.unsafe.exprs "cargo geiger failed"
    q_null rust.unsafe.items "cargo geiger failed"
  fi
fi

# --- rustqual -------------------------------------------------------------------------------
RQ=(rust.rustqual.score rust.rustqual.iosp rust.rustqual.complexity rust.rustqual.dry
  rust.rustqual.srp rust.rustqual.coupling rust.rustqual.test_quality rust.rustqual.architecture)
if q_need rustqual "${RQ[@]}" rust.rustqual.functions; then
  q_tool rustqual rustqual --version
  if rustqual --format json --no-fail . >"$W/rustqual.json" 2>"$W/rustqual.err" \
    && jq -e '.summary.quality_score' "$W/rustqual.json" >/dev/null; then
    q_metric rust.rustqual.score "$(jq '.summary.quality_score * 10000 | round / 100' "$W/rustqual.json")"
    # dimension_scores is in rustqual's dimension order: IOSP, Complexity, DRY, SRP, Coupling,
    # Test Quality, Architecture.
    for i in 1 2 3 4 5 6 7; do
      q_metric "${RQ[$i]}" "$(jq ".summary.dimension_scores[$((i - 1))] * 10000 | round / 100" "$W/rustqual.json")"
    done
    q_metric rust.rustqual.functions "$(jq '.summary.total' "$W/rustqual.json")"
  else
    tail -5 "$W/rustqual.err" >&2
    for k in "${RQ[@]}" rust.rustqual.functions; do q_null "$k" "rustqual failed"; done
  fi
fi

#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Protobuf metrics: buf lint findings (buf's default rules), and buf breaking against the same
# directory in the last release tag (the newest v* tag without a pre-release suffix that is an
# ancestor of the measured commit's parent, so a release tag is compared with the one before it).
# Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init proto
W="$Q_WORK/proto"
export BUF_CACHE_DIR="${BUF_CACHE_DIR:-$W/cache}"
cd "$Q_ROOT"

DIRS=()
while IFS= read -r d; do DIRS+=("$d"); done < <(q_files '*.proto' | xargs -n1 dirname 2>/dev/null | sort -u)
q_need buf proto.buf.lint proto.buf.breaking || exit 0
q_tool buf buf --version
if [ ${#DIRS[@]} = 0 ]; then
  q_metric proto.buf.lint 0
  q_metric proto.buf.breaking 0
  exit 0
fi

lint=0
for d in "${DIRS[@]}"; do
  rc=0
  buf lint "$d" --error-format json >"$W/lint.json" 2>"$W/lint.err" || rc=$?
  # buf exits 100 when it has findings.
  if [ "$rc" != 0 ] && [ "$rc" != 100 ]; then
    tail -5 "$W/lint.err" >&2
    lint=x
    break
  fi
  n="$(q_lines "$W/lint.json")"
  lint=$((lint + n))
done
if [ "$lint" = x ]; then q_null proto.buf.lint "buf lint failed"; else q_metric proto.buf.lint "$lint"; fi

tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' HEAD^ 2>/dev/null || true)"
if [ -z "$tag" ]; then
  q_null proto.buf.breaking "no earlier release tag"
  exit 0
fi
q_info proto.buf.breaking "against $tag"
mkdir -p "$W/against"
breaking=0
for d in "${DIRS[@]}"; do
  # A directory that did not exist in the release has nothing to break.
  git archive "$tag" -- "$d" 2>/dev/null | tar -xf - -C "$W/against" 2>/dev/null || continue
  [ -d "$W/against/$d" ] || continue
  rc=0
  buf breaking "$d" --against "$W/against/$d" --error-format json >"$W/breaking.json" 2>"$W/breaking.err" || rc=$?
  if [ "$rc" != 0 ] && [ "$rc" != 100 ]; then
    tail -5 "$W/breaking.err" >&2
    breaking=x
    break
  fi
  n="$(q_lines "$W/breaking.json")"
  breaking=$((breaking + n))
done
if [ "$breaking" = x ]; then q_null proto.buf.breaking "buf breaking failed"; else q_metric proto.buf.breaking "$breaking"; fi

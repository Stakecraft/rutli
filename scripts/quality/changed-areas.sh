#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Print the quality areas a change touches, comma-separated, for collect.sh --only.
#
#   scripts/quality/changed-areas.sh BASE_COMMIT [HEAD_COMMIT]
#
# semgrep and repo (gitleaks, typos) always run: they are cheap and cover every file. A change to
# the quality tooling itself selects every tree area. audit and image are never selected: their
# counts move when advisories are published, not when code changes, so they run nightly.
set -euo pipefail

[ $# -ge 1 ] || {
  echo "usage: $0 BASE_COMMIT [HEAD_COMMIT]" >&2
  exit 2
}
base="$1"
head="${2:-HEAD}"

areas=(semgrep repo)
add() {
  local a
  for a in "${areas[@]}"; do [ "$a" = "$1" ] && return 0; done
  areas+=("$1")
}

while IFS= read -r f; do
  case "$f" in
    scripts/quality/* | scripts/quality-report.sh | quality/* | .github/workflows/quality.yml)
      for a in rust scala shell python docker actions k8s proto; do add "$a"; done
      ;;
  esac
  case "$f" in frost/*) add rust ;; esac
  case "$f" in driver/* | build.sbt | project/* | .scalafmt.conf) add scala ;; esac
  case "$f" in *.sh | *.bash | scripts/* | deploy/* | .shellcheckrc | .editorconfig) add shell ;; esac
  case "$f" in *.py | pyproject.toml | ruff.toml | .ruff.toml | requirements*.txt) add python ;; esac
  case "${f##*/}" in Dockerfile | Dockerfile.* | *.Dockerfile | .dockerignore | .hadolint.yaml) add docker ;; esac
  case "$f" in .github/*) add actions ;; esac
  case "$f" in deploy/*) add k8s ;; esac
  case "$f" in *.proto | buf.yaml | buf.gen.yaml | buf.work.yaml | */buf.yaml) add proto ;; esac
done < <(git diff --name-only "$base...$head" --)

out=""
for a in "${areas[@]}"; do out="${out:+$out,}$a"; done
echo "$out"

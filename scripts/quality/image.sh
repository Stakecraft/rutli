#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Vulnerabilities in the released cosigner image, by severity (trivy, OS packages and Rust
# binaries). The image is QUALITY_IMAGE, or by default the image of the last release tag of the
# measured tree. trivy pulls the image from the registry itself; no docker needed. Like cargo
# audit, the counts move when advisories are published, so CI runs this nightly. Run by collect.sh
# only when asked for (--only image).
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init image
W="$Q_WORK/image"
SEVERITIES=(CRITICAL HIGH MEDIUM LOW)
KEYS=(image.trivy.critical image.trivy.high image.trivy.medium image.trivy.low)

q_need trivy "${KEYS[@]}" || exit 0
q_tool trivy trivy --version
image="${QUALITY_IMAGE:-}"
if [ -z "$image" ]; then
  tag="$(git -C "$Q_ROOT" describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' HEAD 2>/dev/null || true)"
  if [ -z "$tag" ]; then
    for k in "${KEYS[@]}"; do q_null "$k" "no release tag to take the image from"; done
    exit 0
  fi
  image="ghcr.io/stakecraft/rutli-cosigner:${tag#v}"
fi
q_info image.ref "$image"

if trivy image --quiet --skip-version-check --scanners vuln --format json --cache-dir "${TRIVY_CACHE_DIR:-$W/cache}" \
  --output "$W/trivy.json" "$image" 2>"$W/trivy.err" \
  && jq -e '.ArtifactName' "$W/trivy.json" >/dev/null 2>&1; then
  for s in "${SEVERITIES[@]}"; do
    k="image.trivy.$(echo "$s" | tr '[:upper:]' '[:lower:]')"
    q_metric "$k" "$(jq --arg s "$s" '[.Results[]? | .Vulnerabilities[]? | select(.Severity == $s) | .VulnerabilityID] | unique | length' "$W/trivy.json")"
  done
else
  tail -5 "$W/trivy.err" >&2
  for k in "${KEYS[@]}"; do q_null "$k" "trivy failed on $image"; done
fi

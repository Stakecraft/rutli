#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install the command-line tools of the performance workflows into ~/.local/bin, each at a pinned
# version and checked against a pinned SHA-256 before it is run.
#
# Usage: scripts/perf/install-tools.sh TOOL...     (helm, kind)
#
# To bump a tool: set its version, then its sum to the SHA-256 of the linux-amd64 release asset
# (for helm: the release notes; for kind: the asset's digest on the GitHub release).
# Linux amd64 only: that is what the workflows run on.
set -euo pipefail

HELM_VERSION=v3.16.4 # the version ci.yml checks the chart with
HELM_SHA256=fc307327959aa38ed8f9f7e66d45492bb022a66c3e5da6063958254b9767d179
KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d

[ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || { echo "ERROR: pinned checksums are for Linux x86_64 only" >&2; exit 1; }
[ $# -ge 1 ] || { echo "usage: $0 TOOL... (helm, kind)" >&2; exit 2; }

bin="$HOME/.local/bin"
mkdir -p "$bin"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # url sha256 file
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c -
}

for tool in "$@"; do
  case "$tool" in
    helm)
      fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" "$HELM_SHA256" "$tmp/helm.tar.gz"
      tar -xzf "$tmp/helm.tar.gz" -C "$tmp" linux-amd64/helm
      install -m 0755 "$tmp/linux-amd64/helm" "$bin/helm"
      "$bin/helm" version --short
      ;;
    kind)
      fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256" "$tmp/kind"
      install -m 0755 "$tmp/kind" "$bin/kind"
      "$bin/kind" version
      ;;
    *) echo "ERROR: unknown tool $tool" >&2; exit 2 ;;
  esac
done
if [ -n "${GITHUB_PATH:-}" ]; then echo "$bin" >>"$GITHUB_PATH"; fi

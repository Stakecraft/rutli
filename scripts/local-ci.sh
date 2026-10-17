#!/usr/bin/env bash
# Run the CI jobs of .github/workflows/ci.yml on a workstation (macOS or Linux), in the same order,
# for when GitHub Actions is unavailable or before pushing. Stops at the first failing job.
#
# Usage (from repo root):  scripts/local-ci.sh [rust|driver|deploy|rules|smoke|all]   (default: all)
#
# Needs: Rust stable, JDK 17 + sbt, helm (v3 or v4) and kubectl (for kustomize), Docker (rules,
# smoke), yq v4 and python3 with PyYAML (rules).
# The Canton KMS driver API is not on Maven Central: the first run publishes it to the local ivy
# cache with scripts/publish-canton-deps.sh (CANTON_TAG as in ci.yml).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
CANTON_TAG="${CANTON_TAG:-$(sed -n 's/^ *CANTON_TAG: *//p' .github/workflows/ci.yml | head -1)}"
WHAT="${1:-all}"

step() { printf '\n==> %s\n' "$*"; }

rust() {
  step "FROST core (Rust): cargo test --locked, clippy -D warnings"
  (cd frost && cargo test --locked && cargo clippy --locked --all-targets -- -D warnings)
}

driver() {
  step "Unit tests + assembly (Canton $CANTON_TAG)"
  if ! ls ~/.ivy2/local/com.digitalasset.canton* >/dev/null 2>&1; then
    scripts/publish-canton-deps.sh "$CANTON_TAG"
  fi
  sbt -batch driver/test driver/assembly
  ls -l driver/target/scala-2.13/rutli-driver.jar
}

deploy() {
  step "Deploy manifests policy (Helm + kustomize)"
  scripts/ci-deploy-policy.sh
}

rules() {
  step "Alert rules (promtool)"
  scripts/ci-prometheus-rules.sh
}

smoke() {
  step "FROST TLS cluster smoke (docker compose)"
  scripts/ci-frost-tls-smoke.sh
}

case "$WHAT" in
  rust) rust ;;
  driver) driver ;;
  deploy) deploy ;;
  rules) rules ;;
  smoke) smoke ;;
  all) rust; driver; deploy; rules; smoke ;;
  *) echo "usage: $0 [rust|driver|deploy|rules|smoke|all]" >&2; exit 2 ;;
esac
printf '\n==> local CI: %s passed\n' "$WHAT"

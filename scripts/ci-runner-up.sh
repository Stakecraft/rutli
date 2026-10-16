#!/usr/bin/env bash
# Start the self-hosted CI runner (deploy/ci-runner) on this machine.
# Needs: docker, gh authenticated with admin on the repo (for the registration token).
# See deploy/ci-runner/README.md for switching ci.yml onto it and the trust model.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="${RUNNER_REPO:-Stakecraft/rutli}"
export RUNNER_WORKDIR="${RUNNER_WORKDIR:-$HOME/.cache/rutli-ci-runner/work}"
export RUNNER_NAME="${RUNNER_NAME:-rutli-ci-$(hostname -s)}"
mkdir -p "$RUNNER_WORKDIR"
RUNNER_TOKEN="$(gh api -X POST "repos/$REPO/actions/runners/registration-token" -q .token)"
export RUNNER_TOKEN
docker compose -f deploy/ci-runner/docker-compose.yml up -d --build
echo "runner '$RUNNER_NAME' starting; follow with: docker compose -f deploy/ci-runner/docker-compose.yml logs -f"
echo "route CI to it with: gh variable set CI_RUNNER --body rutli-ci --repo $REPO"

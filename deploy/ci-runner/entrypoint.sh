#!/usr/bin/env bash
# Register once (the registration survives container restarts in the container's own layer),
# then serve jobs. Runs as root so jobs can use the mounted docker socket and `sudo install`.
set -euo pipefail
cd /home/runner
export RUNNER_ALLOW_RUNASROOT=1
if [[ ! -f .runner ]]; then
  : "${RUNNER_TOKEN:?RUNNER_TOKEN (a repo registration token) is required for the first start}"
  ./config.sh --unattended --replace \
    --url "https://github.com/${RUNNER_REPO:-Stakecraft/rutli}" \
    --token "$RUNNER_TOKEN" \
    --name "${RUNNER_NAME:-rutli-ci-$(hostname)}" \
    --labels "${RUNNER_LABELS:-rutli-ci}" \
    --work "$RUNNER_WORKDIR"
fi
exec ./run.sh

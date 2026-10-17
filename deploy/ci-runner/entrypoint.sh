#!/usr/bin/env bash
# Starts as root only to hand the mounted docker socket and the job work dir to the unprivileged
# `runner` user, then registers once (the registration survives container restarts in the
# container's own layer) and serves jobs as `runner` — like GitHub's hosted runners, so tests that
# rely on file permissions (root ignores them) behave the same. `runner` has passwordless sudo.
set -euo pipefail
: "${RUNNER_WORKDIR:?RUNNER_WORKDIR is required}"
if [[ -S /var/run/docker.sock ]]; then chmod 0666 /var/run/docker.sock; fi
mkdir -p "$RUNNER_WORKDIR"
# Per-job scratch; leftovers from earlier runs (possibly root-owned) only get in the way.
rm -rf "${RUNNER_WORKDIR:?}/_temp"
# Best effort: a host bind mount (Docker Desktop file sharing) may refuse chown on some files.
chown -R runner:runner "$RUNNER_WORKDIR" 2>/dev/null || true
runuser -u runner -- test -w "$RUNNER_WORKDIR" || { echo "runner cannot write $RUNNER_WORKDIR" >&2; exit 1; }
cd /home/runner
if [[ ! -f .runner ]]; then
  : "${RUNNER_TOKEN:?RUNNER_TOKEN (a repo registration token) is required for the first start}"
  runuser -u runner -- env HOME=/home/runner ./config.sh --unattended --replace \
    --url "https://github.com/${RUNNER_REPO:-Stakecraft/rutli}" \
    --token "$RUNNER_TOKEN" \
    --name "${RUNNER_NAME:-rutli-ci-$(hostname)}" \
    --labels "${RUNNER_LABELS:-rutli-ci}" \
    --work "$RUNNER_WORKDIR"
fi
exec runuser -u runner -- env HOME=/home/runner ./run.sh

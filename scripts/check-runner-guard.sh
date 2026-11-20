#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# The job-started hook installed on a self-hosted runner must be the one in the repository
# (deploy/ci-runner/job-started-guard.sh): it is the boundary that keeps fork and Dependabot jobs
# off the runner, and an installed copy that drifted from the file everyone reviews is no boundary.
# Run as a step of a job on the runner; it compares the file ACTIONS_RUNNER_HOOK_JOB_STARTED points
# at with the repository's, and names the runner when they differ.
#
# Usage: scripts/check-runner-guard.sh        (exit 0 same, 1 different, unset or missing)
#        RUNNER_GUARD_WARN_ONLY=1 ...          (a *different* guard is reported as a warning, exit 0;
#                                               an unset or unreadable guard always fails)
set -euo pipefail
repo_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/ci-runner/job-started-guard.sh"
runner="${RUNNER_NAME:-this runner}"
installed="${ACTIONS_RUNNER_HOOK_JOB_STARTED:-}"

fail() {
  echo "::error::runner guard: $1"
  exit 1
}

[ -n "$installed" ] || fail "ACTIONS_RUNNER_HOOK_JOB_STARTED is not set on ${runner}: the job-started guard is not installed"
[ -r "$installed" ] || fail "the installed guard ${installed} on ${runner} is missing or unreadable"
want="$(sha256sum "$repo_file" | cut -d' ' -f1)"
have="$(sha256sum "$installed" | cut -d' ' -f1)"
if [ "$want" != "$have" ]; then
  if [ "${RUNNER_GUARD_WARN_ONLY:-0}" = 1 ]; then
    echo "::warning::runner guard: the guard installed on ${runner} (sha256 ${have:0:12}) differs from deploy/ci-runner/job-started-guard.sh (${want:0:12}); reinstall it on every runner (deploy/ci-runner/README.md)"
    exit 0
  fi
  fail "the guard installed on ${runner} (sha256 ${have:0:12}) differs from deploy/ci-runner/job-started-guard.sh (${want:0:12}); reinstall it on every runner (deploy/ci-runner/README.md)"
fi
echo "OK: the guard installed on ${runner} is the repository's (sha256 ${want:0:12})"

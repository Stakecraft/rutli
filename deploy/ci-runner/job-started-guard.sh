#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# Self-hosted runner job-started hook (ACTIONS_RUNNER_HOOK_JOB_STARTED): refuse every job that
# does not come from this repository's own branches. A non-zero exit fails the job before any of
# its steps run.
#
# Why a hook and not only the workflow: a fork pull request runs the workflow file from the PR
# itself, so it can rewrite `runs-on` to target this runner's labels. The hook lives on the runner,
# outside anything a PR can change.
#
# Allowed: push, schedule, workflow_dispatch, and pull_request whose head is a branch of this
# repository (only people with write access can push one). Everything else is refused, including
# pull_request_target, issue_comment and workflow_run. Fails closed: a missing event file, a
# missing jq or an unexpected repository refuses the job.
#
# Install: root-owned, 0755, and `ACTIONS_RUNNER_HOOK_JOB_STARTED=<path>` in the runner's .env
# (the KVM install script does both).
set -u

EXPECTED_REPO="${RUTLI_CI_EXPECTED_REPO:-Stakecraft/rutli}"

refuse() {
  printf '::error::rutli-ci runner guard: %s; this runner only runs jobs from %s branches.\n' "$1" "$EXPECTED_REPO"
  logger -t rutli-ci-guard -- "refused: $1 (event=${GITHUB_EVENT_NAME:-?} repo=${GITHUB_REPOSITORY:-?} run=${GITHUB_RUN_ID:-?})" 2>/dev/null || true
  exit 1
}

[[ "${GITHUB_REPOSITORY:-}" == "$EXPECTED_REPO" ]] || refuse "repository '${GITHUB_REPOSITORY:-unset}'"

case "${GITHUB_EVENT_NAME:-}" in
  push | schedule | workflow_dispatch)
    exit 0
    ;;
  pull_request)
    command -v jq >/dev/null 2>&1 || refuse "jq is missing, cannot read the event"
    [[ -r "${GITHUB_EVENT_PATH:-}" ]] || refuse "event file unreadable"
    head_repo="$(jq -r '.pull_request.head.repo.full_name // empty' "$GITHUB_EVENT_PATH" 2>/dev/null)"
    [[ "$head_repo" == "$EXPECTED_REPO" ]] || refuse "pull request from '${head_repo:-unknown}'"
    exit 0
    ;;
  *)
    refuse "event '${GITHUB_EVENT_NAME:-unset}'"
    ;;
esac

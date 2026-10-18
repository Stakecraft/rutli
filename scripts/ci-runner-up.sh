#!/usr/bin/env bash
# Start the self-hosted CI runner (deploy/ci-runner) inside an ISOLATED Colima VM.
#
# Why a dedicated VM: CI jobs control the docker daemon they are given, which is root on that
# daemon's host. On Docker Desktop that daemon can bind-mount /Users, i.e. your kubeconfig, cloud
# credentials and gh tokens. The `rutli-ci` Colima profile mounts only an empty read-only dir, so
# jobs see nothing of the host. See deploy/ci-runner/README.md.
#
# Needs: colima, docker (CLI + compose plugin), gh authenticated with admin rights on the repo
# (for the one-hour registration token). macOS on Apple silicon (vz + aarch64).
#
# Idempotent: creates the VM if missing, starts it if stopped, refuses to continue if it mounts
# anything but the empty dir read-only, then runs the compose file against the VM's daemon only.
# Re-running re-registers the runner (the token changes, so the container is recreated).
# Env overrides: RUNNER_REPO, RUNNER_NAME, RUNNER_WORKDIR (path inside the VM),
#   RUTLI_CI_PROFILE / RUTLI_CI_CPU / RUTLI_CI_MEMORY (GiB) / RUTLI_CI_DISK (GiB),
#   RUTLI_CI_ROSETTA=0 to accept a VM without Rosetta (default: required, for amd64 image builds).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/ci-runner-lib.sh
source scripts/ci-runner-lib.sh

REPO="${RUNNER_REPO:-Stakecraft/rutli}"
export RUNNER_NAME="${RUNNER_NAME:-rutli-ci-isolated}"
export RUNNER_WORKDIR="${RUNNER_WORKDIR:-$CI_WORKDIR_DEFAULT}"
[[ "$RUNNER_WORKDIR" == /var/lib/rutli-ci/* ]] \
  || die "RUNNER_WORKDIR must be a path inside the VM under /var/lib/rutli-ci/ (got '$RUNNER_WORKDIR')"

for tool in colima docker gh; do command -v "$tool" >/dev/null || die "$tool not found"; done
[[ "$(uname -s)" == Darwin ]] || die "this script targets macOS (Colima vz); on a Linux host use a dedicated machine"

remember_context
trap restore_context EXIT

# 1. The empty dir that replaces Colima's default $HOME mount.
mkdir -p "$CI_EMPTY_DIR"
[[ -z "$(ls -A "$CI_EMPTY_DIR")" ]] || die "$CI_EMPTY_DIR must be empty"

# 2. Create / start the VM. New VMs get Rosetta (--vz-rosetta) for amd64 image builds.
ROSETTA_FLAG=()
[[ "$CI_ROSETTA" == 0 ]] || ROSETTA_FLAG=(--vz-rosetta)
case "$(vm_state)" in
  Running) echo "VM '$CI_PROFILE' already running" ;;
  Stopped) echo "starting VM '$CI_PROFILE'"; colima start --profile "$CI_PROFILE" ;;
  MISSING)
    echo "creating VM '$CI_PROFILE' (${CI_CPU} CPU / ${CI_MEMORY} GiB / ${CI_DISK} GiB disk)"
    colima start --profile "$CI_PROFILE" --cpu "$CI_CPU" --memory "$CI_MEMORY" --disk "$CI_DISK" \
      --vm-type vz --arch aarch64 --runtime docker --mount "$CI_EMPTY_DIR" ${ROSETTA_FLAG[@]+"${ROSETTA_FLAG[@]}"}
    ;;
esac
# `colima start` switches docker's current context to the VM; the EXIT trap switches it back.

# 3. Hard gates: only the empty dir, read-only; docker context is the VM's own.
verify_vm_mounts
verify_rosetta
verify_context
D=(docker --context "$CI_CONTEXT")
"${D[@]}" info >/dev/null || die "cannot reach the VM's docker daemon"

# 4. Isolation probe: the host home must be invisible to containers on this daemon.
probe="$("${D[@]}" run --rm -v "$HOME:/x:ro" alpine:3.20 ls -A /x)" || die "isolation probe failed to run"
[[ -z "$probe" ]] || die "isolation probe sees host files under \$HOME — refusing"
echo "isolation OK: \$HOME is not visible to containers in '$CI_PROFILE'"

# 5. Job work dir lives inside the VM.
colima ssh -p "$CI_PROFILE" -- sudo install -d -m 0777 "$RUNNER_WORKDIR"

# 6. Registration token (never printed) and the runner container, on the VM's daemon.
RUNNER_TOKEN="$(gh api -X POST "repos/$REPO/actions/runners/registration-token" -q .token)"
[[ -n "$RUNNER_TOKEN" ]] || die "could not obtain a registration token for $REPO"
export RUNNER_TOKEN RUNNER_REPO="$REPO"
"${D[@]}" compose -f deploy/ci-runner/docker-compose.yml -p "$CI_PROJECT" up -d --build
unset RUNNER_TOKEN

echo "runner '$RUNNER_NAME' starting on VM '$CI_PROFILE'; follow with:"
echo "  docker --context $CI_CONTEXT compose -f deploy/ci-runner/docker-compose.yml -p $CI_PROJECT logs -f"
echo "route CI to it with: gh variable set CI_RUNNER --body rutli-ci --repo $REPO"

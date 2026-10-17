#!/usr/bin/env bash
# Stop the isolated self-hosted CI runner started by scripts/ci-runner-up.sh.
#
#   scripts/ci-runner-down.sh              stop + remove the runner container (VM keeps running)
#   scripts/ci-runner-down.sh --delete-vm  also delete the Colima VM and everything in it
#
# Does not touch GitHub: unregister the runner afterwards (instructions printed at the end), and
# route CI back to GitHub-hosted runners with: gh variable delete CI_RUNNER --repo Stakecraft/rutli
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/ci-runner-lib.sh
source scripts/ci-runner-lib.sh

DELETE_VM=0
case "${1:-}" in
  "") ;;
  --delete-vm) DELETE_VM=1 ;;
  *) die "usage: $0 [--delete-vm]" ;;
esac
REPO="${RUNNER_REPO:-Stakecraft/rutli}"
RUNNER_NAME="${RUNNER_NAME:-rutli-ci-isolated}"

for tool in colima docker; do command -v "$tool" >/dev/null || die "$tool not found"; done
remember_context
trap restore_context EXIT

if [[ "$(vm_state)" == Running ]]; then
  verify_context
  # compose needs RUNNER_WORKDIR only for variable interpolation here.
  RUNNER_WORKDIR="$CI_WORKDIR_DEFAULT" docker --context "$CI_CONTEXT" compose \
    -f deploy/ci-runner/docker-compose.yml -p "$CI_PROJECT" down
else
  echo "VM '$CI_PROFILE' is not running; no runner container to stop"
fi

if [[ $DELETE_VM -eq 1 ]]; then
  if [[ "$(vm_state)" != MISSING ]]; then
    echo "deleting VM '$CI_PROFILE' (all images, caches and job work dirs in it are lost)"
    colima delete --force --profile "$CI_PROFILE"
  fi
else
  echo "VM '$CI_PROFILE' left in place; stop it with: colima stop -p $CI_PROFILE   (or rerun with --delete-vm)"
fi

cat <<MSG

Unregister the runner on GitHub (needs admin on $REPO):
  id=\$(GH_PAGER=cat gh api repos/$REPO/actions/runners -q '.runners[] | select(.name=="$RUNNER_NAME") | .id')
  GH_PAGER=cat gh api -X DELETE repos/$REPO/actions/runners/\$id
Route CI back to GitHub-hosted runners:
  gh variable delete CI_RUNNER --repo $REPO
MSG

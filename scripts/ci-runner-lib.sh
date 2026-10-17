# Shared helpers for ci-runner-up.sh / ci-runner-down.sh. Source it; do not execute it.
# See deploy/ci-runner/README.md for the trust model: the runner must only ever talk to the
# docker daemon of the dedicated, host-mount-free Colima VM — never to Docker Desktop's.

CI_PROFILE="${RUTLI_CI_PROFILE:-rutli-ci}"
CI_CPU="${RUTLI_CI_CPU:-4}"
CI_MEMORY="${RUTLI_CI_MEMORY:-8}"
CI_DISK="${RUTLI_CI_DISK:-60}"
CI_EMPTY_DIR="${RUTLI_CI_EMPTY_DIR:-$HOME/.rutli-ci-empty}"
CI_CONTEXT="colima-${CI_PROFILE}"
CI_PROJECT="${RUTLI_CI_PROJECT:-rutli-ci-isolated}"
CI_WORKDIR_DEFAULT="/var/lib/rutli-ci/work"   # a path INSIDE the VM

export GH_PAGER=cat
# A stray DOCKER_HOST / DOCKER_CONTEXT would silently redirect docker to another daemon.
unset DOCKER_HOST DOCKER_CONTEXT

die() { echo "error: $*" >&2; exit 1; }

# Docker's *current* context is global state that `colima start|delete` flips. Remember it and put
# it back on exit so Docker Desktop stays the operator's default.
PREV_CONTEXT=""
remember_context() { PREV_CONTEXT="$(docker context show 2>/dev/null || true)"; }
restore_context() {
  if [[ -n "$PREV_CONTEXT" && "$PREV_CONTEXT" != "$CI_CONTEXT" ]]; then
    docker context use "$PREV_CONTEXT" >/dev/null 2>&1 \
      || echo "warning: could not restore docker context '$PREV_CONTEXT'" >&2
  elif [[ "$PREV_CONTEXT" == "$CI_CONTEXT" ]]; then
    echo "warning: your docker context was already '$CI_CONTEXT' before this script ran;" \
      "switch with 'docker context use <name>'" >&2
  fi
}

# Prints the VM's state: Running, Stopped, or MISSING.
vm_state() {
  local line
  line="$(colima list --json 2>/dev/null | grep -E "\"name\": *\"${CI_PROFILE}\"" || true)"
  if [[ -z "$line" ]]; then echo MISSING; return; fi
  if grep -qE '"status": *"Running"' <<<"$line"; then echo Running; else echo Stopped; fi
}

# Refuse to continue unless the only host mount in the VM is the empty dir, read-only.
verify_vm_mounts() {
  local mounts line mp opts n=0
  mounts="$(colima ssh -p "$CI_PROFILE" -- mount)" || die "cannot inspect mounts of VM '$CI_PROFILE'"
  # Host-backed filesystems: virtiofs (vz), 9p / sshfs (qemu). Everything else is the VM's own.
  while IFS= read -r line; do
    [[ "$line" =~ type\ (virtiofs|9p|fuse\.sshfs|sshfs)\  ]] || continue
    mp="${line#* on }"; mp="${mp%% type *}"
    opts="${line##*\(}"; opts="${opts%\)*}"
    n=$((n + 1))
    [[ "$mp" == "$CI_EMPTY_DIR" ]] \
      || die "VM '$CI_PROFILE' mounts host path '$mp' — refusing. Delete the VM (scripts/ci-runner-down.sh --delete-vm) and re-run."
    [[ ",$opts," == *,ro,* ]] \
      || die "VM '$CI_PROFILE' mounts '$mp' read-write ($opts) — refusing."
  done <<<"$mounts"
  [[ $n -ge 1 ]] || die "expected the read-only mount of $CI_EMPTY_DIR in VM '$CI_PROFILE', found none — refusing."
}

# The docker context must point at this profile's own socket, never at Docker Desktop's.
verify_context() {
  local host
  host="$(docker context inspect "$CI_CONTEXT" --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" \
    || die "docker context '$CI_CONTEXT' does not exist (is the Colima profile '$CI_PROFILE' running?)"
  [[ "$host" == *".colima/${CI_PROFILE}/docker.sock" ]] \
    || die "docker context '$CI_CONTEXT' points at '$host', not the Colima profile's socket — refusing."
}

# Shared helpers for ci-runner-up.sh / ci-runner-down.sh. Source it; do not execute it.
# See deploy/ci-runner/README.md for the trust model: the runner must only ever talk to the
# docker daemon of the dedicated, host-mount-free Colima VM — never to Docker Desktop's.

CI_PROFILE="${RUTLI_CI_PROFILE:-rutli-ci}"
CI_CPU="${RUTLI_CI_CPU:-4}"
CI_MEMORY="${RUTLI_CI_MEMORY:-8}"
CI_DISK="${RUTLI_CI_DISK:-60}"
# Rosetta (Apple's amd64 translation) for the VM. QEMU user emulation segfaults the amd64 Rust link
# step of the release image build, so image builds need Rosetta. Set RUTLI_CI_ROSETTA=0 to opt out
# (arm64-only CI jobs work without it).
CI_ROSETTA="${RUTLI_CI_ROSETTA:-1}"
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
    # Rosetta's own share (Apple's translator binary, no host files) is not a host mount.
    # Rosetta share (colima --vz-rosetta): source "vz-rosetta" (colima 0.10) or "rosetta" (lima), fixed mountpoint.
    [[ ( "${line%% on *}" == vz-rosetta || "${line%% on *}" == rosetta ) && "$mp" == /mnt/lima-rosetta ]] && continue
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

# True when the VM has Rosetta registered as a binfmt handler for amd64 binaries.
# Capture-then-grep: `ls | grep -q` under pipefail fails falsely (grep -q exits early, ls gets SIGPIPE).
vm_has_rosetta() {
  local handlers
  handlers="$(colima ssh -p "$CI_PROFILE" -- ls /proc/sys/fs/binfmt_misc/ 2>/dev/null)" || return 1
  grep -qx rosetta <<<"$handlers"
}

# Refuse to continue without Rosetta (unless opted out); print the exact fix for an existing VM.
verify_rosetta() {
  if [[ "$CI_ROSETTA" == 0 ]]; then
    echo "warning: Rosetta check skipped (RUTLI_CI_ROSETTA=0); amd64 image builds will use QEMU and may segfault" >&2
    return 0
  fi
  vm_has_rosetta && return 0
  cat >&2 <<MSG
error: VM '$CI_PROFILE' has no Rosetta handler in binfmt_misc. The release image build
(linux/amd64 + linux/arm64) segfaults at the amd64 link step under QEMU emulation.
Enable Rosetta on the existing VM (keeps its disk and its read-only empty-dir mount):

  scripts/ci-runner-down.sh                  # optional: remove the runner container first
  colima stop -p $CI_PROFILE
  colima start -p $CI_PROFILE --vz-rosetta   # persists 'rosetta: true' in ~/.colima/$CI_PROFILE/colima.yaml

then re-run scripts/ci-runner-up.sh. If that does not take effect, delete and recreate the VM
(scripts/ci-runner-down.sh --delete-vm), which now creates it with --vz-rosetta.
Needs macOS 13+ on Apple silicon. To skip this check: RUTLI_CI_ROSETTA=0.
MSG
  exit 1
}

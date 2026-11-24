# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# The "k8s" environment of scripts/e2e-migration.sh: a Rütli cluster on Kubernetes, as the cluster
# suite installs it (scripts/perf/k8s-deploy.sh), reached with kubectl. Sourced by that script
# (E2E_ENV=k8s), never run on its own. Only E2E_STAGES=ceremony runs here: there is no Canton.
#
# Every cosigner command runs inside the live cosigner pod (`kubectl exec … -c cosigner`), as
# docs/split-ceremony.md §4 does: no Job, no second mount of a cosigner volume. The operator's and
# the refresher's commands (verify-key, refresh) run in the load generator pod, which holds their
# certificates. The dealer runs in a pod of its own (`rutli-perf-dealer`): no service account
# token, no network at all (a NetworkPolicy denies every connection), its work directory in
# memory; files reach it and leave it only through this machine, and Step 8 deletes it.
#
# Environment:
#   RUTLI_NAMESPACE     the cluster's namespace (required)
#   E2E_CERTS           the installation's certificate directory (k8s-deploy.sh --work DIR: DIR/certs);
#                       the dealer needs its ca.crt
#   E2E_DEALER_IMAGE    the dealer's image: one with rutli-dealer of the cosigners' release
#                       (frost/Dockerfile.perf, or frost/Dockerfile.dealer for an earlier tag)
#   E2E_LOADGEN_POD     the load generator pod (default rutli-perf-loadgen)

NS="${RUTLI_NAMESPACE:?RUTLI_NAMESPACE is required for E2E_ENV=k8s}"
LOADGEN_POD="${E2E_LOADGEN_POD:-rutli-perf-loadgen}"
DEALER_POD=rutli-perf-dealer

_k() { kubectl -n "$NS" "$@"; }
_pod() { printf 'rutli-cosigner-n%s-0' "$1"; }
_in_node() {
  local n=$1
  shift
  _k exec "$(_pod "$n")" -c cosigner -- "$@"
}

env_init() {
  [ "${E2E_STAGES:-all}" = ceremony ] || fail "E2E_ENV=k8s runs only E2E_STAGES=ceremony: there is no Canton on the cluster"
  [ -n "${E2E_DEALER_IMAGE:-}" ] || fail "E2E_DEALER_IMAGE is required for E2E_ENV=k8s"
  [ -f "${E2E_CERTS:-}/ca.crt" ] || fail "E2E_CERTS must name the installation's certificate directory (no ca.crt in '${E2E_CERTS:-}')"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/rutli-e2e-migration-k8s.XXXXXX")"
  SYNC="$WORK/sync"
  mkdir -p "$SYNC" "$WORK/certs"
  cp "$E2E_CERTS/ca.crt" "$WORK/certs/ca.crt"
  # shellcheck disable=SC2034  # the procedure runs "$DEALER" split-key …
  DEALER=_dealer_in_pod
  DEALER_STARTED=0
  # A dealer pod left by an interrupted run (and whatever its memory held) goes before anything else.
  _k delete pod "$DEALER_POD" --wait=true --ignore-not-found >/dev/null
  _k delete networkpolicy "$DEALER_POD" --ignore-not-found >/dev/null

  step "Cluster in namespace $NS: every cosigner healthy, the load generator ready"
  local i role
  for i in 1 2 3; do
    _in_node "$i" rutli-cosigner --config "/config/cosigner-$i.json" health >/dev/null \
      || fail "cosigner $i in $NS is not healthy"
  done
  # The operator's and the refresher's client configs: node 1's config with that role's
  # certificate (the load generator pod mounts them at /certs) and the lab profile, as a client
  # config is not a node's.
  _in_node 1 cat /config/cosigner-1.json >"$WORK/node1.json"
  for role in operator refresher; do
    jq --arg role "$role" '.tls.cert = "/certs/\($role).crt" | .tls.key = "/certs/\($role).key"
      | .tls.ca_cert = "/certs/ca.crt" | .profile = "lab"' "$WORK/node1.json" \
      | _k exec -i "$LOADGEN_POD" -- sh -c "umask 077; cat > /tmp/e2e-$role.json"
  done
}

env_cosigner() {
  local n=$1
  shift
  _in_node "$n" env RUST_LOG=off rutli-cosigner --config "/config/cosigner-$n.json" "$@"
}
env_client() {
  local role=$1
  shift
  _k exec "$LOADGEN_POD" -- env RUST_LOG=off rutli-cosigner --config "/tmp/e2e-$role.json" "$@"
}
env_node_out() { printf '/tmp/%s\n' "$2"; }
env_fetch() { _in_node "$1" cat "$2" >"$3"; }
env_push() { # node  local-file: copied to the pod's /tmp (memory-backed); prints the path there
  local dest
  dest="/tmp/$(basename "$2")"
  _k exec -i "$(_pod "$1")" -c cosigner -- sh -c "umask 077; cat > '$dest'" <"$2"
  printf '%s\n' "$dest"
}
env_node_path() { printf '/data/%s\n' "$2"; }
env_node_exists() { _in_node "$1" test -e "$2"; }
env_node_cat() {
  local n=$1
  shift
  _in_node "$n" sh -c "cat $* 2>/dev/null || true"
} # globs expand in the pod
env_node_ls() { _in_node "$1" ls "$2"; }
env_node_shred() {
  local n=$1
  shift
  _in_node "$n" rm -f -- "$@"
} # memory-backed /tmp: gone with the pages

# --- the dealer pod -----------------------------------------------------------------------------
DEALER_STARTED=0
DEALER_ISOLATED=unknown
_dealer_up() {
  [ "$DEALER_STARTED" = 1 ] && return 0
  _k apply -f - >/dev/null <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: $DEALER_POD
  labels: { rutli-perf/suite: "1" }
spec:
  podSelector: { matchLabels: { app: $DEALER_POD } }
  policyTypes: [Ingress, Egress]
---
apiVersion: v1
kind: Pod
metadata:
  name: $DEALER_POD
  labels: { app: $DEALER_POD, rutli-perf/suite: "1" }
spec:
  automountServiceAccountToken: false
  enableServiceLinks: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: dealer
      image: $E2E_DEALER_IMAGE
      imagePullPolicy: IfNotPresent
      command: ["sleep", "infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
      resources:
        requests: { cpu: 10m, memory: 32Mi }
        limits: { cpu: 500m, memory: 128Mi }
      volumeMounts:
        - { name: work, mountPath: /work }
  volumes:
    - name: work
      emptyDir: { medium: Memory, sizeLimit: 16Mi }
YAML
  _k wait --for=condition=Ready "pod/$DEALER_POD" --timeout=300s >/dev/null || fail "the dealer pod did not start"
  DEALER_STARTED=1
  # Does the NetworkPolicy hold? Only a network plugin that enforces policies makes it so (kind's
  # default one does not). Before anything is copied in, try to reach cosigner 1 from the pod.
  # E2E_REQUIRE_DEALER_ISOLATION=1 makes a reachable network a failure; otherwise it is reported.
  if _k exec "$DEALER_POD" -- bash -c "timeout 3 bash -c '</dev/tcp/rutli-node-1.$NS.svc/9101'" >/dev/null 2>&1; then
    DEALER_ISOLATED=false
    [ "${E2E_REQUIRE_DEALER_ISOLATION:-0}" = 1 ] && fail "the dealer pod reaches the network: its NetworkPolicy is not enforced here"
    echo "WARNING: the dealer pod reaches the network: this cluster's network plugin does not enforce its NetworkPolicy"
  else
    DEALER_ISOLATED=true
    echo "the dealer pod reaches no cosigner: its NetworkPolicy holds"
  fi
  export DEALER_ISOLATED
}

# `rutli-dealer` in the dealer pod, with the procedure's local paths: --in, --ca-cert and every
# --recipient are copied in, --out-dir is copied back (only if the dealer wrote it), and
# --password-env NAME passes that variable's value into the dealer's environment for this call only,
# through stdin: never in a command line (the process table, an audit log of `kubectl exec`).
_dealer_in_pod() {
  _dealer_up
  local args=() pw_name="" out="" remote_out="" flag val
  _k exec "$DEALER_POD" -- sh -c 'mkdir -p /work/in && chmod 700 /work/in'
  while [ $# -gt 0 ]; do
    flag=$1
    case "$flag" in
      --in | --ca-cert | --recipient)
        val="/work/in/$(basename "$2")"
        _k exec -i "$DEALER_POD" -- sh -c "umask 077; cat > '$val'" <"$2"
        args+=("$flag" "$val")
        shift 2
        ;;
      --out-dir)
        out=$2
        remote_out="/work/$(basename "$2")"
        args+=("$flag" "$remote_out")
        shift 2
        ;;
      --password-env)
        pw_name=$2
        args+=("$flag" "$2")
        shift 2
        ;;
      *)
        args+=("$flag")
        shift
        ;;
    esac
  done
  local rc=0
  if [ -n "$pw_name" ]; then
    # shellcheck disable=SC2016  # expanded by the pod's shell
    printf '%s\n' "${!pw_name:-}" | _k exec -i "$DEALER_POD" -- \
      sh -c 'IFS= read -r v; export "$1=$v"; shift; exec rutli-dealer "$@"' sh "$pw_name" "${args[@]}" || rc=$?
  else
    _k exec "$DEALER_POD" -- rutli-dealer "${args[@]}" </dev/null || rc=$?
  fi
  if [ -n "$remote_out" ] && _k exec "$DEALER_POD" -- test -d "$remote_out"; then
    (umask 077 && mkdir -p "$out")
    local f
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      (umask 077 && _k exec "$DEALER_POD" -- cat "$remote_out/$f" >"$out/$f")
    done < <(_k exec "$DEALER_POD" -- ls -1 "$remote_out")
  fi
  return "$rc"
}

env_destroy_dealer() { # Step 8: the dealer's "host" and its memory-backed work dir go with the pod
  _k delete pod "$DEALER_POD" --wait=true --ignore-not-found >/dev/null
  _k delete networkpolicy "$DEALER_POD" --ignore-not-found >/dev/null
  ! _k get pod "$DEALER_POD" >/dev/null 2>&1 || fail "the dealer pod is still there"
}

# --- no Canton on the cluster ----------------------------------------------------------------------
_no_canton() { fail "Canton is not driven on the cluster (E2E_ENV=k8s runs E2E_STAGES=ceremony only)"; }
env_canton_conf() { _no_canton; }
env_canton_start() { _no_canton; }
env_canton_alive() { return 1; }
env_canton_wait() { _no_canton; }
env_canton_out() { :; }
env_canton_logs() { :; }
env_driver_audit() { _no_canton; }
env_old_db_exists() { _no_canton; }
env_destroy_old_db() { _no_canton; }

env_cleanup() {
  local rc=$1 i
  _k delete pod "$DEALER_POD" --wait=false --ignore-not-found >/dev/null 2>&1 || true
  _k delete networkpolicy "$DEALER_POD" --ignore-not-found >/dev/null 2>&1 || true
  # Ceremony files in the pods' memory-backed /tmp: requests, bundles, the client configs. The
  # founding backups stay until the pods restart (they are what Step 8 keeps).
  for i in 1 2 3; do
    # shellcheck disable=SC2016  # expanded by the pod's shell
    _in_node "$i" sh -c 'for f in /tmp/r[0-9].json /tmp/share-*.json; do [ -e "$f" ] && rm -f "$f"; done; true' >/dev/null 2>&1 || true
  done
  _k exec "$LOADGEN_POD" -- sh -c 'rm -f /tmp/e2e-operator.json /tmp/e2e-refresher.json' >/dev/null 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    for i in 1 2 3; do
      echo "--- cosigner $i log (tail) ---"
      _k logs "$(_pod "$i")" -c cosigner --tail=30 2>/dev/null || true
    done
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "work dir kept: $WORK"; else shred_local "$WORK"; fi
}

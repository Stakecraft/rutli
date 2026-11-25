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
# certificates. The dealer runs in a pod of its own (`rutli-perf-dealer-…`): no service account
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
#   E2E_ALLOW_UNISOLATED_DEALER=1  go on when the dealer pod reaches the network (its NetworkPolicy
#                       not enforced: kind's default network plugin); otherwise that is a failure

NS="${RUTLI_NAMESPACE:?RUTLI_NAMESPACE is required for E2E_ENV=k8s}"
LOADGEN_POD="${E2E_LOADGEN_POD:-rutli-perf-loadgen}"
DEALER_POD=rutli-perf-dealer # one suite run per namespace
CLEANUP_FAILED=""

_k() { kubectl -n "$NS" "$@"; }
_kq() { kubectl -n "$NS" --request-timeout=30s "$@"; } # bounded: cleanup paths, which must end
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
  # A dealer pod left by a run that was killed outright (and whatever its memory held) goes first.
  _kq delete pod "$DEALER_POD" --wait=true --timeout=120s --ignore-not-found >/dev/null
  _kq delete networkpolicy "$DEALER_POD" --ignore-not-found >/dev/null

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
  # Request files, bundles and founding backups go to each cosigner pod's /tmp, the client configs to
  # the load generator's: both must be memory-backed (the chart's and loadgen.yaml's emptyDir with
  # medium Memory), so that nothing of the ceremony reaches a node's disk.
  for i in 1 2 3; do
    _in_node "$i" grep -q ' /tmp tmpfs ' /proc/mounts || fail "cosigner $i's /tmp is not memory-backed"
  done
  _k exec "$LOADGEN_POD" -- grep -q ' /tmp tmpfs ' /proc/mounts || fail "the load generator's /tmp is not memory-backed"
  # shellcheck disable=SC2016  # expanded by the pod's shell (the cat below)
  for role in operator refresher; do
    jq --arg role "$role" '.tls.cert = "/certs/\($role).crt" | .tls.key = "/certs/\($role).key"
      | .tls.ca_cert = "/certs/ca.crt" | .profile = "lab"' "$WORK/node1.json" \
      | _k exec -i "$LOADGEN_POD" -- sh -c 'umask 077; cat > "$1"' sh "/tmp/e2e-$role.json"
  done

  # The dealer pod, started and its isolation checked here, before anything of the key reaches it
  # (and outside the procedure's `refused` checks, which would swallow a failure's message).
  step "The dealer pod: started, its network isolation checked"
  _dealer_up
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
  # shellcheck disable=SC2016  # expanded by the pod's shell
  _k exec -i "$(_pod "$1")" -c cosigner -- sh -c 'umask 077; cat > "$1"' sh "$dest" <"$2"
  printf '%s\n' "$dest"
}
env_node_path() { printf '/data/%s\n' "$2"; }
# 0: there, 1: not there. Anything else (kubectl exec failed) stops the run: a check that could
# not look must never pass as "absent".
env_node_exists() {
  local rc=0
  # shellcheck disable=SC2016  # expanded by the pod's shell
  _in_node "$1" sh -c 'if [ -e "$1" ]; then exit 10; else exit 11; fi' sh "$2" || rc=$?
  case "$rc" in
    10) return 0 ;;
    11) return 1 ;;
    *) fail "could not check $2 on node $1 (exit $rc)" ;;
  esac
}
env_node_cat() {
  local n=$1
  shift
  # shellcheck disable=SC2016  # expanded by the pod's shell; each argument may be a glob
  _in_node "$n" sh -c 'for p in "$@"; do for f in $p; do cat "$f" 2>/dev/null; done; done; true' sh "$@"
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
  activeDeadlineSeconds: 1800
  terminationGracePeriodSeconds: 1
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    fsGroup: 10001
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
  # default one does not). Before anything is copied in, the pod opens a TCP connection to cosigner
  # 1's pod IP (no DNS involved) on its gRPC port. Only a timeout (exit 124) counts as isolated: a
  # connection, or a refusal, means packets got through, and a probe that could not run at all is a
  # failure, never a pass. A reachable network fails unless E2E_ALLOW_UNISOLATED_DEALER=1 (a
  # throwaway cluster whose network plugin enforces no policies, with the public test key only).
  # Policies add up, so another one in the namespace could open some destinations and not others:
  # targets of different kinds, so that one with a policy of its own cannot pass for isolation.
  # Cosigner 1's pod (gRPC), the Kubernetes API service, the pod's own nameserver (TCP) and an
  # address outside the cluster; then a DNS lookup through the pod's resolver (UDP first). Not the
  # pod's own node: network plugins may exempt it from policies, and a conforming cluster would fail.
  # The external address is IPv4: on an IPv6-only cluster it cannot be reached either way. Inside the pod a connection exits 10, a
  # refusal 11, a timeout 124; any other exit is kubectl's or a missing tool's, and stops the run.
  local ip api ns target rc reachable=""
  ip="$(_k get pod "$(_pod 1)" -o jsonpath='{.status.podIP}')"
  api="$(kubectl -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')"
  ns="$(_k exec "$DEALER_POD" -- sed -n 's/^nameserver[[:space:]]*//p' /etc/resolv.conf | head -n 1)"
  [[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]] || fail "no pod IP for cosigner 1 to probe the dealer's isolation with"
  [[ "$api" =~ ^[0-9a-fA-F.:]+$ ]] || fail "no API service IP to probe the dealer's isolation with"
  [[ "$ns" =~ ^[0-9a-fA-F.:]+$ ]] || fail "no nameserver in the dealer pod's resolv.conf to probe its isolation with"
  for target in "$ip/9101" "$api/443" "$ns/53" 1.1.1.1/443; do
    rc=0
    # shellcheck disable=SC2016  # expanded by the pod's shell
    _k exec "$DEALER_POD" -- bash -c \
      'timeout 5 bash -c "exec 3<>/dev/tcp/$1"; r=$?; case $r in 0) exit 10 ;; 124) exit 124 ;; 126 | 127) exit $r ;; *) exit 11 ;; esac' \
      sh "$target" 2>&1 || rc=$?
    case "$rc" in
      124) ;;
      10 | 11) reachable="$reachable $target" ;;
      *) fail "the dealer pod's isolation could not be checked (probe of $target exited $rc: kubectl exec failed, or no bash or timeout in $E2E_DEALER_IMAGE)" ;;
    esac
  done
  # A name every cluster resolves through the pod's search path: an answer means DNS got through.
  # No answer (2) or a timeout (124) is isolated; a missing getent (127) or a failed exec stops.
  rc=0
  _k exec "$DEALER_POD" -- timeout 15 getent hosts kubernetes.default >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0) reachable="$reachable DNS" ;;
    2 | 124) ;;
    *) fail "the dealer pod's DNS isolation could not be checked (getent exited $rc)" ;;
  esac
  if [ -z "$reachable" ]; then
    DEALER_ISOLATED=true
    echo "the dealer pod reaches neither cosigner 1, the API service, its nameserver nor 1.1.1.1, and resolves no name: its NetworkPolicy holds"
  else
    DEALER_ISOLATED=false
    [ "${E2E_ALLOW_UNISOLATED_DEALER:-0}" = 1 ] || fail "the dealer pod reaches$reachable: its NetworkPolicy is not enforced here"
    echo "WARNING: the dealer pod reaches$reachable: this cluster's network plugin does not enforce its NetworkPolicy"
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
        # shellcheck disable=SC2016  # expanded by the pod's shell
        _k exec -i "$DEALER_POD" -- sh -c 'umask 077; cat > "$1"' sh "$val" <"$2"
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

# Delete the dealer pod and wait; its deny-all NetworkPolicy goes only once the pod is gone, never
# while it might still hold key material. Returns 1 if the pod may still be there, 2 if only the
# NetworkPolicy could not be deleted; the caller decides what that means (Step 8 or the cleanup).
_dealer_down() {
  _kq delete pod "$DEALER_POD" --wait=true --timeout=120s --ignore-not-found >/dev/null 2>&1 || true
  # Gone only when the API says so: an error of `get` keeps the policy.
  local left
  left="$(_kq get pod "$DEALER_POD" --ignore-not-found -o name 2>/dev/null)" || return 1
  [ -z "$left" ] || return 1
  _kq delete networkpolicy "$DEALER_POD" --ignore-not-found >/dev/null 2>&1 || return 2
}

env_destroy_dealer() { # Step 8: the dealer's "host" and its memory-backed work dir go with the pod
  local rc=0
  _dealer_down || rc=$?
  case "$rc" in
    0) ;;
    2) echo "WARNING: the dealer's NetworkPolicy could not be deleted yet; the cleanup tries again" >&2 ;;
    *) fail "the dealer pod is still there" ;;
  esac
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
  # The local work dir (the export, the dealer's output) first: nothing below needs it, and a cluster
  # call that hangs must not keep it on disk.
  if [ -n "${WORK:-}" ]; then
    # Guarded: under set -e a failed removal here would end the trap before the cluster's cleanup.
    if [ "${KEEP:-0}" = 1 ]; then
      echo "work dir kept: $WORK"
    elif ! shred_local "$WORK"; then
      echo "WARNING: the local work dir $WORK could not be removed" >&2
      CLEANUP_FAILED="$CLEANUP_FAILED local-work-dir"
    fi
  fi
  local down=0
  _dealer_down || down=$?
  case "$down" in
    0) ;;
    2)
      echo "WARNING: the dealer's NetworkPolicy $DEALER_POD could not be deleted" >&2
      CLEANUP_FAILED="$CLEANUP_FAILED dealer-networkpolicy"
      ;;
    *)
      echo "WARNING: the dealer pod $DEALER_POD is still there (its NetworkPolicy kept); delete it by hand" >&2
      CLEANUP_FAILED="$CLEANUP_FAILED dealer-pod"
      ;;
  esac
  # A ceremony that failed before every node installed its share leaves a sealed one-time recipient
  # secret on those nodes: abort-import removes it (never an installed share without its flag).
  if [ "$rc" -ne 0 ] && [ -n "${KEY_ID:-}" ] && [ -n "${CEREMONY:-}" ]; then
    for i in 1 2 3; do
      _kq exec "$(_pod "$i")" -c cosigner -- env RUST_LOG=off rutli-cosigner --config "/config/cosigner-$i.json" \
        abort-import --key-id "$KEY_ID" --ceremony-id "$CEREMONY" >/dev/null 2>&1 \
        || echo "WARNING: abort-import on cosigner $i did not answer: its sealed recipient secret may remain" >&2
    done
    # abort-import never removes an installed share: a node that installed before the failure keeps
    # one of the test key $KEY_ID (a key id unique to this run).
    echo "NOTE: a node that installed its share before the failure keeps it, under $KEY_ID" >&2
  fi
  # Ceremony files in the pods' memory-backed /tmp: requests, bundles, the founding backups (Step 8
  # checked them; the suite keeps no copy), the client configs.
  for i in 1 2 3; do
    # shellcheck disable=SC2016  # expanded by the pod's shell
    _kq exec "$(_pod "$i")" -c cosigner -- sh -c 'rm -rf /tmp/r[0-9].json /tmp/share-*.json /tmp/backup-founding-node*' \
      >/dev/null 2>&1 || CLEANUP_FAILED="$CLEANUP_FAILED cosigner-$i:/tmp"
  done
  _kq exec "$LOADGEN_POD" -- sh -c 'rm -f /tmp/e2e-operator.json /tmp/e2e-refresher.json' >/dev/null 2>&1 \
    || CLEANUP_FAILED="$CLEANUP_FAILED loadgen:/tmp"
  [ -z "$CLEANUP_FAILED" ] || echo "WARNING: the cleanup could not remove:$CLEANUP_FAILED" >&2
  if [ "$rc" -ne 0 ]; then
    for i in 1 2 3; do
      echo "--- cosigner $i log (tail) ---"
      _kq logs "$(_pod "$i")" -c cosigner --tail=30 2>/dev/null || true
    done
  fi
}

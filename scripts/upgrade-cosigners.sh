#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Roll the per-node cosigner pods onto the pod template of the current Helm release, ONE AT A TIME.
#
# The chart's per-node StatefulSets use updateStrategy OnDelete: `helm upgrade` changes the three
# StatefulSets in one apply and restarts no pod. With RollingUpdate it would restart all three
# single-replica pods at once, and with threshold 2 of 3 nothing could sign until two were back
# (measured: about 11 s without a cosigner). This script is the order Helm cannot give: it deletes
# one pod, waits for the replacement (on the target revision) to be Ready, waits --settle seconds,
# checks that all three are Ready again, and only then takes the next one.
#
#   scripts/upgrade-cosigners.sh [-n NS] [--release NAME] [--status | --dry-run]
#                                [--only NODE] [--allow-degraded] [--settle SEC] [--timeout SEC]
#
#   --status          per node: running revision, target revision, running image, target image, Ready.
#                     Exit 0 when every node runs the target revision and is Ready, 3 when a roll is
#                     pending, 1 when a node is not Ready.
#   --dry-run         print what would be rolled, in order; change nothing.
#   --only NODE       roll only that node id (1, 2, 3).
#   --force           restart the selected nodes even when they already run the target revision: for a
#                     change the pod template does not carry (a changed ConfigMap, pins, a rotated
#                     certificate). Not resumable by itself: after a stop, continue with --only.
#   --allow-degraded  an upgrade as the repair of ONE node that is not Ready: that node is rolled first,
#                     and the script still never takes a second node down. Without the flag the script
#                     refuses unless every node is Ready. With two nodes not Ready it always refuses:
#                     a third restart would leave no quorum.
#   --settle SEC      wait after each node is Ready before the next (default 120). Ready means the
#                     node's key store is usable and its gRPC port accepts connections (`rutli-cosigner
#                     health`); it does NOT prove the peer connections are back. Measured recovery of the
#                     mesh after a restart was under 2 s, so 120 s is a wide margin on 0.5; use 300 on
#                     0.4.x, where a freshly restarted cosigner can drop one sign session (fixed in 0.5).
#   --timeout SEC     give up on one node after this long (default 600); nothing further is touched.
#
# Resumable: a node whose pod already runs the target revision and is Ready is skipped, so a run that
# stopped at node 2 is started again with the same command. Needs kubectl and jq. KUBECTL=… overrides
# the kubectl binary (the test uses it).
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
NS="rutli"
RELEASE=""
MODE=roll
ONLY=""
DEGRADED=0
FORCE=0
SETTLE=120
TIMEOUT=600
POLL="${UPGRADE_POLL_SECONDS:-3}"

die() { echo "error: $*" >&2; exit 1; }
log() { echo "[$(date -u +%H:%M:%S)] $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -n | --namespace) NS="${2:?}"; shift 2 ;;
    --release) RELEASE="${2:?}"; shift 2 ;;
    --status) MODE=status; shift ;;
    --dry-run) MODE=dry; shift ;;
    --only) ONLY="${2:?}"; shift 2 ;;
    --allow-degraded) DEGRADED=1; shift ;;
    --force) FORCE=1; shift ;;
    --settle) SETTLE="${2:?}"; shift 2 ;;
    --timeout) TIMEOUT="${2:?}"; shift 2 ;;
    -h | --help) sed -n '5,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done
[[ "$SETTLE" =~ ^[0-9]+$ ]] || die "--settle needs a number of seconds"
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout needs a number of seconds"
[ -z "$ONLY" ] || [[ "$ONLY" =~ ^[0-9]+$ ]] || die "--only needs a node id"
command -v jq >/dev/null || die "jq is required"
command -v "$KUBECTL" >/dev/null || die "$KUBECTL is required"

k() { "$KUBECTL" -n "$NS" "$@"; }

SEL="app.kubernetes.io/part-of=rutli,rutli.io/node"
[ -z "$RELEASE" ] || SEL="app.kubernetes.io/instance=$RELEASE,$SEL"

# One line per node, ordered by id, fields joined by "|": id, statefulset, updateStrategy, target revision,
# "controller has observed the latest spec", target image.
sts_table() {
  k get sts -l "$SEL" -o json | jq -r '
    [.items[] | {id: (.metadata.labels["rutli.io/node"] | tonumber), name: .metadata.name,
                 strat: .spec.updateStrategy.type, rev: (.status.updateRevision // ""),
                 seen: ((.status.observedGeneration // 0) == .metadata.generation),
                 image: ([.spec.template.spec.containers[] | select(.name == "cosigner") | .image][0] // "")}]
    | sort_by(.id)[] | [.id, .name, .strat, .rev, .seen, .image] | map(tostring) | join("|")'
}

# For one pod ("|"-joined): uid, revision, ready, running image. Empty when the pod does not exist.
pod_row() {
  local json
  json="$(k get pod "$1-0" -o json --ignore-not-found)" || return 0
  [ -n "$json" ] || return 0
  jq -r '[.metadata.uid, (.metadata.labels["controller-revision-hash"] // ""),
          (([.status.conditions[]? | select(.type == "Ready") | .status == "True"][0]) // false),
          ([.spec.containers[] | select(.name == "cosigner") | .image][0] // "")] | map(tostring) | join("|")' <<<"$json"
}

IDS=(); NAMES=(); STRATS=(); REVS=(); IMAGES=()
load_nodes() {
  IDS=(); NAMES=(); STRATS=(); REVS=(); IMAGES=()
  local id name strat rev _seen image
  local table tries=0
  # Right after `helm upgrade` the StatefulSet controller may not have caught up: retry for ~30 s.
  while :; do
    table="$(sts_table)"
    if [ -n "$table" ] && ! grep -q '|false|' <<<"$table"; then break; fi
    tries=$((tries + 1))
    [ "$tries" -lt 15 ] || die "no cosigner StatefulSets in namespace $NS (selector: $SEL), or their controller has not observed the latest spec yet; run again in a few seconds"
    sleep 2
  done
  while IFS='|' read -r id name strat rev _seen image; do
    IDS+=("$id"); NAMES+=("$name"); STRATS+=("$strat"); REVS+=("$rev"); IMAGES+=("$image")
  done <<<"$table"
}

# State of node index $1: sets P_UID P_REV P_READY P_IMAGE.
read_pod() {
  P_UID=""; P_REV=""; P_READY=false; P_IMAGE=""
  local row
  row="$(pod_row "${NAMES[$1]}")"
  [ -z "$row" ] || IFS='|' read -r P_UID P_REV P_READY P_IMAGE <<<"$row"
}

is_current() { [ -n "$P_UID" ] && [ "$P_REV" = "${REVS[$1]}" ]; }

PENDING=0
NOTREADY=0
print_status() {
  printf '%-5s %-28s %-14s %-24s %-24s %s\n' NODE STATEFULSET STATE RUNNING-REVISION TARGET-REVISION "RUNNING-IMAGE -> TARGET-IMAGE"
  local i state
  PENDING=0; NOTREADY=0
  for i in "${!IDS[@]}"; do
    read_pod "$i"
    if [ -z "$P_UID" ]; then
      state=MISSING; NOTREADY=$((NOTREADY + 1)); PENDING=$((PENDING + 1))
    else
      if [ "$P_READY" = true ]; then state=Ready; else state=NOT-READY; NOTREADY=$((NOTREADY + 1)); fi
      is_current "$i" || { state="$state,OLD"; PENDING=$((PENDING + 1)); }
    fi
    printf '%-5s %-28s %-14s %-24s %-24s %s -> %s\n' "${IDS[$i]}" "${NAMES[$i]}" "$state" "${P_REV:--}" "${REVS[$i]}" "${P_IMAGE:--}" "${IMAGES[$i]}"
  done
}

load_nodes
for i in "${!IDS[@]}"; do
  [ "${STRATS[$i]}" = OnDelete ] || die "StatefulSet ${NAMES[$i]} has updateStrategy ${STRATS[$i]}, not OnDelete: Kubernetes rolls it itself, all nodes at once. Nothing for this script to do; set updateStrategy.type=OnDelete in the chart values."
done

if [ "$MODE" = status ]; then
  print_status
  [ "$NOTREADY" -eq 0 ] || exit 1
  [ "$PENDING" -eq 0 ] || exit 3
  exit 0
fi

index_of() { local i; for i in "${!IDS[@]}"; do if [ "${IDS[$i]}" = "$1" ]; then echo "$i"; return 0; fi; done; return 1; }

# Fail unless every node except index $1 (empty: none excepted) has a Ready pod.
require_others_ready() {
  local i
  for i in "${!IDS[@]}"; do
    [ "$i" != "${1:-}" ] || continue
    read_pod "$i"
    [ "$P_READY" = true ] || die "node ${IDS[$i]} (${NAMES[$i]}-0) is not Ready: refusing to take another cosigner down"
  done
}

# The plan: a not-Ready node first (only with --allow-degraded), then the nodes whose pod is not on the
# target revision, by id.
PLAN=()
NOTREADY_IDX=()
for i in "${!IDS[@]}"; do
  read_pod "$i"
  [ "$P_READY" = true ] || NOTREADY_IDX+=("$i")
done
BROKEN=""
if [ "${#NOTREADY_IDX[@]}" -gt 0 ]; then
  [ "$DEGRADED" = 1 ] || die "not every cosigner is Ready (node $(for i in "${NOTREADY_IDX[@]}"; do printf '%s ' "${IDS[$i]}"; done)): fix it first, or use --allow-degraded to roll the one broken node first"
  [ "${#NOTREADY_IDX[@]}" -eq 1 ] || die "more than one node is not Ready: a restart now would leave no quorum. Repair them by hand first"
  BROKEN="${NOTREADY_IDX[0]}"
  read_pod "$BROKEN"
  if is_current "$BROKEN"; then
    die "node ${IDS[$BROKEN]} already runs the target revision and is still not Ready: restarting it is a repair, not an upgrade step. Look at its logs"
  fi
  PLAN+=("$BROKEN")
fi
for i in "${!IDS[@]}"; do
  [ "$i" != "$BROKEN" ] || continue
  read_pod "$i"
  if [ "$FORCE" = 1 ] || ! is_current "$i"; then PLAN+=("$i"); fi
done
if [ -n "$ONLY" ]; then
  want="$(index_of "$ONLY")" || die "no node $ONLY"
  [ -z "$BROKEN" ] || [ "$BROKEN" = "$want" ] || die "--only $ONLY: node ${IDS[$BROKEN]} is not Ready; roll that one first"
  keep=()
  for i in ${PLAN[@]+"${PLAN[@]}"}; do [ "$i" != "$want" ] || keep+=("$i"); done
  PLAN=(${keep[@]+"${keep[@]}"})
fi

if [ "${#PLAN[@]}" -eq 0 ]; then
  log "nothing to do: every selected cosigner runs the target revision and is Ready"
  exit 0
fi
log "plan, one at a time: $(for i in "${PLAN[@]}"; do printf 'node %s (%s) ' "${IDS[$i]}" "${NAMES[$i]}"; done)"
[ "$MODE" != dry ] || exit 0

for i in "${PLAN[@]}"; do
  name="${NAMES[$i]}"
  require_others_ready "$i"
  read_pod "$i"
  old_uid="$P_UID"
  log "node ${IDS[$i]}: deleting ${name}-0 (target revision ${REVS[$i]})"
  k delete pod "${name}-0" --wait=false --ignore-not-found >/dev/null
  deadline=$((SECONDS + TIMEOUT))
  while :; do
    read_pod "$i"
    if [ -n "$P_UID" ] && [ "$P_UID" != "$old_uid" ] && is_current "$i" && [ "$P_READY" = true ]; then break; fi
    [ "$SECONDS" -lt "$deadline" ] || die "node ${IDS[$i]}: ${name}-0 was not Ready on revision ${REVS[$i]} after ${TIMEOUT}s; stopped, no other node was touched. Inspect: kubectl -n $NS describe pod ${name}-0"
    sleep "$POLL"
  done
  log "node ${IDS[$i]}: ${name}-0 is Ready on ${P_REV} (${P_IMAGE}); settling ${SETTLE}s"
  sleep "$SETTLE"
  require_others_ready ""
  log "node ${IDS[$i]}: done, all cosigners Ready"
done

load_nodes
print_status
if [ -z "$ONLY" ]; then
  [ "$PENDING" -eq 0 ] && [ "$NOTREADY" -eq 0 ] || die "not every node runs the target revision and is Ready"
fi
log "upgrade complete"

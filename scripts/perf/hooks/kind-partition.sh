#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# HOOK_PARTITION for a kind cluster (an example of the hook contract in scripts/perf/cluster.py):
# `start A B` drops all traffic between the cosigner pods on the two nodes, in both directions,
# with iptables rules in each node's container; `stop A B` removes them. Only those two pod
# addresses are matched, so DNS, the load generator and the API server stay reachable from both
# sides (kindnet routes pod addresses between nodes without rewriting them).
set -euo pipefail
action="${1:?start|stop}"
a="${2:?node A}"
b="${3:?node B}"
ns="${RUTLI_NAMESPACE:?RUTLI_NAMESPACE is not set}"
pod_ip() { # node -> the cosigner pod's address on it
  kubectl -n "$ns" get pods -l app.kubernetes.io/name=rutli-cosigner --field-selector "spec.nodeName=$1" \
    -o jsonpath='{.items[0].status.podIP}'
}
ia="$(pod_ip "$a")"
ib="$(pod_ip "$b")"
[ -n "$ia" ] && [ -n "$ib" ] || { echo "no cosigner pod address on $a or $b" >&2; exit 1; }
rules() { # node op
  for chain in FORWARD INPUT OUTPUT; do
    docker exec "$1" iptables "$2" "$chain" -s "$ia" -d "$ib" -m comment --comment rutli-perf-partition -j DROP
    docker exec "$1" iptables "$2" "$chain" -s "$ib" -d "$ia" -m comment --comment rutli-perf-partition -j DROP
  done
}
case "$action" in
  start) rules "$a" -I; rules "$b" -I ;;
  stop) rules "$a" -D 2>/dev/null || true; rules "$b" -D 2>/dev/null || true ;;
  *) echo "usage: $0 start|stop NODE_A NODE_B" >&2; exit 2 ;;
esac

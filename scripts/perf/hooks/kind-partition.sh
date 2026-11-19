#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
#
# HOOK_PARTITION for a kind cluster (an example of the hook contract in scripts/perf/cluster.py):
# `start A B` drops all pod traffic between the two nodes, in both directions, with iptables rules
# in each node's container; `stop A B` removes them. Pod traffic is matched by the nodes' pod
# address ranges (kindnet routes pod addresses between nodes without rewriting them).
set -euo pipefail
action="${1:?start|stop}"
a="${2:?node A}"
b="${3:?node B}"
cidr() { kubectl get node "$1" -o jsonpath='{.spec.podCIDR}'; }
ca="$(cidr "$a")"
cb="$(cidr "$b")"
[ -n "$ca" ] && [ -n "$cb" ] || { echo "no podCIDR on $a or $b" >&2; exit 1; }
rules() { # node other-range op
  for dir in -s -d; do
    for chain in FORWARD INPUT OUTPUT; do
      docker exec "$1" iptables "$3" "$chain" "$dir" "$2" -m comment --comment rutli-perf-partition -j DROP
    done
  done
}
case "$action" in
  start) rules "$a" "$cb" -I; rules "$b" "$ca" -I ;;
  stop) rules "$a" "$cb" -D 2>/dev/null || true; rules "$b" "$ca" -D 2>/dev/null || true ;;
  *) echo "usage: $0 start|stop NODE_A NODE_B" >&2; exit 2 ;;
esac

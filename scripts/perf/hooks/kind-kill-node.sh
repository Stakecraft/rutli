#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
#
# HOOK_KILL_NODE for a kind cluster (an example of the hook contract in scripts/perf/cluster.py):
# `start NODE` freezes every process of the node's container, as a machine that stops answering
# would; `stop NODE` lets them run again. Pausing keeps the container's address, which a restart
# of a kind node would not.
set -euo pipefail
action="${1:?start|stop}"
node="${2:?node name}"
case "$action" in
  start) docker pause "$node" >/dev/null ;;
  stop) docker unpause "$node" >/dev/null 2>&1 || true ;;
  *) echo "usage: $0 start|stop NODE" >&2; exit 2 ;;
esac

# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# Helpers shared by the scripts/quality/<area>.sh collectors. Sourced, not run.
#
# collect.sh sets, for every area script:
#   Q_ROOT  the tree being measured (a checkout of the repository)
#   Q_OUT   directory for the per-area result files
#   Q_WORK  scratch directory (deleted afterwards)
#   Q_HERE  this directory (scripts/quality of the collector, which may be newer than Q_ROOT)
#
# Each area writes $Q_OUT/<area>.json:
#   {"metrics": {key: number|null}, "notes": {key: why it is null}, "info": {key: text},
#    "skipped": {key: why it was not measured in this run}, "tools": {name: version}}
# null means the measurement failed (the ratchet fails on it); skipped means it was turned off
# for this run on purpose (coverage on pull requests, for example) and the ratchet ignores it.

: "${Q_ROOT:?}" "${Q_OUT:?}" "${Q_WORK:?}" "${Q_HERE:?}"

q_init() {
  Q_AREA="$1"
  Q_FILE="$Q_OUT/$1.json"
  echo '{"metrics":{},"notes":{},"info":{},"skipped":{},"tools":{}}' >"$Q_FILE"
  mkdir -p "$Q_WORK/$1"
}

q_log() { echo "[quality:${Q_AREA:-?}] $*" >&2; }

# q_put SECTION KEY JSON-VALUE
q_put() {
  local tmp="$Q_FILE.tmp"
  jq --arg s "$1" --arg k "$2" --argjson v "$3" '.[$s][$k] = $v' "$Q_FILE" >"$tmp"
  mv "$tmp" "$Q_FILE"
}

# q_metric KEY VALUE: VALUE must be a number; anything else records null with a note.
q_metric() {
  local v
  v="$(printf '%s' "$2" | tr -d '[:space:]')"
  if [[ "$v" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
    q_put metrics "$1" "$v"
  else
    q_null "$1" "not a number: '$2'"
  fi
}

# q_null KEY REASON...
q_null() {
  local k="$1"
  shift
  q_put metrics "$k" null
  q_put notes "$k" "$(jq -n --arg r "$*" '$r')"
  q_log "$k: null ($*)"
}

# q_skip KEY REASON...: the metric is deliberately not measured in this run.
q_skip() {
  local k="$1"
  shift
  q_put skipped "$k" "$(jq -n --arg r "$*" '$r')"
}

# q_info KEY TEXT
q_info() { q_put info "$1" "$(jq -n --arg t "$2" '$t')"; }

# q_tool NAME VERSION-COMMAND...: records the first line of the command's output.
q_tool() {
  local name="$1" v
  shift
  v="$("$@" 2>&1 | head -1 || true)"
  q_put tools "$name" "$(jq -n --arg v "$v" '$v')"
}

# q_need TOOL KEY...: true if TOOL is on PATH, otherwise every KEY is null and it returns 1.
q_need() {
  local tool="$1" k
  shift
  command -v "$tool" >/dev/null 2>&1 && return 0
  for k in "$@"; do q_null "$k" "$tool not installed"; done
  return 1
}

# Tracked files of the measured tree, one per line, relative to Q_ROOT.
q_files() { git -C "$Q_ROOT" ls-files "$@"; }

# A copy of the tracked files only (no build output), made once per run. Prints its path.
q_export() {
  local dir="$Q_WORK/tree"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
    git -C "$Q_ROOT" ls-files -z | (cd "$Q_ROOT" && tar --null -T - -cf -) | tar -xf - -C "$dir"
  fi
  echo "$dir"
}

# grep that is not an error when nothing matches: these scripts run with -e and pipefail, where a
# grep without a match inside $(... | ...) would end the script.
q_grep() { grep "$@" || [ $? = 1 ]; }

# Count lines of a file (0 if missing), without the padding some wc versions print.
q_lines() {
  if [ -s "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi
}

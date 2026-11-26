#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Scala metrics for driver/: scalafmt drift, compiler warnings, tests, coverage (sbt-scoverage).
# The generated gRPC Java in driver/src/main/java is not counted. Run by collect.sh.
#
# The sbt build needs the Canton kms-driver-api in the local ivy repository
# (scripts/publish-canton-deps.sh). sbt-scoverage is added for this run only (--addPluginSbtFile),
# so the build itself, and older trees measured by quality-report.sh, need no change.
# QUALITY_SCALA_BUILD=0 skips the sbt run; QUALITY_COVERAGE=0 runs the tests without coverage.
# QUALITY_KEEP_DIR, when set to an existing directory, receives the scoverage report
# (scoverage.xml.gz).
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init scala
W="$Q_WORK/scala"
SCOVERAGE_VERSION=2.4.4

# --- scalafmt -------------------------------------------------------------------------------
SRC=()
while IFS= read -r f; do SRC+=("$f"); done < <(q_files 'driver/src/*.scala')
if [ ${#SRC[@]} = 0 ]; then
  q_metric scala.scalafmt.unformatted_files 0
elif q_need scalafmt scala.scalafmt.unformatted_files; then
  q_tool scalafmt scalafmt --version
  conf="$Q_ROOT/.scalafmt.conf"
  # A tree from before the config was added is measured with the collector's own config.
  [ -f "$conf" ] || conf="$Q_HERE/../../.scalafmt.conf"
  rc=0
  (cd "$Q_ROOT" && scalafmt --non-interactive --quiet --config "$conf" --list "${SRC[@]}") \
    >"$W/scalafmt.out" 2>"$W/scalafmt.err" || rc=$?
  n="$(grep -cE '\.scala$' "$W/scalafmt.out" || true)"
  if [ "$rc" = 0 ] || { [ "$rc" = 1 ] && [ "$n" -gt 0 ]; }; then
    q_metric scala.scalafmt.unformatted_files "$n"
  else
    tail -5 "$W/scalafmt.err" >&2
    q_null scala.scalafmt.unformatted_files "scalafmt failed (exit $rc)"
  fi
fi

# --- sbt: warnings, tests, coverage ---------------------------------------------------------
SBT_KEYS=(scala.warnings scala.tests scala.coverage.statements scala.coverage.branches)
if [ "${QUALITY_SCALA_BUILD:-1}" = 0 ]; then
  for k in "${SBT_KEYS[@]}"; do q_skip "$k" "sbt run off in this run (QUALITY_SCALA_BUILD=0)"; done
  exit 0
fi
COVERAGE="${QUALITY_COVERAGE:-1}"
q_need sbt "${SBT_KEYS[@]}" || exit 0
q_tool java java -version

if [ "$COVERAGE" = 0 ]; then
  SBT=(clean driver/test)
else
  echo "addSbtPlugin(\"org.scoverage\" % \"sbt-scoverage\" % \"$SCOVERAGE_VERSION\")" >"$W/scoverage.sbt"
  SBT=("--addPluginSbtFile=$W/scoverage.sbt" clean coverage driver/test driver/coverageReport)
fi
# A repository that rate-limits the runner (HTTP 429) is retried after a pause; any other
# failure is not.
rate_limited() { grep -qiE '(response|status) code:? 429' "$W/sbt.log"; }
for attempt in 1 2 3; do
  rc=0
  (cd "$Q_ROOT" && sbt -batch -no-colors "${SBT[@]}") >"$W/sbt.log" 2>&1 || rc=$?
  if [ "$rc" = 0 ] || ! rate_limited; then
    break
  fi
  if [ "$attempt" = 3 ]; then
    q_log "sbt: a repository answered HTTP 429 (attempt $attempt); giving up"
    break
  fi
  q_log "sbt: a repository answered HTTP 429 (attempt $attempt); retrying in $((attempt * 60)) s"
  sleep $((attempt * 60))
done
q_info scala.sbt "sbt exit $rc, sbt-scoverage $SCOVERAGE_VERSION"

# A failed download is named before the compile heuristic reads the log: the metrics are empty
# because sbt never got that far, not because the driver failed to compile.
why=""
if [ "$rc" != 0 ] && rate_limited; then
  why="sbt could not download a dependency: a repository rate-limited the runner (HTTP 429)"
elif [ "$rc" != 0 ] && grep -q 'ResolveException' "$W/sbt.log" && ! grep -q 'com\.daml' "$W/sbt.log"; then
  why="sbt could not download a dependency (see the sbt log)"
elif ! grep -qiE 'compiling [0-9]+ Scala source' "$W/sbt.log" || grep -q 'Compilation failed' "$W/sbt.log"; then
  why="sbt could not compile the driver (Canton artifacts missing?)"
fi
if [ -n "$why" ]; then
  tail -30 "$W/sbt.log" >&2
  for k in "${SBT_KEYS[@]}"; do q_null "$k" "$why"; done
  exit 0
fi

# Warnings: one per reported site in Scala sources, plus the counts in scalac's summary lines
# ("there were 3 deprecation warnings; re-run with -deprecation for details").
sites="$(q_grep -E '^\[warn\] .*\.scala:[0-9]+:[0-9]+:' "$W/sbt.log" | sort -u | wc -l | tr -d ' ')"
summary="$(q_grep -oE '^\[warn\] there (was|were) ([0-9]+|one) [a-z]+ warnings?' "$W/sbt.log" \
  | awk '{ n = $4; if (n == "one") n = 1; s += n } END { print s + 0 }')"
q_metric scala.warnings "$((sites + summary))"

# Tests: scalatest's run summary, "Tests: succeeded N, failed N, canceled N, ignored N, pending N".
tests="$(q_grep -E 'Tests: succeeded [0-9]+' "$W/sbt.log" | tail -1 | q_grep -oE '[0-9]+' | awk '{ s += $1 } END { print s + 0 }')"
if grep -qE 'Tests: succeeded [0-9]+' "$W/sbt.log"; then
  q_metric scala.tests "$tests"
else
  q_null scala.tests "no scalatest summary in the sbt output"
fi

if [ "$COVERAGE" = 0 ]; then
  q_skip scala.coverage.statements "coverage off in this run (QUALITY_COVERAGE=0)"
  q_skip scala.coverage.branches "coverage off in this run (QUALITY_COVERAGE=0)"
  exit 0
fi
xml="$(find "$Q_ROOT/driver/target" -path '*scoverage-report/scoverage.xml' 2>/dev/null | head -1)"
if [ -n "$xml" ]; then
  q_tool sbt-scoverage echo "$SCOVERAGE_VERSION"
  q_metric scala.coverage.statements "$(q_grep -m1 -oE 'statement-rate="[0-9.]+"' "$xml" | q_grep -m1 -oE '[0-9.]+')"
  q_metric scala.coverage.branches "$(q_grep -m1 -oE 'branch-rate="[0-9.]+"' "$xml" | q_grep -m1 -oE '[0-9.]+')"
  # The report itself (every statement with its file, line and hit count), for whoever wants to
  # see what is not covered. In CI it lands in the quality-metrics artifact.
  if [ -n "${QUALITY_KEEP_DIR:-}" ] && [ -d "$QUALITY_KEEP_DIR" ]; then
    gzip -c "$xml" >"$QUALITY_KEEP_DIR/scoverage.xml.gz" || rm -f "$QUALITY_KEEP_DIR/scoverage.xml.gz"
  fi
else
  q_null scala.coverage.statements "no scoverage report (sbt exit $rc: tests failed?)"
  q_null scala.coverage.branches "no scoverage report (sbt exit $rc: tests failed?)"
fi

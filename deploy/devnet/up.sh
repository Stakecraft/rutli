#!/usr/bin/env bash
# Phase 0 devnet launcher. Boots a Canton participant that delegates crypto to the rutli driver,
# then runs the smoke-test bootstrap script.
#
# Prereqs:
#   - A Canton 3.5.x community release extracted somewhere, with CANTON_HOME pointing at it.
#     Download: https://github.com/digital-asset/canton/releases  (tag v3.5.6)
#   - The driver fat jar built:  sbt driver/assembly
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

: "${CANTON_HOME:?Set CANTON_HOME to an extracted Canton 3.5.x release directory}"

DRIVER_JAR="$REPO_ROOT/driver/target/scala-2.13/rutli-driver.jar"
if [[ ! -f "$DRIVER_JAR" ]]; then
  echo "Driver jar not found at $DRIVER_JAR"
  echo "Build it first:  (cd \"$REPO_ROOT\" && sbt driver/assembly)"
  exit 1
fi

# Put the driver (with BouncyCastle bundled) on the Canton classpath. The release launcher builds
# its classpath from a fixed jar + the EXTRA_CLASSPATH env var — lib/ is NOT globbed.
export EXTRA_CLASSPATH="$DRIVER_JAR"

echo "Starting Canton with the rutli driver (EXTRA_CLASSPATH=$EXTRA_CLASSPATH)..."
# `run` executes the script headless and exits — right shape for a smoke test.
# Swap `run ... ` for `daemon` (plus --bootstrap) to keep the node up for interactive work.
exec "$CANTON_HOME/bin/canton" run "$HERE/bootstrap.canton" \
  --config "$HERE/canton.conf" \
  --no-tty

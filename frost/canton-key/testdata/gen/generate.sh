#!/usr/bin/env bash
# Regenerates frost/canton-key/testdata/vectors from a throwaway in-memory Canton participant.
#
#   CANTON_HOME=~/.cache/canton-3.6.1/canton-open-source-3.6.1 ./generate.sh
#
# Needs a Canton 3.6.1 open-source release and an OpenJDK (17+) on JAVA_HOME or PATH: Oracle's
# JDK refuses Canton's unsigned bundled BouncyCastle for Cipher, which breaks the password-protected
# export ("JCE cannot authenticate the provider BC"). The node binds to 127.0.0.1 only, uses
# in-memory storage and never connects to a synchronizer; every key it produces is a disposable
# test key. Regenerating replaces all vectors (keys are random), so commit the whole directory.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$(cd "$here/../vectors" && pwd)"
canton_home="${CANTON_HOME:-$HOME/.cache/canton-3.6.1/canton-open-source-3.6.1}"
work="${WORK_DIR:-$(mktemp -d)}"

rm -f "$out"/*.bin "$out"/manifest.json
cd "$work" # Canton writes its log/ directory into the working directory.
RUTLI_VECTOR_OUT="$out" "$canton_home/bin/canton" run "$here/vectors.canton" \
  -c "$here/vectors.conf" --no-tty
echo "vectors in $out; Canton logs in $work/log"

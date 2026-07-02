#!/usr/bin/env bash
# Create a local SoftHSM token for exercising the HSM backend, and print the env exports the
# integration test needs. Dev convenience only — SoftHSM is not a production HSM.
#
# Usage:  scripts/init-softhsm.sh [PIN]        (default PIN: 1234)
set -euo pipefail

PIN="${1:-1234}"
SO_PIN="${2:-5678}"
CONF_DIR="$HOME/.rutli-softhsm"
export SOFTHSM2_CONF="$CONF_DIR/softhsm2.conf"

command -v softhsm2-util >/dev/null || {
  echo "softhsm2-util not found. Install SoftHSM (e.g. 'brew install softhsm' / 'apt-get install softhsm2')."
  exit 1
}

mkdir -p "$CONF_DIR/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $CONF_DIR/tokens
objectstore.backend = file
log.level = INFO
EOF

if softhsm2-util --show-slots 2>/dev/null | grep -q 'Label:[[:space:]]*rutli-test'; then
  echo "Token 'rutli-test' already exists — reusing."
else
  softhsm2-util --init-token --free --label rutli-test --pin "$PIN" --so-pin "$SO_PIN" >/dev/null
  echo "Initialized token 'rutli-test'."
fi

LIB="$(find /opt/homebrew /usr/local /usr/lib /usr/lib64 -name 'libsofthsm2.so' 2>/dev/null | head -1)"
[ -n "$LIB" ] || { echo "Could not locate libsofthsm2.so — set RUTLI_HSM_LIB manually."; exit 1; }

echo
echo "Run these exports, then 'sbt \"driver/testOnly com.stakecraft.rutli.HsmBackendIT\"':"
echo
echo "  export SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "  export RUTLI_HSM_LIB=$LIB"
echo "  export RUTLI_HSM_PIN=$PIN"

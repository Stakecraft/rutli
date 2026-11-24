#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Regenerate the FROST gRPC Java stubs from the shared proto, checked into driver/src/main/java.
#
# We generate out-of-band with native protoc + protoc-gen-grpc-java (NOT the sbt-protoc/scalapb
# bridge, whose socket-based codegen plugin hangs in some sandboxed environments). The protoc
# version MUST match the protobuf-java runtime version in build.sbt, or the generated code will
# reference classes the runtime lacks.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The versions come from build.sbt, so the generator cannot drift from the runtime (override with the
# environment variables to try another version).
sbt_version() { sed -n "s/^val $1 *= *\"\([^\"]*\)\".*/\1/p" "$REPO/build.sbt" | head -n 1; }
PROTOBUF_VERSION="${PROTOBUF_VERSION:-$(sbt_version protobufVersion)}"
GRPC_VERSION="${GRPC_VERSION:-$(sbt_version grpcVersion)}"
[ -n "$PROTOBUF_VERSION" ] && [ -n "$GRPC_VERSION" ] || { echo "cannot read protobufVersion / grpcVersion from build.sbt"; exit 1; }
# Optional: PROTOC_SHA256 and PROTOC_GEN_GRPC_JAVA_SHA256 make the script refuse a binary whose sha256
# differs (CI sets them for linux-x86_64).
sha_ok() { # file expected-sha256: status 0 when they match
  if command -v sha256sum >/dev/null; then
    echo "$2  $1" | sha256sum -c - >/dev/null 2>&1
  else
    echo "$2  $1" | shasum -a 256 -c - >/dev/null 2>&1
  fi
}
verify() { # file expected-sha256-or-empty
  [ -z "$2" ] && return 0
  if ! sha_ok "$1" "$2"; then
    echo "sha256 of $(basename "$1") differs from the expected $2 (after a version bump in build.sbt, update PROTOC_SHA256 and PROTOC_GEN_GRPC_JAVA_SHA256 in .github/workflows/generated-code.yml)"
    exit 1
  fi
}

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) CLASSIFIER="osx-aarch_64" ;;
  Darwin-x86_64) CLASSIFIER="osx-x86_64" ;;
  Linux-x86_64) CLASSIFIER="linux-x86_64" ;;
  Linux-aarch64) CLASSIFIER="linux-aarch_64" ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)"; exit 1 ;;
esac

CENTRAL="https://repo1.maven.org/maven2"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# GEN_GRPC_CACHE_DIR (optional, CI sets it): keep the verified binaries there and reuse them, so most
# runs do not download at all. A cached file is checked against the expected sha256 like a fresh one.
# A download that still fails (Maven Central rate-limits shared runner addresses with HTTP 429) exits
# with 3 and says so: that is not a difference in the stubs.
# The cache file is named by tool, version, platform and expected sha256: a version bump in build.sbt
# misses the cache and downloads, so a stale pin fails on the new download, not silently on an old
# binary. A cached file that does not match is removed and downloaded again.
fetch() { # name version url dest expected-sha256-or-empty
  local cached="" rc=0
  if [ -n "${GEN_GRPC_CACHE_DIR:-}" ] && [ -n "$5" ]; then
    cached="$GEN_GRPC_CACHE_DIR/$1-$2-$CLASSIFIER-$5"
    if [ -f "$cached" ]; then
      if sha_ok "$cached" "$5"; then
        cp "$cached" "$4"
        echo "$1 $2: from the cache (sha256 ${5:0:12})"
        return 0
      fi
      echo "$1 $2: cached copy does not match, downloading again"
      rm -f "$cached"
    fi
  fi
  curl -fsSL --proto '=https' --retry 5 --retry-delay 10 --retry-max-time 180 --max-time 120 -o "$4" "$3" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::error::could not download $1 from Maven Central (curl exit ${rc}; 22 is an HTTP error such as 429, rate limited): this is not a difference in the stubs, re-run the job"
    exit 3
  fi
  verify "$4" "$5"
  if [ -n "$cached" ]; then
    # Best effort: a cache that cannot be written only means the next run downloads again.
    mkdir -p "$GEN_GRPC_CACHE_DIR" && cp "$4" "$cached" || echo "$1 $2: could not write the cache"
  fi
}

echo "Fetching protoc $PROTOBUF_VERSION and protoc-gen-grpc-java $GRPC_VERSION ($CLASSIFIER)..."
fetch protoc "$PROTOBUF_VERSION" "$CENTRAL/com/google/protobuf/protoc/$PROTOBUF_VERSION/protoc-$PROTOBUF_VERSION-$CLASSIFIER.exe" \
  "$TMP/protoc" "${PROTOC_SHA256:-}"
fetch protoc-gen-grpc-java "$GRPC_VERSION" "$CENTRAL/io/grpc/protoc-gen-grpc-java/$GRPC_VERSION/protoc-gen-grpc-java-$GRPC_VERSION-$CLASSIFIER.exe" \
  "$TMP/grpc" "${PROTOC_GEN_GRPC_JAVA_SHA256:-}"
chmod +x "$TMP/protoc" "$TMP/grpc"

OUT="$REPO/driver/src/main/java"
rm -rf "$OUT"
mkdir -p "$OUT"
"$TMP/protoc" \
  --plugin=protoc-gen-grpc-java="$TMP/grpc" \
  --java_out="$OUT" \
  --grpc-java_out="$OUT" \
  -I "$REPO/frost/cosigner/proto" \
  "$REPO/frost/cosigner/proto/cosigner.proto"

echo "Generated $(find "$OUT" -name '*.java' | wc -l | tr -d ' ') Java files into driver/src/main/java"

#!/usr/bin/env bash
# Copyright 2026 StakeCraft
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
verify() { # file expected-sha256-or-empty
  [ -z "$2" ] || echo "$2  $1" | { command -v sha256sum >/dev/null && sha256sum -c - >/dev/null || shasum -a 256 -c - >/dev/null; } \
    || { echo "sha256 of $1 differs from the expected $2"; exit 1; }
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

echo "Fetching protoc $PROTOBUF_VERSION and protoc-gen-grpc-java $GRPC_VERSION ($CLASSIFIER)..."
curl -fsSL --proto '=https' -o "$TMP/protoc" \
  "$CENTRAL/com/google/protobuf/protoc/$PROTOBUF_VERSION/protoc-$PROTOBUF_VERSION-$CLASSIFIER.exe"
curl -fsSL --proto '=https' -o "$TMP/grpc" \
  "$CENTRAL/io/grpc/protoc-gen-grpc-java/$GRPC_VERSION/protoc-gen-grpc-java-$GRPC_VERSION-$CLASSIFIER.exe"
verify "$TMP/protoc" "${PROTOC_SHA256:-}"
verify "$TMP/grpc" "${PROTOC_GEN_GRPC_JAVA_SHA256:-}"
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

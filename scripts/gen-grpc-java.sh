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
PROTOBUF_VERSION="${PROTOBUF_VERSION:-4.29.3}"   # keep in sync with protobufVersion in build.sbt
GRPC_VERSION="${GRPC_VERSION:-1.82.1}"           # keep in sync with grpcVersion in build.sbt

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
curl -sL -o "$TMP/protoc" \
  "$CENTRAL/com/google/protobuf/protoc/$PROTOBUF_VERSION/protoc-$PROTOBUF_VERSION-$CLASSIFIER.exe"
curl -sL -o "$TMP/grpc" \
  "$CENTRAL/io/grpc/protoc-gen-grpc-java/$GRPC_VERSION/protoc-gen-grpc-java-$GRPC_VERSION-$CLASSIFIER.exe"
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

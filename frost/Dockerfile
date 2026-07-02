# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Build the FROST cosigner daemon. protoc is vendored via a build-dependency, so no system protobuf.

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p rutli-cosigner

FROM debian:stable-slim
RUN useradd -r -u 10001 rutli && mkdir /data && chown rutli /data
COPY --from=build /src/target/release/rutli-cosigner /usr/local/bin/rutli-cosigner
USER rutli
VOLUME ["/data"]
ENTRYPOINT ["rutli-cosigner"]

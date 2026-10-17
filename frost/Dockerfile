# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Build the FROST cosigner daemon. protoc is vendored via a build-dependency, so no system protobuf.

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
# Only the daemon. rutli-dealer (the split ceremony's dealer) is deliberately neither built nor
# shipped here: a dealer must never run where a share lives (docs/split-ceremony.md).
# Bounded parallelism: an emulated (QEMU) cross-arch build on a small builder can OOM at link time.
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
RUN cargo build --release -p rutli-cosigner --bin rutli-cosigner

FROM debian:stable-slim
RUN useradd -r -u 10001 rutli && mkdir /data && chown rutli /data
COPY --from=build /src/target/release/rutli-cosigner /usr/local/bin/rutli-cosigner
USER rutli
VOLUME ["/data"]
ENTRYPOINT ["rutli-cosigner"]

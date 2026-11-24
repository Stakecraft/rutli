# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Build the FROST cosigner daemon. protoc is vendored via a build-dependency, so no system protobuf.
#
# Base images are pinned by the digest of their multi-arch index; the tag is a comment for humans.
# The Rust version must match frost/rust-toolchain.toml (image-build-check.yml compares them).
# To refresh a digest:
#   docker buildx imagetools inspect rust:<version>-slim     (the "Digest:" line of the index)

# rust:1.100.0-slim
FROM rust:1.100.0-slim@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS build
WORKDIR /src
COPY . .
# Only the daemon. rutli-dealer (the split ceremony's dealer) is deliberately neither built nor
# shipped here: a dealer must never run where a share lives (docs/split-ceremony.md).
# Bounded parallelism: an emulated (QEMU) cross-arch build on a small builder can OOM at link time.
ARG CARGO_BUILD_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# --locked: exactly the crate versions in the committed Cargo.lock, as CI tests them.
RUN cargo build --release --locked -p rutli-cosigner --bin rutli-cosigner

# debian:stable-slim (trixie when pinned)
FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0
# The base is pinned by digest, and a digest is a day's snapshot: Debian's security updates that came
# after it (libc, zlib) are applied here. Only what the base already has is upgraded (nothing new is
# installed); the downloaded packages and lists are removed again. Findings that Debian has no fix
# for stay: see docs/image-vulnerabilities.md.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends upgrade \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 rutli && mkdir /data && chown rutli /data
COPY --from=build /src/target/release/rutli-cosigner /usr/local/bin/rutli-cosigner
# Licenses of the Rust crates compiled into the binary (scripts/third-party-licenses.sh).
COPY THIRD-PARTY-LICENSES.txt /usr/share/doc/rutli-cosigner/THIRD-PARTY-LICENSES.txt
USER rutli
VOLUME ["/data"]
ENTRYPOINT ["rutli-cosigner"]

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Rütli FROST cosigner daemon.
//!
//! One node in a `t`-of-`n` FROST cluster. Holds a single key share, exposes a gRPC signing API to
//! the Canton KMS driver (the [`pb::signer_server::Signer`] service), and coordinates DKG and
//! two-round signing with its peers (the [`pb::peer_server::Peer`] mesh). The security-critical
//! protocol logic lives in `rutli-frost-core`; this crate is transport + orchestration.
//!
//! v0 scope: static leader (the node the client connects to leads the request) and a fixed peer
//! roster. Raft-based leader election is a documented follow-up (see docs/phase-2-frost.md).

// DaemonError wraps large frost/tonic types; boxing every Err site is not worth the churn.
#![allow(clippy::result_large_err)]

pub mod config;
pub mod error;
pub mod export;
pub mod health;
pub mod hosted;
pub mod keystore;
pub mod metrics;
pub mod node;
pub mod orchestrator;
pub mod peer;
pub mod ratelimit;
pub mod request_auth;
pub mod seal;
pub mod service;
pub mod share_delivery;
pub mod share_import;
pub mod tls;
pub mod verify_key;
pub mod wrap;

/// Generated protobuf/tonic types.
// Lint-exempt: this module is entirely prost/tonic codegen we cannot change, and new clippy
// releases keep adding lints that fire inside it (e.g. double_must_use on async_trait methods
// under Rust 1.99).
#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("rutli.cosigner.v1");
}

// The test PKI helper is shared with the integration tests, which name this crate by its name.
#[cfg(test)]
extern crate self as rutli_cosigner;
#[cfg(test)]
#[path = "../tests/common/pki.rs"]
pub(crate) mod test_pki;

pub use error::DaemonError;
pub type Result<T> = std::result::Result<T, DaemonError>;

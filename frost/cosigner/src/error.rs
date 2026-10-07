// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Core(#[from] rutli_frost_core::CoreError),

    #[error("frost: {0}")]
    Frost(#[from] frost_ed25519::Error),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    /// Deliberately opaque: a decryption failure must not say *why* (bad padding vs bad key vs
    /// wrong length). A distinguishable failure is a padding oracle.
    #[error("decryption failed")]
    DecryptFailed,

    #[error("{0}")]
    RateLimited(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// The key-store readiness probe failed ([`crate::keystore::KeyStore::check_readable`]): the
    /// volume under `data_dir/keys` cannot be listed, opened, read or written. A node in this state
    /// fails every Sign/Dkg it touches, so `Signer.Health` reports NOT_SERVING on it.
    #[error("keystore {} {what}: {source}", .path.display())]
    KeystoreUnavailable {
        path: std::path::PathBuf,
        /// "unreadable" | "not writable" | "unresponsive".
        what: &'static str,
        source: std::io::Error,
    },

    #[error("rpc transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("rpc status: {0}")]
    Status(#[from] tonic::Status),

    /// This node's key store failed its last readiness probe, so it refuses to join a signing
    /// quorum it could not finish. Leaders skip it like an unreachable peer.
    #[error("not serving: {0}")]
    NotServing(String),

    #[error("unknown key id: {0}")]
    UnknownKey(String),

    #[error("unknown dkg session: {0}")]
    UnknownDkg(String),

    #[error("key {0} already exists — refusing DKG (it would overwrite/destroy the existing key)")]
    KeyExists(String),

    #[error("a {kind} ceremony (id {other}) is already in progress for key {key_id}")]
    CeremonyInProgress { key_id: String, kind: &'static str, other: String },

    #[error("ceremony {owner} for key {key_id} was superseded by a newer ceremony — refusing to persist")]
    CeremonySuperseded { key_id: String, owner: String },

    #[error(
        "refusing {kind} for key {key_id}: {pending} in-flight sign session(s) on this node — \
         drain / wait for round-2, then retry"
    )]
    SignInProgress { key_id: String, kind: &'static str, pending: usize },

    #[error(
        "invalid sign message length: got {got} bytes, expected {expected} \
         (Canton's multihash-prefixed SHA-256 digest — see docs/wire-contract.md)"
    )]
    InvalidMessageLength { got: usize, expected: usize },

    #[error("could not reach signing threshold: needed {needed}, got {got}")]
    ThresholdNotMet { needed: usize, got: usize },

    #[error("configuration: {0}")]
    Config(String),

    #[error("cluster disagreement: {0}")]
    Disagreement(String),
}

impl From<DaemonError> for tonic::Status {
    fn from(e: DaemonError) -> Self {
        match e {
            DaemonError::UnknownKey(_) | DaemonError::UnknownDkg(_) => {
                tonic::Status::not_found(e.to_string())
            }
            DaemonError::ThresholdNotMet { .. } | DaemonError::NotServing(_) => {
                tonic::Status::unavailable(e.to_string())
            }
            DaemonError::Config(_) => tonic::Status::failed_precondition(e.to_string()),
            // invalid_argument, and nothing more: same code and message for every cause.
            DaemonError::DecryptFailed => tonic::Status::invalid_argument(e.to_string()),
            // Retryable: a legitimate caller should back off and try again, not treat the key as
            // broken. The driver must NOT fail over to another cosigner on this — every node
            // enforces the same limit, so retrying elsewhere would just spread the load an
            // attacker is generating.
            DaemonError::RateLimited(_) => tonic::Status::resource_exhausted(e.to_string()),
            DaemonError::KeyExists(_) => tonic::Status::already_exists(e.to_string()),
            // aborted: a concurrent ceremony is holding the key; the caller may retry later.
            DaemonError::CeremonyInProgress { .. } => tonic::Status::aborted(e.to_string()),
            DaemonError::CeremonySuperseded { .. } => tonic::Status::aborted(e.to_string()),
            DaemonError::SignInProgress { .. } => tonic::Status::aborted(e.to_string()),
            DaemonError::InvalidMessageLength { .. } => {
                tonic::Status::invalid_argument(e.to_string())
            }
            _ => tonic::Status::internal(e.to_string()),
        }
    }
}

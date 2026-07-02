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

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("rpc transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("rpc status: {0}")]
    Status(#[from] tonic::Status),

    #[error("unknown key id: {0}")]
    UnknownKey(String),

    #[error("unknown dkg session: {0}")]
    UnknownDkg(String),

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
            DaemonError::ThresholdNotMet { .. } => tonic::Status::unavailable(e.to_string()),
            DaemonError::Config(_) => tonic::Status::failed_precondition(e.to_string()),
            _ => tonic::Status::internal(e.to_string()),
        }
    }
}

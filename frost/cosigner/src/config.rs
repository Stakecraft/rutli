// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Static cluster configuration for one cosigner node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// This node's FROST identifier (1..=n).
    pub identifier: u16,
    /// Address this node's gRPC server listens on (host:port).
    pub listen: String,
    /// Signing threshold `t`.
    pub threshold: u16,
    /// Directory for key shares and nonce-store markers (must be durable).
    pub data_dir: PathBuf,
    /// The full cosigner roster, including this node.
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub identifier: u16,
    /// gRPC endpoint of the peer (e.g. http://host:port). Ignored for this node itself.
    pub endpoint: String,
}

impl Config {
    pub fn max_signers(&self) -> u16 {
        self.peers.len() as u16
    }

    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = serde_json::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> crate::Result<()> {
        use crate::DaemonError::Config;
        if self.peers.is_empty() {
            return Err(Config("peer roster is empty".into()));
        }
        if self.threshold < 1 || self.threshold > self.max_signers() {
            return Err(Config(format!(
                "threshold {} out of range 1..={}",
                self.threshold,
                self.max_signers()
            )));
        }
        if !self.peers.iter().any(|p| p.identifier == self.identifier) {
            return Err(Config(format!(
                "this node's identifier {} is not in the peer roster",
                self.identifier
            )));
        }
        Ok(())
    }
}

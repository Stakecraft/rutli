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
    /// Mutual-TLS config. When present, the gRPC server requires client certs and peer clients
    /// present ours; when absent, the node runs plaintext (dev only).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Share sealing (encryption-at-rest for key shares). When present, shares are stored as
    /// AES-256-GCM envelopes keyed from the referenced secret; when absent, shares are plaintext
    /// JSON (dev only).
    #[serde(default)]
    pub share_seal: Option<ShareSealConfig>,
}

/// Where the share-sealing master secret comes from. The secret must be injected at runtime (secret
/// manager, systemd credential, enclave bootstrap) — never stored in this config file or on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSealConfig {
    /// Name of the environment variable holding the master secret (e.g. `openssl rand -hex 32`).
    pub secret_env: String,
}

/// Mutual-TLS material for the cosigner mesh (and the driver→cluster hop). All peers and the driver
/// present certs signed by the same cluster CA; the CA cert is the single trust anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// PEM CA certificate that must sign every peer/client certificate (the trust anchor).
    pub ca_cert: PathBuf,
    /// PEM certificate this node presents (as server, and as client to peers).
    pub cert: PathBuf,
    /// PEM private key for `cert`.
    pub key: PathBuf,
    /// Expected TLS server-name (SNI/SAN) when dialing peers. Peer endpoints use `https://`.
    #[serde(default)]
    pub domain: Option<String>,
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

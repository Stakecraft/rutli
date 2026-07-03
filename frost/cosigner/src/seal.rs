// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Share sealing: encryption-at-rest for this node's key shares.
//!
//! A [`Sealer`] wraps share bytes in AES-256-GCM. The data-encryption key is derived per node via
//! HKDF-SHA256 from an operator-supplied master secret (injected through an env var by a secret
//! manager, systemd credential, or enclave bootstrap — never stored on the node's disk) and a salt
//! bound to this node's identifier, so the same master secret yields different keys per node.
//!
//! Threat model: this closes the *at-rest* exposure — a copied disk, snapshot, or stray backup of
//! `data_dir` no longer yields a usable key share. It does not protect share memory during signing;
//! that requires enclave/HSM sealing ("MPC-of-HSM"), for which this module is the software seam:
//! swap the [`Sealer`] implementation, keep the file format.
//!
//! File format (JSON): `{"v":1,"sealed":true,"nonce":<hex 12B>,"ct":<hex>}`. Legacy plaintext share
//! files are still readable when sealing is enabled, so an operator can turn sealing on and have
//! shares re-sealed on the next write (or via re-save), but new writes are always sealed.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{DaemonError, Result};

const NONCE_LEN: usize = 12;

/// Sealed-share envelope as stored on disk.
#[derive(Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub v: u8,
    pub sealed: bool,
    pub nonce: String,
    pub ct: String,
}

pub struct Sealer {
    key: Zeroizing<[u8; 32]>,
}

impl Sealer {
    /// Derive this node's data-encryption key from the master secret and the node identifier.
    /// The identifier salt makes per-node keys distinct under one master secret.
    pub fn from_master_secret(master: &[u8], node_identifier: u16) -> Self {
        let salt = format!("rutli-share-seal/node-{node_identifier}");
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master);
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(b"share-dek-v1", key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self { key }
    }

    /// Read the master secret from `env_var` (utf-8; recommended ≥ 32 bytes of entropy, e.g.
    /// `openssl rand -hex 32`).
    pub fn from_env(env_var: &str, node_identifier: u16) -> Result<Self> {
        let master = Zeroizing::new(std::env::var(env_var).map_err(|_| {
            DaemonError::Config(format!(
                "share sealing enabled but env var {env_var} is not set"
            ))
        })?);
        if master.len() < 16 {
            return Err(DaemonError::Config(format!(
                "share-seal secret in {env_var} is too short ({} chars); use at least 16, e.g. `openssl rand -hex 32`",
                master.len()
            )));
        }
        Ok(Self::from_master_secret(master.as_bytes(), node_identifier))
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_ref()));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| DaemonError::Config("share sealing failed".into()))?;
        let envelope = SealedEnvelope {
            v: 1,
            sealed: true,
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
        };
        Ok(serde_json::to_vec_pretty(&envelope)?)
    }

    pub fn unseal(&self, file_bytes: &[u8]) -> Result<Vec<u8>> {
        let envelope: SealedEnvelope = serde_json::from_slice(file_bytes)
            .map_err(|e| DaemonError::Config(format!("not a sealed share envelope: {e}")))?;
        if envelope.v != 1 || !envelope.sealed {
            return Err(DaemonError::Config(format!(
                "unsupported sealed envelope (v={}, sealed={})",
                envelope.v, envelope.sealed
            )));
        }
        let nonce_bytes = hex::decode(&envelope.nonce)
            .map_err(|e| DaemonError::Config(format!("bad nonce hex: {e}")))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(DaemonError::Config("bad nonce length".into()));
        }
        let ct = hex::decode(&envelope.ct)
            .map_err(|e| DaemonError::Config(format!("bad ciphertext hex: {e}")))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_ref()));
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_slice())
            .map_err(|_| {
                DaemonError::Config(
                    "share unseal failed — wrong seal secret or corrupted/tampered share file".into(),
                )
            })
    }

    /// Whether `file_bytes` look like a sealed envelope (vs. a legacy plaintext share).
    pub fn is_sealed(file_bytes: &[u8]) -> bool {
        serde_json::from_slice::<SealedEnvelope>(file_bytes)
            .map(|e| e.sealed)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let s = Sealer::from_master_secret(b"correct horse battery staple", 1);
        let sealed = s.seal(b"share bytes").unwrap();
        assert!(Sealer::is_sealed(&sealed));
        assert_eq!(s.unseal(&sealed).unwrap(), b"share bytes");
    }

    #[test]
    fn wrong_key_fails() {
        let a = Sealer::from_master_secret(b"secret-a", 1);
        let b = Sealer::from_master_secret(b"secret-b", 1);
        let sealed = a.seal(b"share bytes").unwrap();
        assert!(b.unseal(&sealed).is_err());
    }

    #[test]
    fn same_secret_different_node_gives_different_key() {
        let a = Sealer::from_master_secret(b"one master secret", 1);
        let b = Sealer::from_master_secret(b"one master secret", 2);
        let sealed = a.seal(b"share bytes").unwrap();
        assert!(b.unseal(&sealed).is_err(), "node-2 key must not open node-1 shares");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let s = Sealer::from_master_secret(b"correct horse battery staple", 1);
        let sealed = s.seal(b"share bytes").unwrap();
        let mut env: SealedEnvelope = serde_json::from_slice(&sealed).unwrap();
        let mut ct = hex::decode(&env.ct).unwrap();
        ct[0] ^= 0x01;
        env.ct = hex::encode(ct);
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(s.unseal(&tampered).is_err());
    }

    #[test]
    fn plaintext_is_not_sealed() {
        assert!(!Sealer::is_sealed(b"{\"key_package\": {}}"));
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! On-disk store for this node's key shares.
//!
//! A share is this cosigner's [`frost::keys::KeyPackage`] plus the group
//! [`frost::keys::PublicKeyPackage`], serialized as JSON, one file per `key_id`. The KeyPackage
//! contains only this node's secret share — never the whole private key, which is never assembled.
//!
//! ⚠️ v0 stores the share as plaintext JSON. Production must wrap it (an HSM/enclave-sealed share,
//! the "MPC-of-HSM" model in the architecture) — tracked as a follow-up.

use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::seal::Sealer;
use crate::{DaemonError, Result};

#[derive(Serialize, Deserialize)]
pub struct Share {
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

pub struct KeyStore {
    dir: PathBuf,
    sealer: Option<Arc<Sealer>>,
}

impl KeyStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_sealer(dir, None)
    }

    /// Open the store with optional share sealing. With a sealer, every write is encrypted
    /// (AES-256-GCM envelope); reads accept both sealed envelopes and legacy plaintext shares
    /// (which get re-sealed on their next save). Without a sealer, reading a sealed share fails
    /// loudly rather than pretending the data is available.
    pub fn open_with_sealer(dir: impl Into<PathBuf>, sealer: Option<Arc<Sealer>>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, sealer })
    }

    fn path(&self, key_id: &str) -> Result<PathBuf> {
        if key_id.is_empty()
            || !key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DaemonError::Config(format!("invalid key id: {key_id:?}")));
        }
        Ok(self.dir.join(format!("{key_id}.json")))
    }

    pub fn exists(&self, key_id: &str) -> bool {
        self.path(key_id).map(|p| p.exists()).unwrap_or(false)
    }

    pub fn save(&self, key_id: &str, share: &Share) -> Result<()> {
        let path = self.path(key_id)?;
        let tmp = path.with_extension("json.tmp");
        let plain = serde_json::to_vec_pretty(share)?;
        let bytes = match &self.sealer {
            Some(s) => s.seal(&plain)?,
            None => plain,
        };
        // Write + fsync the temp file, atomically rename, then fsync the directory — so a share
        // survives power loss as durably as the nonce store (which already fsyncs). Without this a
        // crash right after DKG could lose the just-generated share while peers kept theirs.
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        std::fs::File::open(&self.dir)?.sync_all()?; // fsync the directory entry (the rename)
        Ok(())
    }

    pub fn load(&self, key_id: &str) -> Result<Share> {
        let path = self.path(key_id)?;
        if !path.exists() {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        let bytes = std::fs::read(&path)?;
        let plain = match (&self.sealer, Sealer::is_sealed(&bytes)) {
            (Some(s), true) => s.unseal(&bytes)?,
            // Sealing on, legacy plaintext file: readable (migration path); re-sealed on next save.
            (Some(_), false) => bytes,
            (None, true) => {
                return Err(DaemonError::Config(format!(
                    "share {key_id} is sealed but share sealing is not configured on this node"
                )))
            }
            (None, false) => bytes,
        };
        Ok(serde_json::from_slice(&plain)?)
    }

    pub fn nonce_dir(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}.nonces"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

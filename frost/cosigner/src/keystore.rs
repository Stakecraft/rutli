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
use std::path::{Path, PathBuf};

use crate::{DaemonError, Result};

#[derive(Serialize, Deserialize)]
pub struct Share {
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
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
        std::fs::write(&tmp, serde_json::to_vec_pretty(share)?)?;
        // Atomic replace so a crash never leaves a half-written share.
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn load(&self, key_id: &str) -> Result<Share> {
        let path = self.path(key_id)?;
        if !path.exists() {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
    }

    pub fn nonce_dir(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}.nonces"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

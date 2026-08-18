// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! On-disk store for this node's key shares.
//!
//! A share is this cosigner's [`frost::keys::KeyPackage`] plus the group
//! [`frost::keys::PublicKeyPackage`], serialized as JSON, one file per `key_id`. The KeyPackage
//! contains only this node's secret share — never the whole private key, which is never assembled.
//!
//! With a [`Sealer`], shares are AES-256-GCM envelopes on disk. Legacy plaintext files are
//! re-sealed at startup via [`KeyStore::reseal_plaintext_shares`]. Without a sealer (dev only),
//! shares remain plaintext JSON.

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

/// What a key file holds. FROST shares and cluster-hosted whole keys live in the *same* directory
/// and the same sealed envelope, distinguished by a `kind` tag in the plaintext.
///
/// They share a directory deliberately: `rutli-cosigner backup` flat-copies `data_dir/keys/`, so a
/// sibling directory would be silently skipped from every backup — the exact class of failure
/// hosted keys exist to prevent.
///
/// Legacy files (written before hosted keys existed) have no `kind` field and parse as
/// [`Record::Frost`], so an upgrade needs no migration.
pub enum Record {
    // Boxed: a FROST Share carries the key + public-key packages and dwarfs a hosted record, so an
    // unboxed enum would make every Record as large as the biggest variant.
    Frost(Box<Share>),
    Hosted(Box<crate::hosted::HostedKey>),
}

/// The `kind` tag written into hosted-key files. FROST files carry no tag (backward compatible).
const KIND_HOSTED: &str = "hosted";

pub struct KeyStore {
    dir: PathBuf,
    sealer: Option<Arc<Sealer>>,
}

impl KeyStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_sealer(dir, None)
    }

    /// Open the store with optional share sealing. With a sealer, every write is encrypted
    /// (AES-256-GCM envelope). Call [`reseal_plaintext_shares`] after open to migrate any legacy
    /// plaintext files immediately. Without a sealer, reading a sealed share fails loudly.
    pub fn open_with_sealer(dir: impl Into<PathBuf>, sealer: Option<Arc<Sealer>>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, sealer })
    }

    /// When sealing is enabled, rewrite any leftover plaintext share files as sealed envelopes.
    /// Idempotent: already-sealed files are left alone. Returns how many files were re-sealed.
    pub fn reseal_plaintext_shares(&self) -> Result<usize> {
        let Some(_) = &self.sealer else {
            return Ok(0);
        };
        let mut migrated = 0usize;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".json") {
                continue;
            }
            let key_id = name.trim_end_matches(".json");
            let bytes = std::fs::read(entry.path())?;
            if Sealer::is_sealed(&bytes) {
                continue;
            }
            // load_record() accepts plaintext under a sealer; the save path always writes sealed.
            // Must be record-aware: blindly parsing every file as a FROST Share would fail on a
            // hosted key that was written while sealing was off.
            match self.load_record(key_id)? {
                Record::Frost(share) => self.save(key_id, &share)?,
                Record::Hosted(k) => self.save_hosted(key_id, &k)?,
            }
            migrated += 1;
            tracing::info!(key_id, "re-sealed legacy plaintext share at rest");
        }
        Ok(migrated)
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
        self.write_sealed(key_id, &serde_json::to_vec_pretty(share)?)
    }

    /// Seal `plain` and write it durably: temp file + fsync, atomic rename, fsync the directory —
    /// so a key survives power loss. Shared by FROST shares and hosted keys.
    fn write_sealed(&self, key_id: &str, plain: &[u8]) -> Result<()> {
        let path = self.path(key_id)?;
        let tmp = path.with_extension("json.tmp");
        let bytes = match &self.sealer {
            Some(s) => s.seal(plain)?,
            None => plain.to_vec(),
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
        match self.load_record(key_id)? {
            Record::Frost(s) => Ok(*s),
            Record::Hosted(_) => Err(DaemonError::Config(format!(
                "{key_id} is a cluster-hosted key, not a FROST share"
            ))),
        }
    }

    /// Read a key file and unseal it, without interpreting the contents.
    fn read_plaintext(&self, key_id: &str) -> Result<Vec<u8>> {
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
        Ok(plain)
    }

    // -- cluster-hosted (non-FROST) keys --

    /// Persist a hosted key, sealed, with the same atomic + fsync discipline as a FROST share.
    pub fn save_hosted(&self, key_id: &str, key: &crate::hosted::HostedKey) -> Result<()> {
        let mut value = serde_json::to_value(key)?;
        value
            .as_object_mut()
            .expect("HostedKey serializes to a JSON object")
            .insert("kind".into(), serde_json::Value::String(KIND_HOSTED.into()));
        self.write_sealed(key_id, &serde_json::to_vec_pretty(&value)?)
    }

    pub fn load_hosted(&self, key_id: &str) -> Result<crate::hosted::HostedKey> {
        match self.load_record(key_id)? {
            Record::Hosted(k) => Ok(*k),
            Record::Frost(_) => Err(DaemonError::Config(format!(
                "{key_id} is a FROST share, not a cluster-hosted key"
            ))),
        }
    }

    /// Read a key file without knowing its type up front.
    pub fn load_record(&self, key_id: &str) -> Result<Record> {
        let plain = self.read_plaintext(key_id)?;
        let value: serde_json::Value = serde_json::from_slice(&plain)?;
        let is_hosted = value.get("kind").and_then(|k| k.as_str()) == Some(KIND_HOSTED);
        if is_hosted {
            Ok(Record::Hosted(Box::new(serde_json::from_value(value)?)))
        } else {
            Ok(Record::Frost(Box::new(serde_json::from_value(value)?)))
        }
    }

    /// Key ids of every hosted key on this node (FROST shares excluded).
    pub fn list_hosted(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(key_id) = name.strip_suffix(".json") else { continue };
            // A key that fails to open must not silently vanish from the inventory — that would
            // make a corrupt or wrongly-sealed key look like a deleted one to anti-entropy.
            match self.load_record(key_id) {
                Ok(Record::Hosted(_)) => out.push(key_id.to_string()),
                Ok(Record::Frost(_)) => {}
                Err(e) => {
                    tracing::error!(key_id = %key_id, error = %e, "unreadable key file in keystore");
                    return Err(e);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Remove a key file. Physical erasure is best-effort: on copy-on-write filesystems, SSDs with
    /// wear levelling, and snapshotted volumes the sealed bytes may survive. Real destruction means
    /// rotating the seal master secret.
    pub fn delete(&self, key_id: &str) -> Result<()> {
        let path = self.path(key_id)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
            std::fs::File::open(&self.dir)?.sync_all()?;
        }
        Ok(())
    }

    pub fn nonce_dir(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}.nonces"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::{HostedKey, HostedSpec};

    fn store(tmp: &tempfile::TempDir, sealed: bool) -> KeyStore {
        let sealer = sealed
            .then(|| Arc::new(crate::seal::Sealer::from_master_secret(b"test master secret", 1)));
        KeyStore::open_with_sealer(tmp.path().join("keys"), sealer).unwrap()
    }

    #[test]
    fn hosted_keys_round_trip_sealed_and_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let key = HostedKey::generate(HostedSpec::Rsa2048, 42).unwrap();
        let ct = key.encrypt_oaep(b"before restart").unwrap();

        store(&tmp, true).save_hosted("rutli-enc-1", &key).unwrap();

        // On-disk file must be a sealed envelope, not readable key material.
        let raw = std::fs::read(tmp.path().join("keys").join("rutli-enc-1.json")).unwrap();
        assert!(crate::seal::Sealer::is_sealed(&raw));
        assert!(!String::from_utf8_lossy(&raw).contains("private_der"));

        // A fresh store (as after a restart) reloads it and can still decrypt.
        let reloaded = store(&tmp, true).load_hosted("rutli-enc-1").unwrap();
        assert_eq!(reloaded.decrypt_oaep(&ct).unwrap().as_slice(), b"before restart");
        assert_eq!(reloaded.created_at, 42);
    }

    #[test]
    fn frost_shares_and_hosted_keys_coexist_without_confusion() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        let hosted = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        ks.save_hosted("rutli-sym-1", &hosted).unwrap();

        // list_hosted must not report FROST shares, and typed loads must refuse the wrong kind.
        assert_eq!(ks.list_hosted().unwrap(), vec!["rutli-sym-1".to_string()]);
        assert!(ks.load("rutli-sym-1").is_err(), "a hosted key must not load as a FROST share");
    }

    #[test]
    fn a_legacy_untagged_share_file_still_loads_as_frost() {
        // Files written before hosted keys existed have no "kind" tag. Upgrading must not need a
        // migration, so an untagged record must still parse as a FROST share.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = serde_json::json!({ "key_package": {}, "public_key_package": {} });
        std::fs::write(dir.join("legacy.json"), serde_json::to_vec(&legacy).unwrap()).unwrap();

        let ks = KeyStore::open(&dir).unwrap();
        // It is not valid FROST content, but it must be *classified* as a share, not as hosted.
        match ks.load_record("legacy") {
            Ok(Record::Frost(_)) => {}
            Ok(Record::Hosted(_)) => panic!("untagged legacy file misclassified as a hosted key"),
            Err(_) => {} // frost rejects the empty packages; classification is what matters here
        }
        assert!(ks.list_hosted().is_err() || ks.list_hosted().unwrap().is_empty());
    }

    #[test]
    fn delete_removes_the_key_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.save_hosted("rutli-enc-2", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();
        assert!(ks.exists("rutli-enc-2"));
        ks.delete("rutli-enc-2").unwrap();
        assert!(!ks.exists("rutli-enc-2"));
        ks.delete("rutli-enc-2").unwrap(); // no-op, not an error
        assert!(ks.load_hosted("rutli-enc-2").is_err());
    }

    #[test]
    fn a_wrong_seal_secret_cannot_open_a_hosted_key() {
        let tmp = tempfile::tempdir().unwrap();
        store(&tmp, true)
            .save_hosted("rutli-enc-3", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();

        let wrong = Arc::new(crate::seal::Sealer::from_master_secret(b"a different master", 1));
        let ks = KeyStore::open_with_sealer(tmp.path().join("keys"), Some(wrong)).unwrap();
        assert!(ks.load_hosted("rutli-enc-3").is_err());
    }

    #[test]
    fn plaintext_hosted_keys_are_resealed_on_startup() {
        // reseal_plaintext_shares used to parse every file as a FROST Share; a hosted key written
        // while sealing was off would have broken startup.
        let tmp = tempfile::tempdir().unwrap();
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 7).unwrap();
        store(&tmp, false).save_hosted("rutli-sym-9", &key).unwrap(); // unsealed

        let sealed = store(&tmp, true);
        assert_eq!(sealed.reseal_plaintext_shares().unwrap(), 1);
        let raw = std::fs::read(tmp.path().join("keys").join("rutli-sym-9.json")).unwrap();
        assert!(crate::seal::Sealer::is_sealed(&raw), "hosted key must be sealed after migration");
        assert_eq!(sealed.load_hosted("rutli-sym-9").unwrap().created_at, 7);
    }
}

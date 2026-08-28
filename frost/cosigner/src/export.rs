// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Portable export/import of cluster-hosted keys.
//!
//! This is deliberately **not** the same thing as `backup`, and the two solve different problems:
//!
//! - `backup` copies the sealed files as they sit on disk. The artifact is ciphertext under the
//!   cluster's seal master secret, and it restores only onto the node it came from (the DEK is
//!   derived from the master secret salted by node id). It is the routine durability path.
//! - **export** produces a *portable* artifact that does not depend on the cluster's seal secret or
//!   node identity at all. That is the point: it covers the two cases `backup` cannot — restoring
//!   into a different cluster, and recovering after the seal master secret is lost.
//!
//! Because the artifact is portable, it is as dangerous as the key itself. Two deliberate choices
//! follow:
//!
//! 1. **Offline only.** There is no export/import RPC and there must never be one. An export RPC
//!    would turn a stolen driver certificate from an online, rate-limited, journalled decrypt
//!    *oracle* into permanent silent possession of the key. As a CLI subcommand the operation needs
//!    host access *and* the seal secret (which the operator already keeps in a separate trust
//!    domain), and adds no network attack surface.
//! 2. **Encrypted by default.** The export is sealed under an operator passphrase via Argon2id +
//!    AES-256-GCM, so the artifact is safe to write to media and the operator can Shamir-split or
//!    escrow the passphrase as they see fit. `--unsafe-plaintext` exists for piping into another
//!    KMS/HSM import tool, and says so loudly.
//!
//! **Hosted keys only.** A FROST share is not a whole key — there is nothing to export, and
//! exporting one node's share would be both useless and dangerous. The commands refuse it.

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hosted::HostedKey;
use crate::{DaemonError, Result};

/// Envelope written by `export-key` and read by `import-key`.
///
/// Versioned: an exported key may sit in a safe for years and must still be importable by a much
/// later build, so the reader refuses an unknown version rather than guessing.
#[derive(Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub v: u8,
    /// Fixed marker so a mis-pointed `--in` fails with a clear message instead of a parse error.
    pub kind: String,
    pub key_id: String,
    pub spec: String,
    /// When the key itself was created (carried through so an import preserves provenance).
    pub created_at: u64,
    /// Argon2id parameters, or `None` for a plaintext export.
    pub kdf: Option<Kdf>,
    /// Hex AES-256-GCM nonce (encrypted exports only).
    #[serde(default)]
    pub nonce: String,
    /// Hex payload: AES-256-GCM ciphertext of the key JSON, or the key JSON itself when `kdf` is
    /// `None`.
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
pub struct Kdf {
    pub algo: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

pub const ENVELOPE_VERSION: u8 = 1;
pub const ENVELOPE_KIND: &str = "rutli-key-export";

/// Argon2id parameters. Deliberately costly: the passphrase is the only thing standing between an
/// exported artifact and the key, and unlike an online login this is a once-per-ceremony operation
/// where a second of CPU is free.
const ARGON2_M_COST: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const SALT_LEN: usize = 16;

/// Minimum passphrase length. An export protected by a guessable passphrase is worse than useless:
/// it looks protected.
const MIN_PASSPHRASE_LEN: usize = 12;

/// Produce a portable, passphrase-encrypted export of `key`.
pub fn export_encrypted(key_id: &str, key: &HostedKey, passphrase: &str) -> Result<ExportEnvelope> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(DaemonError::Config(format!(
            "export passphrase must be at least {MIN_PASSPHRASE_LEN} characters — this is the only \
             protection on a portable copy of a private key"
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let dek = derive_dek(passphrase, &salt)?;

    let plain = Zeroizing::new(serde_json::to_vec(key)?);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_ref()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // Bind the ciphertext to the identity fields, so an artifact cannot be relabelled to another
    // key id or spec and imported as something it is not.
    let aad = aad(key_id, key.spec.as_str());
    let ct = cipher
        .encrypt(&nonce, Payload { msg: &plain, aad: &aad })
        .map_err(|_| DaemonError::Config("export encryption failed".into()))?;

    Ok(ExportEnvelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        key_id: key_id.to_string(),
        spec: key.spec.as_str().to_string(),
        created_at: key.created_at,
        kdf: Some(Kdf {
            algo: "argon2id".into(),
            salt: hex::encode(salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }),
        nonce: hex::encode(nonce),
        payload: hex::encode(&ct),
    })
}

/// Produce an UNENCRYPTED export. The artifact is the private key in the clear.
pub fn export_plaintext(key_id: &str, key: &HostedKey) -> Result<ExportEnvelope> {
    Ok(ExportEnvelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        key_id: key_id.to_string(),
        spec: key.spec.as_str().to_string(),
        created_at: key.created_at,
        kdf: None,
        nonce: String::new(),
        payload: hex::encode(serde_json::to_vec(key)?),
    })
}

/// Recover the key from an envelope. `passphrase` must be supplied iff the envelope is encrypted.
pub fn import(envelope: &ExportEnvelope, passphrase: Option<&str>) -> Result<HostedKey> {
    if envelope.kind != ENVELOPE_KIND {
        return Err(DaemonError::Config(format!(
            "not a Rütli key export (kind = {:?})",
            envelope.kind
        )));
    }
    if envelope.v != ENVELOPE_VERSION {
        return Err(DaemonError::Config(format!(
            "unsupported export format version {} (this build reads {ENVELOPE_VERSION})",
            envelope.v
        )));
    }
    let bytes = hex::decode(&envelope.payload)
        .map_err(|e| DaemonError::Config(format!("corrupt export payload: {e}")))?;

    let plain: Zeroizing<Vec<u8>> = match (&envelope.kdf, passphrase) {
        (Some(kdf), Some(pass)) => {
            if kdf.algo != "argon2id" {
                return Err(DaemonError::Config(format!("unsupported export KDF {:?}", kdf.algo)));
            }
            let salt = hex::decode(&kdf.salt)
                .map_err(|e| DaemonError::Config(format!("corrupt export salt: {e}")))?;
            let dek = derive_dek_with(pass, &salt, kdf.m_cost, kdf.t_cost, kdf.p_cost)?;
            let nonce = hex::decode(&envelope.nonce)
                .map_err(|e| DaemonError::Config(format!("corrupt export nonce: {e}")))?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_ref()));
            let aad = aad(&envelope.key_id, &envelope.spec);
            Zeroizing::new(
                cipher
                    .decrypt(Nonce::from_slice(&nonce), Payload { msg: &bytes, aad: &aad })
                    // One opaque error: a wrong passphrase and a tampered artifact are the same
                    // answer to the caller.
                    .map_err(|_| {
                        DaemonError::Config(
                            "could not open the export — wrong passphrase, or the file was altered"
                                .into(),
                        )
                    })?,
            )
        }
        (Some(_), None) => {
            return Err(DaemonError::Config(
                "this export is passphrase-protected — supply it with --passphrase-env".into(),
            ))
        }
        (None, _) => Zeroizing::new(bytes),
    };

    let key: HostedKey = serde_json::from_slice(&plain)?;
    // The header is what an operator reads; if it disagrees with the sealed material, refuse rather
    // than importing something other than what the file claims to be.
    if key.spec.as_str() != envelope.spec {
        return Err(DaemonError::Config(format!(
            "export header says {} but the material is {}",
            envelope.spec,
            key.spec.as_str()
        )));
    }
    Ok(key)
}

fn aad(key_id: &str, spec: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rutli-export-v1");
    for field in [key_id, spec] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

fn derive_dek(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_dek_with(passphrase, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

fn derive_dek_with(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| DaemonError::Config(format!("bad Argon2 parameters: {e}")))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut dek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, dek.as_mut())
        .map_err(|e| DaemonError::Config(format!("key derivation failed: {e}")))?;
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::HostedSpec;

    const PASS: &str = "correct horse battery staple";

    #[test]
    fn an_encrypted_export_round_trips() {
        let key = HostedKey::generate(HostedSpec::Rsa2048, 99).unwrap();
        let ct = key.encrypt_oaep(b"before export").unwrap();

        let env = export_encrypted("rutli-enc-1", &key, PASS).unwrap();
        // The artifact must not contain the key material in the clear.
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains(&key.private_der));
        assert_eq!(env.created_at, 99, "provenance is carried through");

        // Round-trip through JSON, as a real file would.
        let reloaded: ExportEnvelope = serde_json::from_str(&json).unwrap();
        let back = import(&reloaded, Some(PASS)).unwrap();
        assert_eq!(back.decrypt_oaep(&ct).unwrap().as_slice(), b"before export");
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let env = export_encrypted("rutli-sym-1", &key, PASS).unwrap();
        assert!(import(&env, Some("not the passphrase")).is_err());
        assert!(import(&env, None).is_err(), "an encrypted export needs a passphrase");
    }

    #[test]
    fn a_weak_passphrase_is_refused_up_front() {
        // The passphrase is the only protection on a portable private key.
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        assert!(export_encrypted("rutli-sym-1", &key, "short").is_err());
    }

    #[test]
    fn tampering_with_the_artifact_is_detected() {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let mut env = export_encrypted("rutli-sym-1", &key, PASS).unwrap();

        // Flip a byte of ciphertext.
        let mut raw = hex::decode(&env.payload).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        env.payload = hex::encode(&raw);
        assert!(import(&env, Some(PASS)).is_err());
    }

    #[test]
    fn an_artifact_cannot_be_relabelled_to_another_key_id() {
        // The AAD binds the ciphertext to the header, so editing the header to import a key under a
        // different id (or a different spec) fails instead of silently succeeding.
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let mut env = export_encrypted("rutli-sym-original", &key, PASS).unwrap();
        env.key_id = "rutli-sym-impostor".into();
        assert!(import(&env, Some(PASS)).is_err());
    }

    #[test]
    fn a_plaintext_export_round_trips_and_is_marked_unencrypted() {
        let key = HostedKey::generate(HostedSpec::Rsa2048, 5).unwrap();
        let ct = key.encrypt_oaep(b"plaintext path").unwrap();
        let env = export_plaintext("rutli-enc-2", &key).unwrap();
        assert!(env.kdf.is_none(), "a plaintext export must be identifiable as such");

        let back = import(&env, None).unwrap();
        assert_eq!(back.decrypt_oaep(&ct).unwrap().as_slice(), b"plaintext path");
    }

    #[test]
    fn a_foreign_or_future_artifact_is_refused_clearly() {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let mut env = export_plaintext("rutli-sym-1", &key).unwrap();

        let mut wrong_kind = export_plaintext("rutli-sym-1", &key).unwrap();
        wrong_kind.kind = "something-else".into();
        assert!(import(&wrong_kind, None).is_err(), "a mis-pointed --in must say so");

        // A file written by a future build must be refused, not guessed at.
        env.v = ENVELOPE_VERSION + 1;
        assert!(import(&env, None).is_err());
    }
}

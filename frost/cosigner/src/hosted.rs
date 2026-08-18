// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Cluster-hosted (non-FROST) key material: RSA-2048 encryption keypairs and AES-256-GCM
//! symmetric keys.
//!
//! These are **whole keys**, not threshold shares — see `docs/hosted-keys-design.md` for why
//! (short version: no Rust implementation of threshold RSA decryption exists, and the one that
//! would matter for Canton is unfit besides). Each key is generated on one cosigner, replicated to
//! the others, and sealed at rest on every node, so any node can serve a decrypt. The security
//! tier matches the recoverability tier: the non-rotatable namespace key stays in real 2-of-3
//! FROST; these keys — which Canton *can* rotate under that namespace key — get replication.
//!
//! RSA-OAEP runs on **aws-lc-rs** (FIPS-validated, constant-time), deliberately not the pure-Rust
//! `rsa` crate: RUSTSEC-2023-0071 (Marvin timing side-channel, key recovery by a *network*
//! attacker) is still unpatched, and this is a network-facing decryption service — exactly the
//! deployment that advisory warns about.
//!
//! Wire compatibility with Canton: `RsaEsOaepSha256` is RSAES-OAEP with SHA-256 for both the hash
//! and MGF1, and an empty label — which is what BouncyCastle's
//! `RSA/NONE/OAEPWithSHA-256AndMGF1Padding` + `PSource.PSpecified.DEFAULT` produces on the JVM
//! side, and what `OAEP_SHA256_MGF1SHA256` with a `None` label produces here.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{
    KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
    PublicEncryptingKey, OAEP_SHA256_MGF1SHA256,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{DaemonError, Result};

/// RSA-2048 ciphertext/plaintext bounds — Canton's SPI caps asymmetric ciphertext at 256 bytes in
/// and plaintext at 190 out, which is exactly RSA-2048-OAEP-SHA256 (256 − 2·32 − 2).
pub const RSA2048_CIPHERTEXT_LEN: usize = 256;
pub const RSA2048_MAX_PLAINTEXT_LEN: usize = 190;

/// AES-256-GCM symmetric blob framing: `version ‖ nonce(12) ‖ ciphertext‖tag`.
///
/// Versioned deliberately: this blob wraps Canton's encrypted private key store and must stay
/// decryptable for the lifetime of the node, so the format needs an upgrade path. (The driver's
/// older backends wrote a bare `iv ‖ ct` with no version byte and therefore no way to evolve.)
const SYM_FORMAT_V1: u8 = 0x01;
const SYM_NONCE_LEN: usize = 12;

/// What kind of key this is. The string values are the on-disk and on-wire form — never renumber
/// or rename them, they appear in sealed files written by earlier versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostedSpec {
    #[serde(rename = "rsa-2048-oaep-sha256")]
    Rsa2048,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl HostedSpec {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostedSpec::Rsa2048 => "rsa-2048-oaep-sha256",
            HostedSpec::Aes256Gcm => "aes-256-gcm",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "rsa-2048-oaep-sha256" | "rsa2048" => Ok(HostedSpec::Rsa2048),
            "aes-256-gcm" | "aes256-gcm" => Ok(HostedSpec::Aes256Gcm),
            other => Err(DaemonError::Config(format!("unsupported hosted key spec: {other}"))),
        }
    }

    /// Whether this spec has a public half (asymmetric).
    pub fn is_asymmetric(&self) -> bool {
        matches!(self, HostedSpec::Rsa2048)
    }
}

/// A hosted key as stored (sealed) on disk and replicated between cosigners.
///
/// `private_der` is PKCS#8 DER for RSA, or the raw 32-byte key for AES-256. `public_der` is X.509
/// SubjectPublicKeyInfo DER for RSA — exactly the encoding Canton's `PublicKey` expects — and
/// empty for symmetric keys. Both are hex so the record stays plain JSON inside the sealed
/// envelope, matching how FROST shares are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedKey {
    pub spec: HostedSpec,
    pub created_at: u64,
    pub private_der: String,
    #[serde(default)]
    pub public_der: String,
}

impl HostedKey {
    /// Generate a fresh key. RSA-2048 keygen is CPU-heavy (tens to hundreds of ms) — callers on an
    /// async runtime must run this on a blocking thread.
    pub fn generate(spec: HostedSpec, now_secs: u64) -> Result<Self> {
        match spec {
            HostedSpec::Rsa2048 => {
                let sk = PrivateDecryptingKey::generate(KeySize::Rsa2048)
                    .map_err(|e| DaemonError::Config(format!("RSA keygen failed: {e}")))?;
                let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&sk)
                    .map_err(|e| DaemonError::Config(format!("RSA private encode failed: {e}")))?;
                let pk = sk.public_key().clone();
                let spki = AsDer::<PublicKeyX509Der>::as_der(&pk)
                    .map_err(|e| DaemonError::Config(format!("RSA public encode failed: {e}")))?;
                Ok(Self {
                    spec,
                    created_at: now_secs,
                    private_der: hex::encode(pkcs8.as_ref()),
                    public_der: hex::encode(spki.as_ref()),
                })
            }
            HostedSpec::Aes256Gcm => {
                use aes_gcm::aead::rand_core::RngCore;
                let mut key = Zeroizing::new([0u8; 32]);
                aes_gcm::aead::OsRng.fill_bytes(key.as_mut());
                Ok(Self {
                    spec,
                    created_at: now_secs,
                    private_der: hex::encode(key.as_ref()),
                    public_der: String::new(),
                })
            }
        }
    }

    /// X.509 SubjectPublicKeyInfo DER. Errors for symmetric keys, which have no public half.
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        if !self.spec.is_asymmetric() {
            return Err(DaemonError::Config(format!(
                "key spec {} has no public key",
                self.spec.as_str()
            )));
        }
        hex::decode(&self.public_der)
            .map_err(|e| DaemonError::Config(format!("corrupt stored public key: {e}")))
    }

    fn private_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(hex::decode(&self.private_der).map_err(|e| {
            DaemonError::Config(format!("corrupt stored private key material: {e}"))
        })?))
    }

    /// RSAES-OAEP-SHA256 decryption. The **whole** operation happens here, not just the modular
    /// exponentiation: handing raw `c^d mod N` back to the caller to unpad would build a textbook
    /// Bleichenbacher/Manger padding oracle.
    pub fn decrypt_oaep(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.spec != HostedSpec::Rsa2048 {
            return Err(DaemonError::Config(format!(
                "key spec {} cannot perform asymmetric decryption",
                self.spec.as_str()
            )));
        }
        if ciphertext.len() != RSA2048_CIPHERTEXT_LEN {
            return Err(DaemonError::Config(format!(
                "RSA-2048 ciphertext must be {RSA2048_CIPHERTEXT_LEN} bytes, got {}",
                ciphertext.len()
            )));
        }
        let pkcs8 = self.private_bytes()?;
        let sk = PrivateDecryptingKey::from_pkcs8(&pkcs8)
            .map_err(|e| DaemonError::Config(format!("stored RSA key is unusable: {e}")))?;
        let oaep = OaepPrivateDecryptingKey::new(sk)
            .map_err(|e| DaemonError::Config(format!("OAEP init failed: {e}")))?;
        let mut out = Zeroizing::new(vec![0u8; RSA2048_CIPHERTEXT_LEN]);
        let n = oaep
            .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, out.as_mut(), None)
            // Do not surface the library's reason: a distinguishable padding-failure message is
            // itself an oracle. One opaque error for every decryption failure.
            .map_err(|_| DaemonError::DecryptFailed)?
            .len();
        out.truncate(n);
        Ok(out)
    }

    /// Encrypt with this key's public half (used by tests and by the driver's conformance path;
    /// Canton itself encrypts in software with the exported public key).
    pub fn encrypt_oaep(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.spec != HostedSpec::Rsa2048 {
            return Err(DaemonError::Config("not an RSA key".into()));
        }
        if plaintext.len() > RSA2048_MAX_PLAINTEXT_LEN {
            return Err(DaemonError::Config(format!(
                "plaintext exceeds RSA-2048-OAEP capacity ({RSA2048_MAX_PLAINTEXT_LEN} bytes)"
            )));
        }
        let pk = PublicEncryptingKey::from_der(&self.public_key_der()?)
            .map_err(|e| DaemonError::Config(format!("stored RSA public key unusable: {e}")))?;
        let oaep = OaepPublicEncryptingKey::new(pk)
            .map_err(|e| DaemonError::Config(format!("OAEP init failed: {e}")))?;
        let mut out = vec![0u8; RSA2048_CIPHERTEXT_LEN];
        let n = oaep
            .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut out, None)
            .map_err(|e| DaemonError::Config(format!("RSA encryption failed: {e}")))?
            .len();
        out.truncate(n);
        Ok(out)
    }

    /// AES-256-GCM encryption. Output is `0x01 ‖ nonce(12) ‖ ct‖tag`.
    pub fn encrypt_symmetric(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, OsRng};
        use aes_gcm::{AeadCore, Aes256Gcm, Key};

        let key_bytes = self.symmetric_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| DaemonError::Config("symmetric encryption failed".into()))?;
        let mut out = Vec::with_capacity(1 + SYM_NONCE_LEN + ct.len());
        out.push(SYM_FORMAT_V1);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// AES-256-GCM decryption of a blob produced by [`Self::encrypt_symmetric`].
    pub fn decrypt_symmetric(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        if blob.len() < 1 + SYM_NONCE_LEN || blob[0] != SYM_FORMAT_V1 {
            return Err(DaemonError::Config(
                "malformed symmetric ciphertext (bad version or too short)".into(),
            ));
        }
        let key_bytes = self.symmetric_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&blob[1..1 + SYM_NONCE_LEN]);
        let pt = cipher
            .decrypt(nonce, &blob[1 + SYM_NONCE_LEN..])
            .map_err(|_| DaemonError::DecryptFailed)?;
        Ok(Zeroizing::new(pt))
    }

    fn symmetric_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.spec != HostedSpec::Aes256Gcm {
            return Err(DaemonError::Config(format!(
                "key spec {} is not a symmetric key",
                self.spec.as_str()
            )));
        }
        let k = self.private_bytes()?;
        if k.len() != 32 {
            return Err(DaemonError::Config("stored AES key is not 32 bytes".into()));
        }
        Ok(k)
    }
}

/// Seconds since the Unix epoch, for `created_at`.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_roundtrip_and_public_key_shape() {
        let k = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        let spki = k.public_key_der().unwrap();
        assert!(spki.len() > 250, "SPKI DER for RSA-2048 is ~294 bytes, got {}", spki.len());

        let msg = b"canton view session key";
        let ct = k.encrypt_oaep(msg).unwrap();
        assert_eq!(ct.len(), RSA2048_CIPHERTEXT_LEN);
        assert_eq!(k.decrypt_oaep(&ct).unwrap().as_slice(), msg);
    }

    #[test]
    fn rsa_survives_a_serialize_reload_cycle() {
        // The reload path is the whole point of hosting these keys: a restart must not lose them.
        let k = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        let ct = k.encrypt_oaep(b"before restart").unwrap();

        let json = serde_json::to_vec(&k).unwrap();
        let reloaded: HostedKey = serde_json::from_slice(&json).unwrap();
        assert_eq!(reloaded.decrypt_oaep(&ct).unwrap().as_slice(), b"before restart");
    }

    #[test]
    fn rsa_rejects_wrong_length_and_foreign_ciphertext() {
        let k = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        assert!(k.decrypt_oaep(&[0u8; 128]).is_err(), "short ciphertext must be refused");

        // A ciphertext under a different key must fail — and with the opaque error, not a
        // padding-specific one (a distinguishable failure is an oracle).
        let other = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        let ct = other.encrypt_oaep(b"not for you").unwrap();
        assert!(matches!(k.decrypt_oaep(&ct), Err(DaemonError::DecryptFailed)));
    }

    #[test]
    fn rsa_enforces_the_oaep_plaintext_bound() {
        let k = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        assert!(k.encrypt_oaep(&[0u8; RSA2048_MAX_PLAINTEXT_LEN]).is_ok());
        assert!(k.encrypt_oaep(&[0u8; RSA2048_MAX_PLAINTEXT_LEN + 1]).is_err());
    }

    #[test]
    fn symmetric_roundtrip_is_versioned_and_authenticated() {
        let k = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let msg = b"wrapped private key store";
        let blob = k.encrypt_symmetric(msg).unwrap();
        assert_eq!(blob[0], SYM_FORMAT_V1, "framing must carry a version byte");
        assert_eq!(k.decrypt_symmetric(&blob).unwrap().as_slice(), msg);

        // Distinct nonce per call.
        assert_ne!(k.encrypt_symmetric(msg).unwrap(), blob);

        // Tamper anywhere -> authentication failure, not silent garbage.
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(k.decrypt_symmetric(&bad).is_err());

        // Another key cannot read it.
        let other = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        assert!(other.decrypt_symmetric(&blob).is_err());
    }

    #[test]
    fn specs_do_not_cross_over() {
        let rsa = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        let aes = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        assert!(rsa.encrypt_symmetric(b"x").is_err(), "RSA key must not serve symmetric ops");
        assert!(aes.decrypt_oaep(&[0u8; 256]).is_err(), "AES key must not serve RSA ops");
        assert!(aes.public_key_der().is_err(), "symmetric keys have no public half");
    }

    #[test]
    fn spec_names_are_stable_on_disk() {
        // These strings live in sealed files; a rename would orphan existing keys.
        assert_eq!(HostedSpec::Rsa2048.as_str(), "rsa-2048-oaep-sha256");
        assert_eq!(HostedSpec::Aes256Gcm.as_str(), "aes-256-gcm");
        assert_eq!(HostedSpec::parse("rsa-2048-oaep-sha256").unwrap(), HostedSpec::Rsa2048);
        assert_eq!(HostedSpec::parse("aes-256-gcm").unwrap(), HostedSpec::Aes256Gcm);
        assert!(HostedSpec::parse("rsa-4096").is_err());
        let json = serde_json::to_string(&HostedSpec::Rsa2048).unwrap();
        assert_eq!(json, "\"rsa-2048-oaep-sha256\"");
    }
}

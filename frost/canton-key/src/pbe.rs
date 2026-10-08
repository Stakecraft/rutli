// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Canton's password-based encryption, as used by `ExportKeyPair` with a password.
//!
//! Verified against Canton 3.6.1 source (paths under `community/base/src/main/`):
//!
//! - Framing: `UntypedVersionedMessage(version 30)` around
//!   `PasswordBasedEncrypted { bytes ciphertext = 1; SymmetricKeyScheme symmetric_key_scheme = 2;
//!   PbkdfScheme pbkdf_scheme = 3; bytes salt = 4; }`
//!   (`protobuf/.../crypto/v30/crypto.proto:370-389`, wrapper written by
//!   `GrpcVaultService.scala:684-698` via `PasswordBasedEncrypted.toByteString`).
//! - KDF: `PBKDF_SCHEME_ARGON2ID_MODE1 = 1` is Argon2id, m = 12288 KiB, t = 3, p = 1, salt 16 bytes
//!   (`scala/.../crypto/PasswordBasedEncryption.scala:153-167`), run through BouncyCastle's
//!   `Argon2BytesGenerator` with the builder defaults: version 0x13, no secret, no associated data,
//!   password chars converted to UTF-8 (`scala/.../crypto/provider/jce/JcePureCrypto.scala:835-872`).
//!   The output length is the symmetric key size: 16 bytes for AES-128.
//! - Cipher: `SYMMETRIC_KEY_SCHEME_AES128GCM = 1` is AES-128-GCM with a random 12-byte IV prepended
//!   and a 128-bit tag appended, no AAD: `ciphertext = iv(12) ‖ ct ‖ tag(16)`
//!   (`JcePureCrypto.scala:137-143, 232-306`).
//! - Plaintext: the unencrypted `ExportKeyPair` output, i.e. the versioned `CryptoKeyPair` bytes
//!   (`GrpcVaultService.scala:669-697`).
//!
//! Any other scheme id is refused loudly rather than guessed at.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::proto::Msg;
use crate::{Error, Result};

const SYMMETRIC_AES128GCM: u64 = 1;
const PBKDF_ARGON2ID_MODE1: u64 = 1;

/// `PbkdfScheme.Argon2idMode1` (`PasswordBasedEncryption.scala:153-167`). Canton's own comment:
/// "Do not change those parameters, instead add a new mode as a new PBKDF scheme".
const ARGON2_M_KIB: u32 = 12_288;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
const SALT_LEN: usize = 16;

const AES128_KEY_LEN: usize = 16;
const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// A parsed, not yet decrypted `PasswordBasedEncrypted`.
pub(crate) struct PasswordBasedEncrypted<'a> {
    ciphertext: &'a [u8],
    salt: &'a [u8],
}

impl<'a> PasswordBasedEncrypted<'a> {
    /// Strictly parse the inner `PasswordBasedEncrypted` message (already unwrapped from its
    /// `UntypedVersionedMessage`).
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        let m = Msg::parse(buf, "PasswordBasedEncrypted")?;
        m.only(&[1, 2, 3, 4])?;
        let ciphertext = m
            .bytes(1)?
            .ok_or_else(|| Error::Malformed("PasswordBasedEncrypted: no ciphertext".into()))?;
        let symmetric = m.varint(2)?;
        let pbkdf = m.varint(3)?;
        let salt = m.bytes(4)?.unwrap_or_default();

        // Canton refuses UNSPECIFIED (0) for both (`PasswordBasedEncryption.scala:63-67, 169-180`).
        if symmetric != SYMMETRIC_AES128GCM {
            return Err(Error::Unsupported(format!(
                "password-protected export uses symmetric key scheme {symmetric}; only \
                 AES-128-GCM (1) is known"
            )));
        }
        if pbkdf != PBKDF_ARGON2ID_MODE1 {
            return Err(Error::Unsupported(format!(
                "password-protected export uses PBKDF scheme {pbkdf}; only Argon2idMode1 (1) is \
                 known"
            )));
        }
        // Canton validates the salt length against the scheme (`PasswordBasedEncryption.scala:68-78`).
        if salt.len() != SALT_LEN {
            return Err(Error::Malformed(format!(
                "PasswordBasedEncrypted: salt must be {SALT_LEN} bytes, got {}",
                salt.len()
            )));
        }
        if ciphertext.len() < GCM_IV_LEN + GCM_TAG_LEN {
            return Err(Error::Malformed(
                "PasswordBasedEncrypted: ciphertext shorter than IV + tag".into(),
            ));
        }
        Ok(Self { ciphertext, salt })
    }

    /// Derive the key from `password` (UTF-8 bytes, exactly as typed into Canton) and decrypt.
    /// A wrong password and a tampered blob are indistinguishable by design (GCM tag failure).
    pub fn decrypt(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = derive_key(password, self.salt)?;
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key.as_ref()));
        let (iv, ct) = self.ciphertext.split_at(GCM_IV_LEN);
        cipher
            .decrypt(Nonce::from_slice(iv), ct)
            .map(Zeroizing::new)
            .map_err(|_| Error::WrongPasswordOrCorrupt)
    }
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; AES128_KEY_LEN]>> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(AES128_KEY_LEN))
        .map_err(|e| Error::Malformed(format!("Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; AES128_KEY_LEN]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| Error::Malformed(format!("Argon2 key derivation: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pbe(ct: &[u8], sym: u8, kdf: u8, salt: &[u8]) -> Vec<u8> {
        let mut b = vec![0x0a, ct.len() as u8];
        b.extend_from_slice(ct);
        b.extend_from_slice(&[0x10, sym, 0x18, kdf, 0x22, salt.len() as u8]);
        b.extend_from_slice(salt);
        b
    }

    #[test]
    fn unknown_schemes_are_refused_loudly() {
        let ct = [0u8; 40];
        let salt = [7u8; 16];
        assert!(PasswordBasedEncrypted::parse(&pbe(&ct, 1, 1, &salt)).is_ok());
        assert!(matches!(
            PasswordBasedEncrypted::parse(&pbe(&ct, 2, 1, &salt)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            PasswordBasedEncrypted::parse(&pbe(&ct, 1, 2, &salt)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            PasswordBasedEncrypted::parse(&pbe(&ct, 0, 1, &salt)),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn short_salt_and_ciphertext_are_refused() {
        assert!(PasswordBasedEncrypted::parse(&pbe(&[0u8; 40], 1, 1, &[7u8; 8])).is_err());
        assert!(PasswordBasedEncrypted::parse(&pbe(&[0u8; 27], 1, 1, &[7u8; 16])).is_err());
    }
}

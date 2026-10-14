// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Parser for every form in which an existing Canton node's private key can reach Rütli.
//!
//! Migrating a node into a Rütli cluster (docs/roadmap-migration.md, milestones B1–B3, C1) starts
//! with getting its keys out of Canton. This crate turns whatever the operator has into verified
//! key material:
//!
//! | Input | Where it comes from | Entry point |
//! |---|---|---|
//! | Stored key | `common_crypto_private_keys.data` (with `wrapper_key_id` NULL), e.g. from a `pg_dump` | [`parse_stored`], or [`parse`] |
//! | Export | `ExportKeyPair` gRPC / console `keys.secret.download[_to]` | [`parse_export`], or [`parse`] |
//! | Password-protected export | the same with a password | [`parse_export`], or [`parse`] |
//! | PKCS#8 | `-----BEGIN PRIVATE KEY-----` PEM or raw DER, any tool | [`parse_pkcs8`], or [`parse`] |
//!
//! Supported keys: Ed25519 (namespace / protocol / sequencer-auth signing), EC P-256 (signing and
//! ECIES encryption) and RSA-2048 (encryption). Other Canton specs (P-384, secp256k1, ML-DSA) are
//! refused with [`Error::Unsupported`].
//!
//! Every successful parse has **derived the public key from the private material** and checked it
//! against everything the input claims about itself: the Canton `id` (fingerprint) carried in the
//! protobuf, the public key embedded in a SEC1 or PKCS#8 v2 structure, and the declared key spec.
//! Any disagreement is an error, never a warning.
//!
//! # Formats, as verified in Canton 3.6.1 source
//!
//! Paths are relative to `community/base/src/main/` in the Canton repository (tag 3.6.1) unless
//! stated otherwise, and were cross-checked byte-for-byte against keys exported from a real 3.6.1
//! node (`testdata/`).
//!
//! **Versioned wrapper.** Every Canton blob here is an `UntypedVersionedMessage
//! { oneof wrapper { bytes data = 1; } int32 version = 2; }`
//! (`protobuf/.../version/v1/untyped_versioned_message.proto:23-28`), produced by
//! `HasVersionedWrapper.toByteString` (`scala/.../version/HasVersionedWrapper.scala:46-76`).
//! All key messages have exactly one proto version, 30.
//!
//! **Stored key** (`common_crypto_private_keys.data`). Not the bare protobuf, as one might assume:
//! the store writes `privateKey.toByteString(releaseProtocolVersion)`, i.e. the versioned wrapper
//! around `SigningPrivateKey` or `EncryptionPrivateKey`
//! (`scala/.../crypto/store/CryptoPrivateStoreExtended.scala:213-230, 288-303, 388, 414`).
//! The messages (`protobuf/.../crypto/v30/crypto.proto:194-210, 269-282`):
//!
//! ```text
//! SigningPrivateKey    { string id = 1; CryptoKeyFormat format = 2; bytes private_key = 3;
//!                        SigningKeyScheme scheme = 4 [deprecated];
//!                        repeated SigningKeyUsage usage = 5; SigningKeySpec key_spec = 6; }
//! EncryptionPrivateKey { string id = 1; CryptoKeyFormat format = 2; bytes private_key = 3;
//!                        EncryptionKeyScheme scheme = 4 [deprecated]; EncryptionKeySpec key_spec = 5; }
//! ```
//!
//! `id` is the key's Canton fingerprint. `CryptoKeyFormat` (`crypto.proto:347-368`) has five
//! values, not two: DER = 2 (legacy), RAW = 3 (legacy), DER_X509_SPKI = 4 (public keys),
//! **DER_PKCS8_PRIVATE_KEY_INFO = 5**. Canton 3.6.1 generates every private key as format 5
//! (`scala/.../crypto/provider/jce/JcePrivateCrypto.scala:117-131, 165-201, 222-260`) and
//! migrates older RAW Ed25519 and DER EC/RSA keys to it on load (`scala/.../crypto/Signing.scala:
//! 1689-1707`, `Encryption.scala:856-863`). All three are accepted here. See the `asn1` module docs
//! for what is inside the DER for each key spec.
//!
//! **Export** (`ExportKeyPair(fingerprint, protocol_version, password)`,
//! `scala/.../crypto/admin/grpc/GrpcVaultService.scala:584-706`, console
//! `keys.secret.download`, `app-base/.../console/commands/VaultAdministration.scala:484-528`).
//! The versioned wrapper around
//! `CryptoKeyPair { oneof pair { SigningKeyPair signing_key_pair = 1; EncryptionKeyPair
//! encryption_key_pair = 2; } }`, where each pair is `{ reserved 1; <PrivateKey> private_key = 2; }`
//! (`crypto.proto:212-215, 284-287, 322-327`). **The export carries no public key**: field 1 was
//! retired, and Canton re-derives the public key on import (`Signing.scala:1345-1392`). The inner
//! private key is the very same message as the stored form. Export needs preview features enabled
//! on the node (`GrpcVaultService.scala:589-597`).
//!
//! **Password-protected export.** The versioned wrapper around `PasswordBasedEncrypted`, whose
//! plaintext is the plain export above: Argon2id (m = 12 MiB, t = 3, p = 1, 16-byte salt) →
//! AES-128-GCM, `iv(12) ‖ ct ‖ tag(16)`. Details and citations in the `pbe` module.
//!
//! **Fingerprint.** `Fingerprint.create(bytes) = Hash.digest(PublicKeyFingerprint, bytes, Sha256)`
//! (`scala/.../crypto/CryptoKeys.scala:93-98`) with `HashPurpose.PublicKeyFingerprint = 12`
//! (`HashPurpose.scala:63`). The hash is `SHA-256(be_u32(12) ‖ bytes)`
//! (`HashBuilder.scala:192-205`, `Hash.scala:178-181`) rendered as a multihash hex string
//! `"1220" ‖ hex(digest)` (`Hash.scala:108-122`). What `bytes` is depends on the key: for
//! **Ed25519 it is the raw 32-byte public key**, kept for backward compatibility when Ed25519
//! public keys moved from RAW to SPKI (`Signing.scala:1531-1543`, `CryptoKeys.scala:209-220`);
//! for EC P-256 and RSA it is the X.509 SPKI DER. See [`fingerprint`].
//!
//! # Ed25519: seed, not scalar
//!
//! [`PrivateKeyMaterial::Ed25519`] holds the 32-byte **RFC 8032 seed** (BouncyCastle's
//! `Ed25519PrivateKeyParameters.getEncoded`), which is what Canton stores. It is *not* the signing
//! scalar. Anything that needs the scalar — notably the FROST split (B2), whose
//! `frost_ed25519::SigningKey::deserialize` takes a scalar — must expand it: SHA-512(seed), clamp
//! the low half, reduce mod ℓ. This crate deliberately does not do that conversion.
//!
//! # Secret hygiene
//!
//! All secret material is held in [`zeroize::Zeroizing`] containers and wiped on drop, including
//! the decrypted export plaintext and the Argon2 output. [`PrivateKeyMaterial`]'s `Debug` prints no
//! key bytes, and no error message ever contains key bytes. Inputs are borrowed; zeroizing them is
//! the caller's job.
//!
//! # Dependencies
//!
//! Nothing new enters `Cargo.lock`. `ed25519-dalek` derives Ed25519 public keys; `aws-lc-rs`
//! (already the cosigner's RSA engine) validates RSA keys and derives P-256 points; `argon2`,
//! `aes-gcm` and `sha2` implement Canton's PBE and fingerprint; `pkcs8` (RustCrypto, via
//! `ed25519-dalek`) does strict DER; `base64` (via `rcgen`) decodes PEM. Protobuf is read by a
//! small strict reader instead of `prost`, because a conforming protobuf decoder must ignore
//! unknown fields, and for key material that is the wrong default (see the `proto` module).

// The material enum's variants differ in size (an RSA document vs 32 bytes); they are moved rarely
// and boxing them would only add indirection around secrets.
#![allow(clippy::large_enum_variant)]

mod asn1;
mod canton;
mod pbe;
mod proto;

use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors. None of them ever carries key material.
#[derive(Debug, Error)]
pub enum Error {
    /// The input is not a well-formed instance of any accepted format.
    #[error("malformed key input: {0}")]
    Malformed(String),

    /// Well-formed, but a format, algorithm or scheme this crate deliberately does not handle.
    #[error("unsupported key input: {0}")]
    Unsupported(String),

    /// The input is a password-protected export and no password was given.
    #[error("this export is password-protected; supply the password it was exported with")]
    PasswordRequired,

    /// A password was given for an input that is not password-protected. Refused so an operator
    /// never believes an unprotected file was protected.
    #[error("a password was supplied, but this input is not password-protected")]
    NotPasswordProtected,

    /// AES-GCM authentication failed: the password is wrong or the blob was altered. The two are
    /// indistinguishable by design.
    #[error("could not decrypt the export: wrong password, or the file was altered")]
    WrongPasswordOrCorrupt,

    /// The public key derived from the private material disagrees with what the input claims.
    #[error("public key mismatch: {0}")]
    PublicKeyMismatch(String),

    /// The input could be read in more than one way; the caller must disambiguate.
    #[error("ambiguous key input: {0}")]
    Ambiguous(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The key algorithms this crate handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    /// Canton `SigningKeySpec.EcCurve25519`.
    Ed25519,
    /// Canton `SigningKeySpec.EcP256` or `EncryptionKeySpec.EcP256` (ECIES).
    EcP256,
    /// Canton `EncryptionKeySpec.Rsa2048` (RSA-OAEP-SHA256).
    Rsa2048,
}

/// Canton `KeyPurpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    Signing,
    Encryption,
}

/// Canton `SigningKeyUsage` (`crypto.proto:161-173`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningKeyUsage {
    Namespace,
    /// Deprecated in Canton; still accepted on input.
    IdentityDelegation,
    SequencerAuthentication,
    Protocol,
    ProofOfOwnership,
}

impl SigningKeyUsage {
    fn from_proto(v: u64) -> Result<Self> {
        Ok(match v {
            1 => Self::Namespace,
            2 => Self::IdentityDelegation,
            3 => Self::SequencerAuthentication,
            4 => Self::Protocol,
            5 => Self::ProofOfOwnership,
            other => return Err(Error::Unsupported(format!("signing key usage {other}"))),
        })
    }

    /// Canton's `SigningKeyUsage.All` (`Signing.scala:757-763`): what Canton reads a signing key
    /// with an empty usage list as (`fromProtoListWithDefaultV30`, `Signing.scala:874-888`).
    pub const ALL: [Self; 4] =
        [Self::Namespace, Self::SequencerAuthentication, Self::Protocol, Self::ProofOfOwnership];

    /// Canton's name for the usage (`SigningKeyUsage.identifier`, `Signing.scala:816-845`), as the
    /// console prints it. `IdentityDelegation` has none left in Canton; this one is ours.
    pub fn identifier(&self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::IdentityDelegation => "identity-delegation",
            Self::SequencerAuthentication => "sequencer-auth",
            Self::Protocol => "signing",
            Self::ProofOfOwnership => "proof-of-ownership",
        }
    }

    /// The inverse of [`SigningKeyUsage::identifier`].
    pub fn from_identifier(s: &str) -> Option<Self> {
        [
            Self::Namespace,
            Self::IdentityDelegation,
            Self::SequencerAuthentication,
            Self::Protocol,
            Self::ProofOfOwnership,
        ]
        .into_iter()
        .find(|u| u.identifier() == s)
    }
}

/// The `CryptoKeyFormat` the private key bytes were labelled with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoKeyFormat {
    /// `CRYPTO_KEY_FORMAT_DER = 2`: legacy label for PKCS#8 EC and RSA keys.
    LegacyDer,
    /// `CRYPTO_KEY_FORMAT_RAW = 3`: legacy bare 32-byte Ed25519 seed.
    Raw,
    /// `CRYPTO_KEY_FORMAT_DER_PKCS8_PRIVATE_KEY_INFO = 5`: what Canton 3.6.1 writes.
    DerPkcs8,
}

/// Which container the key came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A `common_crypto_private_keys.data` value.
    StoredKey,
    /// `ExportKeyPair` output.
    Export { password_protected: bool },
    /// Plain PKCS#8, PEM or DER. Carries no Canton metadata.
    Pkcs8 { pem: bool },
}

/// The private key itself. `Debug` never prints key bytes.
pub enum PrivateKeyMaterial {
    /// The 32-byte **RFC 8032 seed** — not the signing scalar. See the crate docs.
    Ed25519 { seed: Zeroizing<[u8; 32]> },
    /// The private scalar d, 32 bytes big-endian, 0 < d < n.
    EcP256 { scalar: Zeroizing<[u8; 32]> },
    /// The PKCS#8 v1 `PrivateKeyInfo` DER, validated by aws-lc (2048-bit, e = 65537,
    /// consistent CRT parameters). Ready for `aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8`.
    Rsa2048 { pkcs8_der: Zeroizing<Vec<u8>> },
}

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Ed25519 { .. } => "Ed25519",
            Self::EcP256 { .. } => "EcP256",
            Self::Rsa2048 { .. } => "Rsa2048",
        };
        write!(f, "PrivateKeyMaterial::{name}(<redacted>)")
    }
}

/// A public key, validated (on the curve / well-formed RSA-2048).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// The raw 32-byte Ed25519 public key (RFC 8032 encoding).
    Ed25519([u8; 32]),
    /// The 65-byte uncompressed SEC1 point `0x04 ‖ X ‖ Y`.
    EcP256([u8; 65]),
    /// X.509 SubjectPublicKeyInfo DER.
    Rsa2048 { spki_der: Vec<u8> },
}

impl PublicKey {
    pub fn spec(&self) -> KeySpec {
        match self {
            Self::Ed25519(_) => KeySpec::Ed25519,
            Self::EcP256(_) => KeySpec::EcP256,
            Self::Rsa2048 { .. } => KeySpec::Rsa2048,
        }
    }

    /// X.509 SubjectPublicKeyInfo DER, byte-identical to what Canton stores as the public key
    /// (format `DER_X509_SUBJECT_PUBLIC_KEY_INFO`) and what the KMS driver SPI returns.
    pub fn spki_der(&self) -> Vec<u8> {
        asn1::spki_der(self)
    }

    /// Parse an X.509 SPKI DER (canonical encoding only).
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        asn1::parse_spki(der)
    }

    /// The Canton fingerprint of this key. See [`fingerprint`].
    pub fn fingerprint(&self) -> String {
        fingerprint(self)
    }
}

/// `HashPurpose.PublicKeyFingerprint` (`HashPurpose.scala:63`).
const FINGERPRINT_PURPOSE: u32 = 12;

/// Canton's key fingerprint: `"1220" ‖ hex(SHA-256(be_u32(12) ‖ data))`, where `data` is the raw
/// 32-byte key for Ed25519 and the X.509 SPKI DER for EC P-256 and RSA (`CryptoKeys.scala:93-98,
/// 209-220`, `Signing.scala:1531-1543`, `Hash.scala:108-122, 178-181`). This is the string Canton
/// prints as the key id, and for a namespace key it is the namespace.
pub fn fingerprint(public: &PublicKey) -> String {
    let data = match public {
        PublicKey::Ed25519(pk) => pk.to_vec(),
        other => other.spki_der(),
    };
    let mut h = Sha256::new();
    h.update(FINGERPRINT_PURPOSE.to_be_bytes());
    h.update(&data);
    format!("1220{}", hex::encode(h.finalize()))
}

/// A private key recovered from Canton, with its public half derived and cross-checked.
#[derive(Debug)]
pub struct CantonPrivateKey {
    pub material: PrivateKeyMaterial,
    /// Derived from `material`, never taken from the input.
    pub public: PublicKey,
    /// Known for Canton containers; for plain PKCS#8 only when the algorithm implies it (Ed25519 is
    /// signing-only and RSA encryption-only in Canton; P-256 can be either).
    pub purpose: Option<KeyPurpose>,
    /// Signing usages as recorded by Canton (empty for encryption keys and plain PKCS#8; Canton
    /// itself reads an empty list as "all usages").
    pub usage: Vec<SigningKeyUsage>,
    /// The `id` carried by a Canton container. Always equal to `public.fingerprint()`; a mismatch
    /// fails the parse.
    pub canton_id: Option<String>,
    /// The `CryptoKeyFormat` label of a Canton container.
    pub format: Option<CryptoKeyFormat>,
    pub source: Source,
}

impl CantonPrivateKey {
    pub fn spec(&self) -> KeySpec {
        self.public.spec()
    }

    /// The Canton fingerprint, derived from the private material.
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint()
    }
}

/// Parse any supported input, detecting its kind:
///
/// 1. PEM (`-----BEGIN PRIVATE KEY-----`) → PKCS#8;
/// 2. a DER `SEQUENCE` (first byte `0x30`, which no Canton protobuf here can start with) → PKCS#8;
/// 3. otherwise a Canton protobuf: password-protected export, export, or stored key, told apart by
///    field layout (see `canton::shape`). For a stored key the signing/encryption distinction is
///    made by trying both and requiring exactly one to parse; use [`parse_stored`] with the row's
///    `purpose` to skip that.
///
/// `password` is the export password's UTF-8 bytes. It is required for a password-protected export
/// and refused for every other input.
pub fn parse(input: &[u8], password: Option<&[u8]>) -> Result<CantonPrivateKey> {
    if asn1::looks_like_pem(input) || input.first() == Some(&0x30) {
        refuse_password(password)?;
        return parse_pkcs8(input);
    }
    match proto::untyped_versioned(input) {
        Ok(inner) => match canton::shape(inner)? {
            canton::Shape::PasswordBasedEncrypted => decrypt_export(inner, password),
            canton::Shape::CryptoKeyPair => {
                refuse_password(password)?;
                canton::parse_export_plain(input, Source::Export { password_protected: false })
            }
            canton::Shape::StoredKey => {
                refuse_password(password)?;
                canton::parse_stored(input, None)
            }
        },
        // A well-formed wrapper with a version we do not know: say so.
        Err(e @ Error::Unsupported(_)) => Err(e),
        // Canton's import also accepts a bare, unversioned CryptoKeyPair.
        Err(_) => {
            refuse_password(password)?;
            canton::parse_export_plain(input, Source::Export { password_protected: false })
        }
    }
}

/// Parse `ExportKeyPair` / `keys.secret.download` output, plain or password-protected.
pub fn parse_export(input: &[u8], password: Option<&[u8]>) -> Result<CantonPrivateKey> {
    if let Ok(inner) = proto::untyped_versioned(input) {
        if let canton::Shape::PasswordBasedEncrypted = canton::shape(inner)? {
            return decrypt_export(inner, password);
        }
    }
    refuse_password(password)?;
    canton::parse_export_plain(input, Source::Export { password_protected: false })
}

/// Parse a `common_crypto_private_keys.data` value of an unwrapped row (`wrapper_key_id` NULL).
/// Pass the row's `purpose` column if known (`Some`) to skip auto-detection. A row with a wrapper
/// key is ciphertext under the node's KMS wrapper key and cannot be read here.
pub fn parse_stored(input: &[u8], purpose: Option<KeyPurpose>) -> Result<CantonPrivateKey> {
    canton::parse_stored(input, purpose)
}

/// Parse an unencrypted PKCS#8 private key, PEM (`PRIVATE KEY`) or DER.
pub fn parse_pkcs8(input: &[u8]) -> Result<CantonPrivateKey> {
    let pem = asn1::looks_like_pem(input);
    let der_owned;
    let der: &[u8] = if pem {
        der_owned = asn1::pem_to_der(input)?;
        &der_owned
    } else {
        input
    };
    let (material, public) = asn1::parse_pkcs8(der)?;
    let purpose = match public.spec() {
        KeySpec::Ed25519 => Some(KeyPurpose::Signing),
        KeySpec::Rsa2048 => Some(KeyPurpose::Encryption),
        KeySpec::EcP256 => None,
    };
    Ok(CantonPrivateKey {
        material,
        public,
        purpose,
        usage: Vec::new(),
        canton_id: None,
        format: None,
        source: Source::Pkcs8 { pem },
    })
}

/// A Canton public key as `keys.public.download` writes it.
#[derive(Debug, Clone)]
pub struct CantonPublicKey {
    pub public: PublicKey,
    pub purpose: KeyPurpose,
    pub usage: Vec<SigningKeyUsage>,
}

impl CantonPublicKey {
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint()
    }
}

/// Parse a versioned `SigningPublicKey` / `EncryptionPublicKey` (console `keys.public.download`).
/// Useful to cross-check an imported key against the public key Canton has on record.
pub fn parse_public_key(input: &[u8]) -> Result<CantonPublicKey> {
    let (public, purpose, usage) = canton::parse_public(input)?;
    Ok(CantonPublicKey { public, purpose, usage })
}

fn refuse_password(password: Option<&[u8]>) -> Result<()> {
    match password {
        Some(_) => Err(Error::NotPasswordProtected),
        None => Ok(()),
    }
}

fn decrypt_export(inner: &[u8], password: Option<&[u8]>) -> Result<CantonPrivateKey> {
    let encrypted = pbe::PasswordBasedEncrypted::parse(inner)?;
    let password = password.ok_or(Error::PasswordRequired)?;
    let plain = encrypted.decrypt(password)?;
    canton::parse_export_plain(&plain, Source::Export { password_protected: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_key_bytes() {
        let m = PrivateKeyMaterial::Ed25519 { seed: Zeroizing::new([0xab; 32]) };
        let s = format!("{m:?}");
        assert!(!s.contains("ab") && !s.contains("171"), "{s}");
    }

    #[test]
    fn rfc8032_test_vector_1_fingerprint_input_is_the_raw_key() {
        // RFC 8032 §7.1 TEST 1.
        let seed = Zeroizing::new(asn1_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        let public = asn1::ed25519_public(&seed);
        assert_eq!(hex::encode(public), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let fp = fingerprint(&PublicKey::Ed25519(public));
        assert!(fp.starts_with("1220") && fp.len() == 68);
    }

    fn asn1_hex(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
}

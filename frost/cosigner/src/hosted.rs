// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Cluster-hosted (non-FROST) key material: RSA-2048 encryption keypairs, EC P-256 (ECIES)
//! encryption keypairs and AES-256-GCM symmetric keys.
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
//!
//! **EC P-256 (ECIES, v1.5 in `docs/hosted-keys-design.md`).** The cluster performs only the
//! secret-dependent step of Canton's `EciesHkdfHmacSha256Aes128Cbc`: the static ECDH
//! `Z = x(d·V)` with the sender's ephemeral point `V` ([`HostedKey::ecdh_p256`], served as the
//! `EcdhDerive` RPC). KDF2, AES-128-CBC and HMAC-SHA256 are public computation on `Z` and stay in
//! the driver, inside BouncyCastle's own `IESEngine` — the byte-exact reference implementation of
//! the framing Canton encrypts with. That split is also the v2 wire contract: a threshold P-256 key
//! returns the same `Z` from partial points, so promoting this key type to threshold changes the
//! server side only. ECDH runs on aws-lc-rs (FIPS-validated, constant-time); the peer point is
//! accepted only as a 65-byte uncompressed SEC1 point and must lie on the curve (checked by
//! aws-lc on decode — the uncompressed encoding cannot express the point at infinity).

use aws_lc_rs::agreement::{self, UnparsedPublicKey, ECDH_P256};
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

/// EC P-256 ECDH input and output sizes: the peer's ephemeral public key is accepted only as an
/// uncompressed SEC1 point `0x04 ‖ X ‖ Y` (what BouncyCastle's ECIES writes, and the only form
/// Canton produces), and the shared secret is the 32-byte big-endian x-coordinate of `d·V` — the
/// value BouncyCastle's `ECDHBasicAgreement` yields, padded to the field size as `IESEngine` does.
pub const P256_UNCOMPRESSED_POINT_LEN: usize = 65;
pub const P256_SHARED_SECRET_LEN: usize = 32;

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
    /// An EC P-256 **encryption** key for Canton's ECIES (`EciesHkdfHmacSha256Aes128Cbc`). The
    /// spec names the usage as well as the curve: this key serves `EcdhDerive` and nothing else.
    /// A P-256 *signing* key, should the cluster ever host one, gets its own spec, so ECDH can
    /// never be asked of it.
    #[serde(rename = "ec-p256-ecies")]
    EcP256,
}

impl HostedSpec {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostedSpec::Rsa2048 => "rsa-2048-oaep-sha256",
            HostedSpec::Aes256Gcm => "aes-256-gcm",
            HostedSpec::EcP256 => "ec-p256-ecies",
        }
    }

    /// Every spec this build can generate and serve, in the order `Capabilities` reports them.
    pub const ALL: [HostedSpec; 3] = [HostedSpec::Rsa2048, HostedSpec::Aes256Gcm, HostedSpec::EcP256];

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "rsa-2048-oaep-sha256" | "rsa2048" => Ok(HostedSpec::Rsa2048),
            "aes-256-gcm" | "aes256-gcm" => Ok(HostedSpec::Aes256Gcm),
            "ec-p256-ecies" => Ok(HostedSpec::EcP256),
            other => Err(DaemonError::Config(format!("unsupported hosted key spec: {other}"))),
        }
    }

    /// Whether every cosigner must report this spec before a key of it may be created.
    ///
    /// True for every spec newer than v1 (RSA-2048, AES-256-GCM). A cosigner that predates a spec
    /// cannot parse it: replication to it fails, read-repair on it skips the key, and it answers
    /// `KeyInfo` with "does not exist" — so the leader refuses to create such a key while any peer
    /// does not report the spec (`orchestrator::generate_hosted_key`). v1 specs are exempt: every
    /// released cosigner serves them, and checking them would break a rolling upgrade.
    pub fn needs_every_node(&self) -> bool {
        !matches!(self, HostedSpec::Rsa2048 | HostedSpec::Aes256Gcm)
    }

    /// Whether this spec has a public half (asymmetric).
    pub fn is_asymmetric(&self) -> bool {
        matches!(self, HostedSpec::Rsa2048 | HostedSpec::EcP256)
    }
}

/// A hosted key as stored (sealed) on disk and replicated between cosigners.
///
/// `private_der` is PKCS#8 DER for RSA and EC P-256, or the raw 32-byte key for AES-256.
/// `public_der` is X.509 SubjectPublicKeyInfo DER for RSA and EC P-256 — exactly the encoding
/// Canton's `PublicKey` expects (for P-256: `id-ecPublicKey`, named curve `prime256v1`,
/// uncompressed point, byte-identical to what BouncyCastle writes) — and empty for symmetric keys. Both are hex so the record stays plain JSON inside the sealed
/// envelope, matching how FROST shares are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedKey {
    pub spec: HostedSpec,
    pub created_at: u64,
    pub private_der: String,
    #[serde(default)]
    pub public_der: String,
}

/// Wipe the hex private material when a key goes out of scope, so the many short-lived copies a
/// request makes (load, read-repair, replication) do not linger in freed heap. Best-effort, like
/// every zeroize in a program that also holds the bytes in other forms (serde buffers, aws-lc's own
/// key structures, which aws-lc clears on free).
impl Drop for HostedKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_der.zeroize();
    }
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
            HostedSpec::EcP256 => {
                let sk = agreement::PrivateKey::generate(&ECDH_P256)
                    .map_err(|_| DaemonError::Config("EC P-256 keygen failed".into()))?;
                Self::from_ec_private_key(&sk, now_secs)
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

    /// An EC P-256 hosted key from its private scalar (32 bytes, big-endian, 0 < d < n), e.g. the
    /// scalar of an encryption key exported from Canton. The public half is derived, never taken
    /// from anywhere else.
    pub fn ec_p256_from_scalar(scalar: &[u8], now_secs: u64) -> Result<Self> {
        let sk = agreement::PrivateKey::from_private_key(&ECDH_P256, scalar)
            .map_err(|_| DaemonError::Config("not a valid EC P-256 private scalar".into()))?;
        Self::from_ec_private_key(&sk, now_secs)
    }

    fn from_ec_private_key(sk: &agreement::PrivateKey, now_secs: u64) -> Result<Self> {
        let pkcs8 = AsDer::<Pkcs8V1Der>::as_der(sk)
            .map_err(|_| DaemonError::Config("EC private key encode failed".into()))?;
        let spki = ec_spki(sk)?;
        Ok(Self {
            spec: HostedSpec::EcP256,
            created_at: now_secs,
            private_der: hex::encode(pkcs8.as_ref()),
            public_der: hex::encode(spki),
        })
    }

    /// The stored EC P-256 private key. Refuses every other spec.
    fn ec_private_key(&self) -> Result<agreement::PrivateKey> {
        if self.spec != HostedSpec::EcP256 {
            return Err(DaemonError::Config(format!(
                "key spec {} cannot perform ECDH",
                self.spec.as_str()
            )));
        }
        let der = self.private_bytes()?;
        agreement::PrivateKey::from_private_key_der(&ECDH_P256, &der)
            .map_err(|_| DaemonError::Config("stored EC P-256 key is unusable".into()))
    }

    /// Check that the stored material is internally consistent: for EC P-256, that the stored
    /// public key is the one the private scalar derives. Run on every path that accepts key
    /// material from outside this node (replication, import), so a peer or an artifact can never
    /// pair a private key with somebody else's public key — Canton would then publish a key this
    /// cluster cannot decrypt for. RSA and AES material is checked by its own operations' parsers.
    pub fn validate(&self) -> Result<()> {
        if self.spec == HostedSpec::EcP256 {
            let sk = self.ec_private_key()?;
            if ec_spki(&sk)? != self.public_key_der()? {
                return Err(DaemonError::Config(
                    "EC P-256 key material is inconsistent: the stored public key is not the one \
                     the private key derives"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// The static ECDH of Canton's ECIES: `Z = x(d·V)` for the sender's ephemeral point `V`.
    ///
    /// `peer_point` must be exactly the 65-byte uncompressed SEC1 encoding `0x04 ‖ X ‖ Y`.
    /// Compressed (`0x02`/`0x03`) and hybrid (`0x06`/`0x07`) encodings, SPKI, and anything of
    /// another length are refused here, *before* aws-lc sees them — aws-lc would accept several of
    /// them, and accepting more than Canton produces only widens what an attacker can send. aws-lc
    /// then decodes the point and refuses one that is not on P-256; the uncompressed form cannot
    /// encode the point at infinity, and P-256 has cofactor 1, so every accepted point generates
    /// the full prime-order group (no small-subgroup or invalid-curve leakage of `d`).
    ///
    /// Returns the 32-byte big-endian x-coordinate, the same bytes BouncyCastle's
    /// `ECDHBasicAgreement` + `BigIntegers.asUnsignedByteArray(fieldSize, z)` produce.
    pub fn ecdh_p256(&self, peer_point: &[u8]) -> Result<Zeroizing<[u8; P256_SHARED_SECRET_LEN]>> {
        let sk = self.ec_private_key()?;
        check_uncompressed_p256_point(peer_point)?;
        agreement::agree(
            &sk,
            UnparsedPublicKey::new(&ECDH_P256, peer_point),
            DaemonError::InvalidPoint("the peer point is not on P-256".into()),
            |z| {
                if z.len() != P256_SHARED_SECRET_LEN {
                    return Err(DaemonError::InvalidPoint("unexpected ECDH output length".into()));
                }
                let mut out = Zeroizing::new([0u8; P256_SHARED_SECRET_LEN]);
                out.copy_from_slice(z);
                Ok(out)
            },
        )
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

    /// The public key **derived from the private key** (X.509 SPKI DER), and checked to equal the
    /// stored `public_der`: what `verify-hosted` reports, so a node cannot report a public key its
    /// private key does not have. EC P-256 through [`HostedKey::validate`]; RSA re-derived from its
    /// PKCS#8. Symmetric keys have none.
    pub fn derived_public_key_der(&self) -> Result<Vec<u8>> {
        let stored = self.public_key_der()?;
        let derived = match self.spec {
            HostedSpec::EcP256 => ec_spki(&self.ec_private_key()?)?,
            HostedSpec::Rsa2048 => {
                let sk = PrivateDecryptingKey::from_pkcs8(&self.private_bytes()?)
                    .map_err(|e| DaemonError::Config(format!("stored RSA key is unusable: {e}")))?;
                let pk = sk.public_key().clone();
                AsDer::<PublicKeyX509Der>::as_der(&pk)
                    .map_err(|e| DaemonError::Config(format!("RSA public encode failed: {e}")))?
                    .as_ref()
                    .to_vec()
            }
            HostedSpec::Aes256Gcm => {
                return Err(DaemonError::Config("aes-256-gcm has no public key".into()))
            }
        };
        if derived != stored {
            return Err(DaemonError::Config(format!(
                "{} key material is inconsistent: the stored public key is not the one the private \
                 key derives",
                self.spec.as_str()
            )));
        }
        Ok(derived)
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

/// SPKI DER of an EC P-256 private key's public half.
fn ec_spki(sk: &agreement::PrivateKey) -> Result<Vec<u8>> {
    let pk = sk
        .compute_public_key()
        .map_err(|_| DaemonError::Config("EC public key derivation failed".into()))?;
    let spki = AsDer::<PublicKeyX509Der>::as_der(&pk)
        .map_err(|_| DaemonError::Config("EC public key encode failed".into()))?;
    Ok(spki.as_ref().to_vec())
}

/// The syntactic half of peer-point validation: exactly 65 bytes, uncompressed tag `0x04`. The
/// on-curve half is aws-lc's, in [`HostedKey::ecdh_p256`]. Public so the RPC can refuse a
/// malformed request before charging the key's decryption budget.
pub fn check_uncompressed_p256_point(peer_point: &[u8]) -> Result<()> {
    if peer_point.len() != P256_UNCOMPRESSED_POINT_LEN {
        return Err(DaemonError::InvalidPoint(format!(
            "the peer point must be a {P256_UNCOMPRESSED_POINT_LEN}-byte uncompressed SEC1 point, \
             got {} bytes",
            peer_point.len()
        )));
    }
    if peer_point[0] != 0x04 {
        return Err(DaemonError::InvalidPoint(format!(
            "the peer point must be uncompressed (leading byte 0x04), got 0x{:02x}",
            peer_point[0]
        )));
    }
    Ok(())
}

/// A FROST [`Identifier`] as the small integer the config uses (1..=n).
///
/// Ed25519 identifiers serialize as a **little-endian** scalar (id 2 is `02 00 .. 00`), so the value
/// is in the first two bytes. Cosigner ids come from a `u16` config field, so every other byte must
/// be zero; anything else is not an identifier this crate could have built, and is refused rather
/// than silently truncated.
///
/// Used to key per-node wrapping material off the same numbering as the config roster, and it must
/// agree with the number a peer derives from a certificate CN (`cosigner2` -> 2): a mismatch makes
/// every envelope addressed over gRPC undecryptable by its recipient.
pub fn identifier_index(id: frost_ed25519::Identifier) -> Result<u16> {
    let bytes = id.serialize();
    if bytes.len() < 2 || bytes[2..].iter().any(|&b| b != 0) {
        return Err(DaemonError::Config(
            "FROST identifier does not fit in 16 bits — cosigner ids are 1..=65535".into(),
        ));
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
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
    fn identifier_index_inverts_identifier_try_from() {
        for n in [1u16, 2, 3, 255, 256, 300, u16::MAX] {
            let id = frost_ed25519::Identifier::try_from(n).unwrap();
            assert_eq!(identifier_index(id).unwrap(), n, "id {n} must map back exactly");
        }
        // Distinct nodes must not collapse onto one index (the bug: every node read as 0).
        let a = identifier_index(frost_ed25519::Identifier::try_from(1).unwrap()).unwrap();
        let b = identifier_index(frost_ed25519::Identifier::try_from(2).unwrap()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn identifier_index_refuses_an_identifier_wider_than_16_bits() {
        let wide = frost_ed25519::Identifier::deserialize(&{
            let mut b = [0u8; 32];
            b[0] = 1;
            b[2] = 1; // 65537
            b
        })
        .unwrap();
        assert!(identifier_index(wide).is_err());
    }

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
        assert_eq!(HostedSpec::EcP256.as_str(), "ec-p256-ecies");
        assert_eq!(HostedSpec::parse("ec-p256-ecies").unwrap(), HostedSpec::EcP256);
        assert_eq!(serde_json::to_string(&HostedSpec::EcP256).unwrap(), "\"ec-p256-ecies\"");
        // The curve alone is not a spec: the usage is part of it.
        assert!(HostedSpec::parse("ec-p256").is_err());
        assert!(HostedSpec::parse("ec-p256-ecdsa").is_err());
    }

    // ── EC P-256 / ECIES ────────────────────────────────────────────────────────────────────────
    //
    // Known-answer values from an independent textbook affine P-256 implementation (Python, not
    // aws-lc): d is a fixed test scalar, V = e·G for a fixed e, Z = x(d·V) = x(e·Q). The driver's
    // tests check the same vector on the JVM (JCA ECDH), so all three implementations agree on Z.
    const KAT_D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    const KAT_Q: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
                         7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    const KAT_V: &str = "041f5efe3b2928f7db57c6befca0428a5833ea10b2e70fada8ccf40478c29bbcdb\
                         3a143c9e3f9982325a7750a8b095d0b3feaf12fd01ef6172739b82e9ec62c421";
    const KAT_Z: &str = "605c4045e713174af954ea4740a93c48b42298ab59425be60430752ace33dc1e";
    /// -G: a valid point; d·(-G) = -Q, whose x-coordinate is x(Q).
    const NEG_G: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                         b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a";
    /// The valid point with the smallest x (x = 5)…
    const SMALL_X: &str = "040000000000000000000000000000000000000000000000000000000000000005\
                           459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc";
    /// …and the same point with x written as x + p: a non-reduced field element.
    const SMALL_X_PLUS_P: &str = "04ffffffff00000001000000000000000000000001000000000000000000000004\
                                  459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc";
    /// A point on y² = x³ − 3x (b = 0), the classic invalid-curve-attack input.
    const INVALID_CURVE: &str = "040000000000000000000000000000000000000000000000000000000000000002\
                                 af8bbdfe8cdd5577acbf345b543d28cf402f4e94d3865b97ea0787f2d3aa5d22";

    fn kat_key() -> HostedKey {
        HostedKey::ec_p256_from_scalar(&hex::decode(KAT_D).unwrap(), 1).unwrap()
    }

    fn invalid_point(r: Result<Zeroizing<[u8; 32]>>) -> bool {
        matches!(r, Err(DaemonError::InvalidPoint(_)))
    }

    #[test]
    fn ecdh_matches_an_independent_implementation() {
        let k = kat_key();
        let z = k.ecdh_p256(&hex::decode(KAT_V).unwrap()).unwrap();
        assert_eq!(hex::encode(z.as_ref()), KAT_Z);

        // d·(-G) = -Q: the shared secret is x(Q), which the stored public key carries.
        let z = k.ecdh_p256(&hex::decode(NEG_G).unwrap()).unwrap();
        assert_eq!(hex::encode(z.as_ref()), &KAT_Q[2..66]);

        // A valid point with a tiny x-coordinate is still just a point.
        assert!(k.ecdh_p256(&hex::decode(SMALL_X).unwrap()).is_ok());
    }

    #[test]
    fn the_ec_public_key_is_canton_spki_and_derives_from_the_scalar() {
        let k = kat_key();
        let spki = k.public_key_der().unwrap();
        // Byte-identical to the encoding Canton/BouncyCastle use, as rutli-canton-key builds it.
        let point: [u8; 65] = hex::decode(KAT_Q).unwrap().try_into().unwrap();
        assert_eq!(spki, rutli_canton_key::PublicKey::EcP256(point).spki_der());
        assert_eq!(spki.len(), 91, "P-256 SPKI with a named curve and uncompressed point");
        k.validate().unwrap();
    }

    #[test]
    fn a_generated_ec_key_round_trips_through_serialization() {
        let k = HostedKey::generate(HostedSpec::EcP256, 7).unwrap();
        k.validate().unwrap();
        let json = serde_json::to_vec(&k).unwrap();
        let reloaded: HostedKey = serde_json::from_slice(&json).unwrap();
        // Same key: the same peer point gives the same Z before and after the reload.
        let v = hex::decode(KAT_V).unwrap();
        assert_eq!(k.ecdh_p256(&v).unwrap().as_ref(), reloaded.ecdh_p256(&v).unwrap().as_ref());
        assert_eq!(reloaded.public_key_der().unwrap(), k.public_key_der().unwrap());
        // Two generations are two keys.
        let other = HostedKey::generate(HostedSpec::EcP256, 7).unwrap();
        assert_ne!(other.ecdh_p256(&v).unwrap().as_ref(), k.ecdh_p256(&v).unwrap().as_ref());
    }

    #[test]
    fn ecdh_refuses_every_encoding_but_65_byte_uncompressed() {
        let k = kat_key();
        let v = hex::decode(KAT_V).unwrap();
        // Lengths: empty, SEC1 point at infinity (0x00), compressed, truncated, one byte long, SPKI.
        let mut compressed = vec![if v[64] & 1 == 1 { 0x03 } else { 0x02 }];
        compressed.extend_from_slice(&v[1..33]);
        let mut long = v.clone();
        long.push(0);
        let spki = kat_key().public_key_der().unwrap();
        for bad in [&[][..], &[0x00][..], &compressed, &v[..64], &long, &spki] {
            assert!(invalid_point(k.ecdh_p256(bad)), "{}-byte input must be refused", bad.len());
        }
        // Right length, wrong tag: compressed tags, hybrid tags, infinity tag, garbage.
        for tag in [0x00u8, 0x02, 0x03, 0x05, 0x06, 0x07, 0xff] {
            let mut p = v.clone();
            p[0] = tag;
            assert!(invalid_point(k.ecdh_p256(&p)), "tag 0x{tag:02x} must be refused");
        }
    }

    #[test]
    fn ecdh_refuses_points_that_are_not_on_p256() {
        let k = kat_key();
        let v = hex::decode(KAT_V).unwrap();
        let mut off = v.clone();
        off[64] ^= 1; // y + 1 or y - 1: no longer on the curve
        let mut zero = vec![0u8; 65];
        zero[0] = 0x04; // (0, 0): the "identity as coordinates" encoding
        let mut y_zero = v.clone();
        y_zero[33..].fill(0); // P-256 has no point with y = 0 (prime order, no 2-torsion)
        for (what, bad) in [
            ("off-curve", off),
            ("(0,0)", zero),
            ("y = 0", y_zero),
            ("x + p, non-reduced", hex::decode(SMALL_X_PLUS_P).unwrap()),
            ("invalid curve b = 0", hex::decode(INVALID_CURVE).unwrap()),
            ("all 0xff", [&[0x04u8][..], &[0xffu8; 64][..]].concat()),
        ] {
            assert!(invalid_point(k.ecdh_p256(&bad)), "{what} must be refused");
        }
    }

    #[test]
    fn the_uncompressed_only_gate_is_load_bearing() {
        // aws-lc on its own accepts compressed and hybrid encodings of a valid point. Rütli refuses
        // them before aws-lc sees them: Canton never produces them, and accepting more than Canton
        // produces only widens what an attacker can send.
        let k = kat_key();
        let sk = k.ec_private_key().unwrap();
        let v = hex::decode(KAT_V).unwrap();
        let odd = v[64] & 1 == 1;
        let mut compressed = vec![if odd { 0x03 } else { 0x02 }];
        compressed.extend_from_slice(&v[1..33]);
        let mut hybrid = v.clone();
        hybrid[0] = if odd { 0x07 } else { 0x06 };
        for (what, enc) in [("compressed", compressed), ("hybrid", hybrid)] {
            let z = agreement::agree(
                &sk,
                UnparsedPublicKey::new(&ECDH_P256, &enc),
                (),
                |z| Ok(z.to_vec()),
            );
            assert_eq!(z.map(hex::encode).as_deref(), Ok(KAT_Z), "aws-lc accepts {what}");
            assert!(invalid_point(k.ecdh_p256(&enc)), "Rütli must refuse {what}");
        }
    }

    #[test]
    fn ecdh_is_only_served_by_ec_keys_and_ec_keys_serve_nothing_else() {
        let v = hex::decode(KAT_V).unwrap();
        let rsa = HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap();
        let aes = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        assert!(rsa.ecdh_p256(&v).is_err(), "an RSA key is not an ECDH oracle");
        assert!(aes.ecdh_p256(&v).is_err(), "an AES key is not an ECDH oracle");
        let ec = kat_key();
        assert!(ec.decrypt_oaep(&[0u8; 256]).is_err());
        assert!(ec.encrypt_oaep(b"x").is_err());
        assert!(ec.encrypt_symmetric(b"x").is_err());
        assert!(ec.decrypt_symmetric(&[1u8; 40]).is_err());
    }

    #[test]
    fn validate_catches_a_public_key_that_is_not_the_private_keys() {
        let mut k = kat_key();
        k.public_der = HostedKey::generate(HostedSpec::EcP256, 1).unwrap().public_der.clone();
        assert!(k.validate().is_err());
        let mut k = kat_key();
        k.public_der = String::new();
        assert!(k.validate().is_err());
        // Not a valid scalar: zero, and the group order n itself.
        assert!(HostedKey::ec_p256_from_scalar(&[0u8; 32], 1).is_err());
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        assert!(HostedKey::ec_p256_from_scalar(&n, 1).is_err());
        assert!(HostedKey::ec_p256_from_scalar(&[1u8; 31], 1).is_err(), "wrong length");
    }
}

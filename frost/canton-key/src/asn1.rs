// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! PKCS#8 / SEC1 / SPKI handling and public-key derivation for the three key types Canton's JCE
//! provider can hand us.
//!
//! What Canton 3.6.1 writes (paths under `community/base/src/main/scala/.../crypto/`):
//!
//! - **Ed25519**: a *minimal* PKCS#8 v1 `PrivateKeyInfo` built by hand —
//!   `AlgorithmIdentifier(id-Ed25519)` with no parameters and `privateKey = OCTET STRING(OCTET
//!   STRING(seed))`, where `seed` is BouncyCastle's `Ed25519PrivateKeyParameters.getEncoded`, i.e.
//!   the 32-byte **RFC 8032 seed**, not the clamped scalar (`provider/jce/JcePrivateCrypto.scala:
//!   165-201, 262-283`). Older nodes stored the bare 32-byte seed with format `RAW`, which Canton
//!   migrates to PKCS#8 on load (`Signing.scala:1689-1707`).
//! - **EC P-256** (signing and ECIES encryption): the JCA encoding of a BouncyCastle EC key —
//!   PKCS#8 v1 with `AlgorithmIdentifier(id-ecPublicKey, prime256v1)` around an RFC 5915
//!   `ECPrivateKey { version 1, privateKey OCTET STRING(32), [0] prime256v1, [1] publicKey }`
//!   (`JcePrivateCrypto.scala:105-115, 133-141`; confirmed byte-for-byte on the 3.6.1 vectors).
//! - **RSA-2048**: the JCA PKCS#8 v1 encoding (`rsaEncryption`, NULL parameters, PKCS#1
//!   `RSAPrivateKey` with CRT parameters), e = 65537 (`JcePrivateCrypto.scala:244-251`). Canton's own
//!   import refuses any other exponent and any non-CRT key (`JcePrivateCrypto.scala:364-390`).
//! - Public keys are X.509 `SubjectPublicKeyInfo` DER (format `DER_X509_SUBJECT_PUBLIC_KEY_INFO`).

use aws_lc_rs::agreement::{self, ParsedPublicKey, UnparsedPublicKey, ECDH_P256};
use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::rsa::{PrivateDecryptingKey, PublicEncryptingKey};
use base64::Engine;
use pkcs8::der::asn1::{BitStringRef, Null, OctetStringRef};
use pkcs8::der::{Decode, Reader, SliceReader, TagMode, TagNumber};
use pkcs8::spki::SubjectPublicKeyInfoRef;
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use zeroize::Zeroizing;

use crate::{Error, KeySpec, PrivateKeyMaterial, PublicKey, Result};

const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// DER prefix of an Ed25519 SPKI: `SEQUENCE { SEQUENCE { id-Ed25519 } BIT STRING(0 unused) }`.
const ED25519_SPKI_PREFIX: [u8; 12] = hex_lit(b"302a300506032b6570032100");
/// DER prefix of an uncompressed P-256 SPKI:
/// `SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 } BIT STRING(0 unused, 65 bytes) }`.
const P256_SPKI_PREFIX: [u8; 26] = hex_lit(b"3059301306072a8648ce3d020106082a8648ce3d030107034200");

/// Order n of the P-256 group, big-endian. A private scalar must satisfy 0 < d < n.
const P256_ORDER: [u8; 32] =
    hex_lit(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

const RSA_F4: u32 = 65_537;

const fn hex_lit<const N: usize>(s: &[u8]) -> [u8; N] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex literal"),
        }
    }
    assert!(s.len() == 2 * N, "hex literal length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

fn der_err(what: &str, e: pkcs8::der::Error) -> Error {
    // der errors carry positions and tags only, never content, so they are safe to surface.
    Error::Malformed(format!("{what}: {e}"))
}

/// Parse a PKCS#8 `PrivateKeyInfo` (v1 or v2) holding an Ed25519, P-256 or RSA key, derive the
/// public key from the private material, and check any public key embedded in the structure
/// against it. Trailing bytes after the structure are an error.
pub(crate) fn parse_pkcs8(der: &[u8]) -> Result<(PrivateKeyMaterial, PublicKey)> {
    let pki = PrivateKeyInfo::from_der(der).map_err(|e| der_err("PKCS#8 PrivateKeyInfo", e))?;
    let oid = pki.algorithm.oid;
    let (material, public) = if oid == OID_ED25519 {
        if pki.algorithm.parameters.is_some() {
            return Err(Error::Malformed("Ed25519 AlgorithmIdentifier must not carry parameters (RFC 8410)".into()));
        }
        // CurvePrivateKey ::= OCTET STRING (RFC 8410 §7), itself inside PrivateKeyInfo.privateKey.
        let inner = OctetStringRef::from_der(pki.private_key)
            .map_err(|e| der_err("Ed25519 CurvePrivateKey", e))?;
        let seed = ed25519_seed(inner.as_bytes())?;
        let public = ed25519_public(&seed);
        if let Some(embedded) = pki.public_key {
            if embedded != public.as_slice() {
                return Err(Error::PublicKeyMismatch(
                    "PKCS#8 v2 Ed25519 public key does not match the private seed".into(),
                ));
            }
        }
        (PrivateKeyMaterial::Ed25519 { seed }, PublicKey::Ed25519(public))
    } else if oid == OID_EC_PUBLIC_KEY {
        let curve = pki
            .algorithm
            .parameters_oid()
            .map_err(|_| Error::Malformed("EC AlgorithmIdentifier must name its curve".into()))?;
        if curve != OID_PRIME256V1 {
            return Err(Error::Unsupported(format!("EC curve {curve}; only P-256 (prime256v1) is supported")));
        }
        let (scalar, embedded) = parse_sec1(pki.private_key)?;
        let public = p256_public(&scalar)?;
        for pk in [embedded, pki.public_key].into_iter().flatten() {
            if pk != public.as_slice() {
                return Err(Error::PublicKeyMismatch(
                    "the EC public key embedded in the private key does not match the private scalar".into(),
                ));
            }
        }
        (PrivateKeyMaterial::EcP256 { scalar }, PublicKey::EcP256(public))
    } else if oid == OID_RSA_ENCRYPTION {
        // RFC 8017 A.1: the parameters MUST be NULL.
        match pki.algorithm.parameters {
            Some(p) if p.decode_as::<Null>().is_ok() => {}
            _ => return Err(Error::Malformed("rsaEncryption AlgorithmIdentifier must carry NULL parameters".into())),
        }
        let spki_der = rsa_public_spki(der)?;
        if let Some(embedded) = pki.public_key {
            let spki = SubjectPublicKeyInfoRef::from_der(&spki_der)
                .map_err(|e| der_err("derived RSA SPKI", e))?;
            if Some(embedded) != spki.subject_public_key.as_bytes() {
                return Err(Error::PublicKeyMismatch(
                    "PKCS#8 v2 RSA public key does not match the private key".into(),
                ));
            }
        }
        (
            PrivateKeyMaterial::Rsa2048 { pkcs8_der: Zeroizing::new(der.to_vec()) },
            PublicKey::Rsa2048 { spki_der },
        )
    } else {
        return Err(Error::Unsupported(format!(
            "PKCS#8 algorithm {oid}; supported are Ed25519, EC P-256 and RSA-2048"
        )));
    };
    Ok((material, public))
}

/// Ed25519 seed from exactly 32 bytes.
pub(crate) fn ed25519_seed(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    secret32(bytes).ok_or_else(|| {
        Error::Malformed(format!("Ed25519 private key must be a 32-byte seed, got {} bytes", bytes.len()))
    })
}

/// Copy exactly 32 secret bytes straight into a zeroizing buffer (no intermediate stack array).
fn secret32(bytes: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if bytes.len() != 32 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(bytes);
    Some(out)
}

/// RFC 8032 §5.1.5: the public key is derived from the seed (SHA-512, clamp, multiply).
pub(crate) fn ed25519_public(seed: &Zeroizing<[u8; 32]>) -> [u8; 32] {
    // SigningKey zeroizes itself on drop (ed25519-dalek's default `zeroize` feature).
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A SEC1 private scalar and the public point embedded next to it, if any.
type Sec1Key<'a> = (Zeroizing<[u8; 32]>, Option<&'a [u8]>);

/// RFC 5915 `ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET STRING,
/// parameters [0] ECParameters OPTIONAL, publicKey [1] BIT STRING OPTIONAL }`.
///
/// Returns the 32-byte scalar and the embedded uncompressed public point, if any. The scalar must
/// be exactly 32 bytes: RFC 5915 fixes the length at ceil(log2(n)/8), and BouncyCastle has written
/// it at fixed length for over a decade.
fn parse_sec1(der: &[u8]) -> Result<Sec1Key<'_>> {
    let mut reader = SliceReader::new(der).map_err(|e| der_err("SEC1 ECPrivateKey", e))?;
    let (scalar, public) = reader
        .sequence(|r| {
            let version = u8::decode(r)?;
            let d = OctetStringRef::decode(r)?;
            let params = r.context_specific::<ObjectIdentifier>(TagNumber::N0, TagMode::Explicit)?;
            let public = r.context_specific::<BitStringRef<'_>>(TagNumber::N1, TagMode::Explicit)?;
            Ok((version, d, params, public))
        })
        .and_then(|v| reader.finish(v))
        .map_err(|e| der_err("SEC1 ECPrivateKey", e))
        .and_then(|(version, d, params, public)| {
            if version != 1 {
                return Err(Error::Malformed(format!("SEC1 ECPrivateKey version {version}, expected 1")));
            }
            if let Some(curve) = params {
                if curve != OID_PRIME256V1 {
                    return Err(Error::Malformed(format!(
                        "SEC1 ECPrivateKey names curve {curve}, but the PKCS#8 wrapper says P-256"
                    )));
                }
            }
            let d = d.as_bytes();
            let scalar = secret32(d).ok_or_else(|| {
                Error::Malformed(format!("P-256 private scalar must be 32 bytes, got {}", d.len()))
            })?;
            let public = match public {
                None => None,
                Some(bits) => Some(bits.as_bytes().ok_or_else(|| {
                    Error::Malformed("SEC1 public key BIT STRING has unused bits".into())
                })?),
            };
            Ok((scalar, public))
        })?;
    Ok((scalar, public))
}

/// Q = d·G for P-256, returned as the 65-byte uncompressed SEC1 point.
pub(crate) fn p256_public(scalar: &Zeroizing<[u8; 32]>) -> Result<[u8; 65]> {
    // 0 < d < n, checked explicitly (aws-lc rejects it too; this keeps the guarantee local).
    let s: &[u8; 32] = scalar;
    if s.iter().all(|b| *b == 0) || s >= &P256_ORDER {
        return Err(Error::Malformed("P-256 private scalar is out of range".into()));
    }
    let sk = agreement::PrivateKey::from_private_key(&ECDH_P256, scalar.as_slice())
        .map_err(|_| Error::Malformed("P-256 private scalar rejected".into()))?;
    let pk = sk
        .compute_public_key()
        .map_err(|_| Error::Malformed("P-256 public key derivation failed".into()))?;
    pk.as_ref()
        .try_into()
        .map_err(|_| Error::Malformed("P-256 public key is not a 65-byte uncompressed point".into()))
}

/// Validate an RSA PKCS#8 document with aws-lc (the same library that later serves decryption in
/// the cosigner, `cosigner/src/hosted.rs`), enforce RSA-2048 with e = 65537, and return the X.509
/// SPKI DER of its public half.
fn rsa_public_spki(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    // aws-lc checks the key's internal consistency (RSA_check_key) on load.
    let sk = PrivateDecryptingKey::from_pkcs8(pkcs8_der)
        .map_err(|e| Error::Malformed(format!("RSA private key rejected: {e}")))?;
    if sk.key_size_bits() != 2048 {
        return Err(Error::Unsupported(format!(
            "RSA-{} key; Canton's only RSA spec is RSA-2048",
            sk.key_size_bits()
        )));
    }
    let spki = AsDer::<PublicKeyX509Der>::as_der(&sk.public_key())
        .map_err(|_| Error::Malformed("RSA public key encoding failed".into()))?;
    let spki = spki.as_ref().to_vec();
    if rsa_exponent(&spki)? != RSA_F4 {
        return Err(Error::Unsupported(
            "RSA public exponent is not 65537; Canton refuses such keys".into(),
        ));
    }
    Ok(spki)
}

/// The public exponent of an RSA SPKI, if it fits in a u32.
fn rsa_exponent(spki_der: &[u8]) -> Result<u32> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|e| der_err("RSA SPKI", e))?;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Malformed("RSA SPKI BIT STRING has unused bits".into()))?;
    let mut reader = SliceReader::new(key).map_err(|e| der_err("RSAPublicKey", e))?;
    let e = reader
        .sequence(|r| {
            let _n = pkcs8::der::asn1::UintRef::decode(r)?;
            pkcs8::der::asn1::UintRef::decode(r)
        })
        .and_then(|v| reader.finish(v))
        .map_err(|e| der_err("RSAPublicKey", e))?;
    let bytes = e.as_bytes();
    if bytes.len() > 4 {
        return Err(Error::Unsupported("RSA public exponent larger than 32 bits".into()));
    }
    Ok(bytes.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
}

/// X.509 SPKI DER for a public key, byte-identical to what Canton (BouncyCastle) stores.
pub(crate) fn spki_der(public: &PublicKey) -> Vec<u8> {
    match public {
        PublicKey::Ed25519(pk) => [ED25519_SPKI_PREFIX.as_slice(), pk].concat(),
        PublicKey::EcP256(point) => [P256_SPKI_PREFIX.as_slice(), point].concat(),
        PublicKey::Rsa2048 { spki_der } => spki_der.clone(),
    }
}

/// Parse an X.509 SPKI DER into a validated public key.
pub(crate) fn parse_spki(der: &[u8]) -> Result<PublicKey> {
    let spki = SubjectPublicKeyInfoRef::from_der(der).map_err(|e| der_err("SubjectPublicKeyInfo", e))?;
    let oid = spki.algorithm.oid;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Malformed("SPKI BIT STRING has unused bits".into()))?;
    let public = if oid == OID_ED25519 {
        if spki.algorithm.parameters.is_some() {
            return Err(Error::Malformed("Ed25519 AlgorithmIdentifier must not carry parameters".into()));
        }
        ed25519_public_from_bytes(key)?
    } else if oid == OID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters_oid()
            .map_err(|_| Error::Malformed("EC AlgorithmIdentifier must name its curve".into()))?;
        if curve != OID_PRIME256V1 {
            return Err(Error::Unsupported(format!("EC curve {curve}; only P-256 is supported")));
        }
        p256_public_from_bytes(key)?
    } else if oid == OID_RSA_ENCRYPTION {
        let pk = PublicEncryptingKey::from_der(der)
            .map_err(|e| Error::Malformed(format!("RSA public key rejected: {e}")))?;
        if pk.key_size_bits() != 2048 {
            return Err(Error::Unsupported(format!("RSA-{} public key", pk.key_size_bits())));
        }
        if rsa_exponent(der)? != RSA_F4 {
            return Err(Error::Unsupported("RSA public exponent is not 65537".into()));
        }
        PublicKey::Rsa2048 { spki_der: der.to_vec() }
    } else {
        return Err(Error::Unsupported(format!("public key algorithm {oid}")));
    };
    // Canonical form only: re-encoding must give back the input, so two encodings of one key can
    // never produce two different Canton fingerprints.
    if spki_der(&public) != der {
        return Err(Error::Malformed("SPKI is not in canonical DER form".into()));
    }
    Ok(public)
}

pub(crate) fn ed25519_public_from_bytes(key: &[u8]) -> Result<PublicKey> {
    let arr: [u8; 32] = key
        .try_into()
        .map_err(|_| Error::Malformed(format!("Ed25519 public key must be 32 bytes, got {}", key.len())))?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|_| Error::Malformed("Ed25519 public key is not a valid curve point".into()))?;
    Ok(PublicKey::Ed25519(arr))
}

fn p256_public_from_bytes(key: &[u8]) -> Result<PublicKey> {
    let arr: [u8; 65] = key.try_into().map_err(|_| {
        Error::Malformed(format!("P-256 public key must be a 65-byte uncompressed point, got {} bytes", key.len()))
    })?;
    if arr[0] != 0x04 {
        return Err(Error::Malformed("P-256 public key is not in uncompressed form".into()));
    }
    ParsedPublicKey::try_from(&UnparsedPublicKey::new(&ECDH_P256, arr.as_slice()))
        .map_err(|_| Error::Malformed("P-256 public key is not a valid curve point".into()))?;
    Ok(PublicKey::EcP256(arr))
}

/// Which algorithm a PKCS#8 document holds, without decoding the key itself.
pub(crate) fn pkcs8_spec(der: &[u8]) -> Result<KeySpec> {
    let pki = PrivateKeyInfo::from_der(der).map_err(|e| der_err("PKCS#8 PrivateKeyInfo", e))?;
    match pki.algorithm.oid {
        o if o == OID_ED25519 => Ok(KeySpec::Ed25519),
        o if o == OID_EC_PUBLIC_KEY => Ok(KeySpec::EcP256),
        o if o == OID_RSA_ENCRYPTION => Ok(KeySpec::Rsa2048),
        o => Err(Error::Unsupported(format!("PKCS#8 algorithm {o}"))),
    }
}

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_PKCS8_LABEL: &str = "PRIVATE KEY";

/// Whether `input` looks like PEM (after optional leading whitespace).
pub(crate) fn looks_like_pem(input: &[u8]) -> bool {
    let start = input.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(input.len());
    input[start..].starts_with(PEM_BEGIN.as_bytes())
}

/// Strict single-block RFC 7468 PEM decoding of an unencrypted PKCS#8 `PRIVATE KEY`. Anything
/// outside the one block (other than whitespace) is an error, as are headers and other labels.
pub(crate) fn pem_to_der(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(input).map_err(|_| Error::Malformed("PEM is not valid UTF-8".into()))?;
    let mut lines = text.trim().lines().map(str::trim);
    let first = lines.next().unwrap_or_default();
    let label = first
        .strip_prefix(PEM_BEGIN)
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or_else(|| Error::Malformed("PEM does not start with a BEGIN line".into()))?;
    if label != PEM_PKCS8_LABEL {
        let hint = match label {
            "ENCRYPTED PRIVATE KEY" => "decrypt it first (`openssl pkcs8 -in k.pem -out plain.pem`)",
            "EC PRIVATE KEY" | "RSA PRIVATE KEY" => {
                "convert it to PKCS#8 first (`openssl pkcs8 -topk8 -nocrypt -in k.pem -out plain.pem`)"
            }
            _ => "only unencrypted PKCS#8 \"PRIVATE KEY\" PEM is accepted",
        };
        return Err(Error::Unsupported(format!("PEM label {label:?}: {hint}")));
    }
    let end = format!("-----END {PEM_PKCS8_LABEL}-----");
    let mut body = Zeroizing::new(String::new());
    let mut closed = false;
    for line in lines {
        if closed {
            return Err(Error::Malformed("data after the PEM END line".into()));
        }
        if line == end {
            closed = true;
        } else if line.contains(':') {
            return Err(Error::Malformed("PEM headers are not allowed for PRIVATE KEY".into()));
        } else {
            body.push_str(line);
        }
    }
    if !closed {
        return Err(Error::Malformed("PEM END line missing".into()));
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| Error::Malformed("PEM body is not valid base64".into()))?;
    Ok(Zeroizing::new(der))
}

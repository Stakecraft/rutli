// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Canton's private-key protobuf messages (`crypto/v30/crypto.proto`) and their two containers:
//! the stored row and the `ExportKeyPair` output.

use crate::asn1;
use crate::proto::{self, Msg};
use crate::{
    CantonPrivateKey, CryptoKeyFormat, Error, KeyPurpose, KeySpec, PrivateKeyMaterial, PublicKey,
    Result, SigningKeyUsage, Source,
};

/// The fields shared by `SigningPrivateKey` and `EncryptionPrivateKey`, before key decoding.
struct PrivateKeyMsg<'a> {
    id: &'a str,
    format: u64,
    key: &'a [u8],
    spec: KeySpec,
    purpose: KeyPurpose,
    usage: Vec<SigningKeyUsage>,
}

/// `message SigningPrivateKey { string id = 1; CryptoKeyFormat format = 2; bytes private_key = 3;
/// SigningKeyScheme scheme = 4 [deprecated]; repeated SigningKeyUsage usage = 5;
/// SigningKeySpec key_spec = 6; }` (`crypto.proto:194-210`).
fn signing_private_key(buf: &[u8]) -> Result<PrivateKeyMsg<'_>> {
    let m = Msg::parse(buf, "SigningPrivateKey")?;
    m.only(&[1, 2, 3, 4, 5, 6])?;
    let (id, format, key) = common(&m, "SigningPrivateKey")?;
    // key_spec wins; the deprecated scheme is the fallback for keys written before key_spec
    // existed (`Signing.scala:1048-1062`).
    let spec = match m.varint(6)? {
        1 => KeySpec::Ed25519,
        2 => KeySpec::EcP256,
        3 => return Err(unsupported_signing("EC-P384")),
        4 => return Err(unsupported_signing("EC-secp256k1")),
        5 => return Err(unsupported_signing("ML-DSA-65")),
        0 => match m.varint(4)? {
            1 => KeySpec::Ed25519,
            2 => KeySpec::EcP256,
            3 => return Err(unsupported_signing("EC-DSA-P384 (legacy scheme)")),
            0 => return Err(Error::Malformed("SigningPrivateKey: neither key_spec nor scheme set".into())),
            s => return Err(Error::Unsupported(format!("SigningPrivateKey: unknown legacy scheme {s}"))),
        },
        s => return Err(Error::Unsupported(format!("SigningPrivateKey: unknown key_spec {s}"))),
    };
    let usage = m
        .repeated_varint(5)?
        .into_iter()
        .map(SigningKeyUsage::from_proto)
        .collect::<Result<Vec<_>>>()?;
    Ok(PrivateKeyMsg { id, format, key, spec, purpose: KeyPurpose::Signing, usage })
}

fn unsupported_signing(spec: &str) -> Error {
    Error::Unsupported(format!("signing key spec {spec}; Rütli handles Ed25519 and EC-P256"))
}

/// `message EncryptionPrivateKey { string id = 1; CryptoKeyFormat format = 2;
/// bytes private_key = 3; EncryptionKeyScheme scheme = 4 [deprecated];
/// EncryptionKeySpec key_spec = 5; }` (`crypto.proto:269-282`).
fn encryption_private_key(buf: &[u8]) -> Result<PrivateKeyMsg<'_>> {
    let m = Msg::parse(buf, "EncryptionPrivateKey")?;
    m.only(&[1, 2, 3, 4, 5])?;
    let (id, format, key) = common(&m, "EncryptionPrivateKey")?;
    // `Encryption.scala:321-351`: key_spec, else the deprecated scheme.
    let spec = match m.varint(5)? {
        1 => KeySpec::EcP256,
        2 => KeySpec::Rsa2048,
        0 => match m.varint(4)? {
            1 | 2 => KeySpec::EcP256,
            3 => KeySpec::Rsa2048,
            0 => return Err(Error::Malformed("EncryptionPrivateKey: neither key_spec nor scheme set".into())),
            s => return Err(Error::Unsupported(format!("EncryptionPrivateKey: unknown legacy scheme {s}"))),
        },
        s => return Err(Error::Unsupported(format!("EncryptionPrivateKey: unknown key_spec {s}"))),
    };
    Ok(PrivateKeyMsg { id, format, key, spec, purpose: KeyPurpose::Encryption, usage: Vec::new() })
}

fn common<'a>(m: &Msg<'a>, name: &str) -> Result<(&'a str, u64, &'a [u8])> {
    let id = m.bytes(1)?.unwrap_or_default();
    let id = std::str::from_utf8(id).map_err(|_| Error::Malformed(format!("{name}: id is not UTF-8")))?;
    if id.is_empty() {
        return Err(Error::Malformed(format!("{name}: no id (fingerprint)")));
    }
    let key = m.bytes(3)?.unwrap_or_default();
    if key.is_empty() {
        return Err(Error::Malformed(format!("{name}: no private_key")));
    }
    Ok((id, m.varint(2)?, key))
}

/// Decode the key bytes according to `(spec, format)`, derive the public key, and require the
/// derived Canton fingerprint to equal the message's `id`.
fn decode(msg: PrivateKeyMsg<'_>, source: Source) -> Result<CantonPrivateKey> {
    // `CryptoKeyFormat` (`crypto.proto:347-368`): DER = 2 (legacy, already PKCS#8 for EC/RSA),
    // RAW = 3 (legacy Ed25519 seed), DER_PKCS8_PRIVATE_KEY_INFO = 5 (everything since 3.x).
    // The legacy → PKCS#8 relabelling is `Signing.scala:1689-1707` / `Encryption.scala:856-863`.
    let format = match msg.format {
        2 => CryptoKeyFormat::LegacyDer,
        3 => CryptoKeyFormat::Raw,
        5 => CryptoKeyFormat::DerPkcs8,
        4 => return Err(Error::Malformed("private key labelled as an X.509 public key (format 4)".into())),
        10_000 => return Err(Error::Unsupported("symbolic (test-only) Canton key".into())),
        0 => return Err(Error::Malformed("private key format not set".into())),
        f => return Err(Error::Unsupported(format!("private key format {f}"))),
    };
    let (material, public) = match (msg.spec, format) {
        (KeySpec::Ed25519, CryptoKeyFormat::Raw) => {
            let seed = asn1::ed25519_seed(msg.key)?;
            let public = asn1::ed25519_public(&seed);
            (PrivateKeyMaterial::Ed25519 { seed }, PublicKey::Ed25519(public))
        }
        (KeySpec::Ed25519, CryptoKeyFormat::DerPkcs8)
        | (KeySpec::EcP256 | KeySpec::Rsa2048, CryptoKeyFormat::DerPkcs8 | CryptoKeyFormat::LegacyDer) => {
            let actual = asn1::pkcs8_spec(msg.key)?;
            if actual != msg.spec {
                return Err(Error::Malformed(format!(
                    "key_spec says {:?} but the PKCS#8 document holds {actual:?}",
                    msg.spec
                )));
            }
            asn1::parse_pkcs8(msg.key)?
        }
        (spec, format) => {
            return Err(Error::Unsupported(format!(
                "{spec:?} private key in format {format:?}: Canton never wrote this combination"
            )))
        }
    };
    let derived = public.fingerprint();
    if derived != msg.id {
        return Err(Error::PublicKeyMismatch(format!(
            "the key's id says {} but its private material belongs to {derived}",
            msg.id
        )));
    }
    Ok(CantonPrivateKey {
        material,
        public,
        purpose: Some(msg.purpose),
        usage: msg.usage,
        canton_id: Some(msg.id.to_string()),
        format: Some(format),
        source,
    })
}

/// A stored private key: `UntypedVersionedMessage(30)` around `SigningPrivateKey` or
/// `EncryptionPrivateKey`, as `CryptoPrivateStoreExtended` writes it into
/// `common_crypto_private_keys.data` when `wrapper_key_id` is NULL
/// (`store/CryptoPrivateStoreExtended.scala:226, 303, 388, 414`; reader at `:213, 288`).
///
/// `purpose` is the row's `purpose` column (1 = signing, 2 = encryption). Without it, both message
/// types are tried and exactly one must parse.
pub(crate) fn parse_stored(buf: &[u8], purpose: Option<KeyPurpose>) -> Result<CantonPrivateKey> {
    let inner = proto::untyped_versioned(buf)?;
    let source = Source::StoredKey;
    match purpose.or(signing_by_layout(inner)?) {
        Some(KeyPurpose::Signing) => decode(signing_private_key(inner)?, source),
        Some(KeyPurpose::Encryption) => decode(encryption_private_key(inner)?, source),
        // Layout undecided (legacy keys only): decode both ways. The full decode includes the
        // key-spec-vs-material and fingerprint checks, so a wrong reading cannot survive it.
        None => {
            let as_signing = signing_private_key(inner).and_then(|m| decode(m, source));
            let as_encryption = encryption_private_key(inner).and_then(|m| decode(m, source));
            match (as_signing, as_encryption) {
                (Ok(k), Err(_)) | (Err(_), Ok(k)) => Ok(k),
                (Ok(_), Ok(_)) => Err(Error::Ambiguous(
                    "the stored key decodes as both a signing and an encryption key; pass the \
                     row's purpose"
                        .into(),
                )),
                (Err(se), Err(ee)) => Err(Error::Malformed(format!(
                    "neither a stored signing key ({se}) nor a stored encryption key ({ee})"
                ))),
            }
        }
    }
}

/// Signing vs encryption from the field layout alone, where it is unambiguous: only
/// `SigningPrivateKey` / `SigningPublicKey` have a field 6 (`key_spec`) or a length-delimited
/// field 5 (packed `usage`; scalapb always packs); in the encryption messages field 5 is the varint
/// `key_spec`. Returns `None` when the layout does not decide it (no field 6 and an unpacked or
/// absent field 5), which only legacy or hand-made inputs hit.
fn signing_by_layout(inner: &[u8]) -> Result<Option<KeyPurpose>> {
    let fields = proto::fields(inner, "key")?;
    let signing = fields
        .iter()
        .any(|f| f.number == 6 || (f.number == 5 && matches!(f.value, proto::Value::Bytes(_))));
    Ok(signing.then_some(KeyPurpose::Signing))
}

/// `message CryptoKeyPair { oneof pair { SigningKeyPair signing_key_pair = 1;
/// EncryptionKeyPair encryption_key_pair = 2; } }` with
/// `SigningKeyPair { reserved 1; SigningPrivateKey private_key = 2; }` and the same shape for
/// `EncryptionKeyPair` (`crypto.proto:212-215, 284-287, 322-327`). The public key is no longer
/// exported; Canton re-derives it on import (`Signing.scala:1345-1392`), and so do we.
fn crypto_key_pair(buf: &[u8], source: Source) -> Result<CantonPrivateKey> {
    let m = Msg::parse(buf, "CryptoKeyPair")?;
    m.only(&[1, 2])?;
    let msg = match (m.bytes(1)?, m.bytes(2)?) {
        (Some(pair), None) => signing_private_key(key_pair(pair, "SigningKeyPair")?)?,
        (None, Some(pair)) => encryption_private_key(key_pair(pair, "EncryptionKeyPair")?)?,
        (None, None) => return Err(Error::Malformed("CryptoKeyPair: empty".into())),
        (Some(_), Some(_)) => return Err(Error::Malformed("CryptoKeyPair: both pair kinds set".into())),
    };
    decode(msg, source)
}

fn key_pair<'a>(buf: &'a [u8], name: &'static str) -> Result<&'a [u8]> {
    let m = Msg::parse(buf, name)?;
    if m.bytes(1).map(|b| b.is_some()).unwrap_or(true) {
        return Err(Error::Unsupported(format!(
            "{name} carries the legacy public_key field (1); re-export from Canton 3.5 or later"
        )));
    }
    m.only(&[2])?;
    m.bytes(2)?.ok_or_else(|| Error::Malformed(format!("{name}: no private_key")))
}

/// The plain `ExportKeyPair` output: `UntypedVersionedMessage(30)` around `CryptoKeyPair`
/// (`GrpcVaultService.scala:669-677, 696-697`). Like Canton's own import
/// (`GrpcVaultService.scala:713-728`), a bare unversioned `CryptoKeyPair` is accepted as well.
pub(crate) fn parse_export_plain(buf: &[u8], source: Source) -> Result<CantonPrivateKey> {
    match proto::untyped_versioned(buf) {
        Ok(inner) => crypto_key_pair(inner, source),
        Err(e @ Error::Unsupported(_)) => Err(e),
        Err(versioned_err) => crypto_key_pair(buf, source).map_err(|bare_err| {
            Error::Malformed(format!(
                "not an ExportKeyPair output: as versioned ({versioned_err}), as bare \
                 CryptoKeyPair ({bare_err})"
            ))
        }),
    }
}

/// What a versioned protobuf blob holds, judged from its field layout alone (no crypto):
///
/// - `PasswordBasedEncrypted` is the only one with a *varint* field 3 (`pbkdf_scheme`); in the
///   private-key messages field 3 is the key bytes, and `CryptoKeyPair` has no field 3.
/// - `CryptoKeyPair` is exactly one length-delimited field, number 1 or 2.
/// - Everything else is a stored private key.
pub(crate) enum Shape {
    PasswordBasedEncrypted,
    CryptoKeyPair,
    StoredKey,
}

pub(crate) fn shape(inner: &[u8]) -> Result<Shape> {
    let fields = proto::fields(inner, "versioned payload")?;
    if fields.iter().any(|f| f.number == 3 && matches!(f.value, proto::Value::Varint(_))) {
        return Ok(Shape::PasswordBasedEncrypted);
    }
    if let [f] = fields.as_slice() {
        if matches!(f.number, 1 | 2) && matches!(f.value, proto::Value::Bytes(_)) {
            return Ok(Shape::CryptoKeyPair);
        }
    }
    Ok(Shape::StoredKey)
}

/// Public keys as `keys.public.download` writes them: `UntypedVersionedMessage(30)` around
/// `SigningPublicKey { reserved 1; format = 2; public_key = 3; scheme = 4; usage = 5;
/// key_spec = 6 }` or `EncryptionPublicKey { reserved 1; format = 2; public_key = 3; scheme = 4;
/// key_spec = 5 }` (`crypto.proto:175-192, 253-267`; `VaultAdministration.scala:779-797`).
pub(crate) fn parse_public(buf: &[u8]) -> Result<(PublicKey, KeyPurpose, Vec<SigningKeyUsage>)> {
    let inner = proto::untyped_versioned(buf)?;
    let m = Msg::parse(inner, "public key")?;
    // A public key whose layout does not say "signing" is read as an encryption key; for the
    // undecidable legacy layout the declared-spec-vs-key check below still catches a misreading.
    let signing = signing_by_layout(inner)?.is_some();
    let (purpose, usage, declared) = if signing {
        m.only(&[2, 3, 4, 5, 6])?;
        let usage = m
            .repeated_varint(5)?
            .into_iter()
            .map(SigningKeyUsage::from_proto)
            .collect::<Result<Vec<_>>>()?;
        let declared = match m.varint(6)? {
            0 => None,
            1 => Some(KeySpec::Ed25519),
            2 => Some(KeySpec::EcP256),
            s => return Err(Error::Unsupported(format!("signing public key spec {s}"))),
        };
        (KeyPurpose::Signing, usage, declared)
    } else {
        m.only(&[2, 3, 4, 5])?;
        let declared = match m.varint(5)? {
            0 => None,
            1 => Some(KeySpec::EcP256),
            2 => Some(KeySpec::Rsa2048),
            s => return Err(Error::Unsupported(format!("encryption public key spec {s}"))),
        };
        (KeyPurpose::Encryption, Vec::new(), declared)
    };
    let key = m.bytes(3)?.ok_or_else(|| Error::Malformed("public key: no key bytes".into()))?;
    let public = match m.varint(2)? {
        // DER_X509_SUBJECT_PUBLIC_KEY_INFO, the only format Canton writes since 3.x.
        4 => asn1::parse_spki(key)?,
        // Legacy RAW Ed25519 (`Signing.scala:1455-1462`) and legacy DER, which already was SPKI
        // (`Signing.scala:1464-1467`, `Encryption.scala:704-708`).
        3 => asn1::ed25519_public_from_bytes(key)?,
        2 => asn1::parse_spki(key)?,
        f => return Err(Error::Unsupported(format!("public key format {f}"))),
    };
    if let Some(declared) = declared {
        if declared != public.spec() {
            return Err(Error::Malformed(format!(
                "public key: key_spec says {declared:?} but the key is {:?}",
                public.spec()
            )));
        }
    }
    Ok((public, purpose, usage))
}

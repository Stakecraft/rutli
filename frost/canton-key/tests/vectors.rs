// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Tests against keys exported from a real (throwaway, in-memory) Canton 3.6.1 participant.
//! See testdata/README.md for how they were made.

use std::path::PathBuf;

use base64::Engine;
use rutli_canton_key::{
    parse, parse_export, parse_pkcs8, parse_public_key, parse_stored, CantonPrivateKey,
    CryptoKeyFormat, Error, KeyPurpose, KeySpec, PrivateKeyMaterial, PublicKey, SigningKeyUsage,
    Source,
};

struct Vector {
    name: String,
    fingerprint: String,
    purpose: KeyPurpose,
    spec: KeySpec,
    usage: Vec<SigningKeyUsage>,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/vectors")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn manifest() -> (Vec<Vector>, String) {
    let m: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    let password = m["password"].as_str().unwrap().to_string();
    let keys = m["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| Vector {
            name: k["name"].as_str().unwrap().into(),
            fingerprint: k["fingerprint"].as_str().unwrap().into(),
            purpose: match k["purpose"].as_str().unwrap() {
                "signing" => KeyPurpose::Signing,
                "encryption" => KeyPurpose::Encryption,
                p => panic!("purpose {p}"),
            },
            spec: match k["key_spec"].as_str().unwrap() {
                "EC-Curve25519" => KeySpec::Ed25519,
                "EC-P256" => KeySpec::EcP256,
                "RSA-2048" => KeySpec::Rsa2048,
                s => panic!("spec {s}"),
            },
            usage: {
                let mut u: Vec<_> = k["usage"]
                    .as_str()
                    .unwrap()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| match s {
                        "namespace" => SigningKeyUsage::Namespace,
                        "sequencer-auth" => SigningKeyUsage::SequencerAuthentication,
                        "signing" => SigningKeyUsage::Protocol,
                        "proof-of-ownership" => SigningKeyUsage::ProofOfOwnership,
                        other => panic!("usage {other}"),
                    })
                    .collect();
                u.sort();
                u
            },
        })
        .collect();
    (keys, password)
}

fn vector(name: &str) -> Vector {
    manifest().0.into_iter().find(|v| v.name == name).unwrap()
}

fn password() -> Vec<u8> {
    manifest().1.into_bytes()
}

/// The private material as comparable bytes (test-only; the library never exposes this).
fn secret(k: &CantonPrivateKey) -> Vec<u8> {
    match &k.material {
        PrivateKeyMaterial::Ed25519 { seed } => seed.to_vec(),
        PrivateKeyMaterial::EcP256 { scalar } => scalar.to_vec(),
        PrivateKeyMaterial::Rsa2048 { pkcs8_der } => pkcs8_der.to_vec(),
    }
}

fn check(k: &CantonPrivateKey, v: &Vector) {
    assert_eq!(k.fingerprint(), v.fingerprint, "{}: fingerprint", v.name);
    assert_eq!(k.canton_id.as_deref(), Some(v.fingerprint.as_str()), "{}: id", v.name);
    assert_eq!(k.spec(), v.spec, "{}: spec", v.name);
    assert_eq!(k.purpose, Some(v.purpose), "{}: purpose", v.name);
    let mut usage = k.usage.clone();
    usage.sort();
    assert_eq!(usage, v.usage, "{}: usage", v.name);
    assert_eq!(k.format, Some(CryptoKeyFormat::DerPkcs8), "{}: Canton 3.6.1 writes PKCS#8", v.name);
}

#[test]
fn manifest_covers_every_key_spec_and_the_three_node_keys() {
    let (keys, _) = manifest();
    for spec in [KeySpec::Ed25519, KeySpec::EcP256, KeySpec::Rsa2048] {
        assert!(keys.iter().any(|v| v.spec == spec), "no {spec:?} vector");
    }
    for name in ["namespace", "signing", "sequencer-auth", "encryption"] {
        assert!(keys.iter().any(|v| v.name == name), "no {name} vector");
    }
    assert!(keys.iter().any(|v| v.spec == KeySpec::EcP256 && v.purpose == KeyPurpose::Signing));
    assert!(keys.iter().any(|v| v.spec == KeySpec::EcP256 && v.purpose == KeyPurpose::Encryption));
}

#[test]
fn every_stored_key_parses_and_matches_cantons_fingerprint() {
    for v in manifest().0 {
        let bytes = read(&format!("{}.stored.bin", v.name));
        let explicit = parse_stored(&bytes, Some(v.purpose)).unwrap();
        check(&explicit, &v);
        assert_eq!(explicit.source, Source::StoredKey);

        let auto = parse(&bytes, None).unwrap();
        check(&auto, &v);
        assert_eq!(secret(&auto), secret(&explicit));

        let other = match v.purpose {
            KeyPurpose::Signing => KeyPurpose::Encryption,
            KeyPurpose::Encryption => KeyPurpose::Signing,
        };
        assert!(parse_stored(&bytes, Some(other)).is_err(), "{}: wrong purpose accepted", v.name);
    }
}

#[test]
fn every_export_parses_and_matches_the_stored_key() {
    for v in manifest().0 {
        let stored = parse_stored(&read(&format!("{}.stored.bin", v.name)), None).unwrap();
        let bytes = read(&format!("{}.export.bin", v.name));
        for k in [parse(&bytes, None).unwrap(), parse_export(&bytes, None).unwrap()] {
            check(&k, &v);
            assert_eq!(k.source, Source::Export { password_protected: false });
            assert_eq!(secret(&k), secret(&stored), "{}: export and stored differ", v.name);
        }
        assert!(matches!(parse(&bytes, Some(b"x")), Err(Error::NotPasswordProtected)));
    }
}

#[test]
fn every_password_protected_export_needs_the_right_password() {
    let pw = password();
    for v in manifest().0 {
        let stored = parse_stored(&read(&format!("{}.stored.bin", v.name)), None).unwrap();
        let bytes = read(&format!("{}.export-pw.bin", v.name));

        let k = parse(&bytes, Some(&pw)).unwrap();
        check(&k, &v);
        assert_eq!(k.source, Source::Export { password_protected: true });
        assert_eq!(secret(&k), secret(&stored), "{}: decrypted export differs", v.name);

        assert!(matches!(parse(&bytes, None), Err(Error::PasswordRequired)));
        assert!(matches!(parse_export(&bytes, None), Err(Error::PasswordRequired)));
        assert!(matches!(
            parse(&bytes, Some(b"rutli-test-vector-passwore")),
            Err(Error::WrongPasswordOrCorrupt)
        ));
    }
}

#[test]
fn derived_public_keys_equal_cantons_public_keys() {
    for v in manifest().0 {
        let canton = parse_public_key(&read(&format!("{}.pub.bin", v.name))).unwrap();
        assert_eq!(canton.fingerprint(), v.fingerprint, "{}: our fingerprint of Canton's key", v.name);
        assert_eq!(canton.purpose, v.purpose);
        let mut usage = canton.usage.clone();
        usage.sort();
        assert_eq!(usage, v.usage);

        let ours = parse_stored(&read(&format!("{}.stored.bin", v.name)), None).unwrap();
        assert_eq!(ours.public, canton.public, "{}: derived public key", v.name);
        // Our SPKI encoding is byte-identical to Canton's (BouncyCastle's).
        assert_eq!(ours.public.spki_der(), canton.public.spki_der());
        assert_eq!(PublicKey::from_spki_der(&ours.public.spki_der()).unwrap(), ours.public);
    }
}

// ---- PKCS#8 ----------------------------------------------------------------------------------

/// Pull `private_key` (field 3) out of a stored vector, i.e. the PKCS#8 DER Canton holds.
fn stored_pkcs8(name: &str) -> Vec<u8> {
    let stored = read(&format!("{name}.stored.bin"));
    let inner = proto_field(&stored, 1);
    proto_field(inner, 3).to_vec()
}

fn pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let body: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", body.join("\n"))
}

#[test]
fn plain_pkcs8_der_and_pem_parse_for_every_spec() {
    for v in manifest().0 {
        let der = stored_pkcs8(&v.name);
        let stored = parse_stored(&read(&format!("{}.stored.bin", v.name)), None).unwrap();
        for (input, is_pem) in [(der.clone(), false), (pem(&der).into_bytes(), true)] {
            for k in [parse_pkcs8(&input).unwrap(), parse(&input, None).unwrap()] {
                assert_eq!(k.fingerprint(), v.fingerprint, "{}", v.name);
                assert_eq!(secret(&k), secret(&stored));
                assert_eq!(k.source, Source::Pkcs8 { pem: is_pem });
                assert_eq!(k.canton_id, None);
                let implied = match v.spec {
                    KeySpec::Ed25519 => Some(KeyPurpose::Signing),
                    KeySpec::Rsa2048 => Some(KeyPurpose::Encryption),
                    KeySpec::EcP256 => None,
                };
                assert_eq!(k.purpose, implied);
            }
            assert!(matches!(parse(&input, Some(b"pw")), Err(Error::NotPasswordProtected)));
        }
    }
}

#[test]
fn ed25519_pkcs8_holds_the_rfc8032_seed() {
    // Canton's minimal PKCS#8 for Ed25519 is the RFC 8410 v1 encoding: a fixed 16-byte header,
    // then the 32-byte seed — not a 64-byte expanded key, not a scalar.
    let der = stored_pkcs8("namespace");
    assert_eq!(der.len(), 48);
    assert_eq!(hex::encode(&der[..16]), "302e020100300506032b657004220420");
    let k = parse_pkcs8(&der).unwrap();
    let PrivateKeyMaterial::Ed25519 { seed } = &k.material else { panic!() };
    assert_eq!(&seed[..], &der[16..]);
    // And the seed signs under the namespace key, so it really is the seed (RFC 8032 keygen).
    use ed25519_dalek::{Signer, Verifier};
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let PublicKey::Ed25519(pk) = k.public else { panic!() };
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    vk.verify(b"m", &sk.sign(b"m")).unwrap();
}

#[test]
fn pkcs8_v2_with_a_matching_public_key_is_accepted_and_a_wrong_one_refused() {
    // RFC 8410 OneAsymmetricKey (v2) as OpenSSL 3 / BouncyCastle may write it.
    let seed = &stored_pkcs8("namespace")[16..];
    let pk_ok = match parse_pkcs8(&stored_pkcs8("namespace")).unwrap().public {
        PublicKey::Ed25519(pk) => pk,
        _ => unreachable!(),
    };
    let pk_bad = match parse_pkcs8(&stored_pkcs8("signing")).unwrap().public {
        PublicKey::Ed25519(pk) => pk,
        _ => unreachable!(),
    };
    let v2 = |pk: &[u8; 32]| {
        let mut d = hex::decode("3051020101300506032b657004220420").unwrap();
        d.extend_from_slice(seed);
        d.extend_from_slice(&hex::decode("812100").unwrap());
        d.extend_from_slice(pk);
        d
    };
    assert_eq!(parse_pkcs8(&v2(&pk_ok)).unwrap().fingerprint(), vector("namespace").fingerprint);
    assert!(matches!(parse_pkcs8(&v2(&pk_bad)), Err(Error::PublicKeyMismatch(_))));
}

#[test]
fn sec1_embedded_public_key_must_match_the_scalar() {
    let mut der = stored_pkcs8("encryption");
    let other = match parse_pkcs8(&stored_pkcs8("extra-ecp256-signing")).unwrap().public {
        PublicKey::EcP256(p) => p,
        _ => unreachable!(),
    };
    // The embedded point is the last 65 bytes of the structure.
    let n = der.len();
    der[n - 65..].copy_from_slice(&other);
    assert!(matches!(parse_pkcs8(&der), Err(Error::PublicKeyMismatch(_))));
}

#[test]
fn pkcs8_trailing_bytes_and_truncation_are_refused() {
    for v in manifest().0 {
        let der = stored_pkcs8(&v.name);
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(parse_pkcs8(&trailing).is_err(), "{}: trailing byte", v.name);
        for len in 0..der.len() {
            assert!(parse_pkcs8(&der[..len]).is_err(), "{}: truncated to {len}", v.name);
        }
        let mut p = pem(&der);
        p.push_str("junk\n");
        assert!(parse_pkcs8(p.as_bytes()).is_err(), "{}: data after PEM", v.name);
    }
}

#[test]
fn other_pem_labels_are_refused_with_a_hint() {
    let der = stored_pkcs8("encryption");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    for label in ["ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY", "PUBLIC KEY"] {
        let p = format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n");
        assert!(matches!(parse_pkcs8(p.as_bytes()), Err(Error::Unsupported(_))), "{label}");
    }
}

// ---- Corruption, truncation, legacy forms ----------------------------------------------------

#[test]
fn every_truncation_of_every_container_fails_cleanly() {
    let pw = password();
    for v in manifest().0 {
        for kind in ["stored", "export"] {
            let bytes = read(&format!("{}.{kind}.bin", v.name));
            for len in 0..bytes.len() {
                assert!(parse(&bytes[..len], None).is_err(), "{} {kind} truncated to {len}", v.name);
            }
        }
        // Password-protected: a few cut points (each attempt runs Argon2).
        let bytes = read(&format!("{}.export-pw.bin", v.name));
        for len in [0, 1, 2, 10, bytes.len() / 2, bytes.len() - 20, bytes.len() - 1] {
            assert!(parse(&bytes[..len], Some(&pw)).is_err(), "{} export-pw truncated to {len}", v.name);
        }
    }
}

#[test]
fn trailing_or_unknown_fields_are_refused() {
    for v in manifest().0 {
        for kind in ["stored", "export"] {
            let mut bytes = read(&format!("{}.{kind}.bin", v.name));
            bytes.push(0);
            assert!(parse(&bytes, None).is_err(), "{} {kind}: trailing zero byte", v.name);
            bytes.pop();
            // A well-formed extra field 3 (varint) on the versioned wrapper.
            bytes.extend_from_slice(&[0x18, 0x01]);
            assert!(parse(&bytes, None).is_err(), "{} {kind}: unknown field", v.name);
        }
    }
}

#[test]
fn no_single_bit_flip_yields_a_different_key() {
    // Flipping any bit of a stored or exported key either fails the parse or leaves the key
    // material and its fingerprint untouched (e.g. it turns one usage into another). It can never
    // silently produce a different key.
    for v in manifest().0 {
        for kind in ["stored", "export"] {
            let bytes = read(&format!("{}.{kind}.bin", v.name));
            let reference = parse(&bytes, None).unwrap();
            for i in 0..bytes.len() {
                for bit in 0..8 {
                    let mut b = bytes.clone();
                    b[i] ^= 1 << bit;
                    if let Ok(k) = parse(&b, None) {
                        assert_eq!(k.fingerprint(), reference.fingerprint(), "{} {kind} byte {i} bit {bit}", v.name);
                        assert_eq!(secret(&k), secret(&reference));
                    }
                }
            }
        }
    }
}

#[test]
fn tampering_with_a_password_protected_export_is_detected() {
    let pw = password();
    let bytes = read("namespace.export-pw.bin");
    // Header, IV, middle of the ciphertext, tag, scheme ids and salt.
    let n = bytes.len();
    for i in [3, 8, 60, n - 40, n - 25, n - 22, n - 20, n - 10, n - 1] {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(parse(&b, Some(&pw)).is_err(), "flip at {i} accepted");
    }
}

/// Minimal protobuf encoding helpers for building legacy / doctored messages.
fn enc_len(field: u32, data: &[u8]) -> Vec<u8> {
    let mut out = varint(u64::from(field << 3 | 2));
    out.extend(varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

fn enc_varint(field: u32, v: u64) -> Vec<u8> {
    let mut out = varint(u64::from(field << 3));
    out.extend(varint(v));
    out
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

fn versioned(data: &[u8]) -> Vec<u8> {
    [enc_len(1, data), enc_varint(2, 30)].concat()
}

/// Read a length-delimited field (first occurrence) from a message. Test-only, assumes
/// well-formed input.
fn proto_field(buf: &[u8], want: u32) -> &[u8] {
    let mut pos = 0;
    let rd = |pos: &mut usize| {
        let mut v = 0u64;
        let mut s = 0;
        loop {
            let b = buf[*pos];
            *pos += 1;
            v |= u64::from(b & 0x7f) << s;
            s += 7;
            if b & 0x80 == 0 {
                return v;
            }
        }
    };
    while pos < buf.len() {
        let key = rd(&mut pos);
        match key & 7 {
            0 => {
                rd(&mut pos);
            }
            2 => {
                let len = rd(&mut pos) as usize;
                if (key >> 3) as u32 == want {
                    return &buf[pos..pos + len];
                }
                pos += len;
            }
            w => panic!("wire type {w}"),
        }
    }
    panic!("field {want} not found")
}

fn signing_key_msg(id: &str, format: u64, key: &[u8], usage: &[u64], spec: u64) -> Vec<u8> {
    let packed: Vec<u8> = usage.iter().flat_map(|u| varint(*u)).collect();
    [
        enc_len(1, id.as_bytes()),
        enc_varint(2, format),
        enc_len(3, key),
        enc_len(5, &packed),
        enc_varint(6, spec),
    ]
    .concat()
}

#[test]
fn legacy_raw_ed25519_and_legacy_der_keys_are_accepted() {
    // Pre-3.x nodes stored Ed25519 as a RAW seed (format 3) and EC/RSA PKCS#8 labelled DER (2);
    // Canton migrates them on load (Signing.scala:1689-1707, Encryption.scala:856-863).
    let ns = vector("namespace");
    let seed = &stored_pkcs8("namespace")[16..];
    let raw = versioned(&signing_key_msg(&ns.fingerprint, 3, seed, &[1], 1));
    let k = parse(&raw, None).unwrap();
    assert_eq!(k.fingerprint(), ns.fingerprint);
    assert_eq!(k.format, Some(CryptoKeyFormat::Raw));

    // Legacy deprecated `scheme` instead of key_spec.
    let legacy_scheme = versioned(
        &[enc_len(1, ns.fingerprint.as_bytes()), enc_varint(2, 3), enc_len(3, seed), enc_varint(4, 1), enc_len(5, &[1])]
            .concat(),
    );
    assert_eq!(parse(&legacy_scheme, None).unwrap().fingerprint(), ns.fingerprint);

    let ec = vector("extra-ecp256-signing");
    let der = stored_pkcs8(&ec.name);
    let legacy = versioned(&signing_key_msg(&ec.fingerprint, 2, &der, &[4, 5], 2));
    let k = parse(&legacy, None).unwrap();
    assert_eq!(k.fingerprint(), ec.fingerprint);
    assert_eq!(k.format, Some(CryptoKeyFormat::LegacyDer));

    let rsa = vector("extra-rsa2048-encryption");
    let der = stored_pkcs8(&rsa.name);
    let msg = [enc_len(1, rsa.fingerprint.as_bytes()), enc_varint(2, 2), enc_len(3, &der), enc_varint(5, 2)].concat();
    let k = parse_stored(&versioned(&msg), Some(KeyPurpose::Encryption)).unwrap();
    assert_eq!(k.fingerprint(), rsa.fingerprint);
}

#[test]
fn a_wrong_id_is_a_public_key_mismatch() {
    // The id (fingerprint) is the only public-key claim an export carries; it must match.
    let ns = vector("namespace");
    let other = vector("signing");
    let der = stored_pkcs8("namespace");
    let doctored = versioned(&signing_key_msg(&other.fingerprint, 5, &der, &[1], 1));
    assert!(matches!(parse(&doctored, None), Err(Error::PublicKeyMismatch(_))));
    // Sanity: the same message with the right id parses.
    let good = versioned(&signing_key_msg(&ns.fingerprint, 5, &der, &[1], 1));
    assert_eq!(parse(&good, None).unwrap().fingerprint(), ns.fingerprint);
}

#[test]
fn key_spec_must_match_the_key_material() {
    let ns = vector("namespace");
    let der = stored_pkcs8("namespace");
    // Ed25519 material labelled EC-P256.
    let wrong = versioned(&signing_key_msg(&ns.fingerprint, 5, &der, &[1], 2));
    assert!(parse(&wrong, None).is_err());
    // Ed25519 PKCS#8 labelled with the legacy DER format (Canton never wrote that).
    let wrong = versioned(&signing_key_msg(&ns.fingerprint, 2, &der, &[1], 1));
    assert!(matches!(parse(&wrong, None), Err(Error::Unsupported(_))));
    // Unsupported specs are refused, not mis-parsed.
    for spec in [3, 4, 5, 99] {
        let wrong = versioned(&signing_key_msg(&ns.fingerprint, 5, &der, &[1], spec));
        assert!(matches!(parse(&wrong, None), Err(Error::Unsupported(_))), "spec {spec}");
    }
}

#[test]
fn unknown_versions_and_formats_are_refused() {
    let ns = vector("namespace");
    let der = stored_pkcs8("namespace");
    let msg = signing_key_msg(&ns.fingerprint, 5, &der, &[1], 1);
    let v31 = [enc_len(1, &msg), enc_varint(2, 31)].concat();
    assert!(matches!(parse(&v31, None), Err(Error::Unsupported(_))));
    for format in [0, 1, 4, 6, 10_000] {
        let m = versioned(&signing_key_msg(&ns.fingerprint, format, &der, &[1], 1));
        assert!(parse(&m, None).is_err(), "format {format}");
    }
}

#[test]
fn unknown_password_schemes_are_refused_loudly() {
    // Rebuild the namespace export's PasswordBasedEncrypted with a different scheme id.
    let bytes = read("namespace.export-pw.bin");
    let pbe = proto_field(&bytes, 1);
    let ct = proto_field(pbe, 1);
    let salt = proto_field(pbe, 4);
    for (sym, kdf) in [(2, 1), (1, 2), (0, 1), (1, 0)] {
        let m = versioned(&[enc_len(1, ct), enc_varint(2, sym), enc_varint(3, kdf), enc_len(4, salt)].concat());
        assert!(matches!(parse(&m, Some(&password())), Err(Error::Unsupported(_))), "{sym}/{kdf}");
    }
    // And the unmodified rebuild still decrypts, so the test exercises the scheme check only.
    let m = versioned(&[enc_len(1, ct), enc_varint(2, 1), enc_varint(3, 1), enc_len(4, salt)].concat());
    assert_eq!(parse(&m, Some(&password())).unwrap().fingerprint(), vector("namespace").fingerprint);
}

#[test]
fn a_bare_unversioned_crypto_key_pair_is_accepted_like_canton_does() {
    // GrpcVaultService.scala:713-728 falls back to a bare CryptoKeyPair.
    let bytes = read("signing.export.bin");
    let bare = proto_field(&bytes, 1);
    let k = parse(bare, None).unwrap();
    assert_eq!(k.fingerprint(), vector("signing").fingerprint);
}

// ---- The parsed material is usable by its consumers (B3, C1) ---------------------------------

#[test]
fn rsa_material_decrypts_what_cantons_public_key_encrypts() {
    use aws_lc_rs::rsa::{
        OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
        PublicEncryptingKey, OAEP_SHA256_MGF1SHA256,
    };
    let canton = parse_public_key(&read("extra-rsa2048-encryption.pub.bin")).unwrap();
    let pk = PublicEncryptingKey::from_der(&canton.public.spki_der()).unwrap();
    let mut buf = vec![0u8; 256];
    let ct = OaepPublicEncryptingKey::new(pk)
        .unwrap()
        .encrypt(&OAEP_SHA256_MGF1SHA256, b"view key", &mut buf, None)
        .unwrap()
        .to_vec();

    let k = parse(&read("extra-rsa2048-encryption.export-pw.bin"), Some(&password())).unwrap();
    let PrivateKeyMaterial::Rsa2048 { pkcs8_der } = &k.material else { panic!() };
    let sk = OaepPrivateDecryptingKey::new(PrivateDecryptingKey::from_pkcs8(pkcs8_der).unwrap())
        .unwrap();
    let mut out = vec![0u8; 256];
    let pt = sk.decrypt(&OAEP_SHA256_MGF1SHA256, &ct, &mut out, None).unwrap();
    assert_eq!(pt, b"view key");
}

#[test]
fn ecies_scalar_agrees_with_cantons_public_point() {
    use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey, ECDH_P256};
    let canton = parse_public_key(&read("encryption.pub.bin")).unwrap();
    let PublicKey::EcP256(point) = canton.public else { panic!() };

    let k = parse(&read("encryption.stored.bin"), None).unwrap();
    let PrivateKeyMaterial::EcP256 { scalar } = &k.material else { panic!() };
    let ours = PrivateKey::from_private_key(&ECDH_P256, scalar.as_slice()).unwrap();

    let eph = PrivateKey::generate(&ECDH_P256).unwrap();
    let eph_pub = eph.compute_public_key().unwrap();
    let z1 = agree(&eph, UnparsedPublicKey::new(&ECDH_P256, point), (), |z| Ok(z.to_vec()))
        .unwrap();
    let z2 = agree(&ours, UnparsedPublicKey::new(&ECDH_P256, eph_pub.as_ref()), (), |z| {
        Ok(z.to_vec())
    })
    .unwrap();
    assert_eq!(z1, z2);
}

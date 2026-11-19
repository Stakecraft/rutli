// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Property tests for public-key encodings and Canton fingerprints (issue #121): an SPKI DER
//! round-trips, only its canonical encoding parses, and the fingerprint is a pure function of the
//! key with one spelling.

use proptest::prelude::*;
use rutli_canton_key::{fingerprint, PublicKey};
use sha2::{Digest, Sha256};

/// `cases` per test, unless `PROPTEST_CASES` is set (a longer local run).
fn config(cases: u32) -> ProptestConfig {
    let mut c = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        c.cases = cases;
    }
    c.failure_persistence = None;
    c
}

fn ed25519_public(seed: [u8; 32]) -> PublicKey {
    PublicKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

/// A P-256 public key from a scalar, or `None` for a scalar out of range.
fn p256_public(scalar: [u8; 32]) -> Option<PublicKey> {
    use aws_lc_rs::agreement::{PrivateKey, ECDH_P256};
    let private = PrivateKey::from_private_key(&ECDH_P256, &scalar).ok()?;
    let public = private.compute_public_key().ok()?;
    Some(PublicKey::EcP256(public.as_ref().try_into().ok()?))
}

fn public_key() -> impl Strategy<Value = PublicKey> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(ed25519_public),
        any::<[u8; 32]>().prop_filter_map("P-256 scalar out of range", p256_public),
    ]
}

proptest! {
    #![proptest_config(config(128))]

    /// SPKI DER → key → SPKI DER is the identity, and the fingerprint survives it.
    #[test]
    fn spki_der_round_trips(key in public_key()) {
        let der = key.spki_der();
        let back = PublicKey::from_spki_der(&der).unwrap();
        prop_assert_eq!(&back, &key);
        prop_assert_eq!(back.spki_der(), der);
        prop_assert_eq!(back.fingerprint(), key.fingerprint());
    }

    /// Only the canonical encoding parses: trailing bytes, a truncated encoding, or a changed
    /// length byte are refused (or, for a byte inside the key itself, parse to another key).
    #[test]
    fn only_canonical_spki_der_parses(
        key in public_key(),
        trailing in prop::collection::vec(any::<u8>(), 1..4),
        cut in any::<prop::sample::Index>(),
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let der = key.spki_der();
        let mut longer = der.clone();
        longer.extend_from_slice(&trailing);
        prop_assert!(PublicKey::from_spki_der(&longer).is_err());
        let short = &der[..cut.index(der.len())];
        prop_assert!(PublicKey::from_spki_der(short).is_err());
        let mut changed = der.clone();
        changed[at.index(der.len())] ^= xor;
        if let Ok(other) = PublicKey::from_spki_der(&changed) {
            prop_assert_ne!(&other, &key);
            prop_assert_eq!(other.spki_der(), changed);
        }
    }

    /// The fingerprint is `1220` ‖ hex(SHA-256(be_u32(12) ‖ data)), lower-case, 68 characters,
    /// where data is the raw key for Ed25519 and the SPKI DER otherwise.
    #[test]
    fn fingerprints_follow_cantons_formula(key in public_key()) {
        let data = match &key {
            PublicKey::Ed25519(raw) => raw.to_vec(),
            other => other.spki_der(),
        };
        let mut h = Sha256::new();
        h.update(12u32.to_be_bytes());
        h.update(&data);
        let expected = format!("1220{}", hex::encode(h.finalize()));
        let fp = fingerprint(&key);
        prop_assert_eq!(&fp, &expected);
        prop_assert_eq!(fp.len(), 68);
        prop_assert!(fp.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    /// Different keys have different fingerprints.
    #[test]
    fn different_keys_have_different_fingerprints(a in public_key(), b in public_key()) {
        prop_assert_eq!(a == b, fingerprint(&a) == fingerprint(&b));
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Trusted-dealer split of an **existing** Ed25519 key into FROST shares — migration only.
//!
//! DKG ([`crate::dkg`]) is the default and the recommended way to get a key into a cluster: the
//! key is born distributed and never exists whole. This module exists for one job, milestone B2 of
//! docs/roadmap-migration.md: moving a Canton key that already exists (an existing node's namespace
//! key) into a cluster without changing it, so the namespace and every party ID survive. A dealt
//! key is **strictly weaker** than a DKG key — it existed whole on the old node, in its database
//! and in every backup of it, and once more in the dealer's memory here. Splitting it protects the
//! future (no single cosigner can sign, loss of one share is survivable); it cannot un-expose the
//! past. The runbook (docs/split-ceremony.md) says so plainly and covers destroying the old copies.
//!
//! # Seed, not scalar
//!
//! Canton stores an Ed25519 key as its 32-byte RFC 8032 **seed**. The signing scalar is derived
//! from it: `a = clamp(SHA-512(seed)[0..32]) mod ℓ` (RFC 8032 §5.1.5). FROST shares the scalar, so
//! the seed must be expanded first, here with ed25519-dalek's own expansion
//! ([`ed25519_dalek::SigningKey::to_scalar`]) — the same code that derives the public key Canton
//! fingerprints. Two tempting shortcuts are wrong:
//!
//! - `frost_ed25519::SigningKey::deserialize(seed)` treats the seed as the scalar and splits a
//!   *different* key (or is refused when the seed is not a canonical scalar);
//! - deserializing the clamped bytes is always refused: clamping sets bit 254, so the value is
//!   never below ℓ ≈ 2^252 and `from_canonical_bytes` rejects it.
//!
//! The tests pin both traps. [`split_ed25519_seed`] never trusts the conversion: it checks that
//! the group verifying key it produced is byte-equal to the public key derived from the seed.
//!
//! # What a split guarantees before it returns
//!
//! 1. The group verifying key equals the seed's Ed25519 public key, byte for byte.
//! 2. Every share passes VSS verification against the one commitment all shares carry, has
//!    `min_signers == t`, and its verifying share is the one in the public key package.
//! 3. The public key package is internally consistent ([`check_public_key_package`]).
//! 4. Every `t`-subset of shares reconstructs exactly the original scalar.
//! 5. Every `t`-subset produces a FROST signature over a Canton-shaped 34-byte message that
//!    `ed25519_dalek::VerifyingKey::verify_strict` accepts under the original public key.
//!
//! Signatures from a dealt key are format-identical RFC 8032 signatures, not value-identical ones:
//! FROST's nonce is random, RFC 8032's is derived from the message, so the same message signs to a
//! different (equally valid) signature.
//!
//! # Secret hygiene
//!
//! [`SecretShare`]s and [`KeyPackage`]s built during the checks are zeroized explicitly. The
//! scalars inside FROST's types are `Copy`, so copies can outlive any wipe; the dealer therefore
//! runs as its own short-lived process (`rutli-dealer`) with core dumps and ptrace disabled, and
//! that process isolation is the real control.

use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519 as frost;
use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage, SecretShare};
use frost::{Ed25519Group, Ed25519ScalarField, Field, Group, Identifier, SigningPackage};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{CoreError, Result};

/// Largest cluster a split is done for. The checks visit every `t`-subset, so this bounds the work;
/// it is far above any real cosigner cluster.
pub const MAX_SIGNERS: usize = 16;

/// The FROST signing key for an RFC 8032 seed: SHA-512, clamp, reduce mod ℓ (ed25519-dalek's own
/// expansion). See the module docs for why this is not `SigningKey::deserialize(seed)`.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> Result<frost::SigningKey> {
    let dalek = ed25519_dalek::SigningKey::from_bytes(seed); // zeroized on drop
    Ok(frost::SigningKey::from_scalar(dalek.to_scalar())?)
}

/// The raw 32-byte RFC 8032 public key of a seed — what Canton fingerprints for an Ed25519 key.
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A Canton-shaped 34-byte message, `0x12 0x20 ‖ SHA-256(label)` (docs/wire-contract.md), for
/// self-test and verification signatures. The cosigners refuse to sign any other length.
pub fn canton_test_message(label: &[u8]) -> [u8; 34] {
    let mut out = [0u8; 34];
    out[0] = 0x12;
    out[1] = 0x20;
    out[2..].copy_from_slice(&Sha256::digest(label));
    out
}

/// SHA-256 of the public key package's canonical (postcard) serialization. Cosigners and operators
/// compare this to agree they hold the same sharing without exchanging the package itself.
pub fn pkp_digest(pkp: &PublicKeyPackage) -> Result<[u8; 32]> {
    Ok(Sha256::digest(pkp.serialize()?).into())
}

/// Split the Ed25519 key behind `seed` into `ids.len()` FROST shares with threshold `t`, one per
/// identifier in `ids` (the cosigners' configured `identifier` values), in the order of `ids`.
///
/// Every guarantee in the module docs is checked before this returns; on any failure nothing is
/// returned and the shares are wiped.
pub fn split_ed25519_seed(
    seed: &[u8; 32],
    ids: &[u16],
    t: u16,
) -> Result<(Vec<SecretShare>, PublicKeyPackage)> {
    let identifiers = roster(ids, t)?;
    let expected_public = public_key_from_seed(seed);
    let signing_key = signing_key_from_seed(seed)?;

    let (mut by_id, pkp) = frost::keys::split(
        &signing_key,
        ids.len() as u16,
        t,
        IdentifierList::Custom(&identifiers),
        &mut OsRng,
    )?;
    let mut shares = Vec::with_capacity(identifiers.len());
    for id in &identifiers {
        match by_id.remove(id) {
            Some(share) => shares.push(share),
            None => {
                wipe(&mut shares);
                return Err(CoreError::Dealer("split did not produce a share for every id".into()));
            }
        }
    }

    if let Err(e) = verify_split(&signing_key, &expected_public, &shares, &pkp, t) {
        wipe(&mut shares);
        return Err(e);
    }
    Ok((shares, pkp))
}

/// Check that a public key package is a consistent `t`-of-n sharing: every `t`-subset of its
/// verifying shares interpolates, in the exponent, to the group verifying key.
///
/// This is what a node that receives a package — from the dealer, or after a refresh — can check
/// without any secret: verifying shares that do not lie on one degree-`t−1` polynomial through the
/// group key (a tampered entry, a mislabelled identifier, a wrong `t`) fail here.
pub fn check_public_key_package(pkp: &PublicKeyPackage, t: u16) -> Result<()> {
    let shares = pkp.verifying_shares();
    let n = shares.len();
    if t < 2 || usize::from(t) > n || n > MAX_SIGNERS {
        return Err(CoreError::Dealer(format!(
            "public key package has {n} verifying share(s), threshold {t}: not a valid t-of-n \
             (2 ≤ t ≤ n ≤ {MAX_SIGNERS})"
        )));
    }
    let group = element(&pkp.verifying_key().serialize()?)?;
    let points: Vec<(Identifier, <Ed25519Group as Group>::Element)> = shares
        .iter()
        .map(|(id, share)| Ok((*id, element(&share.serialize()?)?)))
        .collect::<Result<_>>()?;

    for subset in subsets(n, usize::from(t)) {
        let xs: Vec<Identifier> = subset.iter().map(|&i| points[i].0).collect();
        let mut acc = <Ed25519Group as Group>::identity();
        for &i in &subset {
            acc += points[i].1 * lagrange_at_zero(&xs, points[i].0)?;
        }
        if acc != group {
            return Err(CoreError::Dealer(format!(
                "verifying shares {} do not interpolate to the group key — the public key package \
                 is inconsistent (tampered, mislabelled, or not {t}-of-{n})",
                describe(&xs)
            )));
        }
    }
    Ok(())
}

/// Validate the roster and threshold and turn the ids into FROST identifiers.
fn roster(ids: &[u16], t: u16) -> Result<Vec<Identifier>> {
    let n = ids.len();
    if !(2..=MAX_SIGNERS).contains(&n) {
        return Err(CoreError::Dealer(format!("need 2..={MAX_SIGNERS} recipients, got {n}")));
    }
    if t < 2 || usize::from(t) > n {
        return Err(CoreError::Dealer(format!(
            "threshold {t} out of range 2..={n} (t = 1 would hand every node the whole key)"
        )));
    }
    let unique: BTreeSet<u16> = ids.iter().copied().collect();
    if unique.len() != n {
        return Err(CoreError::Dealer(format!("duplicate identifiers in {ids:?}")));
    }
    ids.iter()
        .map(|&i| {
            Identifier::try_from(i)
                .map_err(|_| CoreError::Dealer(format!("invalid identifier {i} (must be ≥ 1)")))
        })
        .collect()
}

/// The post-split checks (module docs, items 1–5).
fn verify_split(
    signing_key: &frost::SigningKey,
    expected_public: &[u8; 32],
    shares: &[SecretShare],
    pkp: &PublicKeyPackage,
    t: u16,
) -> Result<()> {
    // 1. The group key is the Canton key, byte for byte.
    if pkp.verifying_key().serialize()?.as_slice() != expected_public.as_slice() {
        return Err(CoreError::Dealer(
            "group verifying key differs from the seed's Ed25519 public key — seed→scalar \
             conversion is wrong; refusing to hand out shares"
                .into(),
        ));
    }
    let roster: BTreeSet<Identifier> = shares.iter().map(|s| *s.identifier()).collect();
    if pkp.verifying_shares().keys().copied().collect::<BTreeSet<_>>() != roster {
        return Err(CoreError::Dealer("public key package roster differs from the shares".into()));
    }

    // 2. One commitment for everyone, VSS-valid shares, matching verifying shares, min_signers = t.
    let commitment = shares[0].commitment();
    let mut key_packages: Vec<KeyPackage> = Vec::with_capacity(shares.len());
    let outcome = (|| {
        for share in shares {
            if share.commitment() != commitment {
                return Err(CoreError::Dealer("shares carry different VSS commitments".into()));
            }
            let kp = KeyPackage::try_from(share.clone())?; // VSS verification
            let ok = *kp.min_signers() == t
                && kp.verifying_key() == pkp.verifying_key()
                && pkp.verifying_shares().get(kp.identifier()) == Some(kp.verifying_share());
            key_packages.push(kp);
            if !ok {
                return Err(CoreError::Dealer(format!(
                    "share {} disagrees with the public key package or threshold {t}",
                    describe(&[*share.identifier()])
                )));
            }
        }

        // 3. The public package is consistent on its own.
        check_public_key_package(pkp, t)?;

        // 4 + 5. Every t-subset reconstructs the key and signs under the Canton public key.
        let verifier = ed25519_dalek::VerifyingKey::from_bytes(expected_public)
            .map_err(|_| CoreError::Dealer("seed public key is not a valid point".into()))?;
        let message = canton_test_message(b"rutli-dealer/self-test");
        for subset in subsets(key_packages.len(), usize::from(t)) {
            let quorum: Vec<KeyPackage> = subset.iter().map(|&i| key_packages[i].clone()).collect();
            let ids: Vec<Identifier> = quorum.iter().map(|kp| *kp.identifier()).collect();
            let reconstructed = frost::keys::reconstruct(&quorum);
            let signed = selftest_sign(&quorum, pkp, &message);
            let mut quorum = quorum;
            wipe(&mut quorum);
            if reconstructed?.to_scalar() != signing_key.to_scalar() {
                return Err(CoreError::Dealer(format!(
                    "shares {} do not reconstruct the original key",
                    describe(&ids)
                )));
            }
            let signature = ed25519_dalek::Signature::from_bytes(&signed?);
            verifier.verify_strict(&message, &signature).map_err(|_| {
                CoreError::Dealer(format!(
                    "shares {} produced a signature that does not verify under the Canton key",
                    describe(&ids)
                ))
            })?;
        }
        Ok(())
    })();
    wipe(&mut key_packages);
    outcome
}

/// A plain in-process FROST signature (no nonce store: the nonces never leave this function and
/// are dropped with it), for the dealer's self-test.
fn selftest_sign(
    quorum: &[KeyPackage],
    pkp: &PublicKeyPackage,
    message: &[u8],
) -> Result<[u8; 64]> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for kp in quorum {
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(*kp.identifier(), n);
        commitments.insert(*kp.identifier(), c);
    }
    let package = SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for kp in quorum {
        shares.insert(*kp.identifier(), frost::round2::sign(&package, &nonces[kp.identifier()], kp)?);
    }
    let bytes = frost::aggregate(&package, &shares, pkp)?.serialize()?;
    <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| CoreError::Dealer("aggregate signature is not 64 bytes".into()))
}

/// λ_i(0) over the x-coordinates `xs`: ∏_{j≠i} x_j / (x_j − x_i).
fn lagrange_at_zero(
    xs: &[Identifier],
    xi: Identifier,
) -> Result<<Ed25519ScalarField as Field>::Scalar> {
    let xi_s = scalar(xi)?;
    let mut num = <Ed25519ScalarField as Field>::one();
    let mut den = <Ed25519ScalarField as Field>::one();
    for &xj in xs {
        if xj == xi {
            continue;
        }
        let xj_s = scalar(xj)?;
        num *= xj_s;
        den *= xj_s - xi_s;
    }
    let inv = <Ed25519ScalarField as Field>::invert(&den)
        .map_err(|_| CoreError::Dealer("duplicate identifiers in a subset".into()))?;
    Ok(num * inv)
}

fn scalar(id: Identifier) -> Result<<Ed25519ScalarField as Field>::Scalar> {
    let bytes: [u8; 32] = id
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Dealer("identifier is not 32 bytes".into()))?;
    <Ed25519ScalarField as Field>::deserialize(&bytes)
        .map_err(|_| CoreError::Dealer("identifier is not a canonical scalar".into()))
}

fn element(bytes: &[u8]) -> Result<<Ed25519Group as Group>::Element> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CoreError::Dealer("group element is not 32 bytes".into()))?;
    // Rejects the identity, small-order points and non-canonical encodings.
    <Ed25519Group as Group>::deserialize(&bytes)
        .map_err(|_| CoreError::Dealer("invalid group element in the public key package".into()))
}

/// Every `k`-element subset of `0..n`, as sorted index lists.
fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            cur.push(i);
            go(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    go(0, n, k, &mut Vec::with_capacity(k), &mut out);
    out
}

/// Identifiers for an error message, as the small integers operators configured.
fn describe(ids: &[Identifier]) -> String {
    let small: Vec<String> = ids
        .iter()
        .map(|id| {
            let b = id.serialize();
            // Ed25519 identifiers serialize little-endian; a configured id fits in two bytes.
            if b.len() == 32 && b[2..].iter().all(|&x| x == 0) {
                u16::from_le_bytes([b[0], b[1]]).to_string()
            } else {
                hex::encode(b)
            }
        })
        .collect();
    format!("{{{}}}", small.join(","))
}

fn wipe<Z: Zeroize>(items: &mut Vec<Z>) {
    for item in items.iter_mut() {
        item.zeroize();
    }
    items.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::group_verifying_key_bytes;
    use crate::refresh::RefreshParticipant;

    const IDS: [u16; 3] = [1, 2, 3];

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(public)
            .unwrap()
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
            .is_ok()
    }

    fn key_packages(shares: &[SecretShare]) -> Vec<KeyPackage> {
        shares.iter().map(|s| KeyPackage::try_from(s.clone()).unwrap()).collect()
    }

    /// RFC 8032 §7.1 TEST 1–3: (seed, public key).
    const RFC8032: [(&str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ),
    ];

    #[test]
    fn rfc8032_vectors_split_to_their_public_keys_and_sign() {
        for (seed, public) in RFC8032 {
            let (seed, public) = (hex32(seed), hex32(public));
            assert_eq!(public_key_from_seed(&seed), public);
            let (shares, pkp) = split_ed25519_seed(&seed, &IDS, 2).unwrap();
            assert_eq!(group_verifying_key_bytes(&pkp).unwrap(), public);

            let kps = key_packages(&shares);
            let msg = canton_test_message(b"rfc8032");
            let sig = selftest_sign(&kps[1..], &pkp, &msg).unwrap();
            assert!(verify(&public, &msg, &sig));
        }
    }

    #[test]
    fn a_real_canton_3_6_1_namespace_export_splits_to_its_fingerprint() {
        // B1's throwaway vectors: a password-protected ExportKeyPair of a 3.6.1 namespace key.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../canton-key/testdata/vectors");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        let password = manifest["password"].as_str().unwrap();
        let fingerprint = manifest["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["name"] == "namespace")
            .unwrap()["fingerprint"]
            .as_str()
            .unwrap()
            .to_string();

        let input = std::fs::read(dir.join("namespace.export-pw.bin")).unwrap();
        let key = rutli_canton_key::parse(&input, Some(password.as_bytes())).unwrap();
        assert_eq!(key.fingerprint(), fingerprint);
        let rutli_canton_key::PrivateKeyMaterial::Ed25519 { seed } = &key.material else {
            panic!("namespace key is Ed25519")
        };
        let rutli_canton_key::PublicKey::Ed25519(public) = key.public else { unreachable!() };

        let (shares, pkp) = split_ed25519_seed(seed, &IDS, 2).unwrap();
        let group = group_verifying_key_bytes(&pkp).unwrap();
        assert_eq!(group, public, "group key must be the Canton key");
        assert_eq!(
            rutli_canton_key::fingerprint(&rutli_canton_key::PublicKey::Ed25519(group)),
            fingerprint
        );
        let kps = key_packages(&shares);
        let msg = canton_test_message(b"namespace topology");
        assert!(verify(&public, &msg, &selftest_sign(&kps[..2], &pkp, &msg).unwrap()));
    }

    #[test]
    fn the_seed_is_not_the_scalar_and_the_clamped_bytes_do_not_deserialize() {
        let (seed, public) = (hex32(RFC8032[0].0), hex32(RFC8032[0].1));

        // Trap 1: the seed read as a scalar is either refused or a different key.
        match frost::SigningKey::deserialize(&seed) {
            Err(_) => {}
            Ok(wrong) => assert_ne!(
                frost::VerifyingKey::from(&wrong).serialize().unwrap(),
                public.to_vec(),
                "the seed must not be usable as the scalar"
            ),
        }

        // Trap 2: the clamped, unreduced scalar is never canonical (bit 254 set), so it is refused.
        let mut clamped = ed25519_dalek::SigningKey::from_bytes(&seed).to_scalar_bytes();
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        assert!(frost::SigningKey::deserialize(&clamped).is_err());

        // The right path: reduced scalar → the RFC public key.
        let sk = signing_key_from_seed(&seed).unwrap();
        assert_eq!(frost::VerifyingKey::from(&sk).serialize().unwrap(), public.to_vec());
    }

    #[test]
    fn every_t_subset_reconstructs_and_signs_and_shares_carry_the_roster_and_threshold() {
        let seed = hex32(RFC8032[1].0);
        let public = public_key_from_seed(&seed);
        let ids = [3u16, 7, 9, 11]; // configured identifiers need not be 1..=n
        let (shares, pkp) = split_ed25519_seed(&seed, &ids, 3).unwrap();
        let roster: BTreeSet<Identifier> =
            ids.iter().map(|&i| Identifier::try_from(i).unwrap()).collect();
        assert_eq!(pkp.verifying_shares().keys().copied().collect::<BTreeSet<_>>(), roster);
        for (share, &id) in shares.iter().zip(&ids) {
            assert_eq!(*share.identifier(), Identifier::try_from(id).unwrap(), "ordered as given");
        }

        let kps = key_packages(&shares);
        let sk = signing_key_from_seed(&seed).unwrap();
        let msg = canton_test_message(b"all subsets");
        for subset in subsets(kps.len(), 3) {
            let quorum: Vec<KeyPackage> = subset.iter().map(|&i| kps[i].clone()).collect();
            assert!(quorum.iter().all(|kp| *kp.min_signers() == 3));
            assert_eq!(frost::keys::reconstruct(&quorum).unwrap().to_scalar(), sk.to_scalar());
            assert!(verify(&public, &msg, &selftest_sign(&quorum, &pkp, &msg).unwrap()));
        }
        // t − 1 shares reconstruct garbage, not the key.
        let short = frost::keys::reconstruct(&kps[..2]);
        assert!(short.map(|k| k.to_scalar() != sk.to_scalar()).unwrap_or(true));
    }

    #[test]
    fn two_of_three_shares_have_min_signers_two() {
        let (shares, _) = split_ed25519_seed(&hex32(RFC8032[2].0), &IDS, 2).unwrap();
        assert!(key_packages(&shares).iter().all(|kp| *kp.min_signers() == 2));
    }

    #[test]
    fn bad_rosters_and_thresholds_are_refused() {
        let seed = hex32(RFC8032[0].0);
        for (ids, t) in [
            (&[1u16, 2, 3][..], 1u16), // t = 1: every share is the key
            (&[1, 2, 3][..], 4),       // t > n
            (&[1, 2, 2][..], 2),       // duplicate
            (&[0, 1, 2][..], 2),       // zero identifier
            (&[1][..], 1),             // n = 1
        ] {
            assert!(split_ed25519_seed(&seed, ids, t).is_err(), "{ids:?} t={t} must be refused");
        }
    }

    #[test]
    fn interpolation_catches_a_tampered_or_mislabelled_verifying_share() {
        let (shares, pkp) = split_ed25519_seed(&hex32(RFC8032[0].0), &IDS, 2).unwrap();
        check_public_key_package(&pkp, 2).unwrap();
        assert!(check_public_key_package(&pkp, 1).is_err(), "t = 1 is never a valid claim");
        // A threshold lie: a 3-of-3 sharing presented as 2-of-3 does not interpolate (its
        // verifying shares lie on a quadratic, not a line).
        let (_, three_of_three) = split_ed25519_seed(&hex32(RFC8032[0].0), &IDS, 3).unwrap();
        check_public_key_package(&three_of_three, 3).unwrap();
        assert!(check_public_key_package(&three_of_three, 2).is_err());

        let id = |i: u16| Identifier::try_from(i).unwrap();
        let mut vs = pkp.verifying_shares().clone();

        // Replace node 2's verifying share with node 3's (a swap / mislabel).
        let three = vs[&id(3)];
        vs.insert(id(2), three);
        let swapped = PublicKeyPackage::new(vs.clone(), *pkp.verifying_key());
        assert!(check_public_key_package(&swapped, 2).is_err());

        // Replace it with an unrelated point (the verifying share of a different sharing).
        let (_, other) = split_ed25519_seed(&hex32(RFC8032[1].0), &IDS, 2).unwrap();
        vs.insert(id(2), other.verifying_shares()[&id(2)]);
        let tampered = PublicKeyPackage::new(vs, *pkp.verifying_key());
        assert!(check_public_key_package(&tampered, 2).is_err());

        // And a share relabelled to a different identifier fails VSS against the commitment.
        let s = &shares[0];
        let relabelled = SecretShare::new(id(2), *s.signing_share(), s.commitment().clone());
        assert!(KeyPackage::try_from(relabelled).is_err());
    }

    #[test]
    fn pkp_digest_is_stable_and_binds_the_package() {
        let (_, a) = split_ed25519_seed(&hex32(RFC8032[0].0), &IDS, 2).unwrap();
        let (_, b) = split_ed25519_seed(&hex32(RFC8032[0].0), &IDS, 2).unwrap();
        assert_eq!(pkp_digest(&a).unwrap(), pkp_digest(&a.clone()).unwrap());
        // Same key, fresh polynomial: same group key, different verifying shares, different digest.
        assert_eq!(a.verifying_key(), b.verifying_key());
        assert_ne!(pkp_digest(&a).unwrap(), pkp_digest(&b).unwrap());
        // The digest survives the JSON round trip the share files use.
        let json = serde_json::to_vec(&a).unwrap();
        let back: PublicKeyPackage = serde_json::from_slice(&json).unwrap();
        assert_eq!(pkp_digest(&back).unwrap(), pkp_digest(&a).unwrap());
    }

    /// Run the dealer-free refresh over in-process participants; returns the refreshed packages.
    fn refresh(kps: &[KeyPackage], pkp: &PublicKeyPackage) -> Vec<(KeyPackage, PublicKeyPackage)> {
        let n = kps.len() as u16;
        let t = *kps[0].min_signers();
        let mut parts: BTreeMap<Identifier, RefreshParticipant> = kps
            .iter()
            .map(|kp| (*kp.identifier(), RefreshParticipant::new(*kp.identifier(), n, t)))
            .collect();
        let mut r1 = BTreeMap::new();
        for (&id, p) in parts.iter_mut() {
            r1.insert(id, p.part1().unwrap());
        }
        let others = |id: Identifier| -> BTreeMap<_, _> {
            r1.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect()
        };
        let mut r2: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
            BTreeMap::new();
        for (&id, p) in parts.iter_mut() {
            r2.insert(id, p.part2(&others(id)).unwrap());
        }
        kps.iter()
            .map(|kp| {
                let id = *kp.identifier();
                let inbox: BTreeMap<_, _> = r2
                    .iter()
                    .filter(|(&from, _)| from != id)
                    .map(|(&from, out)| (from, out[&id].clone()))
                    .collect();
                parts
                    .get_mut(&id)
                    .unwrap()
                    .part3(&others(id), &inbox, pkp.clone(), kp.clone())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn refresh_of_a_dealt_key_keeps_the_group_key_and_old_shares_stop_combining() {
        let seed = hex32(RFC8032[0].0);
        let public = public_key_from_seed(&seed);
        let (shares, pkp) = split_ed25519_seed(&seed, &IDS, 2).unwrap();
        let dealt = key_packages(&shares);

        let refreshed = refresh(&dealt, &pkp);
        let new_pkp = refreshed[0].1.clone();
        for (_, p) in &refreshed {
            assert_eq!(p, &new_pkp, "every node derives the same refreshed package");
        }
        assert_eq!(group_verifying_key_bytes(&new_pkp).unwrap(), public);
        check_public_key_package(&new_pkp, 2).unwrap();
        assert_ne!(pkp_digest(&new_pkp).unwrap(), pkp_digest(&pkp).unwrap());

        let new: Vec<KeyPackage> = refreshed.into_iter().map(|(kp, _)| kp).collect();
        let msg = canton_test_message(b"after refresh");
        assert!(verify(&public, &msg, &selftest_sign(&new[1..], &new_pkp, &msg).unwrap()));

        // A leaked dealt share does not combine with a live (refreshed) one.
        let sk = signing_key_from_seed(&seed).unwrap();
        let mixed = [dealt[0].clone(), new[1].clone()];
        assert_ne!(frost::keys::reconstruct(&mixed).unwrap().to_scalar(), sk.to_scalar());
        match selftest_sign(&mixed, &new_pkp, &msg) {
            Err(_) => {}
            Ok(sig) => assert!(!verify(&public, &msg, &sig), "old + new share must not sign"),
        }
    }

    #[test]
    fn canton_test_message_has_the_wire_shape() {
        let m = canton_test_message(b"x");
        assert_eq!(m.len(), 34);
        assert_eq!(&m[..2], &[0x12, 0x20]);
    }
}

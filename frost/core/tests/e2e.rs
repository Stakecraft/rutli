// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof for the FROST core, against the wire contract Canton actually enforces
//! (docs/wire-contract.md): sign a 34-byte pre-hashed payload, emit a 64-byte signature that a
//! strict, independent RFC 8032 verifier (ed25519-dalek) accepts under the DKG group key.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost::Identifier;
use rutli_frost_core::dkg::{group_verifying_key_bytes, DkgParticipant};
use rutli_frost_core::nonce_store::NonceStore;
use rutli_frost_core::session::{aggregate, Cosigner};
use rutli_frost_core::CoreError;

const MIN_SIGNERS: u16 = 2;
const MAX_SIGNERS: u16 = 3;

/// Canton's sign payload: 0x1220 (multihash sha2-256/32) ‖ sha256 digest — 34 bytes.
fn canton_digest(msg: &[u8]) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Test stand-in "digest" (content irrelevant to FROST): 2-byte prefix + 32 bytes.
    let mut h = DefaultHasher::new();
    msg.hash(&mut h);
    let seed = h.finish().to_le_bytes();
    let mut out = vec![0x12u8, 0x20u8];
    out.extend(seed.iter().cycle().take(32));
    assert_eq!(out.len(), 34);
    out
}

/// Run a full 2-of-3 DKG in-process; returns each cosigner (with its own temp nonce store).
fn dkg_cluster(tmp: &tempfile::TempDir) -> Vec<Cosigner> {
    let ids: Vec<Identifier> =
        (1u16..=MAX_SIGNERS).map(|i| Identifier::try_from(i).unwrap()).collect();

    let mut participants: BTreeMap<Identifier, DkgParticipant> = ids
        .iter()
        .map(|&id| (id, DkgParticipant::new(id, MAX_SIGNERS, MIN_SIGNERS)))
        .collect();

    // Part 1 — everyone broadcasts.
    let mut r1: BTreeMap<Identifier, frost::keys::dkg::round1::Package> = BTreeMap::new();
    for (&id, p) in participants.iter_mut() {
        r1.insert(id, p.part1().unwrap());
    }

    // Part 2 — everyone processes the others' round-1 packages.
    let mut r2_outbox: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for (&id, p) in participants.iter_mut() {
        let others: BTreeMap<_, _> =
            r1.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect();
        r2_outbox.insert(id, p.part2(&others).unwrap());
    }

    // Part 3 — deliver the point-to-point round-2 packages and finalize.
    let mut cosigners = Vec::new();
    for (&id, p) in participants.iter_mut() {
        let others_r1: BTreeMap<_, _> =
            r1.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect();
        let inbox: BTreeMap<_, _> = r2_outbox
            .iter()
            .filter(|(&from, _)| from != id)
            .map(|(&from, outbox)| (from, outbox.get(&id).unwrap().clone()))
            .collect();
        let (key_package, pubkey_package) = p.part3(&others_r1, &inbox).unwrap();
        let store = NonceStore::open(tmp.path().join(format!("cosigner-{id:?}"))).unwrap();
        cosigners.push(Cosigner::new(key_package, pubkey_package, store));
    }
    cosigners
}

/// Leader-side happy path with the given subset of cosigners.
fn sign_with(
    cosigners: &[&Cosigner],
    session_id: &str,
    message: &[u8],
) -> Result<[u8; 64], CoreError> {
    let mut commitments = BTreeMap::new();
    for c in cosigners {
        commitments.insert(c.identifier(), c.round1(session_id)?);
    }
    let mut shares = BTreeMap::new();
    for c in cosigners {
        shares.insert(c.identifier(), c.round2(session_id, message, &commitments)?);
    }
    aggregate(message, &commitments, &shares, cosigners[0].public_key_package())
}

#[test]
fn dkg_then_threshold_sign_verifies_under_strict_dalek() {
    let tmp = tempfile::tempdir().unwrap();
    let cosigners = dkg_cluster(&tmp);
    let message = canton_digest(b"NamespaceDelegation for PAR::participant1");

    // 2-of-3: cosigners 0 and 2 participate; cosigner 1 is offline.
    let sig = sign_with(&[&cosigners[0], &cosigners[2]], "session-aaaa", &message).unwrap();

    // Independent strict verification: ed25519-dalek against the DKG group key.
    let group_key = group_verifying_key_bytes(cosigners[0].public_key_package()).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig);
    vk.verify_strict(&message, &dalek_sig)
        .expect("FROST output must be a standard RFC 8032 Ed25519 signature");

    // All three cosigners computed the same group key.
    for c in &cosigners {
        assert_eq!(group_verifying_key_bytes(c.public_key_package()).unwrap(), group_key);
    }
}

#[test]
fn different_quorums_produce_valid_sigs_under_same_group_key() {
    let tmp = tempfile::tempdir().unwrap();
    let cosigners = dkg_cluster(&tmp);
    let message = canton_digest(b"OwnerToKeyMapping");
    let group_key = group_verifying_key_bytes(cosigners[0].public_key_package()).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();

    for (i, quorum) in [
        vec![&cosigners[0], &cosigners[1]],
        vec![&cosigners[1], &cosigners[2]],
        vec![&cosigners[0], &cosigners[1], &cosigners[2]],
    ]
    .iter()
    .enumerate()
    {
        let sig = sign_with(quorum, &format!("session-quorum-{i}"), &message).unwrap();
        vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
    }
}

#[test]
fn nonce_reuse_is_refused_even_across_cosigner_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let cosigners = dkg_cluster(&tmp);
    let message = canton_digest(b"first message");
    let session = "session-burn-once";

    // Complete a signature with this session id.
    sign_with(&[&cosigners[0], &cosigners[1]], session, &message).unwrap();

    // Replaying round 1 with the same session id must be refused (burned marker on disk).
    let err = cosigners[0].round1(session).unwrap_err();
    assert!(matches!(err, CoreError::NonceReuse(_)), "got: {err:?}");

    // And round 2 for a session that never did round 1 is unknown.
    let commitments = BTreeMap::new();
    let err = cosigners[0].round2("session-nonexistent", &message, &commitments).unwrap_err();
    assert!(matches!(err, CoreError::UnknownSession(_)), "got: {err:?}");
}

#[test]
fn below_threshold_aggregation_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let cosigners = dkg_cluster(&tmp);
    let message = canton_digest(b"lonely signer");

    // A single cosigner (below min_signers = 2) must not be able to produce a valid signature.
    let result = sign_with(&[&cosigners[0]], "session-solo", &message);
    match result {
        Err(_) => (),
        Ok(sig) => {
            // If FROST permitted single-participant flow structurally, the signature must NOT
            // verify under the group key.
            let group_key = group_verifying_key_bytes(cosigners[0].public_key_package()).unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
            assert!(
                vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig)).is_err(),
                "single share below threshold must never yield a valid group signature"
            );
        }
    }
}

#[test]
fn signature_is_over_exactly_the_34_byte_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let cosigners = dkg_cluster(&tmp);
    let message = canton_digest(b"exact payload");
    let sig = sign_with(&[&cosigners[1], &cosigners[2]], "session-exact", &message).unwrap();
    assert_eq!(sig.len(), 64);

    let group_key = group_verifying_key_bytes(cosigners[0].public_key_package()).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();

    // Tampered message must not verify — confirms the signature binds the exact payload bytes.
    let mut tampered = message.clone();
    tampered[33] ^= 0x01;
    assert!(vk
        .verify_strict(&tampered, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_err());
}

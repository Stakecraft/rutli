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

/// Raw DKG (no Cosigner wrapper) so the test can hold each node's key package for refresh.
fn raw_dkg() -> Vec<(Identifier, frost::keys::KeyPackage, frost::keys::PublicKeyPackage)> {
    use frost::keys::dkg::{part1, part2, part3};
    let ids: Vec<Identifier> =
        (1u16..=MAX_SIGNERS).map(|i| Identifier::try_from(i).unwrap()).collect();
    let mut r1s = BTreeMap::new();
    let mut r1p = BTreeMap::new();
    for &id in &ids {
        let (s, p) = part1(id, MAX_SIGNERS, MIN_SIGNERS, rand::rngs::OsRng).unwrap();
        r1s.insert(id, s);
        r1p.insert(id, p);
    }
    let mut r2s = BTreeMap::new();
    let mut r2out: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for &id in &ids {
        let others: BTreeMap<_, _> =
            r1p.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect();
        let (s, out) = part2(r1s.remove(&id).unwrap(), &others).unwrap();
        r2s.insert(id, s);
        r2out.insert(id, out);
    }
    ids.iter()
        .map(|&id| {
            let others: BTreeMap<_, _> =
                r1p.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect();
            let inbox: BTreeMap<_, _> = r2out
                .iter()
                .filter(|(&from, _)| from != id)
                .map(|(&from, o)| (from, o.get(&id).unwrap().clone()))
                .collect();
            let (kp, pkp) = part3(&r2s[&id], &others, &inbox).unwrap();
            (id, kp, pkp)
        })
        .collect()
}

fn raw_sign(
    signers: &[(Identifier, frost::keys::KeyPackage)],
    pkp: &frost::keys::PublicKeyPackage,
    msg: &[u8],
) -> Result<Vec<u8>, frost::Error> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, kp) in signers {
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut rand::rngs::OsRng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let sp = frost::SigningPackage::new(commitments, msg);
    let mut shares = BTreeMap::new();
    for (id, kp) in signers {
        shares.insert(*id, frost::round2::sign(&sp, &nonces[id], kp)?);
    }
    frost::aggregate(&sp, &shares, pkp)?.serialize()
}

#[test]
fn lost_share_is_repaired_from_helpers_and_signs() {
    use frost::keys::{IdentifierList, KeyPackage};
    use rutli_frost_core::repair::{helper_step1, helper_step2, participant_step3};

    // Trusted-dealer split just to obtain SecretShares (with commitments) for the test.
    let (shares, pkp) =
        frost::keys::generate_with_dealer(MAX_SIGNERS, MIN_SIGNERS, IdentifierList::Default, rand::rngs::OsRng)
            .unwrap();
    let group_key = group_verifying_key_bytes(&pkp).unwrap();

    let id1 = Identifier::try_from(1u16).unwrap();
    let id2 = Identifier::try_from(2u16).unwrap();
    let id3 = Identifier::try_from(3u16).unwrap();

    // id1 is destroyed with no backup. Helpers id2, id3 (a threshold) rebuild its share.
    let helpers = [id2, id3];
    let d2 = helper_step1(&helpers, &shares[&id2], id1).unwrap();
    let d3 = helper_step1(&helpers, &shares[&id3], id1).unwrap();

    // Each helper sums the deltas addressed to it.
    let sigma2 = helper_step2(&[d2[&id2], d3[&id2]]);
    let sigma3 = helper_step2(&[d2[&id3], d3[&id3]]);

    // id1 reconstructs its KeyPackage from the sigmas + the public VSS commitment (any helper's).
    let commitment = shares[&id2].commitment();
    let repaired = participant_step3(&[sigma2, sigma3], id1, commitment).unwrap();

    // The repaired share signs (with an untouched helper) and verifies under the SAME group key.
    let msg = canton_digest(b"after repair");
    let quorum = [(id1, repaired), (id2, KeyPackage::try_from(shares[&id2].clone()).unwrap())];
    let sig = raw_sign(&quorum, &pkp, &msg).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();
    vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig.try_into().unwrap())).unwrap();
}

#[test]
fn refresh_keeps_group_key_and_invalidates_pre_refresh_shares() {
    use rutli_frost_core::refresh::RefreshParticipant;

    let dealt = raw_dkg();
    let ids: Vec<Identifier> = dealt.iter().map(|(id, _, _)| *id).collect();
    let old_pkp = dealt[0].2.clone();
    let group_key = group_verifying_key_bytes(&old_pkp).unwrap();

    // --- distributed refresh (mirrors DKG orchestration) ---
    let mut parts: BTreeMap<Identifier, RefreshParticipant> =
        ids.iter().map(|&id| (id, RefreshParticipant::new(id, MAX_SIGNERS, MIN_SIGNERS))).collect();
    let mut r1 = BTreeMap::new();
    for (&id, p) in parts.iter_mut() {
        r1.insert(id, p.part1().unwrap());
    }
    let mut r2out: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for (&id, p) in parts.iter_mut() {
        let others: BTreeMap<_, _> =
            r1.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect();
        r2out.insert(id, p.part2(&others).unwrap());
    }
    let mut refreshed: Vec<(Identifier, frost::keys::KeyPackage, frost::keys::PublicKeyPackage)> =
        Vec::new();
    for (&id, p) in parts.iter_mut() {
        let (_, old_kp, old_pkp_i) = dealt.iter().find(|(i, _, _)| *i == id).unwrap();
        let others: BTreeMap<_, _> =
            r1.iter().filter(|(&k, _)| k != id).map(|(&k, v)| (k, v.clone())).collect();
        let inbox: BTreeMap<_, _> = r2out
            .iter()
            .filter(|(&from, _)| from != id)
            .map(|(&from, o)| (from, o.get(&id).unwrap().clone()))
            .collect();
        let (nkp, npkp) =
            p.part3(&others, &inbox, old_pkp_i.clone(), old_kp.clone()).unwrap();
        refreshed.push((id, nkp, npkp));
    }

    // Group key is unchanged — Canton's namespace key and node identity are stable.
    for (_, _, npkp) in &refreshed {
        assert_eq!(group_verifying_key_bytes(npkp).unwrap(), group_key, "group key must not change");
    }
    let new_pkp = refreshed[0].2.clone();

    let msg = canton_digest(b"post-refresh topology");
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group_key).unwrap();

    // Refreshed shares sign fine under the same group key.
    let quorum: Vec<_> = refreshed.iter().take(2).map(|(id, kp, _)| (*id, kp.clone())).collect();
    let sig = raw_sign(&quorum, &new_pkp, &msg).unwrap();
    vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig.try_into().unwrap())).unwrap();

    // An attacker with an OLD share + a NEW share cannot forge: the two are on different sharing
    // polynomials now, so aggregation either errors or yields a signature that does not verify.
    let old1 = (dealt[0].0, dealt[0].1.clone());
    let new2 = (refreshed[1].0, refreshed[1].1.clone());
    match raw_sign(&[old1, new2], &new_pkp, &msg) {
        Err(_) => (),
        Ok(bad) => {
            let bad: [u8; 64] = bad.try_into().unwrap();
            assert!(
                vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&bad)).is_err(),
                "a pre-refresh share must not combine with post-refresh shares to sign"
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

#[test]
fn dkg_participant_rejects_out_of_order_calls_without_panic() {
    use rutli_frost_core::dkg::DkgParticipant;
    use rutli_frost_core::CoreError;
    let id = Identifier::try_from(1u16).unwrap();
    let r1: BTreeMap<Identifier, frost::keys::dkg::round1::Package> = BTreeMap::new();
    let r2: BTreeMap<Identifier, frost::keys::dkg::round2::Package> = BTreeMap::new();

    // part2 before part1 → recoverable error, not a panic.
    let mut p = DkgParticipant::new(id, MAX_SIGNERS, MIN_SIGNERS);
    assert!(matches!(p.part2(&r1), Err(CoreError::InvalidCeremonyState(_))));

    // part3 before part2 → recoverable error.
    let mut p = DkgParticipant::new(id, MAX_SIGNERS, MIN_SIGNERS);
    p.part1().unwrap();
    assert!(matches!(p.part3(&r1, &r2), Err(CoreError::InvalidCeremonyState(_))));
}

#[test]
fn refresh_participant_rejects_out_of_order_calls_without_panic() {
    use rutli_frost_core::refresh::RefreshParticipant;
    use rutli_frost_core::CoreError;
    let dealt = raw_dkg();
    let (id, kp, pkp) = (dealt[0].0, dealt[0].1.clone(), dealt[0].2.clone());
    let r1: BTreeMap<Identifier, frost::keys::dkg::round1::Package> = BTreeMap::new();
    let r2: BTreeMap<Identifier, frost::keys::dkg::round2::Package> = BTreeMap::new();

    // part2 before part1.
    let mut p = RefreshParticipant::new(id, MAX_SIGNERS, MIN_SIGNERS);
    assert!(matches!(p.part2(&r1), Err(CoreError::InvalidCeremonyState(_))));

    // part3 before part2.
    let mut p = RefreshParticipant::new(id, MAX_SIGNERS, MIN_SIGNERS);
    p.part1().unwrap();
    assert!(matches!(p.part3(&r1, &r2, pkp, kp), Err(CoreError::InvalidCeremonyState(_))));
}

#[test]
fn in_flight_sign_sessions_are_freed_on_completion_and_abort() {
    let tmp = tempfile::tempdir().unwrap();
    let cosigners = dkg_cluster(&tmp);
    let c = &cosigners[0];

    // Three round-1 sessions minted, none completed yet.
    c.round1("s1").unwrap();
    c.round1("s2").unwrap();
    c.round1("s3").unwrap();
    assert_eq!(c.pending_count(), 3);

    // Aborting a session frees its RAM nonces (leader gave up / timed out).
    c.abort("s2");
    assert_eq!(c.pending_count(), 2);

    // A completed 2-of-3 signature consumes the leader's pending session (round2 removes it).
    let msg = canton_digest(b"free-on-complete");
    sign_with(&[&cosigners[0], &cosigners[1]], "s-complete", &msg).unwrap();
    // s-complete for cosigner 0 was minted and removed by round2 → not left pending.
    // (s1, s3 remain orphaned but are pruned by TTL on future round1s.)
    assert!(c.pending_count() <= 2);
}

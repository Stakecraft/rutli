// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! frost-ed25519 2.2.0 ("v2", a dev-dependency alias) against the version this crate builds with
//! (3.x, through Rütli's own wrappers): every FROST value Rütli stores, sends or hashes must be read
//! by the other version and re-serialize to the same bytes, a cluster with nodes on both versions
//! must sign, refresh and run a DKG to the same outcome, and `pkp_digest` must agree. This is what
//! makes a rolling upgrade and a rollback to 2.2.0 safe.
//!
//! The one format difference between the versions, `PublicKeyPackage::min_signers`, is guarded by
//! [`rutli_frost_core::dkg::without_min_signers`]; `raw_3x_packages_differ` shows what it prevents.

use std::collections::BTreeMap;

use frost_ed25519 as v3;
use frost_ed25519_v2 as v2;
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use rutli_frost_core::dealer::{canton_test_message, pkp_digest, split_ed25519_seed};
use rutli_frost_core::dkg::{without_min_signers, DkgParticipant};
use rutli_frost_core::refresh::RefreshParticipant;

const N: u16 = 3;
const T: u16 = 2;

/// Re-read `x` as the other version's type, checking the JSON is identical both ways.
fn convert<A: Serialize, B: Serialize + DeserializeOwned>(x: &A) -> B {
    let bytes = serde_json::to_vec(x).unwrap();
    let y: B = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "the other version refuses {}: {e}",
            String::from_utf8_lossy(&bytes)
        )
    });
    assert_eq!(
        serde_json::to_vec(&y).unwrap(),
        bytes,
        "JSON differs across versions"
    );
    y
}

fn v2_digest(pkp: &v2::keys::PublicKeyPackage) -> [u8; 32] {
    Sha256::digest(pkp.serialize().unwrap()).into()
}

fn id3(i: u16) -> v3::Identifier {
    v3::Identifier::try_from(i).unwrap()
}
fn id2(i: u16) -> v2::Identifier {
    v2::Identifier::try_from(i).unwrap()
}

/// What the other nodes broadcast in round 1 (`raw` is their JSON on the wire), read as the
/// packages of the version whose identifiers are made by `id`.
fn decode_round1<I: Ord, P: DeserializeOwned>(
    raw: Vec<(u16, Vec<u8>)>,
    id: fn(u16) -> I,
) -> BTreeMap<I, P> {
    raw.into_iter()
        .map(|(j, b)| (id(j), serde_json::from_slice(&b).unwrap()))
        .collect()
}

/// What every other node sent to node `to` in round 2, read as that version's packages.
fn decode_round2<I: Ord, P: DeserializeOwned>(
    r2: &BTreeMap<(u16, u16), Vec<u8>>,
    to: u16,
    id: fn(u16) -> I,
) -> BTreeMap<I, P> {
    (1..=N)
        .filter(|j| *j != to)
        .map(|j| (id(j), serde_json::from_slice(&r2[&(j, to)]).unwrap()))
        .collect()
}

/// Put node `from`'s round-2 output on the wire, one JSON message per other node.
fn send_round2<I: Ord, P: Serialize>(
    r2: &mut BTreeMap<(u16, u16), Vec<u8>>,
    from: u16,
    out: &BTreeMap<I, P>,
    id: fn(u16) -> I,
) {
    for j in (1..=N).filter(|j| *j != from) {
        r2.insert((from, j), serde_json::to_vec(&out[&id(j)]).unwrap());
    }
}

/// Every pair of nodes signs `tag`'s digest, each on its own version, and both versions aggregate
/// to the same signature that verifies under `pkp` (see [`mixed_sign`]).
fn every_pair_signs(nodes: &[Node], pkp: &v3::keys::PublicKeyPackage, tag: &[u8]) {
    let msg = canton_test_message(tag);
    for pair in [[0, 1], [0, 2], [1, 2]] {
        mixed_sign(nodes, &pair, pkp, &msg);
    }
}

fn verify(pkp: &v3::keys::PublicKeyPackage, msg: &[u8], sig: &[u8]) {
    let group: [u8; 32] = pkp.verifying_key().serialize().unwrap().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&group).unwrap();
    vk.verify_strict(
        msg,
        &ed25519_dalek::Signature::from_bytes(sig.try_into().unwrap()),
    )
    .unwrap();
}

/// A key package held by one node, on the version it runs.
enum Node {
    V2(v2::keys::KeyPackage),
    V3(v3::keys::KeyPackage),
}

/// A 2-of-3 DKG with nodes 1 and 3 on v2 and node 2 on 3.x, exchanging JSON as the wire does.
/// Returns each node's key package and the package every node computed.
fn mixed_dkg() -> (Vec<Node>, Vec<[u8; 32]>, v3::keys::PublicKeyPackage) {
    let on_v2 = |i: u16| i != 2;
    let mut s2_1 = BTreeMap::new();
    let mut p3 = DkgParticipant::new(id3(2), N, T);
    let mut r1: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    for i in 1..=N {
        if on_v2(i) {
            let (s, p) = v2::keys::dkg::part1(id2(i), N, T, OsRng).unwrap();
            s2_1.insert(i, s);
            r1.insert(i, serde_json::to_vec(&p).unwrap());
        } else {
            r1.insert(i, serde_json::to_vec(&p3.part1().unwrap()).unwrap());
        }
    }
    let r1_for = |me: u16| -> Vec<(u16, Vec<u8>)> {
        r1.iter()
            .filter(|(j, _)| **j != me)
            .map(|(j, b)| (*j, b.clone()))
            .collect()
    };
    let mut s2_2 = BTreeMap::new();
    let mut r2: BTreeMap<(u16, u16), Vec<u8>> = BTreeMap::new();
    for i in 1..=N {
        if on_v2(i) {
            let m: BTreeMap<_, v2::keys::dkg::round1::Package> = decode_round1(r1_for(i), id2);
            let (s, out) = v2::keys::dkg::part2(s2_1.remove(&i).unwrap(), &m).unwrap();
            s2_2.insert(i, s);
            send_round2(&mut r2, i, &out, id2);
        } else {
            let m: BTreeMap<_, v3::keys::dkg::round1::Package> = decode_round1(r1_for(i), id3);
            let out = p3.part2(&m).unwrap();
            send_round2(&mut r2, i, &out, id3);
        }
    }
    let (mut nodes, mut digests, mut pkp3) = (Vec::new(), Vec::new(), None);
    for i in 1..=N {
        if on_v2(i) {
            let m1: BTreeMap<_, v2::keys::dkg::round1::Package> = decode_round1(r1_for(i), id2);
            let m2: BTreeMap<_, v2::keys::dkg::round2::Package> = decode_round2(&r2, i, id2);
            let (kp, pkp) = v2::keys::dkg::part3(&s2_2[&i], &m1, &m2).unwrap();
            digests.push(v2_digest(&pkp));
            nodes.push(Node::V2(kp));
        } else {
            let m1: BTreeMap<_, v3::keys::dkg::round1::Package> = decode_round1(r1_for(i), id3);
            let m2: BTreeMap<_, v3::keys::dkg::round2::Package> = decode_round2(&r2, i, id3);
            let (kp, pkp) = p3.part3(&m1, &m2).unwrap();
            digests.push(pkp_digest(&pkp).unwrap());
            nodes.push(Node::V3(kp));
            pkp3 = Some(pkp);
        }
    }
    (nodes, digests, pkp3.unwrap())
}

/// Sign with `signers` (indexes into `nodes`), each on its own version, aggregated by both versions.
fn mixed_sign(
    nodes: &[Node],
    signers: &[usize],
    pkp: &v3::keys::PublicKeyPackage,
    msg: &[u8],
) -> Vec<u8> {
    let mut nonces2 = BTreeMap::new();
    let mut nonces3 = BTreeMap::new();
    let mut commitments: BTreeMap<v3::Identifier, v3::round1::SigningCommitments> = BTreeMap::new();
    for &k in signers {
        match &nodes[k] {
            Node::V2(kp) => {
                let (n, c) = v2::round1::commit(kp.signing_share(), &mut OsRng);
                nonces2.insert(k, n);
                commitments.insert(convert(kp.identifier()), convert(&c));
            }
            Node::V3(kp) => {
                let (n, c) = v3::round1::commit(kp.signing_share(), &mut OsRng);
                nonces3.insert(k, n);
                commitments.insert(*kp.identifier(), c);
            }
        }
    }
    let package3 = v3::SigningPackage::new(commitments, msg);
    let package2: v2::SigningPackage = convert(&package3);
    let mut shares3: BTreeMap<v3::Identifier, v3::round2::SignatureShare> = BTreeMap::new();
    for &k in signers {
        match &nodes[k] {
            Node::V2(kp) => {
                let s = v2::round2::sign(&package2, &nonces2[&k], kp).unwrap();
                shares3.insert(convert(kp.identifier()), convert(&s));
            }
            Node::V3(kp) => {
                shares3.insert(
                    *kp.identifier(),
                    v3::round2::sign(&package3, &nonces3[&k], kp).unwrap(),
                );
            }
        }
    }
    let sig3 = v3::aggregate(&package3, &shares3, pkp)
        .unwrap()
        .serialize()
        .unwrap();
    let pkp2: v2::keys::PublicKeyPackage = convert(pkp);
    let shares2: BTreeMap<v2::Identifier, v2::round2::SignatureShare> = convert(&shares3);
    let sig2 = v2::aggregate(&package2, &shares2, &pkp2)
        .unwrap()
        .serialize()
        .unwrap();
    assert_eq!(sig2, sig3, "both versions aggregate to the same signature");
    verify(pkp, msg, &sig3);
    sig3
}

#[test]
fn a_mixed_cluster_runs_a_dkg_to_one_digest_and_signs() {
    let (nodes, digests, pkp) = mixed_dkg();
    assert!(
        digests.iter().all(|d| *d == digests[0]),
        "every node, on either version, computed the same package"
    );
    assert_eq!(pkp.min_signers(), None);
    every_pair_signs(&nodes, &pkp, b"mixed sign");
    // Key packages written by either version read on the other, byte for byte.
    for n in &nodes {
        match n {
            Node::V2(kp) => {
                let _: v3::keys::KeyPackage = convert(kp);
            }
            Node::V3(kp) => {
                let _: v2::keys::KeyPackage = convert(kp);
            }
        }
    }
    // The package Rütli produces on 3.x is read by v2, with the same digest.
    let pkp2: v2::keys::PublicKeyPackage = convert(&pkp);
    assert_eq!(v2_digest(&pkp2), pkp_digest(&pkp).unwrap());
}

#[test]
fn a_mixed_cluster_refreshes_to_one_digest_and_signs() {
    let (nodes, _, old) = mixed_dkg();
    let on_v2 = |i: u16| i != 2;
    let mut s1 = BTreeMap::new();
    let mut p3 = RefreshParticipant::new(id3(2), N, T);
    let mut r1: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    for i in 1..=N {
        if on_v2(i) {
            let (s, p) = v2::keys::refresh::refresh_dkg_part1(id2(i), N, T, OsRng).unwrap();
            s1.insert(i, s);
            r1.insert(i, serde_json::to_vec(&p).unwrap());
        } else {
            r1.insert(i, serde_json::to_vec(&p3.part1().unwrap()).unwrap());
        }
    }
    let r1_for = |me: u16| -> Vec<(u16, Vec<u8>)> {
        r1.iter()
            .filter(|(j, _)| **j != me)
            .map(|(j, b)| (*j, b.clone()))
            .collect()
    };
    let mut s2 = BTreeMap::new();
    let mut r2: BTreeMap<(u16, u16), Vec<u8>> = BTreeMap::new();
    for i in 1..=N {
        if on_v2(i) {
            let m: BTreeMap<_, v2::keys::dkg::round1::Package> = decode_round1(r1_for(i), id2);
            let (s, out) =
                v2::keys::refresh::refresh_dkg_part2(s1.remove(&i).unwrap(), &m).unwrap();
            s2.insert(i, s);
            send_round2(&mut r2, i, &out, id2);
        } else {
            let m: BTreeMap<_, v3::keys::dkg::round1::Package> = decode_round1(r1_for(i), id3);
            let out = p3.part2(&m).unwrap();
            send_round2(&mut r2, i, &out, id3);
        }
    }
    let (mut refreshed, mut digests, mut new3) = (Vec::new(), Vec::new(), None);
    for i in 1..=N {
        let k = usize::from(i - 1);
        match &nodes[k] {
            Node::V2(kp) => {
                let m1: BTreeMap<_, v2::keys::dkg::round1::Package> = decode_round1(r1_for(i), id2);
                let m2: BTreeMap<_, v2::keys::dkg::round2::Package> = decode_round2(&r2, i, id2);
                let old2: v2::keys::PublicKeyPackage = convert(&old);
                let (nkp, npkp) =
                    v2::keys::refresh::refresh_dkg_shares(&s2[&i], &m1, &m2, old2, kp.clone())
                        .unwrap();
                digests.push(v2_digest(&npkp));
                refreshed.push(Node::V2(nkp));
            }
            Node::V3(kp) => {
                let m1: BTreeMap<_, v3::keys::dkg::round1::Package> = decode_round1(r1_for(i), id3);
                let m2: BTreeMap<_, v3::keys::dkg::round2::Package> = decode_round2(&r2, i, id3);
                let (nkp, npkp) = p3.part3(&m1, &m2, old.clone(), kp.clone()).unwrap();
                digests.push(pkp_digest(&npkp).unwrap());
                refreshed.push(Node::V3(nkp));
                new3 = Some(npkp);
            }
        }
    }
    let new3 = new3.unwrap();
    assert!(
        digests.iter().all(|d| *d == digests[0]),
        "every node, on either version, computed the same refreshed package"
    );
    assert_ne!(pkp_digest(&new3).unwrap(), pkp_digest(&old).unwrap());
    assert_eq!(new3.verifying_key(), old.verifying_key());
    every_pair_signs(&refreshed, &new3, b"mixed sign after refresh");
}

#[test]
fn a_split_on_3x_is_read_by_v2_with_the_same_digest() {
    let seed = [7u8; 32];
    let (shares, pkp) = split_ed25519_seed(&seed, &[1, 2, 3], T).unwrap();
    assert_eq!(pkp.min_signers(), None);
    let pkp2: v2::keys::PublicKeyPackage = convert(&pkp);
    assert_eq!(v2_digest(&pkp2), pkp_digest(&pkp).unwrap());
    // Shares as a 3.x dealer writes them install on a v2 node, and sign with a 3.x node.
    let kp_a: v2::keys::KeyPackage =
        v2::keys::KeyPackage::try_from(convert::<_, v2::keys::SecretShare>(&shares[0])).unwrap();
    let kp_b = v3::keys::KeyPackage::try_from(shares[2].clone()).unwrap();
    mixed_sign(
        &[Node::V2(kp_a), Node::V3(kp_b)],
        &[0, 1],
        &pkp,
        &canton_test_message(b"split"),
    );
}

#[test]
fn round_messages_written_by_v2_are_read_by_3x_and_back() {
    // DKG round 1 and 2 as a v2 node sends them.
    let (s1a, p1a) = v2::keys::dkg::part1(id2(1), N, T, OsRng).unwrap();
    let (_, p1b) = v2::keys::dkg::part1(id2(2), N, T, OsRng).unwrap();
    let (_, p1c) = v2::keys::dkg::part1(id2(3), N, T, OsRng).unwrap();
    let r1a: v3::keys::dkg::round1::Package = convert(&p1a);
    // The transcript hash is over the postcard bytes: identical on both versions.
    assert_eq!(r1a.serialize().unwrap(), p1a.serialize().unwrap());
    let m = BTreeMap::from([(id2(2), p1b), (id2(3), p1c)]);
    let (_, out) = v2::keys::dkg::part2(s1a, &m).unwrap();
    let _: v3::keys::dkg::round2::Package = convert(&out[&id2(2)]);
}

/// The guard's reason to exist: a package frost 3.x produces itself records `min_signers`, which v2
/// refuses to read and which changes the digest.
#[test]
fn raw_3x_packages_differ() {
    let (_, raw) =
        v3::keys::generate_with_dealer(N, T, v3::keys::IdentifierList::Default, OsRng).unwrap();
    assert_eq!(raw.min_signers(), Some(T));
    let json = serde_json::to_vec(&raw).unwrap();
    assert!(
        serde_json::from_slice::<v2::keys::PublicKeyPackage>(&json).is_err(),
        "v2 refuses min_signers"
    );
    let normalised = without_min_signers(&raw);
    assert_ne!(pkp_digest(&raw).unwrap(), pkp_digest(&normalised).unwrap());
    let pkp2: v2::keys::PublicKeyPackage = convert(&normalised);
    assert_eq!(v2_digest(&pkp2), pkp_digest(&normalised).unwrap());
}

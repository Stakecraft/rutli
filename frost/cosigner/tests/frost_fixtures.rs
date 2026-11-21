// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Known-answer tests over FROST data written by frost-ed25519 2.2.0: sealed key files (after a
//! DKG and after a refresh), a split ceremony's share bundles and recipient files, public key
//! packages with their `pkp_digest`, the DKG, refresh and signing wire messages, and a signature.
//!
//! The fixtures in `tests/fixtures/frost-2.2.0/` were produced once, by `regenerate` below, with
//! frost-ed25519 2.2.0. They are throwaway test material and protect nothing. These tests pin their
//! bytes: every later version of the code must open them, compute the same digests, re-serialize
//! them byte for byte, and sign with them. Do not regenerate them to make a test pass; a failure
//! here means stored or wire data changed.

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use frost_ed25519 as frost;
use frost_ed25519::Identifier;
use sha2::{Digest, Sha256};

use rutli_cosigner::keystore::{KeyStore, Share};
use rutli_cosigner::seal::{KeyFileBinding, NodeSealBundle, RecordKind, Sealer};
use rutli_cosigner::share_delivery::{self, ShareBundle};
use rutli_frost_core::dealer::pkp_digest;
use rutli_frost_core::dkg::{group_verifying_key_bytes, DkgParticipant};
use rutli_frost_core::refresh::RefreshParticipant;

#[path = "common/pki.rs"]
mod pki;

const N: u16 = 3;
const T: u16 = 2;
const CLUSTER_UUID: &str = "3f5c2b1e-7a4d-4c8e-9b0f-2d6e8a1c4b70";
const DKG_KEY: &str = "frost-fixture-namespace";
const SPLIT_KEY: &str = "frost-import-fixture";
const SPLIT_CEREMONY: &str = "fixture-split";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/frost-2.2.0")
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(dir().join(rel)).unwrap_or_else(|e| panic!("fixture {rel}: {e}"))
}

fn manifest() -> serde_json::Value {
    serde_json::from_slice(&read("manifest.json")).unwrap()
}

fn m(key: &str) -> String {
    manifest()[key]
        .as_str()
        .unwrap_or_else(|| panic!("manifest.{key}"))
        .to_string()
}

fn id(i: u16) -> Identifier {
    Identifier::try_from(i).unwrap()
}

fn binding(node: u16) -> KeyFileBinding {
    KeyFileBinding {
        node,
        cluster_uuid: Some(CLUSTER_UUID.into()),
        write_version: 2,
        accept_v1: false,
    }
}

/// Node `i`'s fixture sealer, from its committed (test-only) seal bundle.
fn sealer(i: u16) -> Sealer {
    let bundle = NodeSealBundle::parse(&read(&format!("seal/node-{i}.json"))).unwrap();
    bundle.sealer().with_binding(binding(i))
}

fn keystore(stage: &str, i: u16) -> (tempfile::TempDir, KeyStore) {
    // Opened on a copy: opening a store may tighten directory modes, and the fixtures stay as
    // committed.
    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let src = dir().join(stage).join(format!("node-{i}/keys"));
    for e in std::fs::read_dir(&src).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), keys.join(e.file_name())).unwrap();
    }
    let ks = KeyStore::open_with_sealer(keys, Some(Arc::new(sealer(i)))).unwrap();
    (tmp, ks)
}

/// A JSON fixture parses as `T` and serializes back to exactly its bytes.
fn round_trips<T: serde::Serialize + serde::de::DeserializeOwned>(rel: &str) -> T {
    let bytes = read(rel);
    let value: T = serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{rel}: {e}"));
    assert_eq!(
        serde_json::to_vec(&value).unwrap(),
        bytes,
        "{rel} does not re-serialize to its bytes"
    );
    value
}

fn verify(group: &[u8; 32], msg: &[u8], sig: &[u8; 64]) {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(group).unwrap();
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .expect("signature verifies");
}

/// Sign `msg` with the key packages of `signers` and aggregate.
fn sign_with(
    kps: &[&frost::keys::KeyPackage],
    pkp: &frost::keys::PublicKeyPackage,
    msg: &[u8],
) -> [u8; 64] {
    let mut rng = rand::rngs::OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for kp in kps {
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces.insert(*kp.identifier(), n);
        commitments.insert(*kp.identifier(), c);
    }
    let package = frost::SigningPackage::new(commitments, msg);
    let shares: BTreeMap<_, _> = kps
        .iter()
        .map(|kp| {
            (
                *kp.identifier(),
                frost::round2::sign(&package, &nonces[kp.identifier()], kp).unwrap(),
            )
        })
        .collect();
    let sig = frost::aggregate(&package, &shares, pkp).unwrap();
    sig.serialize().unwrap().try_into().unwrap()
}

// ── key files ──────────────────────────────────────────────────────────────────────────────────

/// Each node's sealed key file opens, holds the pinned sharing, and its plaintext is exactly what
/// this code writes for the loaded share.
fn key_files(stage: &str, key_id: &str, digest_key: &str, epoch: u64) -> Vec<Share> {
    let group = m("group_verifying_key");
    (1..=N)
        .map(|i| {
            let (_tmp, ks) = keystore(stage, i);
            let share = ks.load(key_id).unwrap();
            assert_eq!(share.epoch, epoch, "{stage} node {i}");
            assert_eq!(*share.key_package.identifier(), id(i));
            assert_eq!(
                hex::encode(share.pkp_digest().unwrap()),
                m(digest_key),
                "{stage} node {i}"
            );
            assert_eq!(
                hex::encode(group_verifying_key_bytes(&share.public_key_package).unwrap()),
                group
            );
            // The plaintext as stored equals the plaintext this code writes for it.
            let raw = read(&format!("{stage}/node-{i}/keys/{key_id}.json"));
            let (plain, hdr) = sealer(i)
                .unseal_record(&raw, key_id, &[RecordKind::FrostShare])
                .unwrap();
            assert_eq!(hdr.unwrap().epoch, epoch);
            assert_eq!(
                serde_json::to_vec(&share).unwrap(),
                plain,
                "{stage} node {i}: plaintext bytes"
            );
            share
        })
        .collect()
}

#[test]
fn dkg_key_files_open_with_the_pinned_digest_and_sign() {
    let shares = key_files("dkg", DKG_KEY, "dkg_pkp_digest", 1);
    let group: [u8; 32] = hex::decode(m("group_verifying_key"))
        .unwrap()
        .try_into()
        .unwrap();
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let kps: Vec<_> = pair.iter().map(|&k| &shares[k].key_package).collect();
        let msg = rutli_frost_core::dealer::canton_test_message(b"fixture dkg");
        verify(
            &group,
            &msg,
            &sign_with(&kps, &shares[0].public_key_package, &msg),
        );
    }
}

#[test]
fn refreshed_key_files_keep_the_group_key_with_a_new_digest_and_sign() {
    let shares = key_files("refresh", DKG_KEY, "refresh_pkp_digest", 2);
    assert_ne!(m("refresh_pkp_digest"), m("dkg_pkp_digest"));
    let group: [u8; 32] = hex::decode(m("group_verifying_key"))
        .unwrap()
        .try_into()
        .unwrap();
    let msg = rutli_frost_core::dealer::canton_test_message(b"fixture refresh");
    verify(
        &group,
        &msg,
        &sign_with(
            &[&shares[0].key_package, &shares[2].key_package],
            &shares[0].public_key_package,
            &msg,
        ),
    );
}

// ── public key packages ────────────────────────────────────────────────────────────────────────

#[test]
fn public_key_packages_re_serialize_and_digest_as_pinned() {
    for (rel, key) in [
        ("dkg/pkp.json", "dkg_pkp_digest"),
        ("refresh/pkp.json", "refresh_pkp_digest"),
        ("split/pkp.json", "split_pkp_digest"),
    ] {
        let pkp: frost::keys::PublicKeyPackage = round_trips(rel);
        assert_eq!(hex::encode(pkp_digest(&pkp).unwrap()), m(key), "{rel}");
        // The digest is SHA-256 over these exact postcard bytes.
        assert_eq!(
            hex::encode(Sha256::digest(pkp.serialize().unwrap())),
            m(key)
        );
        assert_eq!(
            hex::encode(pkp.serialize().unwrap()),
            String::from_utf8(read(&rel.replace(".json", ".postcard.hex")))
                .unwrap()
                .trim()
        );
    }
}

// ── wire messages ──────────────────────────────────────────────────────────────────────────────

#[test]
fn ceremony_wire_messages_re_serialize_byte_for_byte() {
    for stage in ["dkg", "refresh"] {
        for i in 1..=N {
            let r1: frost::keys::dkg::round1::Package =
                round_trips(&format!("{stage}/wire/round1-from-{i}.json"));
            // The round-1 transcript hash is over the postcard bytes.
            let hex_pc =
                String::from_utf8(read(&format!("{stage}/wire/round1-from-{i}.postcard.hex")))
                    .unwrap();
            assert_eq!(
                hex::encode(r1.serialize().unwrap()),
                hex_pc.trim(),
                "{stage} round1 {i}"
            );
            for j in (1..=N).filter(|&j| j != i) {
                let _: frost::keys::dkg::round2::Package =
                    round_trips(&format!("{stage}/wire/round2-{i}-to-{j}.json"));
            }
        }
    }
}

#[test]
fn signing_messages_and_the_signature_hold() {
    let _: BTreeMap<Identifier, frost::round1::SigningCommitments> =
        round_trips("sign/commitments.json");
    let package: frost::SigningPackage = round_trips("sign/signing-package.json");
    let shares: BTreeMap<Identifier, frost::round2::SignatureShare> =
        round_trips("sign/signature-shares.json");
    let pkp: frost::keys::PublicKeyPackage = round_trips("dkg/pkp.json");
    let msg = hex::decode(m("sign_message")).unwrap();
    assert_eq!(package.message(), &msg);
    // The recorded shares still aggregate to the recorded signature.
    let sig = frost::aggregate(&package, &shares, &pkp).unwrap();
    assert_eq!(hex::encode(sig.serialize().unwrap()), m("sign_signature"));
    let group: [u8; 32] = hex::decode(m("group_verifying_key"))
        .unwrap()
        .try_into()
        .unwrap();
    verify(
        &group,
        &msg,
        &hex::decode(m("sign_signature"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
}

// ── split ceremony ─────────────────────────────────────────────────────────────────────────────

#[test]
fn split_bundles_open_with_the_recipient_files_and_sign() {
    let pkp: frost::keys::PublicKeyPackage = round_trips("split/pkp.json");
    let mut kps = Vec::new();
    for i in 1..=N {
        let bundle: ShareBundle = round_trips(&format!("split/bundle-node{i}.json"));
        assert_eq!(bundle.pkp_digest, m("split_pkp_digest"));
        assert_eq!(
            hex::encode(pkp_digest(&bundle.public_key_package).unwrap()),
            m("split_pkp_digest")
        );
        // The recipient file is opened on a copy, as with key stores.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("ceremony")).unwrap();
        let name = format!("{SPLIT_KEY}.recipient");
        std::fs::copy(
            dir().join(format!("split/node-{i}/ceremony/{name}")),
            tmp.path().join("ceremony").join(&name),
        )
        .unwrap();
        let state = share_delivery::load_recipient(tmp.path(), &sealer(i), SPLIT_KEY).unwrap();
        let share = bundle.open(&state).unwrap();
        let kp = frost::keys::KeyPackage::try_from(share).unwrap();
        assert_eq!(kp.verifying_share(), &pkp.verifying_shares()[&id(i)]);
        kps.push(kp);
    }
    let group: [u8; 32] = hex::decode(m("split_group_verifying_key"))
        .unwrap()
        .try_into()
        .unwrap();
    let msg = rutli_frost_core::dealer::canton_test_message(b"fixture split");
    verify(&group, &msg, &sign_with(&[&kps[1], &kps[2]], &pkp, &msg));
}

// ── the fixtures stay out of deployments ───────────────────────────────────────────────────────

/// No configuration under `deploy/` names a fixture key id or the fixture cluster: the fixtures are
/// test material and must never be what a cluster is set up with.
#[test]
fn no_deployment_config_names_a_fixture() {
    let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
    let needles = [DKG_KEY, SPLIT_KEY, SPLIT_CEREMONY, CLUSTER_UUID];
    let mut stack = vec![deploy.clone()];
    let mut seen = 0;
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(text) = std::fs::read_to_string(&p) {
                seen += 1;
                for n in needles {
                    assert!(
                        !text.contains(n),
                        "{} names the test fixture value {n}",
                        p.display()
                    );
                }
            }
        }
    }
    assert!(seen > 0, "nothing read under {}", deploy.display());
}

// ── the generator (run once, on frost-ed25519 2.2.0) ───────────────────────────────────────────

fn write(rel: &str, bytes: &[u8]) {
    let p = dir().join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// A fresh Ed25519 key for the split fixture, generated here and nowhere else (the seed is not
/// kept: the dealer discards it too). Returns the seed and its Canton fingerprint.
fn fresh_split_key() -> ([u8; 32], String) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let public = rutli_frost_core::dealer::public_key_from_seed(&seed);
    (seed, share_delivery::ed25519_fingerprint(&public))
}

/// Write every fixture. Ignored: run by hand only, and only on the FROST version named in the
/// directory. `RUTLI_WRITE_FROST_FIXTURES=1 cargo test --test frost_fixtures -- --ignored regenerate`
#[test]
#[ignore]
fn regenerate() {
    assert_eq!(
        std::env::var("RUTLI_WRITE_FROST_FIXTURES").as_deref(),
        Ok("1"),
        "set RUTLI_WRITE_FROST_FIXTURES=1"
    );
    let _ = std::fs::remove_dir_all(dir());
    let mut man = serde_json::Map::new();
    man.insert("frost_ed25519".into(), "2.2.0".into());
    man.insert("cluster_uuid".into(), CLUSTER_UUID.into());

    // Seal bundles (test-only).
    for i in 1..=N {
        write(
            &format!("seal/node-{i}.json"),
            &NodeSealBundle::random(i).to_json().unwrap(),
        );
    }

    // DKG through our wrapper, recording the wire.
    let mut parts: BTreeMap<u16, DkgParticipant> = (1..=N)
        .map(|i| (i, DkgParticipant::new(id(i), N, T)))
        .collect();
    let r1: BTreeMap<u16, _> = parts
        .iter_mut()
        .map(|(i, p)| (*i, p.part1().unwrap()))
        .collect();
    let others = |me: u16| -> BTreeMap<Identifier, _> {
        r1.iter()
            .filter(|(j, _)| **j != me)
            .map(|(j, p)| (id(*j), p.clone()))
            .collect()
    };
    let mut r2: BTreeMap<u16, BTreeMap<Identifier, _>> = BTreeMap::new();
    for (i, p) in parts.iter_mut() {
        r2.insert(*i, p.part2(&others(*i)).unwrap());
    }
    let mut dkg_shares = BTreeMap::new();
    for (i, p) in parts.iter_mut() {
        let to_me: BTreeMap<Identifier, _> = r2
            .iter()
            .filter(|(j, _)| **j != *i)
            .map(|(j, m)| (id(*j), m[&id(*i)].clone()))
            .collect();
        dkg_shares.insert(*i, p.part3(&others(*i), &to_me).unwrap());
    }
    for (i, pkg) in &r1 {
        write(&format!("dkg/wire/round1-from-{i}.json"), &json(pkg));
        write(
            &format!("dkg/wire/round1-from-{i}.postcard.hex"),
            hex::encode(pkg.serialize().unwrap()).as_bytes(),
        );
    }
    for (i, m2) in &r2 {
        for j in (1..=N).filter(|j| j != i) {
            write(
                &format!("dkg/wire/round2-{i}-to-{j}.json"),
                &json(&m2[&id(j)]),
            );
        }
    }
    let pkp = dkg_shares[&1].1.clone();
    write("dkg/pkp.json", &json(&pkp));
    write(
        "dkg/pkp.postcard.hex",
        hex::encode(pkp.serialize().unwrap()).as_bytes(),
    );
    man.insert(
        "dkg_pkp_digest".into(),
        hex::encode(pkp_digest(&pkp).unwrap()).into(),
    );
    man.insert(
        "group_verifying_key".into(),
        hex::encode(group_verifying_key_bytes(&pkp).unwrap()).into(),
    );
    for (i, (kp, p)) in &dkg_shares {
        let ks = KeyStore::open_with_sealer(
            dir().join(format!("dkg/node-{i}/keys")),
            Some(Arc::new(sealer(*i))),
        )
        .unwrap();
        let share = Share {
            key_package: kp.clone(),
            public_key_package: p.clone(),
            origin: None,
            epoch: 1,
            key_id: DKG_KEY.into(),
        };
        ks.create(DKG_KEY, &share).unwrap();
    }

    // A signature by nodes 1 and 2, recording the wire.
    let msg = rutli_frost_core::dealer::canton_test_message(b"fixture signature");
    let mut rng = rand::rngs::OsRng;
    let (mut nonces, mut commitments) = (BTreeMap::new(), BTreeMap::new());
    for i in [1u16, 2] {
        let (n, c) = frost::round1::commit(dkg_shares[&i].0.signing_share(), &mut rng);
        nonces.insert(id(i), n);
        commitments.insert(id(i), c);
    }
    let package = frost::SigningPackage::new(commitments.clone(), &msg);
    let sig_shares: BTreeMap<Identifier, _> = [1u16, 2]
        .iter()
        .map(|i| {
            (
                id(*i),
                frost::round2::sign(&package, &nonces[&id(*i)], &dkg_shares[i].0).unwrap(),
            )
        })
        .collect();
    let sig = frost::aggregate(&package, &sig_shares, &pkp).unwrap();
    write("sign/commitments.json", &json(&commitments));
    write("sign/signing-package.json", &json(&package));
    write("sign/signature-shares.json", &json(&sig_shares));
    man.insert("sign_message".into(), hex::encode(msg).into());
    man.insert(
        "sign_signature".into(),
        hex::encode(sig.serialize().unwrap()).into(),
    );

    // Refresh through our wrapper, recording the wire.
    let mut rparts: BTreeMap<u16, RefreshParticipant> = (1..=N)
        .map(|i| (i, RefreshParticipant::new(id(i), N, T)))
        .collect();
    let rr1: BTreeMap<u16, _> = rparts
        .iter_mut()
        .map(|(i, p)| (*i, p.part1().unwrap()))
        .collect();
    let rothers = |me: u16| -> BTreeMap<Identifier, _> {
        rr1.iter()
            .filter(|(j, _)| **j != me)
            .map(|(j, p)| (id(*j), p.clone()))
            .collect()
    };
    let mut rr2: BTreeMap<u16, BTreeMap<Identifier, _>> = BTreeMap::new();
    for (i, p) in rparts.iter_mut() {
        rr2.insert(*i, p.part2(&rothers(*i)).unwrap());
    }
    let mut refreshed = BTreeMap::new();
    for (i, p) in rparts.iter_mut() {
        let to_me: BTreeMap<Identifier, _> = rr2
            .iter()
            .filter(|(j, _)| **j != *i)
            .map(|(j, m)| (id(*j), m[&id(*i)].clone()))
            .collect();
        let (kp, pk) = (&dkg_shares[i].0, &dkg_shares[i].1);
        refreshed.insert(
            *i,
            p.part3(&rothers(*i), &to_me, pk.clone(), kp.clone())
                .unwrap(),
        );
    }
    for (i, pkg) in &rr1 {
        write(&format!("refresh/wire/round1-from-{i}.json"), &json(pkg));
        write(
            &format!("refresh/wire/round1-from-{i}.postcard.hex"),
            hex::encode(pkg.serialize().unwrap()).as_bytes(),
        );
    }
    for (i, m2) in &rr2 {
        for j in (1..=N).filter(|j| j != i) {
            write(
                &format!("refresh/wire/round2-{i}-to-{j}.json"),
                &json(&m2[&id(j)]),
            );
        }
    }
    let rpkp = refreshed[&1].1.clone();
    write("refresh/pkp.json", &json(&rpkp));
    write(
        "refresh/pkp.postcard.hex",
        hex::encode(rpkp.serialize().unwrap()).as_bytes(),
    );
    man.insert(
        "refresh_pkp_digest".into(),
        hex::encode(pkp_digest(&rpkp).unwrap()).into(),
    );
    for (i, (kp, p)) in &refreshed {
        let ks = KeyStore::open_with_sealer(
            dir().join(format!("refresh/node-{i}/keys")),
            Some(Arc::new(sealer(*i))),
        )
        .unwrap();
        let share = Share {
            key_package: kp.clone(),
            public_key_package: p.clone(),
            origin: None,
            epoch: 2,
            key_id: DKG_KEY.into(),
        };
        ks.create(DKG_KEY, &share).unwrap();
    }

    // A split ceremony: recipient files on each node, the dealer's bundles.
    let (seed, fingerprint) = fresh_split_key();
    let mut requests = Vec::new();
    for i in 1..=N {
        let data_dir = dir().join(format!("split/node-{i}"));
        let ctx = rutli_cosigner::share_import::NodeContext {
            data_dir: data_dir.clone(),
            identifier: i,
            threshold: T,
            max_signers: N,
            roster: (1..=N).collect(),
            cluster_id: pki::shared().cluster_id(),
        };
        let ks =
            KeyStore::open_with_sealer(data_dir.join("keys"), Some(Arc::new(sealer(i)))).unwrap();
        let signer = pki::shared().signer(&format!("cosigner{i}"));
        requests.push(
            rutli_cosigner::share_import::share_recipient(
                &ctx,
                &ks,
                &sealer(i),
                &signer,
                SPLIT_KEY,
                SPLIT_CEREMONY,
                false,
            )
            .unwrap(),
        );
        // The store itself is not part of the fixture.
        std::fs::remove_dir_all(data_dir.join("keys")).unwrap();
    }
    let roster: Vec<u16> = requests.iter().map(|r| r.identifier).collect();
    let (shares, spkp) = rutli_frost_core::dealer::split_ed25519_seed(&seed, &roster, T).unwrap();
    for (r, s) in requests.iter().zip(&shares) {
        let verified =
            rutli_cosigner::request_auth::verify_request(r, pki::shared().ca_pem.as_bytes())
                .unwrap();
        let usage = rutli_cosigner::carry::CarriedUsage {
            expected: "namespace".into(),
            recorded: Some(vec!["namespace".into()]),
            namespace_fingerprint: None,
        };
        let bundle = share_delivery::seal_share(&verified, s, &spkp, &fingerprint, &usage).unwrap();
        write(
            &format!("split/bundle-node{}.json", r.identifier),
            &json(&bundle),
        );
    }
    write("split/pkp.json", &json(&spkp));
    write(
        "split/pkp.postcard.hex",
        hex::encode(spkp.serialize().unwrap()).as_bytes(),
    );
    man.insert(
        "split_pkp_digest".into(),
        hex::encode(pkp_digest(&spkp).unwrap()).into(),
    );
    man.insert(
        "split_group_verifying_key".into(),
        hex::encode(group_verifying_key_bytes(&spkp).unwrap()).into(),
    );

    write(
        "manifest.json",
        &serde_json::to_vec_pretty(&serde_json::Value::Object(man)).unwrap(),
    );
}

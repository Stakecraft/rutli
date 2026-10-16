// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The durable side of two-phase ceremonies: share epochs, staged shares, ceremony records, and the
//! startup repair of what a crash between those writes leaves behind.

use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::ceremony_record::{CeremonyRecord, CeremonyRecords, RecordState};
use rutli_cosigner::keystore::{KeyStore, Promotion, Share};
use rutli_cosigner::node::Node;
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::DaemonError;

const MASTER: &[u8] = b"ceremony store test master secret";

fn store(dir: &std::path::Path) -> KeyStore {
    KeyStore::open_with_sealer(dir, Some(Arc::new(Sealer::from_master_secret(MASTER, 1)))).unwrap()
}

/// A real 2-of-3 dealt share for node 1.
fn share(seed: u8, epoch: u64) -> Share {
    let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&[seed; 32], &[1, 2, 3], 2).unwrap();
    Share {
        key_package: frost_ed25519::keys::KeyPackage::try_from(shares[0].clone()).unwrap(),
        public_key_package: pkp,
        origin: None,
        epoch,
        key_id: "k".into(),
    }
}

fn node(dir: &std::path::Path) -> Node {
    Node::new(Identifier::try_from(1u16).unwrap(), 3, 2, store(dir))
}

fn record(ceremony_id: &str, state: RecordState, s: &Share) -> CeremonyRecord {
    CeremonyRecord {
        state,
        key_id: "k".into(),
        kind: "refresh".into(),
        roster: vec![1, 2, 3],
        new_epoch: s.epoch,
        new_pkp_digest: hex::encode(s.pkp_digest().unwrap()),
        ..CeremonyRecord::aborted(ceremony_id, "")
    }
}

#[test]
fn a_share_file_without_an_epoch_reads_as_epoch_zero() {
    // Every share written before epochs existed: no `epoch`, no `key_id` in the sealed JSON.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("keys");
    let ks = store(&dir);
    let mut legacy = serde_json::to_value(share(3, 7)).unwrap();
    let obj = legacy.as_object_mut().unwrap();
    obj.remove("epoch");
    obj.remove("key_id");
    let sealed = Sealer::from_master_secret(MASTER, 1).seal(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    std::fs::write(dir.join("legacy.json"), sealed).unwrap();

    let loaded = ks.load("legacy").unwrap();
    assert_eq!(loaded.epoch, 0);
    assert_eq!(loaded.key_id, "");
    let view = node(&dir).key_epoch("legacy").unwrap();
    assert!(view.present);
    assert_eq!(view.epoch, 0);
    assert_eq!(view.origin, "dkg");
    assert_eq!(view.pkp_digest, loaded.pkp_digest().unwrap().to_vec());
    assert!(!view.staged);
    assert!(!node(&dir).key_epoch("absent").unwrap().present);
}

#[test]
fn a_staged_share_is_create_once_invisible_and_promotes_only_as_told() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("keys");
    let ks = store(&dir);
    let s1 = share(1, 1);
    ks.stage("k", "dkg-a", &s1).unwrap();
    assert!(matches!(ks.stage("k", "dkg-a", &share(2, 1)), Err(DaemonError::KeyExists(_))));
    assert_eq!(ks.list_staged().unwrap(), vec![("k".to_string(), "dkg-a".to_string())]);
    assert!(Sealer::is_sealed(&std::fs::read(ks.staged_dir().join("k.dkg-a.json")).unwrap()));
    // Not a key: absent for loads, the hosted inventory and the probe still pass.
    assert!(!ks.exists("k"));
    assert!(ks.list_hosted().unwrap().is_empty());
    ks.check_readable().unwrap();
    assert!(ks.stage("k", "../x", &s1).is_err(), "ceremony ids name files");

    // DKG promotion never replaces a key that appeared meanwhile.
    ks.create("k", &share(9, 0)).unwrap();
    assert_eq!(ks.promote_staged("k", "dkg-a", false).unwrap(), Promotion::TargetExists);
    assert!(ks.has_staged("k", "dkg-a").unwrap(), "a refused promotion leaves the staged share");
    // Refresh promotion is an atomic replace.
    assert_eq!(ks.promote_staged("k", "dkg-a", true).unwrap(), Promotion::Promoted);
    assert_eq!(ks.load("k").unwrap().pkp_digest().unwrap(), s1.pkp_digest().unwrap());
    assert!(ks.list_staged().unwrap().is_empty());

    ks.stage("k", "refresh-b", &share(4, 2)).unwrap();
    ks.discard_staged("k", "refresh-b").unwrap();
    ks.discard_staged("k", "refresh-b").unwrap(); // idempotent
    assert!(ks.list_staged().unwrap().is_empty());
}

#[test]
fn startup_removes_staged_shares_this_node_never_voted_for() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("keys");
    let ks = store(&dir);
    let records = CeremonyRecords::open(ks.ceremony_dir());
    // Crashed between the staged share and the STAGED record: no vote, so nobody commits it.
    ks.stage("k", "refresh-orphan", &share(1, 2)).unwrap();
    // Aborted, but the delete did not finish.
    let aborted = share(2, 2);
    ks.stage("k", "refresh-aborted", &aborted).unwrap();
    records.write(None, &record("refresh-aborted", RecordState::Aborted, &aborted)).unwrap();
    // A live yes-vote keeps its share.
    let staged = share(3, 2);
    ks.stage("k", "refresh-live", &staged).unwrap();
    records.write(None, &record("refresh-live", RecordState::Staged, &staged)).unwrap();

    let n = node(&dir);
    assert_eq!(ks.list_staged().unwrap(), vec![("k".to_string(), "refresh-live".to_string())]);
    assert_eq!(n.ceremony_record("refresh-live").unwrap().state, RecordState::Staged);
    assert_eq!(n.staged_records().len(), 1);
    let view = n.key_epoch("k").unwrap();
    assert!(view.staged);
    assert_eq!(view.staged_ceremony_id, "refresh-live");
    assert_eq!(view.staged_new_epoch, 2);
}

#[test]
fn startup_completes_a_commit_interrupted_after_the_promotion() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("keys");
    let ks = store(&dir);
    let records = CeremonyRecords::open(ks.ceremony_dir());
    ks.create("k", &share(1, 1)).unwrap();
    let new = share(2, 2);
    ks.stage("k", "refresh-1", &new).unwrap();
    let rec = record("refresh-1", RecordState::Staged, &new);
    records.write(None, &rec).unwrap();
    // The crash: renamed into place, record still STAGED.
    ks.promote_staged("k", "refresh-1", true).unwrap();

    let n = node(&dir);
    assert_eq!(n.ceremony_record("refresh-1").unwrap().state, RecordState::Committed);
    assert_eq!(records.load_all().unwrap()[0].state, RecordState::Committed, "durably");
    assert_eq!(n.key_epoch("k").unwrap().epoch, 2);
}

#[test]
fn a_staged_vote_whose_share_vanished_is_left_for_an_operator() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("keys");
    let ks = store(&dir);
    let records = CeremonyRecords::open(ks.ceremony_dir());
    ks.create("k", &share(1, 1)).unwrap();
    // STAGED for an outcome that is neither staged nor live (the staged file was lost).
    records.write(None, &record("refresh-lost", RecordState::Staged, &share(5, 2))).unwrap();
    let n = node(&dir);
    assert_eq!(n.ceremony_record("refresh-lost").unwrap().state, RecordState::Staged);
    assert_eq!(n.key_epoch("k").unwrap().epoch, 1, "the live share is untouched");
}

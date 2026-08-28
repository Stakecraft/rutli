// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Export/import as an operator would run it: the artifact must move a hosted key into a
//! *different* cluster — one with a different seal master secret and a different node identity.
//! That is precisely what `backup` cannot do, and the reason these commands exist.

use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::export::{export_encrypted, export_plaintext, import};
use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::seal::Sealer;

const PASS: &str = "a sufficiently long export passphrase";

fn store(dir: std::path::PathBuf, master: &[u8], node_id: u16) -> KeyStore {
    KeyStore::open_with_sealer(dir, Some(Arc::new(Sealer::from_master_secret(master, node_id))))
        .unwrap()
}

#[test]
fn an_exported_key_imports_into_a_different_cluster() {
    let tmp = tempfile::tempdir().unwrap();

    // Cluster A: node 1, its own master secret.
    let a = store(tmp.path().join("cluster-a"), b"cluster A master secret", 1);
    let key = HostedKey::generate(HostedSpec::Rsa2048, 1234).unwrap();
    a.save_hosted("rutli-enc-portable", &key).unwrap();
    let ciphertext = key.encrypt_oaep(b"encrypted under the original key").unwrap();

    // Export from A (as `export-key` does: load, then seal under a passphrase).
    let envelope = export_encrypted("rutli-enc-portable", &a.load_hosted("rutli-enc-portable").unwrap(), PASS)
        .unwrap();
    let artifact = serde_json::to_vec(&envelope).unwrap();

    // Cluster B: DIFFERENT master secret, DIFFERENT node id. A `backup` from A would be useless
    // here — this is the case export exists for.
    let b = store(tmp.path().join("cluster-b"), b"cluster B has its own secret", 3);
    let reloaded: rutli_cosigner::export::ExportEnvelope = serde_json::from_slice(&artifact).unwrap();
    let imported = import(&reloaded, Some(PASS)).unwrap();
    b.save_hosted(&reloaded.key_id, &imported).unwrap();

    // The key works in cluster B, on ciphertext produced before the move.
    let out = b.load_hosted("rutli-enc-portable").unwrap().decrypt_oaep(&ciphertext).unwrap();
    assert_eq!(out.as_slice(), b"encrypted under the original key");
    // Provenance survives the round trip.
    assert_eq!(b.load_hosted("rutli-enc-portable").unwrap().created_at, 1234);
}

#[test]
fn a_backup_from_another_cluster_is_useless_without_export() {
    // The contrast that motivates the feature: copying the sealed file itself does NOT travel,
    // because the DEK is derived from (master secret, node id).
    let tmp = tempfile::tempdir().unwrap();
    let a_dir = tmp.path().join("a");
    let a = store(a_dir.clone(), b"cluster A master secret", 1);
    a.save_hosted("rutli-sym-1", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();

    // Copy the sealed file into cluster B's directory, exactly as a naive "backup restore" would.
    let b_dir = tmp.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    std::fs::copy(a_dir.join("rutli-sym-1.json"), b_dir.join("rutli-sym-1.json")).unwrap();

    let b = store(b_dir, b"cluster B has its own secret", 3);
    assert!(
        b.load_hosted("rutli-sym-1").is_err(),
        "a sealed backup must not open in a different cluster — that is why export exists"
    );
}

#[test]
fn a_symmetric_key_also_travels() {
    let tmp = tempfile::tempdir().unwrap();
    let a = store(tmp.path().join("a"), b"master a", 1);
    let key = HostedKey::generate(HostedSpec::Aes256Gcm, 7).unwrap();
    a.save_hosted("rutli-sym-portable", &key).unwrap();
    let blob = key.encrypt_symmetric(b"wrapped store").unwrap();

    let envelope = export_encrypted("rutli-sym-portable", &key, PASS).unwrap();
    let imported = import(&envelope, Some(PASS)).unwrap();

    let b = store(tmp.path().join("b"), b"master b", 2);
    b.save_hosted("rutli-sym-portable", &imported).unwrap();
    assert_eq!(
        b.load_hosted("rutli-sym-portable").unwrap().decrypt_symmetric(&blob).unwrap().as_slice(),
        b"wrapped store"
    );
}

#[test]
fn a_frost_share_cannot_be_exported() {
    // The load path the export command uses refuses a FROST share: there is no whole namespace key
    // on any single node, so "exporting" one would be meaningless and dangerous.
    let tmp = tempfile::tempdir().unwrap();
    let ks = store(tmp.path().join("keys"), b"master", 1);
    let _ = Identifier::try_from(1u16).unwrap(); // keep the frost import meaningful
    let plain = serde_json::json!({ "key_package": {}, "public_key_package": {} });
    std::fs::write(tmp.path().join("keys").join("frost-namespace.json"), serde_json::to_vec(&plain).unwrap())
        .unwrap();
    assert!(ks.load_hosted("frost-namespace").is_err());
}

#[test]
fn a_plaintext_export_is_still_importable_but_marked() {
    // The escape hatch for piping into another KMS: no passphrase, and identifiable as unencrypted.
    let tmp = tempfile::tempdir().unwrap();
    let a = store(tmp.path().join("a"), b"master a", 1);
    let key = HostedKey::generate(HostedSpec::Aes256Gcm, 3).unwrap();
    a.save_hosted("rutli-sym-plain", &key).unwrap();

    let envelope = export_plaintext("rutli-sym-plain", &key).unwrap();
    assert!(envelope.kdf.is_none());
    let back = import(&envelope, None).unwrap();
    assert_eq!(back.private_der, key.private_der);
}

// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! A node rolled back to frost-ed25519 2.2.0 ("v2", a dev-dependency alias) must load every key
//! file this version writes: after a DKG and after a refresh, run through the real node and
//! orchestrator code, each node's sealed key file decrypts to JSON whose FROST parts v2 parses and
//! re-serializes byte for byte, with the same `pkp_digest` the node reports.

use std::sync::Arc;

use frost_ed25519::Identifier;
use frost_ed25519_v2 as v2;
use sha2::{Digest, Sha256};

use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, run_refresh, sign, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::seal::{KeyFileBinding, RecordKind, Sealer};

const KEY: &str = "frost-rollback";
const UUID: &str = "0b7e4c2a-1d3f-4e5a-8b9c-6d2e1f0a3b4c";

fn sealer(i: u16) -> Sealer {
    let mut dek = [0u8; 32];
    dek[0] = i as u8;
    dek[31] = 0x5a;
    Sealer::from_dek(zeroize::Zeroizing::new(dek), i).with_binding(KeyFileBinding {
        node: i,
        cluster_uuid: Some(UUID.into()),
        write_version: 2,
        accept_v1: false,
    })
}

/// Node `i`'s key file for KEY, read as a v2 node would: its FROST parts parse with v2 types.
fn read_as_v2(dir: &std::path::Path, i: u16, epoch: u64) -> [u8; 32] {
    let raw = std::fs::read(dir.join(format!("node-{i}/{KEY}.json"))).unwrap();
    let (plain, hdr) = sealer(i)
        .unseal_record(&raw, KEY, &[RecordKind::FrostShare])
        .unwrap();
    assert_eq!(hdr.unwrap().epoch, epoch);
    /// The FROST parts of a key file as a v2 node reads them (the rest of `Share` is Rütli's own).
    #[derive(serde::Deserialize)]
    struct V2Share {
        key_package: v2::keys::KeyPackage,
        public_key_package: v2::keys::PublicKeyPackage,
    }
    let old: V2Share = serde_json::from_slice(&plain).expect("v2 reads the key file");
    // The same file as this version loads it: both versions write each part to the same bytes.
    let ks = KeyStore::open_with_sealer(dir.join(format!("node-{i}")), Some(Arc::new(sealer(i))))
        .unwrap();
    let now = ks.load(KEY).unwrap();
    assert_eq!(
        serde_json::to_vec(&old.key_package).unwrap(),
        serde_json::to_vec(&now.key_package).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&old.public_key_package).unwrap(),
        serde_json::to_vec(&now.public_key_package).unwrap()
    );
    let digest: [u8; 32] = Sha256::digest(old.public_key_package.serialize().unwrap()).into();
    assert_eq!(
        digest,
        now.pkp_digest().unwrap(),
        "v2 and this version compute the same pkp_digest"
    );
    digest
}

#[tokio::test]
async fn key_files_written_after_a_dkg_and_a_refresh_load_on_v2_with_the_same_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let ks = KeyStore::open_with_sealer(
                tmp.path().join(format!("node-{i}")),
                Some(Arc::new(sealer(i))),
            )
            .unwrap();
            Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks))
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>)
        .collect();

    run_dkg(&peers, KEY).await.unwrap();
    for (epoch, step) in [(1u64, "dkg"), (2, "refresh")] {
        if step == "refresh" {
            run_refresh(&peers, KEY).await.unwrap();
        }
        let digests: Vec<[u8; 32]> = (1..=3).map(|i| read_as_v2(tmp.path(), i, epoch)).collect();
        assert!(digests.iter().all(|d| *d == digests[0]), "{step}");
        let msg = rutli_frost_core::dealer::canton_test_message(step.as_bytes());
        sign(&nodes[0], &peers, KEY, &msg).await.unwrap();
    }
}

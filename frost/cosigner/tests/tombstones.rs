// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Audit M2: hosted-key deletes are authorized tombstones.
//!
//! Before, `DeleteKey` (any driver-certificate holder) or `PurgeKey` (any one cosigner) physically
//! removed a hosted key on every node, and anti-entropy pushed a "deleted" key back from any node
//! that missed the delete. Now a delete needs a client-signed delete intent from the delete role,
//! every node verifies it itself, the key becomes a tombstone that keeps its material for a grace
//! period, a valid tombstone beats a live copy in anti-entropy, and a tombstoned id is never
//! regenerated short of a break-glass on every node.
//!
//! Three nodes (2-of-3) with hosted keys, key-file format v2 and the signing policy, wired in
//! process (`LocalPeer`) and, for the role checks, over real mutual TLS.

#[path = "common/pki.rs"]
mod pki;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use rutli_cosigner::config::{ApproverConfig, SigningPolicyConfig};
use rutli_cosigner::hosted::HostedSpec;
use rutli_cosigner::intent::{self, DeletePolicy, IntentVerifier};
use rutli_cosigner::journal::{Retention, SignJournal};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{Node, Round1Ctx, TombstoneOutcome};
use rutli_cosigner::orchestrator::{anti_entropy_sweep, delete_hosted_key, generate_hosted_key, Peers};
use rutli_cosigner::pb;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi};
use rutli_cosigner::seal::{KeyFileBinding, Sealer};
use rutli_cosigner::sign_policy::SignGuard;
use rutli_cosigner::{DaemonError, Result};

const N: u16 = 3;
const T: u16 = 2;
const MASTER: &[u8] = b"tombstone test cluster master secret";
const CLUSTER: &str = "m2testcluster000";
const UUID: &str = "0d6b9a3e-41f0-4c55-8e0e-6b0f2a9c1d7e";

/// Identities: the three cosigners, the driver (signer role), the operator (delete role), and an
/// approver's Ed25519 key.
struct Ids {
    pki: pki::TestPki,
    pems: std::collections::BTreeMap<String, (String, String)>,
    approver: ed25519_dalek::SigningKey,
}

fn leaf(pki: &pki::TestPki, cn: &str) -> (String, String) {
    pki.leaf_custom(|p| {
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.subject_alt_names = vec![rcgen::SanType::DnsName(cn.try_into().unwrap())];
    })
}

impl Ids {
    fn new() -> Self {
        let pki = pki::TestPki::new();
        let mut pems = std::collections::BTreeMap::new();
        for cn in ["cosigner1", "cosigner2", "cosigner3", "driver", "operator"] {
            pems.insert(cn.to_string(), leaf(&pki, cn));
        }
        Self { pki, pems, approver: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]) }
    }

    fn signer(&self, who: &str) -> rutli_cosigner::request_auth::NodeSigner {
        let (c, k) = &self.pems[who];
        rutli_cosigner::request_auth::NodeSigner::from_pem(c.as_bytes(), k.as_bytes()).unwrap()
    }

    fn approver_spki_b64(&self) -> String {
        let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        der.extend_from_slice(self.approver.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(der)
    }
}

fn delete_intent(ids: &Ids, who: &str, key_id: &str) -> pb::SignedIntent {
    let now = intent::now_ms();
    sign(ids, who, unsigned_delete(key_id, now, now + 60_000))
}

fn unsigned_delete(key_id: &str, issued: u64, not_after: u64) -> pb::SignIntent {
    pb::SignIntent {
        version: 1,
        cluster_id: CLUSTER.into(),
        purpose: intent::PURPOSE_DELETE_KEY.into(),
        key_id: key_id.into(),
        digest: intent::delete_digest(key_id).to_vec(),
        request_id: vec![9; 16],
        issued_at_ms: issued,
        not_after_ms: not_after,
        approval_nonce: Vec::new(),
        approvals: Vec::new(),
    }
}

fn sign(ids: &Ids, who: &str, i: pb::SignIntent) -> pb::SignedIntent {
    intent::sign_intent(&ids.signer(who), &i).unwrap()
}

struct Cluster {
    ids: Ids,
    nodes: Vec<Arc<Node>>,
    peers: Peers,
    root: PathBuf,
    _tmp: tempfile::TempDir,
}

fn keys_dir(root: &Path, i: u16) -> PathBuf {
    root.join(format!("node-{i}")).join("keys")
}

fn open_node(root: &Path, ids: &Ids, i: u16, delete: &DeletePolicy, policy: &SigningPolicyConfig, grace: Duration) -> Arc<Node> {
    let sealer = Sealer::from_master_secret(MASTER, i).with_binding(KeyFileBinding {
        node: i,
        cluster_uuid: Some(UUID.into()),
        write_version: 2,
        accept_v1: true,
    });
    let ks = KeyStore::open_with_sealer(keys_dir(root, i), Some(Arc::new(sealer))).unwrap();
    let verifier = IntentVerifier::new(ids.pki.ca_pem.as_bytes().to_vec(), false, CLUSTER.into(), ["driver".to_string()], policy)
        .unwrap()
        .with_delete_policy(delete.clone());
    let journal = SignJournal::open(root.join(format!("node-{i}")).join("journal"), i, Retention { days: 90, max_bytes: 64 << 20 }).unwrap();
    let guard = Arc::new(SignGuard::new(Arc::new(verifier), journal, 10));
    Arc::new(
        Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
            .with_hosted_keys(MASTER, CLUSTER.to_string())
            .unwrap()
            .with_sign_guard(guard)
            .with_delete_grace(grace),
    )
}

fn operator_deletes() -> DeletePolicy {
    DeletePolicy { allowlist: ["operator".to_string()].into(), ..Default::default() }
}

fn cluster() -> Cluster {
    cluster_with(operator_deletes(), SigningPolicyConfig::default(), Duration::from_secs(7 * 86400))
}

fn cluster_with(delete: DeletePolicy, policy: SigningPolicyConfig, grace: Duration) -> Cluster {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let ids = Ids::new();
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| open_node(&root, &ids, i, &delete, &policy, grace)).collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    Cluster { ids, nodes, peers, root, _tmp: tmp }
}

impl Cluster {
    async fn generate(&self, key_id: &str) -> rutli_cosigner::hosted::HostedKey {
        generate_hosted_key(&self.nodes[0], &self.peers, key_id, HostedSpec::Aes256Gcm, 2).await.unwrap().0
    }

    fn file(&self, i: u16, key_id: &str) -> PathBuf {
        keys_dir(&self.root, i).join(format!("{key_id}.json"))
    }

    /// Every node's verdict on `key_id`: (live, tombstoned).
    fn states(&self, key_id: &str) -> Vec<(bool, bool)> {
        self.nodes.iter().map(|n| (n.hosted_exists(key_id), n.hosted_tombstoned(key_id).unwrap())).collect()
    }
}

fn refused(r: Result<impl std::fmt::Debug>, needle: &str) {
    let e = r.expect_err("must be refused");
    assert!(matches!(e, DaemonError::PolicyRefused(_)), "{e:?}");
    assert!(e.to_string().contains(needle), "expected {needle:?} in {e}");
}

// ── deleting ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_signed_delete_tombstones_the_key_on_every_node_and_retains_its_material() {
    let c = cluster();
    let key = c.generate("rutli-sym-1").await;
    let blob = key.encrypt_symmetric(b"wrapped").unwrap();

    let (deleted, tombstones) =
        delete_hosted_key(&c.peers, "rutli-sym-1", &delete_intent(&c.ids, "operator", "rutli-sym-1"), 2).await.unwrap();
    assert!(deleted);
    assert_eq!(tombstones, 3);
    assert_eq!(c.states("rutli-sym-1"), vec![(false, true); 3]);
    for n in &c.nodes {
        // Never served: NOT_FOUND, exactly like a key that never existed.
        assert!(matches!(n.hosted_load("rutli-sym-1"), Err(DaemonError::UnknownKey(_))));
        assert!(n.hosted_decrypt_symmetric("rutli-sym-1", &blob).is_err());
        assert!(n.hosted_list().unwrap().is_empty());
        // The material is still there, sealed inside the tombstone, for the grace period.
        let t = n.hosted_tombstones().unwrap().pop().unwrap();
        assert_eq!(t.retained.as_ref().unwrap().private_der, key.private_der);
        assert!(t.purge_after_ms >= t.deleted_at_ms + 7 * 86_400_000 - 1);
    }
    // The tombstone is a sealed v2 file of kind "tombstone", nothing readable on disk.
    let raw = std::fs::read(c.file(2, "rutli-sym-1")).unwrap();
    assert_eq!(rutli_cosigner::seal::header_of(&raw).unwrap().kind, "tombstone");
    assert!(!String::from_utf8_lossy(&raw).contains(&key.private_der));

    // Idempotent: a retried delete changes nothing.
    let again = delete_hosted_key(&c.peers, "rutli-sym-1", &delete_intent(&c.ids, "operator", "rutli-sym-1"), 2).await.unwrap();
    assert_eq!(again, (false, 3));
}

#[tokio::test]
async fn unsigned_forged_or_unauthorized_deletes_are_refused_at_every_node() {
    let c = cluster();
    c.generate("rutli-sym-2").await;
    let now = intent::now_ms();
    let cases: Vec<(&str, pb::SignedIntent, &str)> = vec![
        // The driver holds the signer role, not the delete role.
        ("driver", delete_intent(&c.ids, "driver", "rutli-sym-2"), "not on this node's hosted_keys.delete_allowlist"),
        // A cosigner certificate (a compromised node) can never delete.
        ("cosigner", delete_intent(&c.ids, "cosigner3", "rutli-sym-2"), "delete_allowlist"),
        // A valid delete of another key.
        ("other key", delete_intent(&c.ids, "operator", "rutli-sym-other"), "intent deletes rutli-sym-other"),
        // A signing intent is not a delete.
        ("purpose", sign(&c.ids, "operator", pb::SignIntent { purpose: "sign".into(), ..unsigned_delete("rutli-sym-2", now, now + 60_000) }), "purpose"),
        // Expired.
        ("expired", sign(&c.ids, "operator", unsigned_delete("rutli-sym-2", now - 600_000, now - 590_000)), "expired"),
        // Another cluster.
        ("cluster", sign(&c.ids, "operator", pb::SignIntent { cluster_id: "othercluster0000".into(), ..unsigned_delete("rutli-sym-2", now, now + 60_000) }), "cluster"),
    ];
    for (what, bad, needle) in &cases {
        for p in &c.peers {
            refused(p.delete_key("delkey-x", "rutli-sym-2", bad).await, needle);
        }
        assert!(delete_hosted_key(&c.peers, "rutli-sym-2", bad, 2).await.is_err(), "{what}");
    }
    // Forged: the operator's intent with its bytes altered after signing.
    let mut forged = delete_intent(&c.ids, "operator", "rutli-sym-other");
    forged.intent = prost::Message::encode_to_vec(&unsigned_delete("rutli-sym-2", now, now + 60_000));
    for p in &c.peers {
        refused(p.delete_key("delkey-x", "rutli-sym-2", &forged).await, "signature");
    }
    // A peer's PurgeKey without an intent is only a rollback of its own fenced generation.
    for p in &c.peers {
        refused(p.purge_key("genkey-anything", "rutli-sym-2").await, "not the rollback");
    }
    assert_eq!(c.states("rutli-sym-2"), vec![(true, false); 3], "the key is untouched everywhere");
}

#[tokio::test]
async fn delete_approvals_are_counted_by_every_node() {
    let ids_policy = |ids: &Ids| SigningPolicyConfig {
        approvers: vec![ApproverConfig { id: "alice".into(), public_key_spki_b64: ids.approver_spki_b64() }],
        ..Default::default()
    };
    // The cluster's own identities, so the approver key matches.
    let probe = Ids::new();
    let policy = ids_policy(&probe);
    let delete = DeletePolicy { approval_threshold: 1, ..operator_deletes() };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| open_node(&root, &probe, i, &delete, &policy, Duration::from_secs(60))).collect();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    generate_hosted_key(&nodes[0], &peers, "rutli-sym-gated", HostedSpec::Aes256Gcm, 2).await.unwrap();

    // Without an approval: refused everywhere.
    let bare = delete_intent(&probe, "operator", "rutli-sym-gated");
    refused(delete_hosted_key(&peers, "rutli-sym-gated", &bare, 2).await, "approval");
    let now = intent::now_ms();
    let nonce = vec![3u8; 16];
    use ed25519_dalek::Signer as _;
    // Audit F6: alice's approval of what looks like a SIGN request over the same digest (the
    // sign-format request id) does not approve the delete.
    let sign_format = intent::approval_request_id("rutli-sym-gated", &intent::delete_digest("rutli-sym-gated"), &nonce);
    let as_sign = pb::IntentApproval {
        approver_id: "alice".into(),
        signature: probe.approver.sign(sign_format.as_bytes()).to_bytes().to_vec(),
    };
    let mislabeled = sign(
        &probe,
        "operator",
        pb::SignIntent { approval_nonce: nonce.clone(), approvals: vec![as_sign], ..unsigned_delete("rutli-sym-gated", now, now + 60_000) },
    );
    refused(delete_hosted_key(&peers, "rutli-sym-gated", &mislabeled, 2).await, "approval");
    // With alice's approval of the DELETE (what rutli-approve signs for `delete:<key>`).
    let request_id = intent::delete_approval_request_id("rutli-sym-gated", &intent::delete_digest("rutli-sym-gated"), &nonce);
    let approval = pb::IntentApproval {
        approver_id: "alice".into(),
        signature: probe.approver.sign(request_id.as_bytes()).to_bytes().to_vec(),
    };
    let approved = sign(
        &probe,
        "operator",
        pb::SignIntent { approval_nonce: nonce, approvals: vec![approval], ..unsigned_delete("rutli-sym-gated", now, now + 60_000) },
    );
    assert!(delete_hosted_key(&peers, "rutli-sym-gated", &approved, 2).await.unwrap().0);
    assert!(nodes.iter().all(|n| n.hosted_tombstoned("rutli-sym-gated").unwrap()));
}

#[tokio::test]
async fn a_delete_acl_limits_what_the_delete_role_may_delete() {
    let delete = DeletePolicy {
        acl: [("operator".to_string(), vec!["rutli-tenant-a-".to_string()])].into(),
        ..operator_deletes()
    };
    let c = cluster_with(delete, SigningPolicyConfig::default(), Duration::from_secs(60));
    c.generate("rutli-tenant-b-key").await;
    refused(
        delete_hosted_key(&c.peers, "rutli-tenant-b-key", &delete_intent(&c.ids, "operator", "rutli-tenant-b-key"), 2).await,
        "delete_acl",
    );
    c.generate("rutli-tenant-a-key").await;
    assert!(delete_hosted_key(&c.peers, "rutli-tenant-a-key", &delete_intent(&c.ids, "operator", "rutli-tenant-a-key"), 2)
        .await
        .unwrap()
        .0);
}

// ── anti-entropy ──────────────────────────────────────────────────────────────────────────────

/// The audit's scenario (a): a key deleted while node 3 is down. Node 3 comes back with its live
/// copy; no sweep may push it back, and node 3's own sweep converts it. Then a node restored from a
/// backup taken before the delete gets the same treatment.
#[tokio::test]
async fn a_valid_tombstone_propagates_and_beats_a_stale_replica() {
    let c = cluster();
    c.generate("rutli-sym-3").await;
    let backup_of_node2 = std::fs::read(c.file(2, "rutli-sym-3")).unwrap();

    // Node 3 is down during the delete.
    let up: Peers = c.peers.iter().take(2).cloned().collect();
    let (_, tombstones) =
        delete_hosted_key(&up, "rutli-sym-3", &delete_intent(&c.ids, "operator", "rutli-sym-3"), 2).await.unwrap();
    assert_eq!(tombstones, 2);
    assert_eq!(c.states("rutli-sym-3"), vec![(false, true), (false, true), (true, false)]);

    // Node 3 is back. The tombstoned nodes' sweeps neither push nor pull the key.
    for n in &c.nodes[..2] {
        anti_entropy_sweep(n, &c.peers).await.unwrap();
    }
    assert_eq!(c.states("rutli-sym-3"), vec![(false, true), (false, true), (true, false)]);
    // Node 3's sweep applies the peers' tombstone (an expired intent is fine for propagation).
    anti_entropy_sweep(&c.nodes[2], &c.peers).await.unwrap();
    assert_eq!(c.states("rutli-sym-3"), vec![(false, true); 3]);
    assert!(c.nodes[2].hosted_tombstones().unwrap()[0].retained.is_some(), "its material is kept for undelete");

    // Node 2 restored from its old backup: the live copy is back on disk...
    std::fs::write(c.file(2, "rutli-sym-3"), &backup_of_node2).unwrap();
    assert!(c.nodes[1].hosted_exists("rutli-sym-3"));
    // ...the others never take it, and its own sweep re-applies the tombstone.
    for i in [0, 2] {
        anti_entropy_sweep(&c.nodes[i], &c.peers).await.unwrap();
    }
    anti_entropy_sweep(&c.nodes[1], &c.peers).await.unwrap();
    assert_eq!(c.states("rutli-sym-3"), vec![(false, true); 3]);

    // A node that never had the key records the tombstone, so the key can never arrive there.
    let fresh = tempfile::tempdir().unwrap();
    let late = open_node(fresh.path(), &c.ids, 3, &operator_deletes(), &SigningPolicyConfig::default(), Duration::from_secs(60));
    let as_late: Peers = c.nodes[..2]
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone()).on_behalf_of(late.clone())) as Arc<dyn PeerApi>)
        .chain(std::iter::once(Arc::new(LocalPeer::new(late.clone())) as Arc<dyn PeerApi>))
        .collect();
    anti_entropy_sweep(&late, &as_late).await.unwrap();
    assert!(late.hosted_tombstoned("rutli-sym-3").unwrap());
}

/// A peer listing a tombstone it cannot back with a valid delete intent (a compromised node, an
/// intent from the driver) changes nothing here.
#[tokio::test]
async fn a_forged_tombstone_from_a_peer_is_refused() {
    let c = cluster();
    c.generate("rutli-sym-4").await;
    let liar: Arc<dyn PeerApi> = Arc::new(LyingPeer {
        inner: Arc::new(LocalPeer::new(c.nodes[2].clone())),
        manifest: vec![
            tomb("rutli-sym-4", delete_intent(&c.ids, "driver", "rutli-sym-4")),
            tomb("rutli-sym-4", delete_intent(&c.ids, "cosigner3", "rutli-sym-4")),
            pb::KeyManifest { key_id: "rutli-sym-4".into(), tombstone: true, delete_intent: b"garbage".to_vec(), ..Default::default() },
        ],
    });
    let peers: Peers = vec![c.peers[0].clone(), c.peers[1].clone(), liar];
    anti_entropy_sweep(&c.nodes[0], &peers).await.unwrap();
    assert!(c.nodes[0].hosted_exists("rutli-sym-4"));
    assert!(!c.nodes[0].hosted_tombstoned("rutli-sym-4").unwrap());
}

fn tomb(key_id: &str, intent: pb::SignedIntent) -> pb::KeyManifest {
    pb::KeyManifest {
        key_id: key_id.into(),
        tombstone: true,
        delete_intent: prost::Message::encode_to_vec(&intent),
        ..Default::default()
    }
}

/// A peer that answers `ListKeys` with a made-up inventory.
struct LyingPeer {
    inner: Arc<LocalPeer>,
    manifest: Vec<pb::KeyManifest>,
}

#[async_trait]
impl PeerApi for LyingPeer {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, k: &str, s: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        self.inner.sign_round1(k, s, ctx).await
    }
    async fn sign_round2(
        &self,
        k: &str,
        s: &str,
        m: &[u8],
        c: &std::collections::BTreeMap<Identifier, SigningCommitments>,
        d: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.inner.sign_round2(k, s, m, c, d).await
    }
    async fn abort_sign(&self, k: &str, s: &str) -> Result<()> {
        self.inner.abort_sign(k, s).await
    }
    async fn ceremony_fence(&self, c: &str, k: &str, kind: &'static str) -> Result<()> {
        self.inner.ceremony_fence(c, k, kind).await
    }
    async fn ceremony_release(&self, c: &str, k: &str) -> Result<()> {
        self.inner.ceremony_release(c, k).await
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(&self, c: &str, k: &str, s: &str, p: &[u8], w: &rutli_cosigner::wrap::Wrapped) -> Result<Vec<u8>> {
        self.inner.replicate_key(c, k, s, p, w).await
    }
    async fn fetch_key(&self, k: &str) -> Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(k).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        Ok(Vec::new())
    }
    async fn list_inventory(&self) -> Result<Vec<pb::KeyManifest>> {
        Ok(self.manifest.clone())
    }
    async fn purge_key(&self, c: &str, k: &str) -> Result<bool> {
        self.inner.purge_key(c, k).await
    }
}

// ── grace, undelete, regeneration ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn undelete_within_grace_restores_the_key_and_the_old_tombstone_no_longer_applies() {
    let c = cluster();
    let key = c.generate("rutli-sym-5").await;
    let blob = key.encrypt_symmetric(b"still mine").unwrap();
    delete_hosted_key(&c.peers, "rutli-sym-5", &delete_intent(&c.ids, "operator", "rutli-sym-5"), 2).await.unwrap();

    // `hosted-undelete` on node 1 only (offline, its own key store): it serves again...
    let ks1 = KeyStore::open_with_sealer(
        keys_dir(&c.root, 1),
        Some(Arc::new(Sealer::from_master_secret(MASTER, 1).with_binding(KeyFileBinding {
            node: 1,
            cluster_uuid: Some(UUID.into()),
            write_version: 2,
            accept_v1: true,
        }))),
    )
    .unwrap();
    let restored = ks1.undelete("rutli-sym-5", intent::now_ms()).unwrap();
    assert!(restored.undeleted_at_ms.is_some());
    assert_eq!(c.nodes[0].hosted_decrypt_symmetric("rutli-sym-5", &blob).unwrap(), b"still mine");
    // ...and the peers' tombstone — whose intent predates the undelete — does not re-delete it.
    anti_entropy_sweep(&c.nodes[0], &c.peers).await.unwrap();
    assert!(c.nodes[0].hosted_exists("rutli-sym-5"));
    assert!(c.nodes[1].hosted_tombstoned("rutli-sym-5").unwrap(), "undelete is per node");
    assert!(ks1.undelete("rutli-sym-5", 0).is_err(), "nothing to undelete any more");
    // A NEW delete still works on the undeleted copy.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let outcome = c.nodes[0]
        .hosted_apply_tombstone("rutli-sym-5", &delete_intent(&c.ids, "operator", "rutli-sym-5"), intent::Expiry::Enforce, None)
        .unwrap();
    assert_eq!(outcome, TombstoneOutcome::Converted);
}

#[tokio::test]
async fn past_the_grace_period_the_retained_material_is_dropped() {
    let c = cluster_with(operator_deletes(), SigningPolicyConfig::default(), Duration::from_millis(1));
    c.generate("rutli-sym-6").await;
    delete_hosted_key(&c.peers, "rutli-sym-6", &delete_intent(&c.ids, "operator", "rutli-sym-6"), 2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    // The sweep drops it (here node 1's; every node sweeps its own).
    anti_entropy_sweep(&c.nodes[0], &c.peers).await.unwrap();
    let t = c.nodes[0].hosted_tombstones().unwrap().pop().unwrap();
    assert!(t.retained.is_none());
    assert!(!String::from_utf8_lossy(&std::fs::read(c.file(1, "rutli-sym-6")).unwrap()).contains("retained"));
}

#[tokio::test]
async fn a_tombstone_blocks_regenerating_the_id_until_cleared_on_every_node() {
    let c = cluster_with(operator_deletes(), SigningPolicyConfig::default(), Duration::from_millis(1));
    c.generate("rutli-sym-7").await;
    delete_hosted_key(&c.peers, "rutli-sym-7", &delete_intent(&c.ids, "operator", "rutli-sym-7"), 2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    for n in &c.nodes {
        n.hosted_purge_expired(intent::now_ms()).unwrap();
    }

    let again = generate_hosted_key(&c.nodes[0], &c.peers, "rutli-sym-7", HostedSpec::Aes256Gcm, 2).await;
    assert!(matches!(&again, Err(DaemonError::KeyExists(m)) if m.contains("tombstoned")), "{again:?}");

    // Break-glass on node 1 only: its peers still refuse the id, so the generation fails and rolls
    // back — node 1 keeps no lonely copy — and node 1 ignores the cleared intent from its peers.
    let ks = |i: u16| {
        KeyStore::open_with_sealer(
            keys_dir(&c.root, i),
            Some(Arc::new(Sealer::from_master_secret(MASTER, i).with_binding(KeyFileBinding {
                node: i,
                cluster_uuid: Some(UUID.into()),
                write_version: 2,
                accept_v1: true,
            }))),
        )
        .unwrap()
    };
    ks(1).clear_tombstone("rutli-sym-7").unwrap();
    let partial = generate_hosted_key(&c.nodes[0], &c.peers, "rutli-sym-7", HostedSpec::Aes256Gcm, 2).await;
    assert!(matches!(&partial, Err(DaemonError::KeyExists(m)) if m.contains("tombstoned")), "{partial:?}");
    assert!(!c.nodes[0].hosted_exists("rutli-sym-7"), "rolled back");
    anti_entropy_sweep(&c.nodes[0], &c.peers).await.unwrap();
    assert!(!c.nodes[0].hosted_tombstoned("rutli-sym-7").unwrap(), "a cleared intent stays cleared");

    // Cleared everywhere: the id is generated afresh, and stays.
    ks(2).clear_tombstone("rutli-sym-7").unwrap();
    ks(3).clear_tombstone("rutli-sym-7").unwrap();
    generate_hosted_key(&c.nodes[0], &c.peers, "rutli-sym-7", HostedSpec::Aes256Gcm, 2).await.unwrap();
    for n in &c.nodes {
        anti_entropy_sweep(n, &c.peers).await.unwrap();
    }
    assert_eq!(c.states("rutli-sym-7"), vec![(true, false); 3]);
}

#[tokio::test]
async fn a_write_quorum_rollback_purges_only_the_generations_own_key() {
    let c = cluster();
    c.generate("rutli-sym-8").await;
    // A compromised leader fences an existing key and asks for a "rollback": refused, the key it
    // did not create in that generation stays.
    c.peers[1].ceremony_fence("genkey-evil", "rutli-sym-8", "genkey").await.unwrap();
    refused(c.peers[1].purge_key("genkey-evil", "rutli-sym-8").await, "not the rollback");
    c.peers[1].ceremony_release("genkey-evil", "rutli-sym-8").await.unwrap();
    assert!(c.nodes[1].hosted_exists("rutli-sym-8"));
    // A tombstone outcome sanity check on the direct path.
    let outcome = c.nodes[1]
        .hosted_apply_tombstone("rutli-sym-8", &delete_intent(&c.ids, "operator", "rutli-sym-8"), intent::Expiry::Enforce, None)
        .unwrap();
    assert_eq!(outcome, TombstoneOutcome::Converted);
}

// ── the delete role over mutual TLS ───────────────────────────────────────────────────────────

/// The Signer and Peer APIs of the three nodes over real mTLS: only the delete role may call
/// DeleteKey, the intent must be the caller's own, and a cosigner certificate cannot purge.
#[tokio::test]
async fn the_driver_certificate_cannot_delete_and_the_delete_role_can() {
    use rutli_cosigner::pb::peer_client::PeerClient;
    use rutli_cosigner::pb::signer_client::SignerClient;
    let c = cluster();
    c.generate("rutli-sym-9").await;
    let dir = c.root.join("certs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.pem"), &c.ids.pki.ca_pem).unwrap();
    let tls_for = |cn: &str| {
        let (cert, key) = &c.ids.pems[cn];
        std::fs::write(dir.join(format!("{cn}.pem")), cert).unwrap();
        std::fs::write(dir.join(format!("{cn}.key")), key).unwrap();
        rutli_cosigner::tls::load(&rutli_cosigner::config::TlsConfig {
            ca_cert: dir.join("ca.pem"),
            cert: dir.join(format!("{cn}.pem")),
            key: dir.join(format!("{cn}.key")),
            domain: None,
            allow_expired_ca: false,
        })
        .unwrap()
    };
    let mut listeners = Vec::new();
    for _ in 0..N {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let endpoints: Vec<String> = listeners.iter().map(|l| format!("https://{}", l.local_addr().unwrap())).collect();
    let tls: Vec<_> = (1..=N).map(|i| tls_for(&format!("cosigner{i}"))).collect();
    let mut servers = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let peers: Peers = (0..N as usize)
            .map(|j| {
                if i == j {
                    Arc::new(LocalPeer::new(c.nodes[i].clone())) as Arc<dyn PeerApi>
                } else {
                    Arc::new(
                        GrpcPeer::connect_lazy(
                            Identifier::try_from(j as u16 + 1).unwrap(),
                            &endpoints[j],
                            Some(tls[i].client_for(&format!("cosigner{}", j + 1))),
                        )
                        .unwrap(),
                    ) as Arc<dyn PeerApi>
                }
            })
            .collect();
        let signer = rutli_cosigner::service::SignerSvc {
            node: c.nodes[i].clone(),
            peers,
            allowed_cns: Some(Arc::new(["driver".to_string()].into())),
            operator_cns: None,
            hosted_write_quorum: 2,
            decrypt_limiter: Arc::new(rutli_cosigner::ratelimit::DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(rutli_cosigner::ratelimit::DecryptRateLimiter::new(0)),
            sign_guard: c.nodes[i].sign_guard().cloned(),
            refresh_cns: None,
        };
        let peer = rutli_cosigner::service::PeerSvc {
            node: c.nodes[i].clone(),
            allowed_cns: Some(Arc::new((1..=N).map(|k| format!("cosigner{k}")).collect::<HashSet<_>>())),
            peer_ids: Some(Arc::new((1..=N).map(|k| (format!("cosigner{k}"), k)).collect())),
        };
        let server = tonic::transport::Server::builder()
            .tls_config(tls[i].server.clone())
            .unwrap()
            .add_service(rutli_cosigner::pb::signer_server::SignerServer::new(signer))
            .add_service(rutli_cosigner::pb::peer_server::PeerServer::new(peer))
            .serve_with_incoming(TcpListenerStream::new(listener));
        servers.push(tokio::spawn(async move {
            let _ = server.await;
        }));
    }
    let channel = |who: &str| -> Channel {
        let (cert, key) = &c.ids.pems[who];
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(&c.ids.pki.ca_pem))
            .domain_name("cosigner1")
            .identity(Identity::from_pem(cert, key));
        Endpoint::from_shared(endpoints[0].clone()).unwrap().tls_config(tls).unwrap().connect_lazy()
    };
    let delete = |intent: Option<pb::SignedIntent>| pb::DeleteKeyRequest { key_id: "rutli-sym-9".into(), intent };
    let denied = |r: std::result::Result<tonic::Response<pb::DeleteKeyReply>, tonic::Status>, needle: &str| {
        let s = r.expect_err("must be refused");
        assert_eq!(s.code(), tonic::Code::PermissionDenied, "{s:?}");
        assert!(s.message().contains(needle), "expected {needle:?} in {}", s.message());
    };

    // The driver — allowed to Sign and Decrypt — may not delete, even with a well-formed intent.
    let mut driver = SignerClient::new(channel("driver"));
    denied(driver.delete_key(delete(Some(delete_intent(&c.ids, "driver", "rutli-sym-9")))).await, "may not delete");
    // The delete role, with no intent, or replaying another client's intent.
    let mut operator = SignerClient::new(channel("operator"));
    denied(operator.delete_key(delete(None)).await, "no delete intent");
    denied(operator.delete_key(delete(Some(delete_intent(&c.ids, "driver", "rutli-sym-9")))).await, "delete_allowlist");
    // A cosigner certificate on the Peer API: no intent, no purge.
    let mut cosigner3 = PeerClient::new(channel("cosigner3"));
    let purge = cosigner3
        .purge_key(pb::PurgeKeyRequest { ceremony_id: "genkey-x".into(), key_id: "rutli-sym-9".into(), intent: None })
        .await;
    assert_eq!(purge.unwrap_err().code(), tonic::Code::PermissionDenied);
    assert_eq!(c.states("rutli-sym-9"), vec![(true, false); 3]);

    // The operator's own intent: tombstoned on every node, over the mesh.
    let reply = operator.delete_key(delete(Some(delete_intent(&c.ids, "operator", "rutli-sym-9")))).await.unwrap().into_inner();
    assert!(reply.deleted);
    assert_eq!(reply.tombstones, 3);
    assert_eq!(c.states("rutli-sym-9"), vec![(false, true); 3]);
    // ListKeys carries the tombstone with its intent; KeyInfo answers "does not exist".
    let listed = cosigner3.list_keys(pb::ListKeysRequest {}).await.unwrap().into_inner().keys;
    assert!(listed.iter().any(|k| k.key_id == "rutli-sym-9" && k.tombstone && !k.delete_intent.is_empty()));
    let info = driver.key_info(pb::KeyInfoRequest { key_id: "rutli-sym-9".into() }).await.unwrap().into_inner();
    assert!(!info.exists);
    for s in &servers {
        s.abort();
    }
}

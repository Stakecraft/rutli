// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Creating a hosted key needs a client-signed generate intent (0.5.0).
//!
//! The intent (purpose `generate-key`) names the cluster, the key, its spec, the cosigner the
//! client asked to lead and a request id; the ceremony id is `genkey-<hex(request_id)>`. Every node
//! verifies it at its genkey fence before it takes the guard — the leader's own node included,
//! before anything is minted — and marks the id fenced, durably. A push is accepted only under the
//! guard that fence took. With `signing_policy.require_ceremony_intent` off, a generation without
//! an intent is accepted and counted, and one that carries an intent is still verified in full.
//!
//! Three nodes (2-of-3) with hosted keys and the signing policy, wired in process; the gRPC-level
//! checks call the services directly (no listening socket).

// tonic::Status is large by value (see the crate root); the RPC helpers return it as the service does.
#![allow(clippy::result_large_err)]

#[path = "common/pki.rs"]
mod pki;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use prost::Message as _;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;
use tonic::{Code, Request};

use rutli_cosigner::config::SigningPolicyConfig;
use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::intent::{self, IntentVerifier};
use rutli_cosigner::journal::{Retention, SignJournal};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{CeremonyKind, Node, Round1Ctx};
use rutli_cosigner::orchestrator::{
    generate_hosted_key, generate_hosted_key_with_intent, repair_hosted_key, Peers, DEFAULT_WRITE_QUORUM,
};
use rutli_cosigner::pb;
use rutli_cosigner::pb::peer_server::Peer;
use rutli_cosigner::pb::signer_server::Signer;
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use rutli_cosigner::sign_policy::SignGuard;
use rutli_cosigner::wrap::Wrapped;
use rutli_cosigner::{DaemonError, Result};

const N: u16 = 3;
const T: u16 = 2;
const MASTER: &[u8] = b"generate intent test cluster master";
const CLUSTER: &str = "genkeycluster000";
const AES: &str = "aes-256-gcm";

fn leaf(pki: &pki::TestPki, cn: &str) -> (String, String) {
    pki.leaf_custom(|p| {
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.subject_alt_names = vec![rcgen::SanType::DnsName(cn.try_into().unwrap())];
    })
}

/// The cosigners, the driver and a second client (signer role), the operator, and a "driver"
/// from another CA.
struct Ids {
    pki: pki::TestPki,
    pems: BTreeMap<&'static str, (String, String)>,
}

impl Ids {
    fn new() -> Self {
        let pki = pki::TestPki::new();
        let rogue_ca = pki::TestPki::new();
        let mut pems = BTreeMap::new();
        for cn in ["cosigner1", "cosigner2", "cosigner3", "driver", "tenant", "operator"] {
            pems.insert(cn, leaf(&pki, cn));
        }
        pems.insert("rogue", leaf(&rogue_ca, "driver"));
        Self { pki, pems }
    }

    fn signer(&self, who: &str) -> rutli_cosigner::request_auth::NodeSigner {
        let (c, k) = &self.pems[who];
        rutli_cosigner::request_auth::NodeSigner::from_pem(c.as_bytes(), k.as_bytes()).unwrap()
    }

    fn verifier(&self, policy: &SigningPolicyConfig) -> IntentVerifier {
        IntentVerifier::new(
            self.pki.ca_pem.as_bytes().to_vec(),
            false,
            CLUSTER.into(),
            ["driver".to_string(), "tenant".to_string()],
            policy,
        )
        .unwrap()
    }

    fn sign(&self, who: &str, i: &pb::SignIntent) -> pb::SignedIntent {
        intent::sign_intent(&self.signer(who), i).unwrap()
    }

    /// A generate intent for `key` of `spec`, led by node `leader`, signed by `who`, request id
    /// 16×`rid`.
    fn generate(&self, who: &str, key: &str, spec: &str, leader: u16, rid: u8) -> pb::SignedIntent {
        self.sign(who, &intent::generate_intent(CLUSTER, key, spec, leader, [rid; 16], intent::now_ms(), 120_000))
    }
}

fn cid(rid: u8) -> String {
    intent::generate_ceremony_id(&[rid; 16])
}

struct Cluster {
    ids: Ids,
    nodes: Vec<Arc<Node>>,
    _tmp: tempfile::TempDir,
}

fn enforcing() -> SigningPolicyConfig {
    SigningPolicyConfig { require_ceremony_intent: Some(true), ..Default::default() }
}

fn opted_out() -> SigningPolicyConfig {
    SigningPolicyConfig { require_ceremony_intent: Some(false), ..Default::default() }
}

/// Three nodes with hosted keys and `policy`, each node's mesh the others acting for it.
fn cluster(policy: SigningPolicyConfig) -> Cluster {
    let tmp = tempfile::tempdir().unwrap();
    let ids = Ids::new();
    let nodes: Vec<Arc<Node>> = (1..=N)
        .map(|i| {
            let sealer = Arc::new(Sealer::from_master_secret(MASTER, i));
            let ks = KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
            let journal = SignJournal::open(
                tmp.path().join(format!("journal-{i}")),
                i,
                Retention { days: 90, max_bytes: 64 << 20 },
            )
            .unwrap();
            let guard = Arc::new(SignGuard::new(Arc::new(ids.verifier(&policy)), journal, 10));
            Arc::new(
                Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
                    .with_hosted_keys(MASTER, CLUSTER.to_string())
                    .unwrap()
                    .with_sign_guard(guard),
            )
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    Cluster { ids, nodes, _tmp: tmp }
}

impl Cluster {
    /// Node `leader`'s view (0-based): itself in process, every other node as a mesh peer that
    /// sees it as `cosigner<leader+1>`.
    fn led_by(&self, leader: usize) -> Peers {
        self.nodes
            .iter()
            .enumerate()
            .map(|(j, n)| {
                let p = LocalPeer::new(n.clone());
                let p = if j == leader { p } else { p.on_behalf_of(self.nodes[leader].clone()) };
                Arc::new(p) as Arc<dyn PeerApi>
            })
            .collect()
    }

    /// Node `from` calling node `to`'s Peer API, as over the mesh.
    fn as_peer(&self, from: usize, to: usize) -> LocalPeer {
        LocalPeer::new(self.nodes[to].clone()).on_behalf_of(self.nodes[from].clone())
    }

    fn commitment(&self, i: usize, key_id: &str) -> Option<Vec<u8>> {
        let n = &self.nodes[i];
        n.hosted_load(key_id).ok().map(|k| n.hosted_commitment(&k).unwrap())
    }

    fn nobody_holds(&self, key_id: &str) -> bool {
        self.nodes.iter().all(|n| !n.hosted_exists(key_id))
    }

    fn signer_svc(&self, i: usize) -> SignerSvc {
        SignerSvc {
            node: self.nodes[i].clone(),
            peers: self.led_by(i),
            allowed_cns: None,
            operator_cns: None,
            hosted_write_quorum: DEFAULT_WRITE_QUORUM,
            decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
            sign_guard: self.nodes[i].sign_guard().cloned(),
            refresh_cns: None,
        }
    }

    /// `key` wrapped by node `from` for node `to` under `key_id`: what a leader pushes.
    fn wrapped(&self, from: usize, to: usize, key_id: &str, key: &HostedKey) -> Wrapped {
        let to_id = rutli_cosigner::hosted::identifier_index(self.nodes[to].identifier).unwrap();
        self.nodes[from].hosted_wrap_for(key_id, key, to_id, &self.nodes[to].dist_public_key().unwrap()).unwrap()
    }
}

fn aes() -> HostedKey {
    HostedKey::generate(HostedSpec::Aes256Gcm, rutli_cosigner::hosted::now_secs()).unwrap()
}

#[track_caller]
fn refused_with<T: std::fmt::Debug>(r: Result<T>, needle: &str) {
    match r {
        Err(DaemonError::PolicyRefused(m)) => {
            assert!(m.starts_with("ceremony intent refused"), "{m:?}");
            assert!(m.contains(needle), "expected {needle:?} in {m:?}");
        }
        other => panic!("expected a generate-intent refusal containing {needle:?}, got {other:?}"),
    }
}

#[track_caller]
fn already_fenced<T: std::fmt::Debug>(r: Result<T>) {
    match r {
        Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("already fenced"), "{m:?}"),
        other => panic!("expected a refusal of a spent id, got {other:?}"),
    }
}

// ── the verifier ───────────────────────────────────────────────────────────────────────────────

/// What a generate intent binds: key, spec, leader, purpose, cluster, ceremony id, validity, and a
/// signer on the signer role within its key ACL, from this cluster's CA.
#[test]
fn a_generate_intent_binds_key_spec_leader_purpose_cluster_time_and_signer() {
    let ids = Ids::new();
    let mut policy = SigningPolicyConfig::default();
    policy.signer_acl.insert("tenant".into(), vec!["rutli-tenant-".into()]);
    let v = ids.verifier(&policy);
    let now = intent::now_ms();
    let key = "rutli-enc-bound";
    let good = intent::generate_intent(CLUSTER, key, AES, 2, [7; 16], now, 120_000);
    let signed = ids.sign("driver", &good);
    let ok = v.verify_generate(&signed, key, AES, 2, &cid(7), now).unwrap();
    assert_eq!((ok.signer_cn.as_str(), ok.spec.as_str(), ok.leader, ok.ceremony_id.as_str()), ("driver", AES, 2, cid(7).as_str()));

    refused_with(v.verify_generate(&signed, "rutli-enc-other", AES, 2, &cid(7), now), "intent is for key");
    refused_with(v.verify_generate(&signed, key, "rsa-2048-oaep-sha256", 2, &cid(7), now), "the generation is of");
    refused_with(v.verify_generate(&signed, key, AES, 3, &cid(7), now), "but cosigner 3 leads it");
    refused_with(v.verify_generate(&signed, key, AES, 2, &cid(8), now), "names ceremony");
    refused_with(v.verify_generate(&signed, key, AES, 2, "genkey-made-up", now), "names ceremony");
    // Another purpose: a DKG intent for the same key is not a generate intent, nor the reverse.
    let dkg = ids.sign("driver", &intent::ceremony_intent(CLUSTER, CeremonyKind::Dkg, key, [7; 16], now, 120_000));
    refused_with(v.verify_generate(&dkg, key, AES, 2, &cid(7), now), "purpose");
    refused_with(v.verify_ceremony(&signed, CeremonyKind::Dkg, key, "dkg-07070707070707070707070707070707", now), "purpose");
    // A ceremony intent that names a spec or a leader is malformed.
    let mut odd = intent::ceremony_intent(CLUSTER, CeremonyKind::Dkg, key, [9; 16], now, 120_000);
    odd.leader = 1;
    refused_with(
        v.verify_ceremony(&ids.sign("driver", &odd), CeremonyKind::Dkg, key, "dkg-09090909090909090909090909090909", now),
        "no leader",
    );
    // Another cluster; expired; a digest.
    let other = pb::SignIntent { cluster_id: "othercluster0000".into(), ..good.clone() };
    refused_with(v.verify_generate(&ids.sign("driver", &other), key, AES, 2, &cid(7), now), "intent is for cluster");
    let expired = pb::SignIntent { issued_at_ms: now - 600_000, not_after_ms: now - 480_000, ..good.clone() };
    refused_with(v.verify_generate(&ids.sign("driver", &expired), key, AES, 2, &cid(7), now), "expired");
    let digest = pb::SignIntent { digest: vec![1; 32], ..good.clone() };
    refused_with(v.verify_generate(&ids.sign("driver", &digest), key, AES, 2, &cid(7), now), "no digest");
    // Signers: outside the key ACL, not on the signer role, another CA, a forged signature.
    refused_with(v.verify_generate(&ids.sign("tenant", &good), key, AES, 2, &cid(7), now), "signer_acl");
    let tenant_key = intent::generate_intent(CLUSTER, "rutli-tenant-a", AES, 2, [7; 16], now, 120_000);
    v.verify_generate(&ids.sign("tenant", &tenant_key), "rutli-tenant-a", AES, 2, &cid(7), now).unwrap();
    for who in ["operator", "cosigner2"] {
        refused_with(v.verify_generate(&ids.sign(who, &good), key, AES, 2, &cid(7), now), "not on this node's signer_allowlist");
    }
    refused_with(v.verify_generate(&ids.sign("rogue", &good), key, AES, 2, &cid(7), now), "certificate");
    let mut forged = ids.sign("driver", &good);
    forged.intent = pb::SignIntent { hosted_spec: "ec-p256-ecies".into(), ..good.clone() }.encode_to_vec();
    refused_with(v.verify_generate(&forged, key, "ec-p256-ecies", 2, &cid(7), now), "signature");
}

// ── every node enforces it ─────────────────────────────────────────────────────────────────────

/// The driver's intent, through the leader it names: every node verifies it, the key lands on all
/// three, and the request id is spent on every node — a second fence under it is refused, from the
/// same leader and from another one presenting an intent with the same request id.
#[tokio::test]
async fn a_generation_with_the_clients_intent_spends_its_request_id_on_every_node() {
    let c = cluster(enforcing());
    let key = "rutli-sym-spent";
    let i = c.ids.generate("driver", key, AES, 1, 1);
    let (_, created, replicas) =
        generate_hosted_key_with_intent(&c.nodes[0], &c.led_by(0), key, HostedSpec::Aes256Gcm, 2, Some(&i)).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 3);
    assert!(c.commitment(0, key).is_some());
    assert_eq!(c.commitment(1, key), c.commitment(0, key));
    assert_eq!(c.commitment(2, key), c.commitment(0, key));

    for p in c.led_by(0) {
        already_fenced(p.genkey_fence(&cid(1), key, AES, Some(&i)).await);
    }
    // Another leader, an intent with the same request id naming it: the id is spent everywhere.
    let again = c.ids.generate("driver", key, AES, 2, 1);
    for p in c.led_by(1) {
        already_fenced(p.genkey_fence(&cid(1), key, AES, Some(&again)).await);
    }
    // A fresh request id for the same key adopts it (idempotent), it does not mint a second key.
    let fresh = c.ids.generate("driver", key, AES, 2, 2);
    let (_, created, _) =
        generate_hosted_key_with_intent(&c.nodes[1], &c.led_by(1), key, HostedSpec::Aes256Gcm, 2, Some(&fresh)).await.unwrap();
    assert!(!created);
}

/// Without an intent a generation is refused at the leader (its own fence, before anything is
/// minted), at a peer's fence, and at a peer's push.
#[tokio::test]
async fn a_generation_without_an_intent_is_refused_at_the_leader_at_a_fence_and_at_a_push() {
    let c = cluster(enforcing());
    let key = "rutli-sym-no-intent";
    refused_with(
        generate_hosted_key(&c.nodes[0], &c.led_by(0), key, HostedSpec::Aes256Gcm, 2).await,
        "carries no generate intent",
    );
    assert!(c.nobody_holds(key));
    // A peer's fence: node 2 asks node 3.
    refused_with(c.as_peer(1, 2).ceremony_fence("genkey-squat", key, "genkey").await, "carries no generate intent");
    refused_with(c.as_peer(1, 2).genkey_fence(&cid(3), key, AES, None).await, "carries no generate intent");
    // A peer's push without a fence.
    let e = c.as_peer(1, 2).replicate_key("genkey-squat", key, AES, &[], &c.wrapped(1, 2, key, &aes())).await;
    assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    assert!(c.nobody_holds(key));
}

/// The same refusals at the gRPC services: the leader's GenerateKey, and a peer's CeremonyFence
/// (PERMISSION_DENIED, the code of every policy refusal); and a fence with an intent from a caller
/// this node cannot place on the roster.
#[tokio::test]
async fn the_services_answer_permission_denied() {
    let c = cluster(enforcing());
    let key = "rutli-sym-svc";
    let e = c
        .signer_svc(0)
        .generate_key(Request::new(pb::GenerateKeyRequest { key_id: key.into(), spec: AES.into(), intent: None }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");
    assert!(e.message().contains("no generate intent"), "{e:?}");
    // An intent that names another leader: refused at the leader before anything is fenced.
    let elsewhere = c.ids.generate("driver", key, AES, 2, 4);
    let e = c
        .signer_svc(0)
        .generate_key(Request::new(pb::GenerateKeyRequest { key_id: key.into(), spec: AES.into(), intent: Some(elsewhere) }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");
    // The right one goes through.
    let mine = c.ids.generate("driver", key, AES, 1, 5);
    let reply = c
        .signer_svc(0)
        .generate_key(Request::new(pb::GenerateKeyRequest { key_id: key.into(), spec: AES.into(), intent: Some(mine) }))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.created);
    assert_eq!(reply.replicas, 3);
    assert_eq!(Some(reply.commitment), c.commitment(2, key));
    // The capabilities name the roster slot a generate intent must name.
    for i in 0..3usize {
        let caps = c.signer_svc(i).capabilities(Request::new(pb::CapabilitiesRequest {})).await.unwrap().into_inner();
        assert_eq!(caps.node_identifier, i as u32 + 1);
    }

    let peer = PeerSvc { node: c.nodes[2].clone(), allowed_cns: None, peer_ids: None, peer_pins: None };
    let fence = |intent: Option<pb::SignedIntent>| pb::CeremonyFenceRequest {
        ceremony_id: cid(6),
        key_id: "rutli-sym-svc-2".into(),
        kind: "genkey".into(),
        spec: AES.into(),
        intent,
        ..Default::default()
    };
    let e = peer.ceremony_fence(Request::new(fence(None))).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");
    // No caller identity: the node cannot tell which cosigner leads, so no intent can bind it.
    let e = peer.ceremony_fence(Request::new(fence(Some(c.ids.generate("driver", "rutli-sym-svc-2", AES, 1, 6))))).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");
    assert!(e.message().contains("cannot tell"), "{e:?}");
    // A delete's fence still takes no intent.
    let mut del = fence(Some(c.ids.generate("driver", "rutli-sym-svc-2", AES, 1, 6)));
    del.kind = "delkey".into();
    assert_eq!(peer.ceremony_fence(Request::new(del)).await.unwrap_err().code(), Code::InvalidArgument);
}

/// Wrong intents at a peer's fence: another key, spec, leader, purpose, cluster, an expired one,
/// one signed outside the key ACL. None takes the guard or spends the id.
#[tokio::test]
async fn a_fence_refuses_an_intent_for_anything_else() {
    let mut policy = enforcing();
    policy.signer_acl.insert("tenant".into(), vec!["rutli-tenant-".into()]);
    let c = cluster(policy);
    let key = "rutli-sym-fence";
    let to3 = c.as_peer(0, 2); // node 1 leads, node 3 is asked
    let now = intent::now_ms();
    let base = intent::generate_intent(CLUSTER, key, AES, 1, [10; 16], now, 120_000);
    let cases: Vec<(pb::SignedIntent, &str, &str)> = vec![
        (c.ids.sign("driver", &pb::SignIntent { key_id: "rutli-sym-other".into(), ..base.clone() }), AES, "intent is for key"),
        (c.ids.sign("driver", &base), "ec-p256-ecies", "the generation is of"),
        (c.ids.sign("driver", &pb::SignIntent { leader: 2, ..base.clone() }), AES, "but cosigner 1 leads it"),
        (c.ids.sign("driver", &pb::SignIntent { purpose: "dkg".into(), ..base.clone() }), AES, "purpose"),
        (c.ids.sign("driver", &pb::SignIntent { cluster_id: "othercluster0000".into(), ..base.clone() }), AES, "intent is for cluster"),
        (
            c.ids.sign("driver", &pb::SignIntent { issued_at_ms: now - 600_000, not_after_ms: now - 480_000, ..base.clone() }),
            AES,
            "expired",
        ),
        (c.ids.sign("tenant", &base), AES, "signer_acl"),
        (c.ids.sign("operator", &base), AES, "signer_allowlist"),
    ];
    for (i, spec, needle) in &cases {
        refused_with(to3.genkey_fence(&cid(10), key, spec, Some(i)).await, needle);
    }
    // Nothing was taken or spent: the right intent fences at once.
    to3.genkey_fence(&cid(10), key, AES, Some(&c.ids.sign("driver", &base))).await.unwrap();
}

/// A compromised cosigner sees the client's intent in its own fence. It cannot lead that
/// generation with it — not on the leader's node, not on a node the leader has not reached yet, not
/// on its own node — because the intent names another leader. It takes no guard and spends nothing.
#[tokio::test]
async fn a_peer_shown_an_intent_cannot_lead_that_generation() {
    let c = cluster(enforcing());
    let key = "rutli-sym-shown";
    let i = c.ids.generate("driver", key, AES, 1, 11);
    // The honest leader (node 1) fences its own node and node 2, which sees the intent.
    c.led_by(0)[0].genkey_fence(&cid(11), key, AES, Some(&i)).await.unwrap();
    c.led_by(0)[1].genkey_fence(&cid(11), key, AES, Some(&i)).await.unwrap();
    // Node 2 presents it to node 1, to node 3 (not reached yet) and to itself.
    refused_with(c.as_peer(1, 0).genkey_fence(&cid(11), key, AES, Some(&i)).await, "but cosigner 2 leads it");
    refused_with(c.as_peer(1, 2).genkey_fence(&cid(11), key, AES, Some(&i)).await, "but cosigner 2 leads it");
    refused_with(
        generate_hosted_key_with_intent(&c.nodes[1], &c.led_by(1), key, HostedSpec::Aes256Gcm, 2, Some(&i)).await,
        "but cosigner 2 leads it",
    );
    // A push into node 3 under the honest ceremony id: no fence there.
    let e = c.as_peer(1, 2).replicate_key(&cid(11), key, AES, &[], &c.wrapped(1, 2, key, &aes())).await;
    assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    assert!(c.nobody_holds(key));
    // Node 3 was not spent: the honest leader still fences it.
    c.led_by(0)[2].genkey_fence(&cid(11), key, AES, Some(&i)).await.unwrap();
}

/// A push must match what the generation's fence declared: a key of another spec under the fence
/// is refused.
#[tokio::test]
async fn a_push_of_another_spec_under_the_fence_is_refused() {
    let c = cluster(enforcing());
    let key = "rutli-enc-spec";
    let i = c.ids.generate("driver", key, AES, 1, 12);
    let to2 = c.as_peer(0, 1);
    to2.genkey_fence(&cid(12), key, AES, Some(&i)).await.unwrap();
    let ec = HostedKey::generate(HostedSpec::EcP256, rutli_cosigner::hosted::now_secs()).unwrap();
    let e = to2.replicate_key(&cid(12), key, "ec-p256-ecies", &[], &c.wrapped(0, 1, key, &ec)).await;
    match e {
        Err(DaemonError::HostedPushRefused(m)) => assert!(m.contains("fenced here for a aes-256-gcm key"), "{m}"),
        other => panic!("expected a refusal of another spec, got {other:?}"),
    }
    let (reason, _) = c.nodes[1].genkey_push_refusal(key, &cid(12), Some("cosigner1"), "ec-p256-ecies").unwrap();
    assert_eq!(reason, "spec");
    assert!(c.nodes[1].genkey_push_refusal(key, &cid(12), Some("cosigner1"), AES).is_none());
    assert!(!c.nodes[1].hosted_exists(key));
}

/// With the default switch, a compromised cosigner can no longer create a key nobody asked for:
/// its fence is refused, so is its push, and nothing spreads. (Step 1 left this open.)
#[tokio::test]
async fn a_planted_key_is_refused_at_the_fence() {
    let c = cluster(enforcing());
    let id = "rutli-sym-unrequested";
    let planted = aes();
    let evil = c.as_peer(1, 2);
    refused_with(evil.ceremony_fence("genkey-squat", id, "genkey").await, "carries no generate intent");
    let e = evil.replicate_key("genkey-squat", id, AES, &[], &c.wrapped(1, 2, id, &planted)).await;
    assert!(matches!(e, Err(DaemonError::HostedPushRefused(_))), "{e:?}");
    // It keeps a copy itself: one holder is not agreement, nothing is pulled.
    c.nodes[1].hosted_store(id, &planted).unwrap();
    assert!(repair_hosted_key(&c.nodes[0], &c.led_by(0), id).await.is_err());
    assert!(!c.nodes[0].hosted_exists(id) && !c.nodes[2].hosted_exists(id));
}

/// The same attack with `require_ceremony_intent: false`: what stays open with the opt-out. For an
/// id nobody holds, the node that fenced it can create it on an honest node, and when it keeps a
/// copy itself it is the second agreeing peer: the material spreads by pull and a later generation
/// adopts it. docs/security/threat-model.md.
#[tokio::test]
async fn with_the_switch_off_a_planted_key_spreads_when_the_attacker_keeps_a_copy() {
    let c = cluster(opted_out());
    let id = "rutli-sym-unrequested";
    let planted = aes();
    let evil = c.as_peer(1, 2);
    evil.ceremony_fence("genkey-squat", id, "genkey").await.unwrap();
    evil.replicate_key("genkey-squat", id, AES, &[], &c.wrapped(1, 2, id, &planted)).await.unwrap();
    evil.ceremony_release("genkey-squat", id).await.unwrap();
    assert!(c.nodes[2].hosted_exists(id));
    let e = generate_hosted_key(&c.nodes[0], &c.led_by(0), id, HostedSpec::Aes256Gcm, 2).await;
    assert!(matches!(e, Err(DaemonError::HostedUnconfirmed { .. })), "{e:?}");
    c.nodes[1].hosted_store(id, &planted).unwrap();
    assert!(repair_hosted_key(&c.nodes[0], &c.led_by(0), id).await.unwrap());
    let (got, created, _) = generate_hosted_key(&c.nodes[0], &c.led_by(0), id, HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(!created);
    assert_eq!(got.private_der, planted.private_der);
}

/// `require_ceremony_intent: false`: a generation without an intent works and is counted; one that
/// carries an intent is verified in full and refused if invalid.
#[tokio::test]
async fn with_the_switch_off_a_generation_without_an_intent_works_and_is_counted() {
    let c = cluster(opted_out());
    let (_, created, replicas) =
        generate_hosted_key(&c.nodes[0], &c.led_by(0), "rutli-sym-legacy", HostedSpec::Aes256Gcm, 2).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 3);
    let bad = c.ids.generate("operator", "rutli-sym-bad", AES, 1, 13);
    refused_with(
        generate_hosted_key_with_intent(&c.nodes[0], &c.led_by(0), "rutli-sym-bad", HostedSpec::Aes256Gcm, 2, Some(&bad)).await,
        "signer_allowlist",
    );
    assert!(c.nobody_holds("rutli-sym-bad"));
    let good = c.ids.generate("driver", "rutli-sym-good", AES, 1, 14);
    generate_hosted_key_with_intent(&c.nodes[0], &c.led_by(0), "rutli-sym-good", HostedSpec::Aes256Gcm, 2, Some(&good))
        .await
        .unwrap();

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let g = c.nodes[2].sign_guard().unwrap().clone();
    metrics::with_local_recorder(&recorder, || {
        assert!(g.authorize_generate("rutli-sym-x", AES, Some(1), "genkey-legacy", None).unwrap().is_none());
        assert!(g.authorize_generate("rutli-sym-x", AES, Some(1), &cid(15), Some(&bad)).is_err());
        let wrong_leader = c.ids.generate("driver", "rutli-sym-x", AES, 2, 16);
        assert!(g.authorize_generate("rutli-sym-x", AES, Some(1), &cid(16), Some(&wrong_leader)).is_err());
    });
    let out = handle.render();
    assert!(out.contains("rutli_ceremony_intent_absent_total 1"), "{out}");
    assert!(out.contains(r#"rutli_ceremony_intent_refusals_total{reason="signer"} 1"#), "{out}");
    assert!(out.contains(r#"rutli_ceremony_intent_refusals_total{reason="leader"} 1"#), "{out}");
}

/// A cosigner that predates generate intents, as the leader sees it: it reports hosted protocol 0
/// (the default of [`PeerApi::hosted_protocol`]) and cannot carry an intent.
struct Old(LocalPeer);

#[async_trait]
impl PeerApi for Old {
    fn identifier(&self) -> Identifier {
        self.0.identifier()
    }
    async fn sign_round1(&self, k: &str, s: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        self.0.sign_round1(k, s, ctx).await
    }
    async fn sign_round2(
        &self,
        k: &str,
        s: &str,
        m: &[u8],
        c: &BTreeMap<Identifier, SigningCommitments>,
        d: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.0.sign_round2(k, s, m, c, d).await
    }
    async fn abort_sign(&self, k: &str, s: &str) -> Result<()> {
        self.0.abort_sign(k, s).await
    }
    async fn ceremony_fence(&self, c: &str, k: &str, kind: &'static str) -> Result<()> {
        self.0.ceremony_fence(c, k, kind).await
    }
    async fn ceremony_release(&self, c: &str, k: &str) -> Result<()> {
        self.0.ceremony_release(c, k).await
    }
    async fn node_info(&self) -> Result<(u16, [u8; 32])> {
        self.0.node_info().await
    }
    async fn replicate_key(&self, c: &str, k: &str, s: &str, p: &[u8], w: &Wrapped) -> Result<Vec<u8>> {
        self.0.replicate_key(c, k, s, p, w).await
    }
    async fn fetch_key(&self, k: &str) -> Result<(String, Vec<u8>, Wrapped)> {
        self.0.fetch_key(k).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.0.list_keys().await
    }
    async fn purge_key(&self, c: &str, k: &str) -> Result<bool> {
        self.0.purge_key(c, k).await
    }
}

/// A mixed cluster: a generation that carries an intent is refused before anything is fenced while
/// a reachable cosigner does not verify generate intents. Nothing is held, nothing is spent: once
/// the node is upgraded the same intent runs.
#[tokio::test]
async fn a_mixed_cluster_refuses_a_generation_with_an_intent_before_fencing() {
    let c = cluster(enforcing());
    let key = "rutli-sym-mixed";
    let i = c.ids.generate("driver", key, AES, 1, 17);
    let mut mixed = c.led_by(0);
    mixed[2] = Arc::new(Old(c.as_peer(0, 2)));
    match generate_hosted_key_with_intent(&c.nodes[0], &mixed, key, HostedSpec::Aes256Gcm, 2, Some(&i)).await {
        Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("cosigner 3 speaks hosted-key protocol 0"), "{m}"),
        other => panic!("expected a refusal of a mixed cluster, got {other:?}"),
    }
    assert!(c.nobody_holds(key));
    let (_, created, replicas) =
        generate_hosted_key_with_intent(&c.nodes[0], &c.led_by(0), key, HostedSpec::Aes256Gcm, 2, Some(&i)).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 3);
}

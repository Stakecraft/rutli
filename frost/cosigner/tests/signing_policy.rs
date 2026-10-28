// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Audit C2: the cosigner-enforced signing policy, against the threat model.
//!
//! Three nodes (2-of-3), each with its signing policy and sign journal, serve Signer + Peer over
//! real mutual TLS (per-node certificates `cosigner1..3` under one test CA). Clients present the
//! identities the threat model names: the driver, a second tenant's driver, a second key under the
//! driver's CN (a stolen-then-revoked key), the operator, the refresher, a cosigner (the
//! compromised node), a certificate from another CA, and no certificate at all.

#[path = "common/pki.rs"]
mod pki;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::Identifier;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use rutli_cosigner::config::{ApprovalRuleConfig, ApproverConfig, SigningPolicyConfig};
use rutli_cosigner::intent::{self, IntentVerifier};
use rutli_cosigner::journal::{read_key_dir, Retention, SignJournal};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::{Node, Round1Ctx};
use rutli_cosigner::orchestrator::{run_dkg, run_dkg_with_intent, sign_with_intent, Peers};
use rutli_cosigner::pb;
use rutli_cosigner::pb::peer_client::PeerClient;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::pb::signer_client::SignerClient;
use rutli_cosigner::pb::signer_server::SignerServer;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::request_auth::NodeSigner;
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use rutli_cosigner::sign_policy::SignGuard;
use rutli_cosigner::{DaemonError, Result};

const N: u16 = 3;
const T: u16 = 2;
const KEY: &str = "frost-participant1-namespace";
const CLUSTER: &str = "c2testcluster000";

fn digest(tag: &[u8]) -> Vec<u8> {
    rutli_frost_core::dealer::canton_test_message(tag).to_vec()
}

fn now_ms() -> u64 {
    intent::now_ms()
}

/// One certificate + key in PEM, signed by `pki` (P-256, no EKU), with CN and SAN `cn`.
fn leaf(pki: &pki::TestPki, cn: &str) -> (String, String) {
    pki.leaf_custom(|p| {
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.subject_alt_names = vec![rcgen::SanType::DnsName(cn.try_into().unwrap())];
    })
}

/// Every identity of the threat model.
struct Ids {
    pki: pki::TestPki,
    dir: PathBuf,
    pems: BTreeMap<&'static str, (String, String)>,
}

impl Ids {
    fn new(dir: &Path) -> Self {
        let pki = pki::TestPki::new();
        let rogue_ca = pki::TestPki::new();
        let mut pems = BTreeMap::new();
        for i in 1..=N {
            let name: &'static str = Box::leak(format!("cosigner{i}").into_boxed_str());
            pems.insert(name, leaf(&pki, name));
        }
        for cn in ["driver", "tenant", "operator", "refresher"] {
            pems.insert(cn, leaf(&pki, cn));
        }
        // A second key certified under the driver's CN (the stolen key the pin revokes), and a
        // "driver" from another CA.
        pems.insert("driver-2", leaf(&pki, "driver"));
        pems.insert("rogue", leaf(&rogue_ca, "driver"));
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("ca.pem"), &pki.ca_pem).unwrap();
        Self { pki, dir: dir.to_path_buf(), pems }
    }

    fn signer(&self, who: &str) -> NodeSigner {
        let (c, k) = &self.pems[who];
        NodeSigner::from_pem(c.as_bytes(), k.as_bytes()).unwrap()
    }

    fn spki_sha256(&self, who: &str) -> String {
        let (c, _) = &self.pems[who];
        let der = rustls_pemfile::certs(&mut c.as_bytes()).next().unwrap().unwrap();
        hex::encode(intent::Caller::from_leaf_der(&der).unwrap().spki_sha256)
    }

    fn tls_config(&self, who: &str) -> rutli_cosigner::config::TlsConfig {
        let (c, k) = &self.pems[who];
        let (cp, kp) = (self.dir.join(format!("{who}.pem")), self.dir.join(format!("{who}.key")));
        std::fs::write(&cp, c).unwrap();
        std::fs::write(&kp, k).unwrap();
        rutli_cosigner::config::TlsConfig {
            ca_cert: self.dir.join("ca.pem"),
            cert: cp,
            key: kp,
            domain: None,
            allow_expired_ca: false,
        }
    }
}

/// A signing intent for `key` over `msg`, signed by `who`.
fn intent_by(ids: &Ids, who: &str, key: &str, msg: &[u8], request: u8) -> pb::SignedIntent {
    let now = now_ms();
    sign(ids, who, unsigned(key, msg, request, now, now + 120_000))
}

fn unsigned(key: &str, msg: &[u8], request: u8, issued: u64, not_after: u64) -> pb::SignIntent {
    pb::SignIntent {
        version: 1,
        cluster_id: CLUSTER.into(),
        purpose: "sign".into(),
        key_id: key.into(),
        digest: msg.to_vec(),
        request_id: vec![request; 16],
        issued_at_ms: issued,
        not_after_ms: not_after,
        approval_nonce: Vec::new(),
        approvals: Vec::new(),
    }
}

/// A ceremony intent for `kind` of `key`, signed by `who`, request id 16×`rid`.
fn ceremony_by(ids: &Ids, who: &str, kind: rutli_cosigner::node::CeremonyKind, key: &str, rid: u8) -> pb::SignedIntent {
    sign(ids, who, intent::ceremony_intent(CLUSTER, kind, key, [rid; 16], now_ms(), 120_000))
}

fn sign(ids: &Ids, who: &str, i: pb::SignIntent) -> pb::SignedIntent {
    intent::sign_intent(&ids.signer(who), &i).unwrap()
}

struct Cluster {
    ids: Ids,
    root: PathBuf,
    nodes: Vec<Arc<Node>>,
    endpoints: Vec<String>,
    servers: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for s in &self.servers {
            s.abort();
        }
    }
}

fn guard(root: &Path, ids: &Ids, i: u16, policy: &SigningPolicyConfig) -> Arc<SignGuard> {
    let verifier = IntentVerifier::new(
        ids.pki.ca_pem.as_bytes().to_vec(),
        false,
        CLUSTER.into(),
        ["driver".to_string(), "tenant".to_string()],
        policy,
    )
    .unwrap()
    .with_refreshers(["refresher".to_string()]);
    let journal = SignJournal::open(
        root.join(format!("node-{i}")).join("journal"),
        i,
        Retention { days: 90, max_bytes: 64 << 20 },
    )
    .unwrap();
    Arc::new(SignGuard::new(Arc::new(verifier), journal, 10))
}

fn open_node(root: &Path, ids: &Ids, i: u16, policy: &SigningPolicyConfig) -> Arc<Node> {
    let ks = KeyStore::open(root.join(format!("node-{i}")).join("keys")).unwrap();
    Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, ks).with_sign_guard(guard(root, ids, i, policy)))
}

/// The cluster, its key `KEY` generated, every node on `policy(i)`; `refreshers` is the
/// refresh_allowlist.
async fn cluster(policy: impl Fn(u16) -> SigningPolicyConfig, refreshers: Option<Vec<String>>) -> Cluster {
    cluster_with(|_, i| policy(i), refreshers).await
}

/// [`cluster`] with a policy that may depend on the identities (pins).
async fn cluster_with(policy: impl Fn(&Ids, u16) -> SigningPolicyConfig, refreshers: Option<Vec<String>>) -> Cluster {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let ids = Ids::new(&root.join("certs"));
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| open_node(&root, &ids, i, &policy(&ids, i))).collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let local: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    if policy(&ids, 1).ceremony_intent_required(true) {
        run_dkg_with_intent(&local, KEY, Some(ceremony_by(&ids, "driver", rutli_cosigner::node::CeremonyKind::Dkg, KEY, 0xd0)))
            .await
            .unwrap();
    } else {
        run_dkg(&local, KEY).await.unwrap();
    }

    let mut listeners = Vec::new();
    for _ in 0..N {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let endpoints: Vec<String> = listeners.iter().map(|l| format!("https://{}", l.local_addr().unwrap())).collect();
    let tls: Vec<_> = (1..=N).map(|i| rutli_cosigner::tls::load(&ids.tls_config(&format!("cosigner{i}"))).unwrap()).collect();
    let peer_cns: Arc<std::collections::HashSet<String>> = Arc::new((1..=N).map(|i| format!("cosigner{i}")).collect());
    let signer_cns: Arc<std::collections::HashSet<String>> = Arc::new(["driver".into(), "tenant".into()].into());
    let mut servers = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let peers: Peers = (0..N as usize)
            .map(|j| {
                if i == j {
                    Arc::new(LocalPeer::new(nodes[i].clone())) as Arc<dyn PeerApi>
                } else {
                    Arc::new(
                        GrpcPeer::connect_lazy(
                            Identifier::try_from(j as u16 + 1).unwrap(),
                            &endpoints[j],
                            Some(tls[i].client_for(&format!("cosigner{}", j + 1))),
                        )
                        .unwrap(),
                    )
                }
            })
            .collect();
        let signer = SignerSvc {
            node: nodes[i].clone(),
            peers,
            allowed_cns: Some(signer_cns.clone()),
            operator_cns: Some(Arc::new(["operator".to_string()].into())),
            hosted_write_quorum: 2,
            decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
            sign_guard: nodes[i].sign_guard().cloned(),
            refresh_cns: refreshers.as_ref().map(|r| Arc::new(r.iter().cloned().collect())),
        };
        let peer = PeerSvc {
            node: nodes[i].clone(),
            allowed_cns: Some(peer_cns.clone()),
            peer_ids: Some(Arc::new((1..=N).map(|k| (format!("cosigner{k}"), k)).collect())),
        };
        let server = tonic::transport::Server::builder()
            .tls_config(tls[i].server.clone())
            .unwrap()
            .add_service(SignerServer::new(signer))
            .add_service(PeerServer::new(peer))
            .serve_with_incoming(TcpListenerStream::new(listener));
        servers.push(tokio::spawn(async move {
            let _ = server.await;
        }));
    }
    Cluster { ids, root, nodes, endpoints, servers, _tmp: tmp }
}

fn strict() -> SigningPolicyConfig {
    SigningPolicyConfig { require_intent: true, ..Default::default() }
}

impl Cluster {
    async fn channel(&self, who: Option<&str>, node: usize) -> std::result::Result<Channel, tonic::transport::Error> {
        let ca = match who {
            Some("rogue") => {
                // The rogue client trusts the cluster CA (it can reach the server), but presents a
                // certificate from its own CA.
                self.ids.pki.ca_pem.clone()
            }
            _ => self.ids.pki.ca_pem.clone(),
        };
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .domain_name(format!("cosigner{}", node + 1));
        if let Some(w) = who {
            let (c, k) = &self.ids.pems[w];
            tls = tls.identity(Identity::from_pem(c, k));
        }
        Endpoint::from_shared(self.endpoints[node].clone()).unwrap().tls_config(tls).unwrap().connect().await
    }

    async fn signer(&self, who: &str, node: usize) -> SignerClient<Channel> {
        SignerClient::new(self.channel(Some(who), node).await.unwrap())
    }

    async fn peer_as(&self, who: &str, node: usize) -> PeerClient<Channel> {
        PeerClient::new(self.channel(Some(who), node).await.unwrap())
    }

    fn group_key(&self) -> [u8; 32] {
        self.nodes[0].group_key(KEY).unwrap()
    }

    fn journal(&self, i: usize) -> Vec<rutli_cosigner::journal::JournalEntry> {
        read_key_dir(&self.root.join(format!("node-{}", i + 1)).join("journal").join(KEY))
            .map(|r| r.entries)
            .unwrap_or_default()
    }

    fn markers(&self, i: usize) -> usize {
        let dir = self.root.join(format!("node-{}", i + 1)).join("keys").join(format!("{KEY}.nonces"));
        std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
    }
}

fn round1(key: &str, session: &str, msg: Option<&[u8]>, intent: Option<pb::SignedIntent>) -> pb::SignRound1Request {
    pb::SignRound1Request {
        key_id: key.into(),
        session_id: session.into(),
        intent,
        message: msg.map(<[u8]>::to_vec).unwrap_or_default(),
        signers: vec![1, 3],
        ..Default::default()
    }
}

fn denied(r: std::result::Result<impl std::fmt::Debug, tonic::Status>, needle: &str) {
    let s = r.expect_err("must be refused");
    assert_eq!(s.code(), tonic::Code::PermissionDenied, "{s:?}");
    assert!(s.message().contains(needle), "expected {needle:?} in {:?}", s.message());
}

// ── a compromised cosigner ────────────────────────────────────────────────────────────────────

/// A compromised node 3 (its share and its `cosigner3` certificate) drives the Peer API of honest
/// node 1 directly. Without a valid driver intent for exactly the message, node 1 refuses round 1 —
/// before it generates a nonce, so there is never a commitment, a share, a marker or a journal
/// entry.
#[tokio::test]
async fn a_compromised_cosigner_gets_no_commitment_from_an_honest_peer_without_a_valid_intent() {
    let c = cluster(|_| strict(), None).await;
    let mut attacker = c.peer_as("cosigner3", 0).await;
    let evil = digest(b"evil topology transaction");
    let good = digest(b"what the driver asked for");

    // No intent at all.
    denied(attacker.sign_round1(round1(KEY, "s-none", Some(&evil), None)).await, "carries no signing intent");
    // An intent the compromised node signed itself with its cosigner key.
    let forged = intent_by(&c.ids, "cosigner3", KEY, &evil, 1);
    denied(attacker.sign_round1(round1(KEY, "s-forged", Some(&evil), Some(forged))).await, "not on this node's signer_allowlist");
    // A real driver intent, its digest rewritten (the signature no longer matches).
    let mut altered = intent_by(&c.ids, "driver", KEY, &good, 2);
    let mut body = <pb::SignIntent as prost::Message>::decode(altered.intent.as_slice()).unwrap();
    body.digest = evil.clone();
    altered.intent = prost::Message::encode_to_vec(&body);
    denied(attacker.sign_round1(round1(KEY, "s-altered", Some(&evil), Some(altered))).await, "bad request signature");
    // A real driver intent, for another digest than the round signs.
    let other = intent_by(&c.ids, "driver", KEY, &good, 3);
    denied(attacker.sign_round1(round1(KEY, "s-other", Some(&evil), Some(other))).await, "another message");
    // A real driver intent for another key.
    let wrong_key = intent_by(&c.ids, "driver", "frost-participant1-other", &evil, 4);
    denied(attacker.sign_round1(round1(KEY, "s-key", Some(&evil), Some(wrong_key))).await, "is for key");
    // A replayed, expired driver intent for the very digest.
    let long_ago = now_ms() - 3_600_000;
    let expired = sign(&c.ids, "driver", unsigned(KEY, &evil, 5, long_ago, long_ago + 60_000));
    denied(attacker.sign_round1(round1(KEY, "s-expired", Some(&evil), Some(expired))).await, "expired");
    // A "driver" certificate from another CA.
    let rogue = intent_by(&c.ids, "rogue", KEY, &evil, 6);
    denied(attacker.sign_round1(round1(KEY, "s-rogue", Some(&evil), Some(rogue))).await, "certificate");
    // An intent for another cluster.
    let mut foreign = unsigned(KEY, &evil, 7, now_ms(), now_ms() + 60_000);
    foreign.cluster_id = "anothercluster00".into();
    denied(attacker.sign_round1(round1(KEY, "s-cluster", Some(&evil), Some(sign(&c.ids, "driver", foreign)))).await, "cluster");

    assert_eq!(c.nodes[0].pending_sign_count(KEY), 0, "no round-1 nonces were generated");
    assert_eq!(c.markers(0), 0, "no nonce marker");
    assert!(c.journal(0).is_empty(), "nothing journaled");
    // ...and a round 2 has nothing to sign with.
    let r2 = attacker
        .sign_round2(pb::SignRound2Request {
            key_id: KEY.into(),
            session_id: "s-none".into(),
            message: evil.clone(),
            commitments_map: b"{}".to_vec(),
            intent_digest: Vec::new(),
        })
        .await;
    assert!(r2.is_err());
    assert!(c.journal(0).is_empty());
}

/// Round 1 of `session` on node 1 (over the attacker's Peer connection) and on node 3 (the
/// compromised node itself, in-process), both under `valid`: the commitment map for round 2.
async fn open_both(
    c: &Cluster,
    attacker: &PeerClient<Channel>,
    session: &str,
    good: &[u8],
    valid: &pb::SignedIntent,
) -> BTreeMap<Identifier, SigningCommitments> {
    let r = attacker.clone().sign_round1(round1(KEY, session, Some(good), Some(valid.clone()))).await.unwrap();
    let c1: SigningCommitments = serde_json::from_slice(&r.into_inner().commitments).unwrap();
    let ctx3 = Round1Ctx {
        message: Some(good.to_vec()),
        signers: Some(vec![1, 3]),
        intent: Some(valid.clone()),
        ..Default::default()
    };
    let c3 = c.nodes[2].sign_round1(KEY, session, &ctx3).unwrap();
    BTreeMap::from([(Identifier::try_from(1u16).unwrap(), c1), (Identifier::try_from(3u16).unwrap(), c3)])
}

/// The leader (or a node that saw a valid intent) swaps the digest between round 1 and round 2, or
/// presents another intent's digest: refused before the marker burns, nothing journaled. With the
/// very digest the intent authorizes, the share is released — and journaled first.
#[tokio::test]
async fn a_leader_cannot_swap_the_digest_or_the_intent_between_the_rounds() {
    let c = cluster(|_| strict(), None).await;
    let mut attacker = c.peer_as("cosigner3", 0).await;
    let good = digest(b"approved digest");
    let evil = digest(b"swapped digest");
    let valid = intent_by(&c.ids, "driver", KEY, &good, 9);
    let valid_digest = intent::intent_digest(&valid).to_vec();

    let cs = open_both(&c, &attacker, "swap-msg", &good, &valid).await;
    let r = attacker
        .sign_round2(pb::SignRound2Request {
            key_id: KEY.into(),
            session_id: "swap-msg".into(),
            message: evil.clone(),
            commitments_map: serde_json::to_vec(&cs).unwrap(),
            intent_digest: valid_digest.clone(),
        })
        .await;
    denied(r, "another message");

    let cs = open_both(&c, &attacker, "swap-intent", &good, &valid).await;
    let other_intent = intent_by(&c.ids, "driver", KEY, &good, 10);
    let r = attacker
        .sign_round2(pb::SignRound2Request {
            key_id: KEY.into(),
            session_id: "swap-intent".into(),
            message: good.clone(),
            commitments_map: serde_json::to_vec(&cs).unwrap(),
            intent_digest: intent::intent_digest(&other_intent).to_vec(),
        })
        .await;
    denied(r, "another signing intent");

    let cs = open_both(&c, &attacker, "no-intent-digest", &good, &valid).await;
    let r = attacker
        .sign_round2(pb::SignRound2Request {
            key_id: KEY.into(),
            session_id: "no-intent-digest".into(),
            message: good.clone(),
            commitments_map: serde_json::to_vec(&cs).unwrap(),
            intent_digest: Vec::new(),
        })
        .await;
    denied(r, "another signing intent");
    assert!(c.journal(0).is_empty(), "no refused round 2 is journaled");
    assert_eq!(c.markers(0), 0, "no refused round 2 burns a marker");
    assert_eq!(c.nodes[0].pending_sign_count(KEY), 0, "a refused round 2 drops the session's nonces");

    // The authorized digest: the share comes out, journaled first.
    let cs = open_both(&c, &attacker, "honest", &good, &valid).await;
    attacker
        .sign_round2(pb::SignRound2Request {
            key_id: KEY.into(),
            session_id: "honest".into(),
            message: good.clone(),
            commitments_map: serde_json::to_vec(&cs).unwrap(),
            intent_digest: valid_digest,
        })
        .await
        .unwrap();
    let j = c.journal(0);
    assert_eq!(j.len(), 1);
    assert_eq!((j[0].purpose.as_str(), j[0].digest.as_str()), ("sign", hex::encode(&good).as_str()));
    assert_eq!(j[0].request_id, hex::encode([9u8; 16]));
    assert_eq!(j[0].signer_cn, "driver");
}

// ── who may call Sign ─────────────────────────────────────────────────────────────────────────

/// Only the driver role signs, only with an intent it signed itself, on its own connection — and
/// every participating node journals the signature before its share leaves.
#[tokio::test]
async fn only_the_driver_signs_with_its_own_intent_and_every_participant_journals_it() {
    let c = cluster(|_| strict(), Some(vec!["refresher".into()])).await;
    let msg = digest(b"a topology transaction");
    let req = |intent: Option<pb::SignedIntent>| pb::SignRequest { key_id: KEY.into(), message: msg.clone(), intent };
    let by_driver = intent_by(&c.ids, "driver", KEY, &msg, 20);

    for who in ["operator", "refresher", "cosigner2"] {
        denied(c.signer(who, 0).await.sign(req(Some(by_driver.clone()))).await, "not permitted to call the Signer API");
    }
    // No client certificate, or one from another CA: no TLS session at all.
    assert!(c.channel(None, 0).await.is_err() || SignerClient::new(c.channel(None, 0).await.unwrap()).sign(req(None)).await.is_err());
    match c.channel(Some("rogue"), 0).await {
        Err(_) => {}
        Ok(ch) => assert!(SignerClient::new(ch).sign(req(Some(by_driver.clone()))).await.is_err()),
    }
    // Another allowlisted client cannot use the driver's intent, nor the driver another's.
    denied(c.signer("tenant", 0).await.sign(req(Some(by_driver.clone()))).await, "only valid on its signer's own connection");
    let by_tenant = intent_by(&c.ids, "tenant", KEY, &msg, 21);
    denied(c.signer("driver", 0).await.sign(req(Some(by_tenant))).await, "only valid on its signer's own connection");
    // The driver without an intent, where one is required.
    denied(c.signer("driver", 0).await.sign(req(None)).await, "carries no signing intent");
    assert!((0..3).all(|i| c.journal(i).is_empty()));

    // The driver with its own intent: a valid signature, journaled on both participants.
    let sig = c.signer("driver", 1).await.sign(req(Some(by_driver))).await.unwrap().into_inner().signature;
    let sig: [u8; 64] = sig.try_into().unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&c.group_key(), &msg, &sig));
    let journaled: Vec<usize> = (0..3).filter(|&i| c.journal(i).iter().any(|e| e.request_id == hex::encode([20u8; 16]))).collect();
    assert!(journaled.len() >= 2 && journaled.contains(&1), "leader and its partner journal it: {journaled:?}");
    for i in journaled {
        let e = &c.journal(i)[0];
        assert_eq!(e.digest, hex::encode(&msg));
        assert_eq!(e.node, i as u16 + 1);
    }
}

/// The refresher refreshes and reads key status, never signs; once `signer_may_refresh` is off the
/// driver no longer refreshes. (Roles only: intent-less refreshes, so ceremony intents opted out.)
#[tokio::test]
async fn the_refresher_refreshes_but_never_signs_and_the_driver_stops_refreshing() {
    let policy = SigningPolicyConfig {
        require_intent: true,
        require_ceremony_intent: Some(false),
        signer_may_refresh: false,
        ..Default::default()
    };
    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    let msg = digest(b"refresher tries");
    let by_driver = intent_by(&c.ids, "driver", KEY, &msg, 30);

    denied(
        c.signer("refresher", 0).await.sign(pb::SignRequest { key_id: KEY.into(), message: msg.clone(), intent: Some(by_driver) }).await,
        "not permitted",
    );
    denied(c.signer("driver", 0).await.refresh(pb::RefreshRequest { key_id: KEY.into(), intent: None }).await, "may not call Refresh");
    c.signer("refresher", 0).await.key_status(pb::KeyStatusRequest { key_id: KEY.into() }).await.unwrap();
    let before = c.nodes[0].key_epoch(KEY).unwrap().epoch;
    let reply = c.signer("refresher", 0).await.refresh(pb::RefreshRequest { key_id: KEY.into(), intent: None }).await.unwrap();
    assert_eq!(reply.into_inner().group_verifying_key, c.group_key().to_vec());
    assert_eq!(c.nodes[0].key_epoch(KEY).unwrap().epoch, before + 1);
}

/// A tenant's driver certificate may use only its own prefix, at the leader and at every peer.
#[tokio::test]
async fn a_signer_without_an_acl_for_a_key_is_refused_when_acls_are_required() {
    let policy = SigningPolicyConfig {
        require_intent: true,
        signer_acl_required: true,
        signer_acl: BTreeMap::from([
            ("driver".to_string(), vec!["frost-participant1-".to_string()]),
            ("tenant".to_string(), vec!["frost-participant2-".to_string()]),
        ]),
        ..Default::default()
    };
    let c = cluster(|_| policy.clone(), None).await;
    let msg = digest(b"tenant 2 reaches for tenant 1's key");
    let by_tenant = intent_by(&c.ids, "tenant", KEY, &msg, 40);
    denied(
        c.signer("tenant", 0).await.sign(pb::SignRequest { key_id: KEY.into(), message: msg.clone(), intent: Some(by_tenant.clone()) }).await,
        "may not use key",
    );
    denied(c.signer("tenant", 0).await.group_key(pb::GroupKeyRequest { key_id: KEY.into() }).await, "may not use key");
    // A compromised node forwarding the tenant's intent to a peer gets the same answer there.
    denied(c.peer_as("cosigner3", 0).await.sign_round1(round1(KEY, "acl", Some(&msg), Some(by_tenant))).await, "may not use key");
    // The driver, on its own prefix, signs.
    let by_driver = intent_by(&c.ids, "driver", KEY, &msg, 41);
    c.signer("driver", 0).await.sign(pb::SignRequest { key_id: KEY.into(), message: msg, intent: Some(by_driver) }).await.unwrap();
}

/// A revoked key: a valid certificate under the driver's CN whose key is not pinned is refused on
/// the Signer API and as an intent signer at every peer; the pinned key keeps signing.
#[tokio::test]
async fn an_spki_pin_revokes_a_ca_valid_but_unpinned_driver_key() {
    let c = cluster_with(
        |ids, _| SigningPolicyConfig {
            require_intent: true,
            signer_pins: BTreeMap::from([("driver".to_string(), vec![ids.spki_sha256("driver")])]),
            ..Default::default()
        },
        None,
    )
    .await;
    assert_ne!(c.ids.spki_sha256("driver"), c.ids.spki_sha256("driver-2"));
    let msg = digest(b"signed with the stolen key");

    let stolen = intent_by(&c.ids, "driver-2", KEY, &msg, 50);
    denied(
        c.signer("driver-2", 0).await.sign(pb::SignRequest { key_id: KEY.into(), message: msg.clone(), intent: Some(stolen.clone()) }).await,
        "not pinned",
    );
    denied(c.signer("driver-2", 0).await.group_key(pb::GroupKeyRequest { key_id: KEY.into() }).await, "not pinned");
    denied(c.peer_as("cosigner3", 1).await.sign_round1(round1(KEY, "pin", Some(&msg), Some(stolen))).await, "not pinned");
    let ok = intent_by(&c.ids, "driver", KEY, &msg, 51);
    c.signer("driver", 0).await.sign(pb::SignRequest { key_id: KEY.into(), message: msg, intent: Some(ok) }).await.unwrap();
}

// ── approvals ─────────────────────────────────────────────────────────────────────────────────

struct Approver {
    id: &'static str,
    key: aws_lc_rs::signature::Ed25519KeyPair,
}

impl Approver {
    fn new(id: &'static str) -> Self {
        let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
        Self { id, key: aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap() }
    }
    fn config(&self) -> ApproverConfig {
        use aws_lc_rs::signature::KeyPair;
        use base64::Engine;
        let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        spki.extend_from_slice(self.key.public_key().as_ref());
        ApproverConfig { id: self.id.into(), public_key_spki_b64: base64::engine::general_purpose::STANDARD.encode(spki) }
    }
    fn approve(&self, key: &str, msg: &[u8], nonce: &[u8]) -> pb::IntentApproval {
        let request_id = intent::approval_request_id(key, msg, nonce);
        pb::IntentApproval { approver_id: self.id.into(), signature: self.key.sign(request_id.as_bytes()).as_ref().to_vec() }
    }
}

/// A key a 2-of-3 approval rule gates is refused at the cosigners without two valid approvals by
/// distinct configured approvers, whatever the driver did.
#[tokio::test]
async fn an_approval_gated_key_is_refused_at_the_cosigners_without_enough_valid_approvals() {
    let (alice, bob, carol, mallory) = (Approver::new("alice"), Approver::new("bob"), Approver::new("carol"), Approver::new("mallory"));
    let policy = SigningPolicyConfig {
        require_intent: true,
        rules: vec![ApprovalRuleConfig { key_id_prefix: "frost-participant1-namespace".into(), mode: "quorum".into(), threshold: 2 }],
        approvers: vec![alice.config(), bob.config(), carol.config()],
        ..Default::default()
    };
    let c = cluster(|_| policy.clone(), None).await;
    let msg = digest(b"a namespace topology change");
    let nonce = [7u8; 16];
    let with = |approvals: Vec<pb::IntentApproval>, nonce: &[u8], request: u8| {
        let mut i = unsigned(KEY, &msg, request, now_ms(), now_ms() + 120_000);
        i.approval_nonce = nonce.to_vec();
        i.approvals = approvals;
        sign(&c.ids, "driver", i)
    };
    let req = |intent| pb::SignRequest { key_id: KEY.into(), message: msg.clone(), intent: Some(intent) };
    let mut driver = c.signer("driver", 0).await;

    denied(driver.sign(req(with(vec![], &nonce, 60))).await, "approval required");
    denied(driver.sign(req(with(vec![alice.approve(KEY, &msg, &nonce)], &nonce, 61))).await, "carries 1 valid");
    let twice = vec![alice.approve(KEY, &msg, &nonce), alice.approve(KEY, &msg, &nonce)];
    denied(driver.sign(req(with(twice, &nonce, 62))).await, "carries 1 valid");
    let outsider = vec![alice.approve(KEY, &msg, &nonce), mallory.approve(KEY, &msg, &nonce)];
    denied(driver.sign(req(with(outsider, &nonce, 63))).await, "carries 1 valid");
    let wrong_nonce = vec![alice.approve(KEY, &msg, &[8; 16]), bob.approve(KEY, &msg, &[8; 16])];
    denied(driver.sign(req(with(wrong_nonce, &nonce, 64))).await, "carries 0 valid");
    let other_digest = vec![alice.approve(KEY, &digest(b"x"), &nonce), bob.approve(KEY, &digest(b"x"), &nonce)];
    denied(driver.sign(req(with(other_digest, &nonce, 65))).await, "carries 0 valid");
    // A compromised node forwarding an un-approved intent to a peer: refused there too.
    denied(
        c.peer_as("cosigner3", 0).await.sign_round1(round1(KEY, "unapproved", Some(&msg), Some(with(vec![], &nonce, 66)))).await,
        "approval required",
    );

    let quorum = vec![alice.approve(KEY, &msg, &nonce), carol.approve(KEY, &msg, &nonce)];
    driver.sign(req(with(quorum, &nonce, 67))).await.unwrap();
    let entry = c.journal(0).into_iter().find(|e| e.request_id == hex::encode([67u8; 16])).unwrap();
    assert_eq!(entry.approvers, vec!["alice".to_string(), "carol".to_string()]);
}

// ── rate limit, journal, rolling upgrade (in-process) ─────────────────────────────────────────

/// Fails round 2 the first time it is asked, then behaves.
struct FlakyOnce {
    inner: Arc<dyn PeerApi>,
    failed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl PeerApi for FlakyOnce {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(&self, key_id: &str, session_id: &str, ctx: &Round1Ctx) -> Result<SigningCommitments> {
        self.inner.sign_round1(key_id, session_id, ctx).await
    }
    async fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        if !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.inner.abort_sign(key_id, session_id).await?;
            return Err(DaemonError::NotServing("test: flaky peer".into()));
        }
        self.inner.sign_round2(key_id, session_id, message, commitments, intent_digest).await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.inner.abort_sign(key_id, session_id).await
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
    async fn replicate_key(&self, a: &str, b: &str, s: &str, d: &[u8], w: &rutli_cosigner::wrap::Wrapped) -> Result<Vec<u8>> {
        self.inner.replicate_key(a, b, s, d, w).await
    }
    async fn fetch_key(&self, k: &str) -> Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(k).await
    }
    async fn list_keys(&self) -> Result<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, c: &str, k: &str) -> Result<bool> {
        self.inner.purge_key(c, k).await
    }
}

/// An in-process cluster (no gRPC) on `policy`, key generated.
async fn local(root: &Path, policy: &SigningPolicyConfig) -> (Ids, Vec<Arc<Node>>) {
    let ids = Ids::new(&root.join("certs"));
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| open_node(root, &ids, i, policy)).collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    if policy.ceremony_intent_required(true) {
        let dkg = ceremony_by(&ids, "driver", rutli_cosigner::node::CeremonyKind::Dkg, KEY, 0xd0);
        run_dkg_with_intent(&peers, KEY, Some(dkg)).await.unwrap();
    } else {
        run_dkg(&peers, KEY).await.unwrap();
    }
    (ids, nodes)
}

fn peers_of(nodes: &[Arc<Node>]) -> Peers {
    nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect()
}

/// One request id is one charge, whatever the retries: with a limit of ONE signature per minute,
/// a sign whose first t-subset fails in round 2 (so the leader releases a share twice, in two
/// sessions) still succeeds; the next request id is refused; and the charge survives a restart.
#[tokio::test]
async fn the_rate_limit_is_charged_once_per_request_id_across_retries_and_survives_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = SigningPolicyConfig { require_intent: true, sign_rate_limit_per_min: 1, sign_rate_limit_per_day: 100, ..Default::default() };
    let (ids, nodes) = local(tmp.path(), &policy).await;
    let msg = digest(b"retried");
    let i1 = intent_by(&ids, "driver", KEY, &msg, 70);

    let mut peers = peers_of(&nodes);
    peers[1] = Arc::new(FlakyOnce { inner: peers[1].clone(), failed: Default::default() });
    let sig = sign_with_intent(&nodes[0], &peers, KEY, &msg, Some(&i1)).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&nodes[0].group_key(KEY).unwrap(), &msg, &sig));
    let leader = read_key_dir(&tmp.path().join("node-1/journal").join(KEY)).unwrap().entries;
    assert_eq!(leader.len(), 2, "the leader released a share in both attempts");
    assert!(leader.iter().all(|e| e.request_id == hex::encode([70u8; 16])));

    // A replay of the same intent is not a new charge...
    sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i1)).await.unwrap();
    // ...a new request id is, and the minute's budget is spent.
    let i2 = intent_by(&ids, "driver", KEY, &msg, 71);
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i2)).await.unwrap_err();
    assert!(matches!(err, DaemonError::RateLimited(_)), "{err:?}");
    assert_eq!(nodes[0].pending_sign_count(KEY), 0);

    // Restart every node (new process: guards and journals reopened over the same directories).
    drop(peers);
    drop(nodes);
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| open_node(tmp.path(), &ids, i, &policy)).collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i2)).await.unwrap_err();
    assert!(matches!(err, DaemonError::RateLimited(_)), "the charge survived the restart: {err:?}");
    sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i1)).await.unwrap();
}

/// The per-request share cap: a valid intent replayed by a compromised leader buys only
/// `max_shares_per_request` shares from an honest node.
#[tokio::test]
async fn a_replayed_intent_is_capped_per_request() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = SigningPolicyConfig { require_intent: true, max_shares_per_request: 2, ..Default::default() };
    let (ids, nodes) = local(tmp.path(), &policy).await;
    let msg = digest(b"replayed");
    let i1 = intent_by(&ids, "driver", KEY, &msg, 72);
    let pair: Peers = peers_of(&nodes).into_iter().take(2).collect();
    sign_with_intent(&nodes[0], &pair, KEY, &msg, Some(&i1)).await.unwrap();
    sign_with_intent(&nodes[0], &pair, KEY, &msg, Some(&i1)).await.unwrap();
    let err = sign_with_intent(&nodes[0], &pair, KEY, &msg, Some(&i1)).await.unwrap_err();
    assert!(matches!(err, DaemonError::RateLimited(ref m) if m.contains("max_shares_per_request")), "{err:?}");
}

/// The journal entry is written before the share leaves: a node that cannot journal releases no
/// share and burns no nonce marker.
#[tokio::test]
async fn a_node_that_cannot_journal_releases_no_share() {
    use std::os::unix::fs::PermissionsExt;
    // The failure is injected by making the journal segment read-only, which root ignores.
    // SAFETY: geteuid has no preconditions and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root, a read-only journal segment would still be writable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (ids, nodes) = local(tmp.path(), &strict()).await;
    let msg = digest(b"journal first");
    sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&intent_by(&ids, "driver", KEY, &msg, 80))).await.unwrap();
    let seg = rutli_cosigner::journal::segments(&tmp.path().join("node-1/journal").join(KEY)).unwrap().pop().unwrap();
    std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o400)).unwrap();

    let markers = |i: u16| std::fs::read_dir(tmp.path().join(format!("node-{i}/keys/{KEY}.nonces"))).unwrap().count();
    let before = markers(1);
    let i2 = intent_by(&ids, "driver", KEY, &msg, 81);
    let ctx = Round1Ctx { message: Some(msg.clone()), signers: Some(vec![1, 2]), intent: Some(i2.clone()), ..Default::default() };
    let cs = BTreeMap::from([
        (Identifier::try_from(1u16).unwrap(), nodes[0].sign_round1(KEY, "no-journal", &ctx).unwrap()),
        (Identifier::try_from(2u16).unwrap(), nodes[1].sign_round1(KEY, "no-journal", &ctx).unwrap()),
    ]);
    let err = nodes[0].sign_round2_with(KEY, "no-journal", &msg, &cs, Some(intent::intent_digest(&i2))).unwrap_err();
    assert!(matches!(err, DaemonError::Io(_) | DaemonError::Journal(_)), "{err:?}");
    assert_eq!(markers(1), before, "no marker burned for a share that was not journaled");
    std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The rolling upgrade: with `require_intent` off, a driver (or leader) that predates intents
/// still signs; each node journals it as `no-intent` and counts it. An intent that is present is
/// still verified in full.
#[tokio::test]
async fn verify_if_present_accepts_an_old_driver_with_a_metric_and_still_checks_a_present_intent() {
    let tmp = tempfile::tempdir().unwrap();
    let (ids, nodes) = local(tmp.path(), &SigningPolicyConfig::default()).await;
    let msg = digest(b"old driver");
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || {
        let ctx = Round1Ctx { message: Some(msg.clone()), signers: Some(vec![1, 2]), ..Default::default() };
        let cs = BTreeMap::from([
            (Identifier::try_from(1u16).unwrap(), nodes[0].sign_round1(KEY, "old", &ctx).unwrap()),
            (Identifier::try_from(2u16).unwrap(), nodes[1].sign_round1(KEY, "old", &ctx).unwrap()),
        ]);
        nodes[0].sign_round2(KEY, "old", &msg, &cs).unwrap();
    });
    // One per node that took part in round 1.
    assert!(handle.render().contains("rutli_sign_intent_absent_total 2"), "{}", handle.render());
    let e = &read_key_dir(&tmp.path().join("node-1/journal").join(KEY)).unwrap().entries[0];
    assert_eq!((e.purpose.as_str(), e.request_id.as_str()), ("no-intent", ""));

    // The whole sign path, no intent: works.
    let sig = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, None).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&nodes[0].group_key(KEY).unwrap(), &msg, &sig));
    // A present intent that is invalid is refused even in this mode.
    let long_ago = now_ms() - 3_600_000;
    let expired = sign(&ids, "driver", unsigned(KEY, &msg, 90, long_ago, long_ago + 60_000));
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&expired)).await.unwrap_err();
    assert!(matches!(err, DaemonError::PolicyRefused(ref m) if m.contains("expired")), "{err:?}");
}

/// A sign-test round (no intent) is accepted only for the node's own test digest of the key: a
/// compromised node cannot dress an arbitrary digest up as a ceremony test.
#[tokio::test]
async fn a_sign_test_round_for_another_message_is_refused_at_the_peer() {
    let c = cluster(|_| strict(), None).await;
    let mut req = round1(KEY, "fake-test", Some(&digest(b"anything")), None);
    req.purpose = "sign-test".into();
    let s = c.peer_as("cosigner3", 0).await.sign_round1(req).await.unwrap_err();
    // A DKG key has no split-ceremony provenance, so there is no test digest at all.
    assert!(s.code() == tonic::Code::FailedPrecondition || s.code() == tonic::Code::PermissionDenied, "{s:?}");
    assert_eq!(c.nodes[0].pending_sign_count(KEY), 0);
}

// ── ceremony intents over gRPC ───────────────────────────────────────────────────────────────

/// `require_ceremony_intent` over real mTLS: the refresher's signed refresh runs; the same call
/// without an intent, or with the intent of another client (an intent is valid only on its
/// signer's own connection), is refused by the leader; the driver's DKG of a new key needs its
/// own DKG intent too.
#[tokio::test]
async fn signer_dkg_and_refresh_need_the_callers_own_ceremony_intent() {
    use rutli_cosigner::node::CeremonyKind::{Dkg, Refresh};
    let policy = SigningPolicyConfig { require_ceremony_intent: Some(true), signer_may_refresh: false, ..Default::default() };
    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    let group = c.group_key().to_vec();
    let refresh = |intent| pb::RefreshRequest { key_id: KEY.into(), intent };

    denied(c.signer("refresher", 0).await.refresh(refresh(None)).await, "carries no ceremony intent");
    // A signer-role refresh intent (tenant), presented by the refresher: refused on its own merits
    // (signer_may_refresh off) before the caller check would refuse it.
    denied(
        c.signer("refresher", 0).await.refresh(refresh(Some(ceremony_by(&c.ids, "tenant", Refresh, KEY, 1)))).await,
        "signer_may_refresh is off",
    );
    let before = c.nodes[0].key_epoch(KEY).unwrap().epoch;
    let signed = ceremony_by(&c.ids, "refresher", Refresh, KEY, 2);
    let reply = c.signer("refresher", 1).await.refresh(refresh(Some(signed.clone()))).await.unwrap();
    assert_eq!(reply.into_inner().group_verifying_key, group);
    for n in &c.nodes {
        assert_eq!(n.key_epoch(KEY).unwrap().epoch, before + 1);
        assert!(n.ceremony_record(&intent::ceremony_id_for(Refresh, &[2; 16])).is_some());
    }
    // The very same signed intent again (byte for byte), through another leader: one intent, one
    // ceremony.
    let again = c.signer("refresher", 2).await.refresh(refresh(Some(signed))).await;
    assert!(again.as_ref().is_err_and(|s| s.message().contains("already used")), "{again:?}");

    // DKG: the driver's own intent runs it; tenant's intent on the driver's connection is refused.
    let key = "frost-participant1-second";
    let dkg = |intent| pb::DkgRequest { key_id: key.into(), intent };
    denied(c.signer("driver", 0).await.dkg(dkg(None)).await, "carries no ceremony intent");
    denied(
        c.signer("driver", 0).await.dkg(dkg(Some(ceremony_by(&c.ids, "tenant", Dkg, key, 3)))).await,
        "only valid on its signer's own connection",
    );
    c.signer("driver", 0).await.dkg(dkg(Some(ceremony_by(&c.ids, "driver", Dkg, key, 4)))).await.unwrap();
    assert!(c.nodes[2].key_epoch(key).unwrap().present);
}

/// A compromised cosigner on the mesh: a DKG/refresh fence or part 1 without a valid client intent
/// is refused by an enforcing honest node (PERMISSION_DENIED); an intent on a hosted-key fence is a
/// protocol error.
#[tokio::test]
async fn a_cosigner_cannot_fence_an_honest_peer_without_a_client_intent() {
    let policy = SigningPolicyConfig { require_ceremony_intent: Some(true), ..Default::default() };
    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    let mut attacker = c.peer_as("cosigner3", 0).await;
    let e = c.nodes[0].key_epoch(KEY).unwrap();
    let fence = |intent: Option<pb::SignedIntent>, id: &str| pb::CeremonyFenceRequest {
        ceremony_id: id.into(),
        key_id: KEY.into(),
        kind: "refresh".into(),
        expected_epoch: e.epoch,
        expected_pkp_digest: e.pkp_digest.clone(),
        protocol: rutli_cosigner::ceremony::CEREMONY_PROTOCOL,
        intent,
    };
    denied(attacker.ceremony_fence(fence(None, "refresh-attacker")).await, "carries no ceremony intent");
    // Its own certificate cannot sign one either.
    let own = ceremony_by(&c.ids, "cosigner3", rutli_cosigner::node::CeremonyKind::Refresh, KEY, 5);
    denied(
        attacker.ceremony_fence(fence(Some(own.clone()), &intent::ceremony_id_for(rutli_cosigner::node::CeremonyKind::Refresh, &[5; 16]))).await,
        "signed by \"cosigner3\"",
    );
    denied(
        attacker
            .ceremony_part1(pb::CeremonyPart1Request {
                ceremony_id: "refresh-attacker".into(),
                key_id: KEY.into(),
                kind: "refresh".into(),
                roster: vec![1, 2, 3],
                protocol: rutli_cosigner::ceremony::CEREMONY_PROTOCOL,
                intent: None,
            })
            .await,
        "carries no ceremony intent",
    );
    let hosted = attacker
        .ceremony_fence(pb::CeremonyFenceRequest {
            ceremony_id: "g".into(),
            key_id: "rutli-hosted".into(),
            kind: "genkey".into(),
            intent: Some(own),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(hosted.code(), tonic::Code::InvalidArgument, "{hosted:?}");
    // Nothing was fenced: the refresher's real refresh runs at once.
    let ok = ceremony_by(&c.ids, "refresher", rutli_cosigner::node::CeremonyKind::Refresh, KEY, 6);
    c.signer("refresher", 0).await.refresh(pb::RefreshRequest { key_id: KEY.into(), intent: Some(ok) }).await.unwrap();
}

/// Over the mesh the leader is the fencing caller's certificate CN: a fenced peer that presents the
/// client's intent it was shown cannot run part 1 (or 2, 3) on a node another cosigner fenced.
#[tokio::test]
async fn only_the_fencing_cosigner_runs_parts_over_grpc() {
    use rutli_cosigner::node::CeremonyKind::Refresh;
    let policy = SigningPolicyConfig { require_ceremony_intent: Some(true), ..Default::default() };
    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    let e = c.nodes[1].key_epoch(KEY).unwrap();
    let x = ceremony_by(&c.ids, "refresher", Refresh, KEY, 7);
    let xid = intent::ceremony_id_for(Refresh, &[7; 16]);
    let protocol = rutli_cosigner::ceremony::CEREMONY_PROTOCOL;
    c.peer_as("cosigner1", 1)
        .await
        .ceremony_fence(pb::CeremonyFenceRequest {
            ceremony_id: xid.clone(),
            key_id: KEY.into(),
            kind: "refresh".into(),
            expected_epoch: e.epoch,
            expected_pkp_digest: e.pkp_digest.clone(),
            protocol,
            intent: Some(x.clone()),
        })
        .await
        .unwrap();
    let part1 = || pb::CeremonyPart1Request {
        ceremony_id: xid.clone(),
        key_id: KEY.into(),
        kind: "refresh".into(),
        roster: vec![1, 2, 3],
        protocol,
        intent: Some(x.clone()),
    };
    let stolen = c.peer_as("cosigner3", 1).await.ceremony_part1(part1()).await.unwrap_err();
    assert_eq!(stolen.code(), tonic::Code::FailedPrecondition, "{stolen:?}");
    assert!(stolen.message().contains("led by peer \"cosigner1\""), "{stolen:?}");
    let part3 = c
        .peer_as("cosigner3", 1)
        .await
        .ceremony_part3(pb::CeremonyPart3Request { ceremony_id: xid.clone(), round1_digest: vec![0; 32] })
        .await
        .unwrap_err();
    assert_eq!(part3.code(), tonic::Code::NotFound, "no session yet: {part3:?}");
    // The fencing cosigner's part 1 runs.
    c.peer_as("cosigner1", 1).await.ceremony_part1(part1()).await.unwrap();
    let part3 = c
        .peer_as("cosigner3", 1)
        .await
        .ceremony_part3(pb::CeremonyPart3Request { ceremony_id: xid.clone(), round1_digest: vec![0; 32] })
        .await
        .unwrap_err();
    assert!(part3.message().contains("led by peer \"cosigner1\""), "{part3:?}");
    // The refusal left the session alone: the leader can still abort it as its own.
    assert!(c.nodes[1].ceremony_record(&xid).is_none(), "nothing recorded by the refused part 3");
}

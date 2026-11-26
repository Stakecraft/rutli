// Copyright 2026 StakeCraft LLC
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
#[path = "common/store_fault.rs"]
mod store_fault;

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
        Self {
            pki,
            dir: dir.to_path_buf(),
            pems,
        }
    }

    fn signer(&self, who: &str) -> NodeSigner {
        let (c, k) = &self.pems[who];
        NodeSigner::from_pem(c.as_bytes(), k.as_bytes()).unwrap()
    }

    fn spki_sha256(&self, who: &str) -> String {
        let (c, _) = &self.pems[who];
        let der = rustls_pemfile::certs(&mut c.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        hex::encode(intent::Caller::from_leaf_der(&der).unwrap().spki_sha256)
    }

    fn tls_config(&self, who: &str) -> rutli_cosigner::config::TlsConfig {
        let (c, k) = &self.pems[who];
        let (cp, kp) = (
            self.dir.join(format!("{who}.pem")),
            self.dir.join(format!("{who}.key")),
        );
        std::fs::write(&cp, c).unwrap();
        std::fs::write(&kp, k).unwrap();
        rutli_cosigner::config::TlsConfig {
            ca_cert: self.dir.join("ca.pem"),
            cert: cp,
            key: kp,
            domain: None,
            allow_expired_ca: false,
            require_peer_pins: None,
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
        ..Default::default()
    }
}

/// A ceremony intent for `kind` of `key`, signed by `who`, request id 16×`rid`.
fn ceremony_by(
    ids: &Ids,
    who: &str,
    kind: rutli_cosigner::node::CeremonyKind,
    key: &str,
    rid: u8,
) -> pb::SignedIntent {
    sign(
        ids,
        who,
        intent::ceremony_intent(CLUSTER, kind, key, [rid; 16], now_ms(), 120_000),
    )
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
        Retention {
            days: 90,
            max_bytes: 64 << 20,
        },
    )
    .unwrap();
    Arc::new(SignGuard::new(Arc::new(verifier), journal, 10))
}

fn open_node(root: &Path, ids: &Ids, i: u16, policy: &SigningPolicyConfig) -> Arc<Node> {
    let ks = KeyStore::open(root.join(format!("node-{i}")).join("keys")).unwrap();
    Arc::new(
        Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
            .with_sign_guard(guard(root, ids, i, policy)),
    )
}

/// The cluster, its key `KEY` generated, every node on `policy(i)`; `refreshers` is the
/// refresh_allowlist.
async fn cluster(
    policy: impl Fn(u16) -> SigningPolicyConfig,
    refreshers: Option<Vec<String>>,
) -> Cluster {
    cluster_with(|_, i| policy(i), refreshers).await
}

/// [`cluster`] with a policy that may depend on the identities (pins).
async fn cluster_with(
    policy: impl Fn(&Ids, u16) -> SigningPolicyConfig,
    refreshers: Option<Vec<String>>,
) -> Cluster {
    cluster_serving(policy, refreshers, &["operator"], 0).await
}

/// [`cluster_with`], with the Signer services' operator role (`operators`) and their
/// `CeremonySignTest` ceiling (`sign_tests_per_min`, 0 = none) chosen by the test.
async fn cluster_serving(
    policy: impl Fn(&Ids, u16) -> SigningPolicyConfig,
    refreshers: Option<Vec<String>>,
    operators: &[&str],
    sign_tests_per_min: u32,
) -> Cluster {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let ids = Ids::new(&root.join("certs"));
    let nodes: Vec<Arc<Node>> = (1..=N)
        .map(|i| open_node(&root, &ids, i, &policy(&ids, i)))
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let local: Peers = nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>)
        .collect();
    if policy(&ids, 1).ceremony_intent_required(true) {
        run_dkg_with_intent(
            &local,
            KEY,
            Some(ceremony_by(
                &ids,
                "driver",
                rutli_cosigner::node::CeremonyKind::Dkg,
                KEY,
                0xd0,
            )),
        )
        .await
        .unwrap();
    } else {
        run_dkg(&local, KEY).await.unwrap();
    }

    let mut listeners = Vec::new();
    for _ in 0..N {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let endpoints: Vec<String> = listeners
        .iter()
        .map(|l| format!("https://{}", l.local_addr().unwrap()))
        .collect();
    let tls: Vec<_> = (1..=N)
        .map(|i| rutli_cosigner::tls::load(&ids.tls_config(&format!("cosigner{i}"))).unwrap())
        .collect();
    let peer_cns: Arc<std::collections::HashSet<String>> =
        Arc::new((1..=N).map(|i| format!("cosigner{i}")).collect());
    let signer_cns: Arc<std::collections::HashSet<String>> =
        Arc::new(["driver".into(), "tenant".into()].into());
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
                            Some(
                                tls[i]
                                    .dial_as(&format!("cosigner{}", j + 1), None, 0)
                                    .unwrap(),
                            ),
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
            operator_cns: Some(Arc::new(
                operators.iter().map(|cn| (*cn).to_string()).collect(),
            )),
            hosted_write_quorum: 2,
            decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(rutli_cosigner::service::ceremony_sign_test_limiter(
                sign_tests_per_min,
            )),
            sign_guard: nodes[i].sign_guard().cloned(),
            refresh_cns: refreshers
                .as_ref()
                .map(|r| Arc::new(r.iter().cloned().collect())),
        };
        let peer = PeerSvc {
            node: nodes[i].clone(),
            allowed_cns: Some(peer_cns.clone()),
            peer_ids: Some(Arc::new(
                (1..=N).map(|k| (format!("cosigner{k}"), k)).collect(),
            )),
            peer_pins: None,
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
    Cluster {
        ids,
        root,
        nodes,
        endpoints,
        servers,
        _tmp: tmp,
    }
}

fn strict() -> SigningPolicyConfig {
    SigningPolicyConfig {
        require_intent: Some(true),
        ..Default::default()
    }
}

/// Intents required, `per_min` signatures a minute and 100 a day.
fn rate_limited(per_min: u32) -> SigningPolicyConfig {
    SigningPolicyConfig {
        require_intent: Some(true),
        sign_rate_limit_per_min: per_min,
        sign_rate_limit_per_day: 100,
        ..Default::default()
    }
}

/// Intents required, and no node releases more than two shares for one request id.
fn capped_at_two_shares() -> SigningPolicyConfig {
    SigningPolicyConfig {
        require_intent: Some(true),
        max_shares_per_request: 2,
        ..Default::default()
    }
}

impl Cluster {
    async fn channel(
        &self,
        who: Option<&str>,
        node: usize,
    ) -> std::result::Result<Channel, tonic::transport::Error> {
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
        Endpoint::from_shared(self.endpoints[node].clone())
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
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
        read_key_dir(
            &self
                .root
                .join(format!("node-{}", i + 1))
                .join("journal")
                .join(KEY),
        )
        .map_or_default(|r| r.entries)
    }

    fn markers(&self, i: usize) -> usize {
        let dir = self
            .root
            .join(format!("node-{}", i + 1))
            .join("keys")
            .join(format!("{KEY}.nonces"));
        std::fs::read_dir(dir).map_or(0, std::iter::Iterator::count)
    }
}

fn round1(
    key: &str,
    session: &str,
    msg: Option<&[u8]>,
    intent: Option<pb::SignedIntent>,
) -> pb::SignRound1Request {
    pb::SignRound1Request {
        key_id: key.into(),
        session_id: session.into(),
        intent,
        message: msg.map_or_default(<[u8]>::to_vec),
        signers: vec![1, 3],
        ..Default::default()
    }
}

fn denied(r: std::result::Result<impl std::fmt::Debug, tonic::Status>, needle: &str) {
    let s = r.expect_err("must be refused");
    assert_eq!(s.code(), tonic::Code::PermissionDenied, "{s:?}");
    assert!(
        s.message().contains(needle),
        "expected {needle:?} in {:?}",
        s.message()
    );
}

/// `who`, presenting `intent` over `msg`, is refused with `needle` on the Signer API (sign and group
/// key, at node 0) and, forwarded by a compromised cosigner3, as a round 1 at node `peer_node`.
async fn denied_on_signer_group_key_and_forwarded_round1(
    c: &Cluster,
    who: &str,
    peer_node: usize,
    session: &str,
    msg: &[u8],
    intent: pb::SignedIntent,
    needle: &str,
) {
    denied(
        c.signer(who, 0)
            .await
            .sign(pb::SignRequest {
                key_id: KEY.into(),
                message: msg.to_vec(),
                intent: Some(intent.clone()),
            })
            .await,
        needle,
    );
    denied(
        c.signer(who, 0)
            .await
            .group_key(pb::GroupKeyRequest { key_id: KEY.into() })
            .await,
        needle,
    );
    denied(
        c.peer_as("cosigner3", peer_node)
            .await
            .sign_round1(round1(KEY, session, Some(msg), Some(intent)))
            .await,
        needle,
    );
}

/// The driver signs `msg` at node 0 under its own intent number `request`; the call must succeed.
async fn driver_signs_at_node0(c: &Cluster, msg: &[u8], request: u8) {
    c.signer("driver", 0)
        .await
        .sign(pb::SignRequest {
            key_id: KEY.into(),
            message: msg.to_vec(),
            intent: Some(intent_by(&c.ids, "driver", KEY, msg, request)),
        })
        .await
        .unwrap();
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
    denied(
        attacker
            .sign_round1(round1(KEY, "s-none", Some(&evil), None))
            .await,
        "carries no signing intent",
    );
    // An intent the compromised node signed itself with its cosigner key.
    let forged = intent_by(&c.ids, "cosigner3", KEY, &evil, 1);
    denied(
        attacker
            .sign_round1(round1(KEY, "s-forged", Some(&evil), Some(forged)))
            .await,
        "not on this node's signer_allowlist",
    );
    // A real driver intent, its digest rewritten (the signature no longer matches).
    let mut altered = intent_by(&c.ids, "driver", KEY, &good, 2);
    let mut body = <pb::SignIntent as prost::Message>::decode(altered.intent.as_slice()).unwrap();
    body.digest = evil.clone();
    altered.intent = prost::Message::encode_to_vec(&body);
    denied(
        attacker
            .sign_round1(round1(KEY, "s-altered", Some(&evil), Some(altered)))
            .await,
        "bad request signature",
    );
    // A real driver intent, for another digest than the round signs.
    let other = intent_by(&c.ids, "driver", KEY, &good, 3);
    denied(
        attacker
            .sign_round1(round1(KEY, "s-other", Some(&evil), Some(other)))
            .await,
        "another message",
    );
    // A real driver intent for another key.
    let wrong_key = intent_by(&c.ids, "driver", "frost-participant1-other", &evil, 4);
    denied(
        attacker
            .sign_round1(round1(KEY, "s-key", Some(&evil), Some(wrong_key)))
            .await,
        "is for key",
    );
    // A replayed, expired driver intent for the very digest.
    let long_ago = now_ms() - 3_600_000;
    let expired = sign(
        &c.ids,
        "driver",
        unsigned(KEY, &evil, 5, long_ago, long_ago + 60_000),
    );
    denied(
        attacker
            .sign_round1(round1(KEY, "s-expired", Some(&evil), Some(expired)))
            .await,
        "expired",
    );
    // A "driver" certificate from another CA.
    let rogue = intent_by(&c.ids, "rogue", KEY, &evil, 6);
    denied(
        attacker
            .sign_round1(round1(KEY, "s-rogue", Some(&evil), Some(rogue)))
            .await,
        "certificate",
    );
    // An intent for another cluster.
    let mut foreign = unsigned(KEY, &evil, 7, now_ms(), now_ms() + 60_000);
    foreign.cluster_id = "anothercluster00".into();
    denied(
        attacker
            .sign_round1(round1(
                KEY,
                "s-cluster",
                Some(&evil),
                Some(sign(&c.ids, "driver", foreign)),
            ))
            .await,
        "cluster",
    );

    assert_eq!(
        c.nodes[0].pending_sign_count(KEY),
        0,
        "no round-1 nonces were generated"
    );
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
    assert_eq!(
        c.journal(0),
        [] as [rutli_cosigner::journal::JournalEntry; 0]
    );
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
    let r = attacker
        .clone()
        .sign_round1(round1(KEY, session, Some(good), Some(valid.clone())))
        .await
        .unwrap();
    let c1: SigningCommitments = serde_json::from_slice(&r.into_inner().commitments).unwrap();
    let ctx3 = Round1Ctx {
        message: Some(good.to_vec()),
        signers: Some(vec![1, 3]),
        intent: Some(valid.clone()),
        ..Default::default()
    };
    let c3 = c.nodes[2].sign_round1(KEY, session, &ctx3).unwrap();
    BTreeMap::from([
        (Identifier::try_from(1u16).unwrap(), c1),
        (Identifier::try_from(3u16).unwrap(), c3),
    ])
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
    assert_eq!(
        c.nodes[0].pending_sign_count(KEY),
        0,
        "a refused round 2 drops the session's nonces"
    );

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
    assert_eq!(
        (j[0].purpose.as_str(), j[0].digest.as_str()),
        ("sign", hex::encode(&good).as_str())
    );
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
    let req = |intent: Option<pb::SignedIntent>| pb::SignRequest {
        key_id: KEY.into(),
        message: msg.clone(),
        intent,
    };
    let by_driver = intent_by(&c.ids, "driver", KEY, &msg, 20);

    for who in ["operator", "refresher", "cosigner2"] {
        denied(
            c.signer(who, 0)
                .await
                .sign(req(Some(by_driver.clone())))
                .await,
            "not permitted to call the Signer API",
        );
    }
    // No client certificate, or one from another CA: no TLS session at all.
    assert!(
        c.channel(None, 0).await.is_err()
            || SignerClient::new(c.channel(None, 0).await.unwrap())
                .sign(req(None))
                .await
                .is_err()
    );
    match c.channel(Some("rogue"), 0).await {
        Err(_) => {}
        Ok(ch) => assert!(SignerClient::new(ch)
            .sign(req(Some(by_driver.clone())))
            .await
            .is_err()),
    }
    // Another allowlisted client cannot use the driver's intent, nor the driver another's.
    denied(
        c.signer("tenant", 0)
            .await
            .sign(req(Some(by_driver.clone())))
            .await,
        "only valid on its signer's own connection",
    );
    let by_tenant = intent_by(&c.ids, "tenant", KEY, &msg, 21);
    denied(
        c.signer("driver", 0).await.sign(req(Some(by_tenant))).await,
        "only valid on its signer's own connection",
    );
    // The driver without an intent, where one is required.
    denied(
        c.signer("driver", 0).await.sign(req(None)).await,
        "carries no signing intent",
    );
    assert!((0..3).all(|i| c.journal(i).is_empty()));

    // The driver with its own intent: a valid signature, journaled on both participants.
    let sig = c
        .signer("driver", 1)
        .await
        .sign(req(Some(by_driver)))
        .await
        .unwrap()
        .into_inner()
        .signature;
    let sig: [u8; 64] = sig.try_into().unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &c.group_key(),
        &msg,
        &sig
    ));
    let journaled: Vec<usize> = (0..3)
        .filter(|&i| {
            c.journal(i)
                .iter()
                .any(|e| e.request_id == hex::encode([20u8; 16]))
        })
        .collect();
    assert!(
        journaled.len() >= 2 && journaled.contains(&1),
        "leader and its partner journal it: {journaled:?}"
    );
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
        require_intent: Some(true),
        require_ceremony_intent: Some(false),
        signer_may_refresh: false,
        ..Default::default()
    };
    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    let msg = digest(b"refresher tries");
    let by_driver = intent_by(&c.ids, "driver", KEY, &msg, 30);

    denied(
        c.signer("refresher", 0)
            .await
            .sign(pb::SignRequest {
                key_id: KEY.into(),
                message: msg.clone(),
                intent: Some(by_driver),
            })
            .await,
        "not permitted",
    );
    denied(
        c.signer("driver", 0)
            .await
            .refresh(pb::RefreshRequest {
                key_id: KEY.into(),
                intent: None,
            })
            .await,
        "may not call Refresh",
    );
    c.signer("refresher", 0)
        .await
        .key_status(pb::KeyStatusRequest { key_id: KEY.into() })
        .await
        .unwrap();
    let before = c.nodes[0].key_epoch(KEY).unwrap().epoch;
    let reply = c
        .signer("refresher", 0)
        .await
        .refresh(pb::RefreshRequest {
            key_id: KEY.into(),
            intent: None,
        })
        .await
        .unwrap();
    assert_eq!(
        reply.into_inner().group_verifying_key,
        c.group_key().to_vec()
    );
    assert_eq!(c.nodes[0].key_epoch(KEY).unwrap().epoch, before + 1);
}

/// A tenant's driver certificate may use only its own prefix, at the leader and at every peer.
#[tokio::test]
async fn a_signer_without_an_acl_for_a_key_is_refused_when_acls_are_required() {
    let policy = SigningPolicyConfig {
        require_intent: Some(true),
        signer_acl_required: true,
        signer_acl: BTreeMap::from([
            (
                "driver".to_string(),
                vec!["frost-participant1-".to_string()],
            ),
            (
                "tenant".to_string(),
                vec!["frost-participant2-".to_string()],
            ),
        ]),
        ..Default::default()
    };
    let c = cluster(|_| policy.clone(), None).await;
    let msg = digest(b"tenant 2 reaches for tenant 1's key");
    let by_tenant = intent_by(&c.ids, "tenant", KEY, &msg, 40);
    // A compromised node forwarding the tenant's intent to a peer gets the same answer there.
    denied_on_signer_group_key_and_forwarded_round1(
        &c,
        "tenant",
        0,
        "acl",
        &msg,
        by_tenant,
        "may not use key",
    )
    .await;
    // The driver, on its own prefix, signs.
    driver_signs_at_node0(&c, &msg, 41).await;
}

/// A revoked key: a valid certificate under the driver's CN whose key is not pinned is refused on
/// the Signer API and as an intent signer at every peer; the pinned key keeps signing.
#[tokio::test]
async fn an_spki_pin_revokes_a_ca_valid_but_unpinned_driver_key() {
    let c = cluster_with(
        |ids, _| SigningPolicyConfig {
            require_intent: Some(true),
            signer_pins: BTreeMap::from([("driver".to_string(), vec![ids.spki_sha256("driver")])]),
            ..Default::default()
        },
        None,
    )
    .await;
    assert_ne!(c.ids.spki_sha256("driver"), c.ids.spki_sha256("driver-2"));
    let msg = digest(b"signed with the stolen key");

    let stolen = intent_by(&c.ids, "driver-2", KEY, &msg, 50);
    denied_on_signer_group_key_and_forwarded_round1(
        &c,
        "driver-2",
        1,
        "pin",
        &msg,
        stolen,
        "not pinned",
    )
    .await;
    driver_signs_at_node0(&c, &msg, 51).await;
}

// ── approvals ─────────────────────────────────────────────────────────────────────────────────

struct Approver {
    id: &'static str,
    key: aws_lc_rs::signature::Ed25519KeyPair,
}

impl Approver {
    fn new(id: &'static str) -> Self {
        let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .unwrap();
        Self {
            id,
            key: aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
        }
    }
    fn config(&self) -> ApproverConfig {
        use aws_lc_rs::signature::KeyPair;
        use base64::Engine;
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(self.key.public_key().as_ref());
        ApproverConfig {
            id: self.id.into(),
            public_key_spki_b64: base64::engine::general_purpose::STANDARD.encode(spki),
        }
    }
    fn approve(&self, key: &str, msg: &[u8], nonce: &[u8]) -> pb::IntentApproval {
        let request_id = intent::approval_request_id(key, msg, nonce);
        pb::IntentApproval {
            approver_id: self.id.into(),
            signature: self.key.sign(request_id.as_bytes()).as_ref().to_vec(),
        }
    }
}

/// A key a 2-of-3 approval rule gates is refused at the cosigners without two valid approvals by
/// distinct configured approvers, whatever the driver did.
#[tokio::test]
async fn an_approval_gated_key_is_refused_at_the_cosigners_without_enough_valid_approvals() {
    let (alice, bob, carol, mallory) = (
        Approver::new("alice"),
        Approver::new("bob"),
        Approver::new("carol"),
        Approver::new("mallory"),
    );
    let policy = SigningPolicyConfig {
        require_intent: Some(true),
        rules: vec![ApprovalRuleConfig {
            key_id_prefix: "frost-participant1-namespace".into(),
            mode: "quorum".into(),
            threshold: 2,
        }],
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
    let req = |intent| pb::SignRequest {
        key_id: KEY.into(),
        message: msg.clone(),
        intent: Some(intent),
    };
    let mut driver = c.signer("driver", 0).await;

    denied(
        driver.sign(req(with(vec![], &nonce, 60))).await,
        "approval required",
    );
    denied(
        driver
            .sign(req(with(
                vec![alice.approve(KEY, &msg, &nonce)],
                &nonce,
                61,
            )))
            .await,
        "carries 1 valid",
    );
    let twice = vec![
        alice.approve(KEY, &msg, &nonce),
        alice.approve(KEY, &msg, &nonce),
    ];
    denied(
        driver.sign(req(with(twice, &nonce, 62))).await,
        "carries 1 valid",
    );
    let outsider = vec![
        alice.approve(KEY, &msg, &nonce),
        mallory.approve(KEY, &msg, &nonce),
    ];
    denied(
        driver.sign(req(with(outsider, &nonce, 63))).await,
        "carries 1 valid",
    );
    let wrong_nonce = vec![
        alice.approve(KEY, &msg, &[8; 16]),
        bob.approve(KEY, &msg, &[8; 16]),
    ];
    denied(
        driver.sign(req(with(wrong_nonce, &nonce, 64))).await,
        "carries 0 valid",
    );
    let other_digest = vec![
        alice.approve(KEY, &digest(b"x"), &nonce),
        bob.approve(KEY, &digest(b"x"), &nonce),
    ];
    denied(
        driver.sign(req(with(other_digest, &nonce, 65))).await,
        "carries 0 valid",
    );
    // A compromised node forwarding an un-approved intent to a peer: refused there too.
    denied(
        c.peer_as("cosigner3", 0)
            .await
            .sign_round1(round1(
                KEY,
                "unapproved",
                Some(&msg),
                Some(with(vec![], &nonce, 66)),
            ))
            .await,
        "approval required",
    );

    let quorum = vec![
        alice.approve(KEY, &msg, &nonce),
        carol.approve(KEY, &msg, &nonce),
    ];
    driver.sign(req(with(quorum, &nonce, 67))).await.unwrap();
    let entry = c
        .journal(0)
        .into_iter()
        .find(|e| e.request_id == hex::encode([67u8; 16]))
        .unwrap();
    assert_eq!(
        entry.approvers,
        vec!["alice".to_string(), "carol".to_string()]
    );
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
    async fn sign_round1(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
    ) -> Result<SigningCommitments> {
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
        self.inner
            .sign_round2(key_id, session_id, message, commitments, intent_digest)
            .await
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
    async fn replicate_key(
        &self,
        a: &str,
        b: &str,
        s: &str,
        d: &[u8],
        w: &rutli_cosigner::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
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

/// A member that answers round 2 late: it holds the request `hold`, then signs anyway — and then
/// replays the same round 2 once more, which must be refused — and holds an abort `abort_hold`.
/// The leader has given up on it by then (its round deadline), so this is a member answering for
/// an attempt the leader abandoned.
struct Late {
    inner: Arc<dyn PeerApi>,
    hold: std::time::Duration,
    abort_hold: std::time::Duration,
    sessions: Arc<std::sync::Mutex<Vec<String>>>,
    /// Each late round 2 as it came out.
    outcomes: Arc<std::sync::Mutex<Vec<LateOutcome>>>,
}

/// What a late round 2 and its replay answered.
#[derive(Clone, Debug)]
struct LateOutcome {
    signed: bool,
    /// The first round 2 found no session (`UnknownSession`).
    first_unknown: bool,
    /// The replay was refused as `UnknownSession` — exactly that, not any error.
    replay_unknown: bool,
    replay: String,
}

fn unknown_session<T>(r: &Result<T>) -> bool {
    matches!(
        r,
        Err(DaemonError::Core(
            rutli_frost_core::CoreError::UnknownSession(_)
        ))
    )
}

impl Late {
    fn new(inner: Arc<dyn PeerApi>, hold: u64, abort_hold: u64) -> Arc<Self> {
        Arc::new(Self {
            inner,
            hold: std::time::Duration::from_secs(hold),
            abort_hold: std::time::Duration::from_secs(abort_hold),
            sessions: Default::default(),
            outcomes: Default::default(),
        })
    }
}

#[async_trait]
impl PeerApi for Late {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
    ) -> Result<SigningCommitments> {
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
        self.sessions.lock().unwrap().push(session_id.to_owned());
        let (inner, hold, outcomes) = (self.inner.clone(), self.hold, self.outcomes.clone());
        let (k, s, m, c, d) = (
            key_id.to_owned(),
            session_id.to_owned(),
            message.to_vec(),
            commitments.clone(),
            intent_digest.copied(),
        );
        // Its own task: the leader dropping this call does not stop the member.
        tokio::spawn(async move {
            tokio::time::sleep(hold).await;
            let first = inner.sign_round2(&k, &s, &m, &c, d.as_ref()).await;
            let replay = inner.sign_round2(&k, &s, &m, &c, d.as_ref()).await;
            outcomes.lock().unwrap().push(LateOutcome {
                signed: first.is_ok(),
                first_unknown: unknown_session(&first),
                replay_unknown: unknown_session(&replay),
                replay: replay
                    .err()
                    .map_or_else(|| "SIGNED TWICE".into(), |e| e.to_string()),
            });
            first
        })
        .await
        .unwrap()
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        let (inner, hold, k, s) = (
            self.inner.clone(),
            self.abort_hold,
            key_id.to_owned(),
            session_id.to_owned(),
        );
        tokio::spawn(async move {
            tokio::time::sleep(hold).await;
            inner.abort_sign(&k, &s).await
        })
        .await
        .unwrap()
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
    async fn replicate_key(
        &self,
        a: &str,
        b: &str,
        s: &str,
        d: &[u8],
        w: &rutli_cosigner::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
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

/// Nonce and intent safety under the leader's round deadlines and detached aborts (peer liveness).
/// Every member handle acts for its leader ([`peers_for`]), so session ownership is the real one:
///
/// - a member whose round 2 comes after the leader gave up on it (and whose abort comes later still)
///   signs that session once: its nonce marker is burnt, a replay of the same round 2 is refused as
///   an unknown session, and the share is journaled once for the request;
/// - meanwhile a second leader with the same request cannot send that session's round 2 or abort
///   it: refused as not the session's owner, nothing burnt, nothing journaled, the session kept;
/// - when the abort reaches the member first, its late round 2 finds no session and releases
///   nothing;
/// - each request id is charged once on every node, however many attempts and late shares it had,
///   and no node releases more than `max_shares_per_request` shares for it.
#[tokio::test(start_paused = true)]
async fn an_abandoned_attempt_never_signs_twice_and_its_intent_is_charged_once() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = rate_limited(2);
    let (ids, nodes) = local(tmp.path(), &policy).await;
    let msg = digest(b"abandoned");
    let journal = |i: u16, request: u8| journal_of(tmp.path(), i, request);
    let markers = rutli_frost_core::nonce_store::NonceStore::open(
        tmp.path().join(format!("node-2/keys/{KEY}.nonces")),
    )
    .unwrap();

    // The member answers round 2 after the leader's 5 s deadline, the abort ten seconds after that.
    let late = Late::new(peers_for(&nodes, 0)[1].clone(), 6, 10);
    let mut peers = peers_for(&nodes, 0);
    peers[1] = late.clone();
    let started = tokio::time::Instant::now();
    let sig = sign_with_intent(
        &nodes[0],
        &peers,
        KEY,
        &msg,
        Some(&intent_by(&ids, "driver", KEY, &msg, 90)),
    )
    .await
    .unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &nodes[0].group_key(KEY).unwrap(),
        &msg,
        &sig
    ));
    assert!(
        started.elapsed() < std::time::Duration::from_millis(5200),
        "one round-2 deadline: {:?}",
        started.elapsed()
    );
    let session = late.sessions.lock().unwrap()[0].clone();

    // Leader 1 gave up on node 2's session; its late round 2 has not landed yet. Another leader
    // (node 3) with the same request can neither sign it nor abort it.
    let rival = LocalPeer::new(nodes[1].clone()).on_behalf_of(nodes[2].clone());
    let owner = |r: &Result<_>| {
        matches!(
            r,
            Err(DaemonError::Core(
                rutli_frost_core::CoreError::NotSessionOwner { .. }
            ))
        )
    };
    let r2 = rival
        .sign_round2(KEY, &session, &msg, &BTreeMap::new(), None)
        .await
        .map(|_| ());
    assert!(owner(&r2), "{r2:?}");
    let abort = rival.abort_sign(KEY, &session).await;
    assert!(owner(&abort), "{abort:?}");
    assert_eq!(
        nodes[1].pending_sign_count(KEY),
        1,
        "the session stays with its opener"
    );
    assert!(!markers.is_consumed(&session).unwrap());
    assert_eq!(journal(2, 90), 0);

    tokio::time::sleep(std::time::Duration::from_secs(12)).await;
    let outcomes = late.outcomes.lock().unwrap().clone();
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].signed, "the late round 2 signed");
    assert!(
        outcomes[0].replay_unknown,
        "a replayed round 2 is an unknown session: {}",
        outcomes[0].replay
    );
    assert!(
        markers.is_consumed(&session).unwrap(),
        "the abandoned session's marker is burnt"
    );
    for n in &nodes {
        assert_eq!(n.pending_sign_count(KEY), 0);
    }
    // The leader released its own share in both attempts, node 2 its late one, node 3 one.
    assert_eq!((journal(1, 90), journal(2, 90), journal(3, 90)), (2, 1, 1));

    // The abort comes first: the late round 2 finds no session and releases nothing.
    let late = Late::new(peers_for(&nodes, 0)[1].clone(), 6, 0);
    let mut peers = peers_for(&nodes, 0);
    peers[1] = late.clone();
    sign_with_intent(
        &nodes[0],
        &peers,
        KEY,
        &msg,
        Some(&intent_by(&ids, "driver", KEY, &msg, 91)),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let outcomes = late.outcomes.lock().unwrap().clone();
    assert_eq!(outcomes.len(), 1);
    assert!(
        !outcomes[0].signed && outcomes[0].first_unknown,
        "no nonces left for the abandoned session: {outcomes:?}"
    );
    assert!(outcomes[0].replay_unknown);
    let session = late.sessions.lock().unwrap()[0].clone();
    assert!(!markers.is_consumed(&session).unwrap());
    assert_eq!(journal(2, 91), 0);

    // Two requests, two charges (the limit is two a minute): attempts and late shares cost nothing
    // more, and the third request is refused.
    let err = sign_with_intent(
        &nodes[0],
        &peers_for(&nodes, 0),
        KEY,
        &msg,
        Some(&intent_by(&ids, "driver", KEY, &msg, 92)),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DaemonError::RateLimited(_)), "{err:?}");
    for i in 1..=N {
        for request in [90, 91] {
            assert!(
                journal(i, request)
                    <= SigningPolicyConfig::default().max_shares_per_request as usize
            );
        }
    }
}

/// Session ids, as a test wrapper saw them.
type Sessions = Arc<std::sync::Mutex<Vec<String>>>;

/// A member's view that records the round 2s and aborts it is sent, and forwards them.
struct Watched {
    inner: Arc<dyn PeerApi>,
    round2s: Sessions,
    aborts: Sessions,
}

#[async_trait]
impl PeerApi for Watched {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(
        &self,
        key_id: &str,
        session_id: &str,
        ctx: &Round1Ctx,
    ) -> Result<SigningCommitments> {
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
        self.round2s.lock().unwrap().push(session_id.to_owned());
        self.inner
            .sign_round2(key_id, session_id, message, commitments, intent_digest)
            .await
    }
    async fn abort_sign(&self, key_id: &str, session_id: &str) -> Result<()> {
        self.aborts.lock().unwrap().push(session_id.to_owned());
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
    async fn replicate_key(
        &self,
        a: &str,
        b: &str,
        s: &str,
        d: &[u8],
        w: &rutli_cosigner::wrap::Wrapped,
    ) -> Result<Vec<u8>> {
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

/// Yield until `done`, moving no time (a held blocking thread keeps paused time from advancing by
/// itself; nothing here needs it to).
async fn until(what: &str, done: impl Fn() -> bool) {
    // Bounded by wall time, not by a count of yields: the work waited for may be on a blocking
    // thread, which a loaded runner can leave unscheduled for longer than any fixed number of
    // yields takes. The short real sleep gives that thread the CPU without moving paused time.
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < give_up {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(std::time::Duration::from_micros(200));
    }
    panic!("never happened within 30 s: {what}");
}

/// An abort that lands DURING a member's round 2, at orchestrator level: node 2's round 2 holds in
/// its store work — after it took the session's authorization and nonces out of memory, before the
/// journal entry and the marker — while the leader's round-2 deadline passes. The leader aborts it
/// (detached) and signs with node 3. The abort finds nothing to drop; when the store moves, node 2's
/// round 2 finishes once: one journal entry, one marker, nothing more for the request.
#[tokio::test(start_paused = true)]
async fn an_abort_during_round_2_finds_nothing_and_the_share_is_journaled_once() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = SigningPolicyConfig {
        require_intent: Some(true),
        sign_rate_limit_per_min: 100,
        sign_rate_limit_per_day: 1000,
        ..Default::default()
    };
    let store = store_fault::StoreFault::new();
    let (ids, nodes) = local_hooked(tmp.path(), &policy, 2, store.hook()).await;
    let msg = digest(b"abort during round 2");
    let journal = |i: u16, request: u8| journal_of(tmp.path(), i, request);
    let (round2s, aborts): (Sessions, Sessions) = Default::default();
    let mut peers = peers_for(&nodes, 0);
    peers[1] = Arc::new(Watched {
        inner: peers[1].clone(),
        round2s: round2s.clone(),
        aborts: aborts.clone(),
    });

    // Node 2 is this request's first partner (#193), so its round 2 is the one that holds.
    assert_eq!(
        rutli_cosigner::orchestrator::partner_offset(&[99; 16], 2),
        0
    );
    store.set(store_fault::Store::Hold);
    let signing = {
        let (leader, peers, intent, msg) = (
            nodes[0].clone(),
            peers.clone(),
            intent_by(&ids, "driver", KEY, &msg, 99),
            msg.clone(),
        );
        tokio::spawn(
            async move { sign_with_intent(&leader, &peers, KEY, &msg, Some(&intent)).await },
        )
    };
    until("node 2's round 2 to hold in its store work", || {
        store.held() == 1
    })
    .await;
    let session = round2s.lock().unwrap()[0].clone();
    assert_eq!(
        nodes[1].pending_sign_count(KEY),
        0,
        "its nonces are out of memory already"
    );
    assert_eq!(journal(2, 99), 0);

    tokio::time::advance(
        rutli_cosigner::peer::ROUND2_DEADLINE + std::time::Duration::from_millis(10),
    )
    .await;
    let sig = signing.await.unwrap().expect("signed with node 3");
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &nodes[0].group_key(KEY).unwrap(),
        &msg,
        &sig
    ));
    until("the abort to reach node 2", || {
        aborts.lock().unwrap().contains(&session)
    })
    .await;
    let markers = rutli_frost_core::nonce_store::NonceStore::open(
        tmp.path().join(format!("node-2/keys/{KEY}.nonces")),
    )
    .unwrap();
    assert!(
        !markers.is_consumed(&session).unwrap(),
        "the abort landed while round 2 held"
    );
    assert_eq!(journal(2, 99), 0);

    store.set(store_fault::Store::Ok);
    until("node 2's round 2 to end", || {
        nodes[1].load_now().inflight == 0
    })
    .await;
    assert!(
        markers.is_consumed(&session).unwrap(),
        "round 2 finished: its marker is burnt"
    );
    assert_eq!((journal(1, 99), journal(2, 99), journal(3, 99)), (2, 1, 1));
    assert_eq!(
        round2s.lock().unwrap().len(),
        1,
        "the leader never resends a round 2"
    );
}

/// With `max_shares_per_request = 1` a second attempt for the same request is refused on a member
/// that already released a share for it (here the leader's own node: it is in every subset), and
/// nothing more is released anywhere.
#[tokio::test]
async fn with_one_share_per_request_a_second_attempt_is_refused_where_a_share_left_already() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = SigningPolicyConfig {
        require_intent: Some(true),
        max_shares_per_request: 1,
        ..Default::default()
    };
    let (ids, nodes) = local(tmp.path(), &policy).await;
    let msg = digest(b"one share each");
    let mut peers = peers_for(&nodes, 0);
    peers[1] = Arc::new(FlakyOnce {
        inner: peers[1].clone(),
        failed: Default::default(),
    });
    let err = sign_with_intent(
        &nodes[0],
        &peers,
        KEY,
        &msg,
        Some(&intent_by(&ids, "driver", KEY, &msg, 94)),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, DaemonError::RateLimited(ref m) if m.contains("max_shares_per_request")),
        "{err:?}"
    );
    let journal = |i: u16| journal_of(tmp.path(), i, 94);
    assert_eq!((journal(1), journal(2), journal(3)), (1, 0, 0));
    for n in &nodes {
        assert_eq!(n.pending_sign_count(KEY), 0);
    }
}

/// Node `i`'s journal entries for request id 16×`request`.
fn journal_of(root: &Path, i: u16, request: u8) -> usize {
    read_key_dir(&root.join(format!("node-{i}/journal")).join(KEY))
        .unwrap()
        .entries
        .into_iter()
        .filter(|e| e.request_id == hex::encode([request; 16]))
        .count()
}

/// Leader `leader`'s (0-based) view of an in-process cluster: its own node as itself, every other
/// node acting for it — so the sessions it opens are owned by its CN there, as over gRPC.
fn peers_for(nodes: &[Arc<Node>], leader: usize) -> Peers {
    nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let peer = if i == leader {
                LocalPeer::new(n.clone())
            } else {
                LocalPeer::new(n.clone()).on_behalf_of(nodes[leader].clone())
            };
            Arc::new(peer) as Arc<dyn PeerApi>
        })
        .collect()
}

/// [`local`] with a [`rutli_cosigner::node::SignStoreHook`] on node `hooked`.
async fn local_hooked(
    root: &Path,
    policy: &SigningPolicyConfig,
    hooked: u16,
    hook: rutli_cosigner::node::SignStoreHook,
) -> (Ids, Vec<Arc<Node>>) {
    let ids = Ids::new(&root.join("certs"));
    let nodes: Vec<Arc<Node>> = (1..=N)
        .map(|i| {
            let ks = KeyStore::open(root.join(format!("node-{i}")).join("keys")).unwrap();
            let node = Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
                .with_sign_guard(guard(root, &ids, i, policy));
            Arc::new(if i == hooked {
                node.with_sign_store_hook(hook.clone())
            } else {
                node
            })
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let dkg = ceremony_by(
        &ids,
        "driver",
        rutli_cosigner::node::CeremonyKind::Dkg,
        KEY,
        0xd0,
    );
    run_dkg_with_intent(&peers_of(&nodes), KEY, Some(dkg))
        .await
        .unwrap();
    (ids, nodes)
}

/// An in-process cluster (no gRPC) on `policy`, key generated.
async fn local(root: &Path, policy: &SigningPolicyConfig) -> (Ids, Vec<Arc<Node>>) {
    let ids = Ids::new(&root.join("certs"));
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| open_node(root, &ids, i, policy)).collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>)
        .collect();
    if policy.ceremony_intent_required(true) {
        let dkg = ceremony_by(
            &ids,
            "driver",
            rutli_cosigner::node::CeremonyKind::Dkg,
            KEY,
            0xd0,
        );
        run_dkg_with_intent(&peers, KEY, Some(dkg)).await.unwrap();
    } else {
        run_dkg(&peers, KEY).await.unwrap();
    }
    (ids, nodes)
}

/// [`local`] on `policy`, the digest of `tag`, and the driver's intent `request` over it.
async fn local_with_driver_intent(
    root: &Path,
    policy: &SigningPolicyConfig,
    tag: &[u8],
    request: u8,
) -> (Ids, Vec<Arc<Node>>, Vec<u8>, pb::SignedIntent) {
    let (ids, nodes) = local(root, policy).await;
    let msg = digest(tag);
    let intent = intent_by(&ids, "driver", KEY, &msg, request);
    (ids, nodes, msg, intent)
}

/// The round-1 commitments of nodes 1 and 2 for `msg` under `session`, both presented with `intent`
/// and the signer set {1, 2}.
fn round1_of_nodes_1_and_2(
    nodes: &[Arc<Node>],
    session: &str,
    msg: &[u8],
    intent: &pb::SignedIntent,
) -> BTreeMap<Identifier, SigningCommitments> {
    let ctx = Round1Ctx {
        message: Some(msg.to_vec()),
        signers: Some(vec![1, 2]),
        intent: Some(intent.clone()),
        ..Default::default()
    };
    BTreeMap::from([
        (
            Identifier::try_from(1u16).unwrap(),
            nodes[0].sign_round1(KEY, session, &ctx).unwrap(),
        ),
        (
            Identifier::try_from(2u16).unwrap(),
            nodes[1].sign_round1(KEY, session, &ctx).unwrap(),
        ),
    ])
}

fn peers_of(nodes: &[Arc<Node>]) -> Peers {
    nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>)
        .collect()
}

/// One request id is one charge, whatever the retries: with a limit of ONE signature per minute,
/// a sign whose first t-subset fails in round 2 (so the leader releases a share twice, in two
/// sessions) still succeeds; the next request id is refused; and the charge survives a restart.
#[tokio::test]
async fn the_rate_limit_is_charged_once_per_request_id_across_retries_and_survives_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = rate_limited(1);
    let (ids, nodes, msg, i1) = local_with_driver_intent(tmp.path(), &policy, b"retried", 79).await;

    // Node 2 is this request's first partner (#193), so the flaky one fails the first subset.
    assert_eq!(
        rutli_cosigner::orchestrator::partner_offset(&[79; 16], 2),
        0
    );
    let mut peers = peers_of(&nodes);
    peers[1] = Arc::new(FlakyOnce {
        inner: peers[1].clone(),
        failed: Default::default(),
    });
    let sig = sign_with_intent(&nodes[0], &peers, KEY, &msg, Some(&i1))
        .await
        .unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &nodes[0].group_key(KEY).unwrap(),
        &msg,
        &sig
    ));
    let leader = read_key_dir(&tmp.path().join("node-1/journal").join(KEY))
        .unwrap()
        .entries;
    assert_eq!(
        leader.len(),
        2,
        "the leader released a share in both attempts"
    );
    assert!(leader
        .iter()
        .all(|e| e.request_id == hex::encode([79u8; 16])));

    // A replay of the same intent is not a new charge...
    sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i1))
        .await
        .unwrap();
    // ...a new request id is, and the minute's budget is spent.
    let i2 = intent_by(&ids, "driver", KEY, &msg, 71);
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i2))
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::RateLimited(_)), "{err:?}");
    assert_eq!(nodes[0].pending_sign_count(KEY), 0);

    // Restart every node (new process: guards and journals reopened over the same directories).
    drop(peers);
    drop(nodes);
    let nodes: Vec<Arc<Node>> = (1..=N)
        .map(|i| open_node(tmp.path(), &ids, i, &policy))
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i2))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::RateLimited(_)),
        "the charge survived the restart: {err:?}"
    );
    sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i1))
        .await
        .unwrap();
}

/// The per-request share cap: a valid intent replayed by a compromised leader buys only
/// `max_shares_per_request` shares from an honest node.
#[tokio::test]
async fn a_replayed_intent_is_capped_per_request() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ids, nodes, msg, i1) =
        local_with_driver_intent(tmp.path(), &capped_at_two_shares(), b"replayed", 72).await;
    let pair: Peers = peers_of(&nodes).into_iter().take(2).collect();
    sign_with_intent(&nodes[0], &pair, KEY, &msg, Some(&i1))
        .await
        .unwrap();
    sign_with_intent(&nodes[0], &pair, KEY, &msg, Some(&i1))
        .await
        .unwrap();
    let err = sign_with_intent(&nodes[0], &pair, KEY, &msg, Some(&i1))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::RateLimited(ref m) if m.contains("max_shares_per_request")),
        "{err:?}"
    );
}

/// A driver that fails over presents the same intent to each leader in turn (one per attempt
/// deadline). The share cap is per node and per request id, so however many leaders it tries, no
/// node releases more than `max_shares_per_request` shares for that request.
#[tokio::test]
async fn failing_over_across_leaders_under_one_intent_stays_within_the_share_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ids, nodes, msg, i1) =
        local_with_driver_intent(tmp.path(), &capped_at_two_shares(), b"failed over", 90).await;
    let all = peers_of(&nodes);
    let pair = |a: usize, b: usize| -> Peers { vec![all[a].clone(), all[b].clone()] };
    // Each leader signs with itself and the next node: two shares per node in all.
    for (lead, other) in [(0, 1), (1, 2), (2, 0)] {
        sign_with_intent(&nodes[lead], &pair(lead, other), KEY, &msg, Some(&i1))
            .await
            .unwrap();
    }
    // Any further attempt under the same intent finds its nodes at the cap.
    for (lead, other) in [(0, 1), (1, 2), (2, 0)] {
        let err = sign_with_intent(&nodes[lead], &pair(lead, other), KEY, &msg, Some(&i1))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DaemonError::RateLimited(ref m) if m.contains("max_shares_per_request")),
            "{err:?}"
        );
    }
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
    sign_with_intent(
        &nodes[0],
        &peers_of(&nodes),
        KEY,
        &msg,
        Some(&intent_by(&ids, "driver", KEY, &msg, 80)),
    )
    .await
    .unwrap();
    let seg = rutli_cosigner::journal::segments(&tmp.path().join("node-1/journal").join(KEY))
        .unwrap()
        .pop()
        .unwrap();
    std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o400)).unwrap();

    let markers = |i: u16| {
        std::fs::read_dir(tmp.path().join(format!("node-{i}/keys/{KEY}.nonces")))
            .unwrap()
            .count()
    };
    let before = markers(1);
    let i2 = intent_by(&ids, "driver", KEY, &msg, 81);
    let cs = round1_of_nodes_1_and_2(&nodes, "no-journal", &msg, &i2);
    let err = nodes[0]
        .sign_round2_with(
            KEY,
            "no-journal",
            &msg,
            &cs,
            Some(intent::intent_digest(&i2)),
        )
        .unwrap_err();
    // A definite I/O error (EACCES) in round-2 store work: the node marks its key store down at
    // once and answers `keystore-down`, so leaders route around it.
    assert!(matches!(err, DaemonError::KeystoreDown(_)), "{err:?}");
    assert!(nodes[0].keystore_health().is_down());
    assert_eq!(
        markers(1),
        before,
        "no marker burned for a share that was not journaled"
    );
    std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Not sticky: the next readiness probe that finds the store working clears it.
    nodes[0].check_keystore().unwrap();
    assert!(!nodes[0].keystore_health().is_down());
}

/// A node that restarted between the two rounds holds neither the session's nonces nor its
/// round-1 authorization. Its round 2 is an unknown session (gRPC `ABORTED`, counted), as on a
/// node without a signing policy, and not a policy refusal: a leader left with a refusal and no
/// other subset would tell the client its request was refused. With intents required and with
/// intents only verified when present.
#[tokio::test]
async fn a_round2_after_a_restart_is_an_unknown_session_not_a_policy_refusal() {
    for policy in [strict(), SigningPolicyConfig::default()] {
        let tmp = tempfile::tempdir().unwrap();
        let (ids, nodes) = local(tmp.path(), &policy).await;
        let msg = digest(b"restart between the rounds");
        let i1 = intent_by(&ids, "driver", KEY, &msg, 85);
        let cs = round1_of_nodes_1_and_2(&nodes, "restarted", &msg, &i1);
        let markers = || {
            std::fs::read_dir(tmp.path().join(format!("node-1/keys/{KEY}.nonces")))
                .map_or(0, std::iter::Iterator::count)
        };
        let journaled = || {
            read_key_dir(&tmp.path().join("node-1/journal").join(KEY))
                .map_or(0, |r| r.entries.len())
        };
        let (burned, entries) = (markers(), journaled());

        // Restart every node (new process: guards and journals reopened over the same directories).
        drop(nodes);
        let nodes: Vec<Arc<Node>> = (1..=N)
            .map(|i| open_node(tmp.path(), &ids, i, &policy))
            .collect();
        rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let err = metrics::with_local_recorder(&recorder, || {
            nodes[0]
                .sign_round2_with(
                    KEY,
                    "restarted",
                    &msg,
                    &cs,
                    Some(intent::intent_digest(&i1)),
                )
                .unwrap_err()
        });
        assert!(
            matches!(
                err,
                DaemonError::Core(rutli_frost_core::CoreError::UnknownSession(_))
            ),
            "{err:?}"
        );
        assert_eq!(tonic::Status::from(err).code(), tonic::Code::Aborted);
        let out = handle.render();
        assert!(
            out.lines()
                .any(|l| l == "rutli_sign_round2_unknown_session_total 1"),
            "{out}"
        );
        assert!(
            !out.contains("rutli_sign_policy_refusals_total"),
            "not counted as a policy refusal:\n{out}"
        );
        assert_eq!(
            (markers(), journaled()),
            (burned, entries),
            "nothing burned, nothing journaled"
        );

        // The request itself is fine: a new session signs it.
        let sig = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i1))
            .await
            .unwrap();
        assert!(rutli_cosigner::verify_key::signature_verifies(
            &nodes[0].group_key(KEY).unwrap(),
            &msg,
            &sig
        ));
    }
}

/// The other half: a session whose nonces this node still holds, but whose round-1 authorization
/// is gone, stays a policy refusal when intents are required. The nonces are dropped and no share
/// leaves, however the authorization was lost.
#[tokio::test]
async fn a_round2_without_its_round1_authorization_is_refused_while_the_nonces_are_held() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ids, nodes, msg, i1) =
        local_with_driver_intent(tmp.path(), &strict(), b"authorization lost", 86).await;
    let cs = round1_of_nodes_1_and_2(&nodes, "no-auth", &msg, &i1);
    let markers = || {
        std::fs::read_dir(tmp.path().join(format!("node-1/keys/{KEY}.nonces")))
            .map_or(0, std::iter::Iterator::count)
    };
    let burned = markers();
    // Lose the authorization (as a restart or a poisoned map would), keep the nonces.
    let owner = rutli_cosigner::node::SessionOwner::Local;
    assert!(nodes[0]
        .sign_guard()
        .unwrap()
        .take_as(KEY, "no-auth", &owner)
        .unwrap()
        .is_some());
    assert_eq!(nodes[0].pending_sign_count(KEY), 1);

    let err = nodes[0]
        .sign_round2_with(KEY, "no-auth", &msg, &cs, Some(intent::intent_digest(&i1)))
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::PolicyRefused(ref m) if m.contains("no round-1 authorization")),
        "{err:?}"
    );
    assert_eq!(
        nodes[0].pending_sign_count(KEY),
        0,
        "the nonces are dropped"
    );
    assert_eq!(markers(), burned);
    // And the session is gone for good: a second try finds nothing to sign with.
    let err = nodes[0]
        .sign_round2_with(KEY, "no-auth", &msg, &cs, Some(intent::intent_digest(&i1)))
        .unwrap_err();
    assert!(
        matches!(
            err,
            DaemonError::Core(rutli_frost_core::CoreError::UnknownSession(_))
        ),
        "{err:?}"
    );
    assert_eq!(markers(), burned);
}

/// The nonces are gone and the authorization is still here: a refresh committed between the two
/// rounds (the cosigner is loaded again with the new share, the policy's session map is not
/// touched). No share can leave, so the round 2 is an unknown session whatever the policy would
/// say about the authorization by now: here its intent has expired meanwhile.
#[tokio::test]
async fn a_round2_after_a_commit_is_an_unknown_session_even_with_a_lapsed_intent() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = SigningPolicyConfig {
        clock_skew_secs: 0,
        require_ceremony_intent: Some(false),
        ..strict()
    };
    let (ids, nodes) = local(tmp.path(), &policy).await;
    let msg = digest(b"commit between the rounds");
    let not_after = now_ms() + 2_000;
    let i1 = sign(
        &ids,
        "driver",
        unsigned(KEY, &msg, 87, not_after - 60_000, not_after),
    );
    let cs = round1_of_nodes_1_and_2(&nodes, "committed", &msg, &i1);
    assert_eq!(nodes[0].pending_sign_count(KEY), 1);

    rutli_cosigner::orchestrator::run_refresh(&peers_of(&nodes), KEY)
        .await
        .unwrap();
    assert_eq!(
        nodes[0].pending_sign_count(KEY),
        0,
        "the commit dropped the cosigner that held the nonces"
    );
    while now_ms() <= not_after {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let err = metrics::with_local_recorder(&recorder, || {
        nodes[0]
            .sign_round2_with(
                KEY,
                "committed",
                &msg,
                &cs,
                Some(intent::intent_digest(&i1)),
            )
            .unwrap_err()
    });
    assert!(
        matches!(
            err,
            DaemonError::Core(rutli_frost_core::CoreError::UnknownSession(_))
        ),
        "{err:?}"
    );
    let out = handle.render();
    assert!(
        out.lines()
            .any(|l| l == "rutli_sign_round2_unknown_session_total 1"),
        "{out}"
    );
    assert!(
        !out.contains("rutli_sign_policy_refusals_total"),
        "not counted as a policy refusal:\n{out}"
    );
    assert!(
        !nodes[0].sign_guard().unwrap().holds(KEY, "committed"),
        "the authorization was taken"
    );
}

/// A round 2 that arrives after the session was aborted (a leader that gave up on this node and
/// whose round 2 was still on its way) is an unknown session too, not a policy refusal.
#[tokio::test]
async fn a_round2_after_an_abort_is_an_unknown_session() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ids, nodes, msg, i1) =
        local_with_driver_intent(tmp.path(), &strict(), b"aborted", 88).await;
    let cs = round1_of_nodes_1_and_2(&nodes, "aborted", &msg, &i1);
    nodes[0]
        .abort_sign_as(KEY, "aborted", &rutli_cosigner::node::SessionOwner::Local)
        .unwrap();
    assert_eq!(nodes[0].pending_sign_count(KEY), 0);
    assert!(
        !nodes[0].sign_guard().unwrap().holds(KEY, "aborted"),
        "the abort forgot the authorization"
    );

    let err = nodes[0]
        .sign_round2_with(KEY, "aborted", &msg, &cs, Some(intent::intent_digest(&i1)))
        .unwrap_err();
    assert!(
        matches!(
            err,
            DaemonError::Core(rutli_frost_core::CoreError::UnknownSession(_))
        ),
        "{err:?}"
    );
    assert!(read_key_dir(&tmp.path().join("node-1/journal").join(KEY))
        .map_or(true, |r| r.entries.is_empty()));
}

/// The opt-out: with `require_intent: false`, a driver (or leader) that predates intents
/// still signs; each node journals it as `no-intent` and counts it. An intent that is present is
/// still verified in full.
#[tokio::test]
async fn verify_if_present_accepts_an_old_driver_with_a_metric_and_still_checks_a_present_intent() {
    let tmp = tempfile::tempdir().unwrap();
    let opt_out = SigningPolicyConfig {
        require_intent: Some(false),
        ..Default::default()
    };
    let (ids, nodes) = local(tmp.path(), &opt_out).await;
    let msg = digest(b"old driver");
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || {
        let ctx = Round1Ctx {
            message: Some(msg.clone()),
            signers: Some(vec![1, 2]),
            ..Default::default()
        };
        let cs = BTreeMap::from([
            (
                Identifier::try_from(1u16).unwrap(),
                nodes[0].sign_round1(KEY, "old", &ctx).unwrap(),
            ),
            (
                Identifier::try_from(2u16).unwrap(),
                nodes[1].sign_round1(KEY, "old", &ctx).unwrap(),
            ),
        ]);
        nodes[0].sign_round2(KEY, "old", &msg, &cs).unwrap();
    });
    // One per node that took part in round 1.
    assert!(
        handle.render().contains("rutli_sign_intent_absent_total 2"),
        "{}",
        handle.render()
    );
    let e = &read_key_dir(&tmp.path().join("node-1/journal").join(KEY))
        .unwrap()
        .entries[0];
    assert_eq!(
        (e.purpose.as_str(), e.request_id.as_str()),
        ("no-intent", "")
    );

    // The whole sign path, no intent: works.
    let sig = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, None)
        .await
        .unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &nodes[0].group_key(KEY).unwrap(),
        &msg,
        &sig
    ));
    // A present intent that is invalid is refused even in this mode.
    let long_ago = now_ms() - 3_600_000;
    let expired = sign(
        &ids,
        "driver",
        unsigned(KEY, &msg, 90, long_ago, long_ago + 60_000),
    );
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&expired))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DaemonError::PolicyRefused(ref m) if m.contains("expired")),
        "{err:?}"
    );
}

/// A sign-test round (no intent) is accepted only for the node's own test digest of the key: a
/// compromised node cannot dress an arbitrary digest up as a ceremony test.
#[tokio::test]
async fn a_sign_test_round_for_another_message_is_refused_at_the_peer() {
    let c = cluster(|_| strict(), None).await;
    let mut req = round1(KEY, "fake-test", Some(&digest(b"anything")), None);
    req.purpose = "sign-test".into();
    let s = c
        .peer_as("cosigner3", 0)
        .await
        .sign_round1(req)
        .await
        .unwrap_err();
    // A DKG key has no split-ceremony provenance, so there is no test digest at all.
    assert!(
        s.code() == tonic::Code::FailedPrecondition || s.code() == tonic::Code::PermissionDenied,
        "{s:?}"
    );
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
    // The replay below is a second refresh right after the first: no refresh interval here
    // (`a_refresh_inside_the_interval_is_refused_at_the_leader_over_grpc` covers it).
    let policy = SigningPolicyConfig {
        require_ceremony_intent: Some(true),
        signer_may_refresh: false,
        refresh_min_interval_secs: 0,
        ..Default::default()
    };
    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    let group = c.group_key().to_vec();
    let refresh = |intent| pb::RefreshRequest {
        key_id: KEY.into(),
        intent,
    };

    denied(
        c.signer("refresher", 0).await.refresh(refresh(None)).await,
        "carries no ceremony intent",
    );
    // A signer-role refresh intent (tenant), presented by the refresher: refused on its own merits
    // (signer_may_refresh off) before the caller check would refuse it.
    denied(
        c.signer("refresher", 0)
            .await
            .refresh(refresh(Some(ceremony_by(
                &c.ids, "tenant", Refresh, KEY, 1,
            ))))
            .await,
        "signer_may_refresh is off",
    );
    let before = c.nodes[0].key_epoch(KEY).unwrap().epoch;
    let signed = ceremony_by(&c.ids, "refresher", Refresh, KEY, 2);
    let reply = c
        .signer("refresher", 1)
        .await
        .refresh(refresh(Some(signed.clone())))
        .await
        .unwrap();
    assert_eq!(reply.into_inner().group_verifying_key, group);
    for n in &c.nodes {
        assert_eq!(n.key_epoch(KEY).unwrap().epoch, before + 1);
        assert!(n
            .ceremony_record(&intent::ceremony_id_for(Refresh, &[2; 16]))
            .is_some());
    }
    // The very same signed intent again (byte for byte), through another leader: one intent, one
    // ceremony.
    let again = c
        .signer("refresher", 2)
        .await
        .refresh(refresh(Some(signed)))
        .await;
    assert!(
        again
            .as_ref()
            .is_err_and(|s| s.message().contains("already used")),
        "{again:?}"
    );

    // DKG: the driver's own intent runs it; tenant's intent on the driver's connection is refused.
    let key = "frost-participant1-second";
    let dkg = |intent| pb::DkgRequest {
        key_id: key.into(),
        intent,
    };
    denied(
        c.signer("driver", 0).await.dkg(dkg(None)).await,
        "carries no ceremony intent",
    );
    denied(
        c.signer("driver", 0)
            .await
            .dkg(dkg(Some(ceremony_by(&c.ids, "tenant", Dkg, key, 3))))
            .await,
        "only valid on its signer's own connection",
    );
    c.signer("driver", 0)
        .await
        .dkg(dkg(Some(ceremony_by(&c.ids, "driver", Dkg, key, 4))))
        .await
        .unwrap();
    assert!(c.nodes[2].key_epoch(key).unwrap().present);
}

/// The refresh interval over mTLS: a second refresh is refused whichever node the client calls —
/// FAILED_PRECONDITION with the `rutli-error: refresh-too-soon` trailer — and when the leader
/// itself has no interval (a node on 0.4.0, or one whose config was changed), an honest peer's
/// refusal at its fence comes back to the client the same way. No node moves.
#[tokio::test]
async fn a_refresh_inside_the_interval_is_refused_at_the_leader_over_grpc() {
    use rutli_cosigner::node::CeremonyKind::Refresh;
    let policy = SigningPolicyConfig {
        require_ceremony_intent: Some(true),
        signer_may_refresh: false,
        ..Default::default()
    };
    let refresh = |intent| pb::RefreshRequest {
        key_id: KEY.into(),
        intent,
    };
    #[track_caller]
    fn too_soon(r: std::result::Result<impl std::fmt::Debug, tonic::Status>) -> tonic::Status {
        let err = r.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err:?}");
        assert_eq!(
            err.metadata()
                .get("rutli-error")
                .and_then(|v| v.to_str().ok()),
            Some("refresh-too-soon"),
            "{err:?}"
        );
        assert!(
            err.message().contains("refresh_min_interval_secs"),
            "{err:?}"
        );
        err
    }

    let c = cluster(|_| policy.clone(), Some(vec!["refresher".into()])).await;
    c.signer("refresher", 0)
        .await
        .refresh(refresh(Some(ceremony_by(
            &c.ids,
            "refresher",
            Refresh,
            KEY,
            1,
        ))))
        .await
        .unwrap();
    let epoch = c.nodes[0].key_epoch(KEY).unwrap().epoch;
    for leader in 0..N as usize {
        let x = ceremony_by(&c.ids, "refresher", Refresh, KEY, 2 + leader as u8);
        too_soon(
            c.signer("refresher", leader)
                .await
                .refresh(refresh(Some(x)))
                .await,
        );
    }
    for n in &c.nodes {
        assert_eq!(n.key_epoch(KEY).unwrap().epoch, epoch);
        assert_eq!(
            n.staged_records(),
            [] as [rutli_cosigner::ceremony_record::CeremonyRecord; 0]
        );
    }

    // Node 1 (endpoint 0) without the interval leads: its own pre-check and fence pass, and node 2,
    // the first peer it fences, refuses over the mesh; the refusal names node 2.
    let no_interval = SigningPolicyConfig {
        refresh_min_interval_secs: 0,
        ..policy.clone()
    };
    let c = cluster(
        |i| {
            if i == 1 {
                no_interval.clone()
            } else {
                policy.clone()
            }
        },
        Some(vec!["refresher".into()]),
    )
    .await;
    c.signer("refresher", 1)
        .await
        .refresh(refresh(Some(ceremony_by(
            &c.ids,
            "refresher",
            Refresh,
            KEY,
            1,
        ))))
        .await
        .unwrap();
    let epoch = c.nodes[0].key_epoch(KEY).unwrap().epoch;
    let err = too_soon(
        c.signer("refresher", 0)
            .await
            .refresh(refresh(Some(ceremony_by(
                &c.ids,
                "refresher",
                Refresh,
                KEY,
                2,
            ))))
            .await,
    );
    assert!(
        err.message().contains("refused by node 2"),
        "the refusal comes from a peer's fence: {err:?}"
    );
    for n in &c.nodes {
        assert_eq!(n.key_epoch(KEY).unwrap().epoch, epoch);
        assert_eq!(
            n.staged_records(),
            [] as [rutli_cosigner::ceremony_record::CeremonyRecord; 0]
        );
    }
}

/// A compromised cosigner on the mesh: a DKG/refresh fence or part 1 without a valid client intent
/// is refused by an enforcing honest node (PERMISSION_DENIED); an intent on a hosted-key fence is a
/// protocol error.
#[tokio::test]
async fn a_cosigner_cannot_fence_an_honest_peer_without_a_client_intent() {
    let policy = SigningPolicyConfig {
        require_ceremony_intent: Some(true),
        ..Default::default()
    };
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
        ..Default::default()
    };
    denied(
        attacker
            .ceremony_fence(fence(None, "refresh-attacker"))
            .await,
        "carries no ceremony intent",
    );
    // Its own certificate cannot sign one either.
    let own = ceremony_by(
        &c.ids,
        "cosigner3",
        rutli_cosigner::node::CeremonyKind::Refresh,
        KEY,
        5,
    );
    denied(
        attacker
            .ceremony_fence(fence(
                Some(own.clone()),
                &intent::ceremony_id_for(rutli_cosigner::node::CeremonyKind::Refresh, &[5; 16]),
            ))
            .await,
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
    // Since 0.5.0 a genkey fence carries a generate intent, verified like any other: a cosigner's
    // own certificate is on no signer role.
    assert_eq!(hosted.code(), tonic::Code::PermissionDenied, "{hosted:?}");
    // Nothing was fenced: the refresher's real refresh runs at once.
    let ok = ceremony_by(
        &c.ids,
        "refresher",
        rutli_cosigner::node::CeremonyKind::Refresh,
        KEY,
        6,
    );
    c.signer("refresher", 0)
        .await
        .refresh(pb::RefreshRequest {
            key_id: KEY.into(),
            intent: Some(ok),
        })
        .await
        .unwrap();
}

/// Over the mesh the leader is the fencing caller's certificate CN: a fenced peer that presents the
/// client's intent it was shown cannot run part 1 (or 2, 3) on a node another cosigner fenced.
#[tokio::test]
async fn only_the_fencing_cosigner_runs_parts_over_grpc() {
    use rutli_cosigner::node::CeremonyKind::Refresh;
    let policy = SigningPolicyConfig {
        require_ceremony_intent: Some(true),
        ..Default::default()
    };
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
            ..Default::default()
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
    let stolen = c
        .peer_as("cosigner3", 1)
        .await
        .ceremony_part1(part1())
        .await
        .unwrap_err();
    assert_eq!(stolen.code(), tonic::Code::FailedPrecondition, "{stolen:?}");
    assert!(
        stolen.message().contains("led by peer \"cosigner1\""),
        "{stolen:?}"
    );
    let part3 = c
        .peer_as("cosigner3", 1)
        .await
        .ceremony_part3(pb::CeremonyPart3Request {
            ceremony_id: xid.clone(),
            round1_digest: vec![0; 32],
        })
        .await
        .unwrap_err();
    assert_eq!(
        part3.code(),
        tonic::Code::NotFound,
        "no session yet: {part3:?}"
    );
    // The fencing cosigner's part 1 runs.
    c.peer_as("cosigner1", 1)
        .await
        .ceremony_part1(part1())
        .await
        .unwrap();
    let part3 = c
        .peer_as("cosigner3", 1)
        .await
        .ceremony_part3(pb::CeremonyPart3Request {
            ceremony_id: xid.clone(),
            round1_digest: vec![0; 32],
        })
        .await
        .unwrap_err();
    assert!(
        part3.message().contains("led by peer \"cosigner1\""),
        "{part3:?}"
    );
    // The refusal left the session alone: the leader can still abort it as its own.
    assert!(
        c.nodes[1].ceremony_record(&xid).is_none(),
        "nothing recorded by the refused part 3"
    );
}

// ── the operator role ─────────────────────────────────────────────────────────────────────────

/// The operator certificate (CN on `operator_allowlist` only) is what `key show`, `verify-key` and
/// `verify-hosted` run with. Over real mTLS it reaches the three operator RPCs (`KeyStatus`,
/// `HostedKeyStatus`, `CeremonySignTest`) and the two open ones (`Health`, `Capabilities`); every
/// other Signer RPC answers PERMISSION_DENIED, even carrying the driver's own valid intents. Every
/// `rpc` of `service Signer` in the proto must be classified here, so a new RPC cannot slip past
/// this test unclassified.
#[tokio::test]
async fn the_operator_certificate_reaches_only_the_operator_rpcs_and_every_signer_rpc_is_classified(
) {
    use rutli_cosigner::node::CeremonyKind;
    const OPEN: [&str; 2] = ["Health", "Capabilities"];
    const OPERATOR: [&str; 3] = ["KeyStatus", "HostedKeyStatus", "CeremonySignTest"];

    let c = cluster(|_| strict(), Some(vec!["refresher".into()])).await;
    let mut op = c.signer("operator", 0).await;
    let key = || KEY.to_string();
    let msg = digest(b"the operator tries to sign");
    let sign = pb::SignRequest {
        key_id: key(),
        message: msg.clone(),
        intent: Some(intent_by(&c.ids, "driver", KEY, &msg, 40)),
    };
    let dkg_id = "frost-participant1-new";
    let dkg = pb::DkgRequest {
        key_id: dkg_id.into(),
        intent: Some(ceremony_by(
            &c.ids,
            "driver",
            CeremonyKind::Dkg,
            dkg_id,
            0x41,
        )),
    };
    let refresh = pb::RefreshRequest {
        key_id: key(),
        intent: Some(ceremony_by(
            &c.ids,
            "driver",
            CeremonyKind::Refresh,
            KEY,
            0x42,
        )),
    };
    let hosted = || "rutli-enc-1".to_string();
    let calls: Vec<(&str, std::result::Result<(), tonic::Status>)> = vec![
        ("Health", op.health(pb::HealthRequest {}).await.map(drop)),
        (
            "Capabilities",
            op.capabilities(pb::CapabilitiesRequest {}).await.map(drop),
        ),
        (
            "KeyStatus",
            op.key_status(pb::KeyStatusRequest { key_id: key() })
                .await
                .map(drop),
        ),
        (
            "HostedKeyStatus",
            op.hosted_key_status(pb::HostedKeyStatusRequest { key_id: hosted() })
                .await
                .map(drop),
        ),
        (
            "CeremonySignTest",
            op.ceremony_sign_test(pb::CeremonySignTestRequest {
                key_id: key(),
                signers: vec![1, 2],
                ..Default::default()
            })
            .await
            .map(drop),
        ),
        (
            "GroupKey",
            op.group_key(pb::GroupKeyRequest { key_id: key() })
                .await
                .map(drop),
        ),
        ("Dkg", op.dkg(dkg).await.map(drop)),
        ("Sign", op.sign(sign).await.map(drop)),
        ("Refresh", op.refresh(refresh).await.map(drop)),
        (
            "GenerateKey",
            op.generate_key(pb::GenerateKeyRequest {
                key_id: hosted(),
                spec: "ec-p256-ecies".into(),
                ..Default::default()
            })
            .await
            .map(drop),
        ),
        (
            "PublicKey",
            op.public_key(pb::PublicKeyRequest { key_id: hosted() })
                .await
                .map(drop),
        ),
        (
            "KeyInfo",
            op.key_info(pb::KeyInfoRequest {
                key_id: hosted(),
                ..Default::default()
            })
            .await
            .map(drop),
        ),
        // Refused for every client here (no delete_allowlist on this cluster) — the operator too.
        (
            "DeleteKey",
            op.delete_key(pb::DeleteKeyRequest {
                key_id: hosted(),
                intent: None,
            })
            .await
            .map(drop),
        ),
        (
            "Decrypt",
            op.decrypt(pb::DecryptRequest {
                key_id: hosted(),
                ciphertext: vec![0; 256],
            })
            .await
            .map(drop),
        ),
        (
            "EcdhDerive",
            op.ecdh_derive(pb::EcdhDeriveRequest {
                key_id: hosted(),
                peer_point: vec![4; 65],
            })
            .await
            .map(drop),
        ),
        (
            "SymmetricEncrypt",
            op.symmetric_encrypt(pb::SymmetricRequest {
                key_id: hosted(),
                data: vec![1],
            })
            .await
            .map(drop),
        ),
        (
            "SymmetricDecrypt",
            op.symmetric_decrypt(pb::SymmetricRequest {
                key_id: hosted(),
                data: vec![1],
            })
            .await
            .map(drop),
        ),
    ];

    // Every rpc of `service Signer`, from the proto itself, is called above exactly once.
    let proto_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proto");
    let mut in_proto = Vec::new();
    for entry in std::fs::read_dir(&proto_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "proto") {
            let text = std::fs::read_to_string(&path).unwrap();
            let mut lines = text
                .lines()
                .map(str::trim)
                .skip_while(|l| !l.starts_with("service Signer {"));
            assert!(
                lines.next().is_none_or(|l| l == "service Signer {"),
                "{}",
                path.display()
            );
            for line in lines.take_while(|l| *l != "}") {
                if let Some(rest) = line.strip_prefix("rpc ") {
                    in_proto.push(rest.split('(').next().unwrap().trim().to_string());
                }
            }
        }
    }
    let called: Vec<String> = calls.iter().map(|(name, _)| name.to_string()).collect();
    let (mut proto_sorted, mut called_sorted) = (in_proto.clone(), called.clone());
    proto_sorted.sort();
    called_sorted.sort();
    assert_eq!(
        proto_sorted, called_sorted,
        "every Signer rpc must be classified by this test"
    );
    assert_eq!(
        in_proto.len(),
        17,
        "service Signer changed: classify the new rpc here deliberately"
    );

    for (name, result) in &calls {
        if OPEN.contains(name) {
            assert!(result.is_ok(), "{name} is open to everyone: {result:?}");
        } else if OPERATOR.contains(name) {
            assert!(
                result
                    .as_ref()
                    .err()
                    .is_none_or(|s| s.code() != tonic::Code::PermissionDenied),
                "{name} must be open to the operator: {result:?}"
            );
        } else {
            let s = result.as_ref().expect_err(name);
            assert_eq!(s.code(), tonic::Code::PermissionDenied, "{name}: {s:?}");
        }
    }
    // The operator RPCs got past authorization and did their own work: the key's status; the
    // hosted-key status of a node without hosted keys; the sign test's refusal of a DKG key (no
    // split-ceremony provenance), from the leader, before any peer is asked.
    let status = c
        .signer("operator", 1)
        .await
        .key_status(pb::KeyStatusRequest { key_id: key() })
        .await
        .unwrap();
    assert_eq!(
        status.into_inner().group_verifying_key,
        c.group_key().to_vec()
    );
    let code_of = |name: &str| {
        calls
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1
            .as_ref()
            .err()
            .map(tonic::Status::code)
    };
    assert_eq!(code_of("KeyStatus"), None);
    assert_eq!(
        code_of("HostedKeyStatus"),
        Some(tonic::Code::FailedPrecondition)
    );
    let sign_test = calls
        .iter()
        .find(|(n, _)| *n == "CeremonySignTest")
        .unwrap()
        .1
        .as_ref()
        .unwrap_err();
    assert!(
        sign_test.code() == tonic::Code::FailedPrecondition
            && sign_test.message().contains("split-ceremony"),
        "{sign_test:?}"
    );
    // Nothing the operator asked for happened: no new key, no signature journaled, same epoch.
    assert!(!c.nodes[0].has_key(dkg_id));
    assert!((0..3).all(|i| c.journal(i).is_empty()));
    assert!(c.nodes.iter().all(|n| n.key_epoch(KEY).unwrap().epoch == 1));
}

// ── the key ACL on the status RPCs ────────────────────────────────────────────────────────────

const OTHER_KEY: &str = "frost-participant2-namespace";

/// `driver` may use `frost-participant1-…` (the cluster's `KEY`), `tenant` `frost-participant2-…`.
fn two_tenants() -> SigningPolicyConfig {
    SigningPolicyConfig {
        require_intent: Some(true),
        signer_acl_required: true,
        signer_acl: BTreeMap::from([
            (
                "driver".to_string(),
                vec!["frost-participant1-".to_string()],
            ),
            (
                "tenant".to_string(),
                vec!["frost-participant2-".to_string()],
            ),
        ]),
        ..Default::default()
    }
}

/// A `CeremonySignTest` request as a 0.5 `verify-key` sends it: with a 32-byte challenge, so the
/// version 2 path is the one checked.
fn sign_test_of(key_id: &str) -> pb::CeremonySignTestRequest {
    pb::CeremonySignTestRequest {
        key_id: key_id.into(),
        signers: vec![1, 2],
        challenge: vec![0x5a; 32],
    }
}

/// The three status RPCs for `key_id` as `who` at `node`, in the order `KeyStatus`,
/// `HostedKeyStatus`, `CeremonySignTest`: each call's gRPC status, `None` for OK.
async fn status_rpcs(
    c: &Cluster,
    who: &str,
    node: usize,
    key_id: &str,
) -> [Option<tonic::Status>; 3] {
    let mut client = c.signer(who, node).await;
    let key = || key_id.to_string();
    [
        client
            .key_status(pb::KeyStatusRequest { key_id: key() })
            .await
            .err(),
        client
            .hosted_key_status(pb::HostedKeyStatusRequest { key_id: key() })
            .await
            .err(),
        client.ceremony_sign_test(sign_test_of(key_id)).await.err(),
    ]
}

fn assert_refused_by_the_acl(who: &str, key_id: &str, results: &[Option<tonic::Status>; 3]) {
    for (rpc, result) in ["KeyStatus", "HostedKeyStatus", "CeremonySignTest"]
        .iter()
        .zip(results)
    {
        let status = result
            .as_ref()
            .unwrap_or_else(|| panic!("{rpc} of {key_id} answered {who}"));
        assert!(
            status.code() == tonic::Code::PermissionDenied
                && status.message().contains("signer_acl"),
            "{rpc} of {key_id} as {who}: {status:?}"
        );
    }
}

/// Past authorization, each RPC does its own work on this cluster: the status of a key that
/// exists; no hosted keys on these nodes; the sign test's refusal of a DKG key.
fn assert_past_authorization(who: &str, results: &[Option<tonic::Status>; 3]) {
    assert!(results[0].is_none(), "KeyStatus as {who}: {:?}", results[0]);
    for (rpc, result) in ["HostedKeyStatus", "CeremonySignTest"]
        .iter()
        .zip(&results[1..])
    {
        assert_eq!(
            result.as_ref().map(tonic::Status::code),
            Some(tonic::Code::FailedPrecondition),
            "{rpc} as {who}: {result:?}"
        );
    }
}

/// `KeyStatus`, `HostedKeyStatus` and `CeremonySignTest` hold a driver-role caller to its key ACL
/// at every node, as `Sign` does. The operator role reads every key and the refresher role keeps
/// `KeyStatus` for every key, as before.
#[tokio::test]
async fn a_driver_certificate_reaches_the_status_rpcs_only_for_keys_its_acl_covers() {
    let c = cluster(|_| two_tenants(), Some(vec!["refresher".into()])).await;
    for node in 0..N as usize {
        let results = status_rpcs(&c, "tenant", node, KEY).await;
        assert_refused_by_the_acl("tenant", KEY, &results);
    }
    assert_refused_by_the_acl(
        "driver",
        OTHER_KEY,
        &status_rpcs(&c, "driver", 0, OTHER_KEY).await,
    );

    // Its own keys: the driver's exists, the tenant's prefix holds none — an answer from the key
    // store (no such key; no hosted keys on these nodes), not from the ACL.
    assert_past_authorization("driver", &status_rpcs(&c, "driver", 1, KEY).await);
    let codes = status_rpcs(&c, "tenant", 2, OTHER_KEY)
        .await
        .map(|s| s.as_ref().map(tonic::Status::code));
    assert_eq!(
        codes,
        [
            Some(tonic::Code::NotFound),
            Some(tonic::Code::FailedPrecondition),
            Some(tonic::Code::NotFound)
        ]
    );

    // The operator role is not key-scoped; the refresher role has KeyStatus for every key.
    assert_past_authorization("operator", &status_rpcs(&c, "operator", 2, KEY).await);
    let status = c
        .signer("refresher", 0)
        .await
        .key_status(pb::KeyStatusRequest { key_id: KEY.into() })
        .await
        .unwrap();
    assert_eq!(
        status.into_inner().group_verifying_key,
        c.group_key().to_vec()
    );
}

/// The ACL is checked before the `CeremonySignTest` ceiling: calls it refuses take nothing from
/// the key's budget and leave no nonce marker or journal entry, so the key's own callers still
/// have the whole budget.
#[tokio::test]
async fn a_sign_test_the_acl_refuses_spends_no_budget_and_leaves_no_marker() {
    let c = cluster_serving(|_, _| two_tenants(), None, &["operator"], 1).await;
    let markers = |c: &Cluster| (0..N as usize).map(|i| c.markers(i)).collect::<Vec<_>>();
    let before = markers(&c);
    let sign_test = |who: &'static str| {
        let c = &c;
        async move {
            c.signer(who, 0)
                .await
                .ceremony_sign_test(sign_test_of(KEY))
                .await
                .unwrap_err()
        }
    };
    // More refusals than the budget of one a minute: none is the rate limiter's answer.
    for _ in 0..3 {
        let status = sign_test("tenant").await;
        assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
    }
    assert_eq!(markers(&c), before);
    assert!((0..3).all(|i| c.journal(i).is_empty()));

    // The budget is whole: the driver's first call gets past the limiter to the sign test's own
    // answer for a DKG key, and only its second is limited (the limiter is on).
    let first = sign_test("driver").await;
    assert!(
        first.code() == tonic::Code::FailedPrecondition
            && first.message().contains("split-ceremony"),
        "{first:?}"
    );
    let second = sign_test("driver").await;
    assert_eq!(second.code(), tonic::Code::ResourceExhausted, "{second:?}");
}

/// The status RPCs read `signer_acl_required` as the sign path does — a driver CN without an
/// entry reads every key while it is off and none once it is on — and a CN that is in the driver
/// role and in the operator or refresher role as well stays under its ACL.
#[tokio::test]
async fn the_status_rpcs_follow_signer_acl_required_and_the_driver_role_decides_for_a_cn_in_two_roles(
) {
    let only = |cn: &str, prefix: &str, required: bool| SigningPolicyConfig {
        require_intent: Some(true),
        signer_acl_required: required,
        signer_acl: BTreeMap::from([(cn.to_string(), vec![prefix.to_string()])]),
        ..Default::default()
    };

    // Not required: `driver` has no entry and reads the key. `tenant` has one, and is listed as
    // an operator and as a refresher too — it is still refused a key outside its prefix.
    let policy = only("tenant", "frost-participant2-", false);
    let c = cluster_serving(
        |_, _| policy.clone(),
        Some(vec!["refresher".into(), "tenant".into()]),
        &["operator", "tenant"],
        0,
    )
    .await;
    assert_past_authorization("driver", &status_rpcs(&c, "driver", 0, KEY).await);
    for node in 0..N as usize {
        let results = status_rpcs(&c, "tenant", node, KEY).await;
        assert_refused_by_the_acl("tenant", KEY, &results);
    }
    assert_past_authorization("operator", &status_rpcs(&c, "operator", 1, KEY).await);

    // Required: `tenant` has no entry and is refused every key, its own prefix included.
    let policy = only("driver", "frost-participant1-", true);
    let c = cluster(|_| policy.clone(), None).await;
    let results = status_rpcs(&c, "tenant", 0, OTHER_KEY).await;
    assert_refused_by_the_acl("tenant", OTHER_KEY, &results);
    assert!(results.iter().all(|s| s
        .as_ref()
        .unwrap()
        .message()
        .contains("signer_acl_required")));
    assert_past_authorization("driver", &status_rpcs(&c, "driver", 2, KEY).await);
}

/// Unset `require_intent` is on (with TLS, which every node here has): a round 1 without an
/// intent is refused before any nonce exists, so one cosigner's mesh certificate cannot get a
/// share over a digest no client asked for. The sign test is still accepted only for the node's
/// own test digest (covered above); a present intent signs as before.
#[tokio::test]
async fn by_default_a_sign_round_without_an_intent_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (ids, nodes) = local(tmp.path(), &SigningPolicyConfig::default()).await;
    assert!(nodes[1].sign_guard().unwrap().require_intent());
    let msg = digest(b"no intent, default policy");
    let ctx = Round1Ctx {
        message: Some(msg.clone()),
        signers: Some(vec![1, 2]),
        ..Default::default()
    };
    let err = nodes[1].sign_round1(KEY, "no-intent", &ctx).unwrap_err();
    assert!(
        matches!(err, DaemonError::PolicyRefused(ref m) if m.contains("no signing intent")),
        "{err:?}"
    );
    assert_eq!(nodes[1].pending_sign_count(KEY), 0);
    let err = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, None)
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::PolicyRefused(_)), "{err:?}");
    let i1 = intent_by(&ids, "driver", KEY, &msg, 86);
    let sig = sign_with_intent(&nodes[0], &peers_of(&nodes), KEY, &msg, Some(&i1))
        .await
        .unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(
        &nodes[0].group_key(KEY).unwrap(),
        &msg,
        &sig
    ));
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Zero-downtime cluster CA rotation over real mutual TLS (docs/ca-rotation.md).
//!
//! During the overlap every node's `tls.ca_cert` is a bundle of the old and the new CA, while the
//! leaves are swapped one node at a time — so for a while a node with an old-CA leaf talks to a
//! node with a new-CA leaf, in both directions. This proves, through the real
//! `rutli_cosigner::tls::load` path and a real tonic server on 127.0.0.1, that the bundle carries
//! both directions (tonic loads every certificate of the PEM as a trust anchor), and that dropping
//! the old CA from a node's trust file really does lock old-CA leaves out.
//!
//! The RPC is the mesh Peer API's `NodeInfo`, behind the cosigner-CN allowlist — so the
//! certificate-CN authorization still works for leaves of either CA.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use frost_ed25519::Identifier;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rutli_cosigner::config::TlsConfig;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::peer::{GrpcPeer, PeerApi};
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::service::PeerSvc;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

const MASTER: &[u8] = b"tls rotation test master secret";
/// The cluster id is pinned, so it is the same before, during and after the rotation.
const CLUSTER: &str = "453bb4aea2088bb5";
/// The server name node 1 is dialled under: its own (`PeerConfig::server_name`), never a shared one.
const NODE1: &str = "cosigner1";

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    /// A CA as `scripts/gen-frost-certs.sh` mints it; `cn` tells the two apart in a bundle.
    fn new(cn: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name.push(DnType::CommonName, cn);
        Self { cert: p.self_signed(&key).unwrap(), key }
    }

    /// A cosigner leaf: CN `cn` and the same name as its SAN (as gen-frost-certs.sh issues it: each
    /// node is dialled under its own name, audit M3), serverAuth + clientAuth.
    fn leaf(&self, cn: &str) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

/// A node's TLS files on disk: its leaf (`cn` from `issuer`) and a trust file holding `trust`, in
/// order (`cat old.crt new.crt` during the overlap).
fn tls_files(dir: &Path, name: &str, issuer: &Ca, cn: &str, trust: &[&Ca]) -> TlsConfig {
    let (cert, key) = issuer.leaf(cn);
    let bundle: String = trust.iter().map(|ca| ca.cert.pem()).collect::<Vec<_>>().join("");
    let (cert_path, key_path, ca_path) =
        (dir.join(format!("{name}.crt")), dir.join(format!("{name}.key")), dir.join(format!("{name}-ca.crt")));
    std::fs::write(&cert_path, cert).unwrap();
    std::fs::write(&key_path, key).unwrap();
    std::fs::write(&ca_path, bundle).unwrap();
    TlsConfig { ca_cert: ca_path, cert: cert_path, key: key_path, domain: None, allow_expired_ca: false }
}

/// Node 1 serves the Peer API with `server`'s TLS; node 2 dials it with `client`'s TLS and asks
/// `NodeInfo`. Returns the identifier node 1 reported, or the failure (its `Debug`, which carries
/// the TLS alert).
async fn node_info(dir: &Path, server: &TlsConfig, client: &TlsConfig) -> Result<u16, String> {
    let (endpoint, serving) = serve(dir, server).await;
    let client_tls = rutli_cosigner::tls::load(client).unwrap();
    // Node 1 dialled under its own name, as the daemon dials every peer (M3).
    let peer = GrpcPeer::connect_lazy(
        Identifier::try_from(1u16).unwrap(),
        &endpoint,
        Some(client_tls.client_for(NODE1)),
    )
    .unwrap();
    let result = peer.node_info().await.map(|(id, _)| id).map_err(|e| format!("{e:?}"));
    serving.abort();
    result
}

/// Node 1 serving the Peer API with `server`'s TLS on 127.0.0.1: its endpoint, and the task to
/// abort.
async fn serve(dir: &Path, server: &TlsConfig) -> (String, tokio::task::JoinHandle<()>) {
    let sealer = Arc::new(Sealer::from_master_secret(MASTER, 1));
    let ks = KeyStore::open_with_sealer(dir.join("node-1"), Some(sealer)).unwrap();
    let node = Arc::new(
        Node::new(Identifier::try_from(1u16).unwrap(), 3, 2, ks)
            .with_hosted_keys(MASTER, CLUSTER.to_string())
            .unwrap(),
    );
    let peer_cns: Arc<HashSet<String>> = Arc::new((1..=3).map(|i| format!("cosigner{i}")).collect());
    let peer_ids = Arc::new((1..=3u16).map(|i| (format!("cosigner{i}"), i)).collect());
    let svc = PeerSvc { node, allowed_cns: Some(peer_cns), peer_ids: Some(peer_ids) };

    let server_tls = rutli_cosigner::tls::load(server).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let serving = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .tls_config(server_tls.server)
            .unwrap()
            .add_service(PeerServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
    (endpoint, serving)
}

/// `verify-key`'s TLS probe (Phase D's negative control): the node's refusal is reported every
/// time, with no race against a request (there is none), and a node that accepts the client — or
/// is not there — yields nothing.
#[tokio::test]
async fn the_tls_probe_reports_how_a_node_refuses_a_client_and_nothing_otherwise() {
    use rutli_cosigner::tls_probe::TlsProbe;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let (old, new) = (Ca::new("old-ca"), Ca::new("new-ca"));
    // Phase D: the node trusts only the new CA.
    let s = tls_files(dir, "s", &new, "cosigner1", &[&new]);
    let (endpoint, serving) = serve(dir, &s).await;

    let old_client = TlsProbe::new(&tls_files(dir, "c-old", &old, "operator", &[&old, &new])).unwrap();
    for _ in 0..20 {
        let r = old_client.refusal_as(&endpoint, NODE1).await;
        assert!(r.as_deref().is_some_and(|r| r.contains("received fatal alert: UnknownCA")), "{r:?}");
    }
    let new_client = TlsProbe::new(&tls_files(dir, "c-new", &new, "operator", &[&old, &new])).unwrap();
    assert_eq!(new_client.refusal_as(&endpoint, NODE1).await, None, "an accepted client is not refused");
    // The client side refusing the node (it trusts only the old CA) is a handshake failure.
    let old_trust = TlsProbe::new(&tls_files(dir, "c-oldtrust", &old, "operator", &[&old])).unwrap();
    let r = old_trust.refusal_as(&endpoint, NODE1).await;
    assert!(r.as_deref().is_some_and(|r| r.contains("handshake failed") && r.contains("UnknownIssuer")), "{r:?}");

    serving.abort();
    let _ = serving.await;
    assert_eq!(old_client.refusal_as(&endpoint, NODE1).await, None, "a node that is down has no TLS detail");
}

#[tokio::test]
async fn a_two_ca_trust_bundle_carries_mtls_both_ways_and_dropping_the_old_ca_locks_it_out() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let old = Ca::new("rutli-frost-cluster-ca");
    let new = Ca::new("rutli-frost-cluster-ca-2026-10");

    // Baseline: before the rotation, old leaves and old trust.
    let s = tls_files(dir, "s0", &old, "cosigner1", &[&old]);
    let c = tls_files(dir, "c0", &old, "cosigner2", &[&old]);
    assert_eq!(node_info(dir, &s, &c).await.unwrap(), 1);

    // (a) The server already has its new-CA leaf, the client still its old-CA leaf; both trust
    //     the bundle old+new.
    let s = tls_files(dir, "sa", &new, "cosigner1", &[&old, &new]);
    let c = tls_files(dir, "ca", &old, "cosigner2", &[&old, &new]);
    assert_eq!(node_info(dir, &s, &c).await.unwrap(), 1, "new-CA server, old-CA client");

    // (b) The reverse, and with the bundle in the other order on one side.
    let s = tls_files(dir, "sb", &old, "cosigner1", &[&new, &old]);
    let c = tls_files(dir, "cb", &new, "cosigner2", &[&old, &new]);
    assert_eq!(node_info(dir, &s, &c).await.unwrap(), 1, "old-CA server, new-CA client");

    // (c) After the old CA is dropped from the server's trust file, a client still presenting an
    //     old-CA leaf is refused at the handshake — even though it trusts the server.
    let s = tls_files(dir, "sc", &new, "cosigner1", &[&new]);
    let c = tls_files(dir, "cc", &old, "cosigner2", &[&old, &new]);
    let e = node_info(dir, &s, &c).await.unwrap_err();
    assert!(e.contains("UnknownCA"), "a server trusting only the new CA must refuse an old-CA client: {e}");

    // (d) The client side of the same lockout: a node that still trusts only the old CA cannot
    //     reach a peer that already has a new-CA leaf — why the bundle must be everywhere before
    //     the first leaf is swapped.
    let s = tls_files(dir, "sd", &new, "cosigner1", &[&old, &new]);
    let c = tls_files(dir, "cd", &old, "cosigner2", &[&old]);
    let e = node_info(dir, &s, &c).await.unwrap_err();
    assert!(e.contains("UnknownIssuer"), "an old-trust client must refuse a new-CA server: {e}");

    // After the rotation: new leaves, new trust only.
    let s = tls_files(dir, "s1", &new, "cosigner1", &[&new]);
    let c = tls_files(dir, "c1", &new, "cosigner2", &[&new]);
    assert_eq!(node_info(dir, &s, &c).await.unwrap(), 1);

    // The CN allowlist still applies to new-CA leaves: the driver's cert is no mesh peer.
    let s = tls_files(dir, "se", &new, "cosigner1", &[&old, &new]);
    let c = tls_files(dir, "ce", &new, "driver", &[&old, &new]);
    let e = node_info(dir, &s, &c).await.unwrap_err();
    assert!(e.contains("PermissionDenied"), "a non-cosigner CN must not reach the Peer API: {e}");
}

// --- Review M1: every certificate in the trust file used to be a full mTLS anchor ----------------

impl Ca {
    /// A CA whose parameters `f` may change after the defaults.
    fn with(cn: &str, f: impl FnOnce(&mut CertificateParams)) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name.push(DnType::CommonName, cn);
        f(&mut p);
        Self { cert: p.self_signed(&key).unwrap(), key }
    }
}

/// A node's TLS files with an arbitrary trust file.
fn tls_files_raw(dir: &Path, name: &str, (cert, key): (String, String), trust: String) -> TlsConfig {
    let (cert_path, key_path, ca_path) =
        (dir.join(format!("{name}.crt")), dir.join(format!("{name}.key")), dir.join(format!("{name}-ca.crt")));
    std::fs::write(&cert_path, cert).unwrap();
    std::fs::write(&key_path, key).unwrap();
    std::fs::write(&ca_path, trust).unwrap();
    TlsConfig { ca_cert: ca_path, cert: cert_path, key: key_path, domain: None, allow_expired_ca: false }
}

fn load_err(cfg: &TlsConfig) -> String {
    match rutli_cosigner::tls::load(cfg) {
        Ok(_) => panic!("tls::load accepted trust file {}", std::fs::read_to_string(&cfg.ca_cert).unwrap()),
        Err(e) => e.to_string(),
    }
}

/// Review M1 (PoC `poc_leaf_in_trust_file_becomes_an_anchor`): `cat ca.crt cosigner1.crt > ca.crt`
/// made cosigner 1's leaf a trust anchor, so whoever holds `cosigner1.key` could mint a
/// `cosigner2` (or `driver`) certificate that passed the handshake and every CN allowlist. Such a
/// trust file is now refused when it is loaded, before any handshake.
#[tokio::test]
async fn a_leaf_in_the_trust_file_is_refused_at_load_and_cannot_issue_a_peer_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let ca = Ca::new("rutli-frost-cluster-ca");
    // Cosigner 1's leaf, mistakenly concatenated into the trust file.
    let leaf_key = KeyPair::generate().unwrap();
    let mut lp = CertificateParams::new(vec!["cosigner1".to_string()]).unwrap();
    lp.distinguished_name.push(DnType::CommonName, "cosigner1");
    lp.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    lp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = lp.signed_by(&leaf_key, &ca.cert, &ca.key).unwrap();
    // The cosigner1.key holder mints "cosigner2", issued by the leaf.
    let forged_key = KeyPair::generate().unwrap();
    let mut fp = CertificateParams::new(vec!["cosigner2".to_string()]).unwrap();
    fp.distinguished_name.push(DnType::CommonName, "cosigner2");
    fp.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    fp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let forged = fp.signed_by(&forged_key, &leaf, &leaf_key).unwrap();

    let polluted = format!("{}{}", ca.cert.pem(), leaf.pem());
    let s = tls_files_raw(dir, "s", ca.leaf("cosigner1"), polluted.clone());
    let e = load_err(&s);
    assert!(e.contains("certificate 1") && e.contains("not a CA"), "{e}");
    // Leaf first, CA second: the same.
    let s = tls_files_raw(dir, "s2", ca.leaf("cosigner1"), format!("{}{}", leaf.pem(), ca.cert.pem()));
    assert!(load_err(&s).contains("certificate 0"));

    // With the trust file as it should be, the forged identity gets nowhere.
    let s = tls_files_raw(dir, "s3", ca.leaf("cosigner1"), ca.cert.pem());
    let c = tls_files_raw(dir, "c3", (forged.pem(), forged_key.serialize_pem()), ca.cert.pem());
    let e = node_info(dir, &s, &c).await.unwrap_err();
    assert!(e.contains("UnknownCA") || e.contains("UnknownIssuer"), "{e}");
}

/// Review M1 (PoC `poc_expired_ca_anchor_still_trusted_by_mtls`): rustls never checks a trust
/// anchor's own validity, so an expired CA left in the file kept certifying its leaves. Refused at
/// load.
#[tokio::test]
async fn an_expired_or_not_yet_valid_ca_in_the_trust_file_is_refused_at_load() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let new = Ca::new("new-ca");
    let expired = Ca::with("expired-ca", |p| {
        p.not_before = rcgen::date_time_ymd(2001, 1, 1);
        p.not_after = rcgen::date_time_ymd(2002, 1, 1);
    });
    let future = Ca::with("future-ca", |p| {
        p.not_before = rcgen::date_time_ymd(2999, 1, 1);
        p.not_after = rcgen::date_time_ymd(3000, 1, 1);
    });
    for (name, bad) in [("expired", &expired), ("future", &future)] {
        let trust = format!("{}{}", bad.cert.pem(), new.cert.pem());
        let s = tls_files_raw(dir, name, new.leaf("cosigner1"), trust);
        let e = load_err(&s);
        assert!(e.contains("certificate 0") && e.contains("expired or not yet valid"), "{name}: {e}");
    }
    // The emergency override (rotating away from a CA that has already expired): the expired CA
    // loads and still certifies its leaves until it is dropped.
    let trust = format!("{}{}", expired.cert.pem(), new.cert.pem());
    let mut s = tls_files_raw(dir, "sx", new.leaf("cosigner1"), trust.clone());
    let mut c = tls_files_raw(dir, "cx", expired.leaf("cosigner2"), trust);
    s.allow_expired_ca = true;
    c.allow_expired_ca = true;
    let loaded = rutli_cosigner::tls::load(&s).unwrap();
    assert!(!loaded.anchors[0].valid_now && loaded.anchors[1].valid_now);
    assert_eq!(node_info(dir, &s, &c).await.unwrap(), 1);
    // ...but never a leaf, override or not.
    let mut leafy = tls_files_raw(dir, "sl", new.leaf("cosigner1"), format!("{}{}", new.cert.pem(), new.leaf("cosigner3").0));
    leafy.allow_expired_ca = true;
    assert!(load_err(&leafy).contains("not a CA"));
}

/// Review M1: a trust file holds CA certificates and nothing else. A private key pasted into it is
/// refused (and its content is never echoed), as is a file with no certificate at all.
#[test]
fn a_trust_file_with_a_private_key_or_no_certificate_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let ca = Ca::new("rutli-frost-cluster-ca");
    let (leaf, key) = ca.leaf("cosigner1");
    let s = tls_files_raw(dir, "k", (leaf.clone(), key.clone()), format!("{}{}", ca.cert.pem(), key));
    let e = load_err(&s);
    assert!(e.contains("PRIVATE KEY") && e.contains("only CA certificates"), "{e}");
    let body = key.lines().nth(1).unwrap();
    assert!(!e.contains(body), "the error must not echo the key: {e}");
    for (name, junk) in [("empty", String::new()), ("text", "not a pem\n".to_string())] {
        let s = tls_files_raw(dir, name, (leaf.clone(), key.clone()), junk);
        assert!(load_err(&s).contains("no CERTIFICATE"), "{name}");
    }
}

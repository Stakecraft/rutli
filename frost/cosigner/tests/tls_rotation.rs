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
const SAN: &str = "rutli-cosigner";

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

    /// A cosigner leaf: CN `cn`, SAN `rutli-cosigner`, serverAuth + clientAuth.
    fn leaf(&self, cn: &str) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![SAN.to_string()]).unwrap();
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
    TlsConfig { ca_cert: ca_path, cert: cert_path, key: key_path, domain: Some(SAN.to_string()) }
}

/// Node 1 serves the Peer API with `server`'s TLS; node 2 dials it with `client`'s TLS and asks
/// `NodeInfo`. Returns the identifier node 1 reported, or the failure (its `Debug`, which carries
/// the TLS alert).
async fn node_info(dir: &Path, server: &TlsConfig, client: &TlsConfig) -> Result<u16, String> {
    let sealer = Arc::new(Sealer::from_master_secret(MASTER, 1));
    let ks = KeyStore::open_with_sealer(dir.join("node-1"), Some(sealer)).unwrap();
    let node = Arc::new(
        Node::new(Identifier::try_from(1u16).unwrap(), 3, 2, ks)
            .with_hosted_keys(MASTER, CLUSTER.to_string())
            .unwrap(),
    );
    let peer_cns: Arc<HashSet<String>> = Arc::new((1..=3).map(|i| format!("cosigner{i}")).collect());
    let svc = PeerSvc { node, allowed_cns: Some(peer_cns) };

    let server_tls = rutli_cosigner::tls::load(server).unwrap();
    let client_tls = rutli_cosigner::tls::load(client).unwrap();
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

    let peer =
        GrpcPeer::connect_lazy(Identifier::try_from(1u16).unwrap(), &endpoint, Some(client_tls.client)).unwrap();
    let result = peer.node_info().await.map(|(id, _)| id).map_err(|e| format!("{e:?}"));
    serving.abort();
    result
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

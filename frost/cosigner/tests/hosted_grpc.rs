// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Hosted-key replication over real mTLS gRPC sockets.
//!
//! `cluster.rs` wires its nodes with `LocalPeer`, which skips the one thing the network path adds:
//! the *recipient number* a wrapped key is addressed to. Over gRPC the serving node takes it from
//! the caller's certificate CN (`cosigner2` -> 2), while the receiving node checks it against
//! `identifier_index` of its own FROST identifier. When `identifier_index` read every node as 0 (it
//! decoded a little-endian scalar as big-endian), `FetchKey` replies were addressed to "node 2" and
//! refused by a node that believed it was node 0 — pull replication and read-repair were dead on a
//! live cluster while every in-process test stayed green.
//!
//! Three real nodes here, each serving Peer + Signer on an ephemeral 127.0.0.1 port behind mutual
//! TLS with per-node CNs `cosigner1..3`, and dialing each other through `GrpcPeer`.

use std::collections::HashSet;
use std::sync::Arc;

use frost_ed25519::Identifier;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rutli_cosigner::config::TlsConfig;
use rutli_cosigner::hosted::HostedSpec;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{
    anti_entropy_sweep, generate_hosted_key, repair_hosted_key, Peers, DEFAULT_WRITE_QUORUM,
};
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::pb::signer_server::SignerServer;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

const N: u16 = 3;
const T: u16 = 2;
const MASTER: &[u8] = b"hosted key cluster master secret for tests";
const CLUSTER: &str = "testcluster00000";
/// The SAN every cosigner cert carries, and the name peers dial with (the endpoints are IPs).
const SAN: &str = "rutli-cosigner";

struct Mesh {
    nodes: Vec<Arc<Node>>,
    /// `peers[i]` is node `i`'s view of the cluster: itself as `LocalPeer`, the rest over gRPC.
    peers: Vec<Peers>,
    servers: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

impl Drop for Mesh {
    fn drop(&mut self) {
        for s in &self.servers {
            s.abort();
        }
    }
}

fn write_tls(dir: &std::path::Path, ca: &(rcgen::Certificate, KeyPair), cn: &str) -> TlsConfig {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![SAN.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.signed_by(&key, &ca.0, &ca.1).unwrap();
    let (cert_path, key_path, ca_path) =
        (dir.join(format!("{cn}.pem")), dir.join(format!("{cn}.key")), dir.join("ca.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca.0.pem()).unwrap();
    TlsConfig { ca_cert: ca_path, cert: cert_path, key: key_path, domain: Some(SAN.to_string()) }
}

async fn mesh() -> Mesh {
    let tmp = tempfile::tempdir().unwrap();

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "rutli test CA");
    let ca = (ca_params.self_signed(&ca_key).unwrap(), ca_key);

    let mut listeners = Vec::new();
    let mut nodes = Vec::new();
    let mut tls = Vec::new();
    for i in 1..=N {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let sealer = Arc::new(Sealer::from_master_secret(MASTER, i));
        let ks =
            KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
        let node = Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
            .with_hosted_keys(MASTER, CLUSTER.to_string())
            .unwrap();
        nodes.push(Arc::new(node));
        tls.push(
            rutli_cosigner::tls::load(&write_tls(tmp.path(), &ca, &format!("cosigner{i}"))).unwrap(),
        );
    }
    let endpoints: Vec<String> =
        listeners.iter().map(|l| format!("https://{}", l.local_addr().unwrap())).collect();

    let peer_cns: Arc<HashSet<String>> =
        Arc::new((1..=N).map(|i| format!("cosigner{i}")).collect());
    let signer_cns: Arc<HashSet<String>> = Arc::new(["driver".to_string()].into());

    let mut peers = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let mut view: Peers = Vec::new();
        for (j, ep) in endpoints.iter().enumerate() {
            let id = Identifier::try_from(j as u16 + 1).unwrap();
            view.push(if i == j {
                Arc::new(LocalPeer::new(node.clone())) as Arc<dyn PeerApi>
            } else {
                Arc::new(GrpcPeer::connect_lazy(id, ep, Some(tls[i].client.clone())).unwrap())
            });
        }
        peers.push(view);
    }

    let mut servers = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let signer = SignerSvc {
            node: nodes[i].clone(),
            peers: peers[i].clone(),
            allowed_cns: Some(signer_cns.clone()),
            operator_cns: None,
            hosted_write_quorum: DEFAULT_WRITE_QUORUM,
            decrypt_limiter: Arc::new(DecryptRateLimiter::new(0)),
            ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
        };
        let peer = PeerSvc { node: nodes[i].clone(), allowed_cns: Some(peer_cns.clone()) };
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
    Mesh { nodes, peers, servers, _tmp: tmp }
}

#[tokio::test]
async fn nodes_report_their_own_identifier_and_distribution_key_over_grpc() {
    let m = mesh().await;
    // Node 1 asks nodes 2 and 3 who they are, over the wire.
    for (j, peer) in m.peers[0].iter().enumerate().skip(1) {
        let (id, pk) = peer.node_info().await.unwrap();
        assert_eq!(id, j as u16 + 1, "NodeInfo must report the config number, not 0");
        assert_eq!(pk, m.nodes[j].dist_public_key().unwrap());
        // ...and which hosted-key specs it serves, so a leader can refuse an EC key while any
        // node predates it.
        let specs = peer.hosted_specs().await.unwrap();
        assert!(specs.contains(&"ec-p256-ecies".to_string()), "{specs:?}");
    }
    let keys: HashSet<[u8; 32]> = m.nodes.iter().map(|n| n.dist_public_key().unwrap()).collect();
    assert_eq!(keys.len(), N as usize, "each node must have its own distribution key");
}

#[tokio::test]
async fn a_node_pulls_a_missing_hosted_key_over_grpc_fetchkey() {
    let m = mesh().await;

    // The key exists on node 1 only (the others were down for the write).
    let (key, created) = m.nodes[0].hosted_generate("rutli-enc-1", HostedSpec::Rsa2048).unwrap();
    assert!(created);
    assert!(!m.nodes[1].hosted_exists("rutli-enc-1"));

    // Read-repair on node 2 and node 3: FetchKey on node 1 wraps to the caller's cert-derived
    // number, and the caller must recognise itself as that node.
    for i in [1usize, 2] {
        assert!(
            repair_hosted_key(&m.nodes[i], &m.peers[i], "rutli-enc-1").await.unwrap(),
            "node {} could not pull the key from node 1 over gRPC",
            i + 1
        );
        let ct = key.encrypt_oaep(b"after repair").unwrap();
        assert_eq!(m.nodes[i].hosted_decrypt("rutli-enc-1", &ct).unwrap(), b"after repair");
    }
}

#[tokio::test]
async fn an_ec_p256_key_replicates_and_repairs_over_grpc() {
    let m = mesh().await;
    let peer = hex::decode(
        "041f5efe3b2928f7db57c6befca0428a5833ea10b2e70fada8ccf40478c29bbcdb\
         3a143c9e3f9982325a7750a8b095d0b3feaf12fd01ef6172739b82e9ec62c421",
    )
    .unwrap();

    // Push path over the wire (ReplicateKey carries the spec string and the SPKI).
    let (key, _, replicas) =
        generate_hosted_key(&m.nodes[0], &m.peers[0], "rutli-enc-ec", HostedSpec::EcP256, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();
    assert_eq!(replicas, N as usize);
    let z = key.ecdh_p256(&peer).unwrap();
    for n in &m.nodes {
        assert_eq!(n.hosted_ecdh("rutli-enc-ec", &peer).unwrap().as_ref(), z.as_ref());
    }

    // Pull path (FetchKey) for a key only node 1 holds.
    let (only, _) = m.nodes[0].hosted_generate("rutli-enc-ec-2", HostedSpec::EcP256).unwrap();
    assert!(repair_hosted_key(&m.nodes[2], &m.peers[2], "rutli-enc-ec-2").await.unwrap());
    assert_eq!(
        m.nodes[2].hosted_ecdh("rutli-enc-ec-2", &peer).unwrap().as_ref(),
        only.ecdh_p256(&peer).unwrap().as_ref()
    );
}

#[tokio::test]
async fn a_hosted_key_replicates_over_grpc_and_the_sweep_pulls_and_converges() {
    let m = mesh().await;

    // Push path: leader on node 1, replicas acknowledged with commitments that must agree.
    let (key, _, replicas) = generate_hosted_key(
        &m.nodes[0],
        &m.peers[0],
        "rutli-sym-1",
        HostedSpec::Aes256Gcm,
        DEFAULT_WRITE_QUORUM,
    )
    .await
    .unwrap();
    assert_eq!(replicas, N as usize);
    let expected = m.nodes[0].hosted_commitment(&key).unwrap();
    for n in &m.nodes {
        assert!(n.hosted_exists("rutli-sym-1"));
        assert_eq!(
            n.hosted_commitment(&n.hosted_load("rutli-sym-1").unwrap()).unwrap(),
            expected,
            "a key's commitment must not depend on which node computes it"
        );
    }

    // Pull path: a key only node 3 holds is pulled by node 2's anti-entropy sweep.
    m.nodes[2].hosted_generate("rutli-enc-9", HostedSpec::Rsa2048).unwrap();
    let (pulled, _pushed) = anti_entropy_sweep(&m.nodes[1], &m.peers[1]).await.unwrap();
    assert!(pulled >= 1, "sweep should pull the key node 2 lacked");
    assert!(m.nodes[1].hosted_exists("rutli-enc-9"));
}

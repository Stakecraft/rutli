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
use rutli_cosigner::node::HostedKeyring;
use rutli_cosigner::seal::{NodeSealBundle, Sealer};
use rutli_cosigner::wrap::{legacy_commitment_key, DistKey};
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

const N: u16 = 3;
const T: u16 = 2;
const MASTER: &[u8] = b"hosted key cluster master secret for tests";
const CLUSTER: &str = "testcluster00000";

struct Mesh {
    /// Each node's `https://127.0.0.1:<port>`, by index.
    endpoints: Vec<String>,
    /// Each node's TLS material, by index.
    tls: Vec<rutli_cosigner::tls::Tls>,
    ca: (rcgen::Certificate, KeyPair),
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

/// A cert with CN `cn` and that same name as its only SAN — what gen-frost-certs.sh issues now
/// (`cosigner<N>`, no shared name). Peers dial by that name; the endpoints are IPs.
fn write_tls(dir: &std::path::Path, ca: &(rcgen::Certificate, KeyPair), cn: &str) -> TlsConfig {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.signed_by(&key, &ca.0, &ca.1).unwrap();
    let (cert_path, key_path, ca_path) =
        (dir.join(format!("{cn}.pem")), dir.join(format!("{cn}.key")), dir.join("ca.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca.0.pem()).unwrap();
    TlsConfig { ca_cert: ca_path, cert: cert_path, key: key_path, domain: None, allow_expired_ca: false }
}

/// How a test node gets its seal keys.
#[derive(Clone, Copy, PartialEq)]
enum SealMode {
    /// The deprecated shared master (`share_seal.secret_env`).
    Legacy,
    /// Its own bundle split from that master (`seal split-legacy`), with peers pinned.
    SplitBundle,
}

async fn mesh() -> Mesh {
    mesh_with(|_| SealMode::Legacy, |_| None).await
}

/// A mesh whose node `i` (1-based) runs `mode(i)`; `pin_override(i)` replaces the distribution key
/// every bundle node pins for node `i` (to model a wrong pin).
async fn mesh_with(mode: impl Fn(u16) -> SealMode, pin_override: impl Fn(u16) -> Option<[u8; 32]>) -> Mesh {
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
        let node = match mode(i) {
            SealMode::Legacy => {
                let sealer = Arc::new(Sealer::from_master_secret(MASTER, i));
                let ks = KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer))
                    .unwrap();
                Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
                    .with_hosted_keys(MASTER, CLUSTER.to_string())
                    .unwrap()
            }
            SealMode::SplitBundle => {
                // What the daemon does on `share_seal.secret_file`: the node holds only its own
                // bundle and knows its peers by pinned public keys and the commitment key.
                let bundle = NodeSealBundle::from_legacy_master(MASTER, i);
                let ks = KeyStore::open_with_sealer(
                    tmp.path().join(format!("node-{i}")),
                    Some(Arc::new(bundle.sealer())),
                )
                .unwrap();
                let keyring = HostedKeyring {
                    dist_key: bundle.dist_key(),
                    commitment_key: legacy_commitment_key(MASTER),
                    peer_dist_keys: (1..=N)
                        .map(|j| {
                            let pinned = if j == i { None } else { pin_override(j) };
                            (j, pinned.unwrap_or_else(|| DistKey::derive(MASTER, j).public_bytes()))
                        })
                        .collect(),
                };
                Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
                    .with_hosted_keyring(keyring, CLUSTER.to_string())
                    .unwrap()
            }
        };
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
    let peer_ids: Arc<std::collections::HashMap<String, u16>> =
        Arc::new((1..=N).map(|i| (format!("cosigner{i}"), i)).collect());

    let mut peers = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let mut view: Peers = Vec::new();
        for (j, ep) in endpoints.iter().enumerate() {
            let id = Identifier::try_from(j as u16 + 1).unwrap();
            view.push(if i == j {
                Arc::new(LocalPeer::new(node.clone())) as Arc<dyn PeerApi>
            } else {
                Arc::new(
                    GrpcPeer::connect_lazy(id, ep, Some(tls[i].client_for(&format!("cosigner{}", j + 1))))
                        .unwrap(),
                )
            });
        }
        // The ceremony mesh: each node reaches its peers over gRPC, as the daemon wires it.
        node.set_mesh(view.clone()).unwrap();
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
            sign_guard: None,
            refresh_cns: None,
        };
        let peer = PeerSvc {
            node: nodes[i].clone(),
            allowed_cns: Some(peer_cns.clone()),
            peer_ids: Some(peer_ids.clone()),
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
    Mesh { endpoints, tls, ca, nodes, peers, servers, _tmp: tmp }
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

#[tokio::test]
async fn a_mixed_legacy_and_bundle_cluster_replicates_and_repairs_over_grpc() {
    // Mid-migration: node 1 still on the shared master, nodes 2 and 3 on bundles split from it.
    // Every direction of push, pull and commitment comparison must work unchanged.
    let m = mesh_with(|i| if i == 1 { SealMode::Legacy } else { SealMode::SplitBundle }, |_| None).await;

    for leader in 0..N as usize {
        let key_id = format!("rutli-sym-mixed-{leader}");
        let (key, _, replicas) = generate_hosted_key(
            &m.nodes[leader],
            &m.peers[leader],
            &key_id,
            HostedSpec::Aes256Gcm,
            DEFAULT_WRITE_QUORUM,
        )
        .await
        .unwrap();
        assert_eq!(replicas, N as usize, "leader {} must reach every node", leader + 1);
        let expected = m.nodes[leader].hosted_commitment(&key).unwrap();
        for n in &m.nodes {
            assert_eq!(n.hosted_commitment(&n.hosted_load(&key_id).unwrap()).unwrap(), expected);
        }
    }

    // FetchKey both ways: the legacy node pulls from a bundle node, and a bundle node from it.
    let (k3, _) = m.nodes[2].hosted_generate("rutli-enc-only-3", HostedSpec::Rsa2048).unwrap();
    assert!(repair_hosted_key(&m.nodes[0], &m.peers[0], "rutli-enc-only-3").await.unwrap());
    let ct = k3.encrypt_oaep(b"mixed").unwrap();
    assert_eq!(m.nodes[0].hosted_decrypt("rutli-enc-only-3", &ct).unwrap(), b"mixed");
    let (k1, _) = m.nodes[0].hosted_generate("rutli-enc-only-1", HostedSpec::Rsa2048).unwrap();
    assert!(repair_hosted_key(&m.nodes[1], &m.peers[1], "rutli-enc-only-1").await.unwrap());
    let ct = k1.encrypt_oaep(b"mixed").unwrap();
    assert_eq!(m.nodes[1].hosted_decrypt("rutli-enc-only-1", &ct).unwrap(), b"mixed");
}

#[tokio::test]
async fn a_node_never_wraps_to_a_key_other_than_the_pinned_one() {
    // Every bundle node pins a wrong key for node 3 (as if node 3 had the wrong bundle mounted, or
    // an impostor answered for it): node 3 reports its real key, which no longer matches the pin.
    let m = mesh_with(|_| SealMode::SplitBundle, |j| (j == 3).then_some([7u8; 32])).await;
    let (_, _, replicas) = generate_hosted_key(
        &m.nodes[0],
        &m.peers[0],
        "rutli-sym-pinned",
        HostedSpec::Aes256Gcm,
        DEFAULT_WRITE_QUORUM,
    )
    .await
    .unwrap();
    assert_eq!(replicas, 2, "node 3 must be refused, nodes 1 and 2 still make the quorum");
    assert!(!m.nodes[2].hosted_exists("rutli-sym-pinned"));
}

#[tokio::test]
async fn a_peer_endpoint_answered_by_another_nodes_certificate_is_refused() {
    // M3: node 1 believes peer 2 lives at node 3's address (DNS hijack, a mis-pointed Service, a
    // compromised node 3 squatting). Node 3's certificate is cluster-CA-signed and allowlisted, but
    // it is not cosigner2's, so the handshake fails — under the old shared `rutli-cosigner` name it
    // would have verified.
    let m = mesh().await;
    let impostor = GrpcPeer::connect_lazy(
        Identifier::try_from(2u16).unwrap(),
        &m.endpoints[2],
        Some(m.tls[0].client_for("cosigner2")),
    )
    .unwrap();
    assert!(impostor.node_info().await.is_err(), "node 3 must not pass as peer 2");
    // The same endpoint dialled under its own name works (the refusal is the name, not the socket).
    let honest = GrpcPeer::connect_lazy(
        Identifier::try_from(3u16).unwrap(),
        &m.endpoints[2],
        Some(m.tls[0].client_for("cosigner3")),
    )
    .unwrap();
    assert_eq!(honest.node_info().await.unwrap().0, 3);
}

#[tokio::test]
async fn fetch_key_identifies_the_caller_by_an_exact_cn_only() {
    // A cert whose CN merely CONTAINS a node number (`cosigner-2`, `xcosigner2`, `cosigner02`) was
    // read as node 2 by the old digit-stripping parser, so an allowlisted odd spelling could pull
    // key material wrapped to another node. Now only the configured CN names a node.
    let m = mesh().await;
    m.nodes[0].hosted_generate("rutli-enc-exact", HostedSpec::Rsa2048).unwrap();

    // Serve node 1 again with a loose allowlist that also admits the odd spellings.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ep = format!("https://{}", listener.local_addr().unwrap());
    let odd = ["cosigner-2", "xcosigner2", "cosigner02"];
    let allowed: Arc<HashSet<String>> = Arc::new(
        (1..=N).map(|i| format!("cosigner{i}")).chain(odd.iter().map(|s| s.to_string())).collect(),
    );
    let peer = PeerSvc {
        node: m.nodes[0].clone(),
        allowed_cns: Some(allowed),
        peer_ids: Some(Arc::new((1..=N).map(|i| (format!("cosigner{i}"), i)).collect())),
    };
    let server = tonic::transport::Server::builder()
        .tls_config(m.tls[0].server.clone())
        .unwrap()
        .add_service(PeerServer::new(peer))
        .serve_with_incoming(TcpListenerStream::new(listener));
    let handle = tokio::spawn(async move {
        let _ = server.await;
    });

    let tmp = tempfile::tempdir().unwrap();
    for cn in odd {
        let tls = rutli_cosigner::tls::load(&write_tls(tmp.path(), &m.ca, cn)).unwrap();
        let caller = GrpcPeer::connect_lazy(Identifier::try_from(1u16).unwrap(), &ep, Some(tls.client_for("cosigner1")))
            .unwrap();
        let e = caller.fetch_key("rutli-enc-exact").await.err().expect("odd CN must be refused");
        assert!(e.to_string().contains("not the configured client CN"), "{cn}: {e}");
    }
    // The exact CN still works over the same server.
    let tls = rutli_cosigner::tls::load(&write_tls(tmp.path(), &m.ca, "cosigner2")).unwrap();
    let caller = GrpcPeer::connect_lazy(Identifier::try_from(1u16).unwrap(), &ep, Some(tls.client_for("cosigner1")))
        .unwrap();
    let (_, _, wrapped) = caller.fetch_key("rutli-enc-exact").await.unwrap();
    assert_eq!(wrapped.recipient, 2);
    handle.abort();
}

#[tokio::test]
async fn dkg_and_refresh_commit_on_every_node_over_mtls_grpc() {
    // Two-phase DKG and refresh over real sockets: each node's commit is decided by asking every
    // peer directly (CeremonyStatus over its own mTLS client), whichever node leads.
    let m = mesh().await;
    let key = "frost-grpc-2pc";
    let group = rutli_cosigner::orchestrator::run_dkg(&m.peers[1], key).await.unwrap();
    for leader in [2usize, 0] {
        assert_eq!(rutli_cosigner::orchestrator::run_refresh(&m.peers[leader], key).await.unwrap(), group);
    }
    let digest = m.nodes[0].key_epoch(key).unwrap().pkp_digest;
    for n in &m.nodes {
        let v = n.key_epoch(key).unwrap();
        assert_eq!((v.epoch, v.staged), (3, false), "DKG then two refreshes");
        assert_eq!(v.pkp_digest, digest);
        assert!(n.staged_records().is_empty());
    }
    // A retried DKG returns the committed key (M5).
    assert_eq!(rutli_cosigner::orchestrator::run_dkg(&m.peers[0], key).await.unwrap(), group);
    let msg = rutli_frost_core::dealer::canton_test_message(b"after grpc refresh");
    let sig = rutli_cosigner::orchestrator::sign(&m.nodes[0], &m.peers[0], key, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

#[tokio::test]
async fn a_round2_delivery_under_another_nodes_identity_is_refused_over_mtls() {
    // C1 over the wire: node 3's certificate may deliver only as node 3. (Node 1 has no session for
    // the ceremony, so an honestly-identified delivery reaches the node and is NOT_FOUND there.)
    let m = mesh().await;
    let as3 = GrpcPeer::connect_lazy(
        Identifier::try_from(1u16).unwrap(),
        &m.endpoints[0],
        Some(m.tls[2].client_for("cosigner1")),
    )
    .unwrap();
    let mut b = [0u8; 32];
    b[0] = 5;
    let pkg = frost_ed25519::keys::dkg::round2::Package::new(frost_ed25519::keys::SigningShare::deserialize(&b).unwrap());
    let err = as3.ceremony_deliver("dkg-x", 2, 1, &[0u8; 32], &pkg).await.unwrap_err();
    match err {
        rutli_cosigner::DaemonError::Status(s) => assert_eq!(s.code(), tonic::Code::PermissionDenied, "{s:?}"),
        other => panic!("{other:?}"),
    }
    match as3.ceremony_deliver("dkg-x", 3, 1, &[0u8; 32], &pkg).await.unwrap_err() {
        rutli_cosigner::DaemonError::Status(s) => assert_eq!(s.code(), tonic::Code::NotFound, "{s:?}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_upgraded_node_refuses_every_relay_rpc_and_an_old_leader_fence() {
    use rutli_cosigner::pb::peer_client::PeerClient;
    use rutli_cosigner::pb::{CeremonyFenceRequest, DkgPart1Request, DkgPart2Request, DkgPart3Request, RefreshPart1Request};
    let m = mesh().await;
    // What an rc.1 leader on node 2 would call on node 1.
    let channel = tonic::transport::Endpoint::from_shared(m.endpoints[0].clone())
        .unwrap()
        .tls_config(m.tls[1].client_for("cosigner1"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut old = PeerClient::new(channel);
    let refused = |r: Result<(), tonic::Status>| {
        let s = r.unwrap_err();
        assert_eq!(s.code(), tonic::Code::FailedPrecondition, "{s:?}");
    };
    refused(old.dkg_part1(DkgPart1Request { dkg_id: "d".into(), key_id: "k".into(), ..Default::default() }).await.map(|_| ()));
    refused(old.dkg_part2(DkgPart2Request { dkg_id: "d".into(), round1_map: b"{}".to_vec() }).await.map(|_| ()));
    refused(old.dkg_part3(DkgPart3Request::default()).await.map(|_| ()));
    refused(old.refresh_part1(RefreshPart1Request { refresh_id: "r".into(), key_id: "k".into() }).await.map(|_| ()));
    refused(old.refresh_part2(DkgPart2Request::default()).await.map(|_| ()));
    refused(old.refresh_part3(DkgPart3Request::default()).await.map(|_| ()));
    // An old leader's DKG fence (no protocol field) is refused before any guard is taken…
    refused(
        old.ceremony_fence(CeremonyFenceRequest {
            ceremony_id: "d".into(),
            key_id: "k".into(),
            kind: "dkg".into(),
            ..Default::default()
        })
        .await
        .map(|_| ()),
    );
    // …while hosted-key fences are unaffected.
    old.ceremony_fence(CeremonyFenceRequest {
        ceremony_id: "g".into(),
        key_id: "rutli-k".into(),
        kind: "genkey".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    // Every node reports protocol 2, which is what a new leader checks first.
    for p in &m.peers[0] {
        assert_eq!(p.ceremony_protocol().await.unwrap(), rutli_cosigner::ceremony::CEREMONY_PROTOCOL);
    }
}

#[tokio::test]
async fn a_plaintext_dev_cluster_without_hosted_keys_runs_dkg_and_refresh_over_grpc() {
    // NodeInfo (the ceremony protocol check) must answer with hosted keys off, and the plaintext
    // dev mesh (no allowlists, nothing authenticated) still delivers round 2 node to node.
    let tmp = tempfile::tempdir().unwrap();
    let mut listeners = Vec::new();
    let mut nodes = Vec::new();
    for i in 1..=N {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let ks = KeyStore::open(tmp.path().join(format!("node-{i}"))).unwrap();
        nodes.push(Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, ks)));
    }
    let endpoints: Vec<String> = listeners.iter().map(|l| format!("http://{}", l.local_addr().unwrap())).collect();
    let mut views = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let view: Peers = endpoints
            .iter()
            .enumerate()
            .map(|(j, ep)| {
                if i == j {
                    Arc::new(LocalPeer::new(node.clone())) as Arc<dyn PeerApi>
                } else {
                    Arc::new(GrpcPeer::connect_lazy(Identifier::try_from(j as u16 + 1).unwrap(), ep, None).unwrap())
                }
            })
            .collect();
        node.set_mesh(view.clone()).unwrap();
        views.push(view);
    }
    let mut servers = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let peer = PeerSvc { node: nodes[i].clone(), allowed_cns: None, peer_ids: None };
        let server = tonic::transport::Server::builder()
            .add_service(PeerServer::new(peer))
            .serve_with_incoming(TcpListenerStream::new(listener));
        servers.push(tokio::spawn(async move {
            let _ = server.await;
        }));
    }
    let group = rutli_cosigner::orchestrator::run_dkg(&views[2], "frost-plain").await.unwrap();
    assert_eq!(rutli_cosigner::orchestrator::run_refresh(&views[1], "frost-plain").await.unwrap(), group);
    for n in &nodes {
        assert_eq!(n.key_epoch("frost-plain").unwrap().epoch, 2);
    }
    for s in servers {
        s.abort();
    }
}

#[tokio::test]
async fn epoch_refusals_and_session_binding_hold_over_mtls_grpc() {
    // H1/M1 and the session binding over real sockets: the refusing node's own sharing rides back
    // in the status trailers, and the leader routes around a stale node.
    use rutli_cosigner::node::{Round1Ctx, StaleMark};
    use rutli_cosigner::DaemonError;
    let m = mesh().await;
    let key = "frost-grpc-epochs";
    let group = rutli_cosigner::orchestrator::run_dkg(&m.peers[0], key).await.unwrap();
    let node2 = &m.peers[0][1]; // node 2 as node 1 dials it
    let v2 = m.nodes[1].key_epoch(key).unwrap();
    let view2 = (v2.epoch, <[u8; 32]>::try_from(v2.pkp_digest.as_slice()).unwrap());

    let wrong = Round1Ctx { leader_view: Some((view2.0 + 1, view2.1)), ..Default::default() };
    match node2.sign_round1(key, "g-mismatch", &wrong).await.unwrap_err() {
        DaemonError::EpochMismatch { peer, leader, .. } => assert_eq!((peer, leader), (view2, wrong.leader_view.unwrap())),
        other => panic!("expected EpochMismatch over gRPC, got {other:?}"),
    }

    // Round 2 for another message than round 1 declared: refused there, nothing burned.
    let msg = rutli_frost_core::dealer::canton_test_message(b"declared");
    let ctx = Round1Ctx { leader_view: Some(view2), message: Some(msg.to_vec()), signers: Some(vec![1, 2]), ..Default::default() };
    let mut cs = std::collections::BTreeMap::new();
    cs.insert(m.nodes[0].identifier, m.nodes[0].sign_round1(key, "g-bind", &ctx).unwrap());
    cs.insert(m.nodes[1].identifier, node2.sign_round1(key, "g-bind", &ctx).await.unwrap());
    let other = rutli_frost_core::dealer::canton_test_message(b"swapped");
    let err = node2.sign_round2(key, "g-bind", &other, &cs, None).await.unwrap_err();
    assert!(
        matches!(&err, DaemonError::Status(s) if s.code() == tonic::Code::FailedPrecondition && s.message().contains("round-1 binding")),
        "{err:?}"
    );

    // A stale node refuses over the wire with its own trailer, and the leader signs around it.
    m.nodes[1].set_stale(key, Some(StaleMark { own_epoch: 1, newer_epoch: 2, reason: "test".into() }));
    let ok = Round1Ctx { leader_view: Some(view2), ..Default::default() };
    assert!(matches!(node2.sign_round1(key, "g-stale", &ok).await.unwrap_err(), DaemonError::StaleShare { .. }));
    let msg = rutli_frost_core::dealer::canton_test_message(b"around a stale node");
    let sig = rutli_cosigner::orchestrator::sign(&m.nodes[0], &m.peers[0], key, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

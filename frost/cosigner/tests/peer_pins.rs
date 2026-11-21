// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Peer key pins (`peers[].tls_spki_sha256`) on the wire, both ways, over an in-memory network
//! (no TCP port): a certificate under the cluster CA with the right name is refused when its key is
//! not the pinned one — when this node dials a peer (the impostor never sees a request) and when a
//! peer calls this node — and the right key completes the RPC. Then a whole pinned mesh runs a DKG,
//! a refresh and a signature through the daemon's own dial, and a DKG with an impostor at one node's
//! address delivers it nothing.

#![allow(clippy::result_large_err)]

#[path = "common/memnet.rs"]
mod memnet;

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use frost_ed25519::Identifier;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rutli_cosigner::config::{PeerConfig, TlsConfig};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi};

type Peers = Vec<Arc<dyn PeerApi>>;
use rutli_cosigner::service::{PeerPins, PeerSvc};
use rutli_cosigner::tls::{spki_sha256_of_pem_file, Tls};

use memnet::MemNet;

const N: u16 = 3;
const T: u16 = 2;

struct Ca(rcgen::Certificate, KeyPair);

fn ca() -> Ca {
    ca_named("rutli test CA")
}

fn ca_named(cn: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    Ca(params.self_signed(&key).unwrap(), key)
}

/// A leaf for `cn` (SAN `cn`, a fresh key) under `ca`, written to `dir/<file>.{pem,key}`.
fn leaf(dir: &Path, ca: &Ca, cn: &str, file: &str) -> TlsConfig {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.signed_by(&key, &ca.0, &ca.1).unwrap();
    let (cert_path, key_path, ca_path) = (dir.join(format!("{file}.pem")), dir.join(format!("{file}.key")), dir.join("ca.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    std::fs::write(&ca_path, ca.0.pem()).unwrap();
    TlsConfig { ca_cert: ca_path, cert: cert_path, key: key_path, domain: None, allow_expired_ca: false, require_peer_pins: None }
}

fn pin(cfg: &TlsConfig) -> [u8; 32] {
    spki_sha256_of_pem_file(&cfg.cert).unwrap()
}

fn node(dir: &Path, id: u16) -> Arc<Node> {
    let ks = KeyStore::open(dir.join(format!("node-{id}"))).unwrap();
    Arc::new(Node::new(Identifier::try_from(id).unwrap(), N, T, ks))
}

fn authority(id: u16) -> String {
    format!("cosigner{id}:{}", 9100 + id)
}

fn endpoint(id: u16) -> String {
    format!("https://{}", authority(id))
}

/// The roster's pins as the daemon builds them for `PeerSvc` (client CN `cosigner<id>`).
fn peer_pins(pins: &[(u16, Vec<[u8; 32]>)]) -> Arc<PeerPins> {
    let mut cfg_peers = Vec::new();
    for id in 1..=N {
        let mut p = PeerConfig::new(id, endpoint(id));
        p.tls_spki_sha256 = pins.iter().find(|(i, _)| *i == id).map(|(_, list)| list.iter().map(hex::encode).collect());
        cfg_peers.push(p);
    }
    let cfg = rutli_cosigner::config::Config { peers: cfg_peers, ..base_config() };
    Arc::new(PeerPins::from_config(&cfg).unwrap())
}

fn base_config() -> rutli_cosigner::config::Config {
    serde_json::from_str(r#"{"identifier":1,"listen":"127.0.0.1:0","threshold":2,"data_dir":"/tmp","peers":[{"identifier":1,"endpoint":"x"}]}"#)
        .unwrap()
}

/// Serve `node`'s Peer API at `authority` on `net` with TLS `server`, the cosigner CN allowlist and
/// `pins`. Counts every request that reaches the service.
fn serve(net: &MemNet, authority: &str, tls: &Tls, node: Arc<Node>, pins: Option<Arc<PeerPins>>) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    serve_with(net, authority, tls, node, pins, true)
}

/// [`serve`], with or without the cosigner CN allowlist.
fn serve_with(
    net: &MemNet,
    authority: &str,
    tls: &Tls,
    node: Arc<Node>,
    pins: Option<Arc<PeerPins>>,
    allowlist: bool,
) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let peer = PeerSvc {
        node,
        allowed_cns: allowlist.then(|| Arc::new((1..=N).map(|i| format!("cosigner{i}")).collect::<HashSet<_>>())),
        peer_ids: Some(Arc::new((1..=N).map(|i| (format!("cosigner{i}"), i)).collect())),
        peer_pins: pins,
    };
    let svc = PeerServer::with_interceptor(peer, move |req| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(req)
    });
    let server = tonic::transport::Server::builder()
        .tls_config(tls.server.clone())
        .unwrap()
        .add_service(svc)
        .serve_with_incoming(net.listen(authority));
    (seen, tokio::spawn(async move {
        let _ = server.await;
    }))
}

/// A client of peer `id` on `net`, dialled as the daemon dials: under `cosigner<id>`, with `pins`.
fn dial(net: &MemNet, tls: &Tls, id: u16, pins: Option<Vec<[u8; 32]>>) -> GrpcPeer {
    let dial = tls.dial_as(&format!("cosigner{id}"), pins, id).unwrap();
    GrpcPeer::connect_lazy_over(Identifier::try_from(id).unwrap(), &endpoint(id), &dial, dial.connector_over(net.dialer()))
        .unwrap()
}

/// The error and everything behind it (the pin refusal sits under tonic's transport error).
fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

#[tokio::test]
async fn outbound_a_wrong_pin_is_refused_and_the_right_pin_completes_an_rpc() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let (c1, c2) = (leaf(tmp.path(), &ca, "cosigner1", "c1"), leaf(tmp.path(), &ca, "cosigner2", "c2"));
    let (t1, t2) = (rutli_cosigner::tls::load(&c1).unwrap(), rutli_cosigner::tls::load(&c2).unwrap());
    let net = MemNet::new();
    let (seen, server) = serve(&net, &authority(2), &t2, node(tmp.path(), 2), None);

    // The right pin: the RPC completes.
    let good = dial(&net, &t1, 2, Some(vec![pin(&c2)]));
    good.hosted_specs().await.expect("the pinned key must get through");
    assert_eq!(seen.load(Ordering::SeqCst), 1);

    // A wrong pin: refused before any request is written, naming the CN and the key it saw.
    let bad = dial(&net, &t1, 2, Some(vec![[7u8; 32]]));
    let e = bad.hosted_specs().await.unwrap_err();
    let text = chain(&e);
    assert!(text.contains("not pinned in peers[id=2].tls_spki_sha256"), "{text}");
    assert!(text.contains("'cosigner2'") && text.contains(&hex::encode(pin(&c2))), "{text}");
    assert_eq!(seen.load(Ordering::SeqCst), 1, "a refused dial must send the peer nothing");

    // Unpinned (tls.require_peer_pins: false): the name alone, as before.
    dial(&net, &t1, 2, None).hosted_specs().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn the_dial_still_refuses_another_ca_and_another_name_with_the_rustls_reason() {
    // The pinned dial keeps rustls's stock checks, and the reason still reaches the caller's error
    // (docs/ca-rotation.md greps for it).
    let tmp = tempfile::tempdir().unwrap();
    let (ca, other) = (ca(), ca_named("another cluster's CA"));
    let c1 = leaf(tmp.path(), &ca, "cosigner1", "c1");
    let t1 = rutli_cosigner::tls::load(&c1).unwrap();
    let foreign = leaf(tmp.path(), &other, "cosigner2", "foreign");
    let pinned = Some(vec![pin(&foreign)]);
    let net = MemNet::new();
    let (seen, server) = serve(&net, &authority(2), &rutli_cosigner::tls::load(&foreign).unwrap(), node(tmp.path(), 2), None);
    let e = dial(&net, &t1, 2, pinned.clone()).hosted_specs().await.unwrap_err();
    assert!(format!("{e:?}").contains("UnknownIssuer"), "{e:?}");
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    server.abort();
    // The right CA, another node's name.
    let c3 = leaf(tmp.path(), &ca, "cosigner3", "c3");
    let net = MemNet::new();
    let (seen, server) = serve(&net, &authority(2), &rutli_cosigner::tls::load(&c3).unwrap(), node(tmp.path(), 2), None);
    let e = dial(&net, &t1, 2, Some(vec![pin(&c3)])).hosted_specs().await.unwrap_err();
    assert!(format!("{e:?}").contains("NotValidForName"), "{e:?}");
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn outbound_an_impostor_with_a_ca_signed_certificate_for_the_name_gets_nothing() {
    // Whoever holds the CA key mints `cosigner2` and answers at node 2's address. The name and the
    // chain verify; the key is not node 2's.
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let c1 = leaf(tmp.path(), &ca, "cosigner1", "c1");
    let real2 = leaf(tmp.path(), &ca, "cosigner2", "real2");
    let fake2 = leaf(tmp.path(), &ca, "cosigner2", "fake2");
    let t1 = rutli_cosigner::tls::load(&c1).unwrap();
    let net = MemNet::new();
    let (seen, server) = serve(&net, &authority(2), &rutli_cosigner::tls::load(&fake2).unwrap(), node(tmp.path(), 2), None);

    let e = dial(&net, &t1, 2, Some(vec![pin(&real2)])).hosted_specs().await.unwrap_err();
    assert!(chain(&e).contains(&hex::encode(pin(&fake2))), "{}", chain(&e));
    assert_eq!(seen.load(Ordering::SeqCst), 0, "the impostor must receive no request");
    // Without the pin it would have been accepted: the check is the pin, not the name or the CA.
    dial(&net, &t1, 2, None).hosted_specs().await.unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn inbound_a_caller_with_an_unpinned_key_is_refused_on_every_peer_rpc() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let c2 = leaf(tmp.path(), &ca, "cosigner2", "c2");
    let real1 = leaf(tmp.path(), &ca, "cosigner1", "real1");
    let old1 = leaf(tmp.path(), &ca, "cosigner1", "old1");
    let c3 = leaf(tmp.path(), &ca, "cosigner3", "c3");
    let net = MemNet::new();
    let pins = peer_pins(&[(1, vec![pin(&real1)]), (2, vec![pin(&c2)])]);
    let (_, server) = serve(&net, &authority(2), &rutli_cosigner::tls::load(&c2).unwrap(), node(tmp.path(), 2), Some(pins));
    let server_pin = Some(vec![pin(&c2)]);

    // A replaced node's old certificate: valid chain, right CN, wrong key.
    let old = dial(&net, &rutli_cosigner::tls::load(&old1).unwrap(), 2, server_pin.clone());
    let e = old.hosted_specs().await.unwrap_err();
    let text = chain(&e);
    assert!(text.contains("PermissionDenied") || text.contains("permission"), "{text}");
    assert!(text.contains("'cosigner1'") && text.contains(&hex::encode(pin(&old1))), "{text}");
    assert!(text.contains("peers[id=1].tls_spki_sha256"), "{text}");
    // ...on the handlers that act on who is calling, too.
    assert!(chain(&old.fetch_key("k").await.err().expect("refused")).contains("not pinned"));
    assert!(old.key_epoch("k").await.is_err());

    // The pinned key passes.
    dial(&net, &rutli_cosigner::tls::load(&real1).unwrap(), 2, server_pin.clone()).hosted_specs().await.unwrap();
    // A peer without pins (only with tls.require_peer_pins: false) passes on its name.
    dial(&net, &rutli_cosigner::tls::load(&c3).unwrap(), 2, server_pin).hosted_specs().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn inbound_pins_hold_without_a_peer_allowlist() {
    // The pin check does not lean on peer_allowlist (which config validation requires with TLS
    // anyway): with pins set and no allowlist, a CA-signed certificate with a roster CN and another
    // key is refused, a certificate with no roster CN is refused, and the pinned key passes.
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let c2 = leaf(tmp.path(), &ca, "cosigner2", "c2");
    let real1 = leaf(tmp.path(), &ca, "cosigner1", "real1");
    let fake1 = leaf(tmp.path(), &ca, "cosigner1", "fake1");
    let driver = leaf(tmp.path(), &ca, "driver", "driver");
    let net = MemNet::new();
    let pins = peer_pins(&[(1, vec![pin(&real1)]), (2, vec![pin(&c2)]), (3, vec![[3; 32]])]);
    let (seen, server) =
        serve_with(&net, &authority(2), &rutli_cosigner::tls::load(&c2).unwrap(), node(tmp.path(), 2), Some(pins), false);
    let server_pin = Some(vec![pin(&c2)]);
    let e = dial(&net, &rutli_cosigner::tls::load(&fake1).unwrap(), 2, server_pin.clone()).hosted_specs().await.unwrap_err();
    assert!(chain(&e).contains(&hex::encode(pin(&fake1))), "{}", chain(&e));
    // The round-2 delivery path takes the sender from the certificate, not the claim.
    let e = dial(&net, &rutli_cosigner::tls::load(&fake1).unwrap(), 2, server_pin.clone())
        .fetch_key("k")
        .await
        .err()
        .expect("refused");
    assert!(chain(&e).contains("not pinned"), "{}", chain(&e));
    let e = dial(&net, &rutli_cosigner::tls::load(&driver).unwrap(), 2, server_pin.clone()).hosted_specs().await.unwrap_err();
    assert!(chain(&e).contains("not the configured client CN"), "{}", chain(&e));
    dial(&net, &rutli_cosigner::tls::load(&real1).unwrap(), 2, server_pin).hosted_specs().await.unwrap();
    assert_eq!(seen.load(Ordering::SeqCst), 4, "the interceptor runs before the service refuses");
    server.abort();
}

#[tokio::test]
async fn a_peer_that_accepts_tcp_and_never_answers_the_handshake_times_out() {
    use tonic::codegen::Service;
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let t1 = rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, "cosigner1", "c1")).unwrap();
    let net = MemNet::new();
    // Something listens at node 2's address, takes the connection and says nothing.
    let _incoming = net.listen(&authority(2));
    let dial = t1.dial_as("cosigner2", Some(vec![[2; 32]]), 2).unwrap().with_connect_timeout(std::time::Duration::from_millis(300));
    let mut connector = dial.connector_over(net.dialer());
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), connector.call(endpoint(2).parse().unwrap()))
        .await
        .expect("the connector's own bound must fire first");
    let Err(e) = outcome else { panic!("a silent peer must fail the dial") };
    assert!(e.to_string().contains("no TCP connection and TLS handshake within"), "{e}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[tokio::test]
async fn a_server_that_does_not_negotiate_h2_is_refused() {
    // A bare rustls server with the right certificate and no ALPN: the handshake completes, the
    // dial refuses it before tonic writes anything.
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let t1 = rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, "cosigner1", "c1")).unwrap();
    let c2 = leaf(tmp.path(), &ca, "cosigner2", "c2");
    let certs = rustls_pemfile::certs(&mut std::fs::read(&c2.cert).unwrap().as_slice()).collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pemfile::private_key(&mut std::fs::read(&c2.key).unwrap().as_slice()).unwrap().unwrap();
    let server = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let net = MemNet::new();
    let mut incoming = net.listen(&authority(2));
    let served = tokio::spawn(async move {
        use tokio_stream::StreamExt;
        while let Some(Ok(io)) = incoming.next().await {
            if let Ok(mut tls) = acceptor.accept(io).await {
                let mut buf = [0u8; 16];
                let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await;
            }
        }
    });
    let e = dial(&net, &t1, 2, Some(vec![pin(&c2)])).hosted_specs().await.unwrap_err();
    assert!(chain(&e).contains("did not negotiate HTTP/2 (ALPN h2)"), "{}", chain(&e));
    served.abort();
}

#[tokio::test]
async fn a_second_dial_is_checked_again_and_cannot_ride_an_earlier_session() {
    // Resumption is off in the mesh client: the second connection of the same dial, to an impostor
    // now at the address, is a full handshake whose certificate is checked again.
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let t1 = rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, "cosigner1", "c1")).unwrap();
    let real2 = leaf(tmp.path(), &ca, "cosigner2", "real2");
    let fake2 = leaf(tmp.path(), &ca, "cosigner2", "fake2");
    let net = MemNet::new();
    let d = t1.dial_as("cosigner2", Some(vec![pin(&real2)]), 2).unwrap();
    let (_, real) = serve(&net, &authority(2), &rutli_cosigner::tls::load(&real2).unwrap(), node(tmp.path(), 2), None);
    GrpcPeer::connect_lazy_over(Identifier::try_from(2u16).unwrap(), &endpoint(2), &d, d.connector_over(net.dialer()))
        .unwrap()
        .hosted_specs()
        .await
        .unwrap();
    real.abort();
    let (seen, fake) = serve(&net, &authority(2), &rutli_cosigner::tls::load(&fake2).unwrap(), node(tmp.path(), 2), None);
    let again = GrpcPeer::connect_lazy_over(Identifier::try_from(2u16).unwrap(), &endpoint(2), &d, d.connector_over(net.dialer())).unwrap();
    assert!(chain(&again.hosted_specs().await.unwrap_err()).contains("not pinned"));
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    fake.abort();
}

#[tokio::test]
async fn two_pins_carry_a_key_roll_and_dropping_the_old_one_revokes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = ca();
    let c1 = leaf(tmp.path(), &ca, "cosigner1", "c1");
    let old2 = leaf(tmp.path(), &ca, "cosigner2", "old2");
    let new2 = leaf(tmp.path(), &ca, "cosigner2", "new2");
    let t1 = rutli_cosigner::tls::load(&c1).unwrap();
    let both = vec![pin(&old2), pin(&new2)];

    // Node 2 still on its old key, then on its new key: node 1 pins both and reaches either.
    for (cfg, at) in [(&old2, "old"), (&new2, "new")] {
        let net = MemNet::new();
        let (_, server) = serve(&net, &authority(2), &rutli_cosigner::tls::load(cfg).unwrap(), node(tmp.path(), 2), None);
        dial(&net, &t1, 2, Some(both.clone())).hosted_specs().await.unwrap_or_else(|e| panic!("{at}: {e}"));
        server.abort();
    }
    // Node 1 serves; node 2 calls with either key while both are pinned, only the new one after.
    for (pins, old_ok) in [(both.clone(), true), (vec![pin(&new2)], false)] {
        let net = MemNet::new();
        let pins = peer_pins(&[(1, vec![pin(&c1)]), (2, pins)]);
        let (_, server) = serve(&net, &authority(1), &t1, node(tmp.path(), 1), Some(pins));
        let as_old = dial(&net, &rutli_cosigner::tls::load(&old2).unwrap(), 1, Some(vec![pin(&c1)]));
        let as_new = dial(&net, &rutli_cosigner::tls::load(&new2).unwrap(), 1, Some(vec![pin(&c1)]));
        assert_eq!(as_old.hosted_specs().await.is_ok(), old_ok);
        as_new.hosted_specs().await.unwrap();
        server.abort();
    }
}

/// A 2-of-3 mesh on `net`: every node serves its Peer API with the roster's pins and dials its
/// peers through `PeerDial` with them, as the daemon does. With `impostor`, that node's address is
/// served instead by a CA-signed certificate for its name with another key (counted in
/// `impostor_seen`).
struct Mesh {
    nodes: Vec<Arc<Node>>,
    peers: Vec<Peers>,
    impostor_seen: Arc<AtomicUsize>,
    servers: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

impl Drop for Mesh {
    fn drop(&mut self) {
        for h in &self.servers {
            h.abort();
        }
    }
}

fn mesh(impostor: Option<u16>) -> Mesh {
    let net = MemNet::new();
    let ca = ca();
    let tmp = tempfile::tempdir().unwrap();
    let cfgs: Vec<TlsConfig> = (1..=N).map(|i| leaf(tmp.path(), &ca, &format!("cosigner{i}"), &format!("c{i}"))).collect();
    let tls: Vec<Tls> = cfgs.iter().map(|c| rutli_cosigner::tls::load(c).unwrap()).collect();
    let roster: Vec<(u16, Vec<[u8; 32]>)> = (1..=N).map(|i| (i, vec![pin(&cfgs[i as usize - 1])])).collect();
    let pins = peer_pins(&roster);
    let nodes: Vec<Arc<Node>> = (1..=N).map(|i| node(tmp.path(), i)).collect();
    let mut peers = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        let view: Peers = (1..=N)
            .map(|j| {
                if j as usize == i + 1 {
                    Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>
                } else {
                    Arc::new(dial(&net, &tls[i], j, Some(roster[j as usize - 1].1.clone()))) as Arc<dyn PeerApi>
                }
            })
            .collect();
        n.set_mesh(view.clone()).unwrap();
        peers.push(view);
    }
    let mut servers = Vec::new();
    let mut impostor_seen = Arc::new(AtomicUsize::new(0));
    for (i, n) in nodes.iter().enumerate() {
        let id = i as u16 + 1;
        if impostor == Some(id) {
            let fake = rutli_cosigner::tls::load(&leaf(tmp.path(), &ca, &format!("cosigner{id}"), "fake")).unwrap();
            let (seen, h) = serve(&net, &authority(id), &fake, node(&tmp.path().join("impostor"), id), None);
            impostor_seen = seen;
            servers.push(h);
        } else {
            servers.push(serve(&net, &authority(id), &tls[i], n.clone(), Some(pins.clone())).1);
        }
    }
    Mesh { nodes, peers, impostor_seen, servers, _tmp: tmp }
}

#[tokio::test]
async fn a_pinned_mesh_runs_dkg_refresh_and_sign_over_the_daemons_dial() {
    let m = mesh(None);
    let key = "frost-pinned";
    let group = rutli_cosigner::orchestrator::run_dkg(&m.peers[0], key).await.unwrap();
    assert_eq!(rutli_cosigner::orchestrator::run_refresh(&m.peers[1], key).await.unwrap(), group);
    let msg = rutli_frost_core::dealer::canton_test_message(b"pinned mesh");
    let sig = rutli_cosigner::orchestrator::sign(&m.nodes[2], &m.peers[2], key, &msg).await.unwrap();
    assert!(rutli_cosigner::verify_key::signature_verifies(&group, &msg, &sig));
}

#[tokio::test]
async fn a_dkg_with_an_impostor_at_one_nodes_address_delivers_it_nothing() {
    // The share capture pins close: whoever holds the CA key mints `cosigner2` and answers at node
    // 2's address. Every honest node refuses it at the handshake, so no round-2 package, or any
    // other request, reaches it, and the DKG fails instead of handing it node 2's share.
    let m = mesh(Some(2));
    let key = "frost-impostor";
    for leader in [0usize, 2] {
        assert!(rutli_cosigner::orchestrator::run_dkg(&m.peers[leader], key).await.is_err());
    }
    assert_eq!(m.impostor_seen.load(Ordering::SeqCst), 0, "the impostor must receive nothing");
    for i in [0usize, 2] {
        assert!(!m.nodes[i].key_epoch(key).unwrap().present, "node {} must hold no key", i + 1);
    }
}

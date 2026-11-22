// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The accept loop (`rutli_cosigner::accept`) under real mutual TLS on 127.0.0.1: a connection
//! that never starts its handshake is cut at the deadline while the server keeps serving, and a
//! connection whose handshake is done is not cut, however long it then stays idle. The caller's
//! certificate reaches the Peer API through the loop: its CN allowlist and its key pins
//! (`peers[].tls_spki_sha256`) both read it.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use frost_ed25519::Identifier;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rutli_cosigner::config::{PeerConfig, TlsConfig};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::peer::{GrpcPeer, PeerApi};
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::service::{PeerPins, PeerSvc};
use rutli_cosigner::tls::spki_sha256_of_pem_file;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls;

const MASTER: &[u8] = b"accept tls test master secret";
const CLUSTER: &str = "453bb4aea2088bb5";
const DEADLINE: Duration = Duration::from_millis(300);

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name
            .push(DnType::CommonName, "rutli-test-ca");
        Self {
            cert: p.self_signed(&key).unwrap(),
            key,
        }
    }

    fn tls_files(&self, dir: &Path, cn: &str) -> TlsConfig {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        let (cert_path, key_path, ca_path) = (
            dir.join(format!("{cn}.crt")),
            dir.join(format!("{cn}.key")),
            dir.join(format!("{cn}-ca.crt")),
        );
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, self.cert.pem()).unwrap();
        TlsConfig {
            ca_cert: ca_path,
            cert: cert_path,
            key: key_path,
            domain: None,
            allow_expired_ca: false,
            require_peer_pins: None,
        }
    }
}

/// Node 1 serving the Peer API with `server`'s TLS through the accept loop, with a short handshake
/// deadline: its address, and the task to abort.
async fn serve(
    dir: &Path,
    server: &TlsConfig,
    pins: Arc<PeerPins>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let sealer = Arc::new(Sealer::from_master_secret(MASTER, 1));
    let ks = KeyStore::open_with_sealer(dir.join("node-1"), Some(sealer)).unwrap();
    let node = Arc::new(
        Node::new(Identifier::try_from(1u16).unwrap(), 3, 2, ks)
            .with_hosted_keys(MASTER, CLUSTER.to_string())
            .unwrap(),
    );
    let peer_cns: Arc<HashSet<String>> =
        Arc::new((1..=3).map(|i| format!("cosigner{i}")).collect());
    let peer_ids = Arc::new((1..=3u16).map(|i| (format!("cosigner{i}"), i)).collect());
    let svc = PeerSvc {
        node,
        allowed_cns: Some(peer_cns),
        peer_ids: Some(peer_ids),
        peer_pins: Some(pins),
    };
    let server_tls = rutli_cosigner::tls::load(server).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = rutli_cosigner::accept::incoming(
        listener,
        64,
        rutli_cosigner::accept::Deadline::new(DEADLINE, true),
    );
    let serving = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .tls_config(server_tls.server)
            .unwrap()
            .add_service(PeerServer::new(svc))
            .serve_with_incoming(incoming)
            .await;
    });
    (addr, serving)
}

/// The roster's pins as the daemon builds them for `PeerSvc`: `pinned` peers under their key's
/// pin, the other cosigners unpinned.
fn pins(pinned: &[(u16, [u8; 32])]) -> Arc<PeerPins> {
    let mut cfg: rutli_cosigner::config::Config = serde_json::from_str(
        r#"{"identifier":1,"listen":"127.0.0.1:0","threshold":2,"data_dir":"/tmp","peers":[]}"#,
    )
    .unwrap();
    cfg.peers = (1..=3u16)
        .map(|id| {
            let mut p = PeerConfig::new(id, format!("https://cosigner{id}:9100"));
            p.tls_spki_sha256 = pinned
                .iter()
                .find(|(i, _)| *i == id)
                .map(|(_, pin)| vec![hex::encode(pin)]);
            p
        })
        .collect();
    Arc::new(PeerPins::from_config(&cfg).unwrap())
}

fn pin(cfg: &TlsConfig) -> [u8; 32] {
    spki_sha256_of_pem_file(&cfg.cert).unwrap()
}

async fn node_info(addr: std::net::SocketAddr, client: &TlsConfig) -> Result<u16, String> {
    let client_tls = rutli_cosigner::tls::load(client).unwrap();
    let peer = GrpcPeer::connect_lazy(
        Identifier::try_from(1u16).unwrap(),
        &format!("https://{addr}"),
        Some(client_tls.dial_as("cosigner1", None, 1).unwrap()),
    )
    .unwrap();
    peer.node_info()
        .await
        .map(|(id, _)| id)
        .map_err(|e| format!("{e:?}"))
}

/// The client's side of mutual TLS as a bare rustls client (as `tls_probe` builds it).
fn rustls_client(cfg: &TlsConfig) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::fs::read(&cfg.ca_cert).unwrap().as_slice()) {
        roots.add(c.unwrap()).unwrap();
    }
    let certs = rustls_pemfile::certs(&mut std::fs::read(&cfg.cert).unwrap().as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::fs::read(&cfg.key).unwrap().as_slice())
        .unwrap()
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn a_connection_that_never_starts_its_handshake_is_cut_and_the_server_keeps_serving() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Ca::new();
    let (server, client) = (
        ca.tls_files(tmp.path(), "cosigner1"),
        ca.tls_files(tmp.path(), "cosigner2"),
    );
    let (addr, serving) = serve(tmp.path(), &server, pins(&[(2, pin(&client))])).await;

    let mut silent = tokio::net::TcpStream::connect(addr).await.unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(10), silent.read(&mut buf))
        .await
        .expect("the server must cut the connection");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a cut connection, got {read:?}"
    );
    assert!(
        start.elapsed() >= DEADLINE - Duration::from_millis(50),
        "cut at the deadline, not before: {:?}",
        start.elapsed()
    );

    assert_eq!(
        node_info(addr, &client).await,
        Ok(1),
        "the server still serves after cutting it"
    );
    serving.abort();
}

/// One HTTP/2 frame: (type, flags, payload).
async fn read_frame<S: tokio::io::AsyncRead + Unpin>(
    io: &mut S,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let mut head = [0u8; 9];
    io.read_exact(&mut head).await?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok((head[3], head[4], payload))
}

async fn tls_handshake(
    addr: std::net::SocketAddr,
    client: &TlsConfig,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("cosigner1").unwrap();
    rustls_client(client)
        .connect(name, tcp)
        .await
        .expect("the mutual TLS handshake completes")
}

/// A connection whose mutual-TLS handshake is done is not cut, however long it then waits before
/// and after starting HTTP/2: the deadline ends with the handshake (rustls may already hold the
/// client's first HTTP/2 bytes from the handshake's last read, so they cannot be awaited below it).
#[tokio::test]
async fn a_connection_past_its_handshake_is_not_cut_while_idle() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Ca::new();
    let (server, client) = (
        ca.tls_files(tmp.path(), "cosigner1"),
        ca.tls_files(tmp.path(), "cosigner2"),
    );
    let (addr, serving) = serve(tmp.path(), &server, pins(&[(2, pin(&client))])).await;

    let mut tls = tls_handshake(addr, &client).await;
    tokio::time::sleep(DEADLINE * 3).await;
    // The HTTP/2 client preface and an empty SETTINGS frame, then idle again.
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .expect("the connection is still open");
    tls.flush().await.unwrap();
    tokio::time::sleep(DEADLINE * 3).await;
    // PING with an 8-byte payload; the server must still be there to ACK it.
    tls.write_all(b"\x00\x00\x08\x06\x00\x00\x00\x00\x00rutli-ok")
        .await
        .expect("the connection is still open");
    tls.flush().await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (kind, flags, payload) = read_frame(&mut tls)
                .await
                .expect("frames, not a closed connection");
            if kind == 0x6 && flags & 0x1 == 0x1 {
                break payload;
            }
        }
    })
    .await
    .expect("the server answers the PING");
    assert_eq!(ack, b"rutli-ok");
    serving.abort();
}

/// A failed handshake (a client certificate from another CA) does not stop the server, and the
/// caller's certificate still reaches the service through the accept loop (the Peer API's CN
/// allowlist reads it).
#[tokio::test]
async fn a_failed_handshake_does_not_stop_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    let (ca, stranger) = (Ca::new(), Ca::new());
    let server = ca.tls_files(tmp.path(), "cosigner1");
    let client = ca.tls_files(tmp.path(), "cosigner2");
    let foreign_dir = tmp.path().join("foreign");
    std::fs::create_dir_all(&foreign_dir).unwrap();
    let mut foreign = stranger.tls_files(&foreign_dir, "cosigner3");
    foreign.ca_cert = client.ca_cert.clone(); // trusts the server, but the server does not trust it
    let (addr, serving) = serve(tmp.path(), &server, pins(&[(2, pin(&client))])).await;

    for _ in 0..3 {
        assert!(
            node_info(addr, &foreign).await.is_err(),
            "a certificate from another CA is refused"
        );
    }
    assert_eq!(
        node_info(addr, &client).await,
        Ok(1),
        "the server still serves after refused handshakes"
    );
    serving.abort();
}

/// A caller whose certificate the CA signed, with a roster CN, but whose key is not that peer's
/// pin is refused through the accept loop: the pin check sees the certificate the handshake took.
#[tokio::test]
async fn a_peer_key_that_is_not_its_pin_is_refused_through_the_accept_loop() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = Ca::new();
    let server = ca.tls_files(tmp.path(), "cosigner1");
    let client = ca.tls_files(tmp.path(), "cosigner2");
    let (addr, serving) = serve(tmp.path(), &server, pins(&[(2, [9; 32])])).await;

    let refused = node_info(addr, &client).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.contains("PermissionDenied") || e.contains("permission")),
        "a key that is not the peer's pin is refused, got {refused:?}"
    );
    serving.abort();
}

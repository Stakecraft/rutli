// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Mutual-TLS material for the cosigner mesh and the driver→cluster hop.
//!
//! Every node (and the driver) presents a certificate signed by the cluster CA; the CA file holds
//! the trust anchors. The server requires a client cert (`client_ca_root`) — i.e. real mTLS, not
//! server-only TLS — so a peer or client without a cluster-signed cert cannot even open a channel,
//! let alone request a signature.
//!
//! The CA file may hold **several** CA certificates, all of them trust anchors for both the client
//! (`ca_certificate`) and the server (`client_ca_root`) side. That is what makes a zero-downtime CA
//! rotation possible (docs/ca-rotation.md): every node trusts the bundle old+new while leaves are
//! swapped, then the old CA is dropped (`tests/tls_rotation.rs`). rustls makes *every* certificate
//! it is given an anchor — a leaf or an expired CA included — so [`load`] first validates the file
//! ([`crate::trust::load_trust_anchors`]: CA certificates only, valid now) and hands tonic exactly
//! the certificates it validated. Changing the file's bytes changes the CA-derived cluster id, so
//! pin `cluster_id` in the config before the first change.

//!
//! **Peer key pins.** A certificate under the cluster CA with the right name is not enough to be a
//! mesh peer: when a roster entry lists `tls_spki_sha256`, the key in that peer's certificate must
//! be one of them, both when the peer calls this node (`service::PeerSvc::authorize`) and when this
//! node dials the peer ([`PeerDial`]). tonic's own TLS client cannot check a key, so the mesh is
//! dialled through [`PeerDial::connector`]: TCP, the TLS handshake with the same trust anchors,
//! client certificate and server name tonic would use, then the pin, before tonic sees the stream.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{self, pki_types::ServerName};
use tonic::codegen::http::Uri;
use tonic::codegen::Service;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

use crate::config::TlsConfig;
use crate::{DaemonError, Result};

/// The identity a certificate's subject names: its Common Name, **only** if there is exactly one
/// CN attribute and it decodes as a string. Two CNs, or one that does not decode, name nobody —
/// otherwise two parsers could disagree about which one counts. The one rule for every
/// identity decision: the Signer/Peer allowlists (`service::cn_of`) and the split ceremony's
/// request signatures (`request_auth`).
pub fn subject_cn(cert: &x509_parser::certificate::X509Certificate<'_>) -> Option<String> {
    let mut cns = cert.subject().iter_common_name();
    let cn = cns.next()?;
    if cns.next().is_some() {
        return None;
    }
    cn.as_str().ok().map(str::to_string)
}

pub struct Tls {
    /// Client config with `tls.domain` as the server name, if one is configured: for operator
    /// commands dialling a target that is not a roster peer. Never used for the mesh.
    pub client: ClientTlsConfig,
    /// CA + identity, no server name. [`Tls::client_for`] adds the one name a given peer must have.
    client_base: ClientTlsConfig,
    pub server: ServerTlsConfig,
    /// The validated trust anchors of `ca_cert`, in file order — for the startup log.
    pub anchors: Vec<crate::trust::TrustAnchor>,
    /// The same anchors and identity as a rustls client, for [`PeerDial`].
    rustls_client: Arc<rustls::ClientConfig>,
}

impl Tls {
    /// The client config for dialling a server that must present `server_name` (a peer's
    /// [`crate::config::PeerConfig::server_name`]). One per peer: a shared name would let any
    /// cosigner certificate answer for any peer (audit M3).
    pub fn client_for(&self, server_name: &str) -> ClientTlsConfig {
        self.client_base.clone().domain_name(server_name.to_string())
    }

    /// The dial for roster peer `peer`: verified under its [`crate::config::PeerConfig::server_name`]
    /// and, when it has pins, refused unless its certificate key is one of them.
    pub fn peer_dial(&self, peer: &crate::config::PeerConfig) -> Result<PeerDial> {
        self.dial_as(&peer.server_name(), peer.tls_spki_pins()?, peer.identifier)
    }

    /// A dial that verifies the server under `server_name` and, with `pins`, its key; `peer` names
    /// it in errors.
    pub fn dial_as(&self, server_name: &str, pins: Option<Vec<[u8; 32]>>, peer: u16) -> Result<PeerDial> {
        PeerDial::new(self.rustls_client.clone(), server_name, pins, peer)
    }
}

/// Load the CA + this node's identity from disk and build the client/server TLS configs. Refuses a
/// CA file that is not exclusively valid CA certificates ([`crate::trust::load_trust_anchors`];
/// `allow_expired_ca` relaxes only the validity period).
pub fn load(cfg: &TlsConfig) -> Result<Tls> {
    let anchors = crate::trust::load_trust_anchors(&read_pem(&cfg.ca_cert)?, cfg.allow_expired_ca)
        .map_err(|e| {
            crate::DaemonError::Config(format!("tls.ca_cert {}: {e}", cfg.ca_cert.display()))
        })?;
    let ca = Certificate::from_pem(crate::trust::to_pem(&anchors));
    let identity = Identity::from_pem(read_pem(&cfg.cert)?, read_pem(&cfg.key)?);

    let client_base = ClientTlsConfig::new().ca_certificate(ca.clone()).identity(identity.clone());
    let client = match &cfg.domain {
        Some(domain) => client_base.clone().domain_name(domain.clone()),
        None => client_base.clone(),
    };

    let server = ServerTlsConfig::new().identity(identity).client_ca_root(ca);
    let rustls_client = rustls_client(cfg, &anchors)?;

    Ok(Tls { client, client_base, server, anchors, rustls_client })
}

/// The gRPC client's TLS settings as a rustls client: the validated `anchors` of `ca_cert`, this
/// side's certificate and key, the `ring` provider and ALPN `h2` — what tonic builds from the same
/// files. Shared by the mesh dial ([`PeerDial`]) and the TLS probe ([`crate::tls_probe`]).
pub(crate) fn rustls_client(
    cfg: &TlsConfig,
    anchors: &[crate::trust::TrustAnchor],
) -> Result<Arc<rustls::ClientConfig>> {
    let bad = |what: &str, e: &dyn std::fmt::Display| DaemonError::Config(format!("tls {what}: {e}"));
    let mut roots = rustls::RootCertStore::empty();
    for a in anchors {
        roots.add(a.der.clone().into()).map_err(|e| bad("ca_cert", &e))?;
    }
    let certs = rustls_pemfile::certs(&mut read_pem(&cfg.cert)?.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| bad("cert", &e))?;
    let key = rustls_pemfile::private_key(&mut read_pem(&cfg.key)?.as_slice())
        .map_err(|e| bad("key", &e))?
        .ok_or_else(|| bad("key", &"no private key in the file"))?;
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| bad("config", &e))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| bad("cert", &e))?;
    config.alpn_protocols = vec![ALPN_H2.to_vec()];
    // Every connection is a full handshake with the peer's certificate, which the pin check in
    // [`PeerDial::handshake`] reads. No session store, so nothing is ever resumed (a resumed
    // session would carry the certificate of an earlier connection, not one proven in this one),
    // and no 0-RTT early data, which would send request bytes before the server's certificate is
    // even seen. Set explicitly rather than left to rustls's defaults (an in-memory ticket store,
    // early data off).
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

const ALPN_H2: &[u8] = b"h2";

/// SHA-256 of a certificate's SubjectPublicKeyInfo (DER) — the value `peers[].tls_spki_sha256` and
/// `signing_policy.signer_pins` hold, and what `openssl x509 -noout -pubkey | openssl pkey -pubin
/// -outform DER | sha256sum` prints. `None` if `cert_der` is not a certificate.
pub fn spki_sha256(cert_der: &[u8]) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(Sha256::digest(cert.public_key().raw).into())
}

/// The SPKI SHA-256 of the first certificate in a PEM file (a node's `tls.cert`): the pin to list
/// for it.
pub fn spki_sha256_of_pem_file(path: &std::path::Path) -> Result<[u8; 32]> {
    let pem = read_pem(path)?;
    let der = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .ok_or_else(|| DaemonError::Config(format!("{}: no certificate in the file", path.display())))?
        .map_err(|e| DaemonError::Config(format!("{}: {e}", path.display())))?;
    spki_sha256(der.as_ref())
        .ok_or_else(|| DaemonError::Config(format!("{}: not an X.509 certificate", path.display())))
}

/// How this node dials one roster peer: the TLS client (trust anchors, client certificate), the
/// server name the peer must present, and the keys its certificate may carry.
#[derive(Clone)]
pub struct PeerDial {
    config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    /// `None`: the peer is not pinned (only allowed with `tls.require_peer_pins: false`).
    pins: Option<Arc<[[u8; 32]]>>,
    peer: u16,
    /// Bound on TCP connect plus the TLS handshake and pin check ([`PeerDial::connector`]).
    connect_timeout: std::time::Duration,
}

/// Default [`PeerDial`] connect bound: the mesh's per-RPC deadline (`peer::PEER_RPC_TIMEOUT`).
pub const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl PeerDial {
    pub fn new(
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        pins: Option<Vec<[u8; 32]>>,
        peer: u16,
    ) -> Result<Self> {
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| DaemonError::Config(format!("peer {peer} tls_server_name {server_name:?}: {e}")))?;
        Ok(Self { config, server_name, pins: pins.map(Into::into), peer, connect_timeout: DIAL_TIMEOUT })
    }

    /// This dial with another bound on connect plus handshake (default [`DIAL_TIMEOUT`]).
    pub fn with_connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn is_pinned(&self) -> bool {
        self.pins.is_some()
    }

    /// The TLS handshake over `io`, then the checks tonic's own client would make (ALPN `h2`) and
    /// the pin. A certificate whose key is not pinned fails with `PermissionDenied`, naming the
    /// certificate's CN and the key it carries; nothing has been sent to the peer by then.
    pub async fn handshake<IO>(&self, io: IO) -> std::io::Result<tokio_rustls::client::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = tokio_rustls::TlsConnector::from(self.config.clone()).connect(self.server_name.clone(), io).await?;
        let (_, session) = tls.get_ref();
        if session.alpn_protocol() != Some(ALPN_H2) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("peer {} did not negotiate HTTP/2 (ALPN h2)", self.peer),
            ));
        }
        if let Some(pins) = &self.pins {
            let leaf = session.peer_certificates().and_then(|c| c.first()).map(|c| c.as_ref());
            let seen = leaf.and_then(spki_sha256);
            if !seen.is_some_and(|h| pins.contains(&h)) {
                metrics::counter!(crate::metrics::PEER_PIN_REFUSALS, "direction" => "outbound").increment(1);
                let cn = leaf
                    .and_then(|d| x509_parser::parse_x509_certificate(d).ok())
                    .and_then(|(_, c)| subject_cn(&c))
                    .unwrap_or_else(|| "?".into());
                let seen = seen.map(hex::encode).unwrap_or_else(|| "(unreadable certificate)".into());
                let msg = format!(
                    "peer {} presented a certificate for '{cn}' with TLS key sha256 {seen}, which is not \
                     pinned in peers[id={}].tls_spki_sha256 — a stale pin, or not that node",
                    self.peer, self.peer
                );
                tracing::error!(peer = self.peer, %cn, spki_sha256 = %seen, "refused a peer's TLS key (outbound): {msg}");
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg));
            }
        }
        Ok(tls)
    }

    /// Connect to `endpoint` (`https://host:port`), verify the certificate under this dial's
    /// server name and the cluster CA, and return its CN and key pin — whatever this dial's pins
    /// say. For `rutli-cosigner tls spki --peers`; writes nothing to the node.
    pub async fn presented_key(&self, endpoint: &str) -> std::io::Result<(String, [u8; 32])> {
        let other = |m: String| std::io::Error::other(m);
        let uri: Uri = endpoint.parse().map_err(|e| other(format!("bad endpoint {endpoint}: {e}")))?;
        let host = uri.host().ok_or_else(|| other(format!("no host in {endpoint}")))?;
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        let port = uri.port_u16().unwrap_or(443);
        let timeout = std::time::Duration::from_secs(5);
        let unpinned = Self { pins: None, ..self.clone() };
        let tls = tokio::time::timeout(timeout, async {
            let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            unpinned.handshake(tcp).await
        })
        .await
        .map_err(|_| other(format!("no TLS handshake with {endpoint} within {timeout:?}")))??;
        let leaf = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.as_ref().to_vec());
        let leaf = leaf.ok_or_else(|| other("the node presented no certificate".into()))?;
        let key = spki_sha256(&leaf).ok_or_else(|| other("unreadable certificate".into()))?;
        let cn = x509_parser::parse_x509_certificate(&leaf)
            .ok()
            .and_then(|(_, c)| subject_cn(&c))
            .unwrap_or_else(|| "?".into());
        Ok((cn, key))
    }

    /// A tonic connector: TCP to the URI's host and port (nodelay, as tonic dials), then
    /// [`PeerDial::handshake`], the two together bounded by the dial's connect timeout. (tonic's
    /// `Endpoint::connect_timeout` wraps a custom connector too, but this bound does not depend
    /// on every caller setting it.)
    pub fn connector(&self) -> PeerConnector<HttpConnector> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        self.connector_over(http)
    }

    /// [`PeerDial::connector`] over another transport (`inner` yields a connected stream for a
    /// URI): tests run the mesh over in-memory streams with it.
    pub fn connector_over<C>(&self, inner: C) -> PeerConnector<C> {
        PeerConnector { inner, dial: self.clone() }
    }

    /// The tonic endpoint for `endpoint` (`https://host:port`) to use with [`PeerDial::connector`]:
    /// the URI tonic dials is rewritten to `http://` so tonic does not add a TLS layer of its own
    /// (the connector already did), and the original URI is kept as the request origin.
    pub fn endpoint(&self, endpoint: &str) -> Result<tonic::transport::Endpoint> {
        let bad = |e: &dyn std::fmt::Display| DaemonError::Config(format!("bad endpoint {endpoint}: {e}"));
        let origin: Uri = endpoint.parse().map_err(|e| bad(&e))?;
        let authority = origin.authority().ok_or_else(|| bad(&"no host:port"))?.clone();
        let dial = Uri::builder()
            .scheme("http")
            .authority(authority)
            .path_and_query("/")
            .build()
            .map_err(|e| bad(&e))?;
        Ok(tonic::transport::Endpoint::from(dial).origin(origin))
    }
}

/// The tonic connector [`PeerDial::connector`] returns.
#[derive(Clone)]
pub struct PeerConnector<C> {
    inner: C,
    dial: PeerDial,
}

/// The error a [`PeerConnector`] fails with (what tonic takes from a connector).
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<C> Service<Uri> for PeerConnector<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Error: Into<BoxError>,
    TokioIo<C::Response>: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Response = TokioIo<tokio_rustls::client::TlsStream<TokioIo<C::Response>>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connect = self.inner.call(uri);
        let dial = self.dial.clone();
        Box::pin(async move {
            let limit = dial.connect_timeout;
            let connected = tokio::time::timeout(limit, async {
                let io = connect.await.map_err(Into::into)?;
                Ok::<_, BoxError>(TokioIo::new(dial.handshake(TokioIo::new(io)).await?))
            })
            .await;
            match connected {
                Ok(result) => result,
                Err(_) => Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("peer {}: no TCP connection and TLS handshake within {limit:?}", dial.peer),
                )) as BoxError),
            }
        })
    }
}

/// Read a PEM file, reporting *which* file failed and why.
///
/// A bare `Io(PermissionDenied)` from `std::fs::read` is nearly undebuggable in a container: the
/// most common cause is a bind-mounted cert directory whose files are owned by the host user and
/// mode 0600, while the cosigner runs as uid 10001 (Docker Desktop on macOS masks host ownership,
/// so this only bites on Linux). Say so, with the path.
pub(crate) fn read_pem(path: &std::path::Path) -> crate::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
            " — the cosigner runs as uid 10001; a bind-mounted cert file owned by another user \
             with mode 0600 is unreadable to it (see deploy/frost/README.md)"
        } else {
            ""
        };
        crate::DaemonError::Config(format!("cannot read TLS material {}: {e}{hint}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    fn leaf(cn: &str) -> rcgen::Certificate {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        params.self_signed(&key).unwrap()
    }

    #[test]
    fn the_peer_pin_is_the_same_hash_as_the_signer_pin() {
        // One value format for peers[].tls_spki_sha256 and signing_policy.signer_pins.
        let cert = leaf("cosigner2");
        let pin = super::spki_sha256(cert.der()).unwrap();
        assert_eq!(pin, crate::intent::Caller::from_leaf_der(cert.der()).unwrap().spki_sha256);
        assert_eq!(super::spki_sha256(b"not a certificate"), None);
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("c.crt");
        std::fs::write(&path, cert.pem()).unwrap();
        assert_eq!(super::spki_sha256_of_pem_file(&path).unwrap(), pin);
        std::fs::write(&path, "no pem here").unwrap();
        assert!(super::spki_sha256_of_pem_file(&path).unwrap_err().to_string().contains("no certificate"));
    }

    /// A certificate made once with openssl, and the pin the documented command printed for it:
    /// `openssl x509 -in c.crt -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum`.
    const OPENSSL_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBfjCCASSgAwIBAgIUDnzeCvUPk2TR2sdV1KicwuBUwCswCgYIKoZIzj0EAwIw
JDESMBAGA1UEAwwJY29zaWduZXIxMQ4wDAYDVQQKDAVydXRsaTAgFw0yNjExMTgy
MzUxMzlaGA8yMTI2MTAyNTIzNTEzOVowJDESMBAGA1UEAwwJY29zaWduZXIxMQ4w
DAYDVQQKDAVydXRsaTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF5tM2mK12DY
vqfmZVJ+JBYEhtBbU81i8KE6+PZ0WvS8rxhiX2TElJpIB30YjX/+T5dfxDskeVVE
+CrvaNXZvZSjMjAwMB0GA1UdDgQWBBSzxdx8Fjvofoc2ark4FM6ZvefKVDAPBgNV
HRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBpHJc+Dj8g5hCusyDwPRe2E
8kpNmnWxXckQkk0jk2w/AiEAidfcE4M/YRd7dOmmVfJNe0lAiCkPBQ1TTapwmiXi
qeM=
-----END CERTIFICATE-----
";
    const OPENSSL_PIN: &str = "baa26290cac11dd1fc6f6cbcbcb0200ac82b3fd2798be4e5a7aed604e31f378e";

    #[test]
    fn the_pin_is_what_the_documented_openssl_command_prints() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("c.crt");
        std::fs::write(&path, OPENSSL_CERT).unwrap();
        assert_eq!(hex::encode(super::spki_sha256_of_pem_file(&path).unwrap()), OPENSSL_PIN);
        // And the command itself, on a certificate made here, where openssl is installed (the
        // digest by `openssl dgst`, as sha256sum is not everywhere).
        let fresh = leaf("cosigner3");
        std::fs::write(&path, fresh.pem()).unwrap();
        let cmd = format!(
            "openssl x509 -in '{}' -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r",
            path.display()
        );
        match std::process::Command::new("sh").args(["-c", &cmd]).output() {
            Ok(out) if out.status.success() => {
                let printed = String::from_utf8_lossy(&out.stdout);
                let printed = printed.split_whitespace().next().unwrap_or_default().to_string();
                assert_eq!(printed, hex::encode(super::spki_sha256(fresh.der()).unwrap()));
            }
            _ => eprintln!("openssl not available: checked the fixed vector only"),
        }
    }

    #[test]
    fn the_mesh_endpoint_dials_plain_http_and_keeps_the_https_origin() {
        // tonic adds its own TLS layer only for an https URI with a TLS config; the pinned
        // connector has already done the handshake, so the URI tonic dials is http://, and the
        // origin carries the configured one.
        let config = std::sync::Arc::new(
            tokio_rustls::rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );
        let dial = super::PeerDial::new(config.clone(), "cosigner2", Some(vec![[1; 32]]), 2).unwrap();
        assert!(dial.is_pinned());
        let ep = dial.endpoint("https://rutli-node-2.rutli.svc:9101").unwrap();
        assert_eq!(ep.uri().to_string(), "http://rutli-node-2.rutli.svc:9101/");
        assert!(dial.endpoint("not a uri at all").is_err());
        assert!(super::PeerDial::new(config, "", None, 2).is_err(), "an empty server name");
    }

    #[test]
    fn the_mesh_client_never_resumes_and_sends_no_early_data() {
        let tmp = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name.push(rcgen::DnType::CommonName, "ca");
        let ca = ca.self_signed(&key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["cosigner1".to_string()]).unwrap().signed_by(&leaf_key, &ca, &key).unwrap();
        let p = |n: &str| tmp.path().join(n);
        std::fs::write(p("ca.pem"), ca.pem()).unwrap();
        std::fs::write(p("c.pem"), leaf.pem()).unwrap();
        std::fs::write(p("c.key"), leaf_key.serialize_pem()).unwrap();
        let cfg = crate::config::TlsConfig {
            ca_cert: p("ca.pem"),
            cert: p("c.pem"),
            key: p("c.key"),
            domain: None,
            allow_expired_ca: false,
            require_peer_pins: None,
        };
        let anchors = crate::trust::load_trust_anchors(&std::fs::read(p("ca.pem")).unwrap(), false).unwrap();
        let config = super::rustls_client(&cfg, &anchors).unwrap();
        assert!(!config.enable_early_data);
        let disabled = format!("{:?}", tokio_rustls::rustls::client::Resumption::disabled());
        assert_ne!(disabled, format!("{:?}", tokio_rustls::rustls::client::Resumption::default()));
        assert_eq!(format!("{:?}", config.resumption), disabled);
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }
}

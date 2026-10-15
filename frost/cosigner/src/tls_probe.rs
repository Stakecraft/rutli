// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Why did a node refuse us? A bare TLS handshake that reports the node's TLS alert, for
//! `verify-key` (docs/ca-rotation.md, Phase D: an old-CA client certificate must be refused with
//! `UnknownCA`, which tells "old CA refused" from "node down").
//!
//! tonic cannot be relied on to say. In TLS 1.3 the client's handshake is complete as soon as it
//! has *sent* its certificate; the server checks it afterwards and answers with an alert and a
//! close. By then the gRPC client is already writing the HTTP/2 preface and the request, and which
//! error the RPC fails with depends on timing: the alert (`received fatal alert: UnknownCA`) if
//! the connection task reads it while the request is in flight, but `Cancelled: operation was
//! canceled: … connection closed` if the connection died before the request reached it, or
//! `connection closed because of a broken pipe` if the write hit the closed socket first. (About
//! half of all runs locally, either way.)
//!
//! [`TlsProbe::refusal`] removes the race: it connects with the same trust anchors, client
//! certificate and server name as the gRPC client, completes the handshake, **writes nothing**, and
//! reads until the node either sends data (it accepted us: no TLS-level refusal) or fails the read
//! (its alert, or a reset). Nothing written, nothing to race with.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio_rustls::rustls::{self, pki_types::ServerName};

use crate::config::TlsConfig;
use crate::{DaemonError, Result};

/// How long the probe waits for TCP connect, and then for the handshake plus the node's first
/// bytes. A node that accepts the client sends its HTTP/2 SETTINGS at once.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TlsProbe {
    config: Arc<rustls::ClientConfig>,
    domain: Option<String>,
}

impl TlsProbe {
    /// The gRPC client's TLS settings ([`crate::tls::load`]) as a rustls client: the validated
    /// trust anchors of `ca_cert`, this side's certificate and key, ALPN `h2`, and `domain` as the
    /// server name when set.
    pub fn new(cfg: &TlsConfig) -> Result<Self> {
        let bad = |what: &str, e: &dyn std::fmt::Display| DaemonError::Config(format!("tls probe {what}: {e}"));
        let anchors = crate::trust::load_trust_anchors(&crate::tls::read_pem(&cfg.ca_cert)?, cfg.allow_expired_ca)
            .map_err(|e| bad("ca_cert", &e))?;
        let mut roots = rustls::RootCertStore::empty();
        for a in anchors {
            roots.add(a.der.into()).map_err(|e| bad("ca_cert", &e))?;
        }
        let certs = rustls_pemfile::certs(&mut crate::tls::read_pem(&cfg.cert)?.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| bad("cert", &e))?;
        let key = rustls_pemfile::private_key(&mut crate::tls::read_pem(&cfg.key)?.as_slice())
            .map_err(|e| bad("key", &e))?
            .ok_or_else(|| bad("key", &"no private key in the file"))?;
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| bad("config", &e))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| bad("cert", &e))?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self { config: Arc::new(config), domain: cfg.domain.clone() })
    }

    /// Connect to `endpoint` (`https://host:port`) and report how the node refuses this client at
    /// the TLS layer: the handshake error, or the error reading after a completed handshake (the
    /// node's alert, e.g. `received fatal alert: UnknownCA`). `None` when the node accepts the
    /// client, or cannot be reached at all (the RPC error already says so), or does not answer.
    pub async fn refusal(&self, endpoint: &str) -> Option<String> {
        let uri: tonic::codegen::http::Uri = endpoint.parse().ok()?;
        let host = uri.host()?.trim_start_matches('[').trim_end_matches(']').to_string();
        let port = uri.port_u16().unwrap_or(443);
        let name = ServerName::try_from(self.domain.clone().unwrap_or_else(|| host.clone())).ok()?;
        let tcp = tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect((host.as_str(), port)))
            .await
            .ok()?
            .ok()?;
        let connector = tokio_rustls::TlsConnector::from(self.config.clone());
        let outcome = tokio::time::timeout(PROBE_TIMEOUT, async {
            let mut tls = match connector.connect(name, tcp).await {
                Ok(tls) => tls,
                Err(e) => return Some(format!("handshake failed: {e}")),
            };
            let mut buf = [0u8; 64];
            match tls.read(&mut buf).await {
                Ok(0) => Some("the node closed the connection after the handshake".into()),
                Ok(_) => None,
                Err(e) => Some(format!("refused after the handshake: {e}")),
            }
        })
        .await;
        outcome.ok().flatten()
    }
}

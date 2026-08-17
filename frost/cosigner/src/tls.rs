// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Mutual-TLS material for the cosigner mesh and the driver→cluster hop.
//!
//! Every node (and the driver) presents a certificate signed by one cluster CA; that CA is the sole
//! trust anchor. The server requires a client cert (`client_ca_root`) — i.e. real mTLS, not
//! server-only TLS — so a peer or client without a cluster-signed cert cannot even open a channel,
//! let alone request a signature.

use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

use crate::config::TlsConfig;
use crate::Result;

pub struct Tls {
    pub client: ClientTlsConfig,
    pub server: ServerTlsConfig,
}

/// Load the CA + this node's identity from disk and build the client/server TLS configs.
pub fn load(cfg: &TlsConfig) -> Result<Tls> {
    let ca = Certificate::from_pem(read_pem(&cfg.ca_cert)?);
    let identity = Identity::from_pem(read_pem(&cfg.cert)?, read_pem(&cfg.key)?);

    let mut client = ClientTlsConfig::new().ca_certificate(ca.clone()).identity(identity.clone());
    if let Some(domain) = &cfg.domain {
        client = client.domain_name(domain.clone());
    }

    let server = ServerTlsConfig::new().identity(identity).client_ca_root(ca);

    Ok(Tls { client, server })
}

/// Read a PEM file, reporting *which* file failed and why.
///
/// A bare `Io(PermissionDenied)` from `std::fs::read` is nearly undebuggable in a container: the
/// most common cause is a bind-mounted cert directory whose files are owned by the host user and
/// mode 0600, while the cosigner runs as uid 10001 (Docker Desktop on macOS masks host ownership,
/// so this only bites on Linux). Say so, with the path.
fn read_pem(path: &std::path::Path) -> crate::Result<Vec<u8>> {
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

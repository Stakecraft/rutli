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
    let ca = Certificate::from_pem(std::fs::read(&cfg.ca_cert)?);
    let identity = Identity::from_pem(std::fs::read(&cfg.cert)?, std::fs::read(&cfg.key)?);

    let mut client = ClientTlsConfig::new().ca_certificate(ca.clone()).identity(identity.clone());
    if let Some(domain) = &cfg.domain {
        client = client.domain_name(domain.clone());
    }

    let server = ServerTlsConfig::new().identity(identity).client_ca_root(ca);

    Ok(Tls { client, server })
}

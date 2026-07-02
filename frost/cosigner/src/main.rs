// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Rütli FROST cosigner daemon entrypoint.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use clap::Parser;
use frost_ed25519::Identifier;

use rutli_cosigner::config::Config;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::pb::signer_server::SignerServer;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi};
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use rutli_cosigner::{DaemonError, Result};

#[derive(Parser)]
#[command(name = "rutli-cosigner", about = "FROST cosigner daemon for the Rütli Canton KMS")]
struct Args {
    /// Path to the JSON cluster config for this node.
    #[arg(short, long, env = "RUTLI_COSIGNER_CONFIG")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let cfg = Config::load(&args.config)?;
    tracing::info!(identifier = cfg.identifier, listen = %cfg.listen, "starting cosigner");

    let identifier = ident(cfg.identifier)?;
    let keystore = KeyStore::open(cfg.data_dir.join("keys"))?;
    let node = Arc::new(Node::new(identifier, cfg.max_signers(), cfg.threshold, keystore));

    // Build the peer roster: this node as a local peer, every other as a lazy gRPC client.
    let mut peers: Vec<Arc<dyn PeerApi>> = Vec::new();
    for p in &cfg.peers {
        if p.identifier == cfg.identifier {
            peers.push(Arc::new(LocalPeer::new(node.clone())));
        } else {
            peers.push(Arc::new(GrpcPeer::connect_lazy(ident(p.identifier)?, &p.endpoint)?));
        }
    }
    peers.sort_by_key(|p| identifier_index(p.identifier()));

    let signer = SignerSvc { node: node.clone(), peers };
    let peer = PeerSvc { node };

    let addr = cfg
        .listen
        .parse()
        .map_err(|e| DaemonError::Config(format!("bad listen addr {}: {e}", cfg.listen)))?;
    tracing::info!(%addr, "gRPC serving Signer + Peer");

    tonic::transport::Server::builder()
        .add_service(SignerServer::new(signer))
        .add_service(PeerServer::new(peer))
        .serve_with_shutdown(addr, shutdown())
        .await?;
    Ok(())
}

fn ident(id: u16) -> Result<Identifier> {
    Identifier::try_from(id).map_err(DaemonError::Frost)
}

/// Stable ordering key for peers (identifiers serialize to fixed-width big-endian bytes).
fn identifier_index(id: Identifier) -> Vec<u8> {
    id.serialize()
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

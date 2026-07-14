// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Rütli FROST cosigner daemon entrypoint.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use clap::{Parser, Subcommand};
use frost_ed25519::Identifier;

use rutli_cosigner::config::Config;
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::pb::peer_server::PeerServer;
use rutli_cosigner::pb::signer_client::SignerClient;
use rutli_cosigner::pb::signer_server::SignerServer;
use rutli_cosigner::pb::RefreshRequest;
use rutli_cosigner::peer::{GrpcPeer, LocalPeer, PeerApi};
use rutli_cosigner::service::{PeerSvc, SignerSvc};
use rutli_cosigner::{DaemonError, Result};

#[derive(Parser)]
#[command(name = "rutli-cosigner", about = "FROST cosigner daemon for the Rütli Canton KMS")]
struct Args {
    /// Path to the JSON cluster config for this node.
    #[arg(short, long, env = "RUTLI_COSIGNER_CONFIG")]
    config: std::path::PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the cosigner daemon (default).
    Serve,
    /// Trigger a proactive share refresh for a key against a running cluster, then exit.
    Refresh {
        /// The FROST key id to refresh (e.g. frost-participant1-namespace).
        #[arg(long)]
        key_id: String,
        /// Signer endpoint to drive the refresh (default: the first peer in the roster).
        #[arg(long)]
        target: Option<String>,
    },
    /// Copy this node's (sealed) key shares to a backup directory. Run with the node stopped.
    Backup {
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Restore this node's key shares from a backup directory. Run with the node stopped.
    Restore {
        #[arg(long)]
        from: std::path::PathBuf,
        /// Overwrite existing share files.
        #[arg(long)]
        force: bool,
    },
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

    match args.command {
        Some(Command::Refresh { key_id, target }) => return refresh_command(&cfg, &key_id, target).await,
        Some(Command::Backup { out }) => return backup_command(&cfg, &out),
        Some(Command::Restore { from, force }) => return restore_command(&cfg, &from, force),
        _ => {}
    }
    tracing::info!(identifier = cfg.identifier, listen = %cfg.listen, "starting cosigner");

    let identifier = ident(cfg.identifier)?;

    // Share sealing: encryption-at-rest for key shares, keyed from an operator-injected secret.
    let sealer = match &cfg.share_seal {
        Some(seal_cfg) => {
            tracing::info!(env = %seal_cfg.secret_env, "share sealing enabled (AES-256-GCM at rest)");
            Some(Arc::new(rutli_cosigner::seal::Sealer::from_env(
                &seal_cfg.secret_env,
                cfg.identifier,
            )?))
        }
        None => {
            tracing::warn!("share sealing DISABLED — key shares stored as plaintext JSON (dev only)");
            None
        }
    };

    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), sealer)?;
    let node = Arc::new(Node::new(identifier, cfg.max_signers(), cfg.threshold, keystore));

    // Load mTLS material once (if configured). Plaintext otherwise (dev only).
    let tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?;
    if tls.is_some() {
        tracing::info!("mutual TLS enabled (cluster CA trust anchor)");
    } else {
        tracing::warn!("running WITHOUT TLS — plaintext gRPC, do not use in production");
    }

    // Build the peer roster: this node as a local peer, every other as a lazy gRPC client.
    let mut peers: Vec<Arc<dyn PeerApi>> = Vec::new();
    for p in &cfg.peers {
        if p.identifier == cfg.identifier {
            peers.push(Arc::new(LocalPeer::new(node.clone())));
        } else {
            let client_tls = tls.as_ref().map(|t| t.client.clone());
            peers.push(Arc::new(GrpcPeer::connect_lazy(ident(p.identifier)?, &p.endpoint, client_tls)?));
        }
    }
    peers.sort_by_key(|p| identifier_index(p.identifier()));

    let allowed_cns = cfg.signer_allowlist.as_ref().map(|v| {
        Arc::new(v.iter().cloned().collect::<std::collections::HashSet<String>>())
    });
    match &allowed_cns {
        Some(cns) => tracing::info!(?cns, "Signer API restricted to allowlisted client CNs"),
        None => tracing::warn!(
            "Signer API has no client allowlist — any cluster-CA cert may request signatures; \
             set signer_allowlist (e.g. the driver cert CN) in production"
        ),
    }

    let signer = SignerSvc { node: node.clone(), peers, allowed_cns };
    let peer = PeerSvc { node };

    let addr = cfg
        .listen
        .parse()
        .map_err(|e| DaemonError::Config(format!("bad listen addr {}: {e}", cfg.listen)))?;
    tracing::info!(%addr, "gRPC serving Signer + Peer");

    let mut server = tonic::transport::Server::builder();
    if let Some(t) = &tls {
        server = server.tls_config(t.server.clone())?;
    }
    server
        .add_service(SignerServer::new(signer))
        .add_service(PeerServer::new(peer))
        .serve_with_shutdown(addr, shutdown())
        .await?;
    Ok(())
}

/// Operator command: connect to a running cosigner and drive a proactive refresh.
async fn refresh_command(cfg: &Config, key_id: &str, target: Option<String>) -> Result<()> {
    let endpoint = target
        .or_else(|| cfg.peers.iter().find(|p| p.identifier != cfg.identifier).map(|p| p.endpoint.clone()))
        .or_else(|| cfg.peers.first().map(|p| p.endpoint.clone()))
        .ok_or_else(|| DaemonError::Config("no target endpoint for refresh".into()))?;

    let mut ep = tonic::transport::Endpoint::from_shared(endpoint.clone())
        .map_err(|e| DaemonError::Config(format!("bad endpoint {endpoint}: {e}")))?;
    if let Some(tls_cfg) = &cfg.tls {
        ep = ep.tls_config(rutli_cosigner::tls::load(tls_cfg)?.client)?;
    }
    tracing::info!(%endpoint, %key_id, "triggering proactive share refresh");
    let mut client = SignerClient::new(ep.connect().await?);
    let reply = client.refresh(RefreshRequest { key_id: key_id.to_string() }).await?.into_inner();
    println!(
        "refresh complete — group key unchanged: {}",
        hex::encode(reply.group_verifying_key)
    );
    Ok(())
}

/// Back up the (sealed) key-share files from data_dir/keys to `out`. Shares are encrypted at rest
/// when sealing is enabled, so the backup carries no plaintext key material.
fn backup_command(cfg: &Config, out: &std::path::Path) -> Result<()> {
    let src = cfg.data_dir.join("keys");
    std::fs::create_dir_all(out)?;
    let n = copy_dir_files(&src, out, true)?;
    println!("backed up {n} share file(s) from {} to {}", src.display(), out.display());
    if cfg.share_seal.is_none() {
        tracing::warn!("shares are NOT sealed — this backup contains plaintext key shares");
    }
    Ok(())
}

/// Restore key-share files from `from` into data_dir/keys.
fn restore_command(cfg: &Config, from: &std::path::Path, force: bool) -> Result<()> {
    let dst = cfg.data_dir.join("keys");
    std::fs::create_dir_all(&dst)?;
    let n = copy_dir_files(from, &dst, force)?;
    println!("restored {n} share file(s) from {} to {}", from.display(), dst.display());
    Ok(())
}

/// Copy regular files from `src` to `dst`. When `!overwrite`, existing destination files are an
/// error (so a restore never clobbers a live share by accident).
fn copy_dir_files(src: &std::path::Path, dst: &std::path::Path, overwrite: bool) -> Result<usize> {
    if !src.is_dir() {
        return Err(DaemonError::Config(format!("{} is not a directory", src.display())));
    }
    let mut count = 0;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let target = dst.join(entry.file_name());
            if target.exists() && !overwrite {
                return Err(DaemonError::Config(format!(
                    "{} exists; pass --force to overwrite",
                    target.display()
                )));
            }
            std::fs::copy(entry.path(), &target)?;
            count += 1;
        }
    }
    Ok(count)
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

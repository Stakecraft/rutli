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
    /// Export ONE cluster-hosted key as a portable artifact. Run with the node stopped.
    ///
    /// Unlike `backup` (sealed with this cluster's master secret, restorable only onto this node),
    /// an export is portable: it can be imported into a different cluster, and it survives the loss
    /// of the seal master secret. That also makes it as dangerous as the key itself, so it is
    /// passphrase-protected unless you explicitly ask otherwise.
    ///
    /// FROST shares cannot be exported — no single node holds a whole namespace key.
    ExportKey {
        /// The hosted key to export (a `rutli-…` key id).
        #[arg(long)]
        key_id: String,
        /// File to write the export artifact to.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Env var holding the passphrase that protects the artifact (Argon2id + AES-256-GCM).
        #[arg(long, conflicts_with = "unsafe_plaintext")]
        passphrase_env: Option<String>,
        /// Write the private key UNENCRYPTED. Only for piping straight into another KMS/HSM import
        /// tool on a trusted host — the file is the key.
        #[arg(long)]
        unsafe_plaintext: bool,
    },
    /// Import a cluster-hosted key from an export artifact. Run with the node stopped.
    ///
    /// The key is written to this node only; once the daemon starts, anti-entropy replicates it to
    /// the rest of the cluster.
    ImportKey {
        /// The export artifact to read.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Env var holding the passphrase, for an encrypted artifact.
        #[arg(long)]
        passphrase_env: Option<String>,
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
        Some(Command::ExportKey { key_id, out, passphrase_env, unsafe_plaintext }) => {
            return export_key_command(&cfg, &key_id, &out, passphrase_env.as_deref(), unsafe_plaintext)
        }
        Some(Command::ImportKey { r#in, passphrase_env }) => {
            return import_key_command(&cfg, &r#in, passphrase_env.as_deref())
        }
        Some(Command::Restore { from, force }) => return restore_command(&cfg, &from, force),
        _ => {}
    }
    tracing::info!(identifier = cfg.identifier, listen = %cfg.listen, "starting cosigner");

    // Prometheus /metrics endpoint (opt-in). Operation counts/latencies only — no key material.
    if let Some(metrics_listen) = &cfg.metrics_listen {
        rutli_cosigner::metrics::install(metrics_listen)?;
        tracing::info!(listen = %metrics_listen, "Prometheus metrics endpoint serving /metrics");
    }

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
    match keystore.reseal_plaintext_shares()? {
        0 => {}
        n => tracing::info!(count = n, "migrated legacy plaintext shares to sealed envelopes"),
    }
    let mut node = Node::new(identifier, cfg.max_signers(), cfg.threshold, keystore);

    // Cluster-hosted (non-FROST) keys. The wrapping key and the at-rest seal key both come from the
    // same operator master secret, so hosted keys require share_seal (enforced by config
    // validation) — a hosted key is a whole private key and must never sit unsealed on disk.
    if cfg.hosted_keys.as_ref().map(|h| h.enabled).unwrap_or(false) {
        let seal_cfg = cfg.share_seal.as_ref().expect("validate() requires share_seal");
        let master = std::env::var(&seal_cfg.secret_env).map_err(|_| {
            DaemonError::Config(format!("hosted keys enabled but {} is not set", seal_cfg.secret_env))
        })?;
        // Bind envelopes to this trust domain: derived from the CA cert, so it changes if the
        // cluster does and an envelope can never be replayed into a different deployment.
        let cluster_id = match &cfg.tls {
            Some(t) => rutli_cosigner::wrap::cluster_id_from_ca(&std::fs::read(&t.ca_cert)?),
            None => "plaintext-dev".to_string(),
        };
        node = node.with_hosted_keys(master.as_bytes(), cluster_id);
        tracing::info!("cluster-hosted keys enabled (RSA-2048 encryption + AES-256-GCM symmetric)");
    }
    let node = Arc::new(node);

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

    let peer_cns = cfg.peer_allowlist.as_ref().map(|v| {
        Arc::new(v.iter().cloned().collect::<std::collections::HashSet<String>>())
    });
    match &peer_cns {
        Some(cns) => tracing::info!(?cns, "mesh Peer API restricted to allowlisted cosigner CNs"),
        None => tracing::warn!(
            "Peer API has no client allowlist — any cluster-CA cert (including the driver's) may \
             drive the raw FROST rounds and could aggregate a signature over an arbitrary message; \
             set peer_allowlist (the cosigner cert CNs) in production"
        ),
    }

    // Anti-entropy: pull hosted keys this node lacks and push ones a peer lacks. This is what
    // heals an under-quorum write and a node restored from a stale backup, so the 2-of-3 write
    // quorum is only safe with it running.
    if let Some(h) = cfg.hosted_keys.as_ref().filter(|h| h.enabled) {
        let (sweep_node, sweep_peers) = (node.clone(), peers.clone());
        let interval = std::time::Duration::from_secs(h.anti_entropy_interval_secs.max(10));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match rutli_cosigner::orchestrator::anti_entropy_sweep(&sweep_node, &sweep_peers).await {
                    Ok((0, 0)) => {}
                    Ok((pulled, pushed)) => {
                        tracing::info!(pulled, pushed, "anti-entropy reconciled hosted keys")
                    }
                    Err(e) => tracing::warn!(error = %e, "anti-entropy sweep failed"),
                }
            }
        });
    }

    let hosted_write_quorum = cfg
        .hosted_keys
        .as_ref()
        .map(|h| h.write_quorum)
        .unwrap_or(rutli_cosigner::orchestrator::DEFAULT_WRITE_QUORUM);
    let decrypt_limit = cfg
        .hosted_keys
        .as_ref()
        .map(|h| h.decrypt_rate_limit_per_min)
        .unwrap_or(rutli_cosigner::config::DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN);
    if decrypt_limit == 0 {
        tracing::warn!(
            "hosted-key decryption rate limiting is DISABLED — a stolen driver certificate can \
             bulk-decrypt recorded traffic at line rate; set hosted_keys.decrypt_rate_limit_per_min"
        );
    } else {
        tracing::info!(per_key_per_min = decrypt_limit, "hosted-key decryption rate limit active");
    }
    let decrypt_limiter = Arc::new(rutli_cosigner::ratelimit::DecryptRateLimiter::new(decrypt_limit));

    let signer = SignerSvc {
        node: node.clone(),
        peers,
        allowed_cns,
        hosted_write_quorum,
        decrypt_limiter,
    };
    let peer = PeerSvc { node, allowed_cns: peer_cns };

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

/// Open this node's keystore for an offline command (export/import), with sealing configured.
///
/// Hosted keys are always sealed at rest, so the seal secret is required — which is exactly the
/// second factor that makes these commands safe as CLI operations: host access alone is not enough.
fn offline_keystore(cfg: &Config) -> Result<KeyStore> {
    let seal_cfg = cfg.share_seal.as_ref().ok_or_else(|| {
        DaemonError::Config(
            "share_seal is not configured — cluster-hosted keys are always sealed, so there is \
             nothing for this command to open"
                .into(),
        )
    })?;
    let sealer =
        Arc::new(rutli_cosigner::seal::Sealer::from_env(&seal_cfg.secret_env, cfg.identifier)?);
    KeyStore::open_with_sealer(cfg.data_dir.join("keys"), Some(sealer))
}

/// Operator command: write one hosted key out as a portable artifact.
fn export_key_command(
    cfg: &Config,
    key_id: &str,
    out: &std::path::Path,
    passphrase_env: Option<&str>,
    unsafe_plaintext: bool,
) -> Result<()> {
    let keystore = offline_keystore(cfg)?;
    // load_hosted refuses a FROST share, so this is also the guard against exporting one.
    let key = keystore.load_hosted(key_id).map_err(|e| match e {
        DaemonError::UnknownKey(k) => DaemonError::Config(format!(
            "no such hosted key on this node: {k} (FROST shares cannot be exported — no single \
             node holds a whole namespace key)"
        )),
        other => other,
    })?;

    let envelope = if unsafe_plaintext {
        tracing::warn!(
            key_id,
            path = %out.display(),
            "writing an UNENCRYPTED private key — this file IS the key; move it to an HSM or \
             offline media and shred the copy"
        );
        rutli_cosigner::export::export_plaintext(key_id, &key)?
    } else {
        let env_name = passphrase_env.ok_or_else(|| {
            DaemonError::Config(
                "pass --passphrase-env NAME (the env var holding the export passphrase), or \
                 --unsafe-plaintext if you really want the key in the clear"
                    .into(),
            )
        })?;
        let passphrase = std::env::var(env_name).map_err(|_| {
            DaemonError::Config(format!("export passphrase: env var {env_name} is not set"))
        })?;
        rutli_cosigner::export::export_encrypted(key_id, &key, &passphrase)?
    };

    // 0600 before any bytes land: an export must never be briefly world-readable.
    write_private_file(out, &serde_json::to_vec_pretty(&envelope)?)?;
    // Deliberately audible in the node's log: an export is a privileged, rare event, and the log is
    // often the only record that a portable copy of a key now exists.
    tracing::warn!(
        key_id,
        path = %out.display(),
        encrypted = !unsafe_plaintext,
        "EXPORTED a cluster-hosted key — a portable copy of this private key now exists outside \
         the cluster; treat the artifact as the key itself"
    );
    println!(
        "exported {key_id} -> {} ({})",
        out.display(),
        if unsafe_plaintext { "UNENCRYPTED" } else { "passphrase-protected" }
    );
    Ok(())
}

/// Operator command: read a portable artifact back into this node's keystore.
fn import_key_command(
    cfg: &Config,
    input: &std::path::Path,
    passphrase_env: Option<&str>,
) -> Result<()> {
    let keystore = offline_keystore(cfg)?;
    let envelope: rutli_cosigner::export::ExportEnvelope =
        serde_json::from_slice(&std::fs::read(input)?)?;

    let passphrase = match passphrase_env {
        Some(name) => Some(std::env::var(name).map_err(|_| {
            DaemonError::Config(format!("import passphrase: env var {name} is not set"))
        })?),
        None => None,
    };
    let key = rutli_cosigner::export::import(&envelope, passphrase.as_deref())?;
    let key_id = envelope.key_id.clone();

    // Hosted keys are create-once-immutable: a key id maps to one key forever, because Canton
    // rotates by minting a new id. Overwriting could destroy material the cluster already
    // committed to, so refuse unless it is byte-identical.
    if keystore.exists(&key_id) {
        let existing = keystore.load_hosted(&key_id)?;
        if existing.private_der != key.private_der {
            return Err(DaemonError::KeyExists(format!(
                "{key_id} already exists on this node with different material — refusing to \
                 overwrite. Rotate to a new key id instead."
            )));
        }
        println!("{key_id} is already present here and identical — nothing to do");
        return Ok(());
    }

    keystore.save_hosted(&key_id, &key)?;
    tracing::warn!(key_id = %key_id, path = %input.display(), "IMPORTED a cluster-hosted key");
    println!(
        "imported {key_id} ({}) — start the daemon; anti-entropy will replicate it to the cluster",
        key.spec.as_str()
    );
    Ok(())
}

/// Create `path` with owner-only permissions BEFORE writing, so the contents are never briefly
/// readable by other users on the host.
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
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

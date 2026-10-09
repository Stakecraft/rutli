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
    /// Reads either a Rütli `export-key` artifact (JSON) or an existing Canton node's EC P-256
    /// encryption key — `ExportKeyPair` / `keys.secret.download` output, plain or
    /// password-protected — which migrates the node without rotating its encryption key. A Canton
    /// key needs --key-id and --expect-fingerprint. The key is written to this node only; once the
    /// daemon starts, anti-entropy replicates it to the rest of the cluster.
    ImportKey {
        /// The export artifact to read.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// Env var holding the passphrase of an encrypted Rütli artifact, or the password of a
        /// password-protected Canton export.
        #[arg(long)]
        passphrase_env: Option<String>,
        /// Canton input only: the hosted key id to create, `<frost.key-prefix>rutli-…` (the driver
        /// routes only ids carrying its prefix and the `rutli-` tag), e.g. `rutli-enc-imported-1`.
        #[arg(long)]
        key_id: Option<String>,
        /// Canton input only: the key's Canton fingerprint (`1220…`), taken from the old node
        /// (`keys.secret.list`), not from the file. Any other key is refused.
        #[arg(long)]
        expect_fingerprint: Option<String>,
        /// Canton input only: the participant's `frost.key-prefix`; --key-id must then start with
        /// `<key-prefix>rutli-`. Without it the prefix is inferred and printed.
        #[arg(long)]
        key_prefix: Option<String>,
    },
    /// Readiness check for container probes (k8s exec readinessProbe, compose healthcheck): the key
    /// store under `data_dir/keys` can be listed, opened and written, and this node's gRPC port
    /// accepts connections. Prints `ready` (exit 0) or the reason (exit 1). Needs no seal secret.
    Health,
    /// Restore this node's key shares from a backup directory. Run with the node stopped.
    Restore {
        #[arg(long)]
        from: std::path::PathBuf,
        /// Overwrite existing share files.
        #[arg(long)]
        force: bool,
    },
    /// Split ceremony, step 1 (docs/split-ceremony.md): mint this node's one-time recipient key for
    /// an imported key and write the public request the dealer needs. The secret half stays here,
    /// sealed, until import-share installs the share. Needs share_seal.
    ShareRecipient {
        /// The id the imported key will have: `<prefix>frost-import-<name>`.
        #[arg(long)]
        key_id: String,
        /// An id for this ceremony, the same on every node (e.g. `b2-2026-10-20`).
        #[arg(long)]
        ceremony_id: String,
        /// Where to write the public request (refuses to overwrite unless --replace).
        #[arg(long)]
        out: std::path::PathBuf,
        /// Discard a pending recipient for this key; any bundle made for it will no longer open.
        #[arg(long)]
        replace: bool,
    },
    /// Split ceremony, Gate 0: print the SAS of this node's PENDING recipient request, read from
    /// the sealed recipient file (not from any request file). Read-only. Witnesses run it in their
    /// own session to check the SAS the dealer is given.
    RecipientSas {
        #[arg(long)]
        key_id: String,
    },
    /// Split ceremony: verify this node's share bundle and install it (never overwrites a key).
    /// Offline only — there is no RPC for this. Safe against a stopped node or inside the live pod.
    ImportShare {
        /// The dealer's `share-<key_id>-node<identifier>.json` for this node.
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// The Canton fingerprint (`1220…`) of the key being imported, from the old node — not from
        /// the bundle. The import refuses any other key.
        #[arg(long)]
        expect_fingerprint: String,
        /// Run every check, install nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Split ceremony: back out on this node. Deletes the pending recipient secret. Deletes an
    /// installed share only if it came from this ceremony, was never refreshed, and
    /// --yes-delete-installed-share is given. Restart the daemon afterwards if it was running.
    AbortImport {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        ceremony_id: String,
        #[arg(long)]
        yes_delete_installed_share: bool,
    },
    /// Check that every cosigner in the roster holds a consistent share of a FROST key with the
    /// expected Canton fingerprint; with --sign-test (imported keys), also that EVERY t-subset of
    /// cosigners signs the ceremony test digest, verified under it. Runs against the live cluster
    /// with an operator certificate (`operator_allowlist`: KeyStatus + CeremonySignTest only, no
    /// Sign); the driver certificate also works. Exits non-zero on any problem.
    VerifyKey {
        #[arg(long)]
        key_id: String,
        /// The Canton fingerprint (`1220…`) the key must have.
        #[arg(long)]
        expect_fingerprint: String,
        /// Have every node lead one signature over a domain-separated test digest.
        #[arg(long)]
        sign_test: bool,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
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
        Some(Command::ImportKey { r#in, passphrase_env, key_id, expect_fingerprint, key_prefix }) => {
            return import_key_command(
                &cfg,
                &r#in,
                passphrase_env.as_deref(),
                key_id.as_deref(),
                expect_fingerprint.as_deref(),
                key_prefix.as_deref(),
            )
        }
        Some(Command::Restore { from, force }) => return restore_command(&cfg, &from, force),
        Some(Command::ShareRecipient { key_id, ceremony_id, out, replace }) => {
            return share_recipient_command(&cfg, &key_id, &ceremony_id, &out, replace)
        }
        Some(Command::RecipientSas { key_id }) => return recipient_sas_command(&cfg, &key_id),
        Some(Command::ImportShare { r#in, expect_fingerprint, dry_run }) => {
            return import_share_command(&cfg, &r#in, &expect_fingerprint, dry_run)
        }
        Some(Command::AbortImport { key_id, ceremony_id, yes_delete_installed_share }) => {
            return abort_import_command(&cfg, &key_id, &ceremony_id, yes_delete_installed_share)
        }
        Some(Command::VerifyKey { key_id, expect_fingerprint, sign_test, json }) => {
            return verify_key_command(&cfg, &key_id, &expect_fingerprint, sign_test, json).await
        }
        Some(Command::Health) => health_command(&cfg),
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
    // A key installed by the split ceremony is only as strong as its dealt shares until the first
    // refresh: every copy of a dealt bundle (and the dealer's memory) still combines with the live
    // shares. Say so at every start until someone runs one.
    // Temps of a create that crashed before its no-replace move: sealed keys that never became
    // live. Old enough that no concurrent offline create (import-share in the pod) still owns them.
    match keystore.sweep_stale_create_temps(std::time::Duration::from_secs(300)) {
        Ok(removed) => {
            for name in removed {
                tracing::warn!(file = %name, "removed a stale key-store create temp (interrupted create)");
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not sweep stale key-store create temps"),
    }
    match keystore.dealt_keys_never_refreshed() {
        Ok(keys) => {
            for key_id in keys {
                tracing::warn!(
                    key_id = %key_id,
                    "key installed by the split ceremony has never been refreshed — the dealt shares \
                     still combine with the live ones; run `rutli-cosigner refresh --key-id {key_id}` \
                     (docs/split-ceremony.md)"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not check for unrefreshed imported keys"),
    }
    let mut node = Node::new(identifier, cfg.max_signers(), cfg.threshold, keystore);

    // Load mTLS material once (if configured). Plaintext otherwise (dev only).
    let tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?;
    if let Some(t) = &tls {
        // Every anchor of the trust file (2 while a CA rotation's bundle is live), validated by
        // `tls::load`: CA certificates only, valid now unless tls.allow_expired_ca.
        tracing::info!(ca_certs = t.anchors.len(), "mutual TLS enabled (cluster CA trust anchors)");
        for (index, a) in t.anchors.iter().enumerate() {
            tracing::info!(
                index,
                subject = %a.subject,
                not_after = %a.not_after,
                sha256 = %a.sha256,
                "trust anchor"
            );
            if !a.valid_now {
                tracing::warn!(
                    index,
                    subject = %a.subject,
                    "trust anchor is expired or not yet valid, accepted because tls.allow_expired_ca \
                     is set — finish the CA rotation and remove the flag"
                );
            } else if a.days_left < 30 {
                tracing::warn!(
                    index,
                    subject = %a.subject,
                    days_left = a.days_left,
                    "trust anchor expires soon — rotate the cluster CA (docs/ca-rotation.md)"
                );
            }
        }
    } else {
        tracing::warn!("running WITHOUT TLS — plaintext gRPC, do not use in production");
    }

    // The cluster identity envelopes are bound to — logged whether or not hosted keys are on, so a
    // CA rotation can confirm the pin took effect on every node before the CA file changes
    // (docs/ca-rotation.md greps for `cluster id <id> (pinned in config)`).
    let cluster_id = cfg.cluster_id()?;
    let source = cfg.cluster_id_source();
    tracing::info!("cluster id {cluster_id} ({source})");
    if cfg.cluster_id.is_some() && cfg.tls.is_some() {
        if let Ok(derived) = cfg.derived_cluster_id() {
            if derived != cluster_id {
                tracing::info!(
                    "cluster id {cluster_id} differs from the id derived from tls.ca_cert \
                     ({derived}) — expected during and after a CA rotation (docs/ca-rotation.md)"
                );
            }
        }
    }
    // ...and it must be the id this node ran under before (review M2): a `helm upgrade` that drops
    // the pin would otherwise move the node to another cluster id silently.
    use rutli_cosigner::cluster_identity::{self, Recorded};
    match cluster_identity::reconcile(&cfg.data_dir, &cluster_id, source, cfg.cluster_id_change_allowed)? {
        Recorded::First => tracing::info!(
            "cluster id {cluster_id} recorded in {} (first start with this check)",
            cluster_identity::path(&cfg.data_dir).display()
        ),
        Recorded::Unchanged => {}
        Recorded::Changed { previous } => tracing::warn!(
            "cluster id CHANGED from {} to {cluster_id} ({source}) because cluster_id_change_allowed \
             is set — remove that flag now",
            previous.as_deref().unwrap_or("<unreadable record>")
        ),
    }
    if cfg.cluster_id_change_allowed {
        tracing::warn!(
            "cluster_id_change_allowed is set: this node would start under any cluster id — remove \
             it once the change has rolled out"
        );
    }

    // Cluster-hosted (non-FROST) keys. The wrapping key and the at-rest seal key both come from the
    // same operator master secret, so hosted keys require share_seal (enforced by config
    // validation) — a hosted key is a whole private key and must never sit unsealed on disk.
    if cfg.hosted_keys.as_ref().map(|h| h.enabled).unwrap_or(false) {
        let seal_cfg = cfg.share_seal.as_ref().expect("validate() requires share_seal");
        let master = std::env::var(&seal_cfg.secret_env).map_err(|_| {
            DaemonError::Config(format!("hosted keys enabled but {} is not set", seal_cfg.secret_env))
        })?;
        // Bind envelopes to this trust domain (the pinned `cluster_id`, else derived from the CA
        // cert), so an envelope can never be replayed into a different deployment.
        node = node.with_hosted_keys(master.as_bytes(), cluster_id.clone())?;
        tracing::info!(
            "cluster-hosted keys enabled (RSA-2048 and EC P-256 encryption, AES-256-GCM symmetric)"
        );
    }
    let node = Arc::new(node);

    // Key-store readiness, re-probed in the background so `rutli_keystore_unreadable`, the
    // transition log and the refusal gate stay current even when nobody calls Health. A dedicated
    // OS thread, not a tokio task: on a stalled volume it must keep going when the runtime cannot.
    rutli_cosigner::health::spawn_monitor(node.clone(), rutli_cosigner::health::MONITOR_INTERVAL);

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
    let operator_cns = cfg.operator_allowlist.as_ref().map(|v| {
        Arc::new(v.iter().cloned().collect::<std::collections::HashSet<String>>())
    });
    if let Some(cns) = &operator_cns {
        tracing::info!(?cns, "operator role: KeyStatus and CeremonySignTest only");
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
    if cfg.ceremony_sign_test_rate_limit_per_min == 0 {
        tracing::warn!(
            "CeremonySignTest rate limiting is DISABLED — an operator or driver certificate can \
             loop it and fill the key volume with nonce markers"
        );
    }
    let ceremony_test_limiter = Arc::new(rutli_cosigner::service::ceremony_sign_test_limiter(
        cfg.ceremony_sign_test_rate_limit_per_min,
    ));

    let signer = SignerSvc {
        node: node.clone(),
        peers,
        allowed_cns,
        operator_cns,
        hosted_write_quorum,
        decrypt_limiter,
        ceremony_test_limiter,
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

/// Operator command: ask every cosigner for its view of `key_id` and check the cluster agrees on the
/// expected key. See [`rutli_cosigner::verify_key`].
async fn verify_key_command(
    cfg: &Config,
    key_id: &str,
    expect_fingerprint: &str,
    sign_test: bool,
    json: bool,
) -> Result<()> {
    use rutli_cosigner::pb::{CeremonySignTestRequest, KeyStatusRequest};
    use rutli_cosigner::verify_key::{check_views, sign_test_plan, NodeView};

    let client_tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?.map(|t| t.client);
    let mut peers = cfg.peers.clone();
    peers.sort_by_key(|p| p.identifier);
    let roster: Vec<u16> = peers.iter().map(|p| p.identifier).collect();

    let mut views = Vec::new();
    let mut clients = Vec::new();
    for p in &peers {
        let client = signer_client(&p.endpoint, client_tls.clone()).await;
        let status = match &client {
            Ok(c) => c
                .clone()
                .key_status(KeyStatusRequest { key_id: key_id.to_string() })
                .await
                .map(|r| r.into_inner())
                .map_err(|s| status_text(&s)),
            Err(e) => Err(format!("unreachable: {}", error_chain(e))),
        };
        views.push(NodeView { identifier: p.identifier, endpoint: p.endpoint.clone(), status });
        clients.push((p.identifier, client));
    }
    let mut report = check_views(key_id, expect_fingerprint, &roster, cfg.threshold, &views);

    if sign_test {
        if report.ok {
            // Every t-subset, leader rotating: every share and every possible quorum is exercised.
            let clients: std::collections::BTreeMap<u16, _> = clients.into_iter().collect();
            for (leader, signers) in sign_test_plan(&roster, cfg.threshold) {
                let result = match &clients[&leader] {
                    Ok(c) => c
                        .clone()
                        .ceremony_sign_test(CeremonySignTestRequest {
                            key_id: key_id.to_string(),
                            signers: signers.iter().map(|&s| u32::from(s)).collect(),
                        })
                        .await
                        .map(|r| {
                            let r = r.into_inner();
                            (r.message, r.signature)
                        })
                        .map_err(|s| status_text(&s)),
                    Err(e) => Err(format!("unreachable: {}", error_chain(e))),
                };
                report.record_signature(leader, &signers, result);
            }
        } else {
            report.problems.push("sign test skipped: the nodes' views are inconsistent".into());
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("verify-key {key_id} — expected {expect_fingerprint}");
        for n in &report.nodes {
            match &n.error {
                Some(e) => println!("  node {} {}: {e}", n.identifier, n.endpoint),
                None => println!(
                    "  node {} {}: fp {} digest {} own-share {} origin {} ceremony {:?} refreshes {}",
                    n.identifier,
                    n.endpoint,
                    n.fingerprint,
                    n.pkp_digest,
                    if n.own_share_in_package { "ok" } else { "MISMATCH" },
                    n.origin,
                    n.ceremony_id,
                    n.refresh_count
                ),
            }
        }
        if let (Some(g), Some(d)) = (&report.group_verifying_key, &report.pkp_digest) {
            println!("  group key {g}\n  pkp digest {d}");
        }
        for s in &report.sign_test {
            println!(
                "  sign test by {:?} led by node {}: {}",
                s.signers,
                s.leader,
                s.error.as_deref().unwrap_or("ok (verify_strict under the Canton key)")
            );
        }
        for p in &report.problems {
            println!("  PROBLEM: {p}");
        }
        println!("{}", if report.ok { "OK" } else { "FAILED" });
    }
    if report.ok {
        Ok(())
    } else {
        Err(DaemonError::Ceremony(format!("verify-key: {} problem(s)", report.problems.len())))
    }
}

/// A Signer client for an operator command, with bounded connect and call times.
async fn signer_client(
    endpoint: &str,
    tls: Option<tonic::transport::ClientTlsConfig>,
) -> Result<SignerClient<tonic::transport::Channel>> {
    let mut ep = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| DaemonError::Config(format!("bad endpoint {endpoint}: {e}")))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30));
    if let Some(tls) = tls {
        ep = ep.tls_config(tls)?;
    }
    Ok(SignerClient::new(ep.connect().await?))
}

/// A gRPC status for the operator: code, message, and the transport error behind it — a refused
/// handshake is only "transport error" without its source (`UnknownCA`, `UnknownIssuer`, ...), which
/// is what the CA rotation's negative control greps for (docs/ca-rotation.md, Phase D).
fn status_text(s: &tonic::Status) -> String {
    let mut out = format!("{:?}: {}", s.code(), s.message());
    append_sources(&mut out, std::error::Error::source(s));
    out
}

/// An error and every error behind it, `a: b: c`, skipping a source already in the text.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    append_sources(&mut out, e.source());
    out
}

fn append_sources(out: &mut String, mut source: Option<&(dyn std::error::Error + 'static)>) {
    while let Some(e) = source {
        let text = e.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = e.source();
    }
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

/// Container readiness probe — see [`Command::Health`]. Exits the process: 0 ready, 1 not.
fn health_command(cfg: &Config) -> ! {
    match readiness(cfg) {
        Ok(()) => {
            println!("ready");
            std::process::exit(0)
        }
        Err(reason) => {
            println!("not ready: {reason}");
            std::process::exit(1)
        }
    }
}

fn readiness(cfg: &Config) -> std::result::Result<(), String> {
    // check_dir rather than KeyStore::open: open would mkdir a missing key dir, and a probe must not
    // change what it inspects.
    KeyStore::check_dir(&cfg.data_dir.join("keys")).map_err(|e| e.to_string())?;

    // Prove the server is up with a bare TCP connect: the port speaks mTLS, and the probe needs no
    // client cert to know something is listening. Dial the local listen address, never this node's
    // own DNS name: a not-ready pod normally loses its Service DNS record, so a probe that resolved
    // itself would keep itself not-ready forever (the shipped headless Service publishes not-ready
    // addresses, but the probe must not depend on that).
    let listen: std::net::SocketAddr =
        cfg.listen.parse().map_err(|e| format!("bad listen addr {}: {e}", cfg.listen))?;
    let target = match listen.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
            std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, listen.port()))
        }
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, listen.port()))
        }
        _ => listen,
    };
    std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_secs(2))
        .map_err(|e| format!("gRPC listener {target} not accepting connections: {e}"))?;
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
    let sealer = offline_sealer(cfg)?;
    KeyStore::open_with_sealer(cfg.data_dir.join("keys"), Some(sealer))
}

/// This node's sealer, for an offline command. Every such command handles key material, which is
/// never stored unsealed — so no share_seal, no command.
fn offline_sealer(cfg: &Config) -> Result<Arc<rutli_cosigner::seal::Sealer>> {
    let seal_cfg = cfg.share_seal.as_ref().ok_or_else(|| {
        DaemonError::Config(
            "share_seal is not configured — cluster-hosted keys and imported shares are always \
             sealed, so this command refuses to run without it"
                .into(),
        )
    })?;
    Ok(Arc::new(rutli_cosigner::seal::Sealer::from_env(&seal_cfg.secret_env, cfg.identifier)?))
}

/// Split ceremony: `share-recipient`. See [`rutli_cosigner::share_import::share_recipient`].
fn share_recipient_command(
    cfg: &Config,
    key_id: &str,
    ceremony_id: &str,
    out: &std::path::Path,
    replace: bool,
) -> Result<()> {
    use rutli_cosigner::share_import::{share_recipient, NodeContext};
    check_cluster_identity(cfg)?;
    let sealer = offline_sealer(cfg)?;
    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), Some(sealer.clone()))?;
    let ctx = NodeContext::from_config(cfg)?;
    if out.exists() && !replace {
        return Err(DaemonError::Config(format!(
            "{} exists; pass --replace to overwrite it (and discard any pending recipient)",
            out.display()
        )));
    }
    // The request is signed with this node's mTLS identity, so the dealer can tell it from one an
    // attacker substituted on the way (request_auth.rs). No TLS, no identity, no request.
    let tls = cfg.tls.as_ref().ok_or_else(|| {
        DaemonError::Config(
            "share-recipient signs the request with this node's mTLS certificate, and tls is not \
             configured — the split ceremony needs a TLS cluster"
                .into(),
        )
    })?;
    let signer = rutli_cosigner::request_auth::NodeSigner::from_files(&tls.cert, &tls.key)?;
    let request = share_recipient(&ctx, &keystore, &sealer, &signer, key_id, ceremony_id, replace)?;
    let json = serde_json::to_vec_pretty(&request)?;
    if replace && out.exists() {
        std::fs::remove_file(out)?;
    }
    // The request is public, but create_new keeps a stale file from ever being mistaken for it.
    use std::io::Write;
    let mut f = rutli_cosigner::share_delivery::private_create_new(out)?;
    f.write_all(&json)?;
    f.sync_all()?;
    tracing::warn!(
        key_id,
        ceremony_id,
        identifier = cfg.identifier,
        "split ceremony: recipient key minted; its secret is sealed under data_dir/ceremony until \
         import-share or abort-import"
    );
    println!("{}", String::from_utf8_lossy(&json));
    println!(
        "wrote {} — hand it to the dealer; recipient_pub {}",
        out.display(),
        request.recipient_pub
    );
    // Gate 0: witnesses read this line here, in a session independent of the file transfer, and
    // the dealer operator must type it back before anything is sealed.
    println!("SAS node {} {}", request.identifier, rutli_cosigner::request_auth::sas(&request));
    Ok(())
}

/// The ceremony commands bind their files to the cluster id: refuse to use one this node does not
/// run under ([`rutli_cosigner::cluster_identity::check`], review M2). Never writes the record.
fn check_cluster_identity(cfg: &Config) -> Result<()> {
    rutli_cosigner::cluster_identity::check(
        &cfg.data_dir,
        &cfg.cluster_id()?,
        cfg.cluster_id_source(),
        cfg.cluster_id_change_allowed,
    )
}

/// Split ceremony: `import-share`. See [`rutli_cosigner::share_import::import_share`].
/// Split ceremony, Gate 0: `recipient-sas`. See [`rutli_cosigner::share_import::recipient_sas`].
fn recipient_sas_command(cfg: &Config, key_id: &str) -> Result<()> {
    let sealer = offline_sealer(cfg)?;
    let line = rutli_cosigner::share_import::recipient_sas(&cfg.data_dir, &sealer, key_id)?;
    println!("{line}");
    Ok(())
}

fn import_share_command(
    cfg: &Config,
    input: &std::path::Path,
    expect_fingerprint: &str,
    dry_run: bool,
) -> Result<()> {
    use rutli_cosigner::share_import::{import_share, read_bundle, NodeContext};
    check_cluster_identity(cfg)?;
    let sealer = offline_sealer(cfg)?;
    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), Some(sealer.clone()))?;
    let ctx = NodeContext::from_config(cfg)?;
    let bundle = read_bundle(input)?;
    let report = import_share(&ctx, &keystore, &sealer, &bundle, expect_fingerprint, dry_run)?;
    if report.outcome == "installed" {
        // Audible on purpose: the node's log may be the only record that a dealt share arrived.
        tracing::warn!(
            key_id = %report.key_id,
            ceremony_id = %report.ceremony_id,
            fingerprint = %report.canton_fingerprint,
            pkp_digest = %report.pkp_digest,
            "IMPORTED a dealer-split FROST share; recipient secret deleted. Refresh the key once \
             every node has its share (docs/split-ceremony.md)"
        );
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Split ceremony: `abort-import`. See [`rutli_cosigner::share_import::abort_import`].
fn abort_import_command(
    cfg: &Config,
    key_id: &str,
    ceremony_id: &str,
    delete_installed: bool,
) -> Result<()> {
    use rutli_cosigner::share_import::{abort_import, NodeContext};
    let sealer = offline_sealer(cfg)?;
    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), Some(sealer.clone()))?;
    let ctx = NodeContext::from_config(cfg)?;
    let report = abort_import(&ctx, &keystore, &sealer, key_id, ceremony_id, delete_installed)?;
    tracing::warn!(
        key_id,
        ceremony_id,
        recipient_deleted = report.recipient_deleted,
        installed_share = report.installed_share,
        "split ceremony aborted on this node"
    );
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.installed_share == "kept" {
        println!(
            "an installed share from this ceremony is still present; pass \
             --yes-delete-installed-share to delete it"
        );
    }
    if report.installed_share == "deleted" {
        println!("restart this cosigner if it is running, so it drops any cached copy of the share");
    }
    Ok(())
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

/// Operator command: read a portable artifact — a Rütli export, or an existing Canton node's EC
/// P-256 encryption key — into this node's keystore.
fn import_key_command(
    cfg: &Config,
    input: &std::path::Path,
    passphrase_env: Option<&str>,
    canton_key_id: Option<&str>,
    expect_fingerprint: Option<&str>,
    key_prefix: Option<&str>,
) -> Result<()> {
    let keystore = offline_keystore(cfg)?;
    let raw = zeroize::Zeroizing::new(std::fs::read(input)?);
    let passphrase = match passphrase_env {
        Some(name) => Some(zeroize::Zeroizing::new(std::env::var(name).map_err(|_| {
            DaemonError::Config(format!("import passphrase: env var {name} is not set"))
        })?)),
        None => None,
    };

    // A Rütli artifact is a JSON object; a Canton export is a protobuf, which never starts with
    // `{` (its first field tag is 0x0a). The flags that only make sense for one of them are
    // refused for the other, so an operator never believes a check ran that did not.
    let is_rutli_envelope = raw.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
    let (key_id, key, origin) = if is_rutli_envelope {
        if canton_key_id.is_some() || expect_fingerprint.is_some() || key_prefix.is_some() {
            return Err(DaemonError::Config(
                "--key-id, --expect-fingerprint and --key-prefix apply to a Canton key; this is a \
                 Rütli export artifact, which carries its own key id"
                    .into(),
            ));
        }
        let envelope: rutli_cosigner::export::ExportEnvelope = serde_json::from_slice(&raw)?;
        let key = rutli_cosigner::export::import(&envelope, passphrase.as_deref().map(|p| p.as_str()))?;
        (envelope.key_id.clone(), key, "a Rütli export".to_string())
    } else {
        let (Some(key_id), Some(expect)) = (canton_key_id, expect_fingerprint) else {
            return Err(DaemonError::Config(
                "this looks like a Canton key export: pass --key-id (the hosted key id to create, \
                 <frost.key-prefix>rutli-…) and --expect-fingerprint (the key's 1220… fingerprint \
                 from the old node)"
                    .into(),
            ));
        };
        let prefix = rutli_cosigner::export::hosted_import_key_id(key_id, key_prefix)?;
        println!(
            "{key_id} is reachable by a driver whose frost.key-prefix is {prefix:?}{}",
            if key_prefix.is_none() { " (pass --key-prefix to enforce it)" } else { "" }
        );
        let imported = rutli_cosigner::export::import_canton(
            &raw,
            passphrase.as_deref().map(|p| p.as_bytes()),
            expect,
            rutli_cosigner::hosted::now_secs(),
        )?;
        (key_id.to_string(), imported.key, format!("Canton key {}", imported.fingerprint))
    };
    drop(raw);
    drop(passphrase);

    // Hosted keys are create-once-immutable: a key id maps to one key forever, because Canton
    // rotates by minting a new id. Overwriting could destroy material the cluster already
    // committed to, so refuse unless it is byte-identical.
    if rutli_cosigner::share_delivery::is_reserved_for_import(&key_id) {
        return Err(DaemonError::ReservedKeyId(key_id));
    }
    if keystore.exists(&key_id) {
        let existing = keystore.load_hosted(&key_id)?;
        if existing.spec != key.spec || existing.private_der != key.private_der {
            return Err(DaemonError::KeyExists(format!(
                "{key_id} already exists on this node with different material — refusing to \
                 overwrite. Rotate to a new key id instead."
            )));
        }
        println!("{key_id} is already present here and identical — nothing to do");
        return Ok(());
    }

    // create, not save: never replaces a file that appeared meanwhile (e.g. an installed share).
    keystore.create_hosted(&key_id, &key)?;
    tracing::warn!(
        key_id = %key_id,
        path = %input.display(),
        origin = %origin,
        "IMPORTED a cluster-hosted key"
    );
    println!(
        "imported {key_id} ({}) from {origin} — start the daemon; anti-entropy will replicate it \
         to the cluster",
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
///
/// Dotfiles are skipped: key files are `<key_id>.json` with ids limited to `[A-Za-z0-9_-]`, so a
/// dotfile is never key material — but the readiness probe's write-test file (`.readyz-…`) is one,
/// and a backup taken from a live pod (`kubectl exec … backup`) could otherwise catch it mid-probe.
fn copy_dir_files(src: &std::path::Path, dst: &std::path::Path, overwrite: bool) -> Result<usize> {
    if !src.is_dir() {
        return Err(DaemonError::Config(format!("{} is not a directory", src.display())));
    }
    let mut count = 0;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_copies_key_files_but_never_dotfiles() {
        let tmp = tempfile::tempdir().unwrap();
        let (src, dst) = (tmp.path().join("keys"), tmp.path().join("backup"));
        std::fs::create_dir_all(src.join("k.nonces")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("k.json"), b"sealed").unwrap();
        std::fs::write(src.join(".readyz-1-2-3"), b"1").unwrap(); // a readiness probe mid-flight

        assert_eq!(copy_dir_files(&src, &dst, false).unwrap(), 1);
        assert!(dst.join("k.json").exists());
        assert!(!dst.join(".readyz-1-2-3").exists(), "a probe file must never land in a backup");
    }
}

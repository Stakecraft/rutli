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
    /// Path to the JSON cluster config for this node. Required by every command except `seal` and `audit-cross-check`.
    #[arg(short, long, env = "RUTLI_COSIGNER_CONFIG")]
    config: Option<std::path::PathBuf>,
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
        /// TLS server name the target must present. Default: that peer's `tls_server_name`
        /// (`cosigner<id>`) when the target is a roster endpoint, else `tls.domain`.
        #[arg(long)]
        tls_server_name: Option<String>,
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
    /// Import a cluster-hosted key from an export artifact. Safe with this node's daemon running
    /// (e.g. `kubectl exec` into the pod) or stopped.
    ///
    /// Reads either a Rütli `export-key` artifact (JSON) or an existing Canton node's EC P-256
    /// encryption key — `ExportKeyPair` / `keys.secret.download` output, plain or
    /// password-protected — which migrates the node without rotating its encryption key. A Canton
    /// key needs --key-id and --expect-fingerprint. The key is written to this node only (create-
    /// once, never an overwrite); anti-entropy replicates it to the rest of the cluster within one
    /// `hosted_keys.anti_entropy_interval_secs` of a running daemon. Check with `verify-hosted`.
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
    /// with an operator certificate (`operator_allowlist`: KeyStatus, HostedKeyStatus and
    /// CeremonySignTest only, no Sign); the driver certificate also works. Exits non-zero on any
    /// problem.
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
    /// Check that every cosigner in the roster holds the same cluster-hosted key — present on each
    /// node (no read-repair), byte-identical public key — and that its Canton fingerprint is the
    /// expected one. Run after `import-key` and before registering the key with the participant.
    /// Public values only: the operator certificate (`operator_allowlist`) suffices; the driver
    /// certificate also works. Exits non-zero on any problem.
    VerifyHosted {
        /// The hosted key, e.g. `<frost.key-prefix>rutli-enc-imported-1220afe2`.
        #[arg(long)]
        key_id: String,
        /// The Canton fingerprint (`1220…`) the key must have, taken from the old node
        /// (`keys.secret.list`), not from the cluster.
        #[arg(long)]
        expect_fingerprint: String,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Per-node seal bundles (`share_seal.secret_file`). Offline, on an operator workstation —
    /// never in the cluster. Needs no `--config`.
    Seal {
        #[command(subcommand)]
        command: SealCommand,
    },
    /// Delete a cluster-hosted key (audit M2) with a delete intent signed by THIS config's TLS
    /// certificate, which must be on every node's hosted_keys.delete_allowlist. Every node
    /// verifies it and replaces the key with a tombstone; the material stays sealed inside it for
    /// hosted_keys.delete_grace_secs (`hosted-undelete`). With --approvals-inbox, first collects
    /// approvals through the same inbox `rutli-approve` serves (for delete_approval_threshold).
    DeleteHostedKey {
        #[arg(long)]
        key_id: String,
        /// Signer endpoint (default: the first roster peer).
        #[arg(long)]
        target: Option<String>,
        /// TLS server name the target must present (default: that peer's `tls_server_name`).
        #[arg(long)]
        tls_server_name: Option<String>,
        /// The approval inbox (`<dir>/pending`, `<dir>/approvals`) to collect approvals in.
        #[arg(long)]
        approvals_inbox: Option<std::path::PathBuf>,
        /// How many distinct approvals to wait for (the nodes' delete_approval_threshold).
        #[arg(long, default_value_t = 0)]
        approvals: usize,
        /// How long to wait for the approvals.
        #[arg(long, default_value_t = 900)]
        approval_timeout_secs: u64,
    },
    /// Undo a hosted-key delete on THIS node (daemon stopped): restore the material its tombstone
    /// retains (within hosted_keys.delete_grace_secs). Run it on every node, then `verify-hosted`:
    /// a node still holding the tombstone answers NOT_FOUND for the key.
    HostedUndelete {
        #[arg(long)]
        key_id: String,
    },
    /// BREAK-GLASS (daemon stopped): remove a hosted key's tombstone on THIS node so the id can be
    /// generated again, and ignore its delete intent from peers from now on. Refused while the
    /// tombstone still retains material. Must be run on EVERY node before the id is generated
    /// again — a node that still holds the tombstone refuses the new key, and the generation fails.
    HostedClearTombstone {
        #[arg(long)]
        key_id: String,
        /// Repeat the key id to confirm.
        #[arg(long)]
        confirm_key_id: String,
    },
    /// Key-file format (audit M4): inspect this node's key files, migrate them to format v2,
    /// downgrade them to v1 for a rollback, seal a genuine plaintext file. Everything but `status`
    /// runs with this node's daemon STOPPED (the instance lock is taken).
    Keyfile {
        #[command(subcommand)]
        command: KeyfileCommand,
    },
    /// Two-phase DKG/refresh ceremonies on this node (docs/ceremonies.md). Run with this node's
    /// daemon STOPPED (the instance lock is taken); it talks to the other cosigners over the mesh
    /// with this node's certificate.
    Ceremony {
        #[command(subcommand)]
        command: CeremonyCommand,
    },
    /// Delete this node's file for a LEGACY partial DKG key — one an interrupted DKG from before
    /// two-phase ceremonies left on fewer than all nodes, wedging every retry of its id (audit M5).
    /// Run on each holder with its daemon stopped. Refuses unless: the key is a DKG share at epoch
    /// 0 here with the confirmed group key, no node holds it at a committed epoch or has a ceremony
    /// for it staged, every other node answers and fewer than all hold it, and it never signed
    /// here. Only discard a key Canton never registered — a 2-of-3 key held by two nodes can sign.
    DiscardPartialKey {
        #[arg(long)]
        key_id: String,
        /// The key's group verifying key (64 hex chars), as `verify-key` or the DKG reply shows it.
        #[arg(long)]
        confirm_group_key: String,
    },
    /// Compare the driver's hash-chained audit log with the cosigners' sign journals (audit C2):
    /// signatures a cosigner journaled that the driver audit lacks (its tail truncated, or a
    /// signature made outside the driver with its certificate), and audited signatures no journal
    /// holds. Verifies both hash chains. Offline, read-only, needs no `--config`. Exit 0:
    /// consistent; 1: discrepancies; 2: a file is unreadable or a chain is broken.
    /// docs/audit-cross-check.md.
    AuditCrossCheck {
        /// The driver's audit log (`audit-log-path`), copied AFTER the journals.
        #[arg(long)]
        driver_audit: std::path::PathBuf,
        /// One node's journal directory (`data_dir/journal`); repeat for every node.
        #[arg(long, required = true)]
        journal: Vec<std::path::PathBuf>,
        /// An audited signature must be in at least this many journals (the threshold, when every
        /// node's journal is given).
        #[arg(long, default_value_t = 1)]
        min_journals: usize,
        /// Do not count signatures made without a signing intent (before require_intent is on).
        #[arg(long)]
        allow_no_intent: bool,
    },
}

#[derive(Subcommand)]
enum KeyfileCommand {
    /// List every key file (committed, staged, pending recipients): format, and which DEK seals
    /// it (current, a previous one of a rotation, or none this node holds). Read-only.
    Status,
    /// Re-seal every key file as format v2 under the current DEK (needs keyfile.cluster_uuid).
    /// Also finishes a DEK rotation. Idempotent.
    Migrate,
    /// Re-seal every key file as format v1 under the current DEK — before rolling this node back
    /// to a release that reads only v1. Set keyfile.write_version back to 1 first, or the daemon
    /// migrates them again at its next start.
    Downgrade,
    /// Seal ONE plaintext key file that sealing refuses. Run once without --confirm: it prints what
    /// the file holds (group key or hosted-key spec and public digest) and a confirmation code; run
    /// again with --confirm <code> to seal exactly that file.
    MigratePlaintext {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        confirm: Option<String>,
    },
}

#[derive(Subcommand)]
enum CeremonyCommand {
    /// Resolve a STAGED ceremony on this node now: ask every roster node for its vote, commit only
    /// if all voted yes for the same outcome, abort only on a no-vote. The daemon's background
    /// resolver does the same every 30 s; this is for an operator who wants it now.
    Resolve {
        #[arg(long)]
        ceremony_id: String,
        /// BREAK-GLASS: treat these roster nodes as PERMANENTLY lost (their disks gone). Commits if
        /// any reachable node committed the ceremony, otherwise aborts it. Never name a node that
        /// may come back: it would hold a share nobody else can combine with.
        #[arg(long, value_delimiter = ',')]
        assume_lost: Vec<u16>,
    },
}

#[derive(Subcommand)]
enum SealCommand {
    /// Split a legacy shared master into one bundle per node, with the CURRENT derivations: each
    /// node keeps its DEK and distribution key, so every sealed file and every envelope still opens
    /// and nothing is re-sealed. Writes `node-<id>.json` (0600, never overwrites) and prints the
    /// public values to pin: each node's `dist_public_key` and `hosted_keys.commitment_key`.
    SplitLegacy {
        /// Node identifiers to write bundles for, e.g. `1,2,3`.
        #[arg(long, value_delimiter = ',', required = true)]
        nodes: Vec<u16>,
        /// Directory to write the bundles into (created if missing).
        #[arg(long)]
        out_dir: std::path::PathBuf,
        /// Env var holding the legacy master, exactly as the cosigners read it.
        #[arg(long, default_value = "RUTLI_SEAL_SECRET")]
        master_env: String,
    },
    /// Write a bundle of fresh random keys for node `--node` of a NEW cluster (an existing node's
    /// sealed files would not open under it). Prints its `dist_public_key`.
    NewNode {
        #[arg(long)]
        node: u16,
        /// File to write (0600, never overwritten).
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Print a bundle's node and `dist_public_key` (never its secrets).
    Inspect {
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
    },
    /// DEK rotation, step 1: write a bundle for the same node with a fresh random share DEK, the
    /// current one kept in `previous_share_deks` (so every file still opens) and the same
    /// distribution seed (no peer re-pins anything). Deploy it, then `keyfile migrate` (or restart:
    /// the daemon re-seals under the new DEK at start), then `seal drop-previous`.
    RotateDek {
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        /// File to write (0600, never overwritten).
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// DEK rotation, last step: the same bundle without `previous_share_deks`. Only once `keyfile
    /// status` on that node shows no file under a previous DEK and a backup has been taken since.
    DropPrevious {
        #[arg(long, value_name = "FILE")]
        r#in: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
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
    if let Some(Command::Seal { command }) = args.command {
        return seal_command(command);
    }
    if let Some(Command::AuditCrossCheck { driver_audit, journal, min_journals, allow_no_intent }) = args.command {
        audit_cross_check_command(&driver_audit, &journal, min_journals, allow_no_intent);
    }
    let config_path = args.config.ok_or_else(|| {
        DaemonError::Config("--config (or RUTLI_COSIGNER_CONFIG) is required".into())
    })?;
    let cfg = Config::load(&config_path)?;

    match args.command {
        Some(Command::Refresh { key_id, target, tls_server_name }) => {
            return refresh_command(&cfg, &key_id, target, tls_server_name).await
        }
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
        Some(Command::VerifyHosted { key_id, expect_fingerprint, json }) => {
            return verify_hosted_command(&cfg, &key_id, &expect_fingerprint, json).await
        }
        Some(Command::Health) => health_command(&cfg),
        Some(Command::Ceremony { command: CeremonyCommand::Resolve { ceremony_id, assume_lost } }) => {
            return ceremony_resolve_command(&cfg, &ceremony_id, &assume_lost).await
        }
        Some(Command::DiscardPartialKey { key_id, confirm_group_key }) => {
            return discard_partial_key_command(&cfg, &key_id, &confirm_group_key).await
        }
        Some(Command::Keyfile { command }) => return keyfile_command(&cfg, command),
        Some(Command::DeleteHostedKey {
            key_id,
            target,
            tls_server_name,
            approvals_inbox,
            approvals,
            approval_timeout_secs,
        }) => {
            return delete_hosted_key_command(
                &cfg,
                &key_id,
                target,
                tls_server_name,
                approvals_inbox.as_deref(),
                approvals,
                std::time::Duration::from_secs(approval_timeout_secs),
            )
            .await
        }
        Some(Command::HostedUndelete { key_id }) => return hosted_undelete_command(&cfg, &key_id),
        Some(Command::HostedClearTombstone { key_id, confirm_key_id }) => {
            return hosted_clear_tombstone_command(&cfg, &key_id, &confirm_key_id)
        }
        _ => {}
    }
    tracing::info!(identifier = cfg.identifier, listen = %cfg.listen, "starting cosigner");

    // One daemon per data directory, for the life of the process (released by the kernel on exit).
    // Taken first, so a second instance fails with this error rather than a port clash. The
    // offline subcommands above deliberately skip it: import-share and import-key are safe to run
    // inside the pod next to a running daemon (create-once, no-clobber key store writes).
    let _instance_lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&cfg.data_dir)?;

    // Prometheus /metrics endpoint (opt-in). Operation counts/latencies only — no key material.
    if let Some(metrics_listen) = &cfg.metrics_listen {
        rutli_cosigner::metrics::install(metrics_listen)?;
        tracing::info!(listen = %metrics_listen, "Prometheus metrics endpoint serving /metrics");
    }

    let identifier = ident(cfg.identifier)?;

    // Share sealing: encryption-at-rest for key shares, keyed from this node's seal bundle (or the
    // deprecated shared master). Read once; dropped below once the sealer and keyring exist.
    let seal_keys = cfg
        .share_seal
        .as_ref()
        .map(|s| rutli_cosigner::seal::SealKeys::load(s, cfg.identifier))
        .transpose()?;
    let sealer = match &seal_keys {
        Some(keys) => {
            match keys {
                rutli_cosigner::seal::SealKeys::Bundle { bundle, .. } => tracing::info!(
                    source = %keys.describe(),
                    "share sealing enabled (bundle node={}) — AES-256-GCM at rest",
                    bundle.node
                ),
                rutli_cosigner::seal::SealKeys::LegacyMaster { .. } => tracing::warn!(
                    source = %keys.describe(),
                    "share sealing enabled from the legacy SHARED master (share_seal.secret_env) — \
                     whoever can read that one secret can derive every node's DEK; migrate to \
                     per-node seal bundles (share_seal.secret_file, docs/runbook-per-node-seal.md)"
                ),
            }
            Some(Arc::new(keys.sealer(cfg.identifier).with_keyfile(&cfg.keyfile)))
        }
        None => {
            tracing::warn!("share sealing DISABLED — key shares stored as plaintext JSON (dev only)");
            None
        }
    };

    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), sealer)?;
    // Audit M4: a plaintext key file under sealing is refused, never sealed as genuine. Name every
    // one and stop: an operator decides, offline, whether each is genuine.
    let plaintext = keystore.plaintext_files()?;
    if !plaintext.is_empty() {
        let names: Vec<String> = plaintext.iter().map(|p| p.display().to_string()).collect();
        return Err(DaemonError::KeyFile(format!(
            "{} PLAINTEXT key file(s) under share sealing: {} — refusing to start. If a file is \
             genuine, seal it with this daemon stopped: `rutli-cosigner keyfile migrate-plaintext \
             --key-id <id>`; otherwise remove it (docs/disaster-recovery.md)",
            names.len(),
            names.join(", ")
        )));
    }
    log_keyfile_policy(&cfg);
    // Files sealed under a previous DEK (a DEK rotation), and v1 files while writing v2, are
    // re-sealed now — under the instance lock, before anything serves.
    match keystore.reseal_outdated() {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "re-sealed key files under the current DEK / format"),
        Err(e) => tracing::warn!(error = %e, "could not check key files for re-sealing"),
    }
    publish_keyfile_gauges(&keystore);
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
    let mut node = Node::new(identifier, cfg.max_signers(), cfg.threshold, keystore)
        .with_require_epoch_match(cfg.signing_policy.require_epoch_match);
    if !cfg.signing_policy.require_epoch_match {
        tracing::info!(
            "signing_policy.require_epoch_match is off: sign round 1 from a leader that names no \
             sharing (a release before epochs) is accepted with a warning — turn it on once every \
             cosigner runs this release"
        );
    }

    // Load mTLS material once (if configured). Plaintext otherwise (dev only).
    let tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?;
    if let Some(t) = &tls {
        // Every anchor of the trust file (2 while a CA rotation's bundle is live), validated by
        // `tls::load`: CA certificates only, valid now unless tls.allow_expired_ca.
        tracing::info!(
            ca_certs = t.anchors.len(),
            "mutual TLS enabled (cluster CA trust anchors); each peer is verified under its own \
             server name (tls_server_name, default cosigner<id>)"
        );
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

    // The signing policy (audit C2): intents verified against the cluster CA, key ACLs, SPKI pins,
    // approvals, the per-key sign rate limit, and the durable sign journal every released share is
    // written to first.
    let sign_guard = {
        let policy = &cfg.signing_policy;
        let ca_pem = match &cfg.tls {
            Some(t) => std::fs::read(&t.ca_cert)?,
            None => Vec::new(),
        };
        let mut verifier = rutli_cosigner::intent::IntentVerifier::new(
            ca_pem,
            cfg.tls.as_ref().is_some_and(|t| t.allow_expired_ca),
            cluster_id.clone(),
            cfg.signer_allowlist.clone().unwrap_or_default(),
            policy,
        )?;
        if let Some(h) = cfg.hosted_keys.as_ref().filter(|h| h.enabled) {
            verifier = verifier.with_delete_policy(rutli_cosigner::intent::DeletePolicy::from_config(h));
            if h.delete_allowlist.is_empty() {
                tracing::info!(
                    "hosted-key deletes are disabled (hosted_keys.delete_allowlist is empty): DeleteKey is \
                     refused and peers' tombstones are not accepted"
                );
            } else {
                tracing::info!(
                    deleters = ?h.delete_allowlist,
                    acl_entries = h.delete_acl.len(),
                    approvals = h.delete_approval_threshold,
                    grace_secs = h.delete_grace_secs,
                    "hosted-key delete role: tombstones need a delete intent signed by one of these CNs"
                );
                if h.delete_approval_threshold == 0 {
                    tracing::warn!(
                        "hosted_keys.delete_approval_threshold is 0: one delete-role certificate alone can \
                         delete a hosted key (recoverable for delete_grace_secs) — require approvals in production"
                    );
                }
            }
        }
        let journal = rutli_cosigner::journal::SignJournal::open(
            cfg.data_dir.join("journal"),
            cfg.identifier,
            rutli_cosigner::journal::Retention {
                days: policy.journal_retention_days,
                max_bytes: u64::from(policy.journal_max_mib_per_key) << 20,
            },
        )?;
        tracing::info!(
            require_intent = policy.require_intent,
            signer_acl_required = policy.signer_acl_required,
            signer_may_refresh = policy.signer_may_refresh,
            acl_entries = policy.signer_acl.len(),
            pinned_cns = policy.signer_pins.len(),
            approval_rules = policy.rules.len(),
            approvers = policy.approvers.len(),
            rate_per_min = policy.sign_rate_limit_per_min,
            rate_per_day = policy.sign_rate_limit_per_day,
            journal = %journal.dir().display(),
            "signing policy"
        );
        if !policy.require_intent {
            tracing::warn!(
                "signing_policy.require_intent is off: a signature without a client-signed intent is \
                 accepted (counted in rutli_sign_intent_absent_total) — turn it on, on every node, once \
                 every cosigner and the driver run this release (docs/approval-quorum.md)"
            );
        }
        if policy.signer_may_refresh {
            tracing::info!(
                "signing_policy.signer_may_refresh is on: the driver certificate may still call Refresh \
                 — turn it off once the refresh job uses a refresh_allowlist certificate"
            );
        }
        Arc::new(rutli_cosigner::sign_policy::SignGuard::new(
            Arc::new(verifier),
            journal,
            cfg.ceremony_sign_test_rate_limit_per_min,
        ))
    };
    node = node.with_sign_guard(sign_guard.clone());

    // Cluster-hosted (non-FROST) keys. The wrapping key comes from the same seal keys as the at-rest
    // DEK, so hosted keys require share_seal (enforced by config validation) — a hosted key is a
    // whole private key and must never sit unsealed on disk.
    if cfg.hosted_keys.as_ref().map(|h| h.enabled).unwrap_or(false) {
        let keys = seal_keys.as_ref().expect("validate() requires share_seal");
        // Bind envelopes to this trust domain (the pinned `cluster_id`, else derived from the CA
        // cert), so an envelope can never be replayed into a different deployment. Peers are known
        // by their pinned distribution keys (bundle) or derived ones (legacy master), never by a
        // master held here.
        node = node.with_hosted_keyring(keys.hosted_keyring(&cfg)?, cluster_id.clone())?;
        if let Some(h) = &cfg.hosted_keys {
            node = node.with_delete_grace(std::time::Duration::from_secs(h.delete_grace_secs));
        }
        tracing::info!(
            "cluster-hosted keys enabled (RSA-2048 and EC P-256 encryption, AES-256-GCM symmetric)"
        );
    }
    // The bundle (or master) is no longer needed: the sealer holds the DEK, the node its own
    // distribution key and the peers' public pins. Wiped on drop.
    drop(seal_keys);
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
            // Per-peer server name (M3): peer 2 must present cosigner2's certificate, so another
            // node's certificate cannot answer at peer 2's endpoint.
            let client_tls = tls.as_ref().map(|t| t.client_for(&p.server_name()));
            peers.push(Arc::new(GrpcPeer::connect_lazy(ident(p.identifier)?, &p.endpoint, client_tls)?));
        }
    }
    peers.sort_by_key(|p| identifier_index(p.identifier()));
    // The mesh: the ceremony resolver asks every peer for its vote directly (never through a
    // leader). A pass now completes anything a crash left STAGED, then every 30 s.
    node.set_mesh(peers.clone())?;
    rutli_cosigner::ceremony::spawn_resolver(node.clone(), rutli_cosigner::ceremony::RESOLVER_INTERVAL);
    // Stale-share check (audit M1): compare this node's sharing of every FROST key with the peers'
    // now and every few minutes; a share found behind is refused for signing until current.
    rutli_cosigner::epoch_check::spawn(node.clone());
    // Burned-session nonce markers past their retention (audit L4): now and every 10 minutes.
    Node::spawn_nonce_pruner(node.clone());

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
        tracing::info!(?cns, "operator role: KeyStatus, HostedKeyStatus and CeremonySignTest only");
    }
    let refresh_cns = cfg.refresh_allowlist.as_ref().map(|v| {
        Arc::new(v.iter().cloned().collect::<std::collections::HashSet<String>>())
    });
    if let Some(cns) = &refresh_cns {
        tracing::info!(?cns, "refresher role: Refresh and KeyStatus only");
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
        tracing::info!(
            per_key_per_min = decrypt_limit,
            "hosted-key decryption rate limit active — per key, on this node only; the cluster-wide \
             ceiling is this times the number of cosigners"
        );
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
        sign_guard: Some(sign_guard),
        refresh_cns,
    };
    let peer = PeerSvc { node, allowed_cns: peer_cns, peer_ids: Some(Arc::new(cfg.peer_identities())) };

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

fn audit_cross_check_command(
    driver_audit: &std::path::Path,
    journals: &[std::path::PathBuf],
    min_journals: usize,
    allow_no_intent: bool,
) -> ! {
    use rutli_cosigner::audit_check;
    let run = || -> Result<audit_check::Report> {
        let audit = audit_check::read_driver_audit(driver_audit)?;
        let mut sets = Vec::new();
        for j in journals {
            sets.push((j.display().to_string(), audit_check::read_journal_root(j)?));
        }
        Ok(audit_check::cross_check(&audit, &sets, &audit_check::Options { min_journals, allow_no_intent }))
    };
    match run() {
        Ok(report) => {
            for line in &report.lines {
                println!("{line}");
            }
            std::process::exit(if report.discrepancies == 0 { 0 } else { 1 })
        }
        Err(e) => {
            eprintln!("audit-cross-check: {e}");
            std::process::exit(2)
        }
    }
}

/// An offline node for the ceremony commands: this node's key store (sealed if configured), its
/// ceremony records (loaded and crash-repaired by `Node::new`), and the mesh, dialled with this
/// node's certificate under each peer's TLS name. The caller holds the instance lock.
fn offline_ceremony_node(cfg: &Config) -> Result<Arc<Node>> {
    let sealer = cfg.share_seal.as_ref().map(|_| offline_sealer(cfg)).transpose()?;
    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), sealer)?;
    let node = Arc::new(Node::new(ident(cfg.identifier)?, cfg.max_signers(), cfg.threshold, keystore));
    let tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?;
    let mut mesh: Vec<Arc<dyn PeerApi>> = Vec::new();
    for p in cfg.peers.iter().filter(|p| p.identifier != cfg.identifier) {
        let client_tls = tls.as_ref().map(|t| t.client_for(&p.server_name()));
        mesh.push(Arc::new(GrpcPeer::connect_lazy(ident(p.identifier)?, &p.endpoint, client_tls)?));
    }
    node.set_mesh(mesh)?;
    Ok(node)
}

/// `ceremony resolve`: see [`CeremonyCommand::Resolve`].
async fn ceremony_resolve_command(cfg: &Config, ceremony_id: &str, assume_lost: &[u16]) -> Result<()> {
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&cfg.data_dir)?;
    let node = offline_ceremony_node(cfg)?;
    let rec = node
        .ceremony_record(ceremony_id)
        .ok_or_else(|| DaemonError::Config(format!("this node has no record of ceremony {ceremony_id}")))?;
    let info = if assume_lost.is_empty() {
        rutli_cosigner::ceremony::resolve(&node, ceremony_id).await?
    } else {
        rutli_cosigner::ceremony::resolve_assume_lost(&node, ceremony_id, assume_lost).await?
    };
    println!(
        "ceremony {ceremony_id} ({} of {}): {} on this node (was {})",
        rec.kind,
        rec.key_id,
        info.phase.as_str(),
        rec.state.as_str()
    );
    Ok(())
}

/// `discard-partial-key`: see [`Command::DiscardPartialKey`].
async fn discard_partial_key_command(cfg: &Config, key_id: &str, confirm_group_key: &str) -> Result<()> {
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&cfg.data_dir)?;
    let confirm: [u8; 32] = hex::decode(confirm_group_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| DaemonError::Config("--confirm-group-key must be 64 hex characters".into()))?;
    let node = offline_ceremony_node(cfg)?;
    let report = rutli_cosigner::ceremony::discard_partial_key(&node, key_id, &confirm).await?;
    println!(
        "discarded this node's file for {} (holders were {:?}); run this on every other holder, \
         then retry the DKG",
        report.key_id, report.holders
    );
    Ok(())
}

/// Operator command: connect to a running cosigner and drive a proactive refresh.
async fn refresh_command(
    cfg: &Config,
    key_id: &str,
    target: Option<String>,
    tls_server_name: Option<String>,
) -> Result<()> {
    let endpoint = target
        .or_else(|| cfg.peers.iter().find(|p| p.identifier != cfg.identifier).map(|p| p.endpoint.clone()))
        .or_else(|| cfg.peers.first().map(|p| p.endpoint.clone()))
        .ok_or_else(|| DaemonError::Config("no target endpoint for refresh".into()))?;

    let mut ep = tonic::transport::Endpoint::from_shared(endpoint.clone())
        .map_err(|e| DaemonError::Config(format!("bad endpoint {endpoint}: {e}")))?;
    if let Some(tls_cfg) = &cfg.tls {
        let tls = rutli_cosigner::tls::load(tls_cfg)?;
        let same = |a: &str, b: &str| {
            a.trim().trim_end_matches('/').eq_ignore_ascii_case(b.trim().trim_end_matches('/'))
        };
        let name = tls_server_name
            .or_else(|| cfg.peers.iter().find(|p| same(&p.endpoint, &endpoint)).map(|p| p.server_name()))
            .or_else(|| tls_cfg.domain.clone())
            .ok_or_else(|| {
                DaemonError::Config(format!(
                    "{endpoint} is not a roster endpoint: pass --tls-server-name (e.g. cosigner1)"
                ))
            })?;
        ep = ep.tls_config(tls.client_for(&name))?;
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

    let tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?;
    let probe = cfg.tls.as_ref().map(rutli_cosigner::tls_probe::TlsProbe::new).transpose()?;
    let mut peers = cfg.peers.clone();
    peers.sort_by_key(|p| p.identifier);
    let roster: Vec<u16> = peers.iter().map(|p| p.identifier).collect();

    let mut views = Vec::new();
    let mut clients = Vec::new();
    for p in &peers {
        // Each node verified under its own name, so one node's certificate cannot answer for
        // another and make an inconsistent cluster look consistent.
        let client = signer_client(&p.endpoint, tls.as_ref().map(|t| t.client_for(&p.server_name()))).await;
        let status = match &client {
            Ok(c) => match c.clone().key_status(KeyStatusRequest { key_id: key_id.to_string() }).await {
                Ok(r) => Ok(r.into_inner()),
                Err(s) => Err(explain_status(&s, probe.as_ref(), &p.endpoint, &p.server_name()).await),
            },
            Err(e) => Err(explain_unreachable(e, probe.as_ref(), &p.endpoint, &p.server_name()).await),
        };
        views.push(NodeView { identifier: p.identifier, endpoint: p.endpoint.clone(), status });
        clients.push((p.identifier, client));
    }
    let mut report = check_views(key_id, expect_fingerprint, &roster, cfg.threshold, &views);

    if sign_test {
        if report.ok {
            // Every t-subset, leader rotating: every share and every possible quorum is exercised.
            let clients: std::collections::BTreeMap<u16, _> = clients.into_iter().collect();
            let endpoints: std::collections::BTreeMap<u16, (&str, String)> =
                peers.iter().map(|p| (p.identifier, (p.endpoint.as_str(), p.server_name()))).collect();
            for (leader, signers) in sign_test_plan(&roster, cfg.threshold) {
                let (endpoint, server_name) = &endpoints[&leader];
                let endpoint = *endpoint;
                let result = match &clients[&leader] {
                    Ok(c) => match c
                        .clone()
                        .ceremony_sign_test(CeremonySignTestRequest {
                            key_id: key_id.to_string(),
                            signers: signers.iter().map(|&s| u32::from(s)).collect(),
                        })
                        .await
                    {
                        Ok(r) => {
                            let r = r.into_inner();
                            Ok((r.message, r.signature))
                        }
                        Err(s) => Err(explain_status(&s, probe.as_ref(), endpoint, server_name).await),
                    },
                    Err(e) => Err(explain_unreachable(e, probe.as_ref(), endpoint, server_name).await),
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
                    "  node {} {}: fp {} digest {} own-share {} origin {} ceremony {:?} refreshes {}{}",
                    n.identifier,
                    n.endpoint,
                    n.fingerprint,
                    n.pkp_digest,
                    if n.own_share_in_package { "ok" } else { "MISMATCH" },
                    n.origin,
                    n.ceremony_id,
                    n.refresh_count,
                    if n.carried_for.is_empty() {
                        String::new()
                    } else {
                        format!(" carried-for {} usage {:?}", n.carried_for, n.recorded_usage)
                    }
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

/// Operator command: ask every cosigner for its own copy of hosted key `key_id` and check the
/// cluster serves one key with the expected Canton fingerprint. See
/// [`rutli_cosigner::verify_hosted`].
async fn verify_hosted_command(cfg: &Config, key_id: &str, expect_fingerprint: &str, json: bool) -> Result<()> {
    use rutli_cosigner::pb::HostedKeyStatusRequest;
    use rutli_cosigner::verify_hosted::{check_hosted_views, HostedView};

    let tls = cfg.tls.as_ref().map(rutli_cosigner::tls::load).transpose()?;
    let mut peers = cfg.peers.clone();
    peers.sort_by_key(|p| p.identifier);
    let roster: Vec<u16> = peers.iter().map(|p| p.identifier).collect();
    let mut views = Vec::new();
    for p in &peers {
        // Each node verified under its own name (M3), so one node's certificate cannot answer for
        // another and make a key missing on one node look present everywhere.
        let client_tls = tls.as_ref().map(|t| t.client_for(&p.server_name()));
        let status = match signer_client(&p.endpoint, client_tls).await {
            Ok(mut c) => c
                .hosted_key_status(HostedKeyStatusRequest { key_id: key_id.to_string() })
                .await
                .map(|r| r.into_inner())
                .map_err(|s| status_text(&s)),
            Err(e) => Err(format!("unreachable: {}", error_chain(&e))),
        };
        views.push(HostedView { identifier: p.identifier, endpoint: p.endpoint.clone(), status });
    }
    let report = check_hosted_views(key_id, expect_fingerprint, &roster, &views);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("verify-hosted {key_id} — expected {}", report.expected_fingerprint);
        for n in &report.nodes {
            match &n.error {
                Some(e) => println!("  node {} {}: {e}", n.identifier, n.endpoint),
                None => println!(
                    "  node {} {}: {} fp {} created_at {}",
                    n.identifier, n.endpoint, n.spec, n.fingerprint, n.created_at
                ),
            }
        }
        if let Some(der) = &report.public_key_der {
            println!("  public key (SPKI) {der}");
        }
        for p in &report.problems {
            println!("  PROBLEM: {p}");
        }
        println!("{}", if report.ok { "OK" } else { "FAILED" });
    }
    if report.ok {
        Ok(())
    } else {
        Err(DaemonError::Config(format!("verify-hosted: {} problem(s)", report.problems.len())))
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

/// [`status_text`], plus — for a transport failure (a status with an error behind it; a status the
/// node *sent* has none) — how the node refuses this client at the TLS layer, if it does. The RPC
/// error alone may say only "connection closed" or "broken pipe" where the node sent `UnknownCA`
/// (a TLS 1.3 race, see [`rutli_cosigner::tls_probe`]).
async fn explain_status(
    s: &tonic::Status,
    probe: Option<&rutli_cosigner::tls_probe::TlsProbe>,
    endpoint: &str,
    server_name: &str,
) -> String {
    let text = status_text(s);
    if std::error::Error::source(s).is_none() {
        return text;
    }
    with_tls_refusal(text, probe, endpoint, server_name).await
}

/// `unreachable: …` for a failed connect, plus the node's TLS refusal if it gives one.
async fn explain_unreachable(
    e: &DaemonError,
    probe: Option<&rutli_cosigner::tls_probe::TlsProbe>,
    endpoint: &str,
    server_name: &str,
) -> String {
    let text = format!("unreachable: {}", error_chain(e));
    match e {
        DaemonError::Transport(_) => with_tls_refusal(text, probe, endpoint, server_name).await,
        _ => text,
    }
}

/// The probe verifies the node under `server_name`, the peer's own name (M3), as the RPC did.
async fn with_tls_refusal(
    text: String,
    probe: Option<&rutli_cosigner::tls_probe::TlsProbe>,
    endpoint: &str,
    server_name: &str,
) -> String {
    // The RPC already carried the alert: nothing to add.
    if text.contains("fatal alert") {
        return text;
    }
    match probe {
        Some(p) => match p.refusal_as(endpoint, server_name).await {
            Some(r) => format!("{text} (TLS probe: {r})"),
            None => text,
        },
        None => text,
    }
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
    let keys = rutli_cosigner::seal::SealKeys::load(seal_cfg, cfg.identifier)?;
    Ok(Arc::new(keys.sealer(cfg.identifier).with_keyfile(&cfg.keyfile)))
}

/// Say which key-file format this node writes and what it accepts (audit M4 rollout).
fn log_keyfile_policy(cfg: &Config) {
    let k = &cfg.keyfile;
    tracing::info!(
        write_version = k.write_version,
        accept_v1 = k.accept_v1,
        cluster_uuid = k.cluster_uuid.as_deref().unwrap_or("<unset>"),
        "key-file format"
    );
    if cfg.share_seal.is_some() && k.write_version == 1 {
        tracing::info!(
            "keyfile.write_version is 1: new key files carry no bound header (v1) — set \
             keyfile.cluster_uuid and write_version 2 on every node once the whole cluster runs this \
             release (docs/disaster-recovery.md, key-file format v2)"
        );
    }
}

/// `rutli_keyfiles{format, dek}`: how many key files are in each format and under which DEK —
/// what a v2 migration and a DEK rotation watch go to zero.
fn publish_keyfile_gauges(keystore: &KeyStore) {
    use rutli_cosigner::seal::DekUse;
    let Ok(paths) = keystore.key_file_paths() else { return };
    let mut counts = std::collections::BTreeMap::new();
    for path in paths {
        let (format, dek) = match keystore.file_state(&path) {
            Ok(Some((v, d))) => (
                if v == 2 { "v2" } else { "v1" },
                match d {
                    DekUse::Current => "current",
                    DekUse::Previous(_) => "previous",
                    DekUse::Unknown => "unknown",
                },
            ),
            _ => ("plaintext", "none"),
        };
        *counts.entry((format, dek)).or_insert(0usize) += 1;
    }
    for format in ["v1", "v2", "plaintext"] {
        for dek in ["current", "previous", "unknown", "none"] {
            let n = counts.get(&(format, dek)).copied().unwrap_or(0);
            metrics::gauge!(rutli_cosigner::metrics::KEYFILES, "format" => format, "dek" => dek).set(n as f64);
        }
    }
}

/// `seal …`: offline seal-bundle tooling. See [`SealCommand`].
fn seal_command(command: SealCommand) -> Result<()> {
    use rutli_cosigner::seal::NodeSealBundle;
    match command {
        SealCommand::SplitLegacy { nodes, out_dir, master_env } => {
            let mut ids = nodes.clone();
            ids.sort_unstable();
            ids.dedup();
            if ids.len() != nodes.len() || ids.contains(&0) {
                return Err(DaemonError::Config(
                    "--nodes must list distinct node identifiers ≥ 1".into(),
                ));
            }
            let master = rutli_cosigner::seal::read_master_env(&master_env)?;
            std::fs::create_dir_all(&out_dir)?;
            let mut pins = Vec::new();
            for &id in &ids {
                let bundle = NodeSealBundle::from_legacy_master(master.as_bytes(), id);
                let path = out_dir.join(format!("node-{id}.json"));
                write_new_private_file(&path, &bundle.to_json()?)?;
                pins.push((id, hex::encode(bundle.dist_public_key()), path));
            }
            let commitment = hex::encode(rutli_cosigner::wrap::legacy_commitment_key(master.as_bytes()));
            drop(master);
            for (id, _, path) in &pins {
                println!("wrote {} (node {id}: its share DEK + distribution seed, nothing else)", path.display());
            }
            println!("\nPublic values to pin (identical on every node; not secret):");
            println!("  hosted_keys.commitment_key = {commitment}");
            for (id, pk, _) in &pins {
                println!("  peers[identifier={id}].dist_public_key = {pk}");
            }
            println!("\nHelm values (deploy/helm/rutli-cosigner, topology: perNode):");
            println!("hostedKeys:\n  commitmentKey: \"{commitment}\"\nnodes:");
            for (id, pk, _) in &pins {
                println!("  - id: {id}\n    distPublicKey: \"{pk}\"");
            }
            println!(
                "\nEach file is ONE node's secret: create one Secret per node from it, delete the \
                 local copies, and never put two nodes' bundles in one place."
            );
        }
        SealCommand::NewNode { node, out } => {
            if node == 0 {
                return Err(DaemonError::Config("--node must be ≥ 1".into()));
            }
            let bundle = NodeSealBundle::random(node);
            write_new_private_file(&out, &bundle.to_json()?)?;
            println!("wrote {} (node {node}, fresh random keys)", out.display());
            println!("  dist_public_key = {}", hex::encode(bundle.dist_public_key()));
            println!(
                "A new cluster also needs one hosted_keys.commitment_key, the same on every node: \
                 `openssl rand -hex 32`."
            );
        }
        SealCommand::Inspect { r#in } => {
            let bytes = zeroize::Zeroizing::new(std::fs::read(&r#in)?);
            let bundle = NodeSealBundle::parse(&bytes)?;
            println!("node {}", bundle.node);
            println!("dist_public_key {}", hex::encode(bundle.dist_public_key()));
            println!("share_dek id {} (+{} previous)", bundle.dek_id(), bundle.previous_count());
        }
        SealCommand::RotateDek { r#in, out } => {
            let bundle = NodeSealBundle::parse(&zeroize::Zeroizing::new(std::fs::read(&r#in)?))?;
            let rotated = bundle.rotated();
            write_new_private_file(&out, &rotated.to_json()?)?;
            println!(
                "wrote {} (node {}): share_dek id {} (new), previous {} — dist_public_key unchanged",
                out.display(),
                rotated.node,
                rotated.dek_id(),
                bundle.dek_id()
            );
            println!(
                "Next: replace node {}'s seal Secret with it, restart the node (it re-seals every key \
                 file under the new DEK at start), check `rutli-cosigner keyfile status`, take a \
                 backup, then `seal drop-previous`.",
                rotated.node
            );
        }
        SealCommand::DropPrevious { r#in, out } => {
            let bundle = NodeSealBundle::parse(&zeroize::Zeroizing::new(std::fs::read(&r#in)?))?;
            if bundle.previous_count() == 0 {
                return Err(DaemonError::Config(format!("{} has no previous DEKs", r#in.display())));
            }
            let dropped = bundle.without_previous();
            write_new_private_file(&out, &dropped.to_json()?)?;
            println!(
                "wrote {} (node {}): share_dek id {}, {} previous DEK(s) dropped. Files sealed under \
                 a dropped DEK no longer open on this node — including old backups.",
                out.display(),
                dropped.node,
                dropped.dek_id(),
                bundle.previous_count()
            );
        }
    }
    Ok(())
}

/// `delete-hosted-key`: see [`Command::DeleteHostedKey`].
async fn delete_hosted_key_command(
    cfg: &Config,
    key_id: &str,
    target: Option<String>,
    tls_server_name: Option<String>,
    inbox: Option<&std::path::Path>,
    approvals: usize,
    approval_timeout: std::time::Duration,
) -> Result<()> {
    use rutli_cosigner::pb;
    let tls_cfg = cfg.tls.as_ref().ok_or_else(|| {
        DaemonError::Config("delete-hosted-key needs tls: the delete intent is signed with tls.cert / tls.key".into())
    })?;
    let signer = rutli_cosigner::request_auth::NodeSigner::from_files(&tls_cfg.cert, &tls_cfg.key)?;
    let peer = match &target {
        Some(t) => cfg.peers.iter().find(|p| p.endpoint.trim_end_matches('/') == t.trim_end_matches('/')),
        None => cfg.peers.first(),
    };
    let endpoint = target.clone().or_else(|| peer.map(|p| p.endpoint.clone())).ok_or_else(|| {
        DaemonError::Config("no target endpoint".into())
    })?;
    let name = tls_server_name.or_else(|| peer.map(|p| p.server_name())).or_else(|| tls_cfg.domain.clone()).ok_or_else(
        || DaemonError::Config(format!("{endpoint} is not a roster endpoint: pass --tls-server-name")),
    )?;
    let tls = rutli_cosigner::tls::load(tls_cfg)?;
    let mut client = signer_client(&endpoint, Some(tls.client_for(&name))).await?;
    let cluster_id = client.capabilities(pb::CapabilitiesRequest {}).await?.into_inner().cluster_id;
    if cluster_id.is_empty() {
        return Err(DaemonError::Config(format!("{endpoint} reports no cluster id — a cosigner older than intents")));
    }
    let digest = rutli_cosigner::intent::delete_digest(key_id);
    let (nonce, collected) = match inbox {
        Some(dir) if approvals > 0 => collect_delete_approvals(dir, key_id, &digest, approvals, approval_timeout)?,
        _ => (Vec::new(), Vec::new()),
    };
    let now = rutli_cosigner::intent::now_ms();
    let mut request_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut request_id);
    let intent = pb::SignIntent {
        version: rutli_cosigner::intent::INTENT_VERSION,
        cluster_id,
        purpose: rutli_cosigner::intent::PURPOSE_DELETE_KEY.into(),
        key_id: key_id.into(),
        digest: digest.to_vec(),
        request_id: request_id.to_vec(),
        issued_at_ms: now,
        not_after_ms: now + 120_000,
        approval_nonce: nonce,
        approvals: collected,
    };
    let signed = rutli_cosigner::intent::sign_intent(&signer, &intent)?;
    let reply = client
        .delete_key(pb::DeleteKeyRequest { key_id: key_id.into(), intent: Some(signed) })
        .await
        .map_err(|s| DaemonError::Config(format!("DeleteKey refused: {}", status_text(&s))))?
        .into_inner();
    println!(
        "{key_id}: {} — tombstoned on {} node(s); anti-entropy brings it to the rest. The material \
         stays sealed in the tombstones for hosted_keys.delete_grace_secs (rutli-cosigner hosted-undelete).",
        if reply.deleted { "deleted" } else { "already deleted / not held" },
        reply.tombstones
    );
    Ok(())
}

/// Collect `threshold` approvals of a delete through a `rutli-approve` inbox: write the pending
/// request (the same flat JSON the driver's approval gate writes, over the delete digest) and wait
/// for `<inbox>/approvals/<requestId>.<approver>.sig`. Returns the nonce and the approvals.
fn collect_delete_approvals(
    inbox: &std::path::Path,
    key_id: &str,
    delete_digest: &[u8; 32],
    threshold: usize,
    timeout: std::time::Duration,
) -> Result<(Vec<u8>, Vec<rutli_cosigner::pb::IntentApproval>)> {
    use base64::Engine;
    use sha2::Digest;
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let request_id = rutli_cosigner::intent::approval_request_id(key_id, delete_digest, &nonce);
    let (pending, approvals_dir) = (inbox.join("pending"), inbox.join("approvals"));
    std::fs::create_dir_all(&pending)?;
    std::fs::create_dir_all(&approvals_dir)?;
    let op_digest = hex::encode(sha2::Sha256::digest(delete_digest));
    let json = serde_json::json!({
        "requestId": request_id, "keyId": key_id, "digest": op_digest, "nonce": hex::encode(nonce),
        "ts": rutli_cosigner::intent::now_ms(), "operation": "delete-hosted-key",
    });
    let file = pending.join(format!("{request_id}.json"));
    std::fs::write(&file, serde_json::to_vec(&json)?)?;
    println!(
        "waiting for {threshold} approval(s) of DELETE {key_id}: request {request_id} in {} — approvers run \
         `ApproveCli approve --inbox {} --request {request_id}` (its digest is SHA-256 of the delete digest)",
        file.display(),
        inbox.display()
    );
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut found: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
        for entry in std::fs::read_dir(&approvals_dir)? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            if !name.starts_with(&format!("{request_id}.")) || !name.ends_with(".sig") {
                continue;
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?) else { continue };
            let (Some(id), Some(rid), Some(sig)) = (v["approverId"].as_str(), v["requestId"].as_str(), v["signature"].as_str())
            else {
                continue;
            };
            if rid != request_id {
                continue;
            }
            if let Ok(sig) = base64::engine::general_purpose::STANDARD.decode(sig) {
                found.insert(id.to_string(), sig);
            }
        }
        if found.len() >= threshold {
            let _ = std::fs::remove_file(&file);
            return Ok((
                nonce.to_vec(),
                found
                    .into_iter()
                    .map(|(approver_id, signature)| rutli_cosigner::pb::IntentApproval { approver_id, signature })
                    .collect(),
            ));
        }
        if std::time::Instant::now() > deadline {
            let _ = std::fs::remove_file(&file);
            return Err(DaemonError::Config(format!(
                "delete of {key_id}: {} of {threshold} approvals within {timeout:?}",
                found.len()
            )));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// `hosted-undelete`: see [`Command::HostedUndelete`].
fn hosted_undelete_command(cfg: &Config, key_id: &str) -> Result<()> {
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&cfg.data_dir)?;
    let keystore = offline_keystore(cfg)?;
    let key = keystore.undelete(key_id, rutli_cosigner::intent::now_ms())?;
    println!(
        "{key_id} undeleted on node {} (spec {}). Undelete it on EVERY node, then check with verify-hosted; \
         the old delete intent no longer applies to it.",
        cfg.identifier,
        key.spec.as_str()
    );
    Ok(())
}

/// `hosted-clear-tombstone`: see [`Command::HostedClearTombstone`].
fn hosted_clear_tombstone_command(cfg: &Config, key_id: &str, confirm: &str) -> Result<()> {
    if key_id != confirm {
        return Err(DaemonError::Config("--confirm-key-id must repeat --key-id".into()));
    }
    let _lock = rutli_cosigner::instance_lock::InstanceLock::acquire(&cfg.data_dir)?;
    let keystore = offline_keystore(cfg)?;
    let t = keystore.clear_tombstone(key_id)?;
    tracing::warn!(key_id, deleted_at_ms = t.deleted_at_ms, "BREAK-GLASS: tombstone cleared");
    println!(
        "{key_id}: tombstone cleared on node {} (its delete intent is now ignored here). Clear it on EVERY \
         node before generating the id again.",
        cfg.identifier
    );
    Ok(())
}

/// `keyfile …`: see [`KeyfileCommand`].
fn keyfile_command(cfg: &Config, command: KeyfileCommand) -> Result<()> {
    use rutli_cosigner::seal::DekUse;
    let sealer = offline_sealer(cfg)?;
    let lock = match command {
        KeyfileCommand::Status => None,
        _ => Some(rutli_cosigner::instance_lock::InstanceLock::acquire(&cfg.data_dir)?),
    };
    let keystore = KeyStore::open_with_sealer(cfg.data_dir.join("keys"), Some(sealer.clone()))?;
    let recipients = rutli_cosigner::share_delivery::list_recipients(&cfg.data_dir)?;
    let recipient_path = |k: &str| rutli_cosigner::share_delivery::recipient_path(&cfg.data_dir, k);
    match command {
        KeyfileCommand::Status => {
            let mut files = keystore.key_file_paths()?;
            for k in &recipients {
                files.push(recipient_path(k)?);
            }
            let (mut outdated, mut previous) = (0, 0);
            println!(
                "node {} — writes v{} (cluster_uuid {}), current DEK {}",
                cfg.identifier,
                cfg.keyfile.write_version,
                cfg.keyfile.cluster_uuid.as_deref().unwrap_or("<unset>"),
                sealer.current_dek_id()
            );
            for path in &files {
                let bytes = std::fs::read(path)?;
                let state = match rutli_cosigner::seal::file_version(&bytes) {
                    None => {
                        outdated += 1;
                        "PLAINTEXT (refused)".to_string()
                    }
                    Some(v) => {
                        if v < 2 {
                            outdated += 1;
                        }
                        let dek = match sealer.dek_use(&bytes) {
                            DekUse::Current => "current DEK".to_string(),
                            DekUse::Previous(i) => {
                                previous += 1;
                                format!("PREVIOUS DEK #{i}")
                            }
                            DekUse::Unknown => "UNKNOWN DEK (does not open here)".to_string(),
                        };
                        format!("v{v}, {dek}")
                    }
                };
                println!("  {}  {state}", path.display());
            }
            println!(
                "{} file(s): {outdated} not yet v2, {previous} under a previous DEK{}",
                files.len(),
                if previous == 0 && sealer.has_previous() {
                    " — the previous DEK(s) can be dropped from the seal bundle (`seal drop-previous`) after a backup"
                } else {
                    ""
                }
            );
        }
        KeyfileCommand::Migrate | KeyfileCommand::Downgrade => {
            let version = if matches!(command, KeyfileCommand::Migrate) { 2 } else { 1 };
            let plaintext = keystore.plaintext_files()?;
            if !plaintext.is_empty() {
                return Err(DaemonError::KeyFile(format!(
                    "plaintext key file(s) {} — seal or remove them first (keyfile migrate-plaintext)",
                    plaintext.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                )));
            }
            let mut n = 0;
            for path in keystore.key_file_paths()? {
                keystore.rewrite(&path, version)?;
                n += 1;
            }
            for k in &recipients {
                rutli_cosigner::share_delivery::reseal_recipient(&cfg.data_dir, &sealer, k, version)?;
                n += 1;
            }
            println!("re-sealed {n} key file(s) as format v{version} under DEK {}", sealer.current_dek_id());
            let tombstones = keystore.list_tombstones()?.len();
            if version == 1 && tombstones > 0 {
                println!(
                    "{tombstones} tombstone(s) of deleted hosted keys: a release before tombstones reads each as \
                     an unreadable file — it serves nothing for the id, but it no longer blocks the key from \
                     coming back from a node that still holds it. Downgrade every node, or none."
                );
            }
            if version == 1 && cfg.keyfile.write_version == 2 {
                println!(
                    "keyfile.write_version is still 2 here: set it to 1 before starting this release \
                     again, or it migrates the files back to v2 at start"
                );
            }
        }
        KeyfileCommand::MigratePlaintext { key_id, confirm } => {
            use sha2::Digest;
            let path = cfg.data_dir.join("keys").join(format!("{key_id}.json"));
            let bytes = std::fs::read(&path)?;
            if rutli_cosigner::seal::Sealer::is_sealed(&bytes) {
                return Err(DaemonError::Config(format!("{} is already sealed", path.display())));
            }
            let code = hex::encode(&sha2::Sha256::digest(&bytes)[..8]);
            let what = match keystore.inspect_plaintext(&key_id) {
                Ok(rutli_cosigner::keystore::Record::Frost(share)) => format!(
                    "FROST share, group key {}, epoch {}",
                    hex::encode(share.public_key_package.verifying_key().serialize()?),
                    share.epoch
                ),
                Ok(rutli_cosigner::keystore::Record::Hosted(k)) => format!(
                    "hosted key {}, public digest {}",
                    k.spec.as_str(),
                    hex::encode(rutli_cosigner::keystore::hosted_header_digest(&k))
                ),
                Ok(rutli_cosigner::keystore::Record::Tombstone(t)) => {
                    format!("tombstone of a deleted hosted key, deleted at {} ms", t.deleted_at_ms)
                }
                Err(e) => return Err(e),
            };
            match confirm {
                Some(c) if c == code => {
                    keystore.migrate_plaintext(&key_id)?;
                    println!("sealed {} ({what})", path.display());
                }
                Some(_) => {
                    return Err(DaemonError::Config(format!(
                        "confirmation code mismatch: the file is not the one inspected (code now {code})"
                    )))
                }
                None => {
                    println!("{}: PLAINTEXT {what}", path.display());
                    println!(
                        "If this is genuine, seal it: rutli-cosigner keyfile migrate-plaintext --key-id \
                         {key_id} --confirm {code}"
                    );
                }
            }
        }
    }
    drop(lock);
    Ok(())
}

/// Create `path` owner-only and write `bytes`; refuses to replace an existing file.
fn write_new_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = rutli_cosigner::share_delivery::private_create_new(path).map_err(|e| {
        DaemonError::Config(format!("cannot create {} (refusing to overwrite): {e}", path.display()))
    })?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
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
    // committed to, so refuse unless it is byte-identical. Safe against a running daemon — see
    // export::install_imported.
    use rutli_cosigner::export::Installed;
    if rutli_cosigner::export::install_imported(&keystore, &key_id, &key)? == Installed::AlreadyPresent {
        println!("{key_id} is already present here and identical — nothing to do");
        return Ok(());
    }
    tracing::warn!(
        key_id = %key_id,
        path = %input.display(),
        origin = %origin,
        "IMPORTED a cluster-hosted key"
    );
    println!(
        "imported {key_id} ({}) from {origin} — anti-entropy replicates it to the cluster (within \
         one interval of a running daemon, or once it starts); then run verify-hosted",
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

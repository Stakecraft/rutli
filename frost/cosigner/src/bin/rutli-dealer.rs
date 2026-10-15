// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-dealer` — the offline dealer of the split ceremony (docs/split-ceremony.md, B2).
//!
//! Reads an existing Canton Ed25519 key (a stored row, an `ExportKeyPair` export, plain or
//! password-protected, or PKCS#8), checks it is the key the operator expects, splits it into one
//! FROST share per cosigner ([`rutli_frost_core::dealer::split_ed25519_seed`]) and seals each share
//! to that cosigner's one-time recipient key ([`rutli_cosigner::share_delivery::seal_share`]).
//!
//! This is the one moment in Rütli where a whole private key is in a process's memory. The binary
//! is built to be run once, on an air-gapped live-boot host, and to leave nothing behind:
//!
//! - core dumps off (`RLIMIT_CORE = 0`) and, on Linux, not dumpable/ptraceable (`PR_SET_DUMPABLE`);
//!   a refusal to run where the kernel would bypass both — a piped `core_pattern` or
//!   `suid_dumpable = 2` — unless `--allow-core-handler` (recorded in dealer-record.json);
//! - memory locked (`mlockall`, Linux, best effort) and a refusal to run with swap enabled unless
//!   `--allow-swap` (where swap cannot be checked — not Linux — it is assumed present);
//! - no logging subscriber at all, and every error message is key-free (the parser's and ours);
//! - the export password only ever from an environment variable, removed from the environment as
//!   soon as it is read — never an argument (visible in `ps` and shell history);
//! - output files are created `0600`, never overwritten.
//!
//! It is deliberately **not** in the cosigner container image: the Dockerfile builds and copies
//! `rutli-cosigner` only. A dealer never runs where a share lives.

#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use rutli_canton_key::{KeySpec, PrivateKeyMaterial, Source};
use rutli_cosigner::carry::{self, CarriedFor};
use rutli_cosigner::request_auth::VerifiedRequest;
use rutli_cosigner::share_delivery::{self, RecipientRequest};
use rutli_cosigner::{DaemonError, Result};

#[derive(Parser)]
#[command(name = "rutli-dealer", about = "Offline dealer for the Rütli split ceremony")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Split an existing Canton Ed25519 key into FROST shares sealed to each cosigner.
    ///
    /// By default the key must be a namespace key (`--expect-usage namespace`). Carrying a
    /// protocol signing or sequencer-authentication key is possible and discouraged
    /// (`--expect-usage protocol`, docs/migration.md "Carrying the signing and encryption keys").
    SplitKey {
        /// The key: a `common_crypto_private_keys.data` value (binary, or hex with --stored-hex),
        /// `ExportKeyPair` output (plain or password-protected), or PKCS#8 PEM/DER.
        #[arg(long, value_name = "FILE")]
        r#in: PathBuf,
        /// Env var holding the export password (password-protected exports only).
        #[arg(long, conflicts_with = "stored_hex")]
        password_env: Option<String>,
        /// The input file is hex text (e.g. `psql … encode(data, 'hex')`), optionally `\x`-prefixed.
        #[arg(long)]
        stored_hex: bool,
        /// The key's Canton fingerprint (`1220…`), taken from the old node, e.g. its namespace.
        #[arg(long)]
        expect_fingerprint: String,
        /// The imported key's id in the cluster: `<prefix>frost-import-<name>` for the namespace
        /// key; `<prefix>frost-import-sig-<name>` (protocol signing) or
        /// `<prefix>frost-import-seqauth-<name>` (sequencer authentication) for a protocol key.
        #[arg(long)]
        key_id: String,
        /// What the key is carried for. `namespace`: its recorded Canton usage must be namespace
        /// alone (or see --namespace-fingerprint). `protocol`: it must include signing or
        /// sequencer-auth, under a `…frost-import-sig-…` / `…frost-import-seqauth-…` id.
        #[arg(long, default_value = "namespace", value_parser = ["namespace", "protocol"])]
        expect_usage: String,
        /// The old node's namespace, read from its UID (`<name>::<namespace>`). Always required for
        /// `--expect-usage protocol`, where it must differ from the key's fingerprint: the key's
        /// recorded usage is unsigned metadata and cannot rule out the namespace key. For
        /// `namespace`, required where the usage is not namespace alone (a Splice `signing` key has
        /// all usages, an empty list reads as all, plain PKCS#8 has none) and must equal the key's
        /// fingerprint. Checked whenever given.
        #[arg(long)]
        namespace_fingerprint: Option<String>,
        /// Signing threshold t. Must equal every recipient's.
        #[arg(long)]
        threshold: u16,
        /// One `share-recipient` request per cosigner (repeat the flag).
        #[arg(long = "recipient", value_name = "FILE", required = true)]
        recipients: Vec<PathBuf>,
        /// The cluster CA certificate — the exact file the cosigners use (`tls.ca_cert`); during a
        /// CA rotation, the bundle of the old and the new CA. Every request must be signed by the
        /// mTLS key of the cosigner it names, certified by a CA in this file, and its cluster id
        /// must be the cluster's (see --cluster-id). The file must hold only CA certificates
        /// that are valid now (the cosigners' rule); each is printed and recorded in
        /// dealer-record.json, and more than one is warned about.
        #[arg(long, value_name = "FILE")]
        ca_cert: PathBuf,
        /// The cluster id the cosigners are pinned to (`cluster_id` in their config). Without it,
        /// the id is derived from --ca-cert, as the cosigners do when unpinned. Required after a
        /// CA rotation.
        #[arg(long, value_name = "ID")]
        cluster_id: Option<String>,
        /// The SAS of every request, comma-separated in identifier order, as witnesses read them
        /// in each pod (`share-recipient` prints `SAS node <i> <sas>`). Without this flag the
        /// dealer asks for each one on the terminal.
        #[arg(long, value_name = "SAS1,SAS2,…")]
        confirm_sas: Option<String>,
        /// Directory for the bundles and the dealer record. Created 0700 if missing; existing
        /// output files are never overwritten.
        #[arg(long)]
        out_dir: PathBuf,
        /// Run even though swap is enabled (or cannot be checked on this OS). The key could be
        /// paged to disk.
        #[arg(long)]
        allow_swap: bool,
        /// Run even though the kernel would hand a crash dump to a user-space handler (a piped
        /// `core_pattern`) or dump non-dumpable processes (`suid_dumpable = 2`).
        #[arg(long)]
        allow_core_handler: bool,
    },
}

fn main() {
    // Before anything touches key material, and before argument parsing can fail with a message.
    let hardening = harden();
    let args = Args::parse();
    let outcome = match args.command {
        Command::SplitKey {
            r#in,
            password_env,
            stored_hex,
            expect_fingerprint,
            key_id,
            threshold,
            recipients,
            ca_cert,
            cluster_id,
            confirm_sas,
            out_dir,
            expect_usage,
            namespace_fingerprint,
            allow_swap,
            allow_core_handler,
        } => split_key(SplitKey {
            input: r#in,
            password_env,
            stored_hex,
            expect_fingerprint,
            key_id,
            threshold,
            recipients,
            ca_cert,
            cluster_id,
            confirm_sas,
            out_dir,
            expect_usage,
            namespace_fingerprint,
            allow_swap,
            allow_core_handler,
            hardening,
        }),
    };
    if let Err(e) = outcome {
        // Display only: none of our errors, nor the parser's, ever carries key material.
        eprintln!("rutli-dealer: refused: {e}");
        std::process::exit(1);
    }
}

struct SplitKey {
    input: PathBuf,
    password_env: Option<String>,
    stored_hex: bool,
    expect_fingerprint: String,
    key_id: String,
    threshold: u16,
    recipients: Vec<PathBuf>,
    ca_cert: PathBuf,
    cluster_id: Option<String>,
    confirm_sas: Option<String>,
    out_dir: PathBuf,
    expect_usage: String,
    namespace_fingerprint: Option<String>,
    allow_swap: bool,
    allow_core_handler: bool,
    hardening: Hardening,
}

/// What the process-level hardening achieved, for the record.
#[derive(Clone, Serialize)]
struct Hardening {
    core_dumps_disabled: bool,
    not_dumpable: bool,
    memory_locked: bool,
    /// `Some(true)` swap on, `Some(false)` off, `None` could not be checked.
    swap_enabled: Option<bool>,
    /// `/proc/sys/kernel/core_pattern` (Linux).
    core_pattern: Option<String>,
    /// `/proc/sys/fs/suid_dumpable` (Linux).
    suid_dumpable: Option<u8>,
    /// A piped core_pattern or suid_dumpable = 2: a crash could still hand memory to a handler.
    core_handler_risk: bool,
}

fn split_key(a: SplitKey) -> Result<()> {
    // An air-gapped live-boot host has only its RTC; certificate validity (request checks) depends
    // on it. Printed and recorded so witnesses can sanity-check it against their own watches.
    let clock = x509_parser::time::ASN1Time::now().to_string();
    println!("dealer clock (UTC): {clock}");
    for warning in a.hardening.warnings() {
        eprintln!("rutli-dealer: warning: {warning}");
    }
    if a.hardening.swap_enabled != Some(false) && !a.allow_swap {
        return Err(refuse(match a.hardening.swap_enabled {
            Some(_) => "swap is enabled on this host (/proc/swaps) — the key could be paged to \
                        disk; run on a host without swap (`swapoff -a`), or pass --allow-swap"
                .into(),
            None => "cannot check for swap on this OS — the key could be paged to disk; run on \
                     the Linux live-boot host, or pass --allow-swap"
                .into(),
        }));
    }
    if a.hardening.core_handler_risk && !a.allow_core_handler {
        return Err(refuse(format!(
            "a crash would still reach a core handler (core_pattern {:?}, suid_dumpable {:?}) — \
             set kernel.core_pattern=core and fs.suid_dumpable=0 on the dealer host, or pass \
             --allow-core-handler",
            a.hardening.core_pattern, a.hardening.suid_dumpable
        )));
    }

    // 1. Everything that needs no secret, first.
    if !share_delivery::is_import_key_id(&a.key_id) {
        return Err(refuse(format!(
            "--key-id {:?} must match ^[A-Za-z0-9_-]*frost-import-[A-Za-z0-9_-]+$",
            a.key_id
        )));
    }
    // The id must be of the class the operator says the key is, before any secret is read.
    let expect_usage = CarriedFor::parse(&a.expect_usage)?;
    carry::check_id_class(&a.key_id, expect_usage)?;
    let expect = share_delivery::canonical_fingerprint(&a.expect_fingerprint)
        .map_err(|e| refuse(format!("--expect-fingerprint: {e}")))?;
    if let Some(id) = &a.cluster_id {
        rutli_cosigner::wrap::check_cluster_id(id).map_err(|e| match e {
            DaemonError::Config(msg) => refuse(format!("--cluster-id: {msg}")),
            other => other,
        })?;
    }
    let ca_pem = std::fs::read(&a.ca_cert)
        .map_err(|e| refuse(format!("--ca-cert {}: {e}", a.ca_cert.display())))?;
    // The cosigners' trust-file rule (`trust::load_trust_anchors`): only valid CA certificates. A
    // leaf in the file would let its key holder certify a request for any node.
    let anchors = rutli_cosigner::trust::load_trust_anchors(&ca_pem, false)
        .map_err(|e| refuse(format!("--ca-cert {}: {e}", a.ca_cert.display())))?;
    for (i, anchor) in anchors.iter().enumerate() {
        println!("trust anchor {i}: {}", anchor.describe());
    }
    if anchors.len() > 1 {
        eprintln!(
            "rutli-dealer: warning: --ca-cert holds {} CA certificates, and a request certified by \
             ANY of them verifies. That is right only for a ceremony during a CA rotation's \
             overlap; afterwards pass the new CA alone (docs/ca-rotation.md, close-out). If the old \
             CA key may be exposed, only the SAS check stands between a request it minted and a \
             real share.",
            anchors.len()
        );
    }
    let cluster_id = match &a.cluster_id {
        Some(pinned) => pinned.clone(),
        None => rutli_cosigner::wrap::cluster_id_from_ca(&ca_pem),
    };
    let requests = read_recipients(&a.recipients, &ca_pem, &cluster_id)?;
    confirm_sas(&requests, a.confirm_sas.as_deref())?;
    let first = &requests[0];
    if first.key_id != a.key_id {
        return Err(refuse(format!(
            "recipients were made for key id {}, not {}",
            first.key_id, a.key_id
        )));
    }
    if first.threshold != a.threshold {
        return Err(refuse(format!(
            "recipients expect threshold {}, not {}",
            first.threshold, a.threshold
        )));
    }
    let outputs: Vec<PathBuf> = requests
        .iter()
        .map(|r| a.out_dir.join(format!("share-{}-node{}.json", r.key_id, r.identifier)))
        .chain(std::iter::once(a.out_dir.join("dealer-record.json")))
        .collect();
    for path in &outputs {
        if path.exists() {
            return Err(refuse(format!("{} exists — refusing to overwrite", path.display())));
        }
    }

    // 2. The key.
    let password = match &a.password_env {
        Some(name) => {
            let value = std::env::var(name)
                .map_err(|_| refuse(format!("--password-env: {name} is not set")))?;
            std::env::remove_var(name); // nothing later in this process needs it
            Some(Zeroizing::new(value))
        }
        None => None,
    };
    let raw = Zeroizing::new(std::fs::read(&a.input)?);
    let input = if a.stored_hex { decode_hex_text(&raw)? } else { raw };
    let key = rutli_canton_key::parse(&input, password.as_ref().map(|p| p.as_bytes()))
        .map_err(|e| refuse(format!("cannot read the key: {e}")))?;
    drop(input);
    drop(password);

    if key.spec() != KeySpec::Ed25519 {
        return Err(refuse(format!(
            "the key is {:?}; only Ed25519 (namespace/signing) keys are split",
            key.spec()
        )));
    }
    let fingerprint = key.fingerprint();
    if fingerprint != expect || key.canton_id.as_ref().is_some_and(|id| id.to_ascii_lowercase() != expect) {
        return Err(refuse(format!(
            "this key's fingerprint is {fingerprint}, not the expected {expect} — wrong key file"
        )));
    }
    // What the key is for (carry.rs): Canton's recorded usage where the container has one (plain
    // PKCS#8 has none), and the old node's namespace wherever the usage alone is ambiguous.
    let recorded = (!matches!(key.source, Source::Pkcs8 { .. })).then_some(key.usage.as_slice());
    let carried = carry::check_dealer_usage(
        expect_usage,
        &a.key_id,
        &fingerprint,
        recorded,
        a.namespace_fingerprint.as_deref(),
    )?;
    let PrivateKeyMaterial::Ed25519 { seed } = &key.material else {
        return Err(refuse("not an Ed25519 key".into()));
    };

    // 3. Split (every check of the dealer module runs inside) and seal.
    let roster: Vec<u16> = requests.iter().map(|r| r.identifier).collect();
    let (mut shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(seed, &roster, a.threshold)?;
    drop(key); // the seed is wiped here
    let sealed: Result<Vec<_>> = requests
        .iter()
        .zip(&shares)
        .map(|(r, s)| share_delivery::seal_share(r, s, &pkp, &fingerprint, &carried))
        .collect();
    for s in shares.iter_mut() {
        s.zeroize();
    }
    let bundles = sealed?;

    // 4. Write. Bundles first, the record last: a record means the ceremony's outputs are complete.
    create_private_dir(&a.out_dir)?;
    for (bundle, path) in bundles.iter().zip(&outputs) {
        write_new(path, &serde_json::to_vec_pretty(bundle)?)?;
    }
    let group = rutli_frost_core::dkg::group_verifying_key_bytes(&pkp)?;
    let record = DealerRecord {
        v: 1,
        kind: "rutli-dealer-record",
        key_id: a.key_id.clone(),
        ceremony_id: first.ceremony_id.clone(),
        cluster_id: first.cluster_id.clone(),
        threshold: a.threshold,
        max_signers: first.max_signers,
        roster: roster.clone(),
        canton_fingerprint: fingerprint.clone(),
        expected_usage: carried.expected.clone(),
        recorded_usage: carried.recorded.clone(),
        namespace_fingerprint: carried.namespace_fingerprint.clone(),
        group_verifying_key: hex::encode(group),
        public_key_package: pkp.clone(),
        pkp_digest: hex::encode(rutli_frost_core::dealer::pkp_digest(&pkp)?),
        recipients: requests
            .iter()
            .map(|r| RecordRecipient {
                identifier: r.identifier,
                recipient_pub: r.recipient_pub.clone(),
                sas: rutli_cosigner::request_auth::sas(r),
                signer_chain: r.signer_chain.clone(),
            })
            .collect(),
        bundles: outputs[..bundles.len()]
            .iter()
            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
            .collect(),
        dealer_binary_sha256: self_sha256(),
        dealer_version: env!("CARGO_PKG_VERSION"),
        hardening: a.hardening.clone(),
        created_at: rutli_cosigner::hosted::now_secs(),
        dealer_clock_utc: clock,
        ca_file_sha256: hex::encode(Sha256::digest(&ca_pem)),
        ca_anchors: anchors
            .iter()
            .map(|t| RecordAnchor {
                subject: t.subject.clone(),
                not_before: t.not_before.clone(),
                not_after: t.not_after.clone(),
                sha256: t.sha256.clone(),
            })
            .collect(),
    };
    let record_path = outputs.last().expect("record path");
    write_new(record_path, &serde_json::to_vec_pretty(&record)?)?;

    println!("split {} into {}-of-{} for cluster {}", fingerprint, a.threshold, roster.len(), first.cluster_id);
    println!("  key id:        {}", a.key_id);
    println!(
        "  carried for:   {} (recorded usage: {})",
        carried.expected,
        match &carried.recorded {
            Some(r) if r.is_empty() => "none, read by Canton as all".to_string(),
            Some(r) => r.join(","),
            None => "unknown, plain PKCS#8".to_string(),
        }
    );
    println!("  ceremony:      {}", first.ceremony_id);
    println!("  group key:     {}", record.group_verifying_key);
    println!("  pkp digest:    {}", record.pkp_digest);
    for path in &outputs {
        println!("  wrote          {}", path.display());
    }
    println!("every node's import-share must print this pkp digest; then shut this host down.");
    Ok(())
}

/// The public record of a split, for the ceremony record. No secret in it.
#[derive(Serialize)]
struct DealerRecord {
    v: u8,
    kind: &'static str,
    key_id: String,
    ceremony_id: String,
    cluster_id: String,
    threshold: u16,
    max_signers: u16,
    roster: Vec<u16>,
    canton_fingerprint: String,
    /// `--expect-usage`: `namespace` or `protocol`.
    expected_usage: String,
    /// The key's recorded Canton usage (`[]`: none recorded, which Canton reads as all; `null`:
    /// plain PKCS#8, no Canton metadata).
    recorded_usage: Option<Vec<String>>,
    /// `--namespace-fingerprint`, when given: the old node's namespace as the operator read it.
    namespace_fingerprint: Option<String>,
    group_verifying_key: String,
    public_key_package: frost_ed25519::keys::PublicKeyPackage,
    pkp_digest: String,
    recipients: Vec<RecordRecipient>,
    bundles: Vec<String>,
    dealer_binary_sha256: String,
    dealer_version: &'static str,
    hardening: Hardening,
    created_at: u64,
    /// The dealer host's clock at start, human-readable — it also decided certificate validity.
    dealer_clock_utc: String,
    /// SHA-256 of the `--ca-cert` file as given.
    ca_file_sha256: String,
    /// The trust anchors of `--ca-cert`, in file order: the CAs a request could be certified by.
    ca_anchors: Vec<RecordAnchor>,
}

#[derive(Serialize)]
struct RecordAnchor {
    subject: String,
    not_before: String,
    not_after: String,
    /// SHA-256 of the certificate (DER).
    sha256: String,
}

#[derive(Serialize)]
struct RecordRecipient {
    identifier: u16,
    recipient_pub: String,
    /// The SAS confirmed at Gate 0.
    sas: String,
    /// The certificate chain that signed the request (base64 DER, leaf first).
    signer_chain: Vec<String>,
}

/// Read every request, verify it was minted by the cosigner it names (signature by that node's mTLS
/// key, certified by a CA in the CA file, cluster id = `cluster_id` —
/// `request_auth::verify_request_for_cluster`), and check they describe one ceremony: same key,
/// ceremony, cluster, threshold, size and roster; one request per roster member, no duplicates, no
/// strays.
fn read_recipients(paths: &[PathBuf], ca_pem: &[u8], cluster_id: &str) -> Result<Vec<VerifiedRequest>> {
    let mut requests = Vec::with_capacity(paths.len());
    for p in paths {
        let r: RecipientRequest = serde_json::from_slice(&std::fs::read(p)?)
            .map_err(|e| refuse(format!("{} is not a share-recipient request: {e}", p.display())))?;
        r.validate().map_err(|e| refuse(format!("{}: {e}", p.display())))?;
        let verified = rutli_cosigner::request_auth::verify_request_for_cluster(&r, ca_pem, cluster_id)
            .map_err(|e| refuse(format!("{}: {e} — do not seal to it; see the runbook", p.display())))?;
        requests.push(verified);
    }
    let first = requests.first().ok_or_else(|| refuse("no --recipient given".into()))?.clone();
    for r in &requests[1..] {
        if r.ceremony_params() != first.ceremony_params() {
            return Err(refuse(format!(
                "recipients disagree: node {} expects (ceremony, key, cluster, t, n, roster) = \
                 {:?}, node {} expects {:?}",
                first.identifier,
                first.ceremony_params(),
                r.identifier,
                r.ceremony_params()
            )));
        }
    }
    let ids: BTreeSet<u16> = requests.iter().map(|r| r.identifier).collect();
    if ids.len() != requests.len() {
        return Err(refuse("two recipient requests for the same node".into()));
    }
    let pubs: BTreeSet<&str> = requests.iter().map(|r| r.recipient_pub.as_str()).collect();
    if pubs.len() != requests.len() {
        return Err(refuse("two recipient requests share a recipient key".into()));
    }
    if ids.iter().copied().collect::<Vec<_>>() != first.roster {
        return Err(refuse(format!(
            "need exactly one request per roster member {:?}, got {:?}",
            first.roster, ids
        )));
    }
    requests.sort_by_key(|r| r.identifier);
    Ok(requests)
}

/// Gate 0: every request's SAS must match what witnesses read in the pod, over a channel that did
/// not carry the request files. From `--confirm-sas` (identifier order), or typed on the terminal.
fn confirm_sas(requests: &[VerifiedRequest], given: Option<&str>) -> Result<()> {
    use std::io::{BufRead, IsTerminal};
    let expected: Vec<(u16, String)> =
        requests.iter().map(|r| (r.identifier, rutli_cosigner::request_auth::sas(r))).collect();
    for (id, sas) in &expected {
        println!("request node {id}: SAS {sas}");
    }
    let typed: Vec<String> = match given {
        Some(list) => list.split(',').map(|s| s.trim().to_ascii_lowercase()).collect(),
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(refuse(
                    "confirm every request's SAS: pass --confirm-sas or run on a terminal".into(),
                ));
            }
            let mut out = Vec::new();
            let stdin = std::io::stdin();
            for (id, _) in &expected {
                eprint!("SAS for node {id}, as read in its pod by the witnesses: ");
                let mut line = String::new();
                stdin.lock().read_line(&mut line)?;
                out.push(line.trim().to_ascii_lowercase());
            }
            out
        }
    };
    if typed.len() != expected.len() {
        return Err(refuse(format!(
            "{} SAS given, {} requests — one per node, in identifier order",
            typed.len(),
            expected.len()
        )));
    }
    for ((id, sas), t) in expected.iter().zip(&typed) {
        if sas != t {
            return Err(refuse(format!(
                "SAS mismatch for node {id}: the request file says {sas}, the pod said {t} — the \
                 request was replaced on its way here. STOP: do not seal; see the runbook"
            )));
        }
    }
    Ok(())
}

/// Hex text → bytes, tolerating whitespace and a psql `\x` prefix.
///
/// Every intermediate is a zeroizing buffer sized once, never grown: no partially filled copy of
/// the key's hex is freed unwiped by a reallocation. The `\x` prefix is sliced off, not copied.
fn decode_hex_text(text: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut compact = Zeroizing::new(Vec::with_capacity(text.len()));
    compact.extend(text.iter().copied().filter(|b| !b.is_ascii_whitespace()));
    let digits: &[u8] = compact.strip_prefix(b"\\x").unwrap_or(&compact);
    if !digits.len().is_multiple_of(2) {
        return Err(refuse("--stored-hex: the input is not hex".into()));
    }
    let mut out = Zeroizing::new(vec![0u8; digits.len() / 2]);
    hex::decode_to_slice(digits, &mut out[..])
        .map_err(|_| refuse("--stored-hex: the input is not hex".into()))?;
    Ok(out)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = share_delivery::private_create_new(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// SHA-256 of this executable, for the record (which binary did the split).
fn self_sha256() -> String {
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(|b| hex::encode(Sha256::digest(b)))
        .unwrap_or_else(|_| "unavailable".into())
}

fn refuse(msg: String) -> DaemonError {
    DaemonError::Ceremony(msg)
}

impl Hardening {
    fn warnings(&self) -> Vec<&'static str> {
        let mut w = Vec::new();
        if !self.core_dumps_disabled {
            w.push("could not disable core dumps (RLIMIT_CORE)");
        }
        if !self.not_dumpable {
            w.push("process is still dumpable/ptraceable (PR_SET_DUMPABLE is Linux-only)");
        }
        if !self.memory_locked {
            w.push(
                "memory not locked (mlockall needs Linux and root or an unlimited memlock limit) \
                 — pages may be swapped",
            );
        }
        w
    }
}

/// Process-level hardening. Best effort, every outcome recorded; the swap policy is enforced by
/// the caller, the rest only warned about (the air-gapped host is the real control).
fn harden() -> Hardening {
    // SAFETY: plain libc calls with valid arguments; no memory is shared with them.
    let core_dumps_disabled = unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0
    };
    #[cfg(target_os = "linux")]
    let (not_dumpable, memory_locked, swap_enabled) = {
        // SAFETY: as above.
        // Variadic: pass the unsigned longs the kernel reads, not ints.
        let not_dumpable = unsafe {
            let zero: libc::c_ulong = 0;
            libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) == 0
        };
        // MCL_FUTURE under a finite RLIMIT_MEMLOCK makes later allocations fail once the limit is
        // reached — an abort mid-split. So lock only where it cannot bite: as root (CAP_IPC_LOCK,
        // the live-boot host) or with an unlimited memlock limit.
        let memory_locked = unsafe {
            let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            let unlimited = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) == 0
                && lim.rlim_cur == libc::RLIM_INFINITY;
            (libc::geteuid() == 0 || unlimited)
                && libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0
        };
        // /proc/swaps: a header line, then one line per active swap area.
        let swap_enabled = std::fs::read_to_string("/proc/swaps")
            .ok()
            .map(|s| s.lines().skip(1).any(|l| !l.trim().is_empty()));
        (not_dumpable, memory_locked, swap_enabled)
    };
    // A piped core_pattern hands a crashing process's memory to a user-space handler regardless
    // of RLIMIT_CORE (systemd-coredump, apport, abrt), and suid_dumpable = 2 dumps even processes
    // that made themselves non-dumpable. Either defeats the two settings above.
    #[cfg(target_os = "linux")]
    let (core_pattern, suid_dumpable) = (
        std::fs::read_to_string("/proc/sys/kernel/core_pattern").ok().map(|s| s.trim().to_string()),
        std::fs::read_to_string("/proc/sys/fs/suid_dumpable").ok().and_then(|s| s.trim().parse().ok()),
    );
    #[cfg(not(target_os = "linux"))]
    let (core_pattern, suid_dumpable): (Option<String>, Option<u8>) = (None, None);
    let core_handler_risk = core_handler_risk(core_pattern.as_deref(), suid_dumpable);
    #[cfg(not(target_os = "linux"))]
    let (not_dumpable, memory_locked, swap_enabled) = (false, false, None);
    Hardening {
        core_dumps_disabled,
        not_dumpable,
        memory_locked,
        swap_enabled,
        core_pattern,
        suid_dumpable,
        core_handler_risk,
    }
}

/// Would a crash reach a core handler despite `RLIMIT_CORE = 0` and `PR_SET_DUMPABLE = 0`?
fn core_handler_risk(core_pattern: Option<&str>, suid_dumpable: Option<u8>) -> bool {
    core_pattern.is_some_and(|p| p.starts_with('|')) || suid_dumpable == Some(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_hex_text_is_decoded_with_or_without_the_psql_prefix() {
        assert_eq!(decode_hex_text(b"\\x0aff\n").unwrap().as_slice(), &[0x0a, 0xff]);
        assert_eq!(decode_hex_text(b" 0a ff ").unwrap().as_slice(), &[0x0a, 0xff]);
        assert!(decode_hex_text(b"\\x0af").is_err(), "odd length");
        assert!(decode_hex_text(b"zz").is_err());
    }

    #[test]
    fn a_piped_core_pattern_or_suid_dumpable_2_is_a_core_handler_risk() {
        assert!(core_handler_risk(Some("|/usr/lib/systemd/systemd-coredump %P"), Some(0)));
        assert!(core_handler_risk(Some("core"), Some(2)));
        assert!(!core_handler_risk(Some("core"), Some(0)));
        assert!(!core_handler_risk(None, None), "not Linux: nothing known, nothing claimed");
    }
}

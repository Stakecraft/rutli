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

use rutli_canton_key::{KeySpec, PrivateKeyMaterial, SigningKeyUsage};
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
        /// The imported key's id in the cluster: `<prefix>frost-import-<name>`.
        #[arg(long)]
        key_id: String,
        /// Signing threshold t. Must equal every recipient's.
        #[arg(long)]
        threshold: u16,
        /// One `share-recipient` request per cosigner (repeat the flag).
        #[arg(long = "recipient", value_name = "FILE", required = true)]
        recipients: Vec<PathBuf>,
        /// Directory for the bundles and the dealer record. Created 0700 if missing; existing
        /// output files are never overwritten.
        #[arg(long)]
        out_dir: PathBuf,
        /// Accept a key whose recorded usage does not include `namespace` (or has none, e.g.
        /// PKCS#8). Without it only namespace keys are split.
        #[arg(long)]
        any_usage: bool,
        /// Run even though swap is enabled (or cannot be checked on this OS). The key could be
        /// paged to disk.
        #[arg(long)]
        allow_swap: bool,
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
            out_dir,
            any_usage,
            allow_swap,
        } => split_key(SplitKey {
            input: r#in,
            password_env,
            stored_hex,
            expect_fingerprint,
            key_id,
            threshold,
            recipients,
            out_dir,
            any_usage,
            allow_swap,
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
    out_dir: PathBuf,
    any_usage: bool,
    allow_swap: bool,
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
}

fn split_key(a: SplitKey) -> Result<()> {
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

    // 1. Everything that needs no secret, first.
    if !share_delivery::is_import_key_id(&a.key_id) {
        return Err(refuse(format!(
            "--key-id {:?} must match ^[A-Za-z0-9_-]*frost-import-[A-Za-z0-9_-]+$",
            a.key_id
        )));
    }
    let expect = a.expect_fingerprint.trim().to_string();
    if !(expect.len() == 68 && expect.starts_with("1220") && expect.chars().all(|c| c.is_ascii_hexdigit())) {
        return Err(refuse(format!("--expect-fingerprint {expect:?} is not a 1220… Canton fingerprint")));
    }
    let requests = read_recipients(&a.recipients)?;
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
    let input = if a.stored_hex { Zeroizing::new(decode_hex_text(&raw)?) } else { raw };
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
    if fingerprint != expect || key.canton_id.as_ref().is_some_and(|id| *id != expect) {
        return Err(refuse(format!(
            "this key's fingerprint is {fingerprint}, not the expected {expect} — wrong key file"
        )));
    }
    if !key.usage.contains(&SigningKeyUsage::Namespace) && !a.any_usage {
        return Err(refuse(format!(
            "the key's recorded usage is {:?}, which does not include namespace — pass --any-usage \
             if you really mean to import a non-namespace key",
            key.usage
        )));
    }
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
        .map(|(r, s)| share_delivery::seal_share(r, s, &pkp, &fingerprint))
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
        group_verifying_key: hex::encode(group),
        public_key_package: pkp.clone(),
        pkp_digest: hex::encode(rutli_frost_core::dealer::pkp_digest(&pkp)?),
        recipients: requests
            .iter()
            .map(|r| RecordRecipient { identifier: r.identifier, recipient_pub: r.recipient_pub.clone() })
            .collect(),
        bundles: outputs[..bundles.len()]
            .iter()
            .map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
            .collect(),
        dealer_binary_sha256: self_sha256(),
        dealer_version: env!("CARGO_PKG_VERSION"),
        hardening: a.hardening.clone(),
        created_at: rutli_cosigner::hosted::now_secs(),
    };
    let record_path = outputs.last().expect("record path");
    write_new(record_path, &serde_json::to_vec_pretty(&record)?)?;

    println!("split {} into {}-of-{} for cluster {}", fingerprint, a.threshold, roster.len(), first.cluster_id);
    println!("  key id:        {}", a.key_id);
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
    group_verifying_key: String,
    public_key_package: frost_ed25519::keys::PublicKeyPackage,
    pkp_digest: String,
    recipients: Vec<RecordRecipient>,
    bundles: Vec<String>,
    dealer_binary_sha256: String,
    dealer_version: &'static str,
    hardening: Hardening,
    created_at: u64,
}

#[derive(Serialize)]
struct RecordRecipient {
    identifier: u16,
    recipient_pub: String,
}

/// Read every request and check they describe one ceremony: same key, ceremony, cluster, threshold,
/// size and roster; one request per roster member, no duplicates, no strays.
fn read_recipients(paths: &[PathBuf]) -> Result<Vec<RecipientRequest>> {
    let mut requests = Vec::with_capacity(paths.len());
    for p in paths {
        let r: RecipientRequest = serde_json::from_slice(&std::fs::read(p)?)
            .map_err(|e| refuse(format!("{} is not a share-recipient request: {e}", p.display())))?;
        r.validate().map_err(|e| refuse(format!("{}: {e}", p.display())))?;
        requests.push(r);
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

/// Hex text → bytes, tolerating whitespace and a psql `\x` prefix.
fn decode_hex_text(text: &[u8]) -> Result<Vec<u8>> {
    let mut s: Zeroizing<String> =
        Zeroizing::new(text.iter().filter(|b| !b.is_ascii_whitespace()).map(|&b| b as char).collect());
    if let Some(rest) = s.strip_prefix("\\x") {
        *s = rest.to_string();
    }
    hex::decode(s.as_bytes()).map_err(|_| refuse("--stored-hex: the input is not hex".into()))
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
    #[cfg(not(target_os = "linux"))]
    let (not_dumpable, memory_locked, swap_enabled) = (false, false, None);
    Hardening { core_dumps_disabled, not_dumpable, memory_locked, swap_enabled }
}

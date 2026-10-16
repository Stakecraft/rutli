// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner restore` (audit M1): epoch-checked, all-or-nothing verification, atomic install.
//!
//! Before, restore was a plain `std::fs::copy` of every file in the backup over `data_dir/keys` —
//! no fsync, no comparison, and `--force` happily put an old epoch's share back over a refreshed one
//! (the node then signed with a sharing nobody else held) or a deleted hosted key back over its
//! tombstone.
//!
//! Now:
//!
//! 1. **Every file is verified before anything is written.** Each backup file is opened exactly
//!    like a live key file of this node ([`KeyStore::load_foreign`]): sealed (a plaintext file is
//!    refused under sealing), its v2 header naming this cluster, this node and the file's key id,
//!    the record consistent with it. One refusal refuses the whole restore.
//! 2. **No rollback, even with `--force`.** A FROST share older than the live one (or than the
//!    newest epoch this node's ceremony records say it committed), another sharing at the same
//!    epoch, or a hosted key over its tombstone is refused unless a per-key break-glass names the
//!    exact backup (`--break-glass --key-id K --expected-epoch E --expected-digest D`, printed in the
//!    refusal). Another group key under the same id, or another record kind, is always refused.
//!    `--force` only allows going forward: a newer epoch, a tombstone over a live key.
//! 3. **Atomic install.** The verified bytes are copied verbatim into `keys/.restore-<uuid>/`
//!    (fsynced), then each is renamed over its target (atomic per file) and the directory fsynced.
//!    A crash before the renames leaves the live store untouched (the staging dot-dir is ignored
//!    and swept by the next restore); a crash during them leaves every file either old or new.
//! 4. The command holds the instance lock (the daemon must be stopped), and the restored node goes
//!    through the stale-share check at its next start: a share behind its peers is refused for
//!    signing until it is current.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::ceremony_record::{CeremonyRecords, RecordState};
use crate::keystore::{KeyStore, Record};
use crate::{DaemonError, Result};

/// Name prefix of the restore staging directory inside the key store (a dot-dir).
pub const STAGING_PREFIX: &str = ".restore-";

/// Restore one key despite a rollback refusal, naming exactly the backup file allowed.
#[derive(Clone, Debug)]
pub struct BreakGlass {
    pub key_id: String,
    pub expected_epoch: u64,
    /// The backup file's identity as the refusal printed it: a share's PKP digest, else the
    /// SHA-256 of the backup file (hex).
    pub expected_digest: String,
}

/// What a verified restore will do.
#[derive(Debug, Default)]
pub struct Plan {
    /// (key id, backup file) to install.
    pub install: Vec<(String, PathBuf)>,
    /// (key id, why it is left alone).
    pub skipped: Vec<(String, String)>,
    /// Keys installed under the break-glass.
    pub broke_glass: Vec<String>,
    /// Break-glass "cleared delete intent" markers (`keys/.cleared/<key>.<intent digest>`) in the
    /// backup, to merge into this node's (audit F7): without them a node restored after an
    /// undelete would accept the cleared tombstone again from a peer.
    pub cleared: Vec<String>,
}

/// The identity a refusal prints and a break-glass must name.
fn identity(record: &Record, file_bytes: &[u8]) -> Result<(u64, String)> {
    Ok(match record {
        Record::Frost(s) => (s.epoch, hex::encode(s.pkp_digest()?)),
        _ => (0, hex::encode(Sha256::digest(file_bytes))),
    })
}

/// The newest epoch this node's ceremony records say it committed for each key.
fn committed_epochs(ks: &KeyStore) -> Result<std::collections::HashMap<String, u64>> {
    let mut out = std::collections::HashMap::new();
    for r in CeremonyRecords::open(ks.ceremony_dir()).load_all()? {
        if r.state == RecordState::Committed {
            let e = out.entry(r.key_id.clone()).or_insert(0);
            *e = (*e).max(r.new_epoch);
        }
    }
    Ok(out)
}

/// Verify every key file in `from` against this node's live store and decide what to install.
/// Any refusal is an error and nothing is installed.
pub fn plan(ks: &KeyStore, from: &Path, force: bool, break_glass: Option<&BreakGlass>) -> Result<Plan> {
    if !from.is_dir() {
        return Err(DaemonError::Config(format!("{} is not a directory", from.display())));
    }
    let committed = committed_epochs(ks)?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Key files only: dotfiles (probe files, temps), nonce dirs and a journal directory in the
        // same backup are never restored.
        if name.starts_with('.') || !name.ends_with(".json") || !entry.file_type()?.is_file() {
            continue;
        }
        files.push(entry.path());
    }
    files.sort();
    let mut plan = Plan { cleared: cleared_markers(&from.join(crate::keystore::CLEARED_DIR))?, ..Plan::default() };
    let mut refusals = Vec::new();
    for path in files {
        let key_id = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
        match decide(ks, &path, &key_id, force, break_glass, committed.get(&key_id).copied()) {
            Ok(Decision::Install { broke_glass }) => {
                if broke_glass {
                    plan.broke_glass.push(key_id.clone());
                }
                plan.install.push((key_id, path));
            }
            Ok(Decision::Skip(why)) => plan.skipped.push((key_id, why)),
            Err(e) => refusals.push(format!("{key_id}: {e}")),
        }
    }
    if let Some(bg) = break_glass {
        if !plan.broke_glass.contains(&bg.key_id) {
            refusals.push(format!("--break-glass names {}, which this restore does not need it for", bg.key_id));
        }
    }
    if !refusals.is_empty() {
        return Err(DaemonError::Config(format!(
            "restore refused — nothing was written:\n  {}",
            refusals.join("\n  ")
        )));
    }
    Ok(plan)
}

/// The marker names in a backup's `.cleared/`: `<key id>.<64 hex>`, anything else ignored.
fn cleared_markers(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let valid = entry.file_type()?.is_file()
            && name.split_once('.').is_some_and(|(k, d)| {
                !k.is_empty()
                    && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    && d.len() == 64
                    && d.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            });
        if valid {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

enum Decision {
    Install { broke_glass: bool },
    Skip(String),
}

fn decide(
    ks: &KeyStore,
    path: &Path,
    key_id: &str,
    force: bool,
    break_glass: Option<&BreakGlass>,
    committed_epoch: Option<u64>,
) -> Result<Decision> {
    let bytes = std::fs::read(path)?;
    let (backup, _hdr) = ks.load_foreign(path, key_id)?;
    let (epoch, digest) = identity(&backup, &bytes)?;
    let glass = break_glass.filter(|b| b.key_id == key_id);
    // A refusal a break-glass naming exactly this backup may override.
    let rollback = |why: String| -> Result<Decision> {
        match glass {
            Some(b) if b.expected_epoch == epoch && b.expected_digest.eq_ignore_ascii_case(&digest) => {
                tracing::warn!(key_id, epoch, digest = %digest, "BREAK-GLASS restore: {why}");
                Ok(Decision::Install { broke_glass: true })
            }
            Some(_) => Err(DaemonError::Config(format!(
                "{why}; the break-glass does not name this backup (it is epoch {epoch}, digest {digest})"
            ))),
            None => Err(DaemonError::Config(format!(
                "{why} — refused even with --force. To restore it anyway (BREAK-GLASS): --break-glass \
                 --key-id {key_id} --expected-epoch {epoch} --expected-digest {digest}"
            ))),
        }
    };
    let live = match ks.load_record(key_id) {
        Ok(r) => Some(r),
        Err(DaemonError::UnknownKey(_)) => None,
        Err(e) => return Err(DaemonError::Config(format!("the live file cannot be read ({e}) — resolve it first"))),
    };
    let overwrite = |what: &str| -> Result<Decision> {
        if force {
            Ok(Decision::Install { broke_glass: false })
        } else {
            Err(DaemonError::Config(format!("{what}; pass --force to replace the live file")))
        }
    };
    match (&backup, live.as_ref()) {
        (Record::Frost(b), None) => match committed_epoch {
            Some(c) if b.epoch < c => rollback(format!(
                "the backup holds epoch {} but this node committed epoch {c} of this key (ceremony records) — \
                 an old sharing",
                b.epoch
            )),
            _ => Ok(Decision::Install { broke_glass: false }),
        },
        (Record::Frost(b), Some(Record::Frost(l))) => {
            if b.public_key_package.verifying_key() != l.public_key_package.verifying_key() {
                return Err(DaemonError::Config(
                    "the backup is a share of ANOTHER group key under this id — never restored over the live key".into(),
                ));
            }
            let (bd, ld) = (b.pkp_digest()?, l.pkp_digest()?);
            if b.epoch == l.epoch && bd == ld {
                return Ok(Decision::Skip(format!("same sharing as live (epoch {})", l.epoch)));
            }
            if b.epoch < l.epoch || committed_epoch.is_some_and(|c| b.epoch < c) {
                return rollback(format!(
                    "the backup holds epoch {} but the live share is epoch {} — restoring it would roll the share \
                     back to a sharing the other nodes no longer hold",
                    b.epoch, l.epoch
                ));
            }
            if b.epoch == l.epoch {
                return rollback(format!("the backup is another sharing at the live epoch {}", l.epoch));
            }
            overwrite(&format!("the backup holds a newer epoch ({} > live {})", b.epoch, l.epoch))
        }
        (Record::Hosted(_), None) | (Record::Tombstone(_), None) => Ok(Decision::Install { broke_glass: false }),
        (Record::Hosted(b), Some(Record::Hosted(l))) => {
            if b.spec == l.spec && b.private_der == l.private_der {
                Ok(Decision::Skip("same hosted key as live".into()))
            } else {
                rollback("the backup holds DIFFERENT material under this hosted key id (ids are create-once)".into())
            }
        }
        (Record::Hosted(_), Some(Record::Tombstone(_))) => {
            rollback("the live file is this key's TOMBSTONE: the key was deleted".into())
        }
        (Record::Tombstone(_), Some(Record::Tombstone(_))) => Ok(Decision::Skip("already tombstoned".into())),
        (Record::Tombstone(_), Some(Record::Hosted(_))) => overwrite("the backup deletes the live hosted key"),
        (_, Some(_)) => Err(DaemonError::Config(
            "the backup and the live file hold different kinds of record — never restored".into(),
        )),
    }
}

/// Install a verified plan atomically per file (see the module docs). `crash_after_staging`:
/// fault injection for tests — fail after the staging copy, before any rename.
pub fn apply(ks: &KeyStore, plan: &Plan, crash_after_staging: bool) -> Result<usize> {
    sweep_staging(ks)?;
    // Markers only ever add a refusal (a cleared intent's tombstone is ignored), so they are merged:
    // created if missing, never removed.
    if !plan.cleared.is_empty() {
        let dir = ks.dir().join(crate::keystore::CLEARED_DIR);
        crate::keystore::ensure_private_dir(&dir)?;
        for name in &plan.cleared {
            let path = dir.join(name);
            if !path.exists() {
                crate::keystore::private_file(&path, true)?.sync_all()?;
            }
        }
        std::fs::File::open(&dir)?.sync_all()?;
    }
    if plan.install.is_empty() {
        return Ok(0);
    }
    let staging = ks.dir().join(format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4()));
    crate::keystore::ensure_private_dir(&staging)?;
    for (key_id, src) in &plan.install {
        use std::io::Write;
        let bytes = std::fs::read(src)?;
        let mut f = crate::keystore::private_file(&staging.join(format!("{key_id}.json")), true)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::File::open(&staging)?.sync_all()?;
    if crash_after_staging {
        return Err(DaemonError::Config("injected crash after staging".into()));
    }
    for (key_id, _) in &plan.install {
        std::fs::rename(staging.join(format!("{key_id}.json")), ks.dir().join(format!("{key_id}.json")))?;
    }
    std::fs::File::open(ks.dir())?.sync_all()?;
    std::fs::remove_dir_all(&staging)?;
    Ok(plan.install.len())
}

/// Remove staging directories a crashed restore left behind (they never became live).
pub fn sweep_staging(ks: &KeyStore) -> Result<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir(ks.dir())? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(STAGING_PREFIX) && entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
            n += 1;
        }
    }
    Ok(n)
}

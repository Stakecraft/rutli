// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! On-disk store for this node's key shares.
//!
//! A share is this cosigner's [`frost::keys::KeyPackage`] plus the group
//! [`frost::keys::PublicKeyPackage`], serialized as JSON, one file per `key_id`. The KeyPackage
//! contains only this node's secret share — never the whole private key, which is never assembled.
//!
//! With a [`Sealer`], shares are AES-256-GCM envelopes on disk. Legacy plaintext files are
//! re-sealed at startup via [`KeyStore::reseal_plaintext_shares`]. Without a sealer (dev only),
//! shares remain plaintext JSON.

use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::seal::Sealer;
use crate::{DaemonError, Result};

#[derive(Serialize, Deserialize)]
pub struct Share {
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
    /// Where the key came from. `None` — every file written before the split ceremony existed, and
    /// every DKG key since — means it was born distributed by DKG. Inside the sealed envelope, so
    /// backup/restore carry it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<KeyOrigin>,
}

/// Provenance of a share that did not come from DKG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyOrigin {
    /// [`ORIGIN_DEALER_SPLIT`]: installed by `import-share` from a trusted-dealer split of an
    /// existing Canton key (docs/split-ceremony.md).
    pub kind: String,
    pub ceremony_id: String,
    pub canton_fingerprint: String,
    /// Seconds since the Unix epoch.
    pub installed_at: u64,
    /// Completed proactive refreshes since install. Zero means the shares are still the ones the
    /// dealer handed out — every copy of a dealt bundle, and the dealer's memory, still combine
    /// with the live shares. The daemon warns about such keys at startup.
    #[serde(default)]
    pub refresh_count: u64,
    /// What the key was carried for and its recorded Canton usage, from the dealer's bundle (B6).
    /// `None` for a key installed from a B2 bundle, which did not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried_usage: Option<crate::carry::CarriedUsage>,
}

pub const ORIGIN_DEALER_SPLIT: &str = "dealer-split";

/// What a key file holds. FROST shares and cluster-hosted whole keys live in the *same* directory
/// and the same sealed envelope, distinguished by a `kind` tag in the plaintext.
///
/// They share a directory deliberately: `rutli-cosigner backup` flat-copies `data_dir/keys/`, so a
/// sibling directory would be silently skipped from every backup — the exact class of failure
/// hosted keys exist to prevent.
///
/// Legacy files (written before hosted keys existed) have no `kind` field and parse as
/// [`Record::Frost`], so an upgrade needs no migration.
pub enum Record {
    // Boxed: a FROST Share carries the key + public-key packages and dwarfs a hosted record, so an
    // unboxed enum would make every Record as large as the biggest variant.
    Frost(Box<Share>),
    Hosted(Box<crate::hosted::HostedKey>),
}

/// The `kind` tag written into hosted-key files. FROST files carry no tag (backward compatible).
const KIND_HOSTED: &str = "hosted";

/// Fault-injection seam: called with the path a key-store operation is about to touch, before it
/// touches it — every key-file read, write and delete, the hosted-key listing, and the readiness
/// probe. Lets a test make the store *hang* (a dead NFS/CSI mount, a frozen volume), which file
/// permissions cannot simulate. Not reachable from config; unset in the daemon.
pub type IoHook = Arc<dyn Fn(&Path) + Send + Sync>;

pub struct KeyStore {
    dir: PathBuf,
    sealer: Option<Arc<Sealer>>,
    io_hook: Option<IoHook>,
}

impl KeyStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_sealer(dir, None)
    }

    /// Open the store with optional share sealing. With a sealer, every write is encrypted
    /// (AES-256-GCM envelope). Call [`reseal_plaintext_shares`] after open to migrate any legacy
    /// plaintext files immediately. Without a sealer, reading a sealed share fails loudly.
    pub fn open_with_sealer(dir: impl Into<PathBuf>, sealer: Option<Arc<Sealer>>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, sealer, io_hook: None })
    }

    /// Install a fault-injection [`IoHook`]. Tests only — see its docs. Must be set before the
    /// store is handed to a [`crate::node::Node`], which passes it on to the readiness probe.
    #[doc(hidden)]
    pub fn with_io_hook(mut self, hook: IoHook) -> Self {
        self.io_hook = Some(hook);
        self
    }

    pub(crate) fn io_hook(&self) -> Option<IoHook> {
        self.io_hook.clone()
    }

    fn touch(&self, path: &Path) {
        if let Some(hook) = &self.io_hook {
            hook(path);
        }
    }

    /// When sealing is enabled, rewrite any leftover plaintext share files as sealed envelopes.
    /// Idempotent: already-sealed files are left alone. Returns how many files were re-sealed.
    pub fn reseal_plaintext_shares(&self) -> Result<usize> {
        let Some(_) = &self.sealer else {
            return Ok(0);
        };
        let mut migrated = 0usize;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".json") {
                continue;
            }
            let key_id = name.trim_end_matches(".json");
            let bytes = std::fs::read(entry.path())?;
            if Sealer::is_sealed(&bytes) {
                continue;
            }
            // load_record() accepts plaintext under a sealer; the save path always writes sealed.
            // Must be record-aware: blindly parsing every file as a FROST Share would fail on a
            // hosted key that was written while sealing was off.
            match self.load_record(key_id)? {
                Record::Frost(share) => self.save(key_id, &share)?,
                Record::Hosted(k) => self.save_hosted(key_id, &k)?,
            }
            migrated += 1;
            tracing::info!(key_id, "re-sealed legacy plaintext share at rest");
        }
        Ok(migrated)
    }

    fn path(&self, key_id: &str) -> Result<PathBuf> {
        if key_id.is_empty()
            || !key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DaemonError::Config(format!("invalid key id: {key_id:?}")));
        }
        Ok(self.dir.join(format!("{key_id}.json")))
    }

    /// Advisory only: a lookup error (EACCES, a dead mount) reads as "absent". Nothing load-bearing
    /// hangs on it — loads and deletes use `try_exists` and surface the error, a store the daemon
    /// cannot stat it cannot write either (stat needs only the directory search permission that
    /// create and rename also need), and a node whose store fails its readiness probe refuses
    /// DKG/refresh at the fence and every key operation at the RPC entry ([`crate::health`]).
    pub fn exists(&self, key_id: &str) -> bool {
        self.path(key_id)
            .map(|p| {
                self.touch(&p);
                p.exists()
            })
            .unwrap_or(false)
    }

    pub fn save(&self, key_id: &str, share: &Share) -> Result<()> {
        self.write_sealed(key_id, &serde_json::to_vec_pretty(share)?)
    }

    /// Persist a **new** share: fails with [`DaemonError::KeyExists`] if any file already exists
    /// for `key_id`, atomically — two racing creates (a DKG and an `import-share`, two imports, a
    /// hosted-key push) cannot both succeed and neither can overwrite the other. Same durability as
    /// [`save`]: see [`KeyStore::create_bytes`].
    ///
    /// [`save`]: KeyStore::save
    pub fn create(&self, key_id: &str, share: &Share) -> Result<()> {
        let plain = crate::share_delivery::to_json_zeroizing(share)?;
        self.create_bytes(key_id, &plain)
    }

    /// [`KeyStore::create`] for a cluster-hosted key: a new hosted key never replaces any file —
    /// in particular never an installed FROST share under the same id.
    pub fn create_hosted(&self, key_id: &str, key: &crate::hosted::HostedKey) -> Result<()> {
        let mut value = serde_json::to_value(key)?;
        value
            .as_object_mut()
            .expect("HostedKey serializes to a JSON object")
            .insert("kind".into(), serde_json::Value::String(KIND_HOSTED.into()));
        self.create_bytes(key_id, &zeroize::Zeroizing::new(serde_json::to_vec(&value)?))
    }

    /// Seal `plain` into a uniquely named dotfile temp (fsynced), move it into place **only if
    /// nothing is there**, then fsync the directory. The no-replace move is `renameat2(…,
    /// RENAME_NOREPLACE)` on Linux/glibc and `renamex_np(…, RENAME_EXCL)` on macOS; where the
    /// filesystem or platform lacks it, `link(2)` (which also refuses an existing target) is the
    /// fallback, and a filesystem with neither is a clear error rather than a silent overwrite.
    /// Temps orphaned by a crash are removed by [`KeyStore::sweep_stale_create_temps`].
    fn create_bytes(&self, key_id: &str, plain: &[u8]) -> Result<()> {
        let path = self.path(key_id)?;
        self.touch(&path);
        let bytes = match &self.sealer {
            Some(s) => s.seal(plain)?,
            None => plain.to_vec(),
        };
        // A dotfile: never a key file (ids are [A-Za-z0-9_-]+), skipped by backup and the probe.
        let tmp = self.dir.join(format!("{CREATE_TMP_PREFIX}{key_id}-{}.tmp", uuid::Uuid::new_v4()));
        {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        let outcome = match rename_noreplace(&tmp, &path) {
            Ok(NoReplace::Moved) => Ok(()),
            Ok(NoReplace::Exists) => Err(DaemonError::KeyExists(key_id.to_string())),
            Ok(NoReplace::Unsupported) => match std::fs::hard_link(&tmp, &path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(DaemonError::KeyExists(key_id.to_string()))
                }
                Err(e) => Err(DaemonError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "the key store filesystem supports neither a no-replace rename nor hard \
                         links ({e}); create-once writes need one of them — refusing rather than \
                         risk overwriting a key"
                    ),
                ))),
            },
            Err(e) => Err(e.into()),
        };
        let _ = std::fs::remove_file(&tmp); // already gone after a successful rename
        outcome?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Remove `.create-*.tmp` files older than `older_than`: left behind when a create crashed
    /// between writing its temp and moving it into place. They hold a sealed key that never became
    /// live. Run at daemon start; returns the names removed (for the log).
    pub fn sweep_stale_create_temps(&self, older_than: std::time::Duration) -> Result<Vec<String>> {
        self.touch(&self.dir);
        let mut removed = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.starts_with(CREATE_TMP_PREFIX) && name.ends_with(".tmp")) {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= older_than);
            if stale && std::fs::remove_file(entry.path()).is_ok() {
                removed.push(name);
            }
        }
        if !removed.is_empty() {
            std::fs::File::open(&self.dir)?.sync_all()?;
        }
        Ok(removed)
    }

    /// FROST keys installed by the split ceremony that have not been refreshed since: their live
    /// shares are still the dealt ones. Unreadable files are skipped (they are reported elsewhere).
    pub fn dealt_keys_never_refreshed(&self) -> Result<Vec<String>> {
        self.touch(&self.dir);
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(key_id) = name.strip_suffix(".json") else { continue };
            if let Ok(Record::Frost(share)) = self.load_record(key_id) {
                if share.origin.as_ref().is_some_and(|o| o.refresh_count == 0) {
                    out.push(key_id.to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Seal `plain` and write it durably: temp file + fsync, atomic rename, fsync the directory —
    /// so a key survives power loss. Shared by FROST shares and hosted keys.
    fn write_sealed(&self, key_id: &str, plain: &[u8]) -> Result<()> {
        let path = self.path(key_id)?;
        self.touch(&path);
        let tmp = path.with_extension("json.tmp");
        let bytes = match &self.sealer {
            Some(s) => s.seal(plain)?,
            None => plain.to_vec(),
        };
        // Write + fsync the temp file, atomically rename, then fsync the directory — so a share
        // survives power loss as durably as the nonce store (which already fsyncs). Without this a
        // crash right after DKG could lose the just-generated share while peers kept theirs.
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        std::fs::File::open(&self.dir)?.sync_all()?; // fsync the directory entry (the rename)
        Ok(())
    }

    pub fn load(&self, key_id: &str) -> Result<Share> {
        match self.load_record(key_id)? {
            Record::Frost(s) => Ok(*s),
            Record::Hosted(_) => Err(DaemonError::Config(format!(
                "{key_id} is a cluster-hosted key, not a FROST share"
            ))),
        }
    }

    /// Read a key file and unseal it, without interpreting the contents.
    fn read_plaintext(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.path(key_id)?;
        self.touch(&path);
        // try_exists, not exists: an unreadable store must surface as an IO error (INTERNAL), never
        // as UnknownKey (NOT_FOUND) — Canton would take NOT_FOUND to mean the key is gone.
        if !path.try_exists()? {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        let bytes = std::fs::read(&path)?;
        let plain = match (&self.sealer, Sealer::is_sealed(&bytes)) {
            (Some(s), true) => s.unseal(&bytes)?,
            // Sealing on, legacy plaintext file: readable (migration path); re-sealed on next save.
            (Some(_), false) => bytes,
            (None, true) => {
                return Err(DaemonError::Config(format!(
                    "share {key_id} is sealed but share sealing is not configured on this node"
                )))
            }
            (None, false) => bytes,
        };
        Ok(plain)
    }

    // -- cluster-hosted (non-FROST) keys --

    /// Persist a hosted key, sealed, with the same atomic + fsync discipline as a FROST share.
    pub fn save_hosted(&self, key_id: &str, key: &crate::hosted::HostedKey) -> Result<()> {
        let mut value = serde_json::to_value(key)?;
        value
            .as_object_mut()
            .expect("HostedKey serializes to a JSON object")
            .insert("kind".into(), serde_json::Value::String(KIND_HOSTED.into()));
        self.write_sealed(key_id, &serde_json::to_vec_pretty(&value)?)
    }

    pub fn load_hosted(&self, key_id: &str) -> Result<crate::hosted::HostedKey> {
        match self.load_record(key_id)? {
            Record::Hosted(k) => Ok(*k),
            Record::Frost(_) => Err(DaemonError::Config(format!(
                "{key_id} is a FROST share, not a cluster-hosted key"
            ))),
        }
    }

    /// Read a key file without knowing its type up front.
    pub fn load_record(&self, key_id: &str) -> Result<Record> {
        let plain = self.read_plaintext(key_id)?;
        let value: serde_json::Value = serde_json::from_slice(&plain)?;
        let is_hosted = value.get("kind").and_then(|k| k.as_str()) == Some(KIND_HOSTED);
        if is_hosted {
            Ok(Record::Hosted(Box::new(serde_json::from_value(value)?)))
        } else {
            Ok(Record::Frost(Box::new(serde_json::from_value(value)?)))
        }
    }

    /// Key ids of every hosted key on this node (FROST shares excluded).
    pub fn list_hosted(&self) -> Result<Vec<String>> {
        self.touch(&self.dir);
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(key_id) = name.strip_suffix(".json") else { continue };
            // An unreadable file (wrong seal secret after a rotation, a partial restore, disk
            // corruption) is reported loudly and skipped — NOT fatal to the whole listing.
            //
            // Failing the inventory would stop anti-entropy for every *healthy* key too, turning
            // one damaged file into a cluster-wide halt of self-healing. Skipping is safe because
            // absence from a listing never causes a delete: peers only push keys the listing lacks,
            // and a push onto an unreadable local file still fails closed in `hosted_store` rather
            // than overwriting it.
            match self.load_record(key_id) {
                Ok(Record::Hosted(_)) => out.push(key_id.to_string()),
                Ok(Record::Frost(_)) => {}
                Err(e) => {
                    metrics::counter!(crate::metrics::UNREADABLE_KEY_FILES).increment(1);
                    tracing::error!(
                        key_id = %key_id,
                        error = %e,
                        "unreadable key file in keystore — skipped from the hosted-key inventory; \
                         it will not be replicated or repaired until an operator resolves it"
                    );
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Remove a key file. Physical erasure is best-effort: on copy-on-write filesystems, SSDs with
    /// wear levelling, and snapshotted volumes the sealed bytes may survive. Real destruction means
    /// rotating the seal master secret.
    pub fn delete(&self, key_id: &str) -> Result<()> {
        let path = self.path(key_id)?;
        self.touch(&path);
        if path.try_exists()? {
            std::fs::remove_file(&path)?;
            std::fs::File::open(&self.dir)?.sync_all()?;
        }
        Ok(())
    }

    pub fn nonce_dir(&self, key_id: &str) -> PathBuf {
        self.dir.join(format!("{key_id}.nonces"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Readiness probe: can this node still list, open, read and write its key store?
    ///
    /// Deliberately an OS-level check, NOT an unseal: a file that opens but will not unseal (seal
    /// secret rotated, foreign restore, corruption) is a per-file problem an operator fixes, already
    /// reported by `rutli_unreadable_key_files_total`, and the node still signs every other key.
    /// This probe catches the *volume* failing — a remount, a permission change, a read-only or
    /// dead mount — which takes every key on the node down at once (2026-10-07 DevNet incident:
    /// the node answered every Sign with `Permission denied (os error 13)` while reporting healthy).
    /// For the same reason, *some* key files failing to open (one mis-chowned file) is counted in
    /// `rutli_unreadable_key_files_total` and logged, not failed: only all of them failing is.
    ///
    /// Cheap enough to run every few seconds: one `read_dir`, a few bytes from each `*.json`, and a
    /// create+remove of a uniquely named dotfile (a sign must write nonce markers, so a read-only
    /// store is the same outage). See [`KeyStore::check_dir`] for the details.
    pub fn check_readable(&self) -> Result<()> {
        Self::check_dir(&self.dir)
    }

    /// [`KeyStore::check_readable`] on a bare directory, without opening a store — `open` would
    /// `mkdir` a missing key directory, which a read-only probe must never do. Used by the
    /// `rutli-cosigner health` container probe.
    pub fn check_dir(dir: &Path) -> Result<()> {
        use std::io::Read;
        let failed = |path: &Path, what: &'static str| {
            let path = path.to_path_buf();
            move |source| DaemonError::KeystoreUnavailable { path, what, source }
        };

        // (opened, unopenable): a subset failing is a per-file problem, every one failing is the volume.
        let mut opened = 0usize;
        let mut unopenable: Vec<(std::path::PathBuf, std::io::Error)> = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(failed(dir, "unreadable"))? {
            let entry = entry.map_err(failed(dir, "unreadable"))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if name.starts_with(PROBE_PREFIX) {
                sweep_stale_probe(&path);
                continue;
            }
            // `*.json` only: `*.json.tmp` is an in-flight write and `*.nonces` is a directory.
            if !name.ends_with(".json") {
                continue;
            }
            // EACCES surfaces on open; a dead mount or stale handle on read.
            let probe = std::fs::File::open(&path).and_then(|mut f| f.read(&mut [0u8; 16]));
            match probe {
                Ok(_) => opened += 1,
                // Deleted (hosted-key delete) between read_dir and open — not a volume problem.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => unopenable.push((path, e)),
            }
        }
        if opened == 0 {
            if let Some((path, e)) = unopenable.pop() {
                return Err(failed(&path, "unreadable")(e));
            }
        }
        for (path, e) in unopenable {
            metrics::counter!(crate::metrics::UNREADABLE_KEY_FILES).increment(1);
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "key file cannot be opened — that key is unusable on this node, the rest of the key \
                 store is fine; fix its ownership/permissions"
            );
        }

        // Write probe. The name is unique per process AND per call: the daemon (its monitor loop
        // and every Health RPC) and the container's exec probe — a separate process — probe the
        // same directory concurrently. `create_new` so a probe can never clobber anything.
        let probe = dir.join(format!(
            "{PROBE_PREFIX}{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
            PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        // Create only, no data written — the same operation a sign needs (NonceStore::consume
        // creates an O_EXCL marker and ignores a failed write), so a data-full disk does not take a
        // node out of signing that could still sign. Inode exhaustion fails here, as it would there.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .map_err(failed(dir, "not writable"))?;
        match std::fs::remove_file(&probe) {
            // NotFound: a concurrent prober swept it as stale. Nothing left behind either way.
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(failed(dir, "not writable")(e))
            }
            _ => Ok(()),
        }
    }
}

/// Name prefix of [`KeyStore::create`]'s temp files (a dotfile, like the probe's).
const CREATE_TMP_PREFIX: &str = ".create-";

enum NoReplace {
    Moved,
    Exists,
    /// The platform or filesystem has no no-replace rename: use the `link(2)` fallback.
    Unsupported,
}

/// Rename `from` to `to` unless `to` exists, atomically.
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<NoReplace> {
    #[cfg(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::other("path contains a NUL byte"))
        };
        let (from_c, to_c) = (c(from)?, c(to)?);
        // SAFETY: two valid NUL-terminated paths; no memory is shared with the call.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from_c.as_ptr(),
                libc::AT_FDCWD,
                to_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        // SAFETY: as above.
        #[cfg(target_os = "macos")]
        let rc = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
        if rc == 0 {
            return Ok(NoReplace::Moved);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EEXIST) => Ok(NoReplace::Exists),
            // ENOTSUP is EOPNOTSUPP on Linux; macOS reports ENOTSUP for a volume without it.
            Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::ENOTSUP) => Ok(NoReplace::Unsupported),
            _ => Err(err),
        }
    }
    #[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
    {
        let _ = (from, to);
        Ok(NoReplace::Unsupported)
    }
}

/// Name prefix of [`KeyStore::check_dir`]'s write-probe files. A dotfile, so it can never collide
/// with a key file (key ids are `[A-Za-z0-9_-]+`), and `rutli-cosigner backup`/`restore` skip it.
const PROBE_PREFIX: &str = ".readyz-";
static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A probe killed between create and remove (an exec probe hitting its timeout on a slow volume)
/// leaves its file behind. Harmless — nothing reads dotfiles — but clear it up once it is clearly
/// not in flight. Best effort: a failure here is the next probe's (or nobody's) problem.
fn sweep_stale_probe(path: &Path) {
    let stale = std::fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age > std::time::Duration::from_secs(300));
    if stale {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::{HostedKey, HostedSpec};

    fn store(tmp: &tempfile::TempDir, sealed: bool) -> KeyStore {
        let sealer = sealed
            .then(|| Arc::new(crate::seal::Sealer::from_master_secret(b"test master secret", 1)));
        KeyStore::open_with_sealer(tmp.path().join("keys"), sealer).unwrap()
    }

    #[test]
    fn hosted_keys_round_trip_sealed_and_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let key = HostedKey::generate(HostedSpec::Rsa2048, 42).unwrap();
        let ct = key.encrypt_oaep(b"before restart").unwrap();

        store(&tmp, true).save_hosted("rutli-enc-1", &key).unwrap();

        // On-disk file must be a sealed envelope, not readable key material.
        let raw = std::fs::read(tmp.path().join("keys").join("rutli-enc-1.json")).unwrap();
        assert!(crate::seal::Sealer::is_sealed(&raw));
        assert!(!String::from_utf8_lossy(&raw).contains("private_der"));

        // A fresh store (as after a restart) reloads it and can still decrypt.
        let reloaded = store(&tmp, true).load_hosted("rutli-enc-1").unwrap();
        assert_eq!(reloaded.decrypt_oaep(&ct).unwrap().as_slice(), b"before restart");
        assert_eq!(reloaded.created_at, 42);
    }

    #[test]
    fn frost_shares_and_hosted_keys_coexist_without_confusion() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        let hosted = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        ks.save_hosted("rutli-sym-1", &hosted).unwrap();

        // list_hosted must not report FROST shares, and typed loads must refuse the wrong kind.
        assert_eq!(ks.list_hosted().unwrap(), vec!["rutli-sym-1".to_string()]);
        assert!(ks.load("rutli-sym-1").is_err(), "a hosted key must not load as a FROST share");
    }

    #[test]
    fn a_legacy_untagged_share_file_still_loads_as_frost() {
        // Files written before hosted keys existed have no "kind" tag. Upgrading must not need a
        // migration, so an untagged record must still parse as a FROST share.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = serde_json::json!({ "key_package": {}, "public_key_package": {} });
        std::fs::write(dir.join("legacy.json"), serde_json::to_vec(&legacy).unwrap()).unwrap();

        let ks = KeyStore::open(&dir).unwrap();
        // It is not valid FROST content, but it must be *classified* as a share, not as hosted.
        match ks.load_record("legacy") {
            Ok(Record::Frost(_)) => {}
            Ok(Record::Hosted(_)) => panic!("untagged legacy file misclassified as a hosted key"),
            Err(_) => {} // frost rejects the empty packages; classification is what matters here
        }
        assert!(ks.list_hosted().is_err() || ks.list_hosted().unwrap().is_empty());
    }

    /// A real 2-of-3 dealt share for node 1, with or without an origin.
    fn dealt_share(origin: Option<KeyOrigin>) -> Share {
        let (shares, pkp) =
            rutli_frost_core::dealer::split_ed25519_seed(&[5u8; 32], &[1, 2, 3], 2).unwrap();
        let key_package = frost::keys::KeyPackage::try_from(shares[0].clone()).unwrap();
        Share { key_package, public_key_package: pkp, origin }
    }

    fn origin() -> KeyOrigin {
        KeyOrigin {
            kind: ORIGIN_DEALER_SPLIT.into(),
            ceremony_id: "c1".into(),
            canton_fingerprint: "1220ab".into(),
            installed_at: 1,
            refresh_count: 0,
            carried_usage: None,
        }
    }

    #[test]
    fn create_never_clobbers_an_existing_key_file() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.create("frost-import-a", &dealt_share(Some(origin()))).unwrap();
        let before = std::fs::read(ks.dir().join("frost-import-a.json")).unwrap();

        let again = ks.create("frost-import-a", &dealt_share(None));
        assert!(matches!(again, Err(DaemonError::KeyExists(_))), "{:?}", again.err());
        // Nor over a hosted key, nor leaving temp files behind.
        ks.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
        assert!(matches!(ks.create("rutli-x", &dealt_share(None)), Err(DaemonError::KeyExists(_))));
        assert_eq!(std::fs::read(ks.dir().join("frost-import-a.json")).unwrap(), before);
        let names: Vec<String> = std::fs::read_dir(ks.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");

        // What was created is sealed and loads with its origin.
        assert!(crate::seal::Sealer::is_sealed(&before));
        assert_eq!(ks.load("frost-import-a").unwrap().origin, Some(origin()));
    }

    #[test]
    fn racing_creates_have_exactly_one_winner() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Arc::new(store(&tmp, false));
        let wins: usize = (0..8)
            .map(|_| {
                let ks = ks.clone();
                std::thread::spawn(move || ks.create("frost-import-race", &dealt_share(None)).is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap() as usize)
            .sum();
        assert_eq!(wins, 1);
        // Losers leave no temp behind.
        let temps = std::fs::read_dir(ks.dir())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temps, 0);
    }

    #[test]
    fn the_no_replace_move_and_the_link_fallback_both_refuse_an_existing_target() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let (a, b, target) = (dir.join("a"), dir.join("b"), dir.join("t"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        match rename_noreplace(&a, &target).unwrap() {
            NoReplace::Moved => {
                assert!(matches!(rename_noreplace(&b, &target).unwrap(), NoReplace::Exists));
                assert_eq!(std::fs::read(&target).unwrap(), b"a");
            }
            // Platform without it (e.g. musl): create() falls back to link(2).
            NoReplace::Unsupported => {}
            NoReplace::Exists => panic!("target did not exist"),
        }
        assert!(std::fs::hard_link(&b, &target).is_err() || !cfg!(unix));
    }

    #[test]
    fn stale_create_temps_are_swept_and_fresh_ones_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        let temp = ks.dir().join(format!("{CREATE_TMP_PREFIX}frost-import-x-123.tmp"));
        std::fs::write(&temp, b"sealed key that never became live").unwrap();
        std::fs::write(ks.dir().join("not-a-temp.json.tmp"), b"x").unwrap();
        assert!(ks.sweep_stale_create_temps(std::time::Duration::from_secs(3600)).unwrap().is_empty());
        assert!(temp.exists(), "a fresh temp may belong to a create in flight");
        let removed = ks.sweep_stale_create_temps(std::time::Duration::ZERO).unwrap();
        assert_eq!(removed, vec![format!("{CREATE_TMP_PREFIX}frost-import-x-123.tmp")]);
        assert!(!temp.exists());
        assert!(ks.dir().join("not-a-temp.json.tmp").exists(), "only create temps are swept");
    }

    #[test]
    fn create_hosted_never_replaces_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.create("frost-import-a", &dealt_share(Some(origin()))).unwrap();
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        assert!(matches!(ks.create_hosted("frost-import-a", &key), Err(DaemonError::KeyExists(_))));
        assert!(ks.load("frost-import-a").is_ok());
        ks.create_hosted("rutli-sym-1", &key).unwrap();
        assert_eq!(ks.load_hosted("rutli-sym-1").unwrap().created_at, 1);
        assert!(matches!(ks.create_hosted("rutli-sym-1", &key), Err(DaemonError::KeyExists(_))));
    }

    #[test]
    fn a_legacy_share_has_no_origin_and_stays_that_way() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, false);
        // A share file as every release before the split ceremony wrote it: no `origin` field.
        let share = dealt_share(None);
        let legacy = serde_json::json!({
            "key_package": share.key_package,
            "public_key_package": share.public_key_package,
        });
        std::fs::write(ks.dir().join("k.json"), serde_json::to_vec(&legacy).unwrap()).unwrap();
        let loaded = ks.load("k").unwrap();
        assert_eq!(loaded.origin, None, "legacy = DKG");
        // Re-saving a DKG share writes no origin field at all (byte-compatible with old readers).
        ks.save("k", &loaded).unwrap();
        let raw = String::from_utf8(std::fs::read(ks.dir().join("k.json")).unwrap()).unwrap();
        assert!(!raw.contains("origin"), "{raw}");
        // And a dealt share's origin survives a round trip.
        ks.save("d", &dealt_share(Some(origin()))).unwrap();
        assert_eq!(ks.load("d").unwrap().origin, Some(origin()));
    }

    #[test]
    fn unrefreshed_dealt_keys_are_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.create("frost-import-new", &dealt_share(Some(origin()))).unwrap();
        ks.create("frost-import-done", &dealt_share(Some(KeyOrigin { refresh_count: 1, ..origin() })))
            .unwrap();
        ks.create("frost-namespace", &dealt_share(None)).unwrap();
        ks.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
        assert_eq!(ks.dealt_keys_never_refreshed().unwrap(), vec!["frost-import-new".to_string()]);
    }

    #[test]
    fn delete_removes_the_key_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.save_hosted("rutli-enc-2", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();
        assert!(ks.exists("rutli-enc-2"));
        ks.delete("rutli-enc-2").unwrap();
        assert!(!ks.exists("rutli-enc-2"));
        ks.delete("rutli-enc-2").unwrap(); // no-op, not an error
        assert!(ks.load_hosted("rutli-enc-2").is_err());
    }

    #[test]
    fn a_wrong_seal_secret_cannot_open_a_hosted_key() {
        let tmp = tempfile::tempdir().unwrap();
        store(&tmp, true)
            .save_hosted("rutli-enc-3", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();

        let wrong = Arc::new(crate::seal::Sealer::from_master_secret(b"a different master", 1));
        let ks = KeyStore::open_with_sealer(tmp.path().join("keys"), Some(wrong)).unwrap();
        assert!(ks.load_hosted("rutli-enc-3").is_err());
    }

    #[test]
    fn plaintext_hosted_keys_are_resealed_on_startup() {
        // reseal_plaintext_shares used to parse every file as a FROST Share; a hosted key written
        // while sealing was off would have broken startup.
        let tmp = tempfile::tempdir().unwrap();
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 7).unwrap();
        store(&tmp, false).save_hosted("rutli-sym-9", &key).unwrap(); // unsealed

        let sealed = store(&tmp, true);
        assert_eq!(sealed.reseal_plaintext_shares().unwrap(), 1);
        let raw = std::fs::read(tmp.path().join("keys").join("rutli-sym-9.json")).unwrap();
        assert!(crate::seal::Sealer::is_sealed(&raw), "hosted key must be sealed after migration");
        assert_eq!(sealed.load_hosted("rutli-sym-9").unwrap().created_at, 7);
    }

    #[test]
    fn an_unreadable_key_file_is_skipped_not_fatal_to_the_inventory() {
        // Found on a live cluster: a key sealed under a rotated secret made list_hosted fail, which
        // would stop anti-entropy for every *healthy* key too — one damaged file halting all
        // self-healing. It must be reported and skipped instead.
        let tmp = tempfile::tempdir().unwrap();
        let good = store(&tmp, true);
        good.save_hosted("rutli-good", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();

        // A key written under a DIFFERENT master secret, as after a seal-secret rotation.
        let other = Arc::new(crate::seal::Sealer::from_master_secret(b"a rotated master secret", 1));
        KeyStore::open_with_sealer(tmp.path().join("keys"), Some(other))
            .unwrap()
            .save_hosted("rutli-stale", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();

        // The healthy key is still listed and usable; the unreadable one is simply absent.
        let listed = good.list_hosted().expect("one bad file must not fail the whole listing");
        assert_eq!(listed, vec!["rutli-good".to_string()]);
        assert!(good.load_hosted("rutli-good").is_ok());
        // Reading the bad one directly still fails loudly — it is skipped, not treated as absent.
        assert!(good.load_hosted("rutli-stale").is_err());
    }

    /// chmod `path`, returning false (and restoring it) when the process can still read it anyway —
    /// i.e. it runs as root, where permission bits are not enforced and these tests prove nothing.
    #[cfg(unix)]
    fn chmod_enforced(path: &Path, mode: u32, restore: u32) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        let readable = if path.is_dir() {
            std::fs::read_dir(path).is_ok()
        } else {
            std::fs::File::open(path).is_ok()
        };
        if readable && mode & 0o444 == 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(restore)).unwrap();
            eprintln!("permission bits not enforced (running as root?) — skipping");
            return false;
        }
        true
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_readable_fails_on_an_unreadable_key_dir_and_recovers() {
        // The 2026-10-07 incident shape: the volume under /data/keys became unreadable and the node
        // kept reporting healthy while every Sign failed with EACCES.
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.save_hosted("rutli-k", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();
        ks.check_readable().expect("a fresh store with a key must pass");
        let leftovers: Vec<_> = std::fs::read_dir(ks.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "the write probe must clean up after itself: {leftovers:?}");

        if !chmod_enforced(ks.dir(), 0o000, 0o700) {
            return;
        }
        let verdict = ks.check_readable();
        chmod(ks.dir(), 0o700); // restore BEFORE asserting, or a failure leaves an undeletable tempdir

        let msg = verdict.expect_err("an unreadable key dir must fail the probe").to_string();
        assert!(msg.contains(&ks.dir().display().to_string()), "error must name the path: {msg}");
        assert!(msg.contains("unreadable"), "{msg}");
        ks.check_readable().expect("restoring the permissions must clear the verdict");
    }

    #[cfg(unix)]
    #[test]
    fn check_readable_tolerates_one_unopenable_key_file_but_not_all_or_a_read_only_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        for id in ["rutli-k", "rutli-other"] {
            ks.save_hosted(id, &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
        }
        let file = ks.dir().join("rutli-k.json");
        let other = ks.dir().join("rutli-other.json");

        // One key file the daemon cannot open (e.g. re-owned by a foreign job's chown): that key is
        // unusable, but the node still signs everything else — counted and logged, not failed.
        if !chmod_enforced(&file, 0o000, 0o600) {
            return;
        }
        let one_bad = ks.check_readable();
        // Every key file unopenable: that is the volume, not a file.
        chmod(&other, 0o000);
        let all_bad = ks.check_readable();
        chmod(&file, 0o600);
        chmod(&other, 0o600);
        assert!(one_bad.is_ok(), "one bad file among good ones must not fail the node: {one_bad:?}");
        let msg = all_bad.expect_err("every key file unopenable must fail the probe").to_string();
        assert!(msg.contains("unreadable"), "{msg}");
        assert!(msg.contains(&ks.dir().display().to_string()), "error must name the path: {msg}");

        // Readable but not writable (a read-only remount): signing needs to write nonce markers.
        chmod(ks.dir(), 0o500);
        let verdict = ks.check_readable();
        chmod(ks.dir(), 0o700);
        let msg = verdict.expect_err("a read-only key dir must fail the probe").to_string();
        assert!(msg.contains("not writable"), "{msg}");

        ks.check_readable().expect("recovers once permissions are back");
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_store_is_an_io_error_never_unknown_key() {
        // NOT_FOUND is the worst possible answer here: Canton would believe the key is gone.
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, true);
        ks.save_hosted("rutli-k", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap())
            .unwrap();
        if !chmod_enforced(ks.dir(), 0o000, 0o700) {
            return;
        }
        let loaded = ks.load_hosted("rutli-k");
        let deleted = ks.delete("rutli-k");
        chmod(ks.dir(), 0o700);
        assert!(
            matches!(loaded, Err(DaemonError::Io(_))),
            "load on an unreadable store must be an IO error: {:?}",
            loaded.err()
        );
        assert!(matches!(deleted, Err(DaemonError::Io(_))), "delete must not report success");
        assert!(ks.load_hosted("rutli-k").is_ok(), "the key was never gone");
    }

    #[test]
    fn check_readable_ignores_non_key_entries_and_sweeps_only_stale_probe_files() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = store(&tmp, false);
        std::fs::create_dir_all(ks.nonce_dir("k")).unwrap(); // a `*.nonces` directory
        std::fs::write(ks.dir().join("k.json.tmp"), b"partial").unwrap(); // an in-flight write
        // A probe file another prober is still using must survive a concurrent probe.
        let fresh = ks.dir().join(format!("{PROBE_PREFIX}1-2-3"));
        std::fs::write(&fresh, b"1").unwrap();
        ks.check_readable().unwrap();
        assert!(fresh.exists(), "an in-flight probe file of another prober must not be removed");
    }
}

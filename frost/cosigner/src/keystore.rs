// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! On-disk store for this node's key shares.
//!
//! A share is this cosigner's [`frost::keys::KeyPackage`] plus the group
//! [`frost::keys::PublicKeyPackage`], serialized as JSON, one file per `key_id`. The KeyPackage
//! contains only this node's secret share — never the whole private key, which is never assembled.
//!
//! With a [`Sealer`], shares are AES-256-GCM envelopes on disk — key-file format v1, or v2 with a
//! header bound into the associated data ([`crate::seal`], audit M4) — and a plaintext key file is
//! **refused** (the daemon will not start with one; `rutli-cosigner keyfile migrate-plaintext`
//! seals a genuine one, offline). Without a sealer (dev only), shares remain plaintext JSON.
//!
//! Every load checks the record against the file it came from: a v2 header must name this node,
//! the file's key id and the expected kind (checked by the [`Sealer`] before decrypting), and the
//! plaintext must agree with the header — its key id, a share's epoch and PKP digest, the share's
//! FROST identifier is this node's.

use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::seal::{KeyFileHeader, RecordKind, RecordMeta, Sealer};
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
    /// Which sharing of the key this is: 1 after a two-phase DKG commit, +1 per committed refresh.
    /// 0 for every file written before epochs existed (the field is absent and defaults) and for a
    /// share installed by the split ceremony (every node gets the same 0 from the same dealer).
    /// Only the comparison between nodes means anything: two nodes on different epochs hold shares
    /// of different sharings, which never combine (H1/M1).
    #[serde(default)]
    pub epoch: u64,
    /// The key id this share was committed under. Empty for files written before it was recorded.
    /// Inside the sealed plaintext; checked against the file name by later work (M4).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_id: String,
}

impl Share {
    /// SHA-256 of the canonical public key package ([`rutli_frost_core::dealer::pkp_digest`]): two
    /// nodes hold shares of the same sharing iff their digests match.
    pub fn pkp_digest(&self) -> Result<[u8; 32]> {
        Ok(rutli_frost_core::dealer::pkp_digest(&self.public_key_package)?)
    }
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
    /// A deleted hosted key (audit M2). Never served, never overwritten by a key.
    Tombstone(Box<crate::hosted::Tombstone>),
}

/// The `kind` tag written into hosted-key files. FROST files carry no tag (backward compatible).
const KIND_HOSTED: &str = "hosted";
/// The `kind` tag of a tombstone file.
const KIND_TOMBSTONE: &str = "tombstone";

/// The record kinds a file under `keys/` may hold.
const STORE_KINDS: &[RecordKind] = &[RecordKind::FrostShare, RecordKind::HostedKey, RecordKind::Tombstone];

#[derive(Serialize)]
struct TaggedTombstone<'a> {
    #[serde(flatten)]
    t: &'a crate::hosted::Tombstone,
    kind: &'static str,
}

/// A share as written: the [`Share`] itself, or — when it does not name its key id yet (a share
/// built by a ceremony or an import) — the share with `key_id` added, so every file written from
/// now on carries its key id inside the sealed plaintext.
#[derive(Serialize)]
struct NamedShare<'a> {
    #[serde(flatten)]
    share: &'a Share,
    key_id: &'a str,
}

/// A hosted key as written: tagged with its kind and key id (the [`crate::hosted::HostedKey`]
/// reader ignores both).
#[derive(Serialize)]
struct TaggedHosted<'a> {
    #[serde(flatten)]
    key: &'a crate::hosted::HostedKey,
    kind: &'static str,
    key_id: &'a str,
}

/// The digest a v2 header records for a hosted key: SHA-256 over its spec and public half
/// (asymmetric keys), empty for a symmetric key — nothing about secret material leaves the
/// ciphertext.
pub fn hosted_header_digest(key: &crate::hosted::HostedKey) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    if !key.spec.is_asymmetric() {
        return Vec::new();
    }
    let mut h = Sha256::new();
    h.update(b"rutli-hosted-pub-v1\n");
    h.update(key.spec.as_str().as_bytes());
    h.update([0u8]);
    h.update(key.public_der.as_bytes());
    h.finalize().to_vec()
}

/// The plaintext and v2 header metadata of a share to be written under `key_id`.
fn share_plaintext(key_id: &str, share: &Share) -> Result<(zeroize::Zeroizing<Vec<u8>>, [u8; 32])> {
    if !share.key_id.is_empty() && share.key_id != key_id {
        return Err(DaemonError::KeyFile(format!(
            "refusing to write the share of {} under key id {key_id}",
            share.key_id
        )));
    }
    let plain = if share.key_id.is_empty() {
        crate::share_delivery::to_json_zeroizing(&NamedShare { share, key_id })?
    } else {
        crate::share_delivery::to_json_zeroizing(share)?
    };
    Ok((plain, share.pkp_digest()?))
}

fn hosted_plaintext(key_id: &str, key: &crate::hosted::HostedKey) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    crate::share_delivery::to_json_zeroizing(&TaggedHosted { key, kind: KIND_HOSTED, key_id })
}

fn tombstone_plaintext(key_id: &str, t: &crate::hosted::Tombstone) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if t.key_id != key_id {
        return Err(DaemonError::KeyFile(format!("refusing to write the tombstone of {} under {key_id}", t.key_id)));
    }
    crate::share_delivery::to_json_zeroizing(&TaggedTombstone { t, kind: KIND_TOMBSTONE })
}

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
    ///
    /// The directory is made owner-only (`0700`) if it is not already, and every key file is
    /// written `0600` ([`private_file`]) — sealed or not: an unsealed (dev) store holds plaintext
    /// shares, and the process umask must never decide who can read them.
    pub fn open_with_sealer(dir: impl Into<PathBuf>, sealer: Option<Arc<Sealer>>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir)?.permissions().mode();
            if mode & 0o077 != 0 {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
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

    /// With sealing on, the key files (committed and staged) that are plaintext — refused by every
    /// load, so the daemon refuses to start with any (audit M4: a plaintext file dropped on the
    /// volume, or restored, used to be accepted and sealed as genuine). Empty without a sealer.
    pub fn plaintext_files(&self) -> Result<Vec<PathBuf>> {
        if self.sealer.is_none() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for path in self.key_file_paths()? {
            if !Sealer::is_sealed(&std::fs::read(&path)?) {
                out.push(path);
            }
        }
        Ok(out)
    }

    /// Every key file of this store: `keys/<id>.json` and `keys/.staged/<id>.<ceremony>.json`
    /// (temps, probes and nonce directories excluded), sorted.
    pub fn key_file_paths(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for dir in [self.dir.clone(), self.staged_dir()] {
            if !dir.try_exists()? {
                continue;
            }
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || !name.ends_with(".json") || !entry.file_type()?.is_file() {
                    continue;
                }
                out.push(entry.path());
            }
        }
        out.sort();
        Ok(out)
    }

    /// The key id (and ceremony id, for a staged share) a key file path names.
    pub fn key_id_of(&self, path: &Path) -> Option<(String, Option<String>)> {
        let stem = path.file_name()?.to_str()?.strip_suffix(".json")?;
        if path.parent()? == self.staged_dir() {
            let (k, c) = stem.split_once('.')?;
            Some((k.to_string(), Some(c.to_string())))
        } else {
            Some((stem.to_string(), None))
        }
    }

    /// Parse a plaintext key file without sealing it (what `keyfile migrate-plaintext` shows the
    /// operator before it seals anything).
    pub fn inspect_plaintext(&self, key_id: &str) -> Result<Record> {
        let bytes = zeroize::Zeroizing::new(std::fs::read(self.path(key_id)?)?);
        if Sealer::is_sealed(&bytes) {
            return Err(DaemonError::Config(format!("{key_id} is sealed, not plaintext")));
        }
        self.parse_record(key_id, &bytes, None)
    }

    /// Seal a plaintext key file in place (offline `keyfile migrate-plaintext`, under the instance
    /// lock). Refuses a file that is already sealed or does not parse as the record its name says.
    pub fn migrate_plaintext(&self, key_id: &str) -> Result<()> {
        let sealer = self
            .sealer
            .as_ref()
            .ok_or_else(|| DaemonError::Config("share sealing is not configured — nothing to migrate to".into()))?;
        let path = self.path(key_id)?;
        let bytes = std::fs::read(&path)?;
        if Sealer::is_sealed(&bytes) {
            return Err(DaemonError::Config(format!("{} is already sealed", path.display())));
        }
        let record = self.parse_record(key_id, &bytes, None)?;
        tracing::info!(key_id, dek_id = %sealer.current_dek_id(), "sealing a plaintext key file");
        match record {
            Record::Frost(share) => self.save(key_id, &share),
            Record::Hosted(k) => self.save_hosted(key_id, &k),
            Record::Tombstone(t) => self.save_tombstone(key_id, &t),
        }
    }

    /// Re-seal one key file in format `version` under the current DEK (offline `keyfile migrate`
    /// / `keyfile downgrade`, and the daemon's start-up pass). The record is loaded and checked as
    /// usual first, so a file that does not belong here is never re-sealed into looking genuine.
    pub fn rewrite(&self, path: &Path, version: u8) -> Result<()> {
        let sealer = self
            .sealer
            .as_ref()
            .ok_or_else(|| DaemonError::Config("share sealing is not configured".into()))?;
        let (key_id, ceremony) = self
            .key_id_of(path)
            .ok_or_else(|| DaemonError::Config(format!("{} is not a key file", path.display())))?;
        let (plain, record) = match &ceremony {
            Some(c) => {
                let share = self.load_staged(&key_id, c)?;
                let (plain, _) = share_plaintext(&key_id, &share)?;
                (plain, Record::Frost(Box::new(share)))
            }
            None => {
                let record = self.load_record(&key_id)?;
                let plain = match &record {
                    Record::Frost(s) => share_plaintext(&key_id, s)?.0,
                    Record::Hosted(k) => hosted_plaintext(&key_id, k)?,
                    Record::Tombstone(t) => tombstone_plaintext(&key_id, t)?,
                };
                (plain, record)
            }
        };
        let digest = record_digest(&record)?;
        let meta = RecordMeta { kind: record_kind(&record), key_id: &key_id, epoch: record_epoch(&record), digest: &digest };
        let bytes = sealer.seal_record_as(version, &meta, &plain)?;
        let dir = path.parent().expect("a key file has a parent");
        write_atomic(dir, path, &bytes)
    }

    /// What a key file is: its format version and the DEK it is sealed under (`keyfile status`,
    /// the start-up pass). `None` for a plaintext file.
    pub fn file_state(&self, path: &Path) -> Result<Option<(u8, crate::seal::DekUse)>> {
        let bytes = std::fs::read(path)?;
        let Some(version) = crate::seal::file_version(&bytes) else { return Ok(None) };
        let dek = match &self.sealer {
            Some(s) => s.dek_use(&bytes),
            None => crate::seal::DekUse::Unknown,
        };
        Ok(Some((version, dek)))
    }

    /// The daemon's start-up pass: re-seal every key file sealed under a previous DEK (a DEK
    /// rotation) and, when writing v2, every v1 file. A file that cannot be rewritten is logged and
    /// left alone (it is reported as unreadable elsewhere). Returns how many were rewritten.
    pub fn reseal_outdated(&self) -> Result<usize> {
        let Some(sealer) = &self.sealer else { return Ok(0) };
        let target = sealer.binding().write_version;
        let mut n = 0;
        for path in self.key_file_paths()? {
            let Some((version, dek)) = self.file_state(&path)? else { continue };
            let outdated_dek = matches!(dek, crate::seal::DekUse::Previous(_));
            let outdated_fmt = version < target;
            if !(outdated_dek || outdated_fmt) {
                continue;
            }
            match self.rewrite(&path, target.max(version)) {
                Ok(()) => {
                    n += 1;
                    tracing::info!(
                        file = %path.display(),
                        from_format = version,
                        to_format = target.max(version),
                        previous_dek = outdated_dek,
                        "re-sealed key file"
                    );
                }
                Err(e) => tracing::error!(file = %path.display(), error = %e, "could not re-seal key file"),
            }
        }
        Ok(n)
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
        let (plain, digest) = share_plaintext(key_id, share)?;
        let meta = RecordMeta { kind: RecordKind::FrostShare, key_id, epoch: share.epoch, digest: &digest };
        self.write_sealed(key_id, &meta, &plain)
    }

    /// Persist a **new** share: fails with [`DaemonError::KeyExists`] if any file already exists
    /// for `key_id`, atomically — two racing creates (a DKG and an `import-share`, two imports, a
    /// hosted-key push) cannot both succeed and neither can overwrite the other. Same durability as
    /// [`save`]: see [`KeyStore::create_bytes`].
    ///
    /// [`save`]: KeyStore::save
    pub fn create(&self, key_id: &str, share: &Share) -> Result<()> {
        let (plain, digest) = share_plaintext(key_id, share)?;
        let meta = RecordMeta { kind: RecordKind::FrostShare, key_id, epoch: share.epoch, digest: &digest };
        self.create_bytes(key_id, &meta, &plain)
    }

    /// [`KeyStore::create`] for a cluster-hosted key: a new hosted key never replaces any file —
    /// in particular never an installed FROST share under the same id.
    pub fn create_hosted(&self, key_id: &str, key: &crate::hosted::HostedKey) -> Result<()> {
        let plain = hosted_plaintext(key_id, key)?;
        let digest = hosted_header_digest(key);
        let meta = RecordMeta { kind: RecordKind::HostedKey, key_id, epoch: 0, digest: &digest };
        self.create_bytes(key_id, &meta, &plain)
    }

    /// Seal `plain` into a uniquely named dotfile temp (fsynced), move it into place **only if
    /// nothing is there**, then fsync the directory. The no-replace move is `renameat2(…,
    /// RENAME_NOREPLACE)` on Linux/glibc and `renamex_np(…, RENAME_EXCL)` on macOS; where the
    /// filesystem or platform lacks it, `link(2)` (which also refuses an existing target) is the
    /// fallback, and a filesystem with neither is a clear error rather than a silent overwrite.
    /// Temps orphaned by a crash are removed by [`KeyStore::sweep_stale_create_temps`].
    fn create_bytes(&self, key_id: &str, meta: &RecordMeta<'_>, plain: &[u8]) -> Result<()> {
        let path = self.path(key_id)?;
        self.create_sealed_at(&self.dir, &path, key_id, meta, plain)
    }

    /// The create-once write behind [`KeyStore::create_bytes`] and [`KeyStore::stage`]: seal
    /// `plain`, write a dotfile temp in `dir` (fsynced), move it to `path` only if nothing is
    /// there, fsync `dir`. `label` names the key in errors and in the temp's name.
    fn create_sealed_at(&self, dir: &Path, path: &Path, label: &str, meta: &RecordMeta<'_>, plain: &[u8]) -> Result<()> {
        self.touch(path);
        let bytes = match &self.sealer {
            Some(s) => s.seal_record(meta, plain)?,
            None => plain.to_vec(),
        };
        // A dotfile: never a key file (ids are [A-Za-z0-9_-]+), skipped by backup and the probe.
        let tmp = dir.join(format!("{CREATE_TMP_PREFIX}{label}-{}.tmp", uuid::Uuid::new_v4()));
        {
            let mut f = private_file(&tmp, true)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        let outcome = match rename_noreplace(&tmp, path) {
            Ok(NoReplace::Moved) => Ok(()),
            Ok(NoReplace::Exists) => Err(DaemonError::KeyExists(label.to_string())),
            Ok(NoReplace::Unsupported) => match std::fs::hard_link(&tmp, path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(DaemonError::KeyExists(label.to_string()))
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
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// Remove `.create-*.tmp` files older than `older_than`: left behind when a create crashed
    /// between writing its temp and moving it into place. They hold a sealed key that never became
    /// live. Run at daemon start; returns the names removed (for the log).
    pub fn sweep_stale_create_temps(&self, older_than: std::time::Duration) -> Result<Vec<String>> {
        let mut removed = self.sweep_stale_temps_in(&self.dir, older_than)?;
        let staged = self.staged_dir();
        if staged.is_dir() {
            removed.extend(self.sweep_stale_temps_in(&staged, older_than)?);
        }
        Ok(removed)
    }

    fn sweep_stale_temps_in(&self, dir: &Path, older_than: std::time::Duration) -> Result<Vec<String>> {
        self.touch(dir);
        let mut removed = Vec::new();
        for entry in std::fs::read_dir(dir)? {
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
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(removed)
    }

    /// Key ids of every FROST share on this node (hosted keys excluded). Unreadable files are
    /// skipped (they are reported elsewhere).
    pub fn list_frost(&self) -> Result<Vec<String>> {
        self.touch(&self.dir);
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(key_id) = name.strip_suffix(".json") else { continue };
            if let Ok(Record::Frost(_)) = self.load_record(key_id) {
                out.push(key_id.to_string());
            }
        }
        out.sort();
        Ok(out)
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
    fn write_sealed(&self, key_id: &str, meta: &RecordMeta<'_>, plain: &[u8]) -> Result<()> {
        let path = self.path(key_id)?;
        self.touch(&path);
        let bytes = match &self.sealer {
            Some(s) => s.seal_record(meta, plain)?,
            None => plain.to_vec(),
        };
        write_atomic(&self.dir, &path, &bytes)
    }

    pub fn load(&self, key_id: &str) -> Result<Share> {
        match self.load_record(key_id)? {
            Record::Frost(s) => Ok(*s),
            Record::Hosted(_) | Record::Tombstone(_) => Err(DaemonError::Config(format!(
                "{key_id} is a cluster-hosted key, not a FROST share"
            ))),
        }
    }

    /// Read a key file and unseal it (`kinds`: what the file may hold), without interpreting the
    /// contents. With sealing on, a plaintext file is refused.
    fn read_plaintext_at(&self, path: &Path, key_id: &str, kinds: &[RecordKind]) -> Result<(Vec<u8>, Option<KeyFileHeader>)> {
        self.touch(path);
        // try_exists, not exists: an unreadable store must surface as an IO error (INTERNAL), never
        // as UnknownKey (NOT_FOUND) — Canton would take NOT_FOUND to mean the key is gone.
        if !path.try_exists()? {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        let bytes = std::fs::read(path)?;
        self.unseal_bytes(&bytes, key_id, kinds)
    }

    fn unseal_bytes(&self, bytes: &[u8], key_id: &str, kinds: &[RecordKind]) -> Result<(Vec<u8>, Option<KeyFileHeader>)> {
        match (&self.sealer, Sealer::is_sealed(bytes)) {
            (Some(s), true) => s.unseal_record(bytes, key_id, kinds),
            (Some(_), false) => Err(DaemonError::KeyFile(format!(
                "{key_id} is a PLAINTEXT key file but sealing is configured — refusing it. If it is \
                 genuine, seal it with the daemon stopped: `rutli-cosigner keyfile migrate-plaintext \
                 --key-id {key_id}`"
            ))),
            (None, true) => Err(DaemonError::Config(format!(
                "share {key_id} is sealed but share sealing is not configured on this node"
            ))),
            (None, false) => Ok((bytes.to_vec(), None)),
        }
    }

    /// Classify and parse a key file's plaintext, and check it against its name and header.
    fn parse_record(&self, key_id: &str, plain: &[u8], hdr: Option<&KeyFileHeader>) -> Result<Record> {
        let value: serde_json::Value = serde_json::from_slice(plain)?;
        let tag = value.get("kind").and_then(|k| k.as_str()).map(str::to_owned);
        let named = value.get("key_id").and_then(|k| k.as_str()).map(str::to_owned);
        if named.as_deref().is_some_and(|n| !n.is_empty() && n != key_id) {
            return Err(DaemonError::KeyFile(format!(
                "the file for {key_id} holds key {} — a key file renamed or copied over another",
                named.unwrap_or_default()
            )));
        }
        let record = if tag.as_deref() == Some(KIND_HOSTED) {
            Record::Hosted(Box::new(serde_json::from_value(value)?))
        } else if tag.as_deref() == Some(KIND_TOMBSTONE) {
            let t: crate::hosted::Tombstone = serde_json::from_value(value)?;
            if t.key_id != key_id {
                return Err(DaemonError::KeyFile(format!("the file for {key_id} holds the tombstone of {}", t.key_id)));
            }
            Record::Tombstone(Box::new(t))
        } else {
            Record::Frost(Box::new(serde_json::from_value(value)?))
        };
        self.check_record(key_id, &record, hdr)?;
        Ok(record)
    }

    /// A record must agree with the header it was sealed under, and a share must be this node's.
    fn check_record(&self, key_id: &str, record: &Record, hdr: Option<&KeyFileHeader>) -> Result<()> {
        if let Some(h) = hdr {
            if h.kind != record_kind(record).as_str() {
                return Err(DaemonError::KeyFile(format!(
                    "{key_id}: the header says {} but the record is a {}",
                    h.kind,
                    record_kind(record).as_str()
                )));
            }
            if h.epoch != record_epoch(record) || h.digest != hex::encode(record_digest(record)?) {
                return Err(DaemonError::KeyFile(format!(
                    "{key_id}: the record does not match its header (epoch {} / digest {})",
                    h.epoch, h.digest
                )));
            }
        }
        if let (Record::Frost(share), Some(s)) = (record, &self.sealer) {
            let own = frost::Identifier::try_from(s.node()).map_err(DaemonError::Frost)?;
            if *share.key_package.identifier() != own {
                return Err(DaemonError::KeyFile(format!(
                    "{key_id}: the share belongs to another FROST identifier than this node's ({})",
                    s.node()
                )));
            }
        }
        Ok(())
    }

    // -- cluster-hosted (non-FROST) keys --

    /// Persist a hosted key, sealed, with the same atomic + fsync discipline as a FROST share.
    pub fn save_hosted(&self, key_id: &str, key: &crate::hosted::HostedKey) -> Result<()> {
        let plain = hosted_plaintext(key_id, key)?;
        let digest = hosted_header_digest(key);
        let meta = RecordMeta { kind: RecordKind::HostedKey, key_id, epoch: 0, digest: &digest };
        self.write_sealed(key_id, &meta, &plain)
    }

    /// A live hosted key. A tombstone reads as [`DaemonError::UnknownKey`] (NOT_FOUND): the key
    /// was deleted.
    pub fn load_hosted(&self, key_id: &str) -> Result<crate::hosted::HostedKey> {
        match self.load_record(key_id)? {
            Record::Hosted(k) => Ok(*k),
            Record::Tombstone(_) => Err(DaemonError::UnknownKey(key_id.to_string())),
            Record::Frost(_) => Err(DaemonError::Config(format!(
                "{key_id} is a FROST share, not a cluster-hosted key"
            ))),
        }
    }

    /// Replace a live hosted key (or an existing tombstone) with `t`, atomically — a delete. Never
    /// replaces a FROST share.
    pub fn save_tombstone(&self, key_id: &str, t: &crate::hosted::Tombstone) -> Result<()> {
        if let Ok(Record::Frost(_)) = self.load_record(key_id) {
            return Err(DaemonError::Config(format!("{key_id} is a FROST share — never tombstoned")));
        }
        let plain = tombstone_plaintext(key_id, t)?;
        let digest = t.intent_digest()?;
        let meta = RecordMeta { kind: RecordKind::Tombstone, key_id, epoch: 0, digest: &digest };
        self.write_sealed(key_id, &meta, &plain)
    }

    /// Record a tombstone for a key this node does not hold: create-once, like a new key, so a key
    /// stored concurrently is never clobbered (the caller re-reads and converts it instead).
    pub fn create_tombstone(&self, key_id: &str, t: &crate::hosted::Tombstone) -> Result<()> {
        let plain = tombstone_plaintext(key_id, t)?;
        let digest = t.intent_digest()?;
        let meta = RecordMeta { kind: RecordKind::Tombstone, key_id, epoch: 0, digest: &digest };
        self.create_bytes(key_id, &meta, &plain)
    }

    /// `keys/.cleared/`: the delete intents an operator cleared by break-glass
    /// (`hosted-clear-tombstone`), one empty marker `<key_id>.<intent digest>` each. A peer's
    /// tombstone carrying a cleared intent is ignored, so clearing a tombstone node by node does not
    /// bring it back from the nodes not cleared yet.
    fn cleared_marker(&self, key_id: &str, intent_digest: &[u8; 32]) -> Result<PathBuf> {
        self.path(key_id)?;
        Ok(self.dir.join(CLEARED_DIR).join(format!("{key_id}.{}", hex::encode(intent_digest))))
    }

    pub fn is_cleared(&self, key_id: &str, intent_digest: &[u8; 32]) -> Result<bool> {
        Ok(self.cleared_marker(key_id, intent_digest)?.try_exists()?)
    }

    /// Break-glass (offline, under the instance lock): remove `key_id`'s tombstone so the id can be
    /// generated again, and remember its intent as cleared. Refuses while the tombstone still
    /// retains material (undelete it, or wait for the grace period) and anything but a tombstone.
    pub fn clear_tombstone(&self, key_id: &str) -> Result<crate::hosted::Tombstone> {
        let t = match self.load_record(key_id)? {
            Record::Tombstone(t) => *t,
            _ => return Err(DaemonError::Config(format!("{key_id} is not a tombstone here"))),
        };
        if t.retained.is_some() {
            return Err(DaemonError::Config(format!(
                "{key_id}'s tombstone still retains the key's material (grace period until {} ms) — undelete \
                 it instead, or wait until the grace period is over",
                t.purge_after_ms
            )));
        }
        self.mark_cleared(key_id, &t.intent_digest()?)?;
        self.delete(key_id)?;
        Ok(t)
    }

    /// Durably note that the delete intent with `intent_digest` no longer applies to `key_id` here.
    fn mark_cleared(&self, key_id: &str, intent_digest: &[u8; 32]) -> Result<()> {
        let marker = self.cleared_marker(key_id, intent_digest)?;
        let dir = marker.parent().expect("marker has a parent").to_path_buf();
        ensure_private_dir(&dir)?;
        private_file(&marker, false)?.sync_all()?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(())
    }

    /// Undo a delete on this node (offline `hosted-undelete`, under the instance lock): restore the
    /// material `key_id`'s tombstone retains, marked undeleted at `now_ms` so the tombstone it came
    /// from — on this node's peers too — no longer applies to it. Refused once the material is gone.
    pub fn undelete(&self, key_id: &str, now_ms: u64) -> Result<crate::hosted::HostedKey> {
        let t = match self.load_record(key_id)? {
            Record::Tombstone(t) => *t,
            _ => return Err(DaemonError::Config(format!("{key_id} is not deleted (no tombstone) on this node"))),
        };
        let mut key = t.retained.clone().ok_or_else(|| {
            DaemonError::Config(format!(
                "{key_id}: the grace period is over and the material was dropped (purge_after {} ms) — only a \
                 backup taken before the delete still holds it",
                t.purge_after_ms
            ))
        })?;
        key.undeleted_at_ms = Some(now_ms);
        // The delete being undone never applies here again — not even from a peer that still
        // holds its tombstone. A new delete (a new intent) does.
        self.mark_cleared(key_id, &t.intent_digest()?)?;
        self.save_hosted(key_id, &key)?;
        Ok(key)
    }

    /// Every tombstone on this node. Unreadable files are skipped (reported by `list_hosted`).
    pub fn list_tombstones(&self) -> Result<Vec<crate::hosted::Tombstone>> {
        self.touch(&self.dir);
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            let Some(key_id) = name.strip_suffix(".json") else { continue };
            if let Ok(Record::Tombstone(t)) = self.load_record(key_id) {
                out.push(*t);
            }
        }
        out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(out)
    }

    /// Read a key file without knowing its type up front.
    pub fn load_record(&self, key_id: &str) -> Result<Record> {
        let path = self.path(key_id)?;
        let (plain, hdr) = self.read_plaintext_at(&path, key_id, STORE_KINDS)?;
        let plain = zeroize::Zeroizing::new(plain);
        self.parse_record(key_id, &plain, hdr.as_ref())
    }

    /// Load the key file at `path` (anywhere — a backup) as if it were this node's file for
    /// `key_id`: unsealed and checked exactly like a live one (restore).
    pub fn load_foreign(&self, path: &Path, key_id: &str) -> Result<(Record, Option<KeyFileHeader>)> {
        self.path(key_id)?; // validates the id
        let (plain, hdr) = self.read_plaintext_at(path, key_id, STORE_KINDS)?;
        let plain = zeroize::Zeroizing::new(plain);
        let record = self.parse_record(key_id, &plain, hdr.as_ref())?;
        Ok((record, hdr))
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
                Ok(Record::Frost(_)) | Ok(Record::Tombstone(_)) => {}
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

    // -- two-phase ceremonies (DKG/refresh): staged shares and ceremony records --

    /// `keys/.staged/`: shares a DKG or refresh produced but this node has not committed. A
    /// dot-dir, so backup, the readiness probe, the hosted-key inventory and the re-seal sweep
    /// never see it, and a staged share is never loaded for signing.
    pub fn staged_dir(&self) -> PathBuf {
        self.dir.join(STAGED_DIR)
    }

    /// `keys/.ceremonies/`: this node's durable ceremony records (its votes). Not secret, but kept
    /// beside the shares they decide, owner-only, and out of backups (a dot-dir).
    pub fn ceremony_dir(&self) -> PathBuf {
        self.dir.join(CEREMONY_DIR)
    }

    fn staged_path(&self, key_id: &str, ceremony_id: &str) -> Result<PathBuf> {
        self.path(key_id)?; // validates the key id
        validate_ceremony_id(ceremony_id)?;
        Ok(self.staged_dir().join(format!("{key_id}.{ceremony_id}.json")))
    }

    /// Durably write the share ceremony `ceremony_id` produced for `key_id`: sealed, fsynced,
    /// create-once (a second stage for the same ceremony and key is refused, never an overwrite).
    /// It does not become `key_id`'s live share until [`KeyStore::promote_staged`].
    pub fn stage(&self, key_id: &str, ceremony_id: &str, share: &Share) -> Result<()> {
        let path = self.staged_path(key_id, ceremony_id)?;
        let dir = self.staged_dir();
        ensure_private_dir(&dir)?;
        // The same header a committed share has (kind, key id, the new epoch), so committing is a
        // pure rename.
        let (plain, digest) = share_plaintext(key_id, share)?;
        let meta = RecordMeta { kind: RecordKind::FrostShare, key_id, epoch: share.epoch, digest: &digest };
        self.create_sealed_at(&dir, &path, key_id, &meta, &plain)
    }

    pub fn has_staged(&self, key_id: &str, ceremony_id: &str) -> Result<bool> {
        let path = self.staged_path(key_id, ceremony_id)?;
        self.touch(&path);
        Ok(path.try_exists()?)
    }

    pub fn load_staged(&self, key_id: &str, ceremony_id: &str) -> Result<Share> {
        let path = self.staged_path(key_id, ceremony_id)?;
        let (plain, hdr) = self.read_plaintext_at(&path, key_id, &[RecordKind::FrostShare])?;
        let plain = zeroize::Zeroizing::new(plain);
        match self.parse_record(key_id, &plain, hdr.as_ref())? {
            Record::Frost(share) => Ok(*share),
            _ => Err(DaemonError::KeyFile(format!("the staged file for {key_id} is not a FROST share"))),
        }
    }

    /// Make a staged share live. `replace = false` (DKG): only if no file exists for `key_id` —
    /// [`Promotion::TargetExists`] otherwise, and the staged file stays. `replace = true` (refresh):
    /// an atomic rename over the old share, so a crash leaves exactly one of the two. Both
    /// directories are fsynced before this returns.
    pub fn promote_staged(&self, key_id: &str, ceremony_id: &str, replace: bool) -> Result<Promotion> {
        let from = self.staged_path(key_id, ceremony_id)?;
        let to = self.path(key_id)?;
        self.touch(&to);
        if replace {
            std::fs::rename(&from, &to)?;
        } else {
            match rename_noreplace(&from, &to)? {
                NoReplace::Moved => {}
                NoReplace::Exists => return Ok(Promotion::TargetExists),
                NoReplace::Unsupported => match std::fs::hard_link(&from, &to) {
                    Ok(()) => std::fs::remove_file(&from)?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Ok(Promotion::TargetExists)
                    }
                    Err(e) => return Err(e.into()),
                },
            }
        }
        std::fs::File::open(&self.dir)?.sync_all()?;
        std::fs::File::open(self.staged_dir())?.sync_all()?;
        Ok(Promotion::Promoted)
    }

    /// Delete a staged share (an aborted ceremony, or an orphan from a crash). Idempotent.
    pub fn discard_staged(&self, key_id: &str, ceremony_id: &str) -> Result<()> {
        let path = self.staged_path(key_id, ceremony_id)?;
        self.touch(&path);
        if path.try_exists()? {
            std::fs::remove_file(&path)?;
            std::fs::File::open(self.staged_dir())?.sync_all()?;
        }
        Ok(())
    }

    /// Every staged share on this node as `(key_id, ceremony_id)`, temps excluded.
    pub fn list_staged(&self) -> Result<Vec<(String, String)>> {
        let dir = self.staged_dir();
        self.touch(&dir);
        if !dir.try_exists()? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let Some(stem) = name.strip_suffix(".json") else { continue };
            // Key ids and ceremony ids never contain '.', so the split is unambiguous.
            if let Some((key_id, ceremony_id)) = stem.split_once('.') {
                if self.staged_path(key_id, ceremony_id).is_ok() {
                    out.push((key_id.to_string(), ceremony_id.to_string()));
                }
            }
        }
        out.sort();
        Ok(out)
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

/// Write `bytes` to `path` durably: an owner-only temp beside it (fsynced), an atomic rename, then
/// fsync `dir` — so the file is either the old one or the new one after a crash, never torn.
pub(crate) fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = private_file(&tmp, false)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()?; // fsync the directory entry (the rename)
    Ok(())
}

/// The v2 header kind of a record.
pub fn record_kind(record: &Record) -> RecordKind {
    match record {
        Record::Frost(_) => RecordKind::FrostShare,
        Record::Hosted(_) => RecordKind::HostedKey,
        Record::Tombstone(_) => RecordKind::Tombstone,
    }
}

/// The epoch a v2 header records for a record (a share's; 0 otherwise).
pub fn record_epoch(record: &Record) -> u64 {
    match record {
        Record::Frost(s) => s.epoch,
        Record::Hosted(_) | Record::Tombstone(_) => 0,
    }
}

/// The digest a v2 header records for a record.
pub fn record_digest(record: &Record) -> Result<Vec<u8>> {
    Ok(match record {
        Record::Frost(s) => s.pkp_digest()?.to_vec(),
        Record::Hosted(k) => hosted_header_digest(k),
        Record::Tombstone(t) => t.intent_digest()?.to_vec(),
    })
}

/// Subdirectory of the key store holding staged (uncommitted) ceremony shares.
pub const STAGED_DIR: &str = ".staged";
/// Subdirectory of the key store holding this node's ceremony records.
pub const CEREMONY_DIR: &str = ".ceremonies";
/// Subdirectory of the key store holding the break-glass cleared-tombstone markers.
pub const CLEARED_DIR: &str = ".cleared";

/// What [`KeyStore::promote_staged`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Promotion {
    Promoted,
    /// No-replace promotion found a file already under the key id; nothing moved.
    TargetExists,
}

/// Ceremony ids name files: the same alphabet as key ids (`[A-Za-z0-9_-]`, which the leader's
/// `<kind>-<uuid>` ids satisfy), bounded in length.
pub fn validate_ceremony_id(ceremony_id: &str) -> Result<()> {
    if ceremony_id.is_empty()
        || ceremony_id.len() > 128
        || !ceremony_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        // Never echo an unbounded id back (a peer's request, a log line).
        let shown: String = ceremony_id.chars().take(64).collect();
        return Err(DaemonError::Config(format!(
            "invalid ceremony id: {shown:?}{} ({} bytes)",
            if ceremony_id.len() > shown.len() { "…" } else { "" },
            ceremony_id.len()
        )));
    }
    Ok(())
}

/// Longest key id a DKG/refresh request may name ([`validate_key_id`]): far above any real id
/// (`<prefix>frost-<name>`), and short enough that a hostile peer cannot make a node log or echo a
/// large payload.
pub const MAX_CEREMONY_KEY_ID_LEN: usize = 200;

/// A key id a DKG/refresh request may name: what a key file may be called (ASCII alphanumerics,
/// `-`, `_`), at most [`MAX_CEREMONY_KEY_ID_LEN`] characters. Pure: the ceremony entry points run it
/// before anything else, so a peer's malformed id is refused before it reaches a log line or a
/// refusal message.
pub fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty()
        || key_id.len() > MAX_CEREMONY_KEY_ID_LEN
        || !key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        let shown: String = key_id.chars().take(64).collect();
        return Err(DaemonError::Config(format!(
            "invalid key id {shown:?}{} ({} bytes)",
            if key_id.len() > shown.len() { "…" } else { "" },
            key_id.len()
        )));
    }
    Ok(())
}

/// Create `dir` if needed and make it owner-only (`0700`).
pub(crate) fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

pub(crate) enum NoReplace {
    Moved,
    Exists,
    /// The platform or filesystem has no no-replace rename: use the `link(2)` fallback.
    Unsupported,
}

/// Rename `from` to `to` unless `to` exists, atomically.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<NoReplace> {
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

/// Open a key-store file for writing, owner-only (`0600`) before any byte lands, whatever the
/// umask. `create_new`: fail if it exists (the create-once temps); otherwise create or truncate (the
/// save temp), and re-apply `0600` in case a leftover file had another mode. The final key file is
/// this temp renamed, so it keeps the mode.
pub(crate) fn private_file(path: &Path, create_new: bool) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::{HostedKey, HostedSpec};

    /// Codex L3: key files are 0600 and the directory 0700 even with sealing off and a permissive
    /// directory to start from — through create (DKG, import-share, hosted create) and save
    /// (refresh, hosted save), including over a leftover temp with another mode.
    #[cfg(unix)]
    #[test]
    fn key_files_are_owner_only_even_unsealed() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ks = store(&tmp, false);
        assert_eq!(mode(&dir), 0o700);

        ks.create("frost-a", &dealt_share(None)).unwrap();
        let leftover = dir.join("frost-b.json.tmp");
        std::fs::write(&leftover, b"stale").unwrap();
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o644)).unwrap();
        ks.save("frost-b", &dealt_share(None)).unwrap();
        let key = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
        ks.create_hosted("rutli-c", &key).unwrap();
        ks.save_hosted("rutli-d", &key).unwrap();
        for f in ["frost-a", "frost-b", "rutli-c", "rutli-d"] {
            assert_eq!(mode(&dir.join(format!("{f}.json"))), 0o600, "{f}");
        }
    }

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
            Ok(Record::Hosted(_)) | Ok(Record::Tombstone(_)) => {
                panic!("untagged legacy file misclassified as a hosted key")
            }
            Err(_) => {} // frost rejects the empty packages; classification is what matters here
        }
        assert!(ks.list_hosted().is_err() || ks.list_hosted().unwrap().is_empty());
    }

    /// A real 2-of-3 dealt share for node 1, with or without an origin.
    fn dealt_share(origin: Option<KeyOrigin>) -> Share {
        let (shares, pkp) =
            rutli_frost_core::dealer::split_ed25519_seed(&[5u8; 32], &[1, 2, 3], 2).unwrap();
        let key_package = frost::keys::KeyPackage::try_from(shares[0].clone()).unwrap();
        Share { key_package, public_key_package: pkp, origin, epoch: 0, key_id: String::new() }
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
    fn plaintext_key_files_are_refused_under_sealing_until_migrate_plaintext() {
        // Audit M4: reseal_plaintext_shares used to accept and seal any plaintext file at start-up,
        // so a file dropped on the volume became genuine. Now it is refused until an operator seals
        // it explicitly.
        let tmp = tempfile::tempdir().unwrap();
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 7).unwrap();
        store(&tmp, false).save_hosted("rutli-sym-9", &key).unwrap(); // unsealed
        store(&tmp, false).save("frost-a", &dealt_share(None)).unwrap();

        let sealed = store(&tmp, true);
        assert_eq!(sealed.plaintext_files().unwrap().len(), 2);
        let e = sealed.load_hosted("rutli-sym-9").err().unwrap().to_string();
        assert!(e.contains("PLAINTEXT") && e.contains("migrate-plaintext"), "{e}");
        assert!(sealed.list_hosted().unwrap().is_empty(), "a refused file is not inventory");

        sealed.migrate_plaintext("rutli-sym-9").unwrap();
        sealed.migrate_plaintext("frost-a").unwrap();
        assert!(sealed.plaintext_files().unwrap().is_empty());
        let raw = std::fs::read(tmp.path().join("keys").join("rutli-sym-9.json")).unwrap();
        assert!(crate::seal::Sealer::is_sealed(&raw), "hosted key must be sealed after migration");
        assert_eq!(sealed.load_hosted("rutli-sym-9").unwrap().created_at, 7);
        assert_eq!(sealed.load("frost-a").unwrap().key_id, "frost-a", "the key id is now inside");
        assert!(sealed.migrate_plaintext("frost-a").is_err(), "already sealed");
    }

    // ── key-file format v2 (audit M4) ─────────────────────────────────────────────────────────

    const UUID: &str = "6f1d3c1e-8a0b-4a43-9c55-0d4f1f0b7a11";

    fn v2_sealer(node: u16, cluster: &str, write: u8) -> Arc<crate::seal::Sealer> {
        Arc::new(crate::seal::Sealer::from_master_secret(b"test master secret", node).with_binding(
            crate::seal::KeyFileBinding {
                node,
                cluster_uuid: Some(cluster.into()),
                write_version: write,
                accept_v1: true,
            },
        ))
    }

    fn v2_store(dir: &Path, node: u16, cluster: &str) -> KeyStore {
        KeyStore::open_with_sealer(dir, Some(v2_sealer(node, cluster, 2))).unwrap()
    }

    /// Edit the clear header of a v2 file in place.
    fn edit_header(path: &Path, f: impl Fn(&mut serde_json::Value)) {
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        f(&mut v["hdr"]);
        std::fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    fn refused(r: Result<impl Sized>, needle: &str) {
        let e = r.err().expect("must be refused").to_string();
        assert!(e.contains(needle), "expected {needle:?} in {e}");
    }

    #[test]
    fn v2_files_carry_a_bound_header_and_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = v2_store(&tmp.path().join("keys"), 1, UUID);
        let share = dealt_share(Some(origin()));
        ks.create("frost-a", &share).unwrap();
        ks.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::EcP256, 3).unwrap()).unwrap();
        let raw = std::fs::read(ks.dir().join("frost-a.json")).unwrap();
        let h = crate::seal::header_of(&raw).expect("a v2 header");
        assert_eq!((h.node, h.key_id.as_str(), h.kind.as_str(), h.cluster.as_str()), (1, "frost-a", "frost-share", UUID));
        assert_eq!(h.digest, hex::encode(share.pkp_digest().unwrap()));
        assert_eq!(ks.load("frost-a").unwrap().origin, Some(origin()));
        assert_eq!(ks.load_hosted("rutli-x").unwrap().created_at, 3);
        assert_eq!(crate::seal::header_of(&std::fs::read(ks.dir().join("rutli-x.json")).unwrap()).unwrap().kind, "hosted-key");
    }

    #[test]
    fn a_v2_header_naming_another_key_node_cluster_kind_or_epoch_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        let ks = v2_store(&dir, 1, UUID);
        ks.create("frost-a", &dealt_share(None)).unwrap();
        let path = dir.join("frost-a.json");
        let good = std::fs::read(&path).unwrap();
        let reset = || std::fs::write(&path, &good).unwrap();

        // The header is checked before anything is decrypted...
        edit_header(&path, |h| h["key_id"] = "frost-b".into());
        refused(ks.load("frost-a"), "holds key frost-b");
        reset();
        edit_header(&path, |h| h["node"] = 2.into());
        refused(ks.load("frost-a"), "belongs to node 2");
        reset();
        edit_header(&path, |h| h["cluster"] = "00000000-0000-4000-8000-000000000000".into());
        refused(ks.load("frost-a"), "another cluster");
        reset();
        edit_header(&path, |h| h["kind"] = "recipient".into());
        refused(ks.load("frost-a"), "record where a frost-share or hosted-key or tombstone is expected");
        reset();
        // A kind the store does hold passes the check and still fails the associated data.
        edit_header(&path, |h| h["kind"] = "hosted-key".into());
        refused(ks.load("frost-a"), "unseal failed");
        reset();
        // ...and every field is bound by the associated data: one the checks accept still fails.
        edit_header(&path, |h| h["epoch"] = 7.into());
        refused(ks.load("frost-a"), "unseal failed");
        reset();
        edit_header(&path, |h| h["digest"] = hex::encode([0u8; 32]).into());
        refused(ks.load("frost-a"), "unseal failed");
        reset();
        assert!(ks.load("frost-a").is_ok());

        // A store expecting another cluster, or run as another node, refuses the file as it is.
        refused(v2_store(&dir, 1, "00000000-0000-4000-8000-000000000000").load("frost-a"), "another cluster");
        let node2 = KeyStore::open_with_sealer(&dir, Some(v2_sealer(2, UUID, 2))).unwrap();
        refused(node2.load("frost-a"), "belongs to node 1");
        let no_uuid = KeyStore::open_with_sealer(
            &dir,
            Some(Arc::new(crate::seal::Sealer::from_master_secret(b"test master secret", 1))),
        )
        .unwrap();
        refused(no_uuid.load("frost-a"), "keyfile.cluster_uuid is not set");
    }

    #[test]
    fn a_key_file_copied_over_another_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        // v2: the header names the key.
        let ks = v2_store(&dir, 1, UUID);
        ks.create("frost-a", &dealt_share(None)).unwrap();
        ks.create("frost-b", &dealt_share(None)).unwrap();
        std::fs::copy(dir.join("frost-a.json"), dir.join("frost-b.json")).unwrap();
        refused(ks.load("frost-b"), "holds key frost-a");
        // A hosted key passed off as a share and vice versa.
        ks.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
        std::fs::copy(dir.join("rutli-x.json"), dir.join("frost-a.json")).unwrap();
        refused(ks.load("frost-a"), "holds key rutli-x");

        // v1 written by this release: the key id inside the sealed plaintext names it.
        let tmp1 = tempfile::tempdir().unwrap();
        let ks1 = store(&tmp1, true);
        ks1.create("frost-a", &dealt_share(None)).unwrap();
        ks1.create("frost-b", &dealt_share(None)).unwrap();
        std::fs::copy(ks1.dir().join("frost-a.json"), ks1.dir().join("frost-b.json")).unwrap();
        refused(ks1.load("frost-b"), "holds key frost-a");
    }

    #[test]
    fn a_share_of_another_node_is_refused_even_under_the_right_dek() {
        // The legacy shared master gives every node its own DEK, so this needs a forged setup: a
        // node-2 share sealed by node 1's sealer.
        let tmp = tempfile::tempdir().unwrap();
        let ks = v2_store(&tmp.path().join("keys"), 1, UUID);
        let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&[5u8; 32], &[1, 2, 3], 2).unwrap();
        let kp2 = frost::keys::KeyPackage::try_from(shares[1].clone()).unwrap();
        let share = Share { key_package: kp2, public_key_package: pkp, origin: None, epoch: 0, key_id: String::new() };
        ks.create("frost-a", &share).unwrap();
        refused(ks.load("frost-a"), "another FROST identifier");
    }

    #[test]
    fn v1_stays_readable_v2_is_opt_in_and_downgrade_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        // A v1 store (this release's default) next to a node that writes v2.
        let v1 = KeyStore::open_with_sealer(&dir, Some(v2_sealer(1, UUID, 1))).unwrap();
        v1.create("frost-a", &dealt_share(None)).unwrap();
        v1.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::Rsa2048, 1).unwrap()).unwrap();
        let path = dir.join("frost-a.json");
        assert_eq!(crate::seal::file_version(&std::fs::read(&path).unwrap()), Some(1), "v2 is opt-in");

        let v2 = v2_store(&dir, 1, UUID);
        assert!(v2.load("frost-a").is_ok(), "a v2 writer reads v1");
        assert_eq!(v2.reseal_outdated().unwrap(), 2, "start-up migrates v1 files when writing v2");
        assert_eq!(crate::seal::file_version(&std::fs::read(&path).unwrap()), Some(2));
        assert!(v1.load("frost-a").is_ok(), "this release reads v2 even while writing v1");
        assert_eq!(v2.reseal_outdated().unwrap(), 0, "idempotent");

        // `keyfile downgrade`: back to v1, which a release that knows only v1 can open with the
        // plain v1 unseal — then forward again.
        for p in v2.key_file_paths().unwrap() {
            v2.rewrite(&p, 1).unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(crate::seal::file_version(&raw), Some(1));
        let plain = crate::seal::Sealer::from_master_secret(b"test master secret", 1).unseal(&raw).unwrap();
        assert!(serde_json::from_slice::<Share>(&plain).is_ok());
        for p in v2.key_file_paths().unwrap() {
            v2.rewrite(&p, 2).unwrap();
        }
        assert!(v2.load("frost-a").is_ok() && v2.load_hosted("rutli-x").is_ok());

        // accept_v1 off refuses a v1 file.
        v1.save("frost-b", &dealt_share(None)).unwrap();
        let strict = KeyStore::open_with_sealer(
            &dir,
            Some(Arc::new(crate::seal::Sealer::from_master_secret(b"test master secret", 1).with_binding(
                crate::seal::KeyFileBinding { node: 1, cluster_uuid: Some(UUID.into()), write_version: 2, accept_v1: false },
            ))),
        )
        .unwrap();
        refused(strict.load("frost-b"), "accept_v1 is off");
        assert!(strict.load("frost-a").is_ok());
    }

    #[test]
    fn a_dek_rotation_reseals_everything_and_the_old_dek_is_then_not_needed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        let binding = |node| crate::seal::KeyFileBinding { node, cluster_uuid: Some(UUID.into()), write_version: 2, accept_v1: true };
        let old = crate::seal::NodeSealBundle::random(1);
        let ks_old = KeyStore::open_with_sealer(&dir, Some(Arc::new(old.sealer().with_binding(binding(1))))).unwrap();
        ks_old.create("frost-a", &dealt_share(None)).unwrap();
        ks_old.save_hosted("rutli-x", &HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap()).unwrap();
        // A v1 file under the old DEK too (written before v2 was switched on).
        let v1_old = KeyStore::open_with_sealer(&dir, Some(Arc::new(old.sealer()))).unwrap();
        v1_old.save("frost-b", &dealt_share(None)).unwrap();
        ks_old.stage("frost-c", "dkg-1", &dealt_share(None)).unwrap();

        let rotated = old.rotated();
        assert_eq!(rotated.previous_count(), 1);
        assert_ne!(rotated.dek_id(), old.dek_id());
        let ks_rot = KeyStore::open_with_sealer(&dir, Some(Arc::new(rotated.sealer().with_binding(binding(1))))).unwrap();
        for p in ks_rot.key_file_paths().unwrap() {
            assert!(matches!(ks_rot.file_state(&p).unwrap(), Some((_, crate::seal::DekUse::Previous(0)))), "{p:?}");
        }
        assert_eq!(ks_rot.reseal_outdated().unwrap(), 4);
        for p in ks_rot.key_file_paths().unwrap() {
            assert_eq!(ks_rot.file_state(&p).unwrap(), Some((2, crate::seal::DekUse::Current)), "{p:?}");
        }

        // The old DEK dropped: everything still opens. The old bundle opens nothing.
        let final_bundle = rotated.without_previous();
        let ks_new = KeyStore::open_with_sealer(&dir, Some(Arc::new(final_bundle.sealer().with_binding(binding(1))))).unwrap();
        assert!(ks_new.load("frost-a").is_ok() && ks_new.load("frost-b").is_ok());
        assert!(ks_new.load_hosted("rutli-x").is_ok() && ks_new.load_staged("frost-c", "dkg-1").is_ok());
        refused(ks_old.load("frost-a"), "does not hold");
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

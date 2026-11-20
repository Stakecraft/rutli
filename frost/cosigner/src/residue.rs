// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner residue-scan`: a read-only inventory of key material on this node's volume and
//! in the backups an operator names, that is not the node's live, current state.
//!
//! It walks `data_dir` and every `--backup` (a directory, a plain tar, or one key file) and reports
//! each copy of a key file that is plaintext, sealed under a DEK other than the current one, an
//! older epoch than the live file, a key id that is not live, a staged share of a ceremony that is
//! not in progress, ceremony material, a hosted key or tombstone (a hosted key has no threshold at
//! rest, so one copy is the whole key), and leftovers (temps, unknown directories, a non-empty
//! `lost+found`).
//!
//! What it can say is limited to the files a walk sees: "nothing found on the paths given", never
//! "destroyed". Freed blocks, snapshots, copies elsewhere and the rest of [`NOT_CHECKED`] are out
//! of its reach, and every report says so.
//!
//! Safe next to a running daemon: it takes no lock (not the instance lock, no file lock), opens
//! every file read-only, writes nothing, never creates a directory, never follows a symbolic link.
//! A file that vanishes or appears while it walks is reported as changed, not as an error.
//!
//! Secrets: a v1 file is classified by one trial open with the current DEK; the plaintext lives in
//! a buffer wiped on drop and only its `epoch`/`kind` fields are read. Every file read is held in a
//! wiped buffer too (a plaintext key file is the key). The DEK and the legacy-master derivation are
//! compared in constant time and never printed: the report carries paths, key ids, epochs, record
//! kinds and DEK ids (a public, truncated hash) only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ceremony_record::{CeremonyRecord, RecordState};
use crate::keystore::{CEREMONY_DIR, CLEARED_DIR, STAGED_DIR};
use crate::seal::{self, DekUse, Sealer};

/// What no file walk can see. Printed with every report, whatever it found.
pub const NOT_CHECKED: &[&str] = &[
    "freed blocks on the volume: a deleted or replaced file's bytes stay on disk until overwritten",
    "volume and storage snapshots",
    "the history of the seal Secrets in the cluster's store (old revisions until compaction)",
    "the legacy master secret and its escrow copies",
    "copies off this volume: backup destinations, operator machines, ceremony media, scratch \
     volumes and /tmp (only the paths given with --backup were read)",
    "core dumps and swap",
];

/// Largest file read for classification. Key files are a few KiB.
const MAX_FILE: u64 = 4 << 20;
/// Most tar entries read from one archive.
const MAX_TAR_ENTRIES: usize = 200_000;
/// Largest GNU long name or pax header read from a tar.
const MAX_TAR_META: u64 = 64 << 10;
/// Most directory entries walked in one scan, and the deepest directory.
const MAX_WALK_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 32;

/// The JSON schema id.
pub const SCHEMA: &str = "rutli-residue-scan/1";

/// What a finding is. Ordered most severe first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// An unsealed key file.
    Plaintext,
    /// A copy of a cluster-hosted key outside the live store.
    HostedCopy,
    /// A tombstone: it keeps the deleted key's material until its purge time.
    Tombstone,
    /// This node's DEK equals the legacy-master derivation.
    LegacyMasterDek,
    /// Sealed under a DEK other than the current one.
    NonCurrentDek,
    /// An older epoch of a live FROST share.
    OlderEpoch,
    /// A key id this node does not hold live.
    NotLiveKey,
    /// A staged share whose ceremony is not in progress.
    StagedOrphan,
    /// Split-ceremony material (`data_dir/ceremony/*`).
    CeremonyMaterial,
    /// A directory the cosigner does not use (`backup-*`, `retired-*`, unknown).
    OtherDir,
    /// A temporary file left by a write.
    TempFile,
    /// A non-empty `lost+found`.
    LostFound,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Plaintext => "plaintext",
            Class::HostedCopy => "hosted-copy",
            Class::Tombstone => "tombstone",
            Class::LegacyMasterDek => "legacy-master-dek",
            Class::NonCurrentDek => "non-current-dek",
            Class::OlderEpoch => "older-epoch",
            Class::NotLiveKey => "not-live-key",
            Class::StagedOrphan => "staged-orphan",
            Class::CeremonyMaterial => "ceremony-material",
            Class::OtherDir => "other-dir",
            Class::TempFile => "temp-file",
            Class::LostFound => "lost-found",
        }
    }

    fn note(self) -> Option<&'static str> {
        match self {
            Class::HostedCopy => Some("a hosted key has no threshold at rest: this one copy is the whole key"),
            Class::Tombstone => Some(
                "a tombstone keeps the deleted key until its purge time; a hosted key has no \
                 threshold at rest, so one copy is the whole key",
            ),
            Class::LegacyMasterDek => {
                Some("anyone holding the legacy master can derive this DEK and open these files")
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub class: Class,
    pub path: String,
    pub key_id: Option<String>,
    pub epoch: Option<u64>,
    pub dek: Option<String>,
    pub note: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unclassified {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadError {
    pub path: String,
    pub error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    /// Listed, then gone before it was read.
    Vanished,
    /// Not in the listing, present at the end of that directory: not read.
    Appeared,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Changed {
    pub path: String,
    pub change: Change,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LiveCounts {
    pub frost: usize,
    pub hosted: usize,
    pub tombstones: usize,
}

/// The scan's result. Serialized as the `--json` output.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub node: u16,
    pub data_dir: String,
    pub backups: Vec<String>,
    pub findings: Vec<Finding>,
    pub unclassified: Vec<Unclassified>,
    pub errors: Vec<ReadError>,
    pub changed: Vec<Changed>,
    pub live: LiveCounts,
    pub not_checked: Vec<String>,
    pub exit: i32,
}

impl Report {
    /// 2: a path could not be read (the scan is incomplete); 1: findings or unclassified entries;
    /// 0: nothing found on the paths given.
    pub fn exit_code(&self) -> i32 {
        if !self.errors.is_empty() {
            2
        } else if !self.findings.is_empty() || !self.unclassified.is_empty() {
            1
        } else {
            0
        }
    }

    /// The check-config style text report.
    pub fn text(&self) -> String {
        let mut out = format!("residue-scan: node {}, data_dir {}\n", self.node, printable(&self.data_dir));
        for b in &self.backups {
            out.push_str(&format!("  backup {}\n", printable(b)));
        }
        for f in &self.findings {
            out.push_str(&format!(
                "[finding] {}: {} key={} epoch={} dek={}\n",
                f.class.as_str(),
                printable(&f.path),
                f.key_id.as_deref().map(printable).unwrap_or_else(|| "-".into()),
                f.epoch.map(|e| e.to_string()).unwrap_or_else(|| "-".into()),
                f.dek.as_deref().unwrap_or("-"),
            ));
            if let Some(n) = f.note {
                out.push_str(&format!("          {n}\n"));
            }
        }
        for u in &self.unclassified {
            out.push_str(&format!("[unclassified] {}: {}\n", printable(&u.path), u.reason));
        }
        for e in &self.errors {
            out.push_str(&format!("[error] {}: {}\n", printable(&e.path), e.error));
        }
        for c in &self.changed {
            let what = match c.change {
                Change::Vanished => "vanished during the scan",
                Change::Appeared => "appeared during the scan (not read)",
            };
            out.push_str(&format!("[changed] {}: {what}\n", printable(&c.path)));
        }
        let mut by_class: BTreeMap<Class, usize> = BTreeMap::new();
        for f in &self.findings {
            *by_class.entry(f.class).or_default() += 1;
        }
        let classes = by_class.iter().map(|(c, n)| format!("{}={n}", c.as_str())).collect::<Vec<_>>();
        out.push_str(&format!(
            "summary: {} finding(s){}, {} unclassified, {} read error(s), {} changed during the scan; \
             live keys: {} FROST, {} hosted, {} tombstone(s)\n",
            self.findings.len(),
            if classes.is_empty() { String::new() } else { format!(" ({})", classes.join(", ")) },
            self.unclassified.len(),
            self.errors.len(),
            self.changed.len(),
            self.live.frost,
            self.live.hosted,
            self.live.tombstones,
        ));
        out.push_str("NOT CHECKED (no file walk sees these):\n");
        for n in &self.not_checked {
            out.push_str(&format!("  - {n}\n"));
        }
        out.push_str(match self.exit_code() {
            0 => "result: nothing found on the paths given (exit 0)\n",
            1 => "result: findings (exit 1)\n",
            _ => "result: some paths could not be read; the scan is incomplete (exit 2)\n",
        });
        out
    }
}

/// What to scan, and with which keys.
pub struct ScanInput<'a> {
    pub data_dir: &'a Path,
    pub node: u16,
    /// `keyfile.cluster_uuid`, if set: a v2 file of another cluster is reported, not compared.
    pub cluster_uuid: Option<&'a str>,
    /// This node's sealer; `None` without `share_seal`.
    pub sealer: Option<&'a Sealer>,
    pub backups: &'a [PathBuf],
    /// This node's DEK under the legacy master (`--legacy-master-env`), if given.
    pub legacy_dek: Option<Zeroizing<[u8; 32]>>,
    /// The config names `share_seal.secret_env`.
    pub config_names_secret_env: bool,
}

// ── one key file ────────────────────────────────────────────────────────────────────────────────

/// What a key file's bytes say, without any key material.
#[derive(Clone, Debug, PartialEq, Eq)]
struct KeyInfo {
    sealed: bool,
    /// `frost-share`, `hosted-key`, `tombstone`, `recipient`; `None` when unknown.
    kind: Option<String>,
    epoch: Option<u64>,
    /// From a v2 header; `None` for v1 and plaintext.
    key_id: Option<String>,
    dek: Option<String>,
    dek_use: Option<DekUse>,
    /// A v2 header of another node or cluster.
    foreign: Option<String>,
}

/// The few plaintext fields the scan reads. Everything else is skipped unparsed.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    epoch: Option<u64>,
    #[serde(default)]
    key_package: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    private_der: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    delete_intent: Option<serde::de::IgnoredAny>,
}

impl Probe {
    /// The record kind a plaintext (or v1-opened) record holds, if it is one.
    fn record_kind(&self) -> Option<&'static str> {
        match self.kind.as_deref() {
            Some("hosted") => Some("hosted-key"),
            Some("tombstone") => Some("tombstone"),
            _ if self.key_package.is_some() => Some("frost-share"),
            _ if self.delete_intent.is_some() => Some("tombstone"),
            _ if self.private_der.is_some() => Some("hosted-key"),
            _ => None,
        }
    }
}

/// Classify `bytes` as a key file, or `None` if they are not one.
fn inspect(bytes: &[u8], input: &ScanInput<'_>) -> Option<KeyInfo> {
    match seal::file_version(bytes) {
        Some(2) => {
            let h = seal::header_of(bytes)?;
            let foreign = if h.node != input.node {
                Some(format!("a key file of node {}", h.node))
            } else if input.cluster_uuid.is_some_and(|c| c != h.cluster) {
                Some(format!("a key file of cluster {}", h.cluster))
            } else {
                None
            };
            Some(KeyInfo {
                sealed: true,
                kind: Some(h.kind.clone()),
                epoch: Some(h.epoch),
                key_id: Some(h.key_id.clone()),
                dek: Some(h.dek_id.clone()),
                dek_use: input.sealer.map(|s| s.dek_use(bytes)),
                foreign,
            })
        }
        Some(1) => {
            let (kind, epoch, dek, dek_use) = match input.sealer {
                Some(s) => match s.trial_open_v1_current(bytes) {
                    Some(plain) => {
                        let p = serde_json::from_slice::<Probe>(&plain).ok();
                        let kind = p.as_ref().and_then(|p| p.record_kind()).map(str::to_string);
                        // A FROST share without the field is epoch 0.
                        let epoch = p.as_ref().map(|p| p.epoch.unwrap_or(0));
                        (kind, epoch, Some(s.current_dek_id()), Some(DekUse::Current))
                    }
                    None => (None, None, None, Some(DekUse::Unknown)),
                },
                None => (None, None, None, None),
            };
            Some(KeyInfo { sealed: true, kind, epoch, key_id: None, dek, dek_use, foreign: None })
        }
        _ => {
            let p = serde_json::from_slice::<Probe>(bytes).ok()?;
            let kind = p.record_kind()?;
            Some(KeyInfo {
                sealed: false,
                kind: Some(kind.to_string()),
                epoch: Some(p.epoch.unwrap_or(0)),
                key_id: None,
                dek: None,
                dek_use: None,
                foreign: None,
            })
        }
    }
}

/// The key id a key file's name gives: `<id>.json`, `<id>.<ceremony>.json`, `<id>.json.tmp`,
/// `.create-<id>-<uuid>.tmp`, `<id>.recipient`. Key ids never contain '.'.
fn key_id_from_name(name: &str) -> Option<String> {
    let name = name.strip_prefix(".create-").unwrap_or(name);
    let stem = name.split('.').next()?;
    (!stem.is_empty()).then(|| stem.to_string())
}

// ── the scan ───────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Live {
    epoch: Option<u64>,
}

struct Scan<'a> {
    input: &'a ScanInput<'a>,
    live: BTreeMap<String, Live>,
    counts: LiveCounts,
    findings: Vec<Finding>,
    unclassified: Vec<Unclassified>,
    errors: Vec<ReadError>,
    changed: Vec<Changed>,
    walked: usize,
}

/// How a read went.
enum Got {
    Bytes(Zeroizing<Vec<u8>>),
    TooLarge,
    Vanished,
    Error(String),
}

fn read_capped(path: &Path) -> Got {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Got::Vanished,
        Err(e) => return Got::Error(e.to_string()),
    };
    let mut buf = Zeroizing::new(Vec::new());
    match file.take(MAX_FILE + 1).read_to_end(&mut buf) {
        Ok(_) if buf.len() as u64 > MAX_FILE => Got::TooLarge,
        Ok(_) => Got::Bytes(buf),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Got::Vanished,
        Err(e) => Got::Error(e.to_string()),
    }
}

/// Whether a file name is one the scan reads as a possible key file.
fn candidate(name: &str) -> bool {
    name.ends_with(".json") || name.ends_with(".tmp") || name.ends_with(".recipient")
}

/// Where a copy was found, which decides what is expected of it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// `keys/<id>.json`: the live file.
    Live,
    /// `keys/.staged/<id>.<ceremony>.json`.
    Staged,
    /// Anywhere else: a backup, an unknown directory, a temp, a tar entry.
    Copy,
}

impl<'a> Scan<'a> {
    fn path_str(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    fn finding(&mut self, class: Class, path: String, key_id: Option<String>, info: Option<&KeyInfo>) {
        self.findings.push(Finding {
            class,
            path,
            key_id,
            epoch: info.and_then(|i| i.epoch),
            dek: info.and_then(|i| i.dek.clone()),
            note: class.note(),
        });
    }

    fn unclassified(&mut self, path: String, reason: impl Into<String>) {
        self.unclassified.push(Unclassified { path, reason: reason.into() });
    }

    fn error(&mut self, path: String, error: impl Into<String>) {
        self.errors.push(ReadError { path, error: error.into() });
    }

    fn vanished(&mut self, path: String) {
        self.changed.push(Changed { path, change: Change::Vanished });
    }

    /// List a directory: its entry names, or `None` after reporting why not.
    fn list(&mut self, dir: &Path) -> Option<BTreeSet<std::ffi::OsString>> {
        match std::fs::read_dir(dir) {
            Ok(rd) => {
                let mut names = BTreeSet::new();
                for e in rd {
                    match e {
                        Ok(e) => {
                            names.insert(e.file_name());
                        }
                        Err(e) => {
                            self.error(Self::path_str(dir), e.to_string());
                            return None;
                        }
                    }
                }
                self.walked += names.len();
                Some(names)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.vanished(Self::path_str(dir));
                None
            }
            Err(e) => {
                self.error(Self::path_str(dir), e.to_string());
                None
            }
        }
    }

    /// After a directory is processed: report entries that appeared since it was listed.
    fn recheck(&mut self, dir: &Path, seen: &BTreeSet<std::ffi::OsString>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            if !seen.contains(&e.file_name()) {
                self.changed.push(Changed { path: Self::path_str(&e.path()), change: Change::Appeared });
            }
        }
    }

    fn file_type(&mut self, path: &Path) -> Option<std::fs::FileType> {
        match std::fs::symlink_metadata(path) {
            Ok(m) => Some(m.file_type()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.vanished(Self::path_str(path));
                None
            }
            Err(e) => {
                self.error(Self::path_str(path), e.to_string());
                None
            }
        }
    }

    /// Classify one key file found at `place`. `name` is its file name (for the key id when the
    /// bytes do not carry one).
    fn classify(&mut self, path: String, name: &str, bytes: &[u8], place: Place) {
        let Some(info) = inspect(bytes, self.input) else {
            if place != Place::Copy {
                self.unclassified(path, "not a key file");
            }
            return;
        };
        let key_id = info.key_id.clone().or_else(|| key_id_from_name(name));
        if let Some(why) = &info.foreign {
            self.unclassified(path, format!("{why}; not compared with this node"));
            return;
        }
        if name.ends_with(".tmp") {
            self.finding(Class::TempFile, path.clone(), key_id.clone(), Some(&info));
        }
        if !info.sealed {
            self.finding(Class::Plaintext, path.clone(), key_id.clone(), Some(&info));
        }
        if info.sealed {
            match info.dek_use {
                Some(DekUse::Current) => {}
                Some(_) => self.finding(Class::NonCurrentDek, path.clone(), key_id.clone(), Some(&info)),
                None => self.unclassified(path.clone(), "sealed, and no share_seal is configured to tell its DEK"),
            }
        }
        match info.kind.as_deref() {
            Some("tombstone") => self.finding(Class::Tombstone, path, key_id, Some(&info)),
            Some("hosted-key") if place != Place::Live => self.finding(Class::HostedCopy, path, key_id, Some(&info)),
            Some("recipient") => self.finding(Class::CeremonyMaterial, path, key_id, Some(&info)),
            Some("frost-share") if place == Place::Copy => {
                let live = key_id.as_ref().and_then(|k| self.live.get(k)).cloned();
                match live {
                    None => self.finding(Class::NotLiveKey, path, key_id, Some(&info)),
                    Some(l) => match (info.epoch, l.epoch) {
                        (Some(c), Some(e)) if c < e => self.finding(Class::OlderEpoch, path, key_id, Some(&info)),
                        (Some(c), Some(e)) if c > e => {
                            self.unclassified(path, format!("epoch {c}, newer than the live file's {e}"))
                        }
                        _ => {}
                    },
                }
            }
            Some("hosted-key") | Some("frost-share") => {}
            Some(other) => self.unclassified(path, format!("unknown record kind {other:?}")),
            // A v1 file the current DEK does not open: its kind is unknown, already reported.
            None => {}
        }
    }

    /// Read and classify the file at `path`.
    fn file(&mut self, path: &Path, place: Place) {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        match read_capped(path) {
            Got::Bytes(b) => self.classify(Self::path_str(path), &name, &b, place),
            Got::TooLarge => {
                if place != Place::Copy || candidate(&name) {
                    self.unclassified(Self::path_str(path), format!("larger than {MAX_FILE} bytes; not read"))
                }
            }
            Got::Vanished => self.vanished(Self::path_str(path)),
            Got::Error(e) => self.error(Self::path_str(path), e),
        }
    }

    // ── the live store ─────────────────────────────────────────────────────────────────────────

    /// Read `keys/<id>.json` into the live map (first pass: copies elsewhere are compared to it).
    fn load_live(&mut self, keys: &Path) {
        let Some(names) = self.list(keys) else { return };
        for name in &names {
            let n = name.to_string_lossy();
            if n.starts_with('.') || !n.ends_with(".json") {
                continue;
            }
            let path = keys.join(name);
            if !matches!(self.file_type(&path), Some(t) if t.is_file()) {
                continue;
            }
            let Got::Bytes(bytes) = read_capped(&path) else { continue };
            let Some(info) = inspect(&bytes, self.input) else { continue };
            if info.foreign.is_some() {
                continue;
            }
            let Some(key_id) = key_id_from_name(&n) else { continue };
            match info.kind.as_deref() {
                Some("frost-share") => self.counts.frost += 1,
                Some("hosted-key") => self.counts.hosted += 1,
                Some("tombstone") => self.counts.tombstones += 1,
                _ => {}
            }
            self.live.insert(key_id, Live { epoch: info.epoch });
        }
    }

    /// `keys/`: classify each entry. Live files are checked for plaintext, DEK and tombstones.
    fn keys_dir(&mut self, keys: &Path) {
        let Some(names) = self.list(keys) else { return };
        for name in &names {
            let n = name.to_string_lossy().into_owned();
            let path = keys.join(name);
            let Some(t) = self.file_type(&path) else { continue };
            if t.is_symlink() {
                self.unclassified(Self::path_str(&path), "a symbolic link; not followed");
            } else if t.is_dir() {
                if n == STAGED_DIR {
                    self.staged_dir(&path, keys);
                } else if n == CEREMONY_DIR || n == CLEARED_DIR || n.ends_with(".nonces") {
                    // Ceremony votes, cleared-intent markers, nonce markers: no key material.
                } else {
                    self.finding(Class::OtherDir, Self::path_str(&path), None, None);
                    self.walk_copies(&path, 1);
                }
            } else if n.starts_with(".readyz-") {
                // The readiness probe's file.
            } else if n.ends_with(".tmp") {
                self.file(&path, Place::Copy);
                // A temp that is not a key file is still a leftover of a write in the key store.
                if !self.findings.iter().any(|f| f.class == Class::TempFile && f.path == Self::path_str(&path)) {
                    self.finding(Class::TempFile, Self::path_str(&path), key_id_from_name(&n), None);
                }
            } else if n.ends_with(".json") && !n.starts_with('.') {
                self.file(&path, Place::Live);
            } else {
                self.unclassified(Self::path_str(&path), "unknown file in the key store");
            }
        }
        self.recheck(keys, &names);
    }

    /// The ceremonies this node has in progress (a STAGED vote), from `keys/.ceremonies/`.
    fn open_ceremonies(&mut self, keys: &Path) -> BTreeSet<String> {
        let dir = keys.join(CEREMONY_DIR);
        let mut open = BTreeSet::new();
        let Ok(rd) = std::fs::read_dir(&dir) else { return open };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with('.') || !n.ends_with(".json") {
                continue;
            }
            if let Got::Bytes(b) = read_capped(&e.path()) {
                if let Ok(r) = serde_json::from_slice::<CeremonyRecord>(&b) {
                    if r.state == RecordState::Staged {
                        open.insert(r.ceremony_id);
                    }
                }
            }
        }
        open
    }

    /// `keys/.staged/`: a staged share of a ceremony this node does not have in progress is an
    /// orphan (an aborted ceremony's quarantine, a crash leftover).
    fn staged_dir(&mut self, dir: &Path, keys: &Path) {
        let open = self.open_ceremonies(keys);
        let Some(names) = self.list(dir) else { return };
        for name in &names {
            let n = name.to_string_lossy().into_owned();
            let path = dir.join(name);
            let Some(t) = self.file_type(&path) else { continue };
            if !t.is_file() {
                self.unclassified(Self::path_str(&path), "not a regular file");
                continue;
            }
            if n.ends_with(".tmp") {
                self.finding(Class::TempFile, Self::path_str(&path), key_id_from_name(&n), None);
                continue;
            }
            let ceremony = n.strip_suffix(".json").and_then(|s| s.split_once('.')).map(|(_, c)| c.to_string());
            let before = self.findings.len();
            self.file(&path, Place::Staged);
            if !ceremony.as_ref().is_some_and(|c| open.contains(c)) {
                let epoch = self.findings[before..].iter().find_map(|f| f.epoch);
                self.findings.push(Finding {
                    class: Class::StagedOrphan,
                    path: Self::path_str(&path),
                    key_id: key_id_from_name(&n),
                    epoch,
                    dek: None,
                    note: None,
                });
            }
        }
        self.recheck(dir, &names);
    }

    /// `data_dir/ceremony/`: split-ceremony recipient secrets.
    fn ceremony_dir(&mut self, dir: &Path) {
        let Some(names) = self.list(dir) else { return };
        for name in &names {
            let n = name.to_string_lossy().into_owned();
            let path = dir.join(name);
            let Some(t) = self.file_type(&path) else { continue };
            if !t.is_file() {
                self.unclassified(Self::path_str(&path), "not a regular file");
                continue;
            }
            let info = match read_capped(&path) {
                Got::Bytes(b) => inspect(&b, self.input),
                Got::Vanished => {
                    self.vanished(Self::path_str(&path));
                    continue;
                }
                Got::Error(e) => {
                    self.error(Self::path_str(&path), e);
                    continue;
                }
                Got::TooLarge => None,
            };
            let class = if n.ends_with(".tmp") { Class::TempFile } else { Class::CeremonyMaterial };
            self.finding(class, Self::path_str(&path), key_id_from_name(&n), info.as_ref());
        }
        self.recheck(dir, &names);
    }

    // ── everything else: copies ────────────────────────────────────────────────────────────────

    /// Walk a directory that holds copies (a backup, an unknown directory): every candidate file
    /// is classified against the live store; tars inside are read too.
    fn walk_copies(&mut self, dir: &Path, depth: usize) {
        if depth > MAX_DEPTH {
            self.unclassified(Self::path_str(dir), format!("deeper than {MAX_DEPTH} levels; not walked"));
            return;
        }
        if self.walked > MAX_WALK_ENTRIES {
            self.error(Self::path_str(dir), format!("walk limit of {MAX_WALK_ENTRIES} entries reached; not walked"));
            return;
        }
        let Some(names) = self.list(dir) else { return };
        for name in &names {
            let n = name.to_string_lossy().into_owned();
            let path = dir.join(name);
            let Some(t) = self.file_type(&path) else { continue };
            if t.is_symlink() {
                self.unclassified(Self::path_str(&path), "a symbolic link; not followed");
            } else if t.is_dir() {
                self.walk_copies(&path, depth + 1);
            } else if t.is_file() {
                if n.ends_with(".tar") {
                    self.tar(&path);
                } else if candidate(&n) {
                    self.file(&path, Place::Copy);
                }
            }
        }
        self.recheck(dir, &names);
    }

    /// `data_dir` itself.
    fn data_dir(&mut self) {
        let dd = self.input.data_dir;
        let Some(names) = self.list(dd) else { return };
        for name in &names {
            let n = name.to_string_lossy().into_owned();
            let path = dd.join(name);
            let Some(t) = self.file_type(&path) else { continue };
            if t.is_symlink() {
                self.unclassified(Self::path_str(&path), "a symbolic link; not followed");
                continue;
            }
            match (n.as_str(), t.is_dir()) {
                ("keys", true) => self.keys_dir(&path),
                ("ceremony", true) => self.ceremony_dir(&path),
                ("journal", true) => {} // sign journals: no key material
                ("lost+found", true) => match std::fs::read_dir(&path) {
                    Ok(mut rd) => {
                        if rd.next().is_some() {
                            self.finding(Class::LostFound, Self::path_str(&path), None, None);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        self.unclassified(Self::path_str(&path), "not readable by this user; check it as root")
                    }
                    Err(e) => self.error(Self::path_str(&path), e.to_string()),
                },
                (_, true) => {
                    self.finding(Class::OtherDir, Self::path_str(&path), None, None);
                    self.walk_copies(&path, 1);
                }
                (n, false)
                    if n == crate::cluster_identity::FILE_NAME
                        || n == crate::instance_lock::LOCK_FILE
                        || n == "delete-policy.json"
                        || n == format!(".{}.tmp", crate::cluster_identity::FILE_NAME) => {}
                (_, false) if n.ends_with(".tar") => self.tar(&path),
                (_, false) if t.is_file() && candidate(&n) => {
                    let before = self.findings.len() + self.unclassified.len();
                    self.file(&path, Place::Copy);
                    if self.findings.len() + self.unclassified.len() == before {
                        self.unclassified(Self::path_str(&path), "unknown file in data_dir");
                    }
                }
                (_, false) => self.unclassified(Self::path_str(&path), "unknown file in data_dir"),
            }
        }
        self.recheck(dd, &names);
    }

    /// One `--backup`: a directory, a tar, or a single key file.
    fn backup(&mut self, path: &Path) {
        let Some(t) = self.file_type(path) else { return };
        if t.is_dir() {
            self.walk_copies(path, 0);
        } else if t.is_file() {
            match tar_magic(path) {
                Ok(true) => self.tar(path),
                Ok(false) => {
                    let before = self.findings.len() + self.unclassified.len() + self.errors.len();
                    self.file(path, Place::Copy);
                    if self.findings.len() + self.unclassified.len() + self.errors.len() == before
                        && !self.changed.iter().any(|c| c.path == Self::path_str(path))
                    {
                        self.unclassified(
                            Self::path_str(path),
                            "neither a directory, a plain tar, nor a key file (compressed archives \
                             are not read: decompress first)",
                        );
                    }
                }
                Err(e) => self.error(Self::path_str(path), e),
            }
        } else {
            self.unclassified(Self::path_str(path), "a symbolic link or special file; not followed");
        }
    }

    // ── tars ───────────────────────────────────────────────────────────────────────────────────

    /// Read a plain tar in place: headers walked by seeking, only candidate entries read (each
    /// capped), at most [`MAX_TAR_ENTRIES`]. Entry names are reported, never joined to a path.
    fn tar(&mut self, path: &Path) {
        let shown = Self::path_str(path);
        match read_tar(path, &shown) {
            Ok(entries) => {
                for e in entries {
                    match e {
                        TarItem::Entry { shown, base, bytes } => self.classify(shown, &base, &bytes, Place::Copy),
                        TarItem::TooLarge { shown } => {
                            self.unclassified(shown, format!("larger than {MAX_FILE} bytes; not read"))
                        }
                    }
                }
            }
            Err(TarError::Vanished) => self.vanished(shown),
            Err(TarError::Read(e)) => self.error(shown, e),
        }
    }
}

enum TarItem {
    Entry { shown: String, base: String, bytes: Zeroizing<Vec<u8>> },
    TooLarge { shown: String },
}

enum TarError {
    Vanished,
    Read(String),
}

/// Whether `path` starts like a tar (ustar or GNU magic at offset 257).
fn tar_magic(path: &Path) -> std::result::Result<bool, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hdr = [0u8; 512];
    let mut got = 0;
    while got < 512 {
        match f.read(&mut hdr[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(got == 512 && &hdr[257..262] == b"ustar")
}

/// A tar numeric field: octal text, or base-256 when the high bit of the first byte is set.
fn tar_num(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = 0;
        for (i, b) in field.iter().enumerate() {
            let b = if i == 0 { b & 0x7f } else { *b };
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        return Some(v);
    }
    let s = std::str::from_utf8(field).ok()?.trim_matches(|c: char| c == '\0' || c == ' ');
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// The `path` record of a pax extended header, if any.
fn pax_path(data: &[u8]) -> Option<String> {
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest.iter().position(|b| *b == b' ')?;
        let len: usize = std::str::from_utf8(&rest[..sp]).ok()?.parse().ok()?;
        if len <= sp || len > rest.len() {
            return None;
        }
        let rec = &rest[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(v) = rec.strip_prefix(b"path=") {
            return Some(String::from_utf8_lossy(v).into_owned());
        }
        rest = &rest[len..];
    }
    None
}

/// Walk a plain tar at `path`, reported as `shown`. Only entries whose base name is a candidate
/// are read; each is reported as `<shown>!<entry name>`.
fn read_tar(path: &Path, shown: &str) -> std::result::Result<Vec<TarItem>, TarError> {
    let io = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::NotFound {
            TarError::Vanished
        } else {
            TarError::Read(e.to_string())
        }
    };
    let mut f = std::fs::File::open(path).map_err(io)?;
    let len = f.metadata().map_err(io)?.len();
    let mut out = Vec::new();
    let mut pos: u64 = 0;
    let mut next_name: Option<String> = None;
    let mut entries = 0usize;
    let corrupt = |at: u64, what: &str| TarError::Read(format!("not a readable tar at offset {at}: {what}"));
    loop {
        if pos + 512 > len {
            return Err(corrupt(pos, "truncated (no end-of-archive marker)"));
        }
        let mut hdr = [0u8; 512];
        f.seek(SeekFrom::Start(pos)).map_err(io)?;
        f.read_exact(&mut hdr).map_err(io)?;
        if hdr.iter().all(|b| *b == 0) {
            return Ok(out);
        }
        entries += 1;
        if entries > MAX_TAR_ENTRIES {
            return Err(TarError::Read(format!(
                "more than {MAX_TAR_ENTRIES} entries; the rest of the archive was not read"
            )));
        }
        let stored = tar_num(&hdr[148..156]).ok_or_else(|| corrupt(pos, "bad header checksum field"))?;
        let sum: u64 = hdr.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { *b as u64 }).sum();
        if stored != sum {
            return Err(corrupt(pos, "header checksum mismatch"));
        }
        let size = tar_num(&hdr[124..136]).ok_or_else(|| corrupt(pos, "bad size field"))?;
        let data_at = pos + 512;
        let padded = size.checked_add(511).map(|s| s / 512 * 512).ok_or_else(|| corrupt(pos, "size overflow"))?;
        if data_at.checked_add(padded).is_none_or(|end| end > len) {
            return Err(corrupt(pos, "entry runs past the end of the file"));
        }
        let typeflag = hdr[156];
        let read_meta = |f: &mut std::fs::File| -> std::result::Result<Vec<u8>, TarError> {
            if size > MAX_TAR_META {
                return Err(corrupt(pos, "extended header too large"));
            }
            let mut b = vec![0u8; size as usize];
            f.seek(SeekFrom::Start(data_at)).map_err(io)?;
            f.read_exact(&mut b).map_err(io)?;
            Ok(b)
        };
        match typeflag {
            b'L' => {
                let b = read_meta(&mut f)?;
                next_name = Some(cstr(&b));
            }
            b'x' => {
                let b = read_meta(&mut f)?;
                if let Some(p) = pax_path(&b) {
                    next_name = Some(p);
                }
            }
            b'0' | 0 | b'7' => {
                let name = next_name.take().unwrap_or_else(|| {
                    let n = cstr(&hdr[0..100]);
                    let prefix = if &hdr[257..262] == b"ustar" { cstr(&hdr[345..500]) } else { String::new() };
                    if prefix.is_empty() { n } else { format!("{prefix}/{n}") }
                });
                let base = name.rsplit('/').next().unwrap_or(&name).to_string();
                if candidate(&base) {
                    let shown = format!("{shown}!{name}");
                    if size > MAX_FILE {
                        out.push(TarItem::TooLarge { shown });
                    } else {
                        let mut b = Zeroizing::new(vec![0u8; size as usize]);
                        f.seek(SeekFrom::Start(data_at)).map_err(io)?;
                        f.read_exact(&mut b).map_err(io)?;
                        out.push(TarItem::Entry { shown, base, bytes: b });
                    }
                }
            }
            _ => {
                next_name = None;
            }
        }
        pos = data_at + padded;
    }
}

/// Control characters escaped, so a crafted file name cannot rewrite the terminal.
fn printable(s: &str) -> String {
    s.chars().flat_map(|c| if c.is_control() { c.escape_default().collect::<Vec<_>>() } else { vec![c] }).collect()
}

/// Run the scan.
pub fn scan(input: &ScanInput<'_>) -> Report {
    let mut s = Scan {
        input,
        live: BTreeMap::new(),
        counts: LiveCounts::default(),
        findings: Vec::new(),
        unclassified: Vec::new(),
        errors: Vec::new(),
        changed: Vec::new(),
        walked: 0,
    };
    let keys = input.data_dir.join("keys");
    if keys.is_dir() {
        s.load_live(&keys);
    }
    s.data_dir();
    for b in input.backups {
        s.backup(b);
    }
    // The legacy master: compared in constant time, never printed.
    if let (Some(dek), Some(sealer)) = (&input.legacy_dek, input.sealer) {
        let which = sealer.which_dek(dek);
        let id = Some(seal::dek_id(dek));
        let at = match which {
            DekUse::Current => Some("share_seal: the current DEK".to_string()),
            DekUse::Previous(i) => Some(format!("share_seal: previous DEK {i}")),
            DekUse::Unknown => None,
        };
        if let Some(path) = at {
            s.findings.push(Finding {
                class: Class::LegacyMasterDek,
                path,
                key_id: None,
                epoch: None,
                dek: id,
                note: Class::LegacyMasterDek.note(),
            });
        }
    }
    let mut not_checked: Vec<String> = NOT_CHECKED.iter().map(|s| s.to_string()).collect();
    if input.legacy_dek.is_none() && input.config_names_secret_env {
        not_checked.push(
            "legacy-master check not done: the config names share_seal.secret_env; pass \
             --legacy-master-env to compare this node's DEKs with the master's derivation"
                .into(),
        );
    }
    if input.legacy_dek.is_some() && input.sealer.is_none() {
        not_checked.push("legacy-master check not done: no share_seal is configured to compare with".into());
    }
    if input.sealer.is_none() {
        not_checked.push("DEKs: no share_seal is configured, so sealed files are not told apart by DEK".into());
    }
    s.findings.sort_by(|a, b| (a.class, &a.path).cmp(&(b.class, &b.path)));
    s.findings.dedup();
    let mut report = Report {
        schema: SCHEMA,
        node: input.node,
        data_dir: Scan::path_str(input.data_dir),
        backups: input.backups.iter().map(|b| Scan::path_str(b)).collect(),
        findings: s.findings,
        unclassified: s.unclassified,
        errors: s.errors,
        changed: s.changed,
        live: s.counts,
        not_checked,
        exit: 0,
    };
    report.exit = report.exit_code();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_numbers() {
        assert_eq!(tar_num(b"0000644\0"), Some(0o644));
        assert_eq!(tar_num(b"        "), Some(0));
        assert_eq!(tar_num(&[0x80, 0, 0, 1, 0]), Some(256));
        assert_eq!(tar_num(b"9"), None);
    }

    #[test]
    fn pax_records() {
        assert_eq!(pax_path(b"20 path=keys/a.json\n").as_deref(), Some("keys/a.json"));
        assert_eq!(pax_path(b"5 x\n"), None);
        assert_eq!(pax_path(b"99 path=x\n"), None);
    }

    #[test]
    fn names_to_key_ids() {
        assert_eq!(key_id_from_name("frost-a.json").as_deref(), Some("frost-a"));
        assert_eq!(key_id_from_name("frost-a.c1.json").as_deref(), Some("frost-a"));
        assert_eq!(key_id_from_name("frost-a.json.tmp").as_deref(), Some("frost-a"));
        assert_eq!(key_id_from_name(".create-frost-a-1.tmp").as_deref(), Some("frost-a-1"));
        assert_eq!(key_id_from_name("frost-a.recipient").as_deref(), Some("frost-a"));
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(printable("a\x1b[2Jb\n"), "a\\u{1b}[2Jb\\n");
    }

    #[test]
    fn a_vanished_file_is_a_change_not_an_error() {
        assert!(matches!(read_capped(Path::new("/nonexistent/rutli-residue")), Got::Vanished));
    }
}

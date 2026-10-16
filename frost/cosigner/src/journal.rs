// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The per-node sign journal (audit C2) and the per-key sign rate limit it backs.
//!
//! Every signature share this node releases is first appended here and fsynced — **before** the
//! nonce marker burns and the share is computed ([`rutli_frost_core::session::Cosigner::round2_guarded`]).
//! A crash between the fsync and the reply leaves an entry for a share nobody received; never the
//! reverse. So the journals of the cosigners are an independent record of every signature the
//! cluster produced, which a stolen driver certificate or a truncated driver audit log cannot
//! erase (`rutli-cosigner audit-cross-check` compares them with the driver's audit log).
//!
//! **Layout.** `data_dir/journal/<key_id>/<first seq, 20 digits>.jsonl`, one JSON object per line,
//! hash-chained: `hash = SHA-256("rutli-journal-v1\n" ‖ JSON of the entry without `hash`)`, and each
//! entry's `prev` is the hash before it (64 zeros for the very first). Segments rotate at
//! [`SEGMENT_BYTES`]; whole segments are deleted past `signing_policy.journal_retention_days` or
//! beyond `journal_max_mib_per_key` (oldest first, never the current one) — bounded on a 1 Gi
//! volume. A deleted prefix only moves the start of the chain; what remains still verifies.
//!
//! **Crashes.** Appends are `write_all` + `sync_data`, and a new segment's directory entry is
//! fsynced. A torn final line (a crash mid-append, never fsynced, so no share left for it) is
//! truncated on open with a warning; any other malformed line or chain break makes the key's
//! journal refuse to open, and with it this node's signing for that key (fail closed — other
//! nodes keep the cluster signing).
//!
//! **I/O errors.** An append that fails anywhere after the segment is opened (a partial write, an
//! fsync error on a hung volume) is rolled back to the last acknowledged length (`set_len`, best
//! effort), and the key's open journal is dropped from memory, so the next use reopens it from
//! disk: a torn tail is truncated there, a complete line whose fsync merely reported an error is
//! taken as the head — never a second entry with the same `seq`/`prev`, which would fork the chain
//! and make the key's journal refuse to open after the next restart. A per-key lock poisoned by a
//! panic mid-append is treated the same way.
//!
//! **Rate limit.** The per-key ceiling (per minute, per rolling 24 h) is charged when an entry is
//! appended for a *new* charge id — the intent's request id **and** the SHA-256 of the intent
//! bytes, or the session for a sign without an intent — so the t-subset retries and leader
//! failovers of one driver call (one signed intent, forwarded unchanged) share one charge, and a
//! replayed intent costs nothing more but is capped at `max_shares_per_request` releases. A client
//! that re-uses one request id for another digest signs another intent, which is a new charge (the
//! request id is chosen by the client; binding only it would let one id amortize any number of
//! digests). The state is rebuilt from the journal's last 24 h on first use after a restart, so a
//! restart does not reset the limit.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DaemonError, Result};

/// Domain separation of an entry hash.
pub const ENTRY_CONTEXT: &[u8] = b"rutli-journal-v1\n";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// A segment is closed and a new one started once it reaches this size.
pub const SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const MINUTE_MS: u64 = 60 * 1000;

/// Why a share was released: a client's intent, the split ceremony's sign test, or a sign without
/// an intent (an older driver or leader, accepted while `require_intent` is off).
pub const PURPOSE_SIGN: &str = "sign";
pub const PURPOSE_SIGN_TEST: &str = "sign-test";
pub const PURPOSE_NO_INTENT: &str = "no-intent";

/// One journal line.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// 1, 2, … per key on this node, across segments.
    pub seq: u64,
    pub ts_ms: u64,
    /// This node's configured identifier.
    pub node: u16,
    pub key_id: String,
    /// [`PURPOSE_SIGN`], [`PURPOSE_SIGN_TEST`] or [`PURPOSE_NO_INTENT`].
    pub purpose: String,
    /// The intent's request id (hex), empty without an intent. The driver's audit entry for the
    /// sign carries the same value (`intent=<hex>`).
    pub request_id: String,
    /// SHA-256 of the intent bytes (hex), empty without an intent.
    pub intent_sha256: String,
    /// The 34-byte message signed (hex).
    pub digest: String,
    pub session_id: String,
    /// The intent's signer CN, empty without an intent.
    pub signer_cn: String,
    /// Approvers whose signatures counted (gated keys).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    pub prev: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
}

impl JournalEntry {
    /// The hash this entry must carry: over its JSON without `hash`.
    pub fn compute_hash(&self) -> String {
        let mut body = self.clone();
        body.hash = String::new();
        let mut h = Sha256::new();
        h.update(ENTRY_CONTEXT);
        h.update(serde_json::to_vec(&body).expect("a journal entry serializes"));
        hex::encode(h.finalize())
    }

    /// What the rate limit charges this entry to (`None`: not charged — the sign test has its own
    /// limiter). An intent's charge binds the authorized operation, not just the client-chosen
    /// request id: `r:<request id>:<intent sha256>` (audit R1).
    fn charge_id(&self) -> Option<String> {
        match self.purpose.as_str() {
            PURPOSE_SIGN => Some(format!("r:{}:{}", self.request_id, self.intent_sha256)),
            PURPOSE_NO_INTENT => Some(format!("s:{}", self.session_id)),
            _ => None,
        }
    }
}

/// Per-key limits for [`SignJournal::append_charged`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// 0 = unlimited.
    pub per_min: u32,
    pub per_day: u32,
    pub max_shares_per_charge: u32,
}

/// Retention of the segments of one key.
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    pub days: u32,
    pub max_bytes: u64,
}

/// The verdict of reading one key's journal: entries, head, a torn tail.
#[derive(Debug, Default)]
pub struct ReadReport {
    pub entries: Vec<JournalEntry>,
    /// Bytes of a torn final line (not truncated by [`read_key_dir`], which never writes).
    pub torn_tail_bytes: usize,
    pub segments: usize,
}

/// The sign journal of one node.
pub struct SignJournal {
    dir: PathBuf,
    node: u16,
    retention: Retention,
    keys: Mutex<HashMap<String, Arc<Mutex<KeyJournal>>>>,
    /// Injected I/O faults (tests only), consumed one per append.
    #[cfg(test)]
    faults: Mutex<VecDeque<Fault>>,
}

/// An I/O fault a test injects into the next append.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Half the line is written, then the write fails (ENOSPC/EIO mid-write).
    PartialWrite,
    /// The whole line is written, then the fsync fails (and the rollback works).
    SyncFails,
    /// The whole line is written, the fsync fails, and so does the rollback's `set_len` (a hung
    /// volume): the line stays on disk without being acknowledged.
    SyncAndRollbackFail,
    /// A partial write whose rollback fails too: a torn tail stays on disk.
    PartialWriteNoRollback,
}

#[cfg(test)]
type FaultArg = Fault;
/// No faults outside tests.
#[cfg(not(test))]
type FaultArg = std::convert::Infallible;

/// One key's open journal plus its rate-limit ledger.
struct KeyJournal {
    dir: PathBuf,
    current: PathBuf,
    current_len: u64,
    seq: u64,
    head: String,
    /// Distinct charges of the last 24 h, oldest first.
    charges: VecDeque<(u64, String)>,
    /// Shares released per charge id within the same window.
    shares: HashMap<String, u32>,
    /// An append failed (or a holder panicked) after touching the segment: memory may no longer
    /// match the disk, so nobody may append through this instance again — it is evicted and the
    /// next use reopens the journal from disk.
    broken: bool,
}

impl SignJournal {
    /// The journal under `dir` (normally `data_dir/journal`) for node `node`. Nothing is read until
    /// a key is first used.
    pub fn open(dir: impl Into<PathBuf>, node: u16, retention: Retention) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            node,
            retention,
            keys: Mutex::new(HashMap::new()),
            #[cfg(test)]
            faults: Mutex::new(VecDeque::new()),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn key(&self, key_id: &str, now_ms: u64) -> Result<Arc<Mutex<KeyJournal>>> {
        check_key_id(key_id)?;
        let mut keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(k) = keys.get(key_id) {
            return Ok(k.clone());
        }
        let k = Arc::new(Mutex::new(KeyJournal::open(&self.dir.join(key_id), now_ms, self.retention)?));
        keys.insert(key_id.to_string(), k.clone());
        Ok(k)
    }

    /// Drop `key_id`'s open journal if it is still `k` (a broken or poisoned instance): the next
    /// use reopens it from disk.
    fn evict(&self, key_id: &str, k: &Arc<Mutex<KeyJournal>>) {
        let mut keys = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        if keys.get(key_id).is_some_and(|cur| Arc::ptr_eq(cur, k)) {
            keys.remove(key_id);
        }
    }

    /// Charge (if `entry` has a new charge id) against `limits`, then append `entry` durably — or
    /// refuse with [`DaemonError::RateLimited`] and append nothing. `seq`, `ts_ms`, `node`, `prev`
    /// and `hash` are filled in here. The check and the append are one step per key.
    pub fn append_charged(&self, entry: JournalEntry, limits: Limits, now_ms: u64) -> Result<JournalEntry> {
        // A broken or poisoned instance is evicted and the journal reopened from disk; twice in a
        // row means the disk itself is the problem, and the caller gets the error.
        for _ in 0..2 {
            let key = self.key(&entry.key_id, now_ms)?;
            let mut guard = match key.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    // A holder panicked mid-append: its write may or may not be on disk.
                    let mut g = poisoned.into_inner();
                    g.broken = true;
                    drop(g);
                    self.evict(&entry.key_id, &key);
                    crate::sync::note("sign_journal", "reopened");
                    continue;
                }
            };
            if guard.broken {
                drop(guard);
                self.evict(&entry.key_id, &key);
                continue;
            }
            let result = self.charge_and_append(&mut guard, entry.clone(), limits, now_ms);
            if guard.broken {
                drop(guard);
                self.evict(&entry.key_id, &key);
            }
            return result;
        }
        Err(DaemonError::Journal(format!(
            "sign journal of {} could not be reopened after an I/O error — refusing to sign with this key on this node",
            entry.key_id
        )))
    }

    fn charge_and_append(&self, k: &mut KeyJournal, mut entry: JournalEntry, limits: Limits, now_ms: u64) -> Result<JournalEntry> {
        k.prune(now_ms);
        if let Some(id) = entry.charge_id() {
            match k.shares.get(&id) {
                Some(&n) if n >= limits.max_shares_per_charge => {
                    return Err(DaemonError::RateLimited(format!(
                        "key {}: request already released {n} signature share(s) on this node \
                         (signing_policy.max_shares_per_request)",
                        entry.key_id
                    )))
                }
                Some(_) => {}
                None => {
                    let last_min = k.charges.iter().rev().take_while(|(t, _)| *t + MINUTE_MS > now_ms).count();
                    if limits.per_min > 0 && last_min >= limits.per_min as usize {
                        return Err(DaemonError::RateLimited(format!(
                            "key {}: {last_min} signatures in the last minute on this node \
                             (signing_policy sign rate limit {}/min)",
                            entry.key_id, limits.per_min
                        )));
                    }
                    if limits.per_day > 0 && k.charges.len() >= limits.per_day as usize {
                        return Err(DaemonError::RateLimited(format!(
                            "key {}: {} signatures in the last 24 h on this node (signing_policy sign \
                             rate limit {}/day)",
                            entry.key_id,
                            k.charges.len(),
                            limits.per_day
                        )));
                    }
                }
            }
        }
        entry.node = self.node;
        entry.ts_ms = now_ms;
        #[cfg(test)]
        let fault = self.faults.lock().unwrap().pop_front();
        #[cfg(not(test))]
        let fault = None;
        let written = k.append(entry, self.retention, now_ms, fault)?;
        if let Some(id) = written.charge_id() {
            let n = k.shares.entry(id.clone()).or_insert(0);
            if *n == 0 {
                k.charges.push_back((now_ms, id));
            }
            *n += 1;
        }
        Ok(written)
    }
}

impl KeyJournal {
    fn open(dir: &Path, now_ms: u64, retention: Retention) -> Result<Self> {
        let created = !dir.exists();
        std::fs::create_dir_all(dir)?;
        if created {
            if let Some(parent) = dir.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        let mut segs = segments(dir)?;
        // A torn tail can only be in the last segment: truncate it (it was never fsynced, so no
        // share was released for it).
        if let Some(last) = segs.last() {
            let torn = torn_tail(last)?;
            if torn > 0 {
                let len = std::fs::metadata(last)?.len();
                tracing::warn!(
                    file = %last.display(),
                    bytes = torn,
                    "sign journal ends with a torn line (a crash mid-append, never fsynced) — truncating it"
                );
                let f = std::fs::OpenOptions::new().write(true).open(last)?;
                f.set_len(len - torn as u64)?;
                f.sync_all()?;
            }
        }
        // Read back far enough for the rate-limit window (newest segments first), verifying the
        // chain of what is read.
        let mut recent: Vec<JournalEntry> = Vec::new();
        let mut seq = 0;
        let mut head = GENESIS.to_string();
        let mut next_prev: Option<String> = None;
        for seg in segs.iter().rev() {
            let (entries, torn) = read_segment(seg)?;
            if torn > 0 {
                return Err(corrupt(seg, "a torn line in a closed segment"));
            }
            verify_entries(&entries, seg)?;
            if let (Some(last), Some(want)) = (entries.last(), &next_prev) {
                if &last.hash != want {
                    return Err(corrupt(seg, "the next segment does not continue its chain"));
                }
            }
            // The head is the newest entry of the newest non-empty segment (a rotation that
            // crashed before its first append leaves an empty newest segment).
            if seq == 0 {
                if let Some(last) = entries.last() {
                    seq = last.seq;
                    head = last.hash.clone();
                }
            }
            next_prev = entries.first().map(|e| e.prev.clone());
            let older = entries.first().is_some_and(|e| e.ts_ms + DAY_MS <= now_ms);
            recent.splice(0..0, entries);
            if older {
                break;
            }
        }
        if segs.is_empty() {
            let first = dir.join(segment_name(1));
            std::fs::File::create(&first)?.sync_all()?;
            std::fs::File::open(dir)?.sync_all()?;
            segs.push(first);
        }
        let current = segs.last().expect("one segment").clone();
        let current_len = std::fs::metadata(&current)?.len();
        let mut k = Self {
            dir: dir.to_path_buf(),
            current,
            current_len,
            seq,
            head,
            charges: VecDeque::new(),
            shares: HashMap::new(),
            broken: false,
        };
        for e in recent.iter().filter(|e| e.ts_ms + DAY_MS > now_ms) {
            if let Some(id) = e.charge_id() {
                let n = k.shares.entry(id.clone()).or_insert(0);
                if *n == 0 {
                    k.charges.push_back((e.ts_ms, id));
                }
                *n += 1;
            }
        }
        k.sweep(retention, now_ms);
        Ok(k)
    }

    fn prune(&mut self, now_ms: u64) {
        while let Some((t, id)) = self.charges.front() {
            if t + DAY_MS > now_ms {
                break;
            }
            self.shares.remove(id);
            self.charges.pop_front();
        }
    }

    /// Append one entry durably. On any error after the segment is touched the file is cut back to
    /// the last acknowledged length (best effort) and this instance is marked broken, so the caller
    /// evicts it and the next append reopens the journal from disk (see the module doc).
    fn append(
        &mut self,
        mut entry: JournalEntry,
        retention: Retention,
        now_ms: u64,
        #[allow(unused_variables)] fault: Option<FaultArg>,
    ) -> Result<JournalEntry> {
        if self.current_len >= SEGMENT_BYTES {
            let next = self.dir.join(segment_name(self.seq + 1));
            std::fs::File::create(&next)?.sync_all()?;
            std::fs::File::open(&self.dir)?.sync_all()?;
            self.current = next;
            self.current_len = 0;
            self.sweep(retention, now_ms);
        }
        entry.seq = self.seq + 1;
        entry.prev = self.head.clone();
        entry.hash = entry.compute_hash();
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new().append(true).open(&self.current)?;
        let written = (|| -> std::io::Result<()> {
            #[cfg(test)]
            if matches!(fault, Some(Fault::PartialWrite) | Some(Fault::PartialWriteNoRollback)) {
                f.write_all(&line[..line.len() / 2])?;
                return Err(std::io::Error::other("injected: partial write"));
            }
            f.write_all(&line)?;
            #[cfg(test)]
            if matches!(fault, Some(Fault::SyncFails) | Some(Fault::SyncAndRollbackFail)) {
                return Err(std::io::Error::other("injected: fsync failed"));
            }
            f.sync_data()
        })();
        if let Err(e) = written {
            self.broken = true;
            #[cfg(test)]
            let skip_rollback = matches!(fault, Some(Fault::SyncAndRollbackFail) | Some(Fault::PartialWriteNoRollback));
            #[cfg(not(test))]
            let skip_rollback = false;
            let rolled_back = !skip_rollback && f.set_len(self.current_len).and_then(|()| f.sync_all()).is_ok();
            tracing::error!(
                file = %self.current.display(),
                error = %e,
                rolled_back,
                "sign journal append failed — the share is refused; the journal is reopened from disk on next use"
            );
            return Err(e.into());
        }
        self.current_len += line.len() as u64;
        self.seq = entry.seq;
        self.head = entry.hash.clone();
        metrics::counter!(crate::metrics::SIGN_JOURNAL_ENTRIES).increment(1);
        Ok(entry)
    }

    /// Delete closed segments past the retention age or the size cap, oldest first.
    fn sweep(&mut self, retention: Retention, now_ms: u64) {
        let Ok(segs) = segments(&self.dir) else { return };
        let mut sized: Vec<(PathBuf, u64, Option<std::time::SystemTime>)> = segs
            .into_iter()
            .map(|p| {
                let md = std::fs::metadata(&p).ok();
                let len = md.as_ref().map(|m| m.len()).unwrap_or(0);
                (p, len, md.and_then(|m| m.modified().ok()))
            })
            .collect();
        let mut total: u64 = sized.iter().map(|(_, l, _)| l).sum();
        let max_age = std::time::Duration::from_millis(u64::from(retention.days) * DAY_MS);
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_millis(now_ms);
        let mut removed = false;
        while sized.len() > 1 {
            let (path, len, modified) = &sized[0];
            let too_old = modified.is_some_and(|m| now.duration_since(m).is_ok_and(|age| age > max_age));
            if !(too_old || total > retention.max_bytes) {
                break;
            }
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!(file = %path.display(), error = %e, "could not delete an old sign journal segment");
                break;
            }
            tracing::info!(file = %path.display(), "deleted an old sign journal segment (retention)");
            total -= len;
            removed = true;
            sized.remove(0);
        }
        if removed {
            let _ = std::fs::File::open(&self.dir).and_then(|d| d.sync_all());
        }
    }
}

fn segment_name(first_seq: u64) -> String {
    format!("{first_seq:020}.jsonl")
}

/// The segment files of one key directory, oldest first.
pub fn segments(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension().is_some_and(|x| x == "jsonl")
                    && p.file_stem().and_then(|s| s.to_str()).is_some_and(|s| s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
            })
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    out.sort();
    Ok(out)
}

/// Bytes of a torn final line: no trailing newline and does not parse.
fn torn_tail(path: &Path) -> Result<usize> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(0);
    }
    let cut = bytes.iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
    // A complete entry missing only its newline cannot be told from a torn one that happens to
    // parse; both are treated as never acknowledged (the append returns only after the newline is
    // fsynced with the rest).
    Ok(bytes.len() - cut)
}

/// The entries of one segment and the length of a torn final line.
fn read_segment(path: &Path) -> Result<(Vec<JournalEntry>, usize)> {
    let bytes = std::fs::read(path)?;
    let torn = if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        0
    } else {
        bytes.len() - bytes.iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0)
    };
    let body = &bytes[..bytes.len() - torn];
    let mut out = Vec::new();
    for (i, line) in body.split(|&b| b == b'\n').filter(|l| !l.is_empty()).enumerate() {
        let e: JournalEntry = serde_json::from_slice(line)
            .map_err(|err| corrupt(path, &format!("line {} does not parse: {err}", i + 1)))?;
        out.push(e);
    }
    Ok((out, torn))
}

/// Each entry's hash, and the chain within the slice.
fn verify_entries(entries: &[JournalEntry], path: &Path) -> Result<()> {
    for (i, e) in entries.iter().enumerate() {
        if e.hash != e.compute_hash() {
            return Err(corrupt(path, &format!("entry seq {} does not match its hash", e.seq)));
        }
        if i > 0 && (e.prev != entries[i - 1].hash || e.seq != entries[i - 1].seq + 1) {
            return Err(corrupt(path, &format!("the chain breaks at seq {}", e.seq)));
        }
    }
    Ok(())
}

/// Read one key's journal directory without writing: every entry of every segment, the chain
/// verified across segments (the first remaining entry's `prev` is taken as given — older segments
/// may have been deleted by retention). For the offline tools.
pub fn read_key_dir(dir: &Path) -> Result<ReadReport> {
    let segs = segments(dir)?;
    let mut report = ReadReport { segments: segs.len(), ..Default::default() };
    for (i, seg) in segs.iter().enumerate() {
        let (entries, torn) = read_segment(seg)?;
        if torn > 0 {
            if i + 1 != segs.len() {
                return Err(corrupt(seg, "a torn line in a closed segment"));
            }
            report.torn_tail_bytes = torn;
        }
        if let (Some(prev), Some(first)) = (report.entries.last(), entries.first()) {
            if first.prev != prev.hash || first.seq != prev.seq + 1 {
                return Err(corrupt(seg, "the segment does not continue the previous one's chain"));
            }
        }
        verify_entries(&entries, seg)?;
        report.entries.extend(entries);
    }
    Ok(report)
}

fn check_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() || !key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(DaemonError::Config(format!("invalid key id: {key_id:?}")));
    }
    Ok(())
}

fn corrupt(path: &Path, what: &str) -> DaemonError {
    DaemonError::Journal(format!(
        "sign journal {} is corrupt ({what}) — refusing to sign with this key on this node; inspect it \
         with `rutli-cosigner audit-cross-check` and move the file aside only after it is understood",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits { per_min: 3, per_day: 5, max_shares_per_charge: 2 };
    const KEEP: Retention = Retention { days: 90, max_bytes: 64 << 20 };

    fn entry(key: &str, request: &str) -> JournalEntry {
        JournalEntry {
            key_id: key.into(),
            purpose: PURPOSE_SIGN.into(),
            request_id: request.into(),
            digest: "12".repeat(34),
            session_id: format!("sign-{request}"),
            ..Default::default()
        }
    }

    #[test]
    fn entries_chain_and_survive_a_reopen_with_the_rate_limit_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let t0 = 1_800_000_000_000u64;
        {
            let j = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
            for (i, r) in ["a", "b", "c"].iter().enumerate() {
                j.append_charged(entry("k", r), LIMITS, t0 + i as u64).unwrap();
            }
            // Per minute: the 4th distinct request in the minute is refused, nothing appended.
            assert!(matches!(j.append_charged(entry("k", "d"), LIMITS, t0 + 10), Err(DaemonError::RateLimited(_))));
            // The same request again is not a new charge, but is capped per request.
            j.append_charged(entry("k", "a"), LIMITS, t0 + 11).unwrap();
            assert!(matches!(j.append_charged(entry("k", "a"), LIMITS, t0 + 12), Err(DaemonError::RateLimited(_))));
        }
        let report = read_key_dir(&tmp.path().join("k")).unwrap();
        assert_eq!(report.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
        assert_eq!(report.entries[0].prev, GENESIS);
        assert_eq!(report.entries[0].node, 1);

        // A restart rebuilds the ledger: still 3 charges in that minute, 3 of 5 for the day.
        let j = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
        assert!(matches!(j.append_charged(entry("k", "e"), LIMITS, t0 + 20), Err(DaemonError::RateLimited(_))));
        assert!(matches!(j.append_charged(entry("k", "a"), LIMITS, t0 + 21), Err(DaemonError::RateLimited(_))));
        let later = t0 + 2 * MINUTE_MS;
        j.append_charged(entry("k", "e"), LIMITS, later).unwrap();
        j.append_charged(entry("k", "f"), LIMITS, later).unwrap();
        // Day limit: 5 charges in 24 h.
        assert!(matches!(j.append_charged(entry("k", "g"), LIMITS, later + 1), Err(DaemonError::RateLimited(_))));
        // A day later the window has moved on.
        j.append_charged(entry("k", "g"), LIMITS, t0 + DAY_MS + 3 * MINUTE_MS).unwrap();
        // Sign-test entries are journaled but never charged.
        for i in 0..10 {
            let mut e = entry("k", "");
            e.purpose = PURPOSE_SIGN_TEST.into();
            j.append_charged(e, LIMITS, t0 + DAY_MS + 3 * MINUTE_MS + i).unwrap();
        }
        assert_eq!(read_key_dir(&tmp.path().join("k")).unwrap().entries.len(), 17);
    }

    /// Audit R1: the charge binds the authorized operation. One request id re-used for two intents
    /// over different digests is two charges; the same signed intent again (a t-subset retry or a
    /// leader failover forwards it unchanged) is still one.
    #[test]
    fn one_request_id_for_two_digests_is_two_charges() {
        let tmp = tempfile::tempdir().unwrap();
        let t0 = 1_800_000_000_000u64;
        let limits = Limits { per_min: 2, per_day: 100, max_shares_per_charge: 3 };
        let j = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
        let intent = |digest: &str, intent_sha: &str| {
            let mut e = entry("k", "0f".repeat(16).as_str());
            e.digest = digest.into();
            e.intent_sha256 = intent_sha.into();
            e
        };
        let a = intent(&"12".repeat(34), &"aa".repeat(32));
        let b = intent(&"13".repeat(34), &"bb".repeat(32));
        j.append_charged(a.clone(), limits, t0).unwrap();
        // Retries / failovers of the same intent: no new charge.
        j.append_charged(a.clone(), limits, t0 + 1).unwrap();
        j.append_charged(a.clone(), limits, t0 + 2).unwrap();
        // Same request id, another digest: a second charge (the minute's limit of 2 is now full).
        j.append_charged(b.clone(), limits, t0 + 3).unwrap();
        let c = intent(&"14".repeat(34), &"cc".repeat(32));
        assert!(
            matches!(j.append_charged(c, limits, t0 + 4), Err(DaemonError::RateLimited(_))),
            "a third digest under the same request id is a third charge, refused by the per-minute limit"
        );
        // The per-charge share cap applies to each intent separately.
        assert!(matches!(j.append_charged(a, limits, t0 + 5), Err(DaemonError::RateLimited(_))));
        j.append_charged(b, limits, t0 + 6).unwrap();
        let k = j.keys.lock().unwrap().get("k").unwrap().clone();
        let k = k.lock().unwrap();
        assert_eq!(k.charges.len(), 2, "two slots: {:?}", k.charges);
    }

    /// Audit F1: an append that fails after touching the segment never leaves the file and the
    /// in-memory head out of step: the next appends continue the chain, and the journal reopens.
    #[test]
    fn a_failed_append_rolls_back_and_the_chain_stays_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let t0 = 1_800_000_000_000u64;
        let unlimited = Limits { per_min: 0, per_day: 0, max_shares_per_charge: u32::MAX };
        let j = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
        j.append_charged(entry("k", "a"), unlimited, t0).unwrap();

        // 1. A partial write: refused, the torn half is cut back, the next append is seq 2.
        j.faults.lock().unwrap().push_back(Fault::PartialWrite);
        assert!(matches!(j.append_charged(entry("k", "b"), unlimited, t0 + 1), Err(DaemonError::Io(_))));
        assert_eq!(read_key_dir(&tmp.path().join("k")).unwrap().torn_tail_bytes, 0, "rolled back");
        assert_eq!(j.append_charged(entry("k", "b"), unlimited, t0 + 2).unwrap().seq, 2);

        // 2. An fsync error after a full write, rollback works: the line is gone, seq 3 is next.
        j.faults.lock().unwrap().push_back(Fault::SyncFails);
        assert!(j.append_charged(entry("k", "c"), unlimited, t0 + 3).is_err());
        assert_eq!(read_key_dir(&tmp.path().join("k")).unwrap().entries.len(), 2);
        assert_eq!(j.append_charged(entry("k", "c"), unlimited, t0 + 4).unwrap().seq, 3);

        // 3. An fsync error and a failed rollback (hung volume): the complete line stays on disk
        // unacknowledged. The instance was evicted, so the next append reopens from disk, takes
        // that line as the head and continues after it — never a second seq 4.
        j.faults.lock().unwrap().push_back(Fault::SyncAndRollbackFail);
        assert!(j.append_charged(entry("k", "d"), unlimited, t0 + 5).is_err());
        assert_eq!(read_key_dir(&tmp.path().join("k")).unwrap().entries.len(), 4, "the unacknowledged line stayed");
        assert_eq!(j.append_charged(entry("k", "e"), unlimited, t0 + 6).unwrap().seq, 5);

        // 4. A partial write whose rollback fails too: the torn tail stays until the reopen cuts it.
        j.faults.lock().unwrap().push_back(Fault::PartialWriteNoRollback);
        assert!(j.append_charged(entry("k", "f"), unlimited, t0 + 7).is_err());
        assert!(read_key_dir(&tmp.path().join("k")).unwrap().torn_tail_bytes > 0);
        assert_eq!(j.append_charged(entry("k", "f"), unlimited, t0 + 8).unwrap().seq, 6);

        // 5. A holder panicking mid-append poisons the per-key lock: evicted and reopened.
        let key = j.key("k", t0 + 9).unwrap();
        let k2 = key.clone();
        let _ = std::thread::spawn(move || {
            let _g = k2.lock().unwrap();
            panic!("injected: a holder panics mid-append");
        })
        .join();
        assert!(key.is_poisoned());
        assert_eq!(j.append_charged(entry("k", "g"), unlimited, t0 + 10).unwrap().seq, 7);

        let report = read_key_dir(&tmp.path().join("k")).unwrap();
        assert_eq!(report.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(report.torn_tail_bytes, 0);
        drop(j);
        // A restart opens it cleanly and continues.
        let j = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
        assert_eq!(j.append_charged(entry("k", "h"), unlimited, t0 + 11).unwrap().seq, 8);
    }

    #[test]
    fn a_torn_tail_is_truncated_and_a_tampered_line_refuses_to_open() {
        let tmp = tempfile::tempdir().unwrap();
        let t0 = 1_800_000_000_000u64;
        let j = SignJournal::open(tmp.path(), 2, KEEP).unwrap();
        j.append_charged(entry("k", "a"), LIMITS, t0).unwrap();
        j.append_charged(entry("k", "b"), LIMITS, t0 + 1).unwrap();
        drop(j);
        let seg = segments(&tmp.path().join("k")).unwrap().pop().unwrap();
        let good = std::fs::read(&seg).unwrap();

        // Torn: half a line appended.
        let mut torn = good.clone();
        torn.extend_from_slice(b"{\"seq\":3,\"ts_ms\":");
        std::fs::write(&seg, &torn).unwrap();
        assert_eq!(read_key_dir(&tmp.path().join("k")).unwrap().torn_tail_bytes, 17);
        let j = SignJournal::open(tmp.path(), 2, KEEP).unwrap();
        let e = j.append_charged(entry("k", "c"), LIMITS, t0 + 2).unwrap();
        assert_eq!(e.seq, 3);
        drop(j);
        assert_eq!(read_key_dir(&tmp.path().join("k")).unwrap().entries.len(), 3);

        // Tampered: a digest rewritten in place.
        let text = String::from_utf8(std::fs::read(&seg).unwrap()).unwrap();
        std::fs::write(&seg, text.replacen(&"12".repeat(34), &"13".repeat(34), 1)).unwrap();
        assert!(matches!(read_key_dir(&tmp.path().join("k")), Err(DaemonError::Journal(_))));
        let j = SignJournal::open(tmp.path(), 2, KEEP).unwrap();
        assert!(matches!(j.append_charged(entry("k", "d"), LIMITS, t0 + 3), Err(DaemonError::Journal(_))));
    }

    #[test]
    fn segments_rotate_and_retention_deletes_the_oldest_but_the_chain_still_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let t0 = 1_800_000_000_000u64;
        let unlimited = Limits { per_min: 0, per_day: 0, max_shares_per_charge: u32::MAX };
        let small = Retention { days: 90, max_bytes: SEGMENT_BYTES * 2 };
        let j = SignJournal::open(tmp.path(), 1, small).unwrap();
        let mut n = 0u64;
        // Fat entries rotate quickly: about five segments' worth.
        while n * 16_000 < SEGMENT_BYTES * 5 {
            let mut e = entry("k", &format!("{n:032x}"));
            e.approvers = vec!["x".repeat(16_000)];
            j.append_charged(e, unlimited, t0 + n).unwrap();
            n += 1;
        }
        let segs = segments(&tmp.path().join("k")).unwrap();
        let total: u64 = segs.iter().map(|p| std::fs::metadata(p).unwrap().len()).sum();
        assert!(total <= SEGMENT_BYTES * 3, "the size cap holds (one current segment of slack): {total}");
        let report = read_key_dir(&tmp.path().join("k")).unwrap();
        assert!(report.entries.first().unwrap().seq > 1, "the oldest entries were deleted");
        assert_eq!(report.entries.last().unwrap().seq, n);
    }
}

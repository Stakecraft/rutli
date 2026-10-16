// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner audit-cross-check`: the driver's hash-chained audit log against the cosigners'
//! sign journals (audit C2 / L1).
//!
//! The driver's audit log is tamper-evident but not truncation-evident: dropping its last entries
//! leaves a valid, shorter chain, and a signature made with a stolen driver certificate never
//! reaches it at all. The cosigners' sign journals ([`crate::journal`]) are an independent record:
//! every share a node released, with the intent's request id, which the driver also writes into the
//! sign's audit entry (`intent=<hex>`). Comparing the two finds:
//!
//! * **in a cosigner journal, missing from the driver audit** — the driver's audit tail was
//!   truncated, or someone signed outside the driver with its certificate (both: investigate);
//! * **in the driver audit (outcome=ok), missing from every journal supplied** — a journal was lost
//!   or rolled back, or not all journals were supplied (`--min-journals` raises the bar to the
//!   threshold when every node's journal is given);
//! * **cosigner entries without an intent** (`purpose: no-intent`) — signatures nobody can
//!   attribute, expected only before `signing_policy.require_intent` is on (`--allow-no-intent`).
//!
//! Both chains are verified first; a broken one is an error of its own. Entries older than the
//! other side's first record (journal retention, a driver audit log started later) are skipped and
//! counted, not reported.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::journal::{read_key_dir, JournalEntry, PURPOSE_NO_INTENT, PURPOSE_SIGN};
use crate::{DaemonError, Result};

/// One `sign` entry of the driver's audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverSign {
    pub seq: u64,
    pub ts_ms: u64,
    pub key_id: String,
    /// The intent request id (hex); `None` for a sign without one (`intent=none`, or a driver
    /// older than intents).
    pub request_id: Option<String>,
    pub ok: bool,
}

/// What the driver audit log holds.
#[derive(Debug, Default)]
pub struct DriverAudit {
    pub entries: usize,
    pub signs: Vec<DriverSign>,
    pub first_ts_ms: Option<u64>,
    pub torn_tail: bool,
}

#[derive(serde::Deserialize)]
struct AuditLine {
    seq: u64,
    ts: String,
    op: String,
    detail: String,
    prev: String,
    hash: String,
}

const DRIVER_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Read and verify the driver's hash-chained audit log (`HashChainedAuditLog`: `hash =
/// SHA-256(prev ‖ seq ‖ ts ‖ op ‖ detail)`, seq from 1, genesis `prev` 64 zeros). A torn final line
/// is tolerated (the driver truncates it at its next start); anything else that breaks the chain is
/// an error.
pub fn read_driver_audit(path: &Path) -> Result<DriverAudit> {
    let bytes = std::fs::read(path)?;
    let mut text = String::from_utf8(bytes).map_err(|_| bad(path, "not UTF-8"))?;
    let mut torn_tail = false;
    if !text.is_empty() && !text.ends_with('\n') {
        let cut = text.rfind('\n').map(|i| i + 1).unwrap_or(0);
        if serde_json::from_str::<AuditLine>(&text[cut..]).is_err() {
            text.truncate(cut);
            torn_tail = true;
        }
    }
    let mut out = DriverAudit { torn_tail, ..Default::default() };
    let mut prev = DRIVER_GENESIS.to_string();
    for (i, line) in text.lines().filter(|l| !l.is_empty()).enumerate() {
        let e: AuditLine =
            serde_json::from_str(line).map_err(|err| bad(path, &format!("entry {} does not parse: {err}", i + 1)))?;
        let mut h = Sha256::new();
        h.update(e.prev.as_bytes());
        h.update(e.seq.to_string().as_bytes());
        h.update(e.ts.as_bytes());
        h.update(e.op.as_bytes());
        h.update(e.detail.as_bytes());
        if e.prev != prev || e.seq != i as u64 + 1 || hex::encode(h.finalize()) != e.hash {
            return Err(bad(path, &format!("the hash chain breaks at entry {}", i + 1)));
        }
        prev = e.hash.clone();
        out.entries += 1;
        let ts_ms = parse_instant_ms(&e.ts).ok_or_else(|| bad(path, &format!("entry {} has a bad ts {:?}", e.seq, e.ts)))?;
        out.first_ts_ms.get_or_insert(ts_ms);
        if e.op == "sign" {
            if let Some(s) = parse_sign(e.seq, ts_ms, &e.detail) {
                out.signs.push(s);
            }
        }
    }
    Ok(out)
}

/// `keyId=<k> algo=… inBytes=… [intent=<hex>|intent=none] [failover=…] … outcome=ok|failed …`
fn parse_sign(seq: u64, ts_ms: u64, detail: &str) -> Option<DriverSign> {
    let mut key_id = None;
    let mut request_id = None;
    let mut ok = None;
    for token in detail.split_whitespace() {
        if let Some(v) = token.strip_prefix("outcome=") {
            ok = Some(v == "ok");
            break; // an error message may follow; nothing after it is ours
        }
        if let Some(v) = token.strip_prefix("keyId=") {
            key_id.get_or_insert_with(|| v.to_string());
        } else if let Some(v) = token.strip_prefix("intent=") {
            if v != "none" {
                request_id.get_or_insert_with(|| v.to_string());
            }
        }
    }
    Some(DriverSign { seq, ts_ms, key_id: key_id?, request_id, ok: ok? })
}

/// Every entry of one node's journal directory (`data_dir/journal`, one subdirectory per key), each
/// key's chain verified.
pub fn read_journal_root(dir: &Path) -> Result<Vec<JournalEntry>> {
    let mut out = Vec::new();
    let mut keys: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    keys.sort();
    for k in keys {
        out.extend(read_key_dir(&k)?.entries);
    }
    Ok(out)
}

/// Knobs of [`cross_check`].
#[derive(Clone, Debug)]
pub struct Options {
    /// A driver `outcome=ok` sign must appear in at least this many of the supplied journals.
    pub min_journals: usize,
    /// Do not count cosigner signatures without an intent as discrepancies.
    pub allow_no_intent: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { min_journals: 1, allow_no_intent: false }
    }
}

/// The verdict: what was compared, and every discrepancy.
#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub discrepancies: usize,
}

impl Report {
    fn info(&mut self, s: String) {
        self.lines.push(s);
    }
    fn flag(&mut self, s: String) {
        self.discrepancies += 1;
        self.lines.push(format!("DISCREPANCY: {s}"));
    }
}

/// Compare the driver audit with the journals (`(label, entries)` per node).
pub fn cross_check(audit: &DriverAudit, journals: &[(String, Vec<JournalEntry>)], opts: &Options) -> Report {
    let mut r = Report::default();
    r.info(format!(
        "driver audit: {} entries, {} sign(s) ({} with an intent){}",
        audit.entries,
        audit.signs.len(),
        audit.signs.iter().filter(|s| s.request_id.is_some()).count(),
        if audit.torn_tail { "; a torn final line (crash mid-append) ignored" } else { "" }
    ));
    // Driver side, by (key, request id).
    let mut driver: BTreeMap<(String, String), &DriverSign> = BTreeMap::new();
    for s in &audit.signs {
        if let Some(rid) = &s.request_id {
            let slot = driver.entry((s.key_id.clone(), rid.clone())).or_insert(s);
            if s.ok && !slot.ok {
                *slot = s;
            }
        }
    }
    // Cosigner side: request -> journals that recorded it; the earliest entry per key and journal.
    let mut journaled: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut first_ts: BTreeMap<String, u64> = BTreeMap::new();
    let mut no_intent: BTreeMap<(String, String), (usize, u64, u64)> = BTreeMap::new();
    let mut skipped_old = 0usize;
    for (label, entries) in journals {
        r.info(format!(
            "journal {label}: {} entr{} over {} key(s)",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            entries.iter().map(|e| e.key_id.as_str()).collect::<BTreeSet<_>>().len()
        ));
        for e in entries {
            let first = first_ts.entry(e.key_id.clone()).or_insert(e.ts_ms);
            *first = (*first).min(e.ts_ms);
            match e.purpose.as_str() {
                PURPOSE_SIGN => {
                    if audit.first_ts_ms.is_none_or(|t| e.ts_ms < t) {
                        skipped_old += 1;
                        continue;
                    }
                    journaled.entry((e.key_id.clone(), e.request_id.clone())).or_default().insert(label.clone());
                }
                PURPOSE_NO_INTENT => {
                    let n = no_intent.entry((label.clone(), e.key_id.clone())).or_insert((0, e.ts_ms, e.ts_ms));
                    n.0 += 1;
                    n.1 = n.1.min(e.ts_ms);
                    n.2 = n.2.max(e.ts_ms);
                }
                _ => {} // sign-test: the operator's fixed digest, not a driver signature
            }
        }
    }
    if skipped_old > 0 {
        r.info(format!("{skipped_old} journal entr(ies) older than the driver audit log's first entry: not compared"));
    }

    // 1. Journaled at a cosigner, absent from the driver audit.
    for ((key, rid), labels) in &journaled {
        if !driver.contains_key(&(key.clone(), rid.clone())) {
            r.flag(format!(
                "key {key} request {rid} was signed at {} but is not in the driver audit log — the \
                 driver audit tail was truncated, or a signature was made outside the driver with its \
                 certificate",
                labels.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    // 2. In the driver audit (ok), journaled by too few cosigners.
    let mut skipped_retention = 0usize;
    for ((key, rid), s) in &driver {
        if !s.ok {
            continue;
        }
        if first_ts.get(key).is_none_or(|&t| s.ts_ms < t) && !journaled.contains_key(&(key.clone(), rid.clone())) {
            skipped_retention += 1;
            continue;
        }
        let n = journaled.get(&(key.clone(), rid.clone())).map(|l| l.len()).unwrap_or(0);
        if n < opts.min_journals {
            r.flag(format!(
                "key {key} request {rid} (driver audit seq {}) signed ok but is in {n} of the supplied \
                 journals (need {}) — a cosigner journal was lost or rolled back, or not every journal \
                 was supplied",
                s.seq, opts.min_journals
            ));
        }
    }
    if skipped_retention > 0 {
        r.info(format!(
            "{skipped_retention} driver sign(s) older than the supplied journals (retention) or for keys no \
             journal holds: not compared"
        ));
    }
    // 3. Unattributable signatures.
    for ((label, key), (n, first, last)) in &no_intent {
        let msg = format!(
            "{label}: {n} signature(s) with key {key} without a signing intent ({} .. {}) — cannot be \
             matched to the driver audit",
            fmt_ms(*first),
            fmt_ms(*last)
        );
        if opts.allow_no_intent {
            r.info(format!("{msg} (allowed: --allow-no-intent)"));
        } else {
            r.flag(msg);
        }
    }
    let legacy = audit.signs.iter().filter(|s| s.request_id.is_none() && s.ok).count();
    if legacy > 0 {
        r.info(format!("{legacy} driver sign(s) without an intent: not matchable"));
    }
    r.info(if r.discrepancies == 0 {
        "consistent: every journaled signature is in the driver audit log and every audited one is journaled".into()
    } else {
        format!("{} discrepanc(ies)", r.discrepancies)
    });
    r
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (Java's `Instant.toString`) as Unix epoch milliseconds.
pub fn parse_instant_ms(ts: &str) -> Option<u64> {
    let ts = ts.strip_suffix('Z')?;
    let (date, time) = ts.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    let millis: i64 = format!("{frac:0<3}").get(..3)?.parse().ok()?;
    // Days from civil (Howard Hinnant).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let ms = ((days * 24 + hh) * 60 + mm) * 60_000 + ss * 1000 + millis;
    u64::try_from(ms).ok()
}

/// Unix epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn fmt_ms(ms: u64) -> String {
    let ms = ms as i64;
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    )
}

fn bad(path: &Path, what: &str) -> DaemonError {
    DaemonError::Config(format!("driver audit log {}: {what}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_instants_parse() {
        assert_eq!(parse_instant_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_instant_ms("2026-10-16T14:08:50.123Z"), Some(1_792_159_730_123));
        assert_eq!(parse_instant_ms("2026-10-16T14:08:50.1Z"), Some(1_792_159_730_100));
        assert_eq!(parse_instant_ms("2026-10-16T14:08:50.123456789Z"), Some(1_792_159_730_123));
        assert_eq!(parse_instant_ms("2026-10-16 14:08:50Z"), None);
        assert_eq!(fmt_ms(1_792_159_730_123), "2026-10-16T14:08:50.123Z");
        assert_eq!(fmt_ms(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn sign_details_parse() {
        let s = parse_sign(3, 9, "keyId=frost-ns algo=Ed25519 inBytes=34 intent=00ff failover=a→b reason=UNAVAILABLE sigBytes=64 outcome=ok").unwrap();
        assert_eq!((s.key_id.as_str(), s.request_id.as_deref(), s.ok), ("frost-ns", Some("00ff"), true));
        let f = parse_sign(4, 9, "keyId=k algo=Ed25519 inBytes=34 intent=none outcome=failed error=intent=xx").unwrap();
        assert_eq!((f.request_id, f.ok), (None, false));
    }
}

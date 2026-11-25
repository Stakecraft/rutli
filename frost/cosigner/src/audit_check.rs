// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner audit-cross-check`: the driver's hash-chained audit log against the cosigners'
//! sign journals (audit C2 / L1).
//!
//! The driver's audit log is tamper-evident but not truncation-evident: dropping its last entries
//! leaves a valid, shorter chain, and a signature made with a stolen driver certificate never
//! reaches it at all. The cosigners' sign journals ([`crate::journal`]) are an independent record:
//! every share a node released, with the intent's request id and the message signed. The driver
//! writes the same request id into the sign's audit entry (`intent=<hex>`), and the SHA-256 of the
//! bytes it signed (`msg=<hex>`). Comparing the two finds:
//!
//! * **in a cosigner journal, missing from the driver audit** — the driver's audit tail was
//!   truncated, or someone signed outside the driver with its certificate (both: investigate);
//! * **in the driver audit (outcome=ok), missing from every journal supplied** — a journal was lost
//!   or rolled back, or not all journals were supplied (`--min-journals` raises the bar to the
//!   threshold when every node's journal is given);
//! * **a message journaled under an audited request id that the driver did not sign** — the driver
//!   draws a fresh request id for every sign and binds exactly one message to it, so any other
//!   message under that request id was signed outside the driver with its certificate. With `msg=`
//!   the report names the message the driver signed and each one signed out of band. Audit lines
//!   from an older driver carry no `msg=`; for those the check falls back to counting: more
//!   messages journaled under the request id than the driver audited signs for it. Journal entries
//!   are keyed on the authorized operation `(key, request id, message)`, as the cosigners charge
//!   them (a charge is `r:<request id>:<intent sha256>`), not on the bare client-chosen request id:
//!   re-using an audited request id for another digest does not hide behind the audited sign;
//! * **cosigner entries without an intent** (`purpose: no-intent`) — signatures nobody can
//!   attribute, expected only before `signing_policy.require_intent` is on (`--allow-no-intent`).
//!
//! Both chains are verified first; a broken one is an error of its own. Entries older than the
//! other side's first record (journal retention, a driver audit log started later) are skipped and
//! counted, not reported.
//!
//! An empty side proves nothing: an empty driver audit log, journals that are all empty, or two
//! sides with no signature between them to compare give the verdict [`Verdict::NothingToCompare`],
//! never "consistent". One empty journal among others is only a warning: with `t < n` a node can
//! journal nothing over a short window (the partners are spread over every cosigner, so over many
//! signatures it is a reason to look), and `--min-journals` holds each audited sign to the
//! threshold anyway. A driver audit log cut down to nothing is the extreme case of a truncated tail.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::journal::{read_key_dir, JournalEntry, PURPOSE_NO_INTENT, PURPOSE_SIGN};
use crate::{DaemonError, Result};

/// Exit status of the check when nothing was compared at all.
const EXIT_NOTHING_TO_COMPARE: i32 = 3;
/// Digits of the fractional second kept when parsing an instant (milliseconds).
const MILLIS_DIGITS: usize = 3;
/// Years in one Gregorian era (the 400-year cycle).
const YEARS_PER_ERA: i64 = 400;
/// Days in one Gregorian era.
const DAYS_PER_ERA: i64 = 146_097;
/// Days in a common year.
const DAYS_PER_YEAR: i64 = 365;
/// Years between leap days (without the century rule).
const YEARS_PER_LEAP_DAY: i64 = 4;
/// Years in a century (the century rule skips a leap day).
const YEARS_PER_CENTURY: i64 = 100;
/// Months in a year.
const MONTHS_PER_YEAR: i64 = 12;
/// Shift between a January-based and a March-based month index.
const MARCH_BASED_MONTH_SHIFT: i64 = 9;
/// Month number of March, the first month of the March-based year.
const MARCH_MONTH_NUMBER: i64 = 3;
/// March-based index of January, the first month that falls in the next civil year.
const MARCH_BASED_JANUARY: i64 = 10;
/// Days in a five-month run of the March-based year (March to July).
const DAYS_PER_FIVE_MONTHS: i64 = 153;
/// Months in that run.
const MONTHS_PER_RUN: i64 = 5;
/// Days from 0000-03-01 to the Unix epoch 1970-01-01.
const DAYS_FROM_YEAR_ZERO_TO_EPOCH: i64 = 719_468;
/// Days per four years (the leap-day correction step in the civil-from-days formula).
const DAYS_PER_FOUR_YEARS: i64 = 1460;
/// Days per century (the century correction step in the civil-from-days formula).
const DAYS_PER_CENTURY: i64 = 36_524;
/// Days per era less one (the era correction step in the civil-from-days formula).
const DAYS_PER_ERA_LESS_ONE: i64 = 146_096;
/// Hours in a day.
const HOURS_PER_DAY: i64 = 24;
/// Minutes in an hour.
const MINUTES_PER_HOUR: i64 = 60;
/// Milliseconds in a second.
const MILLIS_PER_SECOND: i64 = 1000;
/// Milliseconds in a minute.
const MILLIS_PER_MINUTE: i64 = 60_000;
/// Milliseconds in a day.
const MILLIS_PER_DAY: i64 = 86_400_000;

/// One `sign` entry of the driver's audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverSign {
    pub seq: u64,
    pub ts_ms: u64,
    pub key_id: String,
    /// The intent request id (hex); `None` for a sign without one (`intent=none`, or a driver
    /// older than intents).
    pub request_id: Option<String>,
    /// SHA-256 (lower-case hex) of the bytes the driver signed (`msg=<hex>`); `None` for a line from
    /// a driver older than `msg=`.
    pub msg: Option<String>,
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
        let cut = text.rfind('\n').map_or(0, |i| i + 1);
        if serde_json::from_str::<AuditLine>(&text[cut..]).is_err() {
            text.truncate(cut);
            torn_tail = true;
        }
    }
    let mut out = DriverAudit {
        torn_tail,
        ..Default::default()
    };
    let mut prev = DRIVER_GENESIS.to_string();
    for (i, line) in text.lines().filter(|l| !l.is_empty()).enumerate() {
        let e: AuditLine = serde_json::from_str(line)
            .map_err(|err| bad(path, &format!("entry {} does not parse: {err}", i + 1)))?;
        let mut h = Sha256::new();
        h.update(e.prev.as_bytes());
        h.update(e.seq.to_string().as_bytes());
        h.update(e.ts.as_bytes());
        h.update(e.op.as_bytes());
        h.update(e.detail.as_bytes());
        if e.prev != prev || e.seq != i as u64 + 1 || hex::encode(h.finalize()) != e.hash {
            return Err(bad(
                path,
                &format!("the hash chain breaks at entry {}", i + 1),
            ));
        }
        prev = e.hash.clone();
        out.entries += 1;
        let ts_ms = parse_instant_ms(&e.ts)
            .ok_or_else(|| bad(path, &format!("entry {} has a bad ts {:?}", e.seq, e.ts)))?;
        out.first_ts_ms.get_or_insert(ts_ms);
        if e.op == "sign" {
            if let Some(s) = parse_sign(e.seq, ts_ms, &e.detail) {
                out.signs.push(s);
            }
        }
    }
    Ok(out)
}

/// `keyId=<k> algo=… inBytes=… [msg=<sha256 hex>] [intent=<hex>|intent=none] [failover=…] …
/// outcome=ok|failed …`
fn parse_sign(seq: u64, ts_ms: u64, detail: &str) -> Option<DriverSign> {
    let mut key_id = None;
    let mut request_id = None;
    let mut msg = None;
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
        } else if let Some(v) = token.strip_prefix("msg=") {
            msg.get_or_insert_with(|| v.to_ascii_lowercase());
        }
    }
    Some(DriverSign {
        seq,
        ts_ms,
        key_id: key_id?,
        request_id,
        msg,
        ok: ok?,
    })
}

/// The driver's `msg=` for a journaled message: SHA-256 of the bytes the journal's `digest` (hex)
/// holds. A `digest` that is not hex cannot be matched to any `msg=`; its text is hashed instead.
pub fn message_sha256(digest_hex: &str) -> String {
    match hex::decode(digest_hex) {
        Ok(bytes) => hex::encode(Sha256::digest(bytes)),
        Err(_) => format!("unhashable:{digest_hex}"),
    }
}

/// One message journaled under a `(key, request id)`: its digest (hex, as journaled) and the
/// journals that recorded it.
type Journaled = (String, BTreeSet<String>);

/// The driver audit's sign lines for one `(key, request id)`.
#[derive(Default)]
struct DriverGroup<'a> {
    /// Every line, any outcome.
    lines: usize,
    /// By `msg=`: the best line (an ok one if any) for that message.
    by_msg: BTreeMap<String, &'a DriverSign>,
    /// Lines without `msg=` (an older driver): how many, and the best one.
    legacy_lines: usize,
    legacy: Option<&'a DriverSign>,
}

fn better<'a>(slot: &mut Option<&'a DriverSign>, s: &'a DriverSign) {
    match slot {
        Some(cur) if cur.ok || !s.ok => {}
        _ => *slot = Some(s),
    }
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
        Self {
            min_journals: 1,
            allow_no_intent: false,
        }
    }
}

/// What was compared, every discrepancy, and every reason the comparison proves nothing.
#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub discrepancies: usize,
    /// Why there was nothing to compare (an empty driver audit log, only empty journals, no
    /// signature on either side). Each is also a `NOTHING TO COMPARE:` line.
    pub nothing_to_compare: Vec<String>,
}

/// The outcome of [`cross_check`]. Only [`Verdict::Consistent`] is a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Signatures were compared and every one matched.
    Consistent,
    /// At least one `DISCREPANCY:` line.
    Discrepancies,
    /// No discrepancy, but the driver audit log or every supplied journal was empty, or no
    /// signature was compared at all: the check proves nothing.
    NothingToCompare,
}

impl Verdict {
    /// The process exit status: 0 consistent, 1 discrepancies, 3 nothing to compare (2 is an
    /// unreadable file or a broken chain, before any verdict).
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Consistent => 0,
            Verdict::Discrepancies => 1,
            Verdict::NothingToCompare => EXIT_NOTHING_TO_COMPARE,
        }
    }
}

impl Report {
    fn info(&mut self, s: String) {
        self.lines.push(s);
    }
    fn flag(&mut self, s: String) {
        self.discrepancies += 1;
        self.lines.push(format!("DISCREPANCY: {s}"));
    }
    fn empty(&mut self, s: String) {
        self.lines.push(format!("NOTHING TO COMPARE: {s}"));
        self.nothing_to_compare.push(s);
    }
    /// Discrepancies win over an empty side; only a comparison that found signatures and no
    /// discrepancy is consistent.
    pub fn verdict(&self) -> Verdict {
        if self.discrepancies > 0 {
            Verdict::Discrepancies
        } else if !self.nothing_to_compare.is_empty() {
            Verdict::NothingToCompare
        } else {
            Verdict::Consistent
        }
    }
}

/// Compare the driver audit with the journals (`(label, entries)` per node).
pub fn cross_check(
    audit: &DriverAudit,
    journals: &[(String, Vec<JournalEntry>)],
    opts: &Options,
) -> Report {
    let mut r = Report::default();
    info_driver_audit_summary(&mut r, audit);
    let driver = group_driver_signs(audit);
    let idx = index_journals(&mut r, audit, journals);
    flag_journaled_not_audited(&mut r, &idx.journaled, &driver);
    let mut counts = DriverCounts {
        compared: idx.compared,
        ..Default::default()
    };
    check_audited_signs(&mut r, &driver, &idx, opts, &mut counts);
    report_unattributable_signs(&mut r, audit, &idx.no_intent, opts);
    check_nothing_to_compare(&mut r, audit, journals, counts.compared);
    info_verdict(&mut r, counts.compared);
    r
}

/// What the journals hold, indexed for [`cross_check`].
#[derive(Default)]
struct JournalIndex {
    /// Cosigner side, keyed on the authorized operation: (key, request id) -> message (its
    /// SHA-256, the driver's `msg=`) -> the journaled digest and the journals that recorded it.
    /// Retries of one driver call re-sign the intent (a new intent hash) but keep the request id
    /// and the message, so the message, not the intent hash, is what one driver sign pins.
    journaled: BTreeMap<(String, String), BTreeMap<String, Journaled>>,
    /// The earliest entry per key.
    first_ts: BTreeMap<String, u64>,
    /// Entries without an intent, by (journal, key): count, first and last timestamp.
    no_intent: BTreeMap<(String, String), (usize, u64, u64)>,
    /// Journal entries older than the driver audit log's first entry.
    skipped_old: usize,
    /// Signatures actually put side by side: journaled signs inside the driver audit's window.
    compared: usize,
}

/// Counters of the driver-side pass of [`cross_check`].
#[derive(Default)]
struct DriverCounts {
    /// Signatures put side by side so far (journaled and audited ones).
    compared: usize,
    /// Audited signs older than the supplied journals, or for keys no journal holds.
    skipped_retention: usize,
    /// Audited signs without `msg=` that were compared on the request id only.
    legacy_compared: usize,
}

/// What the driver-side pass reads for one `(key, request id)` of the driver audit.
struct GroupCtx<'a> {
    key: &'a str,
    rid: &'a str,
    /// The messages journaled under this key and request id, if any.
    by_message: Option<&'a BTreeMap<String, Journaled>>,
    first_ts: &'a BTreeMap<String, u64>,
    opts: &'a Options,
}

impl GroupCtx<'_> {
    /// Whether an audited sign predates the journals of its key, with no journal holding it.
    fn too_old(&self, s: &DriverSign) -> bool {
        self.first_ts.get(self.key).is_none_or(|&t| s.ts_ms < t) && self.by_message.is_none()
    }
}

/// Add the one-line summary of the driver audit to the report.
fn info_driver_audit_summary(r: &mut Report, audit: &DriverAudit) {
    r.info(format!(
        "driver audit: {} entries, {} sign(s) ({} with an intent, {} with a message digest){}",
        audit.entries,
        audit.signs.len(),
        audit
            .signs
            .iter()
            .filter(|s| s.request_id.is_some())
            .count(),
        audit.signs.iter().filter(|s| s.msg.is_some()).count(),
        if audit.torn_tail {
            "; a torn final line (crash mid-append) ignored"
        } else {
            ""
        }
    ));
}

/// The driver audit's sign lines grouped by `(key, request id)`.
fn group_driver_signs(audit: &DriverAudit) -> BTreeMap<(String, String), DriverGroup<'_>> {
    // Driver side, by (key, request id): its lines by message (`msg=`), plus those of an older
    // driver that carry no message digest. The driver draws a fresh random request id for every
    // sign and binds one message to it, so each line stands for one authorized message.
    let mut driver: BTreeMap<(String, String), DriverGroup> = BTreeMap::new();
    for s in &audit.signs {
        if let Some(rid) = &s.request_id {
            let g = driver.entry((s.key_id.clone(), rid.clone())).or_default();
            g.lines += 1;
            if let Some(m) = &s.msg {
                let mut slot = g.by_msg.get(m).copied();
                better(&mut slot, s);
                g.by_msg.insert(m.clone(), slot.unwrap_or(s));
            } else {
                g.legacy_lines += 1;
                better(&mut g.legacy, s);
            }
        }
    }
    driver
}

/// Index every journal entry: the signs inside the driver audit's window, the earliest entry per
/// key and the entries without an intent.
fn index_journals(
    r: &mut Report,
    audit: &DriverAudit,
    journals: &[(String, Vec<JournalEntry>)],
) -> JournalIndex {
    let mut idx = JournalIndex::default();
    for (label, entries) in journals {
        info_journal_summary(r, label, entries);
        for e in entries {
            index_journal_entry(audit, label, e, &mut idx);
        }
    }
    if idx.skipped_old > 0 {
        r.info(format!(
            "{} journal entr(ies) older than the driver audit log's first entry: not compared",
            idx.skipped_old
        ));
    }
    idx
}

/// Report one journal's entry count, with a warning when it is empty.
fn info_journal_summary(r: &mut Report, label: &str, entries: &[JournalEntry]) {
    if entries.is_empty() {
        // Not a failure on its own: with t < n a node the leaders never pick journals nothing.
        // `--min-journals` still holds every audited sign to the threshold.
        r.info(format!(
            "WARNING: journal {label} is empty — that node took part in no signature, or the path is wrong \
             (a node's data_dir/journal, one subdirectory per key) or the copy failed"
        ));
    }
    r.info(format!(
        "journal {label}: {} entr{} over {} key(s)",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        entries
            .iter()
            .map(|e| e.key_id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    ));
}

/// Add one journal entry to the index.
fn index_journal_entry(audit: &DriverAudit, label: &str, e: &JournalEntry, idx: &mut JournalIndex) {
    let first = idx.first_ts.entry(e.key_id.clone()).or_insert(e.ts_ms);
    *first = (*first).min(e.ts_ms);
    match e.purpose.as_str() {
        PURPOSE_SIGN => {
            if audit.first_ts_ms.is_none_or(|t| e.ts_ms < t) {
                idx.skipped_old += 1;
                return;
            }
            idx.compared += 1;
            idx.journaled
                .entry((e.key_id.clone(), e.request_id.clone()))
                .or_default()
                .entry(message_sha256(&e.digest))
                .or_insert_with(|| (e.digest.clone(), BTreeSet::new()))
                .1
                .insert(label.to_string());
        }
        PURPOSE_NO_INTENT => {
            let n = idx
                .no_intent
                .entry((label.to_string(), e.key_id.clone()))
                .or_insert((0, e.ts_ms, e.ts_ms));
            n.0 += 1;
            n.1 = n.1.min(e.ts_ms);
            n.2 = n.2.max(e.ts_ms);
        }
        _ => {} // sign-test: the operator's fixed digest, not a driver signature
    }
}

/// The journals that recorded a message, joined with `, `.
fn join_labels(labels: &BTreeSet<String>) -> String {
    labels.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// A journaled message as the report names it: digest, `msg=` and the journals holding it.
fn describe_journaled(sha: &str, (digest, labels): &Journaled) -> String {
    format!("message {digest} (msg={sha}) at {}", join_labels(labels))
}

/// Step 1: flag what is journaled at a cosigner but absent from the driver audit — every message
/// of the request id — or journaled over messages the driver did not sign under that request id.
fn flag_journaled_not_audited(
    r: &mut Report,
    journaled: &BTreeMap<(String, String), BTreeMap<String, Journaled>>,
    driver: &BTreeMap<(String, String), DriverGroup<'_>>,
) {
    for ((key, rid), by_message) in journaled {
        let Some(g) = driver.get(&(key.clone(), rid.clone())) else {
            for (sha, m) in by_message {
                r.flag(format!(
                    "key {key} request {rid} was signed ({}) but is not in the driver audit log — the \
                     driver audit tail was truncated, or a signature was made outside the driver with \
                     its certificate",
                    describe_journaled(sha, m)
                ));
            }
            continue;
        };
        flag_out_of_band_messages(r, key, rid, by_message, g);
    }
}

/// Flag the messages journaled under an audited request id that the driver did not sign.
fn flag_out_of_band_messages(
    r: &mut Report,
    key: &str,
    rid: &str,
    by_message: &BTreeMap<String, Journaled>,
    g: &DriverGroup<'_>,
) {
    // Messages no `msg=` line of this request id names.
    let unmatched: Vec<_> = by_message
        .iter()
        .filter(|(sha, _)| !g.by_msg.contains_key(*sha))
        .collect();
    if g.legacy_lines == 0 {
        // Every driver line names its message: each other message is out of band, by name.
        let driver_signed = g
            .by_msg
            .iter()
            .map(|(m, s)| format!("msg={m} (seq {})", s.seq))
            .collect::<Vec<_>>()
            .join(", ");
        for (sha, m) in unmatched {
            r.flag(format!(
                "key {key} request {rid}: {} was signed OUT OF BAND — the driver audit log signed only \
                 {driver_signed} under this request id, and the driver binds one message to each request \
                 id, so this one was signed outside the driver with its certificate",
                describe_journaled(sha, m)
            ));
        }
    } else if unmatched.len() > g.legacy_lines {
        // An older driver's lines carry no message: count, as they cannot be told apart.
        r.flag(format!(
            "key {key} request {rid} was signed over {} different messages ({}) but the driver \
             audit log holds {} sign(s) for it (seq {}) — the driver binds one message to each \
             request id, so at least {} of them were signed outside the driver with its \
             certificate",
            by_message.len(),
            by_message
                .iter()
                .map(|(sha, m)| describe_journaled(sha, m))
                .collect::<Vec<_>>()
                .join("; "),
            g.lines,
            g.legacy
                .or_else(|| g.by_msg.values().next().copied())
                .map_or(0, |s| s.seq),
            unmatched.len() - g.legacy_lines
        ));
    }
}

/// Step 2: flag what is in the driver audit (ok) but journaled by too few cosigners.
fn check_audited_signs(
    r: &mut Report,
    driver: &BTreeMap<(String, String), DriverGroup<'_>>,
    idx: &JournalIndex,
    opts: &Options,
    counts: &mut DriverCounts,
) {
    for ((key, rid), g) in driver {
        let ctx = GroupCtx {
            key: key.as_str(),
            rid: rid.as_str(),
            by_message: idx.journaled.get(&(key.clone(), rid.clone())),
            first_ts: &idx.first_ts,
            opts,
        };
        check_group_messages(r, g, &ctx, counts);
        check_group_legacy(r, g, &ctx, counts);
    }
    if counts.skipped_retention > 0 {
        r.info(format!(
            "{} driver sign(s) older than the supplied journals (retention) or for keys no \
             journal holds: not compared",
            counts.skipped_retention
        ));
    }
    if counts.legacy_compared > 0 {
        r.info(format!(
            "{} driver sign(s) without msg= (an older driver): matched on the request id only",
            counts.legacy_compared
        ));
    }
}

/// Check each audited message of one `(key, request id)`, by name.
fn check_group_messages(
    r: &mut Report,
    g: &DriverGroup<'_>,
    ctx: &GroupCtx<'_>,
    counts: &mut DriverCounts,
) {
    let (key, rid, opts) = (ctx.key, ctx.rid, ctx.opts);
    for (msg, s) in &g.by_msg {
        if !s.ok {
            continue;
        }
        if ctx.too_old(s) {
            counts.skipped_retention += 1;
            continue;
        }
        counts.compared += 1;
        let n = ctx
            .by_message
            .and_then(|m| m.get(msg))
            .map_or(0, |(_, l)| l.len());
        if n < opts.min_journals {
            r.flag(format!(
                "key {key} request {rid} msg={msg} (driver audit seq {}) signed ok but is in {n} of \
                 the supplied journals (need {}) — a cosigner journal was lost or rolled back, or not \
                 every journal was supplied",
                s.seq, opts.min_journals
            ));
        }
    }
}

/// Check the line of an older driver (no `msg=`) of one `(key, request id)`: the most journals
/// holding any one message of the request (several messages are flagged by step 1).
fn check_group_legacy(
    r: &mut Report,
    g: &DriverGroup<'_>,
    ctx: &GroupCtx<'_>,
    counts: &mut DriverCounts,
) {
    let (key, rid, opts) = (ctx.key, ctx.rid, ctx.opts);
    if let Some(s) = g.legacy.filter(|s| s.ok) {
        if ctx.too_old(s) {
            counts.skipped_retention += 1;
            return;
        }
        counts.legacy_compared += 1;
        counts.compared += 1;
        let n = ctx
            .by_message
            .and_then(|m| m.values().map(|(_, l)| l.len()).max())
            .unwrap_or(0);
        if n < opts.min_journals {
            r.flag(format!(
                "key {key} request {rid} (driver audit seq {}) signed ok but is in {n} of the supplied \
                 journals (need {}) — a cosigner journal was lost or rolled back, or not every journal \
                 was supplied",
                s.seq, opts.min_journals
            ));
        }
    }
}

/// Step 3: report the signatures without an intent, which cannot be matched to the driver audit.
fn report_unattributable_signs(
    r: &mut Report,
    audit: &DriverAudit,
    no_intent: &BTreeMap<(String, String), (usize, u64, u64)>,
    opts: &Options,
) {
    for ((label, key), (n, first, last)) in no_intent {
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
    let legacy = audit
        .signs
        .iter()
        .filter(|s| s.request_id.is_none() && s.ok)
        .count();
    if legacy > 0 {
        r.info(format!(
            "{legacy} driver sign(s) without an intent: not matchable"
        ));
    }
}

/// Record why the comparison proves nothing, when an empty side or no common window says so.
fn check_nothing_to_compare(
    r: &mut Report,
    audit: &DriverAudit,
    journals: &[(String, Vec<JournalEntry>)],
    compared: usize,
) {
    if audit.entries == 0 {
        r.empty(
            "the driver audit log is empty — copy the driver's audit-log-path (after the journals); an \
             empty log cannot show which signatures the driver made, and a log cut down to nothing is the \
             extreme case of a truncated tail"
                .into(),
        );
    } else if journals.iter().all(|(_, e)| e.is_empty()) {
        r.empty(
            "every supplied journal is empty — check the paths (each node's data_dir/journal) and copy them in \
             full; empty journals cannot show which signatures the cluster made"
                .into(),
        );
    } else if compared == 0 && r.nothing_to_compare.is_empty() {
        r.empty(
            "no signature on either side falls inside the other side's records — nothing was compared \
             (no signs yet, or the journals and the driver audit log cover different periods)"
                .into(),
        );
    }
}

/// Add the closing verdict line to the report.
fn info_verdict(r: &mut Report, compared: usize) {
    r.info(match r.verdict() {
        Verdict::Consistent => format!(
            "consistent: {compared} signature record(s) compared; every journaled signature is in the driver \
             audit log and every audited one is journaled"
        ),
        Verdict::Discrepancies => format!("{} discrepanc(ies)", r.discrepancies),
        Verdict::NothingToCompare => {
            "NOT consistent: nothing to compare, so this run proves nothing (exit 3)".into()
        }
    });
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (Java's `Instant.toString`) as Unix epoch milliseconds.
pub fn parse_instant_ms(ts: &str) -> Option<u64> {
    let ts = ts.strip_suffix('Z')?;
    let (date, time) = ts.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    let millis: i64 = format!("{frac:0<3}").get(..MILLIS_DIGITS)?.parse().ok()?;
    // Days from civil (Howard Hinnant).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(YEARS_PER_ERA);
    let yoe = y2 - era * YEARS_PER_ERA;
    let mp = (m + MARCH_BASED_MONTH_SHIFT) % MONTHS_PER_YEAR;
    let doy = (DAYS_PER_FIVE_MONTHS * mp + 2) / MONTHS_PER_RUN + day - 1;
    let doe = yoe * DAYS_PER_YEAR + yoe / YEARS_PER_LEAP_DAY - yoe / YEARS_PER_CENTURY + doy;
    let days = era * DAYS_PER_ERA + doe - DAYS_FROM_YEAR_ZERO_TO_EPOCH;
    let ms = ((days * HOURS_PER_DAY + hh) * MINUTES_PER_HOUR + mm) * MILLIS_PER_MINUTE
        + ss * MILLIS_PER_SECOND
        + millis;
    u64::try_from(ms).ok()
}

/// Unix epoch milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn fmt_ms(ms: u64) -> String {
    let ms = ms as i64;
    let (days, rem) = (ms.div_euclid(MILLIS_PER_DAY), ms.rem_euclid(MILLIS_PER_DAY));
    // Civil from days (Howard Hinnant).
    let z = days + DAYS_FROM_YEAR_ZERO_TO_EPOCH;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z - era * DAYS_PER_ERA;
    let yoe = (doe - doe / DAYS_PER_FOUR_YEARS + doe / DAYS_PER_CENTURY
        - doe / DAYS_PER_ERA_LESS_ONE)
        / DAYS_PER_YEAR;
    let doy = doe - (DAYS_PER_YEAR * yoe + yoe / YEARS_PER_LEAP_DAY - yoe / YEARS_PER_CENTURY);
    let mp = (MONTHS_PER_RUN * doy + 2) / DAYS_PER_FIVE_MONTHS;
    let d = doy - (DAYS_PER_FIVE_MONTHS * mp + 2) / MONTHS_PER_RUN + 1;
    let m = if mp < MARCH_BASED_JANUARY {
        mp + MARCH_MONTH_NUMBER
    } else {
        mp - MARCH_BASED_MONTH_SHIFT
    };
    let y = yoe + era * YEARS_PER_ERA + i64::from(m <= 2);
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
        assert_eq!(
            parse_instant_ms("2026-10-16T14:08:50.123Z"),
            Some(1_792_159_730_123)
        );
        assert_eq!(
            parse_instant_ms("2026-10-16T14:08:50.1Z"),
            Some(1_792_159_730_100)
        );
        assert_eq!(
            parse_instant_ms("2026-10-16T14:08:50.123456789Z"),
            Some(1_792_159_730_123)
        );
        assert_eq!(parse_instant_ms("2026-10-16 14:08:50Z"), None);
        assert_eq!(fmt_ms(1_792_159_730_123), "2026-10-16T14:08:50.123Z");
        assert_eq!(fmt_ms(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn sign_details_parse() {
        let s = parse_sign(3, 9, "keyId=frost-ns algo=Ed25519 inBytes=34 intent=00ff failover=a→b reason=UNAVAILABLE sigBytes=64 outcome=ok").unwrap();
        assert_eq!(
            (s.key_id.as_str(), s.request_id.as_deref(), s.ok),
            ("frost-ns", Some("00ff"), true)
        );
        assert_eq!(s.msg, None, "an older driver's line carries no msg=");
        let f = parse_sign(
            4,
            9,
            "keyId=k algo=Ed25519 inBytes=34 intent=none outcome=failed error=intent=xx msg=ff",
        )
        .unwrap();
        assert_eq!(
            (f.request_id, f.msg, f.ok),
            (None, None, false),
            "nothing after outcome= is parsed"
        );
        let m = parse_sign(
            5,
            9,
            "keyId=k algo=Ed25519 inBytes=34 msg=ABcd intent=00ff sigBytes=64 outcome=ok",
        )
        .unwrap();
        assert_eq!(
            (m.request_id.as_deref(), m.msg.as_deref()),
            (Some("00ff"), Some("abcd"))
        );
    }

    #[test]
    fn a_journaled_message_hashes_to_the_drivers_msg() {
        // The driver's msg= is SHA-256 of the signed bytes; the journal holds those bytes as hex.
        let digest = "1220".to_string() + &"ab".repeat(32);
        assert_eq!(
            message_sha256(&digest),
            hex::encode(Sha256::digest(hex::decode(&digest).unwrap()))
        );
        assert!(message_sha256("not hex").starts_with("unhashable:"));
    }

    fn journaled(node: u16, request: &str, message: &str, ts_ms: u64) -> JournalEntry {
        JournalEntry {
            ts_ms,
            node,
            key_id: "frost-ns".into(),
            purpose: PURPOSE_SIGN.into(),
            request_id: request.into(),
            // Each intent names its own digest, so its hash (the charge) differs too.
            intent_sha256: hex::encode(Sha256::digest(format!("{request}/{message}"))),
            digest: message.into(),
            ..Default::default()
        }
    }

    /// A sign line from a driver older than `msg=`.
    fn signed(seq: u64, request: &str) -> DriverSign {
        DriverSign {
            seq,
            ts_ms: 1_000 + seq,
            key_id: "frost-ns".into(),
            request_id: Some(request.into()),
            msg: None,
            ok: true,
        }
    }

    /// A sign line naming the message signed (`msg=`).
    fn signed_msg(seq: u64, request: &str, message: &str) -> DriverSign {
        DriverSign {
            msg: Some(message_sha256(message)),
            ..signed(seq, request)
        }
    }

    #[test]
    fn msg_names_the_message_the_driver_signed_and_each_one_signed_out_of_band() {
        let (rid, m1, m2, m3) = (
            "a".repeat(32),
            "11".repeat(34),
            "22".repeat(34),
            "33".repeat(34),
        );
        let audit = DriverAudit {
            entries: 1,
            signs: vec![signed_msg(1, &rid, &m1)],
            first_ts_ms: Some(1_000),
            torn_tail: false,
        };
        let opts = Options {
            min_journals: 2,
            allow_no_intent: false,
        };
        let honest = vec![
            ("n1".to_string(), vec![journaled(1, &rid, &m1, 2_000)]),
            ("n2".to_string(), vec![journaled(2, &rid, &m1, 2_000)]),
        ];
        let r = cross_check(&audit, &honest, &opts);
        assert_eq!(r.discrepancies, 0, "{:#?}", r.lines);
        assert!(
            r.lines[0].contains("1 with a message digest"),
            "{:#?}",
            r.lines
        );

        // Two more messages under the audited request id: each named as out of band, next to the
        // message the driver did sign.
        let mut reused = honest.clone();
        reused[0].1.push(journaled(1, &rid, &m2, 3_000));
        reused[1].1.push(journaled(2, &rid, &m3, 3_000));
        let r = cross_check(&audit, &reused, &opts);
        assert_eq!(r.discrepancies, 2, "{:#?}", r.lines);
        let flagged: Vec<_> = r
            .lines
            .iter()
            .filter(|l| l.starts_with("DISCREPANCY"))
            .collect();
        for (m, node) in [(&m2, "n1"), (&m3, "n2")] {
            let line = flagged
                .iter()
                .find(|l| l.contains(m.as_str()))
                .unwrap_or_else(|| panic!("{flagged:#?}"));
            assert!(
                line.contains("OUT OF BAND") && line.contains(&format!("at {node}")),
                "{line}"
            );
            assert!(
                line.contains(&format!("signed only msg={} (seq 1)", message_sha256(&m1))),
                "{line}"
            );
            assert!(
                line.contains(&format!("msg={}", message_sha256(m))),
                "{line}"
            );
        }
        assert!(
            !flagged
                .iter()
                .any(|l| l.contains(&format!("message {m1} "))),
            "the audited message is not flagged"
        );

        // The driver signed m1, the cluster only ever journaled m2 under its request id: m2 is out
        // of band, and the audited m1 is in no journal.
        let swapped = vec![("n1".to_string(), vec![journaled(1, &rid, &m2, 2_000)])];
        let r = cross_check(&audit, &swapped, &Options::default());
        assert_eq!(r.discrepancies, 2, "{:#?}", r.lines);
        assert!(
            r.lines
                .iter()
                .any(|l| l.contains("OUT OF BAND") && l.contains(&m2)),
            "{:#?}",
            r.lines
        );
        assert!(
            r.lines.iter().any(|l| l.contains(&format!(
                "msg={} (driver audit seq 1) signed ok but is in 0",
                message_sha256(&m1)
            ))),
            "{:#?}",
            r.lines
        );

        // An older driver line (no msg=) for the same journals: the count-based fallback, which
        // cannot tell which of two messages the driver signed.
        let legacy = DriverAudit {
            signs: vec![signed(1, &rid)],
            ..audit
        };
        let mut two = honest.clone();
        two[0].1.push(journaled(1, &rid, &m2, 3_000));
        let r = cross_check(&legacy, &two, &opts);
        assert_eq!(r.discrepancies, 1, "{:#?}", r.lines);
        assert!(
            r.lines
                .iter()
                .any(|l| l.contains("signed over 2 different messages")),
            "{:#?}",
            r.lines
        );
        assert!(
            r.lines
                .iter()
                .any(|l| l.contains("without msg= (an older driver)")),
            "{:#?}",
            r.lines
        );
    }

    #[test]
    fn an_empty_side_is_nothing_to_compare_never_consistent() {
        let (rid, m1) = ("a".repeat(32), "11".repeat(34));
        let audit = DriverAudit {
            entries: 1,
            signs: vec![signed_msg(1, &rid, &m1)],
            first_ts_ms: Some(1_000),
            torn_tail: false,
        };
        let full = vec![("n1".to_string(), vec![journaled(1, &rid, &m1, 2_000)])];
        assert_eq!(
            cross_check(&audit, &full, &Options::default()).verdict(),
            Verdict::Consistent
        );

        // An empty driver audit log next to a full journal.
        let r = cross_check(&DriverAudit::default(), &full, &Options::default());
        assert_eq!(
            (r.verdict(), r.discrepancies),
            (Verdict::NothingToCompare, 0),
            "{:#?}",
            r.lines
        );
        assert!(
            r.lines
                .iter()
                .any(|l| l.starts_with("NOTHING TO COMPARE: the driver audit log is empty")),
            "{:#?}",
            r.lines
        );
        assert!(
            !r.lines.iter().any(|l| l.starts_with("consistent")),
            "{:#?}",
            r.lines
        );
        assert_eq!(r.verdict().exit_code(), 3);

        // Both empty.
        let r = cross_check(
            &DriverAudit::default(),
            &[("n1".to_string(), vec![])],
            &Options::default(),
        );
        assert_eq!(r.verdict(), Verdict::NothingToCompare, "{:#?}", r.lines);

        // A full driver audit log next to only empty journals (the sign is then "for a key no
        // journal holds", which was skipped and passed).
        let r = cross_check(
            &audit,
            &[("n1".to_string(), vec![]), ("n2".to_string(), vec![])],
            &Options::default(),
        );
        assert_eq!(r.verdict(), Verdict::NothingToCompare, "{:#?}", r.lines);
        assert!(
            r.lines
                .iter()
                .any(|l| l.contains("every supplied journal is empty")),
            "{:#?}",
            r.lines
        );

        // One empty journal among full ones (a node the leaders never picked): a warning, and the
        // threshold check still applies.
        let mut one_empty = full.clone();
        one_empty.push(("n2".to_string(), vec![]));
        let r = cross_check(&audit, &one_empty, &Options::default());
        assert_eq!(r.verdict(), Verdict::Consistent, "{:#?}", r.lines);
        assert!(
            r.lines
                .iter()
                .any(|l| l.starts_with("WARNING: journal n2 is empty")),
            "{:#?}",
            r.lines
        );
        let r = cross_check(
            &audit,
            &one_empty,
            &Options {
                min_journals: 2,
                allow_no_intent: false,
            },
        );
        assert_eq!(r.verdict(), Verdict::Discrepancies, "{:#?}", r.lines);

        // Entries on both sides, but no signature to compare (a deployment that never signed).
        let no_signs = DriverAudit {
            entries: 3,
            signs: vec![],
            first_ts_ms: Some(1_000),
            torn_tail: false,
        };
        let mut test_only = journaled(1, &rid, &m1, 2_000);
        test_only.purpose = "sign-test".into();
        let r = cross_check(
            &no_signs,
            &[("n1".to_string(), vec![test_only])],
            &Options::default(),
        );
        assert_eq!(r.verdict(), Verdict::NothingToCompare, "{:#?}", r.lines);
        assert!(
            r.lines.iter().any(|l| l.contains("nothing was compared")),
            "{:#?}",
            r.lines
        );

        // A discrepancy wins over nothing to compare.
        let r = cross_check(
            &DriverAudit::default(),
            &[("n1".to_string(), vec![journaled(1, &rid, &m1, 2_000)])],
            &Options::default(),
        );
        assert_eq!(
            r.verdict(),
            Verdict::NothingToCompare,
            "an empty log skips every journal entry: {:#?}",
            r.lines
        );
        let r = cross_check(
            &no_signs,
            &[
                ("n1".to_string(), vec![journaled(1, &rid, &m1, 2_000)]),
                ("n2".to_string(), vec![]),
            ],
            &Options::default(),
        );
        assert_eq!(
            (r.verdict(), r.verdict().exit_code()),
            (Verdict::Discrepancies, 1),
            "{:#?}",
            r.lines
        );
    }

    #[test]
    fn one_request_id_over_two_messages_is_two_operations() {
        let (rid, m1, m2) = ("a".repeat(32), "11".repeat(34), "22".repeat(34));
        let audit = DriverAudit {
            entries: 1,
            signs: vec![signed(1, &rid)],
            first_ts_ms: Some(1_000),
            torn_tail: false,
        };
        let opts = Options {
            min_journals: 2,
            allow_no_intent: false,
        };

        // The audited sign, journaled by both nodes (a retry re-signs the intent: same request id and
        // message, another intent hash) — consistent.
        let mut retry = journaled(2, &rid, &m1, 2_100);
        retry.intent_sha256 = "ff".repeat(32);
        let honest = vec![
            ("n1".to_string(), vec![journaled(1, &rid, &m1, 2_000)]),
            ("n2".to_string(), vec![retry]),
        ];
        let r = cross_check(&audit, &honest, &opts);
        assert_eq!(r.discrepancies, 0, "{:#?}", r.lines);

        // A second intent re-using the audited request id for another digest (signed outside the
        // driver with its certificate): a distinct entry, and the driver audit line covers only one.
        let mut reused = honest.clone();
        reused[0].1.push(journaled(1, &rid, &m2, 3_000));
        let r = cross_check(&audit, &reused, &opts);
        assert_eq!(r.discrepancies, 1, "{:#?}", r.lines);
        let line = r
            .lines
            .iter()
            .find(|l| l.starts_with("DISCREPANCY"))
            .unwrap();
        assert!(
            line.contains("signed over 2 different messages")
                && line.contains(&m1)
                && line.contains(&m2),
            "{line}"
        );
        assert!(line.contains("driver audit log holds 1 sign(s)"), "{line}");

        // Without the driver line both messages are reported, each on its own.
        let none = DriverAudit {
            signs: vec![],
            ..audit
        };
        let r = cross_check(&none, &reused, &Options::default());
        let missing: Vec<_> = r
            .lines
            .iter()
            .filter(|l| l.contains("is not in the driver audit log"))
            .collect();
        assert_eq!(missing.len(), 2, "{:#?}", r.lines);
        assert!(
            missing.iter().any(|l| l.contains(&m1)) && missing.iter().any(|l| l.contains(&m2)),
            "{missing:#?}"
        );
    }
}

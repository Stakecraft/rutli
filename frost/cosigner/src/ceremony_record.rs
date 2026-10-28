// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Durable per-node ceremony records: this node's vote in a two-phase DKG or refresh (H1, M5).
//!
//! A ceremony C on key K moves through, on every node:
//!
//! ```text
//! (none) --part1--> SESSION (memory only) --part3 ok--> staged share (fsync) --> STAGED (fsync)  [yes]
//! SESSION --error / abort / orphan / restart--> ABORTED                                           [no]
//! STAGED --every roster node STAGED|COMMITTED with the same outcome--> promote share --> COMMITTED
//! STAGED --direct evidence: a node ABORTED, or one staged a different outcome--> ABORTED
//! ```
//!
//! **Safety invariant (crash faults).** A node commits only after confirming *directly* (over the
//! mTLS mesh, not through the leader) that every roster node holds a durable yes-vote for the same
//! outcome; it aborts only on direct evidence that some node voted no or diverged. A recorded vote
//! is never rewritten except STAGED → COMMITTED / ABORTED, and a terminal state never changes
//! (one operator break-glass excepted, below). So with nodes that crash, restart or lose
//! messages, no two nodes resolve one ceremony differently, and nobody needs the leader to finish:
//! every node runs the resolver ([`decide`]) itself.
//!
//! **Byzantine cosigner (audit F3).** The votes peers report are not signed or cross-checked, so
//! one *lying* cosigner can tell one honest node STAGED and the other ABORTED: the first commits,
//! the second aborts (a split: they no longer sign together, every signature needs the liar). With
//! n = 3, f = 1 this cannot be prevented without Byzantine agreement; it costs availability, never
//! the key (no node ever holds two shares of one sharing it should not). It is detected and
//! recoverable instead:
//!
//! * an abort while some peer reported a yes-vote for this node's outcome re-gathers the votes
//!   before acting ([`mixed_evidence`]), and COMMITTED plus ABORTED reported for one ceremony is
//!   proof of equivocation ([`equivocation`]: with crash faults a node commits only after every
//!   yes-vote, after which nobody can abort) — counted and logged;
//! * the resolver never deletes the staged share of a ceremony it aborts: it is **quarantined**
//!   (kept beside the ABORTED record) until every peer is seen terminal with nobody COMMITTED
//!   ([`quarantine_droppable`]), or a retention passes;
//! * a peer later reporting COMMITTED for this node's outcome flags a split
//!   (`rutli_ceremonies_split`), and the operator may `ceremony recover-commit` the quarantined
//!   share — key-safe, since an honest COMMITTED node saw every node's yes-vote for that outcome.
//!
//! Records live in `data_dir/keys/.ceremonies/<ceremony_id>.json`, written with the key store's
//! discipline: temp + fsync + rename (create-once for a node's first vote) + directory fsync.
//! They hold public values only (digests, epochs, the roster).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::keystore::{private_file, rename_noreplace, validate_ceremony_id, NoReplace};
use crate::{DaemonError, Result};

/// A node's durable vote.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    /// Yes: the new share is staged (fsynced) and this node will commit it once every roster node
    /// confirms the same outcome.
    Staged,
    /// The staged share is now the live one.
    Committed,
    /// No: this node will never commit the ceremony (and has deleted any staged share).
    Aborted,
}

impl RecordState {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordState::Staged => "staged",
            RecordState::Committed => "committed",
            RecordState::Aborted => "aborted",
        }
    }
}

/// One ceremony as this node recorded it. Digests are lowercase hex, empty when not applicable
/// (an ABORTED record written for a ceremony this node never staged knows only its id).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CeremonyRecord {
    pub ceremony_id: String,
    pub state: RecordState,
    #[serde(default)]
    pub key_id: String,
    /// "dkg" | "refresh".
    #[serde(default)]
    pub kind: String,
    /// Configured identifiers of every participant; commit needs a yes-vote from each.
    #[serde(default)]
    pub roster: Vec<u16>,
    #[serde(default)]
    pub old_epoch: u64,
    #[serde(default)]
    pub old_pkp_digest: String,
    #[serde(default)]
    pub new_epoch: u64,
    #[serde(default)]
    pub new_pkp_digest: String,
    #[serde(default)]
    pub group_key: String,
    /// Digest of the round-1 map this node used (C1); identical on every honest node.
    #[serde(default)]
    pub round1_digest: String,
    /// Why an ABORTED record was written (log text, never key material).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Every other roster node has been seen in a terminal state for this ceremony: nothing can
    /// ask this node about it any more, so the record may be garbage-collected once old.
    #[serde(default)]
    pub peers_settled: bool,
    #[serde(default)]
    pub created_ms: u64,
    #[serde(default)]
    pub updated_ms: u64,
    /// ABORTED by the resolver with its staged share kept (quarantined), in case a peer reports it
    /// COMMITTED later (audit F3). Cleared when the share is dropped.
    #[serde(default, skip_serializing_if = "is_false")]
    pub quarantined: bool,
    /// When a peer was first seen reporting COMMITTED for this node's outcome of a ceremony this
    /// node aborted (a split; 0 = never).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub split_detected_ms: u64,
    /// A no-vote recorded because a peer asked about a ceremony id this node had no session or
    /// record for: who asked (the caller's certificate CN, empty for an in-process caller). Counted
    /// against the caps on such records (audit F2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_asked_by: Option<String>,
    /// COMMITTED by the operator's `ceremony recover-commit` from a quarantined ABORTED record.
    #[serde(default, skip_serializing_if = "is_false")]
    pub recovered: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl CeremonyRecord {
    /// A no-vote for a ceremony this node knows nothing more about.
    pub fn aborted(ceremony_id: &str, reason: impl Into<String>) -> Self {
        let now = now_ms();
        Self {
            ceremony_id: ceremony_id.to_string(),
            state: RecordState::Aborted,
            key_id: String::new(),
            kind: String::new(),
            roster: Vec::new(),
            old_epoch: 0,
            old_pkp_digest: String::new(),
            new_epoch: 0,
            new_pkp_digest: String::new(),
            group_key: String::new(),
            round1_digest: String::new(),
            reason: reason.into(),
            peers_settled: false,
            created_ms: now,
            updated_ms: now,
            quarantined: false,
            split_detected_ms: 0,
            unknown_asked_by: None,
            recovered: false,
        }
    }

    /// The outcome this node voted for: what every node must agree on to commit.
    pub fn outcome(&self) -> Outcome {
        Outcome {
            key_id: self.key_id.clone(),
            kind: self.kind.clone(),
            new_epoch: self.new_epoch,
            new_pkp_digest: self.new_pkp_digest.clone(),
            round1_digest: self.round1_digest.clone(),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, RecordState::Committed | RecordState::Aborted)
    }
}

/// What two nodes must agree on before either commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub key_id: String,
    pub kind: String,
    pub new_epoch: u64,
    pub new_pkp_digest: String,
    pub round1_digest: String,
}

/// Whether a node may move its record for one ceremony from `from` to `to`. Re-writing the same
/// state is allowed (idempotent retries); leaving a terminal state never is.
pub fn transition_allowed(from: Option<RecordState>, to: RecordState) -> bool {
    use RecordState::*;
    matches!(
        (from, to),
        (None, Staged)
            | (None, Aborted)
            | (Some(Staged), Staged)
            | (Some(Staged), Committed)
            | (Some(Staged), Aborted)
            | (Some(Committed), Committed)
            | (Some(Aborted), Aborted)
    )
}

/// Subdirectory of the record directory holding the fence marks ([`CeremonyRecords::mark_fenced`]).
/// Its dot keeps it out of [`CeremonyRecords::load_all`].
pub const FENCED_DIR: &str = ".fenced";

/// The record directory. Callers serialize writes (the node holds one lock over its records);
/// this type only does the durable IO and the transition check.
pub struct CeremonyRecords {
    dir: PathBuf,
}

impl CeremonyRecords {
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, ceremony_id: &str) -> Result<PathBuf> {
        validate_ceremony_id(ceremony_id)?;
        Ok(self.dir.join(format!("{ceremony_id}.json")))
    }

    /// Every record on disk. A file that does not parse is reported (it is a lost vote — an
    /// operator must look) and skipped, never deleted.
    pub fn load_all(&self) -> Result<Vec<CeremonyRecord>> {
        if !self.dir.try_exists()? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            let parsed = std::fs::read(entry.path())
                .map_err(DaemonError::from)
                .and_then(|b| serde_json::from_slice::<CeremonyRecord>(&b).map_err(DaemonError::from));
            match parsed {
                Ok(r) if format!("{}.json", r.ceremony_id) == name => out.push(r),
                Ok(r) => tracing::error!(
                    file = %name,
                    ceremony_id = %r.ceremony_id,
                    "ceremony record file name does not match its ceremony id — ignored; an \
                     operator must inspect it"
                ),
                Err(e) => tracing::error!(
                    file = %name,
                    error = %e,
                    "unreadable ceremony record — this node's vote for that ceremony is lost; an \
                     operator must inspect it (docs/ceremonies.md)"
                ),
            }
        }
        out.sort_by(|a, b| a.ceremony_id.cmp(&b.ceremony_id));
        Ok(out)
    }

    /// Durably record `rec`, replacing `prev` (this node's current record for the ceremony, or
    /// `None` for its first vote). The first vote is create-once: if a record appeared on disk
    /// meanwhile, this refuses instead of overwriting it.
    pub fn write(&self, prev: Option<&CeremonyRecord>, rec: &CeremonyRecord) -> Result<()> {
        if !transition_allowed(prev.map(|p| p.state), rec.state) {
            return Err(DaemonError::Disagreement(format!(
                "ceremony {}: refusing to change this node's recorded vote from {} to {}",
                rec.ceremony_id,
                prev.map(|p| p.state.as_str()).unwrap_or("none"),
                rec.state.as_str()
            )));
        }
        if let Some(p) = prev {
            if p.ceremony_id != rec.ceremony_id {
                return Err(DaemonError::Config("ceremony record id mismatch".into()));
            }
        }
        let path = self.path(&rec.ceremony_id)?;
        crate::keystore::ensure_private_dir(&self.dir)?;
        let tmp = self.dir.join(format!(".{}-{}.tmp", rec.ceremony_id, uuid::Uuid::new_v4()));
        {
            let mut f = private_file(&tmp, true)?;
            f.write_all(&serde_json::to_vec_pretty(rec)?)?;
            f.sync_all()?;
        }
        let moved = if prev.is_none() {
            match rename_noreplace(&tmp, &path) {
                Ok(NoReplace::Moved) => Ok(()),
                Ok(NoReplace::Exists) => Err(DaemonError::Disagreement(format!(
                    "ceremony {}: a record already exists on disk — refusing to overwrite a vote",
                    rec.ceremony_id
                ))),
                Ok(NoReplace::Unsupported) => match std::fs::hard_link(&tmp, &path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        Err(DaemonError::Disagreement(format!(
                            "ceremony {}: a record already exists on disk — refusing to overwrite \
                             a vote",
                            rec.ceremony_id
                        )))
                    }
                    Err(e) => Err(e.into()),
                },
                Err(e) => Err(e.into()),
            }
        } else {
            std::fs::rename(&tmp, &path).map_err(DaemonError::from)
        };
        let _ = std::fs::remove_file(&tmp);
        moved?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// The one exception to "a terminal vote never changes" (audit F3): the operator's
    /// `ceremony recover-commit` turns a quarantined ABORTED record into COMMITTED, after a peer
    /// proved the outcome committed. Anything else is refused.
    pub fn write_recovery(&self, prev: &CeremonyRecord, rec: &CeremonyRecord) -> Result<()> {
        if !(prev.state == RecordState::Aborted
            && prev.quarantined
            && rec.state == RecordState::Committed
            && rec.recovered
            && prev.ceremony_id == rec.ceremony_id
            && prev.outcome() == rec.outcome())
        {
            return Err(DaemonError::Disagreement(format!(
                "ceremony {}: recovery only turns a quarantined ABORTED vote into COMMITTED for the same outcome",
                rec.ceremony_id
            )));
        }
        let path = self.path(&rec.ceremony_id)?;
        let tmp = self.dir.join(format!(".{}-{}.tmp", rec.ceremony_id, uuid::Uuid::new_v4()));
        {
            let mut f = private_file(&tmp, true)?;
            f.write_all(&serde_json::to_vec_pretty(rec)?)?;
            f.sync_all()?;
        }
        let moved = std::fs::rename(&tmp, &path);
        let _ = std::fs::remove_file(&tmp);
        moved?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Whether a record file exists for `ceremony_id`, parsed or not (the startup repair must not
    /// mistake an unreadable vote for no vote — audit F4).
    pub fn file_exists(&self, ceremony_id: &str) -> Result<bool> {
        Ok(self.path(ceremony_id)?.try_exists()?)
    }

    fn fenced_dir(&self) -> PathBuf {
        self.dir.join(FENCED_DIR)
    }

    /// Durably mark `ceremony_id` as fenced on this node, test-and-set: `false` when it already
    /// was. Existence is the mark (a create-new file, fsynced with its directory); the content —
    /// key id, leader, time — is for operators. Survives a restart, unlike the in-memory guard.
    pub fn mark_fenced(&self, ceremony_id: &str, key_id: &str, leader: Option<&str>) -> Result<bool> {
        validate_ceremony_id(ceremony_id)?;
        let dir = self.fenced_dir();
        crate::keystore::ensure_private_dir(&self.dir)?;
        crate::keystore::ensure_private_dir(&dir)?;
        let mut f = match private_file(&dir.join(ceremony_id), true) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let mark = serde_json::json!({
            "ceremony_id": ceremony_id,
            "key_id": key_id,
            "leader": leader.unwrap_or("self"),
            "fenced_ms": now_ms(),
        });
        f.write_all(&serde_json::to_vec(&mark)?)?;
        f.sync_all()?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(true)
    }

    /// Delete fence marks older than `older_than` (by file time). Returns how many.
    pub fn prune_fenced(&self, older_than: std::time::Duration) -> Result<usize> {
        let dir = self.fenced_dir();
        if !dir.try_exists()? {
            return Ok(0);
        }
        let mut n = 0;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let old = entry.metadata()?.modified()?.elapsed().is_ok_and(|age| age >= older_than);
            if old {
                std::fs::remove_file(entry.path())?;
                n += 1;
            }
        }
        if n > 0 {
            std::fs::File::open(&dir)?.sync_all()?;
        }
        Ok(n)
    }

    /// Delete a record (garbage collection of a settled, old ceremony only).
    pub fn remove(&self, ceremony_id: &str) -> Result<()> {
        let path = self.path(ceremony_id)?;
        if path.try_exists()? {
            std::fs::remove_file(&path)?;
            std::fs::File::open(&self.dir)?.sync_all()?;
        }
        Ok(())
    }
}

/// Where a ceremony stands on one node, as `Peer.CeremonyStatus` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The session is still in memory (before this node's part 3).
    InProgress,
    Staged,
    Committed,
    Aborted,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::InProgress => "in progress",
            Phase::Staged => "staged",
            Phase::Committed => "committed",
            Phase::Aborted => "aborted",
        }
    }
}

/// One node's answer about one ceremony: its phase and, for a yes-vote, the outcome voted for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusInfo {
    pub phase: Phase,
    pub outcome: Option<Outcome>,
}

impl StatusInfo {
    pub fn in_progress() -> Self {
        Self { phase: Phase::InProgress, outcome: None }
    }

    pub fn from_record(r: &CeremonyRecord) -> Self {
        match r.state {
            RecordState::Staged => Self { phase: Phase::Staged, outcome: Some(r.outcome()) },
            RecordState::Committed => Self { phase: Phase::Committed, outcome: Some(r.outcome()) },
            RecordState::Aborted => Self { phase: Phase::Aborted, outcome: None },
        }
    }

    /// How the resolver counts this answer.
    pub fn report(&self) -> PeerReport {
        match (self.phase, &self.outcome) {
            (Phase::InProgress, _) => PeerReport::InProgress,
            (Phase::Aborted, _) => PeerReport::Aborted,
            (Phase::Staged, Some(o)) => PeerReport::Staged(o.clone()),
            (Phase::Committed, Some(o)) => PeerReport::Committed(o.clone()),
            (p, None) => PeerReport::Unknown(format!("{} without an outcome", p.as_str())),
        }
    }
}

/// What a peer reports about a ceremony (the `CeremonyStatus` peer RPC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerReport {
    /// The peer still holds the ceremony session in memory (before its part 3).
    InProgress,
    Staged(Outcome),
    Committed(Outcome),
    Aborted,
    /// No answer, or an answer this node cannot interpret: not evidence of anything.
    Unknown(String),
}

/// The resolver's verdict for one STAGED ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Every roster node holds a durable yes-vote for this node's outcome.
    Commit,
    /// Direct evidence that the ceremony can never commit anywhere.
    Abort(String),
    /// Not decidable yet (a node is unreachable or still in progress); ask again later.
    Wait(String),
}

/// Decide a STAGED ceremony from what every other roster node reports (`reports`, by identifier;
/// this node's own vote is `local`). Pure, so the safety argument can be tested directly:
///
/// * Commit only if **every** other roster node reports STAGED or COMMITTED with exactly this
///   node's outcome — a node missing from `reports` counts as not yet known.
/// * Abort if any node reports ABORTED, or a yes-vote for a *different* outcome (divergence: no
///   outcome can then gather every vote, so committing is impossible for everyone).
/// * Otherwise wait.
pub fn decide(local: &CeremonyRecord, me: u16, reports: &BTreeMap<u16, PeerReport>) -> Decision {
    if local.state != RecordState::Staged {
        return Decision::Wait(format!("local record is {}, not staged", local.state.as_str()));
    }
    let mine = local.outcome();
    let mut waiting = Vec::new();
    for &id in local.roster.iter().filter(|&&id| id != me) {
        match reports.get(&id) {
            Some(PeerReport::Aborted) => {
                return Decision::Abort(format!("node {id} recorded ABORTED"));
            }
            Some(PeerReport::Staged(o)) | Some(PeerReport::Committed(o)) if *o != mine => {
                return Decision::Abort(format!(
                    "node {id} staged a different outcome (epoch {} pkp {}…, ours epoch {} pkp {}…)",
                    o.new_epoch,
                    short(&o.new_pkp_digest),
                    mine.new_epoch,
                    short(&mine.new_pkp_digest)
                ));
            }
            Some(PeerReport::Staged(_)) | Some(PeerReport::Committed(_)) => {}
            Some(PeerReport::InProgress) => waiting.push(format!("node {id} in progress")),
            Some(PeerReport::Unknown(why)) => waiting.push(format!("node {id}: {why}")),
            None => waiting.push(format!("node {id}: not asked")),
        }
    }
    if waiting.is_empty() {
        Decision::Commit
    } else {
        Decision::Wait(waiting.join("; "))
    }
}

/// Some other roster node reports a yes-vote (STAGED or COMMITTED) for exactly this node's outcome.
/// An abort while this holds is acted on only after the votes are gathered again (audit F3).
pub fn mixed_evidence(local: &CeremonyRecord, me: u16, reports: &BTreeMap<u16, PeerReport>) -> bool {
    let mine = local.outcome();
    local.roster.iter().filter(|&&id| id != me).any(|id| {
        matches!(reports.get(id), Some(PeerReport::Staged(o)) | Some(PeerReport::Committed(o)) if *o == mine)
    })
}

/// COMMITTED for this node's outcome and ABORTED, both reported for one ceremony: impossible with
/// crash faults (a node commits only after every yes-vote, and a yes-voter then never sees a
/// no-vote), so some cosigner equivocated (audit F3).
pub fn equivocation(local: &CeremonyRecord, me: u16, reports: &BTreeMap<u16, PeerReport>) -> bool {
    let mine = local.outcome();
    let others = || local.roster.iter().filter(move |&&id| id != me).filter_map(|id| reports.get(id));
    others().any(|r| matches!(r, PeerReport::Committed(o) if *o == mine))
        && others().any(|r| matches!(r, PeerReport::Aborted))
}

/// For a ceremony this node aborted: some peer reports it COMMITTED with this node's outcome — the
/// nodes resolved it differently (a split), and the quarantined share is what heals it.
pub fn split_evident(local: &CeremonyRecord, me: u16, reports: &BTreeMap<u16, PeerReport>) -> bool {
    let mine = local.outcome();
    local
        .roster
        .iter()
        .filter(|&&id| id != me)
        .any(|id| matches!(reports.get(id), Some(PeerReport::Committed(o)) if *o == mine))
}

/// For a ceremony this node aborted with its share quarantined: every other roster node reports a
/// terminal vote and none COMMITTED this node's outcome. An honest node that committed would say
/// so, and a terminal vote never changes, so no honest node can commit it any more — the share is
/// of no further use.
pub fn quarantine_droppable(local: &CeremonyRecord, me: u16, reports: &BTreeMap<u16, PeerReport>) -> bool {
    let mine = local.outcome();
    local.roster.iter().filter(|&&id| id != me).all(|id| match reports.get(id) {
        Some(PeerReport::Aborted) => true,
        Some(PeerReport::Committed(o)) => *o != mine,
        _ => false,
    })
}

fn short(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fence mark is test-and-set, durable across a reopen, invisible to `load_all`, and pruned
    /// by age only.
    #[test]
    fn fence_marks_are_set_once_survive_a_reopen_and_are_pruned_by_age() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CeremonyRecords::open(tmp.path().join("ceremonies"));
        assert!(store.mark_fenced("refresh-aa", "frost-ns", Some("cosigner1")).unwrap());
        assert!(!store.mark_fenced("refresh-aa", "frost-ns", None).unwrap());
        let reopened = CeremonyRecords::open(tmp.path().join("ceremonies"));
        assert!(!reopened.mark_fenced("refresh-aa", "frost-ns", Some("cosigner3")).unwrap());
        assert!(reopened.load_all().unwrap().is_empty(), "a mark is not a vote");
        assert_eq!(reopened.prune_fenced(std::time::Duration::from_secs(3600)).unwrap(), 0);
        assert_eq!(reopened.prune_fenced(std::time::Duration::ZERO).unwrap(), 1);
        assert!(reopened.mark_fenced("refresh-aa", "frost-ns", None).unwrap());
        assert!(reopened.mark_fenced("../x", "frost-ns", None).is_err(), "ids are validated");
    }

    fn staged(id: &str, roster: &[u16], pkp: &str) -> CeremonyRecord {
        CeremonyRecord {
            key_id: "k".into(),
            kind: "refresh".into(),
            state: RecordState::Staged,
            roster: roster.to_vec(),
            new_epoch: 2,
            new_pkp_digest: pkp.into(),
            round1_digest: "r1".into(),
            ..CeremonyRecord::aborted(id, "")
        }
    }

    #[test]
    fn transitions_never_leave_a_terminal_state() {
        use RecordState::*;
        for to in [Staged, Committed, Aborted] {
            assert_eq!(transition_allowed(Some(Committed), to), to == Committed, "committed -> {to:?}");
            assert_eq!(transition_allowed(Some(Aborted), to), to == Aborted, "aborted -> {to:?}");
        }
        assert!(transition_allowed(None, Staged));
        assert!(transition_allowed(None, Aborted));
        assert!(!transition_allowed(None, Committed), "commit requires a staged yes-vote first");
        assert!(transition_allowed(Some(Staged), Committed));
        assert!(transition_allowed(Some(Staged), Aborted));
    }

    #[test]
    fn records_are_create_once_and_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CeremonyRecords::open(tmp.path().join(".ceremonies"));
        let rec = staged("refresh-1", &[1, 2, 3], "aa");
        store.write(None, &rec).unwrap();
        // A second "first vote" for the same ceremony is refused, never an overwrite.
        let other = CeremonyRecord::aborted("refresh-1", "late");
        assert!(store.write(None, &other).is_err());
        assert_eq!(store.load_all().unwrap(), vec![rec.clone()]);
        // Staged -> committed is a replace; committed -> aborted is refused.
        let committed = CeremonyRecord { state: RecordState::Committed, ..rec.clone() };
        store.write(Some(&rec), &committed).unwrap();
        let aborted = CeremonyRecord { state: RecordState::Aborted, ..rec.clone() };
        assert!(store.write(Some(&committed), &aborted).is_err());
        assert_eq!(store.load_all().unwrap(), vec![committed]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        assert!(store.write(None, &CeremonyRecord::aborted("../evil", "x")).is_err());
    }

    #[test]
    fn an_unparsable_record_is_skipped_not_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".ceremonies");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("dkg-x.json"), b"{ not json").unwrap();
        let store = CeremonyRecords::open(&dir);
        assert!(store.load_all().unwrap().is_empty());
        assert!(dir.join("dkg-x.json").exists());
    }

    #[test]
    fn decide_commits_only_on_every_matching_yes_vote() {
        let local = staged("c", &[1, 2, 3], "aa");
        let yes = PeerReport::Staged(local.outcome());
        let committed = PeerReport::Committed(local.outcome());
        let all = |r2: PeerReport, r3: PeerReport| BTreeMap::from([(2u16, r2), (3u16, r3)]);

        assert_eq!(decide(&local, 1, &all(yes.clone(), committed.clone())), Decision::Commit);
        // One node not yet known, in progress, or unreachable: wait — never commit, never abort.
        assert!(matches!(decide(&local, 1, &BTreeMap::from([(2, yes.clone())])), Decision::Wait(_)));
        assert!(matches!(decide(&local, 1, &all(yes.clone(), PeerReport::InProgress)), Decision::Wait(_)));
        assert!(matches!(
            decide(&local, 1, &all(yes.clone(), PeerReport::Unknown("timeout".into()))),
            Decision::Wait(_)
        ));
        // Evidence: any no-vote aborts, even with another node still unknown.
        assert!(matches!(
            decide(&local, 1, &all(PeerReport::Unknown("down".into()), PeerReport::Aborted)),
            Decision::Abort(_)
        ));
        // A yes-vote for another outcome (pkp, epoch, key or round-1 digest) is divergence.
        for tweak in 0..4 {
            let mut o = local.outcome();
            match tweak {
                0 => o.new_pkp_digest = "bb".into(),
                1 => o.new_epoch += 1,
                2 => o.key_id = "other".into(),
                _ => o.round1_digest = "r1x".into(),
            }
            assert!(
                matches!(decide(&local, 1, &all(yes.clone(), PeerReport::Committed(o))), Decision::Abort(_)),
                "tweak {tweak}"
            );
        }
        // A record that is not STAGED is never decided again.
        let done = CeremonyRecord { state: RecordState::Committed, ..local };
        assert!(matches!(decide(&done, 1, &all(yes, committed)), Decision::Wait(_)));
    }

    #[test]
    fn split_predicates() {
        let local = staged("c", &[1, 2, 3], "aa");
        let yes = PeerReport::Staged(local.outcome());
        let committed = PeerReport::Committed(local.outcome());
        let mut other = local.outcome();
        other.new_pkp_digest = "bb".into();
        let all = |r2: PeerReport, r3: PeerReport| BTreeMap::from([(2u16, r2), (3u16, r3)]);

        // A crash: one node no, the other yes — mixed, not (yet) proof of anything.
        let crash = all(PeerReport::Aborted, yes.clone());
        assert!(mixed_evidence(&local, 1, &crash) && !equivocation(&local, 1, &crash));
        assert!(!quarantine_droppable(&local, 1, &crash), "node 3 may still be resolving");
        // COMMITTED and ABORTED for one ceremony: equivocation, a split if this node aborted.
        let lie = all(PeerReport::Aborted, committed.clone());
        assert!(equivocation(&local, 1, &lie) && split_evident(&local, 1, &lie));
        assert!(!quarantine_droppable(&local, 1, &lie));
        // Every peer terminal, nobody committed this outcome: the quarantined share can go.
        assert!(quarantine_droppable(&local, 1, &all(PeerReport::Aborted, PeerReport::Aborted)));
        assert!(quarantine_droppable(&local, 1, &all(PeerReport::Aborted, PeerReport::Committed(other.clone()))));
        assert!(!quarantine_droppable(&local, 1, &all(PeerReport::Aborted, PeerReport::Unknown("down".into()))));
        assert!(!mixed_evidence(&local, 1, &all(PeerReport::Aborted, PeerReport::Staged(other))));
    }

    #[test]
    fn only_a_quarantined_abort_can_be_recovered_to_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CeremonyRecords::open(tmp.path().join(".ceremonies"));
        let rec = staged("refresh-9", &[1, 2, 3], "aa");
        store.write(None, &rec).unwrap();
        let aborted = CeremonyRecord { state: RecordState::Aborted, ..rec.clone() };
        store.write(Some(&rec), &aborted).unwrap();
        let committed = CeremonyRecord { state: RecordState::Committed, recovered: true, ..rec.clone() };
        assert!(store.write_recovery(&aborted, &committed).is_err(), "not quarantined");
        let quarantined = CeremonyRecord { quarantined: true, ..aborted.clone() };
        store.write(Some(&aborted), &quarantined).unwrap();
        let mut wrong = committed.clone();
        wrong.new_pkp_digest = "bb".into();
        assert!(store.write_recovery(&quarantined, &wrong).is_err(), "another outcome");
        store.write_recovery(&quarantined, &committed).unwrap();
        assert_eq!(store.load_all().unwrap(), vec![committed]);
    }
}

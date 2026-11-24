// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! The per-key minimum interval between refreshes (`signing_policy.refresh_min_interval_secs`).
//!
//! Every refresh moves every node to a new epoch, and a node's backup of an older epoch no longer
//! restores that node (`restore` refuses to roll a share back). A client that could refresh a key
//! continuously (a stolen refresher certificate, or the driver certificate while
//! `signer_may_refresh` is on) would leave the nodes' backups on different epochs, so a later loss
//! of nodes could not be recovered. Every node therefore refuses to take part in a refresh of a key
//! it took part in less than the interval ago. The check runs on each node at the fence and at
//! part 1 (and at the leader before it contacts anyone), so a leader — a compromised cosigner
//! included — cannot get around it: a refresh needs every roster node.
//!
//! **What counts** is read from this node's own ceremony records, the durable state the two-phase
//! commit already keeps (so the limit survives a restart and there is no second source of truth):
//! a refresh of the key that this node **staged** — committed, or aborted after it staged. A
//! refresh that failed before staging (a refused fence, a failed part 1 or 2, a leader that died)
//! changes no share and does not count, so starting and abandoning refreshes cannot block the next
//! legitimate one. A late abort does count: it leaves a staged (quarantined) share and a record on
//! every node, and only a node that took part can cause one after staging — it could block every
//! refresh anyway by refusing — so it gains nothing, while not counting it would let a compromised
//! leader loop refreshes for free. DKG records never count.
//!
//! **From when:** the moment the refresh resolved on this node (`resolved_ms`): its commit, since
//! no backup of the new epoch can exist before it, or its abort, since until then the staged
//! ceremony blocked every other one anyway. Never the staging time: a commit delayed past the
//! interval would otherwise let the next refresh start right after it, before any backup.
//!
//! **The operator's way past it** is per-node config, `signing_policy.refresh_interval_waived_at`:
//! one refresh of each key is let through after that time, then the interval applies from that
//! refresh again; it lapses 24 h after its time. No client certificate can set it.

use crate::ceremony_record::{CeremonyRecord, RecordState};

/// Milliseconds in a second.
const MILLIS_PER_SECOND: u64 = 1000;

/// A refresh of a key this node took part in that counts against the interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountedRefresh {
    pub ceremony_id: String,
    /// When it resolved on this node (Unix ms): see [`at_ms`].
    pub at_ms: u64,
    pub state: RecordState,
}

/// The decision for a refresh of one key at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No counted refresh within the interval (or the interval is off).
    Allowed,
    /// Within the interval, but let through by the operator's waiver (`waived_at_ms`).
    Waived {
        last: CountedRefresh,
        waived_at_ms: u64,
    },
    /// Within the interval: refused until `next_ms`.
    TooSoon { last: CountedRefresh, next_ms: u64 },
}

/// When a counted refresh happened on this node: when it **resolved** here — committed (the new
/// epoch went live, so no backup of it can exist before this moment) or aborted after staging. A
/// commit delayed past the interval (a peer down, the resolver late) therefore still holds the next
/// refresh off for a full interval after the commit. A record written before 0.5.0 has no
/// `resolved_ms`: its `updated_ms` is used, which is the commit or a later write, never earlier. A
/// STAGED record (refused anyway while it is pending) counts from its last write.
fn at_ms(rec: &CeremonyRecord) -> u64 {
    match rec.state {
        RecordState::Committed | RecordState::Aborted if rec.resolved_ms != 0 => rec.resolved_ms,
        _ => rec.updated_ms.max(rec.created_ms),
    }
}

/// Whether `rec` counts against `key_id`'s interval: a refresh of the key this node staged —
/// STAGED, COMMITTED, or ABORTED after staging (its outcome digest is set). An ABORTED record
/// written for a ceremony that never staged here names no outcome.
pub fn counts(rec: &CeremonyRecord, key_id: &str) -> bool {
    rec.key_id == key_id
        && rec.kind == "refresh"
        && match rec.state {
            RecordState::Staged | RecordState::Committed => true,
            RecordState::Aborted => !rec.new_pkp_digest.is_empty(),
        }
}

/// The newest refresh of `key_id` among `records` that counts against the interval.
pub fn last_counted<'a>(
    records: impl IntoIterator<Item = &'a CeremonyRecord>,
    key_id: &str,
) -> Option<CountedRefresh> {
    records
        .into_iter()
        .filter(|r| counts(r, key_id))
        .max_by_key(|r| at_ms(r))
        .map(|r| CountedRefresh {
            ceremony_id: r.ceremony_id.clone(),
            at_ms: at_ms(r),
            state: r.state,
        })
}

/// Refreshes of `key_id` among `records` that committed at or after `since_ms`.
pub fn committed_since<'a>(
    records: impl IntoIterator<Item = &'a CeremonyRecord>,
    key_id: &str,
    since_ms: u64,
) -> usize {
    records
        .into_iter()
        .filter(|r| {
            r.key_id == key_id
                && r.kind == "refresh"
                && r.state == RecordState::Committed
                && at_ms(r) >= since_ms
        })
        .count()
}

/// The verdict for a refresh at `now_ms`, given the last counted refresh, the interval and the
/// operator's waiver time.
///
/// A clock that went back puts `now_ms` before the last refresh: refused until it catches up. The
/// waiver applies from its time (`now_ms >= waived_at_ms`, so a refresh it let through stages
/// after it and the next one is held to the interval again) for
/// [`crate::config::REFRESH_WAIVER_LIFETIME_MS`], and only while no counted refresh is newer than it.
pub fn verdict(
    last: Option<&CountedRefresh>,
    now_ms: u64,
    interval_secs: u64,
    waived_at_ms: Option<u64>,
) -> Verdict {
    let Some(last) = last else {
        return Verdict::Allowed;
    };
    if interval_secs == 0 {
        return Verdict::Allowed;
    }
    let next_ms = last
        .at_ms
        .saturating_add(interval_secs.saturating_mul(MILLIS_PER_SECOND));
    if now_ms >= next_ms {
        return Verdict::Allowed;
    }
    if let Some(w) = waived_at_ms {
        let live =
            now_ms >= w && now_ms < w.saturating_add(crate::config::REFRESH_WAIVER_LIFETIME_MS);
        if live && last.at_ms < w {
            return Verdict::Waived {
                last: last.clone(),
                waived_at_ms: w,
            };
        }
    }
    Verdict::TooSoon {
        last: last.clone(),
        next_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = 3600 * 1000;
    const DAY: u64 = 24 * H;
    const T0: u64 = 1_800_000_000_000;
    const INTERVAL: u64 = crate::config::DEFAULT_REFRESH_MIN_INTERVAL_SECS;

    fn rec(
        id: &str,
        key: &str,
        kind: &str,
        state: RecordState,
        staged: bool,
        at: u64,
    ) -> CeremonyRecord {
        CeremonyRecord {
            ceremony_id: id.into(),
            state,
            key_id: key.into(),
            kind: kind.into(),
            roster: vec![1, 2, 3],
            old_epoch: 1,
            old_pkp_digest: "aa".into(),
            new_epoch: 2,
            new_pkp_digest: if staged { "bb".into() } else { String::new() },
            group_key: "cc".into(),
            round1_digest: "dd".into(),
            reason: String::new(),
            peers_settled: true,
            // Staged a day before it resolved; settled an hour after.
            created_ms: at - DAY,
            updated_ms: at + H,
            resolved_ms: if state == RecordState::Staged { 0 } else { at },
            quarantined: false,
            split_detected_ms: 0,
            unknown_asked_by: None,
            recovered: false,
        }
    }

    fn last(records: &[CeremonyRecord]) -> Option<CountedRefresh> {
        last_counted(records, "k")
    }

    #[test]
    fn committed_and_late_aborted_refreshes_count_early_failures_and_dkgs_do_not() {
        use RecordState::*;
        let records = vec![
            rec("dkg-1", "k", "dkg", Committed, true, T0 + 5 * DAY),
            rec(
                "refresh-early",
                "k",
                "refresh",
                Aborted,
                false,
                T0 + 6 * DAY,
            ),
            rec(
                "refresh-other-key",
                "other",
                "refresh",
                Committed,
                true,
                T0 + 7 * DAY,
            ),
            rec("refresh-1", "k", "refresh", Committed, true, T0),
        ];
        assert_eq!(last(&records).unwrap().ceremony_id, "refresh-1");
        let mut late = records.clone();
        late.push(rec(
            "refresh-late",
            "k",
            "refresh",
            Aborted,
            true,
            T0 + 2 * DAY,
        ));
        assert_eq!(last(&late).unwrap().ceremony_id, "refresh-late");
        // An ABORTED no-vote for an id this node never knew names no key at all.
        let unknown = CeremonyRecord::aborted("refresh-x", "unknown");
        assert!(!counts(&unknown, "k") && !counts(&unknown, ""));
        assert_eq!(last(&records[..3]), None);
    }

    #[test]
    fn the_weekly_schedule_passes_and_a_second_refresh_inside_the_interval_does_not() {
        let l = last(&[rec(
            "refresh-1",
            "k",
            "refresh",
            RecordState::Committed,
            true,
            T0,
        )]);
        // Weekly CronJob: the next Monday.
        assert_eq!(
            verdict(l.as_ref(), T0 + 7 * DAY, INTERVAL, None),
            Verdict::Allowed
        );
        // A missed run redone a few days later, and the boundary itself.
        assert_eq!(
            verdict(l.as_ref(), T0 + 3 * DAY, INTERVAL, None),
            Verdict::Allowed
        );
        assert!(
            matches!(verdict(l.as_ref(), T0 + 3 * DAY - 1, INTERVAL, None), Verdict::TooSoon { next_ms, .. } if next_ms == T0 + 3 * DAY)
        );
        // A loop: every attempt after the first is refused.
        for dt in [1, 60_000, H, DAY, 2 * DAY] {
            assert!(
                matches!(
                    verdict(l.as_ref(), T0 + dt, INTERVAL, None),
                    Verdict::TooSoon { .. }
                ),
                "{dt}"
            );
        }
        // No refresh yet, or the limit off.
        assert_eq!(verdict(None, T0, INTERVAL, None), Verdict::Allowed);
        assert_eq!(verdict(l.as_ref(), T0 + 1, 0, None), Verdict::Allowed);
        // A clock that went back is held, not let through.
        assert!(matches!(
            verdict(l.as_ref(), T0 - DAY, INTERVAL, None),
            Verdict::TooSoon { .. }
        ));
    }

    #[test]
    fn the_waiver_lets_one_refresh_through_after_its_time_then_the_interval_applies_again() {
        let first = rec(
            "refresh-1",
            "k",
            "refresh",
            RecordState::Committed,
            true,
            T0,
        );
        let w = T0 + 2 * H; // the operator decides two hours after the weekly refresh
        let l = last(std::slice::from_ref(&first));
        assert!(
            matches!(verdict(l.as_ref(), w + 60_000, INTERVAL, Some(w)), Verdict::Waived { waived_at_ms, .. } if waived_at_ms == w)
        );
        // Not before its time.
        assert!(matches!(
            verdict(l.as_ref(), w - 1, INTERVAL, Some(w)),
            Verdict::TooSoon { .. }
        ));
        // The waived refresh staged after the waiver time: the next one is held to the interval.
        let after = vec![
            first.clone(),
            rec(
                "refresh-2",
                "k",
                "refresh",
                RecordState::Committed,
                true,
                w + 61_000,
            ),
        ];
        let l2 = last(&after);
        assert!(matches!(
            verdict(l2.as_ref(), w + 120_000, INTERVAL, Some(w)),
            Verdict::TooSoon { .. }
        ));
        // A waived refresh that failed before staging leaves no record: the waiver still applies.
        let failed = vec![
            first.clone(),
            rec(
                "refresh-f",
                "k",
                "refresh",
                RecordState::Aborted,
                false,
                w + 61_000,
            ),
        ];
        assert!(matches!(
            verdict(last(&failed).as_ref(), w + 120_000, INTERVAL, Some(w)),
            Verdict::Waived { .. }
        ));
        // It lapses 24 h after its time.
        assert!(matches!(
            verdict(l.as_ref(), w + DAY, INTERVAL, Some(w)),
            Verdict::TooSoon { .. }
        ));
        // A waiver older than the last refresh waives nothing.
        assert!(matches!(
            verdict(l.as_ref(), T0 + H, INTERVAL, Some(T0 - H)),
            Verdict::TooSoon { .. }
        ));
    }

    /// A commit delayed past the interval counts from the commit, not from the staging; a record
    /// from before 0.5.0 (no `resolved_ms`) from its last write, which is never earlier.
    #[test]
    fn a_late_commit_counts_from_the_commit() {
        let staged_at = T0;
        let committed_at = T0 + 4 * DAY;
        let mut late = rec(
            "refresh-late",
            "k",
            "refresh",
            RecordState::Committed,
            true,
            committed_at,
        );
        late.created_ms = staged_at;
        let l = last(std::slice::from_ref(&late));
        assert!(
            matches!(verdict(l.as_ref(), committed_at + H, INTERVAL, None), Verdict::TooSoon { next_ms, .. } if next_ms == committed_at + 3 * DAY)
        );
        assert_eq!(
            verdict(l.as_ref(), committed_at + 3 * DAY, INTERVAL, None),
            Verdict::Allowed
        );
        let old = CeremonyRecord {
            resolved_ms: 0,
            updated_ms: committed_at + H,
            ..late
        };
        assert_eq!(
            last(std::slice::from_ref(&old)).unwrap().at_ms,
            committed_at + H
        );
    }

    #[test]
    fn committed_refreshes_in_a_window_are_counted_per_key() {
        use RecordState::*;
        let records = vec![
            rec("refresh-1", "k", "refresh", Committed, true, T0),
            rec("refresh-2", "k", "refresh", Committed, true, T0 + 3 * DAY),
            rec("refresh-3", "k", "refresh", Aborted, true, T0 + 4 * DAY),
            rec(
                "refresh-4",
                "other",
                "refresh",
                Committed,
                true,
                T0 + 4 * DAY,
            ),
        ];
        assert_eq!(committed_since(&records, "k", T0), 2);
        assert_eq!(committed_since(&records, "k", T0 + 1), 1);
        assert_eq!(committed_since(&records, "other", 0), 1);
    }
}

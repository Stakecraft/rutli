// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Stale-share detection (audit M1, H1): at startup and periodically, compare this node's sharing
//! of each FROST key with every peer's (`Peer.KeyEpoch`) and mark the key **stale** when this node
//! is behind. A stale node refuses sign round 1 and refuses to lead for the key
//! ([`crate::node::Node::set_stale`]), so a share revived by a restore from an old backup, a PVC
//! snapshot rollback or a backup mix-up is never used — the leaders route around it.
//!
//! Evidence, per key (see [`evaluate`]):
//!
//! * **Local proof.** This node's own COMMITTED ceremony record says the key reached a newer epoch
//!   than the share on disk: the share was rolled back under the node. Stale, whatever peers say.
//! * **Peers.** A peer holding the same group key at a newer committed epoch, when no peer holds
//!   this node's exact sharing and this node has no staged vote for that newer sharing. With
//!   two-phase ceremonies a newer committed epoch exists only if every node voted for it, so a
//!   node that is merely waiting to commit has the STAGED vote and is not stale (its resolver
//!   commits it); one that has neither the vote nor the sharing was rolled back. Requiring that no
//!   peer shares this node's sharing keeps a single lying peer from benching an honest node that
//!   another peer vouches for, and keeps an old sharing that still has a quorum (several nodes
//!   rolled back together) signing rather than benching all of them.
//!
//! A peer that holds exactly this node's sharing (same group key, epoch and PKP digest) vouches for
//! it **even when that peer is marked stale on peers' answers alone**. Otherwise one lying peer
//! plus one restart benches every honest node for good: while B restarts, A's only answer is the
//! liar's and A goes stale; when B returns it would discard A as stale, believe the liar and go
//! stale too, and from then on each honest node would discard the other. A peer whose mark comes
//! from its OWN committed ceremony record (`stale_by_own_record`) does not vouch: it proves that
//! the sharing it holds was superseded, and a node holding the same sharing is rolled back too. A
//! peer before 0.5.0 never sets that flag, so it vouches whenever it holds this node's sharing.
//!
//! A stale peer's claim of a NEWER epoch is no evidence that this node is behind, but it is doubt:
//! with no voucher it keeps the previous verdict instead of clearing a mark. A node that is simply
//! ahead of a lagging peer stays current. A peer that does not answer, holds no FROST share under
//! the id, or a different group key is not evidence either way. With no usable answer the previous
//! verdict is kept.
//!
//! What one lying peer can still do: while no peer that holds this node's sharing answers (the
//! others restarting, or a refresh still committing on them), it can bench this node; the stale
//! reason then says the claim is unconfirmed. The mark clears on the next pass that reaches such a
//! peer; a stale key is re-checked every [`RETRY_INTERVAL`] (minus a small jitter). A liar can
//! also echo a rolled-back node's old sharing and keep it from being marked stale; telling that
//! apart from an honest peer needs signed ceremony evidence. By design, t nodes restored to the
//! same old sharing without their ceremony records keep signing with it: t shares of any sharing
//! are the key.
//!
//! Recovery from a stale share is a restore of a current backup or a re-enrolment; the check
//! clears the mark by itself once the share is current again.

use std::sync::Arc;
use std::time::Duration;

use crate::node::{Node, StaleMark};
use crate::pb::KeyEpochReply;

/// How often a running node repeats the check once every key got a conclusive answer.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How soon to retry while some key had no usable peer answer (peers still starting) or is stale.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Up to this much is taken off each [`RETRY_INTERVAL`] at random, so nodes do not poll in step.
pub const RETRY_JITTER: Duration = Duration::from_secs(5);

/// The epoch check's verdict for one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// This node's sharing is current.
    Current,
    /// This node is behind: mark the key stale.
    Stale(StaleMark),
    /// A newer sharing is committed elsewhere and this node voted for it: its resolver commits it.
    PendingCommit { newer_epoch: u64 },
    /// No usable answer, or doubt without proof: keep the previous verdict.
    Inconclusive,
}

/// Decide one key. `mine` is this node's own `KeyEpoch` view (present, FROST), `committed_epoch`
/// the newest epoch its own COMMITTED ceremony records name for the key, `answers` the peers'
/// views by identifier.
pub fn evaluate(mine: &KeyEpochReply, committed_epoch: Option<u64>, answers: &[(u16, KeyEpochReply)]) -> Verdict {
    if let Some(e) = committed_epoch.filter(|&e| e > mine.epoch) {
        return Verdict::Stale(StaleMark {
            own_epoch: mine.epoch,
            newer_epoch: e,
            by_own_record: true,
            reason: format!(
                "this node's own ceremony record committed epoch {e}, but its share is at epoch {} — \
                 the share was rolled back (restored from an older backup?)",
                mine.epoch
            ),
        });
    }
    let same_key = |v: &KeyEpochReply| {
        v.present && v.origin != "hosted" && v.group_verifying_key == mine.group_verifying_key
    };
    let holds_mine = |v: &KeyEpochReply| same_key(v) && v.epoch == mine.epoch && v.pkp_digest == mine.pkp_digest;
    let proven_superseded = |v: &KeyEpochReply| v.stale && v.stale_by_own_record;
    // A peer marked stale on peers' answers still vouches for the sharing it holds; one whose own
    // ceremony record superseded that sharing does not.
    let shares_mine = answers.iter().any(|(_, v)| holds_mine(v) && !proven_superseded(v));
    let mine_superseded = answers.iter().any(|(_, v)| holds_mine(v) && proven_superseded(v));
    let newer: Vec<&(u16, KeyEpochReply)> =
        answers.iter().filter(|(_, v)| same_key(v) && !v.stale && v.epoch > mine.epoch).collect();
    if mine.staged {
        let voted = newer.iter().find(|(_, v)| {
            v.epoch == mine.staged_new_epoch && v.pkp_digest == mine.staged_new_pkp_digest
        });
        if let Some((_, v)) = voted {
            return Verdict::PendingCommit { newer_epoch: v.epoch };
        }
    }
    let Some((peer, newest)) = newer.iter().copied().max_by_key(|(_, v)| v.epoch) else {
        if shares_mine {
            return Verdict::Current;
        }
        // Nobody vouches. A stale peer's newer claim, or a peer whose own record superseded this
        // sharing, is doubt: keep the previous verdict. Ahead of lagging peers only: current.
        let doubt = mine_superseded || answers.iter().any(|(_, v)| same_key(v) && v.epoch > mine.epoch);
        let fresh = answers.iter().any(|(_, v)| same_key(v) && !v.stale);
        return if fresh && !doubt { Verdict::Current } else { Verdict::Inconclusive };
    };
    if shares_mine {
        tracing::warn!(
            peer,
            peer_epoch = newest.epoch,
            own_epoch = mine.epoch,
            "a peer reports a newer sharing this node never voted for, but another peer holds this \
             node's sharing — not marking it stale"
        );
        return Verdict::Current;
    }
    let confirmation = if newer.len() == 1 && !mine_superseded {
        "Only that one cosigner claims a newer epoch, so the claim is unconfirmed: a cosigner that is \
         wrong or compromised can cause this while no cosigner holding this node's epoch answers. \
         Compare `rutli-cosigner verify-key` across the nodes before restoring anything; the mark \
         clears by itself on the next pass that reaches a cosigner holding this node's epoch."
    } else {
        "Several cosigners confirm a newer epoch, or a cosigner on this node's epoch was rolled back \
         under its own ceremony record: restored from an older backup?"
    };
    Verdict::Stale(StaleMark {
        own_epoch: mine.epoch,
        newer_epoch: newest.epoch,
        by_own_record: false,
        reason: format!(
            "cosigner {peer} holds epoch {} of the same group key, no cosigner that answered vouches for \
             this node's epoch {}, and this node never voted for the newer one. {confirmation}",
            newest.epoch, mine.epoch
        ),
    })
}

/// One pass over every FROST key on this node. Returns how many keys were inconclusive (no usable
/// peer answer) or stale, so the caller can retry sooner: a mark that one peer's unconfirmed claim
/// caused clears on the first retry that reaches a peer holding this node's sharing.
pub async fn check_all(node: &Arc<Node>) -> usize {
    let keys = match node.blocking(|n| n.frost_key_ids()).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "epoch check: cannot list this node's keys");
            return 1;
        }
    };
    let mut inconclusive = 0;
    for key_id in keys {
        match check_key(node, &key_id).await {
            Ok(Verdict::Inconclusive | Verdict::Stale(_)) => inconclusive += 1,
            Ok(_) => {}
            Err(e) => {
                inconclusive += 1;
                tracing::warn!(key_id, error = %e, "epoch check failed");
            }
        }
    }
    inconclusive
}

/// Check one key now and apply the verdict.
pub async fn check_key(node: &Arc<Node>, key_id: &str) -> crate::Result<Verdict> {
    let mine = {
        let k = key_id.to_owned();
        node.blocking(move |n| n.key_epoch(&k)).await?
    };
    if !mine.present || mine.origin == "hosted" {
        return Ok(Verdict::Current);
    }
    let committed = node.committed_epoch(key_id);
    let mut answers = Vec::new();
    for id in node.mesh_ids() {
        let Some(peer) = node.mesh_peer(id) else { continue };
        match peer.key_epoch(key_id).await {
            Ok(v) => answers.push((id, v)),
            Err(e) => tracing::debug!(key_id, peer = id, error = %e, "epoch check: peer did not answer"),
        }
    }
    let verdict = evaluate(&mine, committed, &answers);
    match &verdict {
        Verdict::Stale(mark) => node.set_stale(key_id, Some(mark.clone())),
        Verdict::Current => node.set_stale(key_id, None),
        Verdict::PendingCommit { newer_epoch } => {
            tracing::info!(
                key_id,
                own_epoch = mine.epoch,
                newer_epoch,
                "a peer already committed a ceremony this node has staged — resolving"
            );
            node.set_stale(key_id, None);
            let _ = crate::ceremony::resolve(node, &mine.staged_ceremony_id).await;
        }
        Verdict::Inconclusive => {}
    }
    Ok(verdict)
}

/// [`RETRY_INTERVAL`] minus a random part of [`RETRY_JITTER`].
fn retry_delay() -> Duration {
    let jitter_ms = rand::RngCore::next_u64(&mut rand::rngs::OsRng) % RETRY_JITTER.as_millis() as u64;
    RETRY_INTERVAL - Duration::from_millis(jitter_ms)
}

/// The background check: a pass now (startup), then every [`CHECK_INTERVAL`] — or every
/// [`RETRY_INTERVAL`] (minus a jitter) while some key had no usable peer answer or is stale.
/// Restarted after a panic ([`crate::supervise`]).
pub fn spawn(node: Arc<Node>) -> tokio::task::JoinHandle<()> {
    crate::supervise::spawn_supervised("epoch_check", node, |node| async move {
        loop {
            let inconclusive = check_all(&node).await;
            tokio::time::sleep(if inconclusive > 0 { retry_delay() } else { CHECK_INTERVAL }).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(epoch: u64, digest: u8) -> KeyEpochReply {
        KeyEpochReply {
            present: true,
            epoch,
            pkp_digest: vec![digest; 32],
            group_verifying_key: vec![1; 32],
            origin: "dkg".into(),
            ..Default::default()
        }
    }

    fn staged(mut v: KeyEpochReply, epoch: u64, digest: u8) -> KeyEpochReply {
        v.staged = true;
        v.staged_ceremony_id = "c".into();
        v.staged_new_epoch = epoch;
        v.staged_new_pkp_digest = vec![digest; 32];
        v
    }

    fn stale(mut v: KeyEpochReply, by_own_record: bool) -> KeyEpochReply {
        v.stale = true;
        v.stale_by_own_record = by_own_record;
        v.stale_reason = "test".into();
        v
    }

    fn is_stale(v: &Verdict) -> bool {
        matches!(v, Verdict::Stale(_))
    }

    fn unconfirmed(v: &Verdict) -> bool {
        matches!(v, Verdict::Stale(m) if m.reason.contains("unconfirmed"))
    }

    /// The 0.4.0 rule, kept verbatim for comparison: stale peers were dropped before anything else,
    /// and only the newest claim was compared with a staged vote.
    fn evaluate_040(mine: &KeyEpochReply, committed_epoch: Option<u64>, answers: &[(u16, KeyEpochReply)]) -> Verdict {
        if let Some(e) = committed_epoch.filter(|&e| e > mine.epoch) {
            return Verdict::Stale(StaleMark { own_epoch: mine.epoch, newer_epoch: e, by_own_record: true, reason: "record".into() });
        }
        let usable: Vec<&(u16, KeyEpochReply)> = answers
            .iter()
            .filter(|(_, v)| {
                v.present && v.origin != "hosted" && !v.stale && v.group_verifying_key == mine.group_verifying_key
            })
            .collect();
        if usable.is_empty() {
            return Verdict::Inconclusive;
        }
        let shares_mine = usable.iter().any(|(_, v)| v.epoch == mine.epoch && v.pkp_digest == mine.pkp_digest);
        let newest = usable.iter().filter(|(_, v)| v.epoch > mine.epoch).max_by_key(|(_, v)| v.epoch);
        let Some((_, newer)) = newest else { return Verdict::Current };
        if mine.staged && mine.staged_new_epoch == newer.epoch && mine.staged_new_pkp_digest == newer.pkp_digest {
            return Verdict::PendingCommit { newer_epoch: newer.epoch };
        }
        if shares_mine {
            return Verdict::Current;
        }
        Verdict::Stale(StaleMark { own_epoch: mine.epoch, newer_epoch: newer.epoch, by_own_record: false, reason: "peers".into() })
    }

    type Rule = fn(&KeyEpochReply, Option<u64>, &[(u16, KeyEpochReply)]) -> Verdict;

    /// A toy cluster for running passes of the check in order. Node `i` holds `shares[i]` and the
    /// committed record `records[i]`; `marks[i]` is its stale mark (`Some(by_own_record)`). A node
    /// on 0.4.0 (`old[i]`) runs [`evaluate_040`] and never sets `stale_by_own_record`. The liar
    /// answers `lie` whatever it is asked.
    struct Cluster {
        shares: Vec<KeyEpochReply>,
        records: Vec<Option<u64>>,
        marks: Vec<Option<bool>>,
        old: Vec<bool>,
        liar: Option<(usize, KeyEpochReply)>,
    }

    impl Cluster {
        fn new(n: usize, epoch: u64, digest: u8) -> Self {
            Cluster {
                shares: vec![view(epoch, digest); n],
                records: vec![None; n],
                marks: vec![None; n],
                old: vec![false; n],
                liar: None,
            }
        }

        fn reply(&self, i: usize) -> KeyEpochReply {
            if let Some((l, lie)) = &self.liar {
                if *l == i {
                    return lie.clone();
                }
            }
            let mut v = self.shares[i].clone();
            v.stale = self.marks[i].is_some();
            v.stale_by_own_record = self.marks[i] == Some(true) && !self.old[i];
            v
        }

        /// One pass of node `i` reaching the peers in `up`; applies the verdict as `check_key` does.
        fn pass(&mut self, i: usize, up: &[usize]) -> Verdict {
            let answers: Vec<(u16, KeyEpochReply)> =
                up.iter().filter(|&&p| p != i).map(|&p| (p as u16 + 1, self.reply(p))).collect();
            let rule: Rule = if self.old[i] { evaluate_040 } else { evaluate };
            let v = rule(&self.shares[i], self.records[i], &answers);
            match &v {
                Verdict::Stale(m) => self.marks[i] = Some(m.by_own_record),
                Verdict::Current | Verdict::PendingCommit { .. } => self.marks[i] = None,
                Verdict::Inconclusive => {}
            }
            v
        }

        fn benched(&self) -> Vec<bool> {
            self.marks.iter().map(Option::is_some).collect()
        }
    }

    const A: usize = 0;
    const B: usize = 1;
    const C: usize = 2;

    #[test]
    fn a_node_behind_every_peer_is_stale() {
        let v = evaluate(&view(2, 2), None, &[(2, view(3, 3)), (3, view(3, 3))]);
        assert!(matches!(v, Verdict::Stale(StaleMark { own_epoch: 2, newer_epoch: 3, by_own_record: false, .. })), "{v:?}");
        assert!(!unconfirmed(&v), "{v:?}");
        // Behind the one peer that answered: stale, and the reason says it is unconfirmed.
        assert!(unconfirmed(&evaluate(&view(2, 2), None, &[(3, view(3, 3))])));
    }

    #[test]
    fn a_peer_vouching_for_this_nodes_sharing_outweighs_one_claiming_a_newer_one() {
        assert_eq!(evaluate(&view(2, 2), None, &[(2, view(9, 9)), (3, view(2, 2))]), Verdict::Current);
    }

    #[test]
    fn a_node_waiting_to_commit_is_not_stale() {
        let mine = staged(view(2, 2), 3, 3);
        assert_eq!(evaluate(&mine, None, &[(2, view(3, 3))]), Verdict::PendingCommit { newer_epoch: 3 });
        // A staged vote for something else does not excuse it.
        let other = staged(view(2, 2), 3, 4);
        assert!(is_stale(&evaluate(&other, None, &[(2, view(3, 3))])));
    }

    #[test]
    fn its_own_commit_record_proves_a_rollback_without_any_peer() {
        let v = evaluate(&view(2, 2), Some(3), &[]);
        assert!(matches!(v, Verdict::Stale(StaleMark { by_own_record: true, .. })), "{v:?}");
        assert_eq!(evaluate(&view(3, 3), Some(3), &[]), Verdict::Inconclusive);
        // It wins over every voucher, live or stale.
        let vouchers = [(2, view(2, 2)), (3, stale(view(2, 2), false))];
        assert!(is_stale(&evaluate(&view(2, 2), Some(3), &vouchers)));
    }

    #[test]
    fn unusable_answers_are_no_evidence() {
        let mut other_key = view(5, 5);
        other_key.group_verifying_key = vec![2; 32];
        let mut hosted = view(5, 5);
        hosted.origin = "hosted".into();
        let absent = KeyEpochReply::default();
        let answers = [(1, other_key), (3, hosted), (4, absent)];
        assert_eq!(evaluate(&view(2, 2), None, &answers), Verdict::Inconclusive);
        assert_eq!(evaluate(&view(2, 2), None, &[(2, view(2, 2))]), Verdict::Current);
        // Ahead of lagging peers, or level with another sharing: current.
        assert_eq!(evaluate(&view(2, 2), None, &[(2, view(1, 1)), (3, view(2, 7))]), Verdict::Current);
    }

    #[test]
    fn one_liar_and_one_restart_no_longer_bench_both_honest_nodes() {
        // 2-of-3: A and B hold epoch 2, C claims epoch 3 of the same group key.
        let mut c = Cluster::new(3, 2, 2);
        c.liar = Some((C, view(3, 3)));
        // B restarts; A's pass sees only C. This window needs signed evidence to close.
        assert!(unconfirmed(&c.pass(A, &[C])));
        // B is back: A is marked stale on peers' answers but holds B's sharing, so B stays current.
        assert_eq!(c.pass(B, &[A, C]), Verdict::Current);
        // A's next pass (a retry, A is stale) sees B and clears.
        assert_eq!(c.pass(A, &[B, C]), Verdict::Current);
        assert_eq!(c.benched(), [false, false, false]);
        assert_eq!(c.pass(B, &[A, C]), Verdict::Current);
        assert_eq!(c.pass(A, &[B, C]), Verdict::Current);
    }

    #[test]
    fn under_0_4_0_one_liar_and_one_restart_benched_both_for_good() {
        let mut c = Cluster::new(3, 2, 2);
        c.liar = Some((C, view(3, 3)));
        c.old = vec![true; 3];
        c.pass(A, &[C]);
        c.pass(B, &[A, C]);
        for _ in 0..3 {
            c.pass(A, &[B, C]);
            c.pass(B, &[A, C]);
        }
        assert_eq!(c.benched(), [true, true, false]);
    }

    #[test]
    fn both_honest_nodes_already_marked_recover_with_or_without_the_liar() {
        for liar_up in [true, false] {
            let mut c = Cluster::new(3, 2, 2);
            c.liar = Some((C, view(3, 3)));
            c.marks = vec![Some(false), Some(false), None];
            let up: &[usize] = if liar_up { &[A, B, C] } else { &[A, B] };
            assert_eq!(c.pass(A, up), Verdict::Current, "liar up: {liar_up}");
            assert_eq!(c.pass(B, up), Verdict::Current, "liar up: {liar_up}");
            assert_eq!(c.benched(), [false, false, false]);
            // 0.4.0 stays stuck in the same state.
            c.marks = vec![Some(false), Some(false), None];
            c.old = vec![true; 3];
            c.pass(A, up);
            c.pass(B, up);
            assert_eq!(c.benched(), [true, true, false], "0.4.0, liar up: {liar_up}");
        }
    }

    #[test]
    fn a_fixed_node_next_to_a_0_4_0_node_recovers() {
        for old in [A, B] {
            let mut c = Cluster::new(3, 2, 2);
            c.liar = Some((C, view(3, 3)));
            c.old[old] = true;
            c.pass(A, &[C]); // B restarts
            c.pass(B, &[A, C]);
            c.pass(A, &[B, C]);
            c.pass(B, &[A, C]);
            assert_eq!(c.benched(), [false, false, false], "0.4.0 on node {old}");
        }
    }

    #[test]
    fn a_rolled_back_node_is_still_stale() {
        for n in [3, 5] {
            let all: Vec<usize> = (0..n).collect();
            let mut c = Cluster::new(n, 3, 3);
            c.shares[A] = view(2, 2);
            let v = c.pass(A, &all);
            assert!(matches!(&v, Verdict::Stale(m) if m.newer_epoch == 3) && !unconfirmed(&v), "n = {n}: {v:?}");
            // The others are not affected by it.
            assert_eq!(c.pass(B, &all), Verdict::Current, "n = {n}");
            // Every peer on the newer epoch marked stale (say, by a liar earlier): their claims are
            // no evidence, so nothing changes — the mark stays, and an unmarked node stays unmarked.
            for mark in c.marks.iter_mut().take(n).skip(1) {
                *mark = Some(false);
            }
            assert_eq!(c.pass(A, &all), Verdict::Inconclusive, "n = {n}");
            assert_eq!(c.marks[A], Some(false));
            c.marks[A] = None;
            assert_eq!(c.pass(A, &all), Verdict::Inconclusive, "n = {n}");
            assert_eq!(c.marks[A], None);
        }
    }

    #[test]
    fn a_co_holder_rolled_back_under_its_own_record_does_not_vouch() {
        // A refresh committed epoch 3 everywhere. B's share is restored to 2 but its record of 3
        // survives; A's share is restored to the same 2 and its record does not survive.
        for n in [3, 5] {
            let all: Vec<usize> = (0..n).collect();
            let mut c = Cluster::new(n, 3, 3);
            c.shares[A] = view(2, 2);
            c.shares[B] = view(2, 2);
            c.records[B] = Some(3);
            let v = c.pass(B, &all);
            assert!(matches!(v, Verdict::Stale(StaleMark { by_own_record: true, .. })), "n = {n}: {v:?}");
            let v = c.pass(A, &all);
            assert!(is_stale(&v) && !unconfirmed(&v), "n = {n}: {v:?}");
            // B stays stale on every pass, and so does A.
            c.pass(B, &all);
            assert!(is_stale(&c.pass(A, &all)), "n = {n}");
            // Mixed versions: a 0.4.0 B does not say why it is stale, so it still vouches for A.
            c.old[B] = true;
            c.marks[A] = None;
            assert_eq!(c.pass(A, &all), Verdict::Current, "n = {n}");
        }
    }

    #[test]
    fn two_nodes_rolled_back_together_without_records_keep_their_old_sharing() {
        // n = 3: A and B restored to epoch 2 with no record of 3, C at 3. Whichever checks first
        // alone goes stale; the other then still counts it, and both end up current (by design: t
        // shares of a sharing are the key). Under 0.4.0 the order decided and both stayed stale.
        for old in [false, true] {
            let mut c = Cluster::new(3, 2, 2);
            c.shares[C] = view(3, 3);
            c.old = vec![old; 3];
            assert!(is_stale(&c.pass(A, &[C])));
            c.pass(B, &[A, C]);
            c.pass(A, &[B, C]);
            let expect = if old { [true, true, false] } else { [false, false, false] };
            assert_eq!(c.benched(), expect, "0.4.0: {old}");
        }
    }

    #[test]
    fn a_staged_node_is_pending_even_when_a_liar_claims_a_later_epoch() {
        // 2-of-3, refresh to epoch 3: B committed, A staged 3 (holds 2), C claims 4.
        let mut c = Cluster::new(3, 2, 2);
        c.shares[A] = staged(view(2, 2), 3, 3);
        c.shares[B] = view(3, 3);
        c.liar = Some((C, view(4, 4)));
        assert_eq!(c.pass(A, &[B, C]), Verdict::PendingCommit { newer_epoch: 3 });
        assert!(is_stale(&evaluate_040(&c.shares[A], None, &[(2, view(3, 3)), (3, view(4, 4))])));
        // B, until A commits, has no peer on its sharing: the liar alone benches it.
        assert!(unconfirmed(&c.pass(B, &[A, C])));
        // A's resolver commits epoch 3; B's next pass sees it and clears.
        c.shares[A] = view(3, 3);
        assert_eq!(c.pass(B, &[A, C]), Verdict::Current);
        assert_eq!(c.pass(A, &[B, C]), Verdict::Current);
        assert_eq!(c.benched(), [false, false, false]);

        // n = 5: B and D committed 3, A and E staged 3, C claims 4.
        let mut c = Cluster::new(5, 2, 2);
        c.shares[A] = staged(view(2, 2), 3, 3);
        c.shares[4] = staged(view(2, 2), 3, 3);
        c.shares[B] = view(3, 3);
        c.shares[3] = view(3, 3);
        c.liar = Some((C, view(4, 4)));
        let all = [0, 1, 2, 3, 4];
        assert_eq!(c.pass(A, &all), Verdict::PendingCommit { newer_epoch: 3 });
        assert_eq!(c.pass(4, &all), Verdict::PendingCommit { newer_epoch: 3 });
        // B has D on its sharing.
        assert_eq!(c.pass(B, &all), Verdict::Current);
    }

    #[test]
    fn no_voucher_and_only_stale_newer_claims_keep_the_previous_verdict() {
        // This node at 2, no record; the peers at 3 are all marked stale; one live peer is older.
        let answers = [(2, stale(view(3, 3), false)), (3, stale(view(3, 3), false)), (4, view(1, 1))];
        assert_eq!(evaluate(&view(2, 2), None, &answers), Verdict::Inconclusive);
        // A peer on this sharing proven superseded by its own record is doubt too.
        assert_eq!(evaluate(&view(2, 2), None, &[(2, stale(view(2, 2), true)), (3, view(1, 1))]), Verdict::Inconclusive);
        // Simply ahead of a lagging peer: current.
        assert_eq!(evaluate(&view(2, 2), None, &[(4, view(1, 1))]), Verdict::Current);
        assert_eq!(evaluate(&view(2, 2), None, &[(3, stale(view(1, 1), true)), (4, view(1, 1))]), Verdict::Current);
        // A voucher still clears.
        assert_eq!(evaluate(&view(2, 2), None, &[(2, stale(view(3, 3), false)), (3, stale(view(2, 2), false))]), Verdict::Current);
    }

    #[test]
    fn an_alternating_liar_with_the_honest_peer_down_then_back() {
        // Honest A and B on epoch 2; B down; C alternates a newer epoch and an echo of A's.
        let mut c = Cluster::new(3, 2, 2);
        c.liar = Some((C, view(3, 3)));
        assert!(unconfirmed(&c.pass(A, &[C])));
        c.liar = Some((C, view(2, 2)));
        assert_eq!(c.pass(A, &[C]), Verdict::Current);
        c.liar = Some((C, view(3, 3)));
        assert!(is_stale(&c.pass(A, &[C])));
        // B is back: both current whatever C says.
        assert_eq!(c.pass(B, &[A, C]), Verdict::Current);
        assert_eq!(c.pass(A, &[B, C]), Verdict::Current);
        c.liar = Some((C, view(2, 2)));
        assert_eq!(c.pass(A, &[B, C]), Verdict::Current);
        assert_eq!(c.benched(), [false, false, false]);

        // A rolled-back R (epoch 2) next to honest H (3): with H down, the echo keeps R current (a
        // known limit); with H back, the newer claims of H and C bench it, and an echo clears it
        // again (the same limit: an echo cannot be told from an honest co-holder).
        let mut c = Cluster::new(3, 3, 3);
        c.shares[A] = view(2, 2);
        c.liar = Some((C, view(2, 2)));
        assert_eq!(c.pass(A, &[C]), Verdict::Current);
        c.liar = Some((C, view(3, 3)));
        assert!(is_stale(&c.pass(A, &[B, C])));
        c.liar = Some((C, view(2, 2)));
        assert_eq!(c.pass(A, &[B, C]), Verdict::Current);
    }

    #[test]
    fn a_liar_echoing_an_old_sharing_keeps_a_rolled_back_node_current() {
        // A known limit, the same before and after: an echo of this node's own sharing is
        // indistinguishable from an honest peer without signed ceremony evidence.
        for rule in [evaluate as Rule, evaluate_040] {
            assert_eq!(rule(&view(2, 2), None, &[(2, view(3, 3)), (3, view(2, 2))]), Verdict::Current);
            let n5 = [(2, view(3, 3)), (3, view(3, 3)), (4, view(3, 3)), (5, view(2, 2))];
            assert_eq!(rule(&view(2, 2), None, &n5), Verdict::Current);
            // The node's own commit record still catches it when the record survived the restore.
            assert!(is_stale(&rule(&view(2, 2), Some(3), &n5)));
        }
    }

    #[test]
    fn a_new_wording_of_the_same_mark_is_not_a_change() {
        let m = |own, newer, rec, reason: &str| StaleMark { own_epoch: own, newer_epoch: newer, by_own_record: rec, reason: reason.into() };
        assert!(m(2, 3, false, "one peer").same_state(&m(2, 3, false, "two peers")));
        assert!(!m(2, 3, false, "x").same_state(&m(2, 4, false, "x")));
        assert!(!m(2, 3, false, "x").same_state(&m(2, 3, true, "x")));
    }

    #[test]
    fn the_retry_delay_stays_within_its_jitter() {
        for _ in 0..100 {
            let d = retry_delay();
            assert!(d <= RETRY_INTERVAL && d > RETRY_INTERVAL - RETRY_JITTER, "{d:?}");
        }
    }
}

// Copyright 2026 StakeCraft
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
//! A peer that does not answer, holds no FROST share under the id, a different group key, or
//! reports itself stale is not evidence either way. With no usable answer the previous verdict is
//! kept. Recovery from a stale share is a restore of a current backup or a re-enrolment; the check
//! clears the mark by itself once the share is current again.

use std::sync::Arc;
use std::time::Duration;

use crate::node::{Node, StaleMark};
use crate::pb::KeyEpochReply;

/// How often a running node repeats the check once every key got a conclusive answer.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How soon to retry while some key had no usable peer answer (peers still starting).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// The epoch check's verdict for one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// This node's sharing is current.
    Current,
    /// This node is behind: mark the key stale.
    Stale(StaleMark),
    /// A newer sharing is committed elsewhere and this node voted for it: its resolver commits it.
    PendingCommit { newer_epoch: u64 },
    /// No usable answer: keep the previous verdict.
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
            reason: format!(
                "this node's own ceremony record committed epoch {e}, but its share is at epoch {} — \
                 the share was rolled back (restored from an older backup?)",
                mine.epoch
            ),
        });
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
    let Some((peer, newer)) = newest else { return Verdict::Current };
    if mine.staged && mine.staged_new_epoch == newer.epoch && mine.staged_new_pkp_digest == newer.pkp_digest {
        return Verdict::PendingCommit { newer_epoch: newer.epoch };
    }
    if shares_mine {
        tracing::warn!(
            peer,
            peer_epoch = newer.epoch,
            own_epoch = mine.epoch,
            "a peer reports a newer sharing this node never voted for, but another peer holds this \
             node's sharing — not marking it stale"
        );
        return Verdict::Current;
    }
    Verdict::Stale(StaleMark {
        own_epoch: mine.epoch,
        newer_epoch: newer.epoch,
        reason: format!(
            "cosigner {peer} holds epoch {} of the same group key and no cosigner holds this node's \
             epoch {}, which never voted for the newer one (restored from an older backup?)",
            newer.epoch, mine.epoch
        ),
    })
}

/// One pass over every FROST key on this node. Returns how many keys were inconclusive (no usable
/// peer answer), so the caller can retry sooner.
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
            Ok(Verdict::Inconclusive) => inconclusive += 1,
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

/// The background check: a pass now (startup), then every [`CHECK_INTERVAL`] — or every
/// [`RETRY_INTERVAL`] while some key had no usable peer answer.
pub fn spawn(node: Arc<Node>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let inconclusive = check_all(&node).await;
            tokio::time::sleep(if inconclusive > 0 { RETRY_INTERVAL } else { CHECK_INTERVAL }).await;
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

    #[test]
    fn a_node_behind_every_peer_is_stale() {
        let v = evaluate(&view(2, 2), None, &[(2, view(3, 3)), (3, view(3, 3))]);
        assert!(matches!(v, Verdict::Stale(StaleMark { own_epoch: 2, newer_epoch: 3, .. })), "{v:?}");
        // Behind the one peer that answered: still stale.
        assert!(matches!(evaluate(&view(2, 2), None, &[(3, view(3, 3))]), Verdict::Stale(_)));
    }

    #[test]
    fn a_peer_vouching_for_this_nodes_sharing_outweighs_one_claiming_a_newer_one() {
        assert_eq!(evaluate(&view(2, 2), None, &[(2, view(9, 9)), (3, view(2, 2))]), Verdict::Current);
    }

    #[test]
    fn a_node_waiting_to_commit_is_not_stale() {
        let mut mine = view(2, 2);
        mine.staged = true;
        mine.staged_ceremony_id = "c".into();
        mine.staged_new_epoch = 3;
        mine.staged_new_pkp_digest = vec![3; 32];
        assert_eq!(evaluate(&mine, None, &[(2, view(3, 3))]), Verdict::PendingCommit { newer_epoch: 3 });
        // A staged vote for something else does not excuse it.
        mine.staged_new_pkp_digest = vec![4; 32];
        assert!(matches!(evaluate(&mine, None, &[(2, view(3, 3))]), Verdict::Stale(_)));
    }

    #[test]
    fn its_own_commit_record_proves_a_rollback_without_any_peer() {
        assert!(matches!(evaluate(&view(2, 2), Some(3), &[]), Verdict::Stale(_)));
        assert_eq!(evaluate(&view(3, 3), Some(3), &[]), Verdict::Inconclusive);
    }

    #[test]
    fn unusable_answers_are_no_evidence() {
        let mut other_key = view(5, 5);
        other_key.group_verifying_key = vec![2; 32];
        let mut stale_peer = view(5, 5);
        stale_peer.stale = true;
        let mut hosted = view(5, 5);
        hosted.origin = "hosted".into();
        let absent = KeyEpochReply::default();
        let answers = [(1, other_key), (2, stale_peer), (3, hosted), (4, absent)];
        assert_eq!(evaluate(&view(2, 2), None, &answers), Verdict::Inconclusive);
        assert_eq!(evaluate(&view(2, 2), None, &[(2, view(2, 2))]), Verdict::Current);
        // Older or equal peers never make this node stale.
        assert_eq!(evaluate(&view(2, 2), None, &[(2, view(1, 1)), (3, view(2, 7))]), Verdict::Current);
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The networked half of two-phase ceremonies, run by every node for itself: the resolver that
//! commits or aborts a STAGED ceremony from its peers' votes (asked directly over the mesh, never
//! through the leader), the operator break-glass for a permanently lost node, and the legacy
//! partial-key discard. The vote rules are [`crate::ceremony_record::decide`].

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::ceremony_record::{decide, CeremonyRecord, Decision, PeerReport, RecordState, StatusInfo};
use crate::node::Node;
use crate::{DaemonError, Result};

/// How often a node retries its STAGED ceremonies (and settles finished ones).
pub const RESOLVER_INTERVAL: Duration = Duration::from_secs(30);

/// How long a settled ceremony record is kept.
pub const RECORD_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);

/// Run `fut` as its own task and await it: a caller that stops waiting (a client deadline, a
/// dropped RPC, a killed CronJob pod) cannot cut it in half. A panic stays a panic.
pub async fn detach<T, F>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(result) => result,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(DaemonError::Io(std::io::Error::other(format!("ceremony task did not run: {e}")))),
    }
}

/// Every other roster node's answer about `rec`'s ceremony, asked directly. Nodes in `skip` are
/// not asked. A node that cannot be asked reports [`PeerReport::Unknown`].
async fn gather(node: &Arc<Node>, rec: &CeremonyRecord, skip: &[u16]) -> Result<BTreeMap<u16, PeerReport>> {
    let me = node.index()?;
    let mut reports = BTreeMap::new();
    for &id in rec.roster.iter().filter(|&&id| id != me && !skip.contains(&id)) {
        let report = match node.mesh_peer(id) {
            None => PeerReport::Unknown("not in this node's mesh".into()),
            Some(peer) => match peer.ceremony_status(&rec.ceremony_id).await {
                Ok(info) => info.report(),
                Err(e) => PeerReport::Unknown(e.to_string()),
            },
        };
        reports.insert(id, report);
    }
    Ok(reports)
}

/// Resolve ceremony `ceremony_id` on `node` now, if it is STAGED here: ask every roster node,
/// [`decide`], apply. Anything else is answered as [`Node::ceremony_status`] would (so asking about
/// a ceremony this node never joined records its no-vote). Never acts on the caller's word.
pub async fn resolve(node: &Arc<Node>, ceremony_id: &str) -> Result<StatusInfo> {
    let rec = match node.ceremony_record(ceremony_id) {
        Some(r) if r.state == RecordState::Staged => r,
        Some(r) => return Ok(StatusInfo::from_record(&r)),
        None => {
            let id = ceremony_id.to_owned();
            return node.blocking(move |n| n.ceremony_status(&id)).await;
        }
    };
    let reports = gather(node, &rec, &[]).await?;
    let decision = decide(&rec, node.index()?, &reports);
    if let Decision::Wait(why) = &decision {
        tracing::debug!(ceremony_id, key_id = %rec.key_id, waiting = %why, "staged ceremony not decidable yet");
        return Ok(StatusInfo::from_record(&rec));
    }
    let id = ceremony_id.to_owned();
    node.blocking(move |n| n.apply_resolution(&id, &decision)).await
}

/// One resolver pass: every STAGED ceremony, then settling and garbage-collecting finished ones.
/// Returns how many STAGED ceremonies remain.
pub async fn resolve_pending(node: &Arc<Node>) -> usize {
    for rec in node.staged_records() {
        if let Err(e) = resolve(node, &rec.ceremony_id).await {
            tracing::warn!(ceremony_id = %rec.ceremony_id, key_id = %rec.key_id, error = %e, "ceremony resolution failed");
        }
    }
    let staged = node.staged_records();
    metrics::gauge!(crate::metrics::CEREMONIES_STAGED).set(staged.len() as f64);
    for rec in &staged {
        tracing::warn!(
            ceremony_id = %rec.ceremony_id,
            key_id = %rec.key_id,
            "ceremony still STAGED: waiting for every roster node to answer (signing continues on \
             the old share); a permanently lost node needs `rutli-cosigner ceremony resolve \
             --assume-lost` (docs/ceremonies.md)"
        );
    }
    for rec in node.unsettled_records() {
        let Ok(reports) = gather(node, &rec, &[]).await else { continue };
        let settled = rec
            .roster
            .iter()
            .filter(|&&id| node.index().map(|me| me != id).unwrap_or(true))
            .all(|id| matches!(reports.get(id), Some(PeerReport::Committed(_)) | Some(PeerReport::Aborted)));
        if settled {
            if let Err(e) = node.mark_settled(&rec.ceremony_id) {
                tracing::warn!(ceremony_id = %rec.ceremony_id, error = %e, "could not mark a ceremony settled");
            }
        }
    }
    match node.gc_records(RECORD_RETENTION) {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "garbage-collected settled ceremony records"),
        Err(e) => tracing::warn!(error = %e, "ceremony record garbage collection failed"),
    }
    staged.len()
}

/// The background resolver: a pass now (startup) and every `interval`.
pub fn spawn_resolver(node: Arc<Node>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            resolve_pending(&node).await;
            tokio::time::sleep(interval).await;
        }
    })
}

/// Break-glass for a STAGED ceremony whose resolution waits on nodes that are **permanently**
/// gone (`lost`): commit if any reachable node COMMITTED it (that node saw every yes-vote, the lost
/// ones included); otherwise abort — safe only because nobody reachable committed and the lost
/// nodes' shares are gone with them. Every roster node not in `lost` must answer. A "lost" node
/// that comes back after this holds a share nobody else can combine with; never use it for a node
/// that may return.
pub async fn resolve_assume_lost(node: &Arc<Node>, ceremony_id: &str, lost: &[u16]) -> Result<StatusInfo> {
    let me = node.index()?;
    if lost.contains(&me) {
        return Err(DaemonError::CeremonyRefused("this node cannot assume itself lost".into()));
    }
    let rec = node
        .ceremony_record(ceremony_id)
        .ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.to_string()))?;
    if rec.state != RecordState::Staged {
        return Ok(StatusInfo::from_record(&rec));
    }
    if let Some(stranger) = lost.iter().find(|id| !rec.roster.contains(id)) {
        return Err(DaemonError::CeremonyRefused(format!("node {stranger} is not in this ceremony's roster")));
    }
    let reports = gather(node, &rec, lost).await?;
    // Evidence among the reachable nodes decides exactly as the normal resolver would.
    let mut normal = decide(&rec, me, &reports);
    if let Decision::Wait(_) = normal {
        let mine = rec.outcome();
        let mut missing = Vec::new();
        let mut someone_committed = false;
        for &id in rec.roster.iter().filter(|&&id| id != me && !lost.contains(&id)) {
            match reports.get(&id) {
                Some(PeerReport::Committed(o)) if *o == mine => someone_committed = true,
                Some(PeerReport::Staged(o)) if *o == mine => {}
                other => missing.push(format!("node {id}: {other:?}")),
            }
        }
        if !missing.is_empty() {
            return Err(DaemonError::CeremonyRefused(format!(
                "cannot decide ceremony {ceremony_id}: only nodes named in --assume-lost may be \
                 unanswered, but {}",
                missing.join("; ")
            )));
        }
        normal = if someone_committed {
            Decision::Commit
        } else {
            Decision::Abort(format!(
                "break-glass: nodes {lost:?} declared permanently lost and no reachable node committed"
            ))
        };
    }
    tracing::warn!(ceremony_id, ?lost, decision = ?normal, "break-glass ceremony resolution");
    let id = ceremony_id.to_owned();
    node.blocking(move |n| n.apply_resolution(&id, &normal)).await
}

/// What [`discard_partial_key`] found and did.
#[derive(Debug)]
pub struct DiscardReport {
    pub key_id: String,
    /// Configured identifiers of the nodes that hold a file for the key (this one included).
    pub holders: Vec<u16>,
}

/// Operator path for a **legacy** partial DKG key (audit M5): a key file left on fewer than all
/// nodes by a pre-two-phase DKG that failed between nodes, which wedges every retry of a
/// deterministic key id. Deletes this node's file for `key_id` (and its nonce markers), refusing
/// unless every safety condition holds:
///
/// * this node's share is a DKG share at epoch 0 (written before two-phase ceremonies — anything a
///   two-phase ceremony committed is never partial) and its group key is `confirm_group_key`;
/// * no ceremony for the key is staged or committed here;
/// * every other roster node answers, none holds the key at an epoch ≥ 1 or with a staged
///   ceremony, and fewer than all nodes hold it at all;
/// * no signing session has ever been burned for the key on this node.
///
/// The caller holds the instance lock (the daemon on this node is stopped). Whether Canton ever
/// registered the key — a 2-of-3 partial key held by two nodes can sign — only the operator knows.
pub async fn discard_partial_key(node: &Arc<Node>, key_id: &str, confirm_group_key: &[u8; 32]) -> Result<DiscardReport> {
    let refuse = |why: String| Err(DaemonError::CeremonyRefused(format!("discard-partial-key {key_id}: {why}")));
    let me = node.index()?;
    let local = {
        let id = key_id.to_owned();
        node.blocking(move |n| n.key_epoch(&id)).await?
    };
    if !local.present {
        return refuse("this node holds no file for it".into());
    }
    if local.origin != "dkg" {
        return refuse(format!(
            "this node's file is a {} key, not a DKG share (an imported key has abort-import)",
            local.origin
        ));
    }
    if local.epoch != 0 || local.staged {
        return refuse(format!(
            "this node holds it at epoch {} (staged: {}) — a key a two-phase ceremony committed is \
             never partial",
            local.epoch, local.staged
        ));
    }
    if local.group_verifying_key != confirm_group_key {
        return refuse(format!(
            "its group key is {}, not the --confirm-group-key given",
            hex::encode(&local.group_verifying_key)
        ));
    }
    if node.has_ceremony_for(key_id) {
        return refuse("this node has a staged or committed ceremony record for it".into());
    }
    let mut holders = vec![me];
    for id in 1..=node.max_signers {
        if id == me {
            continue;
        }
        let peer = node
            .mesh_peer(id)
            .ok_or_else(|| DaemonError::CeremonyRefused(format!("node {id} is not in the roster mesh")))?;
        let view = match peer.key_epoch(key_id).await {
            Ok(v) => v,
            Err(e) => return refuse(format!("node {id} did not answer ({e}) — every node must, to prove the key is partial")),
        };
        if view.staged || (view.present && view.epoch >= 1) {
            return refuse(format!(
                "node {id} holds it at a committed epoch {} (staged: {})",
                view.epoch, view.staged
            ));
        }
        if view.present {
            holders.push(id);
        }
    }
    if holders.len() >= usize::from(node.max_signers) {
        return refuse("every node holds it — the key is not partial".into());
    }
    let id = key_id.to_owned();
    node.blocking(move |n| n.discard_local_key(&id)).await?;
    holders.sort_unstable();
    Ok(DiscardReport { key_id: key_id.to_string(), holders })
}

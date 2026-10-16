// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The networked half of DKG/refresh, run by every node for itself:
//!
//! * **Confidential round 2 (audit C1).** A node delivers each of its round-2 packages straight to
//!   its recipient over the mTLS mesh ([`part2_and_deliver`]): the sender dials the recipient under
//!   its own TLS name (`cosigner<id>`), the recipient identifies the sender by its certificate CN.
//!   The leader only coordinates; no peer API returns a round-2 package to it. Every delivery
//!   carries the sender's digest of the round-1 map ([`round1_digest`]), and part 3 requires all of
//!   them equal to the recipient's own, so a leader that shows nodes different round-1 maps makes
//!   every honest node abort.
//! * **Two-phase commit.** The resolver commits or aborts a STAGED ceremony from its peers' votes,
//!   asked directly over the mesh, never through the leader; the vote rules are
//!   [`crate::ceremony_record::decide`]. Plus the operator break-glass for a permanently lost node
//!   and the legacy partial-key discard.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use frost_ed25519::keys::dkg::round1;
use frost_ed25519::Identifier;
use sha2::{Digest, Sha256};

use crate::ceremony_record::{
    decide, equivocation, mixed_evidence, quarantine_droppable, split_evident, CeremonyRecord, Decision, PeerReport,
    RecordState, StatusInfo,
};
use crate::node::{CeremonyKind, KeyVersion, Node};
use crate::{DaemonError, Result};

/// The DKG/refresh wire protocol this build speaks: 2 = direct round-2 delivery with the round-1
/// digest echo and two-phase commit. A leader refuses to start a ceremony unless every roster node
/// reports at least this (`NodeInfo.ceremony_protocol`), and an upgraded node refuses the old
/// leader-relayed RPCs — so a mixed-version cluster refuses ceremonies instead of falling back.
pub const CEREMONY_PROTOCOL: u32 = 2;

/// What the round-1 digest binds besides the map: which ceremony, over which key and sharing.
pub struct DigestContext<'a> {
    pub ceremony_id: &'a str,
    pub key_id: &'a str,
    pub kind: CeremonyKind,
    pub max_signers: u16,
    pub min_signers: u16,
    /// Refresh: the (epoch, PKP digest) being replaced. DKG: none (zeros).
    pub old: Option<KeyVersion>,
}

/// `SHA-256("rutli-ceremony-r1-v2" ‖ lp(ceremony_id) ‖ lp(key_id) ‖ lp(kind) ‖ u16 n ‖ u16 t ‖
/// u64 old_epoch ‖ old_pkp_digest[32 or zero] ‖ Σ_{id asc}(id ‖ lp(package)))`, with frost's own
/// canonical serializations and `lp` a u32 big-endian length prefix. Equal on two nodes iff they
/// were shown the same round-1 map for the same ceremony.
pub fn round1_digest(ctx: &DigestContext<'_>, map: &BTreeMap<Identifier, round1::Package>) -> Result<[u8; 32]> {
    fn lp(h: &mut Sha256, bytes: &[u8]) {
        h.update((bytes.len() as u32).to_be_bytes());
        h.update(bytes);
    }
    let mut h = Sha256::new();
    h.update(b"rutli-ceremony-r1-v2");
    lp(&mut h, ctx.ceremony_id.as_bytes());
    lp(&mut h, ctx.key_id.as_bytes());
    lp(&mut h, ctx.kind.as_str().as_bytes());
    h.update(ctx.max_signers.to_be_bytes());
    h.update(ctx.min_signers.to_be_bytes());
    let (old_epoch, old_digest) = ctx.old.unwrap_or((0, [0u8; 32]));
    h.update(old_epoch.to_be_bytes());
    h.update(old_digest);
    for (id, pkg) in map {
        h.update(id.serialize());
        lp(&mut h, &pkg.serialize()?);
    }
    Ok(h.finalize().into())
}

/// What part 2 tells the leader: the node's round-1 digest and whom it delivered to. Never a
/// round-2 package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part2Outcome {
    pub round1_digest: [u8; 32],
    pub delivered: Vec<u16>,
}

/// Part 2 on `node`: compute its round-2 packages ([`Node::ceremony_part2_compute`]) and deliver
/// each directly to its recipient over the node's mesh. Any failed delivery aborts the session
/// here (the leader then aborts it everywhere). The packages never leave this function except to
/// their recipients.
pub async fn part2_and_deliver(
    node: &Arc<Node>,
    ceremony_id: &str,
    round1_map: BTreeMap<Identifier, round1::Package>,
) -> Result<Part2Outcome> {
    let id = ceremony_id.to_owned();
    let (digest, packages) = node.blocking(move |n| n.ceremony_part2_compute(&id, &round1_map)).await?;
    let me = node.index()?;
    let mut delivered = Vec::new();
    for (to, package) in packages {
        let sent = match node.mesh_peer(to) {
            Some(peer) => peer.ceremony_deliver(ceremony_id, me, to, &digest, &package).await,
            None => Err(DaemonError::CeremonyRefused(format!("node {to} is not in this node's mesh"))),
        };
        if let Err(e) = sent {
            // The recipient's error text (serde errors from parsing a package, for one) stays in
            // this node's log; the leader gets only its category (audit F11).
            tracing::warn!(ceremony_id, to, error = %e, "round-2 delivery failed; aborting this node's session");
            let id = ceremony_id.to_owned();
            let _ = node.blocking(move |n| n.ceremony_abort(&id)).await;
            return Err(DaemonError::CeremonyRefused(format!(
                "delivering the round-2 package to node {to} failed ({}) — see that node's and this node's logs",
                delivery_failure_code(&e)
            )));
        }
        delivered.push(to);
    }
    Ok(Part2Outcome { round1_digest: digest, delivered })
}

/// The category of a failed round-2 delivery, for the leader: a gRPC code or an error kind,
/// never the recipient's message (audit F11).
fn delivery_failure_code(e: &DaemonError) -> &'static str {
    match e {
        DaemonError::Status(s) => s.code().description(),
        DaemonError::Transport(_) => "transport error",
        DaemonError::NotServing(_) => "recipient not serving",
        DaemonError::UnknownDkg(_) => "recipient has no such session",
        DaemonError::Serde(_) | DaemonError::Frost(_) => "malformed package",
        DaemonError::CeremonyRefused(_) | DaemonError::Ceremony(_) | DaemonError::Config(_) => "refused by the recipient",
        _ => "error",
    }
}

/// How often a node retries its STAGED ceremonies (and settles finished ones).
pub const RESOLVER_INTERVAL: Duration = Duration::from_secs(30);

/// How long a settled ceremony record is kept.
pub const RECORD_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long the staged share of an aborted ceremony is quarantined when no split is detected and
/// not every peer has been seen terminal (audit F3). A detected split keeps it until the operator
/// recovers or drops it.
pub const QUARANTINE_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

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
    resolve_from(node, ceremony_id, None).await
}

/// [`resolve`] on behalf of the peer whose certificate CN is `asker` (`Peer.CeremonyCommit`): an
/// unknown id is answered as [`Node::ceremony_status_from`] would for that asker.
///
/// An abort is never applied on the first look when some peer reported a yes-vote for this node's
/// outcome ([`mixed_evidence`]): the votes are gathered again after [`Node::regather_delay`] and
/// decided afresh (audit F3). With crash faults that only delays the abort; against a cosigner
/// telling nodes different votes it gives the node that is told COMMITTED time to say so, which
/// proves the equivocation ([`equivocation`]). Every resolver abort keeps the staged share
/// quarantined; it is dropped once every peer is terminal with nobody committed
/// ([`quarantine_droppable`]).
pub async fn resolve_from(node: &Arc<Node>, ceremony_id: &str, asker: Option<String>) -> Result<StatusInfo> {
    let rec = match node.ceremony_record(ceremony_id) {
        Some(r) if r.state == RecordState::Staged => r,
        Some(r) => return Ok(StatusInfo::from_record(&r)),
        None => {
            let id = ceremony_id.to_owned();
            return node.blocking(move |n| n.ceremony_status_from(&id, asker.as_deref())).await;
        }
    };
    let me = node.index()?;
    let mut reports = gather(node, &rec, &[]).await?;
    let mut decision = decide(&rec, me, &reports);
    if matches!(decision, Decision::Abort(_)) && mixed_evidence(&rec, me, &reports) {
        tracing::warn!(
            ceremony_id,
            key_id = %rec.key_id,
            "a peer voted no while another holds a yes-vote for this node's outcome — gathering the votes again before aborting"
        );
        tokio::time::sleep(node.regather_delay()).await;
        match node.ceremony_record(ceremony_id) {
            Some(r) if r.state == RecordState::Staged => {}
            Some(r) => return Ok(StatusInfo::from_record(&r)),
            None => return Err(DaemonError::UnknownDkg(ceremony_id.into())),
        }
        reports = gather(node, &rec, &[]).await?;
        decision = decide(&rec, me, &reports);
    }
    if let Decision::Wait(why) = &decision {
        tracing::debug!(ceremony_id, key_id = %rec.key_id, waiting = %why, "staged ceremony not decidable yet");
        return Ok(StatusInfo::from_record(&rec));
    }
    let split = equivocation(&rec, me, &reports);
    if split {
        metrics::counter!(crate::metrics::CEREMONY_EQUIVOCATIONS).increment(1);
        tracing::error!(
            ceremony_id,
            key_id = %rec.key_id,
            ?reports,
            "ceremony reported both COMMITTED and ABORTED by peers — a cosigner equivocated (docs/ceremonies.md)"
        );
    }
    let quarantine = matches!(decision, Decision::Abort(_)) && !quarantine_droppable(&rec, me, &reports);
    let id = ceremony_id.to_owned();
    node.blocking(move |n| n.apply_resolution_with(&id, &decision, quarantine, split)).await
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
    // Quarantined aborts (audit F3): a peer now reporting COMMITTED for this node's outcome is a
    // split; every peer terminal with nobody committed frees the share.
    if let Ok(me) = node.index() {
        for rec in node.quarantined_records() {
            let Ok(reports) = gather(node, &rec, &[]).await else { continue };
            if split_evident(&rec, me, &reports) {
                if node.flag_split(&rec.ceremony_id).unwrap_or(false) {
                    metrics::counter!(crate::metrics::CEREMONY_EQUIVOCATIONS).increment(1);
                }
                tracing::error!(
                    ceremony_id = %rec.ceremony_id,
                    key_id = %rec.key_id,
                    ?reports,
                    "SPLIT: this node aborted a ceremony a peer reports COMMITTED with the same outcome — a \
                     cosigner equivocated. The staged share is quarantined; after checking the committed \
                     node, run `rutli-cosigner ceremony recover-commit --ceremony-id {}` with this node's \
                     daemon stopped (docs/ceremonies.md)",
                    rec.ceremony_id
                );
            } else if rec.split_detected_ms == 0 && quarantine_droppable(&rec, me, &reports) {
                if let Err(e) = node.drop_quarantine(&rec.ceremony_id) {
                    tracing::warn!(ceremony_id = %rec.ceremony_id, error = %e, "could not drop a quarantined share");
                }
            }
        }
    }
    match node.gc_quarantine(QUARANTINE_RETENTION) {
        Ok(0) => {}
        Ok(n) => tracing::info!(dropped = n, "dropped quarantined staged shares past their retention"),
        Err(e) => tracing::warn!(error = %e, "quarantine garbage collection failed"),
    }
    metrics::gauge!(crate::metrics::CEREMONIES_SPLIT).set(node.split_count() as f64);
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

/// Operator recovery of a split (audit F3; `rutli-cosigner ceremony recover-commit`, daemon
/// stopped, instance lock held): commit the quarantined staged share of a ceremony this node
/// aborted, because a peer reports it COMMITTED with exactly this node's outcome.
///
/// Refuses unless every condition holds: this node's record is ABORTED with the share quarantined;
/// some peer reports COMMITTED with this node's outcome **and** its key state shows that sharing
/// live (epoch and PKP digest); no peer reports a yes-vote for any other outcome; and the commit
/// rules of [`Node::apply_resolution`] (a refresh replaces exactly the sharing it started from).
///
/// Key-safe: an honest COMMITTED node committed only after confirming every roster node's yes-vote
/// for that outcome, so it is a complete sharing of the same group key. A *lying* COMMITTED report
/// can at worst move this node onto a sharing the other honest node does not hold — availability,
/// as before — so the operator confirms which node is suspect first.
pub async fn recover_commit(node: &Arc<Node>, ceremony_id: &str) -> Result<StatusInfo> {
    let me = node.index()?;
    let rec = node
        .ceremony_record(ceremony_id)
        .ok_or_else(|| DaemonError::UnknownDkg(ceremony_id.to_string()))?;
    if rec.state != RecordState::Aborted || !rec.quarantined {
        return Err(DaemonError::CeremonyRefused(format!(
            "ceremony {ceremony_id} is {} here{} — nothing to recover",
            rec.state.as_str(),
            if rec.state == RecordState::Aborted { " and its staged share is not quarantined" } else { "" }
        )));
    }
    let reports = gather(node, &rec, &[]).await?;
    let mine = rec.outcome();
    if let Some((id, _)) = reports
        .iter()
        .find(|(_, r)| matches!(r, PeerReport::Staged(o) | PeerReport::Committed(o) if *o != mine))
    {
        return Err(DaemonError::CeremonyRefused(format!(
            "node {id} reports a yes-vote for another outcome of {ceremony_id} — refusing"
        )));
    }
    let mut proven = Vec::new();
    for (&id, r) in &reports {
        if !matches!(r, PeerReport::Committed(o) if *o == mine) {
            continue;
        }
        let Some(peer) = node.mesh_peer(id) else { continue };
        match peer.key_epoch(&rec.key_id).await {
            Ok(v) if v.present && v.epoch == rec.new_epoch && hex::encode(&v.pkp_digest) == rec.new_pkp_digest => {
                proven.push(id)
            }
            Ok(v) => tracing::warn!(
                node = id,
                epoch = v.epoch,
                "reports the ceremony COMMITTED but its live share is not that sharing — not counted"
            ),
            Err(e) => tracing::warn!(node = id, error = %e, "could not read its key state — not counted"),
        }
    }
    if proven.is_empty() {
        return Err(DaemonError::CeremonyRefused(format!(
            "no peer both reports {ceremony_id} COMMITTED with this node's outcome and holds that sharing \
             live (reports: {reports:?}) — nothing proves the ceremony committed anywhere"
        )));
    }
    tracing::warn!(ceremony_id, key_id = %rec.key_id, committed_on = ?proven, "recovering a split ceremony");
    let id = ceremony_id.to_owned();
    let _ = me;
    node.blocking(move |n| n.apply_recovery(&id)).await
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

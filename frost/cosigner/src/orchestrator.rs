// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Leader-side coordination of DKG and signing across the peer set. Transport-agnostic: it drives
//! [`PeerApi`], so the same code runs over gRPC in production and over in-process peers in tests.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use frost_ed25519 as frost;
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;

use crate::ceremony_record::Phase;
use crate::node::{CeremonyKind, Node};
use crate::peer::PeerApi;
use crate::pb;
use crate::{DaemonError, Result};

pub type Peers = Vec<Arc<dyn PeerApi>>;

/// Length of the digest Canton hands the KMS driver for Ed25519 topology signs
/// (`0x12 0x20 ‖ sha256(tx)` — see `docs/wire-contract.md`). The Signer API rejects anything else
/// so a miswired client cannot mint signatures over arbitrary payloads through the cluster.
pub const CANTON_DIGEST_LEN: usize = 34;

/// Coordinate a full DKG across every peer and return the agreed 32-byte group verifying key.
/// Every peer stages its own share and commits it only once every node has confirmed, directly
/// with every other node, that all staged the same outcome (see [`crate::ceremony_record`]); the
/// whole private key is never assembled anywhere.
///
/// Idempotent by key id (audit M5): a retry for a key every node has committed returns it; a retry
/// while a ceremony for it is still resolving answers UNAVAILABLE (the driver fails over, Canton
/// retries); a legacy partial key (files on some nodes only, from before two-phase ceremonies) is
/// refused with the operator path.
///
/// The ceremony runs as its own task: a caller that stops waiting (driver deadline, client
/// cancel) cannot cut it between nodes.
pub async fn run_dkg(peers: &Peers, key_id: &str) -> Result<[u8; 32]> {
    run_dkg_with_intent(peers, key_id, None).await
}

/// [`run_dkg`] for a client's ceremony intent (refresh-fence remediation, layer L2): the ceremony
/// id is the one the intent names (`dkg-<hex(request_id)>`), and the intent goes, unchanged, with
/// the fence and part 1 to every node, which verifies it itself before it takes the guard. Without
/// an intent (an older client) the id is random and every node decides whether it accepts that
/// (`signing_policy.require_ceremony_intent`).
pub async fn run_dkg_with_intent(peers: &Peers, key_id: &str, intent: Option<pb::SignedIntent>) -> Result<[u8; 32]> {
    Ok(run_dkg_outcome(peers, key_id, intent).await?.group_key)
}

/// What a DKG request came to: the group key, whether the key already existed (the request
/// returned it without a ceremony), and the id of the ceremony that made a new key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgOutcome {
    pub group_key: [u8; 32],
    pub existing: bool,
    /// The ceremony that created a new key; `None` for an existing one (the leader looks up the DKG
    /// it committed it under, [`crate::node::Node::committed_dkg_ceremony`]).
    pub ceremony_id: Option<String>,
}

/// [`run_dkg_with_intent`], saying whether the key already existed (`DkgReply.existing`).
pub async fn run_dkg_outcome(peers: &Peers, key_id: &str, intent: Option<pb::SignedIntent>) -> Result<DkgOutcome> {
    let (peers, key_id) = (peers.clone(), key_id.to_owned());
    crate::ceremony::detach(async move { run_dkg_attached(&peers, &key_id, intent.as_ref()).await }).await
}

/// The ceremony id for a ceremony of `kind` led for `intent` (its own id), or a random one.
fn ceremony_id(kind: CeremonyKind, intent: Option<&pb::SignedIntent>) -> Result<String> {
    match intent {
        Some(i) => crate::intent::ceremony_id_of(i, kind),
        None => Ok(new_id(kind.as_str())),
    }
}

async fn run_dkg_attached(peers: &Peers, key_id: &str, intent: Option<&pb::SignedIntent>) -> Result<DkgOutcome> {
    // Every peer refuses too (fence and part 1); this just answers before touching the mesh.
    if crate::share_delivery::is_reserved_for_import(key_id) {
        return Err(DaemonError::ReservedKeyId(key_id.to_string()));
    }
    require_ceremony_protocol(peers).await?;
    let views = key_views(peers, key_id).await?;
    if let Some(existing) = dkg_preflight(peers, key_id, &views).await? {
        return Ok(DkgOutcome { group_key: existing, existing: true, ceremony_id: None });
    }
    let dkg_id = ceremony_id(CeremonyKind::Dkg, intent)?;
    fence_all(peers, &dkg_id, key_id, CeremonyKind::Dkg, None, intent).await?;
    let staged = ceremony_stage(peers, &dkg_id, key_id, CeremonyKind::Dkg, intent).await;
    let group_key = finish_ceremony(peers, &dkg_id, key_id, staged).await?;
    Ok(DkgOutcome { group_key, existing: false, ceremony_id: Some(dkg_id) })
}

/// Parts 1–3 of a DKG or refresh (ceremony protocol 2): every node ends with a staged share and a
/// STAGED vote, or the error. The leader handles only public values — round-1 packages, digests,
/// the staged outcome; round-2 packages go node to node ([`crate::ceremony::part2_and_deliver`]).
async fn ceremony_stage(
    peers: &Peers,
    ceremony_id: &str,
    key_id: &str,
    kind: CeremonyKind,
    intent: Option<&pb::SignedIntent>,
) -> Result<[u8; 32]> {
    let mut roster =
        peers.iter().map(|p| crate::hosted::identifier_index(p.identifier())).collect::<Result<Vec<_>>>()?;
    roster.sort_unstable();
    // Part 1: every node commits; the leader collects the (public) round-1 packages.
    let mut round1_map = BTreeMap::new();
    for p in peers {
        round1_map.insert(p.identifier(), p.ceremony_part1(ceremony_id, key_id, kind, &roster, intent).await?);
    }
    // Part 2: every node checks the map, then delivers its round-2 packages to their recipients
    // itself. The leader learns only each node's digest of the map. Equal digests are checked here
    // for an early, clear failure; the check that matters runs on every node in part 3.
    let mut digest: Option<[u8; 32]> = None;
    for p in peers {
        let me = crate::hosted::identifier_index(p.identifier())?;
        let out = p.ceremony_part2(ceremony_id, &round1_map).await?;
        let expected: Vec<u16> = roster.iter().copied().filter(|&id| id != me).collect();
        if out.delivered != expected {
            return Err(DaemonError::Disagreement(format!(
                "cosigner {me} delivered round 2 to {:?}, expected {expected:?}",
                out.delivered
            )));
        }
        agree(&mut digest, out.round1_digest, "nodes computed different round-1 digests")?;
    }
    let digest = digest.ok_or_else(|| DaemonError::Config("no peers configured for the ceremony".into()))?;
    // Part 3: each node checks every delivery against its own digest, stages and votes yes.
    let mut outcome: Option<crate::node::StagedOutcome> = None;
    for p in peers {
        let staged = p.ceremony_part3(ceremony_id, &digest).await?;
        match outcome {
            None => outcome = Some(staged),
            Some(prev) if prev != staged => {
                return Err(DaemonError::Disagreement(format!(
                    "nodes staged different outcomes for {key_id} (epoch {} vs {}) — aborting",
                    prev.new_epoch, staged.new_epoch
                )))
            }
            _ => {}
        }
    }
    outcome.map(|o| o.group_key).ok_or_else(|| DaemonError::Config("no peers configured for the ceremony".into()))
}

/// Refuse to start a ceremony unless every roster node speaks ceremony protocol 2 — so a cluster in
/// the middle of a rolling upgrade refuses DKG/refresh loudly instead of falling back to relaying
/// secret shares through the leader. A node that cannot be asked is refused too.
async fn require_ceremony_protocol(peers: &Peers) -> Result<()> {
    for p in peers {
        let id = crate::hosted::identifier_index(p.identifier())?;
        let problem = match p.ceremony_protocol().await {
            Ok(v) if v >= crate::ceremony::CEREMONY_PROTOCOL => continue,
            Ok(v) => format!("cosigner {id} speaks ceremony protocol {v}"),
            Err(e) => format!("cosigner {id} could not report its ceremony protocol ({e})"),
        };
        return Err(DaemonError::CeremonyRefused(format!(
            "{problem}; DKG and refresh need protocol {} on every node — finish upgrading the \
             cluster first (signing is unaffected)",
            crate::ceremony::CEREMONY_PROTOCOL
        )));
    }
    Ok(())
}

/// Coordinate a proactive refresh across every peer. Same three-part exchange as DKG, but each
/// peer folds the fresh zero-sharing into its existing share, at the next epoch. The group public
/// key is unchanged (verified by every node); shares stolen before this refresh become useless.
/// Requires all peers, all on one sharing (same epoch and PKP digest) — a refresh over mixed
/// epochs is refused, never attempted.
///
/// Two-phase like DKG: no node replaces its share until every node has confirmed, directly, that
/// all staged the same new sharing. A failure at any point leaves every node on the old epoch (or,
/// after the first commit, lets every node's resolver finish the new one) — never a mix (H1).
pub async fn run_refresh(peers: &Peers, key_id: &str) -> Result<[u8; 32]> {
    run_refresh_with_intent(peers, key_id, None).await
}

/// [`run_refresh`] for a client's ceremony intent: as [`run_dkg_with_intent`], with the id
/// `refresh-<hex(request_id)>`.
pub async fn run_refresh_with_intent(
    peers: &Peers,
    key_id: &str,
    intent: Option<pb::SignedIntent>,
) -> Result<[u8; 32]> {
    let (peers, key_id) = (peers.clone(), key_id.to_owned());
    crate::ceremony::detach(async move { run_refresh_attached(&peers, &key_id, intent.as_ref()).await }).await
}

async fn run_refresh_attached(peers: &Peers, key_id: &str, intent: Option<&pb::SignedIntent>) -> Result<[u8; 32]> {
    require_ceremony_protocol(peers).await?;
    let views = key_views(peers, key_id).await?;
    let expect = refresh_preflight(peers, key_id, &views).await?;
    let refresh_id = ceremony_id(CeremonyKind::Refresh, intent)?;
    fence_all(peers, &refresh_id, key_id, CeremonyKind::Refresh, Some(expect), intent).await?;
    let staged = ceremony_stage(peers, &refresh_id, key_id, CeremonyKind::Refresh, intent).await;
    finish_ceremony(peers, &refresh_id, key_id, staged).await
}

fn agree(seen: &mut Option<[u8; 32]>, gk: [u8; 32], what: &str) -> Result<()> {
    match seen {
        None => *seen = Some(gk),
        Some(prev) if *prev != gk => return Err(DaemonError::Disagreement(what.into())),
        _ => {}
    }
    Ok(())
}

/// Every peer's [`crate::pb::KeyEpochReply`] for `key_id`, by identifier. A ceremony needs every
/// node, so a peer that cannot answer refuses the ceremony before anything starts.
async fn key_views(peers: &Peers, key_id: &str) -> Result<Vec<(u16, crate::pb::KeyEpochReply)>> {
    let mut views = Vec::new();
    for p in peers {
        let id = crate::hosted::identifier_index(p.identifier())?;
        match p.key_epoch(key_id).await {
            Ok(v) => views.push((id, v)),
            Err(e) => {
                return Err(DaemonError::NotServing(format!(
                    "cosigner {id} cannot report its state for {key_id} ({e}) — a DKG/refresh needs \
                     every node"
                )))
            }
        }
    }
    Ok(views)
}

/// Ask every node holding a STAGED ceremony for `key_id` to resolve it now, then answer
/// UNAVAILABLE: the caller retries once it has settled.
async fn resolving(peers: &Peers, key_id: &str, views: &[(u16, crate::pb::KeyEpochReply)]) -> DaemonError {
    let ids: std::collections::BTreeSet<&str> =
        views.iter().filter(|(_, v)| v.staged).map(|(_, v)| v.staged_ceremony_id.as_str()).collect();
    for id in &ids {
        for p in peers {
            let _ = p.ceremony_commit(id).await;
        }
    }
    DaemonError::NotServing(format!(
        "a ceremony for {key_id} ({}) is staged and still resolving — retry shortly",
        ids.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

/// The DKG idempotency decision (M5). `Some(group key)`: already committed everywhere.
async fn dkg_preflight(
    peers: &Peers,
    key_id: &str,
    views: &[(u16, crate::pb::KeyEpochReply)],
) -> Result<Option<[u8; 32]>> {
    if views.iter().any(|(_, v)| v.staged) {
        return Err(resolving(peers, key_id, views).await);
    }
    let holders: Vec<u16> = views.iter().filter(|(_, v)| v.present).map(|(id, _)| *id).collect();
    if holders.is_empty() {
        return Ok(None);
    }
    if let Some((id, v)) = views.iter().find(|(_, v)| v.present && v.origin != "dkg") {
        tracing::debug!(node = id, origin = %v.origin, "DKG over a non-DKG key refused");
        return Err(DaemonError::KeyExists(key_id.to_string()));
    }
    if holders.len() < views.len() {
        return Err(DaemonError::CeremonyRefused(format!(
            "{key_id} exists on cosigners {holders:?} only — a partial key from an interrupted DKG \
             before two-phase ceremonies (or a node that lost its file). If no node holds it at an \
             epoch >= 1 and Canton never registered it, remove it with `rutli-cosigner \
             discard-partial-key` on each holder (docs/ceremonies.md); otherwise restore the lost \
             share"
        )));
    }
    // `holders` is not empty, so neither is `views`; checked anyway, no panic in a preflight.
    let Some((_, first)) = views.first() else {
        return Err(DaemonError::CeremonyRefused(format!("no cosigner answered for {key_id}")));
    };
    let same = views.iter().all(|(_, v)| {
        v.epoch == first.epoch && v.pkp_digest == first.pkp_digest && v.group_verifying_key == first.group_verifying_key
    });
    if !same {
        return Err(DaemonError::CeremonyRefused(format!(
            "{key_id} exists on every node but they hold different sharings — refusing (verify-key \
             shows which)"
        )));
    }
    let gk: [u8; 32] = first
        .group_verifying_key
        .as_slice()
        .try_into()
        .map_err(|_| DaemonError::Disagreement("group key not 32 bytes".into()))?;
    tracing::info!(key_id, epoch = first.epoch, "DKG retry for a committed key: returning it");
    Ok(Some(gk))
}

/// The refresh precondition: every node holds `key_id` on one sharing and nothing is staged.
/// Returns that sharing's (epoch, PKP digest), which every node re-checks at its fence.
async fn refresh_preflight(
    peers: &Peers,
    key_id: &str,
    views: &[(u16, crate::pb::KeyEpochReply)],
) -> Result<(u64, [u8; 32])> {
    if views.iter().any(|(_, v)| v.staged) {
        return Err(resolving(peers, key_id, views).await);
    }
    if let Some((id, _)) = views.iter().find(|(_, v)| !v.present) {
        return Err(DaemonError::UnknownKey(format!("{key_id} (absent on cosigner {id})")));
    }
    if let Some((id, v)) = views.iter().find(|(_, v)| v.origin == "hosted") {
        return Err(DaemonError::CeremonyRefused(format!(
            "{key_id} is a cluster-hosted key on cosigner {id}, not a FROST share ({})",
            v.origin
        )));
    }
    let Some((first_id, first)) = views.first() else {
        return Err(DaemonError::CeremonyRefused(format!("no cosigner answered for {key_id}")));
    };
    if let Some((id, v)) = views.iter().find(|(_, v)| v.epoch != first.epoch || v.pkp_digest != first.pkp_digest) {
        return Err(DaemonError::CeremonyRefused(format!(
            "refusing to refresh {key_id}: cosigner {id} is on epoch {} but cosigner {} is on epoch {} \
             (or their sharings differ) — the nodes must hold one sharing (verify-key shows which)",
            v.epoch, first_id, first.epoch
        )));
    }
    let digest: [u8; 32] = first
        .pkp_digest
        .as_slice()
        .try_into()
        .map_err(|_| DaemonError::Disagreement("pkp digest not 32 bytes".into()))?;
    Ok((first.epoch, digest))
}

/// After the staging phase: on success, drive the commit; on failure, abort every in-memory
/// session (a STAGED vote is untouched by that), let every STAGED node resolve on its peers'
/// evidence, release the fences, and return the error.
async fn finish_ceremony(peers: &Peers, ceremony_id: &str, key_id: &str, staged: Result<[u8; 32]>) -> Result<[u8; 32]> {
    match staged {
        Ok(group_key) => {
            commit_everywhere(peers, ceremony_id, key_id).await?;
            Ok(group_key)
        }
        Err(e) => {
            tracing::warn!(ceremony_id, key_id, error = %e, "ceremony failed before every node staged; aborting");
            for p in peers {
                if let Err(err) = p.ceremony_abort(ceremony_id).await {
                    tracing::debug!(peer = ?p.identifier(), error = %err, "ceremony abort failed");
                }
            }
            for p in peers {
                let _ = p.ceremony_commit(ceremony_id).await; // resolves STAGED nodes to ABORTED
            }
            release_all(peers, ceremony_id, key_id).await;
            Err(e)
        }
    }
}

/// How many times the leader asks every node to resolve before leaving the rest to the nodes'
/// own resolvers.
const COMMIT_ROUNDS: u32 = 5;

/// Ask every node to resolve the ceremony (each confirms with every other node itself) until all
/// report COMMITTED. Any ABORTED: the ceremony failed everywhere (no node committed — a node aborts
/// only on evidence that makes committing impossible). Still STAGED somewhere after the retries
/// (a node unreachable): UNAVAILABLE — the nodes finish on their own, and a retry sees the result.
async fn commit_everywhere(peers: &Peers, ceremony_id: &str, key_id: &str) -> Result<()> {
    let mut pending = Vec::new();
    for round in 0..COMMIT_ROUNDS {
        pending.clear();
        for p in peers {
            let id = crate::hosted::identifier_index(p.identifier())?;
            match p.ceremony_commit(ceremony_id).await {
                Ok(s) if s.phase == Phase::Committed => {}
                Ok(s) if s.phase == Phase::Aborted => {
                    return Err(DaemonError::Disagreement(format!(
                        "ceremony {ceremony_id} for {key_id} aborted on cosigner {id} — no node \
                         changed its share"
                    )))
                }
                Ok(s) => pending.push(format!("cosigner {id}: {}", s.phase.as_str())),
                Err(e) => pending.push(format!("cosigner {id}: {e}")),
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100 << round)).await;
    }
    Err(DaemonError::NotServing(format!(
        "ceremony {ceremony_id} for {key_id} is staged but not yet committed everywhere ({}); every \
         node's resolver completes it — retry to confirm",
        pending.join("; ")
    )))
}

/// Most t-subsets one Sign tries: C(5,3) = 10 covers every supported roster (C(3,2) = 3).
pub const MAX_SIGN_ATTEMPTS: usize = 10;

/// Wall-clock budget for one Sign's attempts — inside the driver's 60 s deadline, so a request
/// that cannot be served here ends with an error the driver can still fail over on.
pub const SIGN_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// Coordinate one signature (audit H1: epoch-matched quorums with retry).
///
/// * The leader signs only with its own sharing of the key (epoch, PKP digest), which it sends in
///   round 1; a peer on another sharing refuses ([`DaemonError::EpochMismatch`]), and a stale peer
///   refuses too. A leader whose own share is stale declines to lead (UNAVAILABLE, the driver
///   fails over).
/// * Candidate t-subsets are the roster's combinations, leader first then by identifier. Each
///   attempt is a fresh session (a new random session id per member, fresh round-1 commitments from every member —
///   commitments are never reused across subsets). A member that fails round 1 or round 2, or whose
///   share fails verification at aggregation (frost's cheater detection names it), is excluded for
///   the rest of the request; its session is aborted on the members that hold nonces, and the next
///   subset without any excluded member is tried.
/// * If `t` peers report one sharing that is not older than the leader's, the leader is the odd
///   one out: it stops and answers UNAVAILABLE so the driver fails over to a node on the cluster's
///   sharing (and nudges its own resolver if it has a ceremony for the key staged).
/// * At most [`MAX_SIGN_ATTEMPTS`] attempts within [`SIGN_BUDGET`].
///
/// Every step that may read this node's key store runs on the blocking pool ([`Node::blocking`];
/// the [`PeerApi`] calls do the same on their side), so a stalled volume parks a blocking thread,
/// never an async worker.
pub async fn sign(node: &Arc<Node>, peers: &Peers, key_id: &str, message: &[u8]) -> Result<[u8; 64]> {
    sign_with_intent(node, peers, key_id, message, None).await
}

/// [`sign`] for a client's signing intent (audit C2), forwarded unchanged to every member in round
/// 1 (each verifies it itself and binds its session to it) and named by digest in round 2. The
/// caller (`Signer.Sign`) has verified it and bound it to the mTLS caller already. A member's
/// policy refusal (an invalid intent there, its rate limit, missing approvals under its rules)
/// excludes it like any failure; when no subset can sign, that refusal is the answer
/// (PERMISSION_DENIED / RESOURCE_EXHAUSTED, which the driver does not fail over on) rather than
/// UNAVAILABLE.
pub async fn sign_with_intent(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    message: &[u8],
    intent: Option<&crate::pb::SignedIntent>,
) -> Result<[u8; 64]> {
    if message.len() != CANTON_DIGEST_LEN {
        return Err(DaemonError::InvalidMessageLength {
            got: message.len(),
            expected: CANTON_DIGEST_LEN,
        });
    }
    let me = {
        let key_id = key_id.to_owned();
        node.blocking(move |n| n.signing_view(&key_id)).await?
    };
    if let Some(mark) = &me.stale {
        return Err(DaemonError::NotServing(format!(
            "this node's share of {key_id} is stale (epoch {} < {}): {} — not leading",
            mark.own_epoch, mark.newer_epoch, mark.reason
        )));
    }
    let threshold = usize::from(me.threshold);
    let started = std::time::Instant::now();

    // Leader first, then the rest in roster order.
    let mut ordered: Vec<&Arc<dyn PeerApi>> = peers.iter().filter(|p| p.identifier() == node.identifier).collect();
    ordered.extend(peers.iter().filter(|p| p.identifier() != node.identifier));

    let mut excluded: BTreeMap<Identifier, String> = BTreeMap::new();
    // The first signing-policy refusal by a member: the answer if no subset can sign.
    let mut policy_refusal: Option<DaemonError> = None;
    // Sharings peers reported that differ from ours and are not older (epoch-mismatch refusals).
    let mut elsewhere: BTreeMap<Identifier, crate::node::KeyVersion> = BTreeMap::new();
    let mut attempts = 0usize;
    // Members that answered "no room for this leader's sessions" (a cap on waiting sessions). Not
    // a failure of theirs: the room is this leader's own, filled by its earlier sessions. They are
    // skipped while other subsets remain, never excluded, and tried once more after a pass.
    let mut busy: BTreeSet<Identifier> = BTreeSet::new();
    let mut busy_retried = false;
    'passes: loop {
        for subset in combinations(ordered.len(), threshold) {
            // `combinations(ordered.len(), threshold)` yields only indices below `ordered.len()`.
            #[allow(clippy::indexing_slicing)]
            let members: Vec<&Arc<dyn PeerApi>> = subset.iter().map(|&i| ordered[i]).collect();
            if members.iter().any(|p| excluded.contains_key(&p.identifier()) || busy.contains(&p.identifier())) {
                continue;
            }
            if attempts >= MAX_SIGN_ATTEMPTS || started.elapsed() >= SIGN_BUDGET {
                break 'passes;
            }
            attempts += 1;
            if attempts > 1 {
                metrics::counter!(crate::metrics::SIGN_RETRIES).increment(1);
            }
            let ctx =
                crate::node::Round1Ctx { leader_view: Some(me.view), intent: intent.cloned(), ..Default::default() };
            match attempt(node, &members, key_id, message, &ctx, "sign").await {
                Ok(signature) => return Ok(signature),
                Err(Attempt::Fatal(e)) => return Err(e),
                Err(Attempt::Members(failed)) => {
                    for (id, e) in failed {
                        if is_sessions_full(&e) {
                            tracing::warn!(key_id, peer = ?id, error = %e, "a cosigner has no room for this leader's sign sessions; trying a subset without it");
                            busy.insert(id);
                            continue;
                        }
                        if policy_refusal.is_none() && is_policy_refusal(&e) {
                            policy_refusal = Some(clone_policy_refusal(&e));
                        }
                        if let DaemonError::EpochMismatch { peer, .. } = &e {
                            if peer.0 >= me.view.0 {
                                elsewhere.insert(id, *peer);
                            }
                        }
                        tracing::warn!(key_id, peer = ?id, error = %e, "excluding a cosigner from this signature");
                        excluded.insert(id, e.to_string());
                    }
                    if let Some((view, holders)) = quorum_elsewhere(&elsewhere, threshold) {
                        nudge_resolver(node, key_id);
                        return Err(DaemonError::NotServing(format!(
                            "{holders} cosigners hold sharing epoch {} (pkp {}…) of {key_id}, but this node \
                             holds epoch {} (pkp {}…) — not leading; another cosigner can sign",
                            view.0,
                            &hex::encode(view.1)[..12],
                            me.view.0,
                            &hex::encode(me.view.1)[..12]
                        )));
                    }
                }
            }
        }
        if !busy.is_empty() && !busy_retried {
            busy_retried = true;
            busy.clear();
            continue 'passes;
        }
        break;
    }
    let usable = ordered.len() - excluded.len();
    tracing::warn!(key_id, attempts, ?excluded, ?busy, "sign gave up: no t-subset of cosigners could sign");
    if let Some(refusal) = policy_refusal {
        return Err(refusal);
    }
    if !busy.is_empty() {
        // UNAVAILABLE: the driver fails over to another leader, which has its own room.
        return Err(DaemonError::NotServing(format!(
            "sign for {key_id}: cosigner(s) {busy:?} have no room for more of this leader's sign sessions \
             (and no subset without them could sign) — another cosigner can lead"
        )));
    }
    if usable < threshold {
        Err(DaemonError::ThresholdNotMet { needed: threshold, got: usable })
    } else {
        Err(DaemonError::NotServing(format!(
            "sign for {key_id} gave up after {attempts} attempt(s) in {:?} ({} cosigner(s) excluded)",
            started.elapsed(),
            excluded.len()
        )))
    }
}

/// A member's "no room for this leader's sessions" (a cap on waiting sign sessions), in process or
/// over gRPC (the `rutli-error: sessions-full` trailer).
fn is_sessions_full(e: &DaemonError) -> bool {
    match e {
        DaemonError::Core(rutli_frost_core::CoreError::SessionsFull { .. }) => true,
        DaemonError::Status(s) => s
            .metadata()
            .get(crate::error::ERROR_TRAILER)
            .is_some_and(|v| v.to_str().ok() == Some(crate::error::SESSIONS_FULL)),
        _ => false,
    }
}

/// A member refused for the signing policy (audit C2) rather than for being unable to sign.
fn is_policy_refusal(e: &DaemonError) -> bool {
    matches!(e, DaemonError::PolicyRefused(_) | DaemonError::RateLimited(_))
}

fn clone_policy_refusal(e: &DaemonError) -> DaemonError {
    match e {
        DaemonError::RateLimited(m) => DaemonError::RateLimited(m.clone()),
        other => DaemonError::PolicyRefused(other.to_string()),
    }
}

/// Why one signing attempt (one t-subset, one session) failed.
enum Attempt {
    /// These members failed (round 1, round 2, or an invalid share): another subset may work.
    Members(Vec<(Identifier, DaemonError)>),
    /// Not attributable to a member: give up.
    Fatal(DaemonError),
}

/// One signing session over exactly `members`: round 1 to each (fresh nonces, bound to `message`
/// and this signer set), round 2 to each, aggregate. On a member's failure the session is aborted
/// on every member still holding nonces for it, so nothing lingers until the pending TTL; a member
/// that already produced its share has burned its nonce and is unaffected.
///
/// Each member, this node's own share included, gets its own random session id, used for its
/// round 1, round 2 and abort. FROST needs no common id: the members agree on the message and the
/// commitment map (keyed by identifier), and each node keys its nonces and its single-use marker
/// by the id it was given. A member therefore never learns the id another member's copy lives
/// under, so it cannot open that id there first (the leader's round 1 would meet a duplicate and
/// exclude an honest node), abort it or send its round 2. The attempt id is for the leader's log
/// only and never leaves this node.
async fn attempt(
    node: &Arc<Node>,
    members: &[&Arc<dyn PeerApi>],
    key_id: &str,
    message: &[u8],
    base: &crate::node::Round1Ctx,
    prefix: &str,
) -> std::result::Result<[u8; 64], Attempt> {
    let attempt_id = new_id("attempt");
    let sessions: Vec<String> = members.iter().map(|_| new_id(prefix)).collect();
    // The members, not their session ids: the id map is what this design keeps from each member.
    tracing::debug!(
        key_id,
        attempt = %attempt_id,
        members = ?members.iter().map(|p| p.identifier()).collect::<Vec<_>>(),
        "sign attempt: one session id per member"
    );
    let mut open = OpenSessions { key_id: key_id.to_owned(), opened: Vec::new() };
    let mut signers = Vec::with_capacity(members.len());
    for p in members {
        signers.push(crate::hosted::identifier_index(p.identifier()).map_err(Attempt::Fatal)?);
    }
    let ctx = &crate::node::Round1Ctx { message: Some(message.to_vec()), signers: Some(signers), ..base.clone() };
    let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    // `sessions` has one id per member (built from `members` above), so the zip drops nothing.
    for (p, session) in members.iter().zip(&sessions) {
        // Noted before asking: a round 1 that times out or errors may still have opened the
        // session on the member, so a failure aborts it there too.
        open.opened.push(((*p).clone(), session.clone()));
        match p.sign_round1(key_id, session, ctx).await {
            Ok(c) => {
                commitments.insert(p.identifier(), c);
            }
            Err(e) => {
                metrics::counter!(crate::metrics::SIGN_ROUND1_SKIPS).increment(1);
                tracing::debug!(key_id, attempt = %attempt_id, peer = ?p.identifier(), "sign round 1 failed");
                open.abort_now().await;
                return Err(Attempt::Members(vec![(p.identifier(), e)]));
            }
        }
    }
    let intent_digest = ctx.intent.as_ref().map(crate::intent::intent_digest);
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for (p, session) in members.iter().zip(&sessions) {
        match p.sign_round2(key_id, session, message, &commitments, intent_digest.as_ref()).await {
            Ok(share) => {
                shares.insert(p.identifier(), share);
            }
            Err(e) => {
                tracing::debug!(key_id, attempt = %attempt_id, peer = ?p.identifier(), "sign round 2 failed");
                // Members before this one burned their nonce; this one and later ones may still
                // hold theirs — free them now.
                open.abort_now().await;
                return Err(Attempt::Members(vec![(p.identifier(), e)]));
            }
        }
    }
    // Every member answered round 2: every session is burned, nothing is left to abort.
    open.opened.clear();
    let (k, m) = (key_id.to_owned(), message.to_vec());
    match node.blocking(move |n| n.aggregate(&k, &m, &commitments, &shares)).await {
        Ok(signature) => Ok(signature),
        Err(e) => match culprit(&e) {
            Some(id) => {
                metrics::counter!(crate::metrics::INVALID_SIGNATURE_SHARES).increment(1);
                tracing::error!(key_id, peer = ?id, error = %e, "a cosigner returned an invalid signature share");
                Err(Attempt::Members(vec![(id, e)]))
            }
            None => Err(Attempt::Fatal(e)),
        },
    }
}

/// The cosigner frost's cheater detection blames for a failed aggregation, if any.
fn culprit(e: &DaemonError) -> Option<Identifier> {
    match e {
        DaemonError::Core(rutli_frost_core::CoreError::Frost(f)) | DaemonError::Frost(f) => f.culprit(),
        _ => None,
    }
}

/// A sharing (other than the leader's, not older) that at least `threshold` peers reported, with
/// how many did.
fn quorum_elsewhere(
    elsewhere: &BTreeMap<Identifier, crate::node::KeyVersion>,
    threshold: usize,
) -> Option<(crate::node::KeyVersion, usize)> {
    let mut counts: BTreeMap<crate::node::KeyVersion, usize> = BTreeMap::new();
    for v in elsewhere.values() {
        *counts.entry(*v).or_default() += 1;
    }
    counts.into_iter().find(|(_, n)| *n >= threshold)
}

/// Best-effort: if this node has a ceremony for `key_id` staged (it may be the one node that has
/// not committed yet), ask its resolver to settle it now instead of at the next pass.
fn nudge_resolver(node: &Arc<Node>, key_id: &str) {
    for rec in node.staged_records().into_iter().filter(|r| r.key_id == key_id) {
        let node = node.clone();
        tokio::spawn(async move {
            let _ = crate::ceremony::resolve(&node, &rec.ceremony_id).await;
        });
    }
}

/// Every `k`-element subset of `0..n` as sorted index lists, in lexicographic order — so with the
/// leader at index 0, every subset containing it comes first.
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..n {
            if n - i < k - cur.len() {
                break;
            }
            cur.push(i);
            go(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    if k > 0 && k <= n {
        go(0, n, k, &mut Vec::with_capacity(k), &mut out);
    }
    out
}

/// The split ceremony's sign test (`Signer.CeremonySignTest`): sign the key's fixed test digest
/// ([`Node::ceremony_test_message`], computed here from the key's provenance, never supplied by the
/// caller) with **exactly** the quorum `signers` — no substitution if one of them fails — so
/// `verify-key` can prove that every `t`-subset of cosigners signs. Returns (message, signature).
///
/// Deliberately separate from [`sign`]: the production path keeps its "first `t` responders"
/// quorum selection untouched.
pub async fn ceremony_sign_test(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    signers: &[u16],
) -> Result<([u8; 34], [u8; 64])> {
    let (message, view) = {
        let key_id = key_id.to_owned();
        node.blocking(move |n| Ok((n.ceremony_test_message(&key_id)?, n.signing_view(&key_id)?)))
            .await?
    };
    let threshold = view.threshold;
    let wanted: std::collections::BTreeSet<Identifier> = signers
        .iter()
        .map(|&i| Identifier::try_from(i).map_err(DaemonError::Frost))
        .collect::<Result<_>>()?;
    if wanted.len() != signers.len() || wanted.len() != usize::from(threshold) {
        return Err(DaemonError::Ceremony(format!(
            "a sign-test quorum is exactly {threshold} distinct cosigners, got {signers:?}"
        )));
    }
    let quorum: Vec<&Arc<dyn PeerApi>> =
        peers.iter().filter(|p| wanted.contains(&p.identifier())).collect();
    if quorum.len() != wanted.len() {
        return Err(DaemonError::Ceremony(format!("{signers:?} are not all in this node's roster")));
    }

    // One attempt over exactly this quorum, with the leader's sharing like any sign. No intent: each
    // member accepts a sign-test round only for its own test digest of the key.
    let ctx = crate::node::Round1Ctx { leader_view: Some(view.view), sign_test: true, ..Default::default() };
    match attempt(node, &quorum, key_id, &message, &ctx, "signtest").await {
        Ok(signature) => Ok((message, signature)),
        Err(Attempt::Fatal(e)) => Err(e),
        Err(Attempt::Members(mut failed)) => Err(failed.pop().map(|(_, e)| e).expect("one member error")),
    }
}

/// The sessions an attempt asked its members to open and has not seen used. A failure aborts them
/// ([`OpenSessions::abort_now`]); an attempt dropped before it finished (the driver's call was
/// cancelled or ran out of time, and tonic dropped the request's future) aborts them from `Drop`.
/// Without that they would stay on the members until the pending TTL, counted against this
/// leader's caps there, and a burst of cancelled calls would leave it no room. Each abort runs as
/// its own task, so it finishes even if the attempt is dropped while waiting for it, and the list is
/// taken when the abort starts, so no session is aborted twice by it.
struct OpenSessions {
    key_id: String,
    opened: Vec<(Arc<dyn PeerApi>, String)>,
}

impl OpenSessions {
    fn spawn_abort(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        if self.opened.is_empty() {
            return None;
        }
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let (opened, key_id) = (std::mem::take(&mut self.opened), self.key_id.clone());
        Some(runtime.spawn(async move { abort_sign(&opened, &key_id).await }))
    }

    async fn abort_now(&mut self) {
        if let Some(task) = self.spawn_abort() {
            let _ = task.await;
        }
    }
}

impl Drop for OpenSessions {
    fn drop(&mut self) {
        if !self.opened.is_empty() {
            tracing::debug!(key_id = %self.key_id, sessions = self.opened.len(), "sign attempt dropped before it finished; aborting its sessions");
            let _ = self.spawn_abort();
        }
    }
}

/// Best-effort: tell each quorum member to drop the in-flight session so its round-1 nonces are
/// freed now instead of at the pending-TTL sweep. Errors are swallowed — abort is a courtesy, and
/// the per-session TTL is the correctness backstop. Aborting a session a peer already completed
/// (round-2 done) is a harmless no-op.
async fn abort_sign(opened: &[(Arc<dyn PeerApi>, String)], key_id: &str) {
    metrics::counter!(crate::metrics::SIGN_ABORTS).increment(1);
    for (p, session_id) in opened {
        if let Err(e) = p.abort_sign(key_id, session_id).await {
            tracing::debug!(peer = ?p.identifier(), error = %e, "sign abort failed; nonces will TTL-expire");
        }
    }
}

/// Take the per-key ceremony guard on every peer before DKG/refresh crypto. Rolls back on the
/// first refusal so a partial fence never sticks.
///
/// For a ceremony led for a client intent, the rollback also aborts the ceremony id on every peer:
/// a fence writes no durable record, so without this the intent's id would stay unused everywhere
/// and another node (a compromised cosigner that refused its own fence, say) could lead the same
/// ceremony itself with the still-valid intent. The abort records a durable no-vote for the id on
/// every reachable node (an unknown id's no-vote, under the per-asker cap), so the intent is spent.
/// A client retries with a fresh intent (the driver and `rutli-cosigner refresh` mint one per
/// attempt).
///
/// The leader fences its own node first: that binds the ceremony to this leader on its own node
/// before any peer has seen the client's intent. A peer that races the remaining fences with the
/// intent it was shown can then bind at most the other nodes to itself, which stops the ceremony,
/// but never run it: every ceremony needs the leader's node, which takes parts 1–3 only from the
/// leader (and lets no one else release its fence).
async fn fence_all(
    peers: &Peers,
    ceremony_id: &str,
    key_id: &str,
    kind: CeremonyKind,
    expect: Option<(u64, [u8; 32])>,
    intent: Option<&pb::SignedIntent>,
) -> Result<()> {
    let mut fenced: Vec<&Arc<dyn PeerApi>> = Vec::new();
    let own_node_first = peers.iter().filter(|p| p.is_local()).chain(peers.iter().filter(|p| !p.is_local()));
    for p in own_node_first {
        match p.ceremony_begin(ceremony_id, key_id, kind, expect, intent).await {
            Ok(()) => fenced.push(p),
            Err(e) => {
                for q in &fenced {
                    let _ = q.ceremony_release(ceremony_id, key_id).await;
                }
                if intent.is_some() {
                    for q in peers {
                        if let Err(err) = q.ceremony_abort(ceremony_id).await {
                            tracing::debug!(peer = ?q.identifier(), error = %err, "abort after a refused fence failed");
                        }
                    }
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

async fn release_all(peers: &Peers, ceremony_id: &str, key_id: &str) {
    for p in peers {
        if let Err(e) = p.ceremony_release(ceremony_id, key_id).await {
            tracing::debug!(peer = ?p.identifier(), error = %e, "ceremony release failed");
        }
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ── cluster-hosted (non-FROST) keys ────────────────────────────────────────────────────────────

/// How many cosigners must durably hold a hosted key before the leader reports success.
///
/// 2 of 3 by default, matching the cluster's own fault model: requiring all three would mean you
/// cannot mint or rotate an encryption key while any node is down, which is strictly worse than
/// the single copy an HSM gives. This is only safe *with* anti-entropy and the replica-count
/// alert — both ship alongside it — because they are what turn an under-replicated write into a
/// transient state rather than a permanent one.
pub const DEFAULT_WRITE_QUORUM: usize = 2;

/// Whether an error means "this cosigner is not answering" as opposed to a real refusal.
///
/// Only transport-level failures count: a peer that answers with a conflict must never be treated
/// as absent, or two leaders could write the same key id concurrently.
fn is_unreachable(e: &DaemonError) -> bool {
    match e {
        DaemonError::Transport(_) => true,
        DaemonError::Status(s) => match s.code() {
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => true,
            // Our own client-side deadline (peer::PEER_RPC_TIMEOUT): tonic reports it as Cancelled
            // "Timeout expired". A peer that does not answer in time is as good as unreachable.
            tonic::Code::Cancelled => s.message().contains("Timeout expired"),
            // tonic reports a connection that failed below the RPC layer as Unknown with the
            // message "transport error" — which is what a stopped cosigner actually produces, as
            // opposed to the Unavailable one might expect. Match it narrowly: a genuine refusal
            // from our own code always carries a specific code (Aborted, FailedPrecondition, …),
            // never Unknown, so this cannot swallow a real conflict.
            tonic::Code::Unknown => {
                let m = s.message();
                m.contains("transport error") || m.contains("connection")
            }
            _ => false,
        },
        _ => false,
    }
}

/// Generate a hosted key on the leader and replicate it to the cluster.
///
/// Idempotent by `key_id`: if the key already exists anywhere, this repairs replicas instead of
/// minting a second key, so a client retry or driver failover can never produce two different keys
/// under one name.
///
/// Without a client generate intent: see [`generate_hosted_key_with_intent`].
pub async fn generate_hosted_key(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    spec: crate::hosted::HostedSpec,
    write_quorum: usize,
) -> Result<(crate::hosted::HostedKey, bool, usize)> {
    generate_hosted_key_with_intent(node, peers, key_id, spec, write_quorum, None).await
}

/// [`generate_hosted_key`] for a client's generate intent (purpose `generate-key`): the ceremony id
/// is the one the intent names (`genkey-<hex(request_id)>`), and the intent goes, unchanged, with
/// the fence to every node, which verifies it itself — key, spec, and that this node is the leader
/// it names — before it takes the guard. A node that does not verify generate intents (a 0.4.0
/// cosigner, `NodeInfo.hosted_protocol` < 2) is refused before anything is fenced. Without an
/// intent (an older client) the id is random and every node decides whether it accepts that
/// (`signing_policy.require_ceremony_intent`).
///
/// The leader fences its own node first, and that fence must succeed: it is where the leader's
/// own node verifies the intent, before anything is minted.
pub async fn generate_hosted_key_with_intent(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    spec: crate::hosted::HostedSpec,
    write_quorum: usize,
    intent: Option<&pb::SignedIntent>,
) -> Result<(crate::hosted::HostedKey, bool, usize)> {
    // A hosted key squatting on an import id would make the split ceremony's install fail, and one
    // under a FROST id that key's DKG. Every node refuses both too; this answers before the mesh.
    if crate::share_delivery::is_reserved_for_import(key_id) {
        return Err(DaemonError::ReservedKeyId(key_id.to_string()));
    }
    crate::node::refuse_unless_hosted_id(key_id)?;
    if spec.needs_every_node() {
        ensure_every_peer_supports(node, peers, spec).await?;
    }
    let ceremony_id = match intent {
        Some(i) => crate::intent::generate_ceremony_id_of(i)?,
        None => new_id(crate::intent::GENKEY_CEREMONY_PREFIX),
    };
    if intent.is_some() {
        require_hosted_protocol(node, peers, key_id).await?;
    }

    // Fence the key cluster-wide: the guard is per-key, so this also serializes against a
    // concurrent generate for the same id on another leader.
    //
    // Unlike DKG/refresh — all-party ceremonies where a missing peer means the ceremony cannot
    // proceed — a hosted-key write only needs `write_quorum` nodes. So an UNREACHABLE peer is
    // skipped rather than fatal: a node that is down cannot start a racing operation on this key
    // anyway. A peer that is reachable and *refuses* (something else holds the guard) still aborts,
    // because that is a genuine conflict. Without this distinction the 2-of-3 write quorum could
    // never actually be used with a node down, which is the entire point of it.
    //
    // The leader's own node first, and it may not be skipped: its fence is where this node checks
    // the client's intent before anything is minted, and it binds the generation to this leader
    // here before any peer has seen the intent.
    let mut fenced: Vec<&Arc<dyn PeerApi>> = Vec::new();
    let mut reachable: Vec<&Arc<dyn PeerApi>> = Vec::new();
    let own_first = peers
        .iter()
        .filter(|p| p.identifier() == node.identifier)
        .chain(peers.iter().filter(|p| p.identifier() != node.identifier));
    for p in own_first {
        let own = p.identifier() == node.identifier;
        match p.genkey_fence(&ceremony_id, key_id, spec.as_str(), intent).await {
            Ok(()) => {
                fenced.push(p);
                reachable.push(p);
            }
            Err(e) if !own && is_unreachable(&e) => {
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "cosigner unreachable while fencing a hosted-key write; continuing without it");
            }
            Err(e) => {
                release_fences(&fenced, &ceremony_id, key_id).await;
                return Err(e);
            }
        }
    }
    if reachable.len() < write_quorum {
        release_fences(&fenced, &ceremony_id, key_id).await;
        return Err(DaemonError::ThresholdNotMet { needed: write_quorum, got: reachable.len() });
    }

    let fenced_ids: Vec<Identifier> = fenced.iter().map(|p| p.identifier()).collect();
    let outcome =
        generate_hosted_fenced(node, peers, key_id, spec, write_quorum, &ceremony_id, &fenced_ids).await;
    release_fences(&fenced, &ceremony_id, key_id).await;
    outcome
}

/// Refuse a generation that carries a client generate intent while a reachable cosigner does not
/// verify generate intents (`NodeInfo.hosted_protocol` below [`HOSTED_PROTOCOL`]: a 0.4.0 node).
/// Such a node would refuse the fence anyway (a 0.4.0 node refuses an intent on a genkey fence);
/// this says why, before anything is fenced. A node that cannot be reached is skipped, as by the
/// fence: it takes no part in this generation and pulls the key later. One that answers but
/// cannot say is refused.
async fn require_hosted_protocol(node: &Arc<Node>, peers: &Peers, key_id: &str) -> Result<()> {
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        let who = peer_label(p.identifier());
        let problem = match p.hosted_protocol().await {
            Ok(v) if v >= HOSTED_PROTOCOL => continue,
            Err(e) if is_unreachable(&e) => continue,
            Ok(v) => format!("{who} speaks hosted-key protocol {v}"),
            Err(e) => format!("{who} could not report its hosted-key protocol ({e})"),
        };
        hosted_refusal("mixed-version");
        tracing::warn!(key_id, peer = %who, problem = %problem, "hosted-key generation refused before fencing: a reachable cosigner does not verify generate intents");
        return Err(DaemonError::CeremonyRefused(format!(
            "{problem}; a hosted-key generation with a client intent needs protocol {HOSTED_PROTOCOL} on \
             every reachable cosigner — finish upgrading the cluster first (existing hosted keys keep \
             working), or see docs/hosted-keys.md, Upgrading from 0.4.0"
        )));
    }
    Ok(())
}

/// The hosted-key creation protocol this node speaks (`NodeInfo.hosted_protocol`): 2 = it verifies
/// a client generate intent at its genkey fence. 0.4.0 nodes report 0.
pub const HOSTED_PROTOCOL: u32 = 2;

/// Refuse to create a `spec` key unless every other cosigner reports the spec (`NodeInfo`).
///
/// A cosigner that predates the spec cannot store or serve the key, and worse, answers for it as if
/// it did not exist (read-repair skips what it cannot parse; `KeyInfo` says `exists: false`) — the
/// shape that turns a lagging replica into a Canton `KmsDecryptError`. So unlike an RSA/AES write,
/// which commits at the write quorum with a node down, an EC key is only created when every node is
/// up and upgraded: a peer that cannot be asked is refused too, because it cannot be shown to be
/// upgraded. Key creation is rare (onboarding, rotation); this costs no availability on any
/// serving path.
async fn ensure_every_peer_supports(
    node: &Arc<Node>,
    peers: &Peers,
    spec: crate::hosted::HostedSpec,
) -> Result<()> {
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        let who = crate::hosted::identifier_index(p.identifier()).map(|i| format!("cosigner {i}"))?;
        let problem = match p.hosted_specs().await {
            Ok(specs) if specs.iter().any(|s| s == spec.as_str()) => continue,
            Ok(_) => format!("{who} does not support it"),
            Err(e) => format!("{who} could not be asked ({e})"),
        };
        return Err(DaemonError::Config(format!(
            "refusing to create an {} key: {problem}. Every cosigner must run a release that serves \
             {} — and be up — before keys of that spec are created (docs/hosted-keys.md, rollout \
             order). RSA and AES keys are unaffected.",
            spec.as_str(),
            spec.as_str()
        )));
    }
    Ok(())
}

async fn generate_hosted_fenced(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    spec: crate::hosted::HostedSpec,
    write_quorum: usize,
    ceremony_id: &str,
    fenced: &[Identifier],
) -> Result<(crate::hosted::HostedKey, bool, usize)> {
    // RSA-2048 keygen is hundreds of milliseconds of pure CPU. Running it inline would park a
    // tokio worker for that whole time — with a small worker pool, a burst of key generations could
    // starve health checks and in-flight signing on the same node. Do the idempotency check here
    // (cheap, needs the keystore) and the keygen off-runtime.
    let existing = {
        let key_id = key_id.to_owned();
        node.blocking(move |n| n.hosted_existing(&key_id, spec)).await?
    };
    let (key, created) = match existing {
        Some(existing) => (existing, false),
        // Never mint a second key under an id a peer already holds (a generation whose leader died
        // after replicating, a retry through another leader): adopt it when two peers agree on it,
        // and refuse otherwise.
        None => match adopt_existing(node, peers, key_id, spec, write_quorum).await? {
            Some(adopted) => (adopted, false),
            None => {
                let key = tokio::task::spawn_blocking(move || {
                    crate::hosted::HostedKey::generate(spec, crate::hosted::now_secs())
                })
                .await
                .map_err(|e| DaemonError::Config(format!("key generation task failed: {e}")))??;
                // A new key is written here only after the write quorum holds it (below): a leader
                // that dies before that leaves no copy of its own.
                (key, true)
            }
        },
    };
    let public_der = if spec.is_asymmetric() { key.public_key_der()? } else { Vec::new() };

    // Replicate to every other peer, wrapping per recipient. The leader counts itself: it holds
    // the key already, or writes it once the peers' replicas make the quorum.
    let mut replicas = 1usize;
    let mut failures = Vec::new();
    let mut conflict = None;
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        match replicate_to(node, p.as_ref(), ceremony_id, key_id, &key, &public_der).await {
            Ok(()) => replicas += 1,
            // A peer that holds other material under the id (or found another peer that does):
            // never outvoted by the replicas that agree. Stop here and roll back.
            Err(e) if is_material_conflict(&e) => {
                conflict = Some((peer_label(p.identifier()), e));
                break;
            }
            Err(e) => {
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "hosted key replication failed");
                failures.push(e);
            }
        }
    }
    if let Some((who, e)) = conflict {
        // Each node removes only a key it created in this generation, while this leader still
        // holds its fence; a copy that was there before stays.
        rollback_generation(peers, fenced, ceremony_id, key_id).await;
        metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
        hosted_refusal("generate-conflict");
        tracing::error!(
            key_id,
            peer = %who,
            error = %e,
            "hosted key generation ABORTED: a cosigner holds different material under this id — \
             rolled back; resolve the conflict by hand (docs/hosted-keys.md)"
        );
        return Err(DaemonError::HostedConflict {
            key_id: key_id.to_string(),
            detail: format!("{who} holds different material ({e}); the generation was aborted and rolled back"),
        });
    }

    // A peer holding a tombstone for the id (audit M2) means the id was deleted: generating it
    // again needs the tombstone cleared on EVERY node first, so one refusal stops the generation.
    let tombstoned_somewhere = failures.iter().any(|e| e.to_string().contains("is tombstoned"));
    if replicas < write_quorum || tombstoned_somewhere {
        // Below quorum the key is not durable enough to hand out: a single node holding the only
        // copy is exactly the failure this feature exists to prevent. Roll back so the id stays
        // free for a clean retry. Each node removes only a key it created in this generation.
        rollback_generation(peers, fenced, ceremony_id, key_id).await;
        if tombstoned_somewhere {
            return Err(crate::node::tombstoned(key_id));
        }
        return Err(DaemonError::ThresholdNotMet { needed: write_quorum, got: replicas });
    }
    if created {
        let (id, stored, ceremony) = (key_id.to_owned(), key.clone(), ceremony_id.to_owned());
        if let Err(e) = node.blocking(move |n| n.hosted_store_for(&id, &stored, Some(&ceremony))).await {
            rollback_generation(peers, fenced, ceremony_id, key_id).await;
            return Err(e);
        }
    }
    if replicas < peers.len() {
        tracing::warn!(
            key_id,
            replicas,
            expected = peers.len(),
            "hosted key is under-replicated — anti-entropy will repair it"
        );
    }
    Ok((key, created, replicas))
}

/// Roll an aborted generation back on every node it fenced: each removes only a key it created in
/// this generation, while the fence is still held. A node the purge does not reach may keep that
/// copy: logged with the node and the key, and counted (`rutli_hosted_rollback_incomplete_total`).
async fn rollback_generation(peers: &Peers, fenced: &[Identifier], ceremony_id: &str, key_id: &str) {
    for p in peers.iter().filter(|p| fenced.contains(&p.identifier())) {
        if let Err(e) = p.purge_key(ceremony_id, key_id).await {
            metrics::counter!(crate::metrics::HOSTED_ROLLBACK_INCOMPLETE).increment(1);
            tracing::warn!(
                peer = ?p.identifier(),
                key_id,
                ceremony_id,
                error = %e,
                "the rollback of an aborted hosted-key generation did not reach this cosigner: a copy \
                 the generation wrote may remain there (docs/hosted-keys.md, \"A leader that dies\")"
            );
        }
    }
}

async fn replicate_to(
    node: &Node,
    peer: &dyn PeerApi,
    ceremony_id: &str,
    key_id: &str,
    key: &crate::hosted::HostedKey,
    public_der: &[u8],
) -> Result<()> {
    let (recipient, reported_pub) = peer.node_info().await?;
    // Wrap only to the key pinned for that roster slot, never to whatever the peer reports: a
    // peer answering under another node's number, or with a key other than its pin (a wrong seal
    // bundle mounted, an impostor), gets nothing.
    let expected = crate::hosted::identifier_index(peer.identifier())?;
    if recipient != expected {
        return Err(DaemonError::Disagreement(format!(
            "peer {expected} reports itself as node {recipient} — refusing to replicate {key_id} to it"
        )));
    }
    let recipient_pub = node.dist_public_key_for(recipient)?;
    if reported_pub != recipient_pub {
        return Err(DaemonError::Disagreement(format!(
            "peer {recipient} reports distribution key {}, but its pinned key is {} — wrong seal \
             bundle on that node, or a wrong pin here; refusing to replicate {key_id} to it",
            hex::encode(reported_pub),
            hex::encode(recipient_pub)
        )));
    }
    let wrapped = node.hosted_wrap_for(key_id, key, recipient, &recipient_pub)?;
    let commitment = peer
        .replicate_key(ceremony_id, key_id, key.spec.as_str(), public_der, &wrapped)
        .await?;
    // The peer's commitment must match ours, or it stored something else under this id.
    if commitment != node.hosted_commitment(key)? {
        return Err(DaemonError::HostedConflict {
            key_id: key_id.to_string(),
            detail: format!("{} answered with a commitment to different material", peer_label(peer.identifier())),
        });
    }
    Ok(())
}

/// Whether a replica's refusal means it holds (or saw) other material under the id: this release's
/// [`DaemonError::HostedConflict`] (in process, or decoded from the `hosted-conflict` trailer), or
/// a 0.4.0 node's create-once refusal (ALREADY_EXISTS, "... with different material ...").
pub(crate) fn is_material_conflict(e: &DaemonError) -> bool {
    match e {
        DaemonError::HostedConflict { .. } => true,
        DaemonError::KeyExists(m) => m.contains("different material"),
        DaemonError::Status(s) => {
            s.code() == tonic::Code::AlreadyExists && s.message().contains("different material")
        }
        _ => false,
    }
}

fn peer_label(id: Identifier) -> String {
    match crate::hosted::identifier_index(id) {
        Ok(i) => format!("cosigner {i}"),
        Err(_) => format!("{id:?}"),
    }
}

/// Count material from a peer that this node refuses: a time in the future, or anything else that
/// does not open or validate.
fn count_bad_material(e: &DaemonError) {
    if matches!(e, DaemonError::HostedInvalid(_)) {
        hosted_refusal("timestamp")
    } else {
        hosted_refusal("invalid")
    }
}

/// Count one refusal in `rutli_hosted_replication_refusals_total{reason}` (the reasons are listed
/// in [`crate::metrics::HOSTED_REFUSAL_REASONS`]).
pub(crate) fn hosted_refusal(reason: &'static str) {
    metrics::counter!(crate::metrics::HOSTED_REPLICATION_REFUSALS, "reason" => reason).increment(1);
}

async fn release_fences(fenced: &[&Arc<dyn PeerApi>], ceremony_id: &str, key_id: &str) {
    for p in fenced {
        let _ = p.ceremony_release(ceremony_id, key_id).await;
    }
}

/// Delete a hosted key across the cluster (audit M2): every node verifies the client's delete
/// intent itself and replaces the key with a tombstone. Fenced like a generation, so a concurrent
/// generate cannot interleave. A node that is down gets the tombstone from anti-entropy (a valid
/// tombstone beats a key), so this succeeds once `write_quorum` nodes hold it. Returns (whether
/// any node held the key live, how many nodes hold the tombstone).
pub async fn delete_hosted_key(
    peers: &Peers,
    key_id: &str,
    intent: &pb::SignedIntent,
    write_quorum: usize,
) -> Result<(bool, usize)> {
    let ceremony_id = new_id("delkey");
    let mut fenced: Vec<&Arc<dyn PeerApi>> = Vec::new();
    // Nodes that hold nothing hosted under a non-hosted id (they refuse its fence and its
    // tombstone with NotHostedKeyId): the cleanup of a key squatted on a FROST id.
    let mut nothing_here = 0usize;
    for p in peers {
        match p.ceremony_fence(&ceremony_id, key_id, "delkey").await {
            Ok(()) => fenced.push(p),
            Err(e) if is_unreachable(&e) => {
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "cosigner unreachable while fencing a hosted-key delete; anti-entropy will bring it the tombstone");
            }
            // A node that holds nothing under a non-hosted id (the cleanup of a key squatted on a
            // FROST id before 0.4.0-rc.6): nothing to delete there, and no tombstone may be recorded.
            Err(e) if is_not_hosted_id(&e) => {
                tracing::info!(peer = ?p.identifier(), key_id, "no hosted record under a non-hosted id on this cosigner; skipping it");
                nothing_here += 1;
            }
            Err(e) => {
                release_fences(&fenced, &ceremony_id, key_id).await;
                return Err(e);
            }
        }
    }
    let (mut deleted_anywhere, mut tombstones, mut refusal) = (false, 0usize, None);
    for p in &fenced {
        match p.delete_key(&ceremony_id, key_id, intent).await {
            Ok(converted) => {
                deleted_anywhere |= converted;
                tombstones += 1;
            }
            Err(e) if is_not_hosted_id(&e) => nothing_here += 1, // its record went meanwhile
            Err(e) => {
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "hosted key delete refused or failed on peer");
                if refusal.is_none() && !is_unreachable(&e) {
                    refusal = Some(e);
                }
            }
        }
    }
    release_fences(&fenced, &ceremony_id, key_id).await;
    // The cleanup of a squatted non-hosted id: no tombstone may be recorded where nothing hosted
    // is, so the write quorum cannot apply. It succeeds when every node answered — a tombstone
    // where a record was, "nothing here" elsewhere — with no refusal, and at least one node held
    // a record: on success the nodes report nothing hosted left under the id. Nothing anywhere (a
    // typo, a live FROST key) is NOT_FOUND, not a delete.
    if crate::node::refuse_unless_hosted_id(key_id).is_err() {
        if refusal.is_none() && tombstones + nothing_here == peers.len() {
            if tombstones == 0 {
                return Err(DaemonError::UnknownKey(format!(
                    "{key_id} (nothing hosted under this non-hosted id on any cosigner)"
                )));
            }
            return Ok((deleted_anywhere, tombstones));
        }
        return Err(refusal.unwrap_or(DaemonError::ThresholdNotMet { needed: peers.len(), got: tombstones + nothing_here }));
    }
    if tombstones < write_quorum {
        // A node's refusal (an invalid intent, a role it does not grant) is the answer, not "too
        // few nodes"; tombstones already written stay and propagate.
        return Err(refusal.unwrap_or(DaemonError::ThresholdNotMet { needed: write_quorum, got: tombstones }));
    }
    if tombstones < peers.len() {
        tracing::warn!(key_id, tombstones, expected = peers.len(), "hosted key delete reached only some nodes — anti-entropy propagates the tombstone");
    }
    Ok((deleted_anywhere, tombstones))
}

/// [`DaemonError::NotHostedKeyId`], in process or as a peer's INVALID_ARGUMENT naming it.
fn is_not_hosted_id(e: &DaemonError) -> bool {
    match e {
        DaemonError::NotHostedKeyId(_) => true,
        DaemonError::Status(s) => s.code() == tonic::Code::InvalidArgument && s.message().contains("is not a hosted-key id"),
        _ => false,
    }
}

/// How many cosigners currently hold `key_id` (for reporting and the replica alert).
pub async fn hosted_replica_count(peers: &Peers, key_id: &str) -> usize {
    let mut n = 0;
    for p in peers {
        if let Ok(keys) = p.list_keys().await {
            if keys.iter().any(|(id, _, _)| id == key_id) {
                n += 1;
            }
        }
    }
    n
}

/// How many peers must return the same material before this node stores a hosted key it does not
/// hold (read-repair, the anti-entropy sweep, a leader adopting an existing key). A constant, also
/// for five nodes: the threat model is one compromised cosigner, and two agreeing peers means at
/// least one honest one.
pub const PULL_AGREEMENT: usize = 2;

/// How long a replication check waits for one peer's copy of a hosted key. Shorter than
/// [`crate::peer::PEER_RPC_TIMEOUT`]: a push handler asks the other peers before it answers the
/// generation's leader, whose own call to it has that deadline.
pub const PEER_COPY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// What one peer holds under a hosted key id, as this node sees it.
///
/// The rule every decision below follows: **only an answer counts.** A peer that is silent (down,
/// or slower than [`PEER_COPY_TIMEOUT`]) is unknown, never "does not hold it"; a peer whose answer
/// this node cannot use (does not open or validate, a time in the future, a tombstone whose delete
/// intent does not verify) holds something unknown, never nothing and never agreement.
enum PeerCopy {
    /// A copy that opened and validated here, with this node's commitment to it.
    Holds { commitment: Vec<u8>, key: crate::hosted::HostedKey },
    /// NOT_FOUND: the peer holds nothing under the id.
    Absent,
    /// The peer holds a tombstone for the id (its delete intent not yet checked here).
    Tombstone(Box<pb::KeyManifest>),
    /// It answered with something this node refuses. Logged and counted when seen.
    Unusable,
    /// No answer in time, or a refusal that says nothing about the key.
    Silent,
}

/// Every peer's copy of `key_id` (this node and `exclude` left out, each roster node once), asked
/// concurrently, each with [`PEER_COPY_TIMEOUT`]. A copy is unwrapped and validated here, and the
/// commitment computed here, never taken from the peer.
async fn peer_copies(
    node: &Arc<Node>,
    peers: &[Arc<dyn PeerApi>],
    key_id: &str,
    exclude: Option<u16>,
) -> Vec<(u16, PeerCopy)> {
    let mut asked = tokio::task::JoinSet::new();
    let mut seen = std::collections::HashSet::new();
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        let Ok(id) = crate::hosted::identifier_index(p.identifier()) else { continue };
        // A roster entry listed twice is one node: it counts once.
        if Some(id) == exclude || !seen.insert(id) {
            continue;
        }
        let (p, id_owned) = (p.clone(), key_id.to_owned());
        asked.spawn(async move { (id, tokio::time::timeout(PEER_COPY_TIMEOUT, p.fetch_key_state(&id_owned)).await) });
    }
    let mut out = Vec::new();
    while let Some(joined) = asked.join_next().await {
        // A task that failed (panicked) is a peer that did not answer: counted silent below.
        let Ok((peer, answer)) = joined else { continue };
        let copy = match answer {
            Err(_) => PeerCopy::Silent,
            Ok(Err(e)) if is_not_found(&e) => PeerCopy::Absent,
            Ok(Err(e)) => {
                tracing::debug!(key_id, peer, error = %e, "no usable answer from peer for a hosted key");
                PeerCopy::Silent
            }
            Ok(Ok(crate::peer::FetchedCopy::Tombstone(t))) => PeerCopy::Tombstone(t),
            Ok(Ok(crate::peer::FetchedCopy::Key { spec, wrapped })) => {
                let opened = crate::hosted::HostedSpec::parse(&spec)
                    .and_then(|spec| node.hosted_unwrap(key_id, spec, &wrapped))
                    .and_then(|key| Ok((node.hosted_commitment(&key)?, key)));
                match opened {
                    Ok((commitment, key)) => PeerCopy::Holds { commitment, key },
                    Err(e) => {
                        count_bad_material(&e);
                        tracing::warn!(key_id, peer, error = %e, "a peer's copy of a hosted key is refused: it does not open or validate here");
                        PeerCopy::Unusable
                    }
                }
            }
        };
        out.push((peer, copy));
    }
    for id in seen {
        if Some(id) != exclude && !out.iter().any(|(p, _)| *p == id) {
            out.push((id, PeerCopy::Silent));
        }
    }
    out.sort_by_key(|(peer, _)| *peer);
    out
}

/// NOT_FOUND, in process or over the mesh.
fn is_not_found(e: &DaemonError) -> bool {
    match e {
        DaemonError::UnknownKey(_) => true,
        DaemonError::Status(s) => s.code() == tonic::Code::NotFound,
        _ => false,
    }
}

/// The peers' answers about one key id, sorted by kind.
#[derive(Default)]
struct Tally {
    holders: BTreeMap<Vec<u8>, Vec<(u16, crate::hosted::HostedKey)>>,
    absent: Vec<u16>,
    tombstones: Vec<(u16, Box<pb::KeyManifest>)>,
    unusable: Vec<u16>,
    silent: Vec<u16>,
}

impl Tally {
    fn of(copies: Vec<(u16, PeerCopy)>) -> Self {
        let mut t = Tally::default();
        for (peer, copy) in copies {
            match copy {
                PeerCopy::Holds { commitment, key } => t.holders.entry(commitment).or_default().push((peer, key)),
                PeerCopy::Absent => t.absent.push(peer),
                PeerCopy::Tombstone(m) => t.tombstones.push((peer, m)),
                PeerCopy::Unusable => t.unusable.push(peer),
                PeerCopy::Silent => t.silent.push(peer),
            }
        }
        t
    }

    /// (peer, short commitment) of every holder, when they hold different material.
    fn disagreement(&self) -> Option<Vec<(u16, String)>> {
        (self.holders.len() > 1).then(|| {
            self.holders
                .iter()
                .flat_map(|(c, holders)| holders.iter().map(move |(p, _)| (*p, hex::encode(c.get(..6).unwrap_or(c.as_slice())))))
                .collect()
        })
    }

    fn supporters(&self) -> Vec<u16> {
        self.holders.values().flatten().map(|(p, _)| *p).collect()
    }

    /// The agreed key: [`PULL_AGREEMENT`] peers return the same material, no peer returns other
    /// material, and **every** peer answered with something usable — a silent or unusable peer
    /// may hold other material, so it blocks a confirmation. Of the supporters' times, the latest
    /// creation time and the latest undelete time (`None` only when no supporter has one): the
    /// times are not committed to, and an earlier time would let a delete intent issued before the
    /// real creation or undelete apply. Every supporter's times are already bounded by now plus
    /// the clock skew.
    fn confirmed(&self) -> Option<(crate::hosted::HostedKey, Vec<u16>)> {
        if self.holders.len() != 1 || !self.silent.is_empty() || !self.unusable.is_empty() || !self.tombstones.is_empty() {
            return None;
        }
        let holders = self.holders.values().next()?;
        if holders.len() < PULL_AGREEMENT {
            return None;
        }
        let mut key = holders.first()?.1.clone();
        key.created_at = holders.iter().map(|(_, k)| k.created_at).max().unwrap_or(key.created_at);
        key.undeleted_at_ms = holders.iter().filter_map(|(_, k)| k.undeleted_at_ms).max();
        Some((key, holders.iter().map(|(p, _)| *p).collect()))
    }

    /// Nothing usable was returned at all: no holder, no unusable answer, no tombstone left.
    fn none_held(&self) -> bool {
        self.holders.is_empty() && self.unusable.is_empty() && self.tombstones.is_empty()
    }
}

/// How many distinct roster nodes `peers` and this node make.
fn roster_size(node: &Node, peers: &[Arc<dyn PeerApi>]) -> usize {
    let mut ids: std::collections::HashSet<Identifier> = peers.iter().map(|p| p.identifier()).collect();
    ids.insert(node.identifier);
    ids.len()
}

/// Whether enough nodes said "I do not hold it" for this node to conclude that no node does: a
/// written key sits on at least `write_quorum` nodes, so `n - write_quorum + 1` explicit absences
/// (this node included) leave no room for a written copy among the nodes that did not answer.
fn absence_is_proven(n: usize, write_quorum: usize, absent_peers: usize) -> bool {
    let q = write_quorum.clamp(1, n.max(1));
    absent_peers + 1 > n - q
}

/// Apply the peers' tombstones for `key_id` here, with the checks the sweep applies (each delete
/// intent verified by this node). Returns whether the id is deleted: this node now holds a
/// tombstone for it, or a peer's tombstone verified here (also where this node's own tombstone was
/// cleared by hand, which it does not take back). A tombstone that does not verify is logged and
/// moved to `unusable`.
async fn apply_peer_tombstones(node: &Arc<Node>, key_id: &str, t: &mut Tally) -> Result<bool> {
    let mut verified = false;
    for (peer, m) in std::mem::take(&mut t.tombstones) {
        match apply_peer_tombstone(node, &m).await {
            Ok(outcome) => {
                verified = true;
                if outcome != crate::node::TombstoneOutcome::Already {
                    tracing::warn!(key_id, from = peer, ?outcome, "applied a peer's tombstone before pulling: the key is deleted");
                }
            }
            Err(e) => {
                tracing::error!(key_id, peer, error = %e, "REFUSED a peer's tombstone — an answer this node cannot use");
                t.unusable.push(peer);
            }
        }
    }
    let id = key_id.to_owned();
    Ok(verified || node.blocking(move |n| n.hosted_tombstoned(&id)).await?)
}

/// Apply one peer tombstone (a `KeyManifest` with `tombstone` set) on this node, verifying its
/// delete intent here. Shared by the sweep, read-repair, a leader's look and a push check.
async fn apply_peer_tombstone(node: &Arc<Node>, t: &pb::KeyManifest) -> Result<crate::node::TombstoneOutcome> {
    // A deletion time in the future is refused like a key's: now plus the clock skew allowance.
    let limit = crate::intent::now_ms().saturating_add(node.hosted_skew_ms());
    if t.deleted_at_ms > limit {
        hosted_refusal("timestamp");
        return Err(DaemonError::HostedInvalid(format!(
            "peer tombstone for {}: deleted_at {} ms lies in the future (limit {limit} ms)",
            t.key_id, t.deleted_at_ms
        )));
    }
    let intent = <pb::SignedIntent as prost::Message>::decode(t.delete_intent.as_slice()).map_err(|e| {
        crate::intent::refused_delete("malformed", format!("peer tombstone for {}: {e}", t.key_id))
    })?;
    let info = crate::node::DeletedKeyInfo { spec: t.spec.clone(), created_at: t.created_at, commitment: t.commitment.clone() };
    let (deleted_at_ms, id) = (t.deleted_at_ms, t.key_id.clone());
    node.blocking(move |n| {
        n.hosted_apply_tombstone(&id, &intent, crate::intent::Expiry::Propagated { deleted_at_ms }, Some(&info))
    })
    .await
}

/// Pull a hosted key this node is missing (the sweep, and tests). Unthrottled: read-repair on the
/// request path goes through [`read_repair`].
///
/// Without this, a decrypt that lands on a lagging replica would return NOT_FOUND to Canton — and
/// the driver correctly does not fail over on NOT_FOUND, since that is normally authoritative.
/// Repairing on demand is what makes NOT_FOUND trustworthy.
///
/// `Ok(true)`: held (now or before). `Ok(false)` (NOT_FOUND): tombstoned here or at a peer that
/// answered (the tombstone is applied here first), or no node holds it — and enough nodes said so
/// ([`absence_is_proven`]). The key is stored only when [`Tally::confirmed`]. Everything else —
/// one copy, copies that disagree, a silent or unusable peer — is
/// [`DaemonError::HostedUnconfirmed`] (UNAVAILABLE), so the caller fails over.
pub async fn repair_hosted_key(node: &Arc<Node>, peers: &Peers, key_id: &str) -> Result<bool> {
    match locally_settled(node, key_id).await? {
        Some(answer) => Ok(answer),
        None => pull_missing(node, peers, key_id).await,
    }
}

/// [`repair_hosted_key`] for a request: within this node's read-repair ceiling
/// ([`crate::node::REPAIR_FANOUT_PER_SEC`]). Over it, UNAVAILABLE — never NOT_FOUND, so a client
/// that floods made-up ids cannot hide a real key; the driver fails over.
pub async fn read_repair(node: &Arc<Node>, peers: &Peers, key_id: &str) -> Result<bool> {
    if let Some(answer) = locally_settled(node, key_id).await? {
        return Ok(answer);
    }
    if !node.take_repair_token() {
        hosted_refusal("throttled");
        tracing::debug!(key_id, "read-repair ceiling reached: answering UNAVAILABLE without asking the peers");
        return Err(DaemonError::HostedUnconfirmed {
            key_id: key_id.to_string(),
            detail: "this node's read-repair ceiling is reached; retry, or ask another cosigner".into(),
        });
    }
    pull_missing(node, peers, key_id).await
}

/// Held here (`Some(true)`), tombstoned here (`Some(false)`: a deleted key is never pulled back,
/// checked before any peer is asked), or neither (`None`).
async fn locally_settled(node: &Arc<Node>, key_id: &str) -> Result<Option<bool>> {
    if hosted_exists(node, key_id).await? {
        return Ok(Some(true));
    }
    let id = key_id.to_owned();
    if node.blocking(move |n| n.hosted_tombstoned(&id)).await? {
        return Ok(Some(false));
    }
    Ok(None)
}

async fn pull_missing(node: &Arc<Node>, peers: &Peers, key_id: &str) -> Result<bool> {
    let n = roster_size(node, peers);
    let mut t = Tally::of(peer_copies(node, peers, key_id, None).await);
    if !t.tombstones.is_empty() && apply_peer_tombstones(node, key_id, &mut t).await? {
        return Ok(false);
    }
    if let Some(held) = t.disagreement() {
        metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
        hosted_refusal("disagreement");
        tracing::error!(
            key_id,
            peers = ?held,
            "hosted key CONFLICT: peers hold different material under this id — this node \
             stores neither and answers UNAVAILABLE; resolve by hand (docs/hosted-keys.md)"
        );
        return Err(DaemonError::HostedUnconfirmed {
            key_id: key_id.to_string(),
            detail: format!("peers hold different material (peer, commitment): {held:?}"),
        });
    }
    if t.none_held() {
        if absence_is_proven(n, node.hosted_write_quorum(), t.absent.len()) {
            return Ok(false);
        }
        hosted_refusal("unconfirmed");
        tracing::warn!(
            key_id,
            absent = ?t.absent,
            silent = ?t.silent,
            "too few cosigners answered for this node to say a hosted key does not exist — \
             answering UNAVAILABLE, not NOT_FOUND"
        );
        return Err(DaemonError::HostedUnconfirmed {
            key_id: key_id.to_string(),
            detail: format!(
                "{} of {n} cosigners answered that they do not hold it (this one included), {} silent",
                t.absent.len() + 1,
                t.silent.len()
            ),
        });
    }
    if let Some((key, supporters)) = t.confirmed() {
        let id = key_id.to_owned();
        node.blocking(move |n| n.hosted_store(&id, &key)).await?;
        tracing::info!(key_id, from = ?supporters, "pulled a missing hosted key, confirmed by every peer");
        return Ok(true);
    }
    hosted_refusal("unconfirmed");
    tracing::warn!(
        key_id,
        holders = ?t.supporters(),
        refused = ?t.unusable,
        silent = ?t.silent,
        "a missing hosted key is not confirmed: fewer than two peers hold the same copy, or a peer \
         is silent or answered with something unusable — not pulled; this node answers UNAVAILABLE \
         for it until every peer answers"
    );
    Err(DaemonError::HostedUnconfirmed {
        key_id: key_id.to_string(),
        detail: format!(
            "holders {:?}, unusable {:?}, silent {:?}; {PULL_AGREEMENT} agreeing copies and an answer from every peer are needed",
            t.supporters(),
            t.unusable,
            t.silent
        ),
    })
}

/// A leader that lacks `key_id`: whether a peer already holds it. `Some(key)` when the copies are
/// confirmed ([`Tally::confirmed`]; stored here, not as created by this generation, so a rollback
/// leaves it); `None` — mint — only when no peer holds anything under the id **and** enough nodes
/// said so ([`absence_is_proven`]: `n - write_quorum + 1`, this one included). A key the client was
/// given sits on at least `write_quorum` nodes, so it cannot hide among the silent ones; with
/// 2-of-3 this node and one peer are enough, so one node down still mints. Otherwise, and for one
/// copy, copies that disagree, an unusable answer or a peer's tombstone, the generation is refused:
/// minting a second key over a copy would fork the id.
async fn adopt_existing(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    spec: crate::hosted::HostedSpec,
    write_quorum: usize,
) -> Result<Option<crate::hosted::HostedKey>> {
    let mut t = Tally::of(peer_copies(node, peers, key_id, None).await);
    if !t.tombstones.is_empty() && apply_peer_tombstones(node, key_id, &mut t).await? {
        return Err(crate::node::tombstoned(key_id));
    }
    if let Some(held) = t.disagreement() {
        metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
        hosted_refusal("generate-conflict");
        tracing::error!(key_id, peers = ?held, "hosted key generation refused: peers hold different material under this id");
        return Err(DaemonError::HostedConflict {
            key_id: key_id.to_string(),
            detail: format!("peers hold different material (peer, commitment): {held:?}"),
        });
    }
    if t.none_held() {
        let n = roster_size(node, peers);
        if absence_is_proven(n, write_quorum, t.absent.len()) {
            return Ok(None);
        }
        hosted_refusal("unconfirmed");
        tracing::warn!(
            key_id,
            absent = ?t.absent,
            silent = ?t.silent,
            "hosted key generation refused: too few cosigners answered that they hold nothing under \
             this id — a key could sit on the silent ones"
        );
        return Err(DaemonError::HostedUnconfirmed {
            key_id: key_id.to_string(),
            detail: format!(
                "{} of {n} cosigners answered that they hold nothing under the id (this one included); \
                 {} needed before a new key is minted",
                t.absent.len() + 1,
                n + 1 - write_quorum.clamp(1, n.max(1))
            ),
        });
    }
    if let Some((key, supporters)) = t.confirmed() {
        if key.spec != spec {
            return Err(DaemonError::KeyExists(format!(
                "{key_id} already exists with spec {} (requested {})",
                key.spec.as_str(),
                spec.as_str()
            )));
        }
        let (id, stored) = (key_id.to_owned(), key.clone());
        node.blocking(move |n| n.hosted_store(&id, &stored)).await?;
        tracing::info!(key_id, from = ?supporters, "generation found the key on agreeing peers: adopted, not minted");
        return Ok(Some(key));
    }
    hosted_refusal("unconfirmed");
    tracing::warn!(
        key_id,
        holders = ?t.supporters(),
        refused = ?t.unusable,
        silent = ?t.silent,
        "hosted key generation refused: a peer holds a copy that is not confirmed"
    );
    Err(DaemonError::HostedUnconfirmed {
        key_id: key_id.to_string(),
        detail: format!(
            "holders {:?}, unusable {:?}, silent {:?}; a new key is not minted over a copy",
            t.supporters(),
            t.unusable,
            t.silent
        ),
    })
}

/// A peer's push of hosted key `key_id` (`Peer.ReplicateKey`, or the in-process peer): the same
/// rules over every transport. `leader` is the caller's certificate CN (`None`: no caller
/// identity, a plaintext dev mesh), `sender` its roster identifier when known.
///
/// - Identical material already here: a no-op. Different material here: refused,
///   [`DaemonError::HostedConflict`].
/// - An id this node does not hold: accepted only while `leader` holds this node's generation
///   fence for the id under `ceremony_id`, for the spec that fence declared, and — where generate
///   intents are required — taken under a verified client generate intent
///   ([`Node::genkey_push_refusal`]; FAILED_PRECONDITION otherwise), and only if no other
///   peer that answers holds different material (HostedConflict), a tombstone (refused as
///   tombstoned, the tombstone applied here) or a copy this node cannot check
///   (HostedUnconfirmed). A silent peer does not block the push, or one node down would stop
///   every generation.
///
/// Every refusal is logged with the caller and the key, and counted.
pub async fn accept_replica(
    node: &Arc<Node>,
    ceremony_id: &str,
    key_id: &str,
    spec: &str,
    wrapped: &crate::wrap::Wrapped,
    leader: Option<&str>,
    sender: Option<u16>,
) -> Result<Vec<u8>> {
    let from = match (sender, leader) {
        (Some(s), _) => format!("cosigner {s}"),
        (None, Some(cn)) => cn.to_string(),
        (None, None) => "an unidentified caller".to_string(),
    };
    let spec = crate::hosted::HostedSpec::parse(spec)?;
    let key = match node.hosted_unwrap(key_id, spec, wrapped) {
        Ok(key) => key,
        Err(e) => {
            count_bad_material(&e);
            tracing::warn!(key_id, peer = %from, error = %e, "refused a pushed hosted key: it does not open or validate");
            return Err(e);
        }
    };
    let (id, k) = (key_id.to_owned(), key.clone());
    match node.blocking(move |n| n.hosted_push_check(&id, &k)).await {
        Ok(Some(commitment)) => return Ok(commitment),
        Ok(None) => {}
        Err(e @ DaemonError::HostedConflict { .. }) => {
            metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
            hosted_refusal("conflict");
            tracing::error!(key_id, peer = %from, "refused a pushed hosted key: this node holds different material under the id");
            return Err(e);
        }
        Err(e) => return Err(e),
    }
    if let Some((reason, e)) = node.genkey_push_refusal(key_id, ceremony_id, leader, spec.as_str()) {
        match reason {
            "spec" => hosted_refusal("spec"),
            "intent" => hosted_refusal("intent"),
            _ => hosted_refusal("unfenced"),
        }
        if reason == "unfenced" {
            tracing::warn!(
                key_id,
                peer = %from,
                ceremony_id,
                "refused a pushed hosted key: the id is not held here and the caller holds no \
                 generation fence for it under that ceremony (a 0.4.0 node's anti-entropy push looks \
                 like this; this node pulls the key itself once two peers agree)"
            );
        } else {
            tracing::warn!(
                key_id,
                peer = %from,
                ceremony_id,
                reason,
                error = %e,
                "refused a pushed hosted key: it does not match what the generation's fence was taken \
                 under on this node — if that peer runs this release, investigate it as compromised"
            );
        }
        return Err(e);
    }
    // Each such check asks every peer: charged to this node's fan-out ceiling, so a peer that fences
    // and pushes made-up ids in a loop is bounded. Over it: "try again" (UNAVAILABLE), which the
    // leader counts as a failed replica, never as a conflict.
    if !node.take_repair_token() {
        hosted_refusal("throttled");
        tracing::warn!(key_id, peer = %from, "refused a pushed hosted key for now: this node's fan-out ceiling is reached");
        return Err(DaemonError::HostedUnconfirmed {
            key_id: key_id.to_string(),
            detail: "this node's fan-out ceiling is reached; try again".into(),
        });
    }
    // The fence holder may still be the one compromised node: before a key this node lacks is
    // stored, no other peer that answers may hold different material, a tombstone, or a copy this
    // node cannot check.
    let mine = node.hosted_commitment(&key)?;
    let mut t = Tally::of(peer_copies(node, &node.mesh_peers(), key_id, sender).await);
    if !t.tombstones.is_empty() && apply_peer_tombstones(node, key_id, &mut t).await? {
        tracing::warn!(key_id, peer = %from, "refused a pushed hosted key: a peer holds a valid tombstone for the id");
        return Err(crate::node::tombstoned(key_id));
    }
    if let Some(other) = t.holders.iter().find(|(c, _)| **c != mine).and_then(|(_, h)| h.first().map(|(p, _)| *p)) {
        metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
        hosted_refusal("conflict");
        tracing::error!(
            key_id,
            peer = %from,
            holder = other,
            "refused a pushed hosted key: another cosigner holds different material under the id"
        );
        return Err(DaemonError::HostedConflict {
            key_id: key_id.to_string(),
            detail: format!("cosigner {other} holds different material; the push from {from} is refused"),
        });
    }
    if !t.unusable.is_empty() {
        hosted_refusal("unverifiable");
        tracing::warn!(
            key_id,
            peer = %from,
            unusable = ?t.unusable,
            "refused a pushed hosted key: another cosigner answered with a copy this node cannot check"
        );
        return Err(DaemonError::HostedUnconfirmed {
            key_id: key_id.to_string(),
            detail: format!("cosigner(s) {:?} answered with a copy this node cannot check; the push from {from} is refused", t.unusable),
        });
    }
    let (id, cid, cn) = (key_id.to_owned(), ceremony_id.to_owned(), leader.map(str::to_owned));
    node.blocking(move |n| n.hosted_store_pushed(&id, &key, &cid, cn.as_deref())).await
}

/// Log and publish (`rutli_hosted_keys_future_timestamp`) the hosted keys held here whose creation
/// or undelete time lies in the future. Run at start-up and by every sweep.
pub async fn report_future_timestamps(node: &Arc<Node>) {
    match node.blocking(|n| n.hosted_future_timestamps()).await {
        Ok(found) => {
            metrics::gauge!(crate::metrics::HOSTED_FUTURE_TIMESTAMPS).set(found.len() as f64);
            for (key_id, why) in &found {
                tracing::error!(
                    key_id = %key_id,
                    why = %why,
                    "hosted key with a time in the future: it refuses every delete until then — check \
                     the clock of the node that created it (docs/hosted-keys.md)"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not check hosted-key timestamps"),
    }
}

/// One anti-entropy sweep: apply peers' tombstones, then pull what this node is missing. Returns
/// how many keys it pulled.
///
/// Pulling is what heals a node that missed a write (down during a 2-of-3 generation) or was
/// restored from a stale backup: each missing key is pulled once per sweep, and stored only when
/// two peers return the same material ([`repair_hosted_key`]). The sweep never pushes a key to a
/// peer: each node pulls for itself. Applies to hosted keys ONLY — a FROST share must never be
/// copied between nodes, since two nodes holding the same share silently breaks the threshold.
///
/// Tombstones first (audit M2): a peer's tombstone whose delete intent verifies here converts this
/// node's live copy (or is recorded where the key is absent), so a node that was down during a
/// delete, or was restored from an old backup, never pulls the deleted key back. A tombstone that
/// does not verify is refused and counted (`rutli_delete_intent_refusals_total`). Nothing
/// tombstoned here is pulled.
/// Most missing ids one sweep pulls in total, and per listing peer: each pull asks every peer, and a
/// peer's inventory may list any number of made-up ids. The rest wait for the next sweep.
pub const SWEEP_MAX_PULLS: usize = 256;
pub const SWEEP_MAX_PULLS_PER_PEER: usize = 64;

/// The missing ids one sweep pulls, in order, within [`SWEEP_MAX_PULLS`] and
/// [`SWEEP_MAX_PULLS_PER_PEER`]. Ids more peers list come first: a real key that missed this node
/// is listed by at least two (only two agreeing copies can be pulled anyway), so one peer listing
/// made-up ids cannot push it out of the budget. Logs when the bound leaves ids for the next sweep.
fn sweep_pull_order(missing: BTreeMap<String, Vec<Identifier>>) -> Vec<String> {
    let mut ids: Vec<(String, Vec<Identifier>)> = missing.into_iter().collect();
    ids.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    let mut budget: std::collections::HashMap<Identifier, usize> = std::collections::HashMap::new();
    let (mut chosen, mut left) = (Vec::new(), 0usize);
    for (id, listers) in ids {
        let has_budget = listers.iter().any(|l| budget.get(l).copied().unwrap_or(0) < SWEEP_MAX_PULLS_PER_PEER);
        if chosen.len() >= SWEEP_MAX_PULLS || !has_budget {
            left += 1;
            continue;
        }
        for l in &listers {
            *budget.entry(*l).or_insert(0) += 1;
        }
        chosen.push(id);
    }
    if left > 0 {
        tracing::warn!(
            pulling = chosen.len(),
            left,
            "anti-entropy: the pull bound of this sweep is reached — the remaining missing ids wait \
             for the next sweep (a peer listing many ids this node lacks: check which in its inventory)"
        );
    }
    chosen
}

/// How long the sweep waits for one peer's inventory (`ListKeys` lists every key, so longer than a
/// single key's [`PEER_COPY_TIMEOUT`]).
pub const SWEEP_LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn anti_entropy_sweep(node: &Arc<Node>, peers: &Peers) -> Result<usize> {
    if !node.hosted_enabled() {
        return Ok(0);
    }
    // A store that failed its readiness probe is not reconciled against: nothing could be pulled
    // into it, and its listing is not to be trusted.
    node.refuse_if_keystore_down()?;

    // Every peer's inventory first, so tombstones from anyone apply before anything is pulled.
    // Asked concurrently, each with SWEEP_LIST_TIMEOUT: one hung peer must not stall repair,
    // tombstone propagation and the gauges; the sweep goes on with the peers that answered.
    let mut asked = tokio::task::JoinSet::new();
    let mut seen = std::collections::HashSet::new();
    for (i, p) in peers.iter().enumerate() {
        if p.identifier() == node.identifier || !seen.insert(p.identifier()) {
            continue;
        }
        let p = p.clone();
        asked.spawn(async move { (i, tokio::time::timeout(SWEEP_LIST_TIMEOUT, p.list_inventory()).await) });
    }
    let mut answers = Vec::new();
    while let Some(joined) = asked.join_next().await {
        if let Ok(answer) = joined {
            answers.push(answer);
        }
    }
    answers.sort_by_key(|(i, _)| *i);
    let mut inventories: Vec<(&Arc<dyn PeerApi>, Vec<pb::KeyManifest>)> = Vec::new();
    for (i, answer) in answers {
        // `i` is an index into `peers` from the loop above, so it is always present.
        let Some(p) = peers.get(i) else { continue };
        // Never skip a peer silently: an unreachable peer — e.g. an mTLS UnknownIssuer while the
        // cluster CA is being rotated (docs/ca-rotation.md) — is exactly what an operator must see.
        // With hosted keys on, every node sweeps every peer each interval, so this line covers
        // every directed mesh link.
        match answer {
            Ok(Ok(inv)) => inventories.push((p, inv)),
            Ok(Err(e)) => tracing::warn!(peer = ?p.identifier(), error = %e, "anti-entropy: cannot list keys on peer"),
            Err(_) => tracing::warn!(
                peer = ?p.identifier(),
                timeout_secs = SWEEP_LIST_TIMEOUT.as_secs(),
                "anti-entropy: peer did not list its keys in time — going on without it"
            ),
        }
    }

    let mut tombstoned = 0usize;
    for (p, inv) in &inventories {
        for t in inv.iter().filter(|m| m.tombstone) {
            match apply_peer_tombstone(node, t).await {
                Ok(crate::node::TombstoneOutcome::Already) => {}
                Ok(outcome) => {
                    tombstoned += 1;
                    tracing::warn!(key_id = %t.key_id, from = ?p.identifier(), ?outcome, "anti-entropy: applied a peer's tombstone");
                }
                Err(e) => tracing::error!(
                    key_id = %t.key_id,
                    peer = ?p.identifier(),
                    error = %e,
                    "anti-entropy: REFUSED a peer's tombstone — this node keeps what it holds"
                ),
            }
        }
    }

    let mine: std::collections::HashSet<String> =
        node.blocking(|n| n.hosted_list()).await?.into_iter().collect();
    // key_id -> how many cosigners hold it. Seeded with this node's own inventory; each reachable
    // peer adds its own. Published as the min at the end — the signal that a below-`n` write
    // quorum has not healed.
    let mut replicas: std::collections::HashMap<String, usize> =
        mine.iter().map(|k| (k.clone(), 1usize)).collect();
    // Ids some peer holds live and this node does not: each is pulled once below, however many
    // peers list it.
    // Ids some peer lists live and this node lacks, with the peers that list them.
    let mut missing: BTreeMap<String, Vec<Identifier>> = BTreeMap::new();

    for (p, inv) in &inventories {
        let theirs: Vec<&pb::KeyManifest> = inv.iter().filter(|m| !m.tombstone).collect();
        for m in &theirs {
            *replicas.entry(m.key_id.clone()).or_insert(0) += 1;
        }

        // Divergence on a shared key is a hard error, never a merge: hosted keys are
        // create-once-immutable, so two different materials under one id means something is wrong
        // that a sweep must not paper over.
        for m in &theirs {
            if let Ok(local) = hosted_load(node, &m.key_id).await {
                if node.hosted_commitment(&local)? != m.commitment {
                    metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
                    tracing::error!(
                        key_id = %m.key_id,
                        peer = ?p.identifier(),
                        "hosted key CONFLICT: this node and the peer hold different material \
                         under the same key id — refusing to reconcile automatically"
                    );
                }
            } else if !mine.contains(&m.key_id) {
                missing.entry(m.key_id.clone()).or_default().push(p.identifier());
            }
        }
    }

    let mut pulled = 0usize;
    for key_id in sweep_pull_order(missing) {
        // Tombstoned here (just now, by a peer's tombstone, or before): repair_hosted_key answers
        // false without asking anyone.
        match repair_hosted_key(node, peers, &key_id).await {
            Ok(true) => pulled += 1,
            Ok(false) => {}
            Err(e) => {
                metrics::counter!(crate::metrics::ANTI_ENTROPY_PULL_FAILURES).increment(1);
                tracing::debug!(key_id = %key_id, error = %e, "anti-entropy: a missing hosted key was not pulled");
            }
        }
    }
    if pulled > 0 {
        metrics::counter!(crate::metrics::ANTI_ENTROPY_REPAIRS).increment(pulled as u64);
    }
    // The grace period of every tombstone: drop retained material past it.
    if let Err(e) = node.blocking(|n| n.hosted_purge_expired(crate::intent::now_ms())).await {
        tracing::warn!(error = %e, "could not drop expired tombstone material");
    }
    if tombstoned > 0 {
        tracing::info!(tombstoned, "anti-entropy applied tombstones");
    }
    report_future_timestamps(node).await;
    // Recount after repair so the gauge reflects the healed state, not the state that triggered it.
    let healed: std::collections::HashSet<String> =
        node.blocking(|n| n.hosted_list()).await?.into_iter().collect();
    for id in &healed {
        replicas.entry(id.clone()).or_insert(1);
    }
    // A key pulled in this sweep counts this node too.
    for id in healed.difference(&mine) {
        if let Some(n) = replicas.get_mut(id) {
            *n += 1;
        }
    }
    // Ids deleted since the sweep began are no longer replicas of anything.
    replicas.retain(|id, _| healed.contains(id) || !mine.contains(id));
    metrics::gauge!(crate::metrics::HOSTED_KEYS).set(healed.len() as f64);
    metrics::gauge!(crate::metrics::KEY_REPLICAS)
        .set(replicas.values().copied().min().map(|m| m as f64).unwrap_or(f64::NAN));
    if let Ok(ts) = node.blocking(|n| n.hosted_tombstones()).await {
        let retained = ts.iter().filter(|t| t.retained.is_some()).count();
        metrics::gauge!(crate::metrics::HOSTED_TOMBSTONES, "retained" => "true").set(retained as f64);
        metrics::gauge!(crate::metrics::HOSTED_TOMBSTONES, "retained" => "false").set((ts.len() - retained) as f64);
    }
    Ok(pulled)
}

/// [`Node::hosted_load`] off the async workers.
async fn hosted_load(node: &Arc<Node>, key_id: &str) -> Result<crate::hosted::HostedKey> {
    let key_id = key_id.to_owned();
    node.blocking(move |n| n.hosted_load(&key_id)).await
}

/// [`Node::hosted_exists`] off the async workers.
pub(crate) async fn hosted_exists(node: &Arc<Node>, key_id: &str) -> Result<bool> {
    let key_id = key_id.to_owned();
    node.blocking(move |n| Ok(n.hosted_exists(&key_id))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_preflight_with_no_answers_is_refused_not_a_panic() {
        // refresh_preflight used to index views[0]; no answers is an error, never a panic.
        let peers: Peers = Vec::new();
        assert!(matches!(refresh_preflight(&peers, "k", &[]).await, Err(DaemonError::CeremonyRefused(_))));
    }

    #[test]
    fn a_peer_rpc_timeout_counts_as_unreachable_but_a_refusal_does_not() {
        // What tonic returns when peer::PEER_RPC_TIMEOUT fires (also on a fresh connection whose
        // handshake never completes — a wedged peer).
        let timed_out = DaemonError::Status(tonic::Status::cancelled("Timeout expired"));
        assert!(is_unreachable(&timed_out));
        // A sick node's refusal (UNAVAILABLE) is skipped too; a genuine conflict is not.
        assert!(is_unreachable(&DaemonError::Status(tonic::Status::unavailable("not serving"))));
        assert!(!is_unreachable(&DaemonError::Status(tonic::Status::cancelled("client went away"))));
        assert!(!is_unreachable(&DaemonError::Status(tonic::Status::aborted("ceremony in progress"))));
    }
}

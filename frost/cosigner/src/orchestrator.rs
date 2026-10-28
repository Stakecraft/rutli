// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Leader-side coordination of DKG and signing across the peer set. Transport-agnostic: it drives
//! [`PeerApi`], so the same code runs over gRPC in production and over in-process peers in tests.

use std::collections::BTreeMap;
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

async fn run_dkg_attached(peers: &Peers, key_id: &str, intent: Option<&pb::SignedIntent>) -> Result<[u8; 32]> {
    // Every peer refuses too (fence and part 1); this just answers before touching the mesh.
    if crate::share_delivery::is_reserved_for_import(key_id) {
        return Err(DaemonError::ReservedKeyId(key_id.to_string()));
    }
    require_ceremony_protocol(peers).await?;
    let views = key_views(peers, key_id).await?;
    if let Some(existing) = dkg_preflight(peers, key_id, &views).await? {
        return Ok(existing);
    }
    let dkg_id = ceremony_id(CeremonyKind::Dkg, intent)?;
    fence_all(peers, &dkg_id, key_id, CeremonyKind::Dkg, None, intent).await?;
    let staged = ceremony_stage(peers, &dkg_id, key_id, CeremonyKind::Dkg, intent).await;
    finish_ceremony(peers, &dkg_id, key_id, staged).await
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
    let first = &views[0].1;
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
    let first = &views[0].1;
    if let Some((id, v)) = views.iter().find(|(_, v)| v.epoch != first.epoch || v.pkp_digest != first.pkp_digest) {
        return Err(DaemonError::CeremonyRefused(format!(
            "refusing to refresh {key_id}: cosigner {id} is on epoch {} but cosigner {} is on epoch {} \
             (or their sharings differ) — the nodes must hold one sharing (verify-key shows which)",
            v.epoch, views[0].0, first.epoch
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
///   attempt is a fresh session (new session id, fresh round-1 commitments from every member —
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
    for subset in combinations(ordered.len(), threshold) {
        let members: Vec<&Arc<dyn PeerApi>> = subset.iter().map(|&i| ordered[i]).collect();
        if members.iter().any(|p| excluded.contains_key(&p.identifier())) {
            continue;
        }
        if attempts >= MAX_SIGN_ATTEMPTS || started.elapsed() >= SIGN_BUDGET {
            break;
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
    let usable = ordered.len() - excluded.len();
    tracing::warn!(key_id, attempts, ?excluded, "sign gave up: no t-subset of cosigners could sign");
    if let Some(refusal) = policy_refusal {
        return Err(refusal);
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

/// One signing session over exactly `members`: round 1 to each (fresh nonces under a fresh session
/// id, bound to `message` and this signer set), round 2 to each, aggregate. On a member's failure
/// the session is aborted on every member still holding nonces for it, so nothing lingers until
/// the pending TTL; a member that already produced its share has burned its nonce and is
/// unaffected.
async fn attempt(
    node: &Arc<Node>,
    members: &[&Arc<dyn PeerApi>],
    key_id: &str,
    message: &[u8],
    base: &crate::node::Round1Ctx,
    prefix: &str,
) -> std::result::Result<[u8; 64], Attempt> {
    let session_id = new_id(prefix);
    let mut signers = Vec::with_capacity(members.len());
    for p in members {
        signers.push(crate::hosted::identifier_index(p.identifier()).map_err(Attempt::Fatal)?);
    }
    let ctx = &crate::node::Round1Ctx { message: Some(message.to_vec()), signers: Some(signers), ..base.clone() };
    let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    for (i, p) in members.iter().enumerate() {
        match p.sign_round1(key_id, &session_id, ctx).await {
            Ok(c) => {
                commitments.insert(p.identifier(), c);
            }
            Err(e) => {
                metrics::counter!(crate::metrics::SIGN_ROUND1_SKIPS).increment(1);
                abort_sign(&members[..i], key_id, &session_id).await;
                return Err(Attempt::Members(vec![(p.identifier(), e)]));
            }
        }
    }
    let intent_digest = ctx.intent.as_ref().map(crate::intent::intent_digest);
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for p in members {
        match p.sign_round2(key_id, &session_id, message, &commitments, intent_digest.as_ref()).await {
            Ok(share) => {
                shares.insert(p.identifier(), share);
            }
            Err(e) => {
                // Members before this one burned their nonce; this one and later ones may still
                // hold theirs — free them now.
                abort_sign(members, key_id, &session_id).await;
                return Err(Attempt::Members(vec![(p.identifier(), e)]));
            }
        }
    }
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

/// Best-effort: tell each quorum member to drop the in-flight session so its round-1 nonces are
/// freed now instead of at the pending-TTL sweep. Errors are swallowed — abort is a courtesy, and
/// the per-session TTL is the correctness backstop. Aborting a session a peer already completed
/// (round-2 done) is a harmless no-op.
async fn abort_sign(chosen: &[&Arc<dyn PeerApi>], key_id: &str, session_id: &str) {
    metrics::counter!(crate::metrics::SIGN_ABORTS).increment(1);
    for p in chosen {
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
pub async fn generate_hosted_key(
    node: &Arc<Node>,
    peers: &Peers,
    key_id: &str,
    spec: crate::hosted::HostedSpec,
    write_quorum: usize,
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
    let ceremony_id = new_id("genkey");

    // Fence the key cluster-wide: the guard is per-key, so this also serializes against a
    // concurrent generate for the same id on another leader.
    //
    // Unlike DKG/refresh — all-party ceremonies where a missing peer means the ceremony cannot
    // proceed — a hosted-key write only needs `write_quorum` nodes. So an UNREACHABLE peer is
    // skipped rather than fatal: a node that is down cannot start a racing operation on this key
    // anyway. A peer that is reachable and *refuses* (something else holds the guard) still aborts,
    // because that is a genuine conflict. Without this distinction the 2-of-3 write quorum could
    // never actually be used with a node down, which is the entire point of it.
    let mut fenced: Vec<&Arc<dyn PeerApi>> = Vec::new();
    let mut reachable: Vec<&Arc<dyn PeerApi>> = Vec::new();
    for p in peers {
        match p.ceremony_fence(&ceremony_id, key_id, "genkey").await {
            Ok(()) => {
                fenced.push(p);
                reachable.push(p);
            }
            Err(e) if is_unreachable(&e) => {
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

    let outcome =
        generate_hosted_fenced(node, peers, key_id, spec, write_quorum, &ceremony_id).await;
    release_fences(&fenced, &ceremony_id, key_id).await;
    outcome
}

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
        None => {
            let key = tokio::task::spawn_blocking(move || {
                crate::hosted::HostedKey::generate(spec, crate::hosted::now_secs())
            })
            .await
            .map_err(|e| DaemonError::Config(format!("key generation task failed: {e}")))??;
            let (id, stored, ceremony) = (key_id.to_owned(), key.clone(), ceremony_id.to_owned());
            node.blocking(move |n| n.hosted_store_for(&id, &stored, Some(&ceremony))).await?;
            (key, true)
        }
    };
    let public_der = if spec.is_asymmetric() { key.public_key_der()? } else { Vec::new() };

    // The leader already holds it; replicate to every other peer, wrapping per recipient.
    let mut replicas = 1usize;
    let mut failures = Vec::new();
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        match replicate_to(node, p.as_ref(), ceremony_id, key_id, &key, &public_der).await {
            Ok(()) => replicas += 1,
            Err(e) => {
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "hosted key replication failed");
                failures.push(e);
            }
        }
    }

    // A peer holding a tombstone for the id (audit M2) means the id was deleted: generating it
    // again needs the tombstone cleared on EVERY node first, so one refusal stops the generation.
    let tombstoned_somewhere = failures.iter().any(|e| e.to_string().contains("is tombstoned"));
    if replicas < write_quorum || tombstoned_somewhere {
        // Below quorum the key is not durable enough to hand out: a single node holding the only
        // copy is exactly the failure this feature exists to prevent. Roll back so the id stays
        // free for a clean retry. Each node removes only a key it created in this generation.
        for p in peers {
            let _ = p.purge_key(ceremony_id, key_id).await;
        }
        if tombstoned_somewhere {
            return Err(crate::node::tombstoned(key_id));
        }
        return Err(DaemonError::ThresholdNotMet { needed: write_quorum, got: replicas });
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
        return Err(DaemonError::Disagreement(format!(
            "peer {:?} stored different material for {key_id}",
            peer.identifier()
        )));
    }
    Ok(())
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
            Err(e) => {
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "hosted key delete refused or failed on peer");
                if refusal.is_none() && !is_unreachable(&e) {
                    refusal = Some(e);
                }
            }
        }
    }
    release_fences(&fenced, &ceremony_id, key_id).await;
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

/// Pull a hosted key this node is missing from whichever peer has it (read-repair).
///
/// Without this, a decrypt that lands on a lagging replica would return NOT_FOUND to Canton — and
/// the driver correctly does not fail over on NOT_FOUND, since that is normally authoritative.
/// Repairing on demand is what makes NOT_FOUND trustworthy.
pub async fn repair_hosted_key(node: &Arc<Node>, peers: &Peers, key_id: &str) -> Result<bool> {
    if hosted_exists(node, key_id).await? {
        return Ok(true);
    }
    // A deleted key is never pulled back (audit M2): its tombstone answers NOT_FOUND.
    let id = key_id.to_owned();
    if node.blocking(move |n| n.hosted_tombstoned(&id)).await? {
        return Ok(false);
    }
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        let Ok((spec, _pub_der, wrapped)) = p.fetch_key(key_id).await else { continue };
        let Ok(spec) = crate::hosted::HostedSpec::parse(&spec) else { continue };
        match node.hosted_unwrap(key_id, spec, &wrapped) {
            Ok(key) => {
                let id = key_id.to_owned();
                node.blocking(move |n| n.hosted_store(&id, &key)).await?;
                tracing::info!(key_id, from = ?p.identifier(), "repaired missing hosted key from peer");
                return Ok(true);
            }
            Err(e) => {
                tracing::warn!(key_id, peer = ?p.identifier(), error = %e, "hosted key repair failed");
            }
        }
    }
    Ok(false)
}

/// One anti-entropy sweep: apply peers' tombstones, pull anything this node is missing, and push
/// anything a peer is missing.
///
/// Pushing is what heals an under-quorum write; pulling is what heals a node restored from a stale
/// backup. Applies to hosted keys ONLY — a FROST share must never be copied between nodes, since
/// two nodes holding the same share silently breaks the threshold.
///
/// Tombstones first (audit M2): a peer's tombstone whose delete intent verifies here converts this
/// node's live copy (or is recorded where the key is absent), so a node that was down during a
/// delete, or was restored from an old backup, never pushes the deleted key back. A tombstone that
/// does not verify is refused and counted (`rutli_delete_intent_refusals_total`). Nothing is pushed
/// to a peer that holds a tombstone for the id, and nothing tombstoned here is pulled.
pub async fn anti_entropy_sweep(node: &Arc<Node>, peers: &Peers) -> Result<(usize, usize)> {
    if !node.hosted_enabled() {
        return Ok((0, 0));
    }
    // A store that failed its readiness probe is not reconciled against: nothing could be pulled
    // into it, and its listing is not to be trusted.
    node.refuse_if_keystore_down()?;

    // Every peer's inventory first, so tombstones from anyone apply before anything is pushed.
    let mut inventories: Vec<(&Arc<dyn PeerApi>, Vec<pb::KeyManifest>)> = Vec::new();
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        // Never skip a peer silently: an unreachable peer — e.g. an mTLS UnknownIssuer while the
        // cluster CA is being rotated (docs/ca-rotation.md) — is exactly what an operator must see.
        // With hosted keys on, every node sweeps every peer each interval, so this line covers
        // every directed mesh link.
        match p.list_inventory().await {
            Ok(inv) => inventories.push((p, inv)),
            Err(e) => tracing::warn!(peer = ?p.identifier(), error = %e, "anti-entropy: cannot list keys on peer"),
        }
    }

    let mut tombstoned = 0usize;
    for (p, inv) in &inventories {
        for t in inv.iter().filter(|m| m.tombstone) {
            let intent = match <pb::SignedIntent as prost::Message>::decode(t.delete_intent.as_slice()) {
                Ok(i) => i,
                Err(e) => {
                    crate::intent::refused_delete("malformed", format!("peer tombstone for {}: {e}", t.key_id));
                    continue;
                }
            };
            let info = crate::node::DeletedKeyInfo { spec: t.spec.clone(), created_at: t.created_at, commitment: t.commitment.clone() };
            let deleted_at_ms = t.deleted_at_ms;
            let id = t.key_id.clone();
            match node
                .blocking(move |n| {
                    n.hosted_apply_tombstone(&id, &intent, crate::intent::Expiry::Propagated { deleted_at_ms }, Some(&info))
                })
                .await
            {
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
    let (mut pulled, mut pushed) = (0usize, 0usize);
    // key_id -> how many cosigners hold it. Seeded with this node's own inventory; each reachable
    // peer adds its own. Published as the min at the end — the signal that a below-`n` write
    // quorum has not healed.
    let mut replicas: std::collections::HashMap<String, usize> =
        mine.iter().map(|k| (k.clone(), 1usize)).collect();

    for (p, inv) in &inventories {
        let theirs: Vec<&pb::KeyManifest> = inv.iter().filter(|m| !m.tombstone).collect();
        // Ids the peer holds in any form: never push to it what it holds or deleted.
        let their_ids: std::collections::HashSet<String> = inv.iter().map(|m| m.key_id.clone()).collect();
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
            }
        }

        for m in &theirs {
            if !mine.contains(&m.key_id) && repair_hosted_key(node, peers, &m.key_id).await.unwrap_or(false) {
                pulled += 1;
            }
        }
        for key_id in &mine {
            if their_ids.contains(key_id) {
                continue;
            }
            let Ok(key) = hosted_load(node, key_id).await else { continue };
            let public_der =
                if key.spec.is_asymmetric() { key.public_key_der().unwrap_or_default() } else { Vec::new() };
            match replicate_to(node, p.as_ref(), &new_id("repair"), key_id, &key, &public_der).await {
                Ok(()) => {
                    pushed += 1;
                    tracing::info!(key_id, to = ?p.identifier(), "pushed missing hosted key to peer");
                }
                Err(e) => tracing::warn!(key_id, peer = ?p.identifier(), error = %e, "anti-entropy push failed"),
            }
        }
    }
    if pulled + pushed > 0 {
        metrics::counter!(crate::metrics::ANTI_ENTROPY_REPAIRS).increment((pulled + pushed) as u64);
    }
    // The grace period of every tombstone: drop retained material past it.
    if let Err(e) = node.blocking(|n| n.hosted_purge_expired(crate::intent::now_ms())).await {
        tracing::warn!(error = %e, "could not drop expired tombstone material");
    }
    if tombstoned > 0 {
        tracing::info!(tombstoned, "anti-entropy applied tombstones");
    }
    // Recount after repair so the gauge reflects the healed state, not the state that triggered it.
    let healed: std::collections::HashSet<String> =
        node.blocking(|n| n.hosted_list()).await?.into_iter().collect();
    for id in &healed {
        replicas.entry(id.clone()).or_insert(1);
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
    Ok((pulled, pushed))
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

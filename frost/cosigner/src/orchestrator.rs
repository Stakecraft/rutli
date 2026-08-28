// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Leader-side coordination of DKG and signing across the peer set. Transport-agnostic: it drives
//! [`PeerApi`], so the same code runs over gRPC in production and over in-process peers in tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use frost_ed25519 as frost;
use frost::keys::dkg::round2;
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;

use crate::node::Node;
use crate::peer::PeerApi;
use crate::{DaemonError, Result};

pub type Peers = Vec<Arc<dyn PeerApi>>;

/// Length of the digest Canton hands the KMS driver for Ed25519 topology signs
/// (`0x12 0x20 ‖ sha256(tx)` — see `docs/wire-contract.md`). The Signer API rejects anything else
/// so a miswired client cannot mint signatures over arbitrary payloads through the cluster.
pub const CANTON_DIGEST_LEN: usize = 34;

/// Coordinate a full DKG across every peer and return the agreed 32-byte group verifying key.
/// Every peer persists its own share; the whole private key is never assembled anywhere.
pub async fn run_dkg(peers: &Peers, key_id: &str) -> Result<[u8; 32]> {
    let dkg_id = new_id("dkg");
    fence_all(peers, &dkg_id, key_id, "dkg").await?;

    // Part 1: every peer commits and broadcasts.
    let mut round1_map = BTreeMap::new();
    for p in peers {
        match p.dkg_part1(&dkg_id, key_id).await {
            Ok(pkg) => {
                round1_map.insert(p.identifier(), pkg);
            }
            Err(e) => {
                release_all(peers, &dkg_id, key_id).await;
                return Err(e);
            }
        }
    }

    // Part 2: every peer processes the full round-1 set → per-recipient round-2 packages.
    let mut outbox: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> = BTreeMap::new();
    for p in peers {
        outbox.insert(p.identifier(), p.dkg_part2(&dkg_id, &round1_map).await?);
    }

    // Part 3: route each round-2 package to its recipient and finalize.
    let mut group_key: Option<[u8; 32]> = None;
    for p in peers {
        let me = p.identifier();
        let mut inbox: BTreeMap<Identifier, round2::Package> = BTreeMap::new();
        for (&from, packages) in outbox.iter() {
            if from == me {
                continue;
            }
            let pkg = packages.get(&me).ok_or_else(|| {
                DaemonError::Disagreement(format!("missing round2 package from {from:?} to {me:?}"))
            })?;
            inbox.insert(from, pkg.clone());
        }
        let gk = p.dkg_part3(&dkg_id, &round1_map, &inbox).await?;
        match group_key {
            None => group_key = Some(gk),
            Some(prev) if prev != gk => {
                return Err(DaemonError::Disagreement("peers derived different group keys".into()))
            }
            _ => {}
        }
    }
    group_key.ok_or_else(|| DaemonError::Config("no peers configured for DKG".into()))
}

/// Coordinate a proactive refresh across every peer. Same three-part exchange as DKG, but each
/// peer folds the fresh zero-sharing into its existing share. The group public key is unchanged
/// (verified by every node); shares stolen before this refresh become useless. Requires all peers
/// (like DKG) — refresh is a scheduled ceremony, not a per-request path.
///
/// Before any crypto, every peer takes the per-key ceremony fence so **no node** can start a new
/// sign mid-refresh. If any peer still has in-flight sign nonces, the fence fails and is rolled
/// back cluster-wide (`SignInProgress`).
pub async fn run_refresh(peers: &Peers, key_id: &str) -> Result<[u8; 32]> {
    let refresh_id = new_id("refresh");
    fence_all(peers, &refresh_id, key_id, "refresh").await?;

    let mut round1_map = BTreeMap::new();
    for p in peers {
        match p.refresh_part1(&refresh_id, key_id).await {
            Ok(pkg) => {
                round1_map.insert(p.identifier(), pkg);
            }
            Err(e) => {
                release_all(peers, &refresh_id, key_id).await;
                return Err(e);
            }
        }
    }

    let mut outbox: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> = BTreeMap::new();
    for p in peers {
        outbox.insert(p.identifier(), p.refresh_part2(&refresh_id, &round1_map).await?);
    }

    let mut group_key: Option<[u8; 32]> = None;
    for p in peers {
        let me = p.identifier();
        let mut inbox: BTreeMap<Identifier, round2::Package> = BTreeMap::new();
        for (&from, packages) in outbox.iter() {
            if from == me {
                continue;
            }
            let pkg = packages.get(&me).ok_or_else(|| {
                DaemonError::Disagreement(format!("missing refresh package from {from:?} to {me:?}"))
            })?;
            inbox.insert(from, pkg.clone());
        }
        let gk = p.refresh_part3(&refresh_id, &round1_map, &inbox).await?;
        match group_key {
            None => group_key = Some(gk),
            Some(prev) if prev != gk => {
                return Err(DaemonError::Disagreement("refresh diverged the group key".into()))
            }
            _ => {}
        }
    }
    group_key.ok_or_else(|| DaemonError::Config("no peers configured for refresh".into()))
}

/// Coordinate one signature. Selects a threshold-sized quorum, tolerating peers that fail round 1
/// (a downed cosigner), and aggregates the shares into a 64-byte Ed25519 signature.
pub async fn sign(node: &Node, peers: &Peers, key_id: &str, message: &[u8]) -> Result<[u8; 64]> {
    if message.len() != CANTON_DIGEST_LEN {
        return Err(DaemonError::InvalidMessageLength {
            got: message.len(),
            expected: CANTON_DIGEST_LEN,
        });
    }
    let threshold = node.threshold_for(key_id)? as usize;
    let session_id = new_id("sign");

    // Round 1: gather commitments until we reach the threshold; skip peers that error.
    let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    let mut chosen: Vec<&Arc<dyn PeerApi>> = Vec::new();
    for p in peers {
        if commitments.len() >= threshold {
            break;
        }
        match p.sign_round1(key_id, &session_id).await {
            Ok(c) => {
                commitments.insert(p.identifier(), c);
                chosen.push(p);
            }
            Err(e) => {
                metrics::counter!(crate::metrics::SIGN_ROUND1_SKIPS).increment(1);
                tracing::warn!(peer = ?p.identifier(), error = %e, "sign_round1 failed; trying next");
            }
        }
    }
    if commitments.len() < threshold {
        // Not enough cosigners answered round 1 — free the nonces of those that did.
        abort_sign(&chosen, key_id, &session_id).await;
        return Err(DaemonError::ThresholdNotMet { needed: threshold, got: commitments.len() });
    }

    // Round 2: the chosen quorum produces signature shares over the fixed commitment set.
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for p in &chosen {
        match p.sign_round2(key_id, &session_id, message, &commitments).await {
            Ok(share) => {
                shares.insert(p.identifier(), share);
            }
            Err(e) => {
                // A quorum member failed round 2. The peers that already produced a share have
                // burned their nonce; those not yet reached still hold round-1 nonces — free them.
                abort_sign(&chosen, key_id, &session_id).await;
                return Err(e);
            }
        }
    }

    node.aggregate(key_id, message, &commitments, &shares)
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
async fn fence_all(peers: &Peers, ceremony_id: &str, key_id: &str, kind: &'static str) -> Result<()> {
    let mut fenced: Vec<&Arc<dyn PeerApi>> = Vec::new();
    for p in peers {
        match p.ceremony_fence(ceremony_id, key_id, kind).await {
            Ok(()) => fenced.push(p),
            Err(e) => {
                for q in &fenced {
                    let _ = q.ceremony_release(ceremony_id, key_id).await;
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
    node: &Node,
    peers: &Peers,
    key_id: &str,
    spec: crate::hosted::HostedSpec,
    write_quorum: usize,
) -> Result<(crate::hosted::HostedKey, bool, usize)> {
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

async fn generate_hosted_fenced(
    node: &Node,
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
    let (key, created) = match node.hosted_existing(key_id, spec)? {
        Some(existing) => (existing, false),
        None => {
            let key = tokio::task::spawn_blocking(move || {
                crate::hosted::HostedKey::generate(spec, crate::hosted::now_secs())
            })
            .await
            .map_err(|e| DaemonError::Config(format!("key generation task failed: {e}")))??;
            node.hosted_store(key_id, &key)?;
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

    if replicas < write_quorum {
        // Below quorum the key is not durable enough to hand out: a single node holding the only
        // copy is exactly the failure this feature exists to prevent. Roll back so the id stays
        // free for a clean retry.
        for p in peers {
            let _ = p.purge_key(ceremony_id, key_id).await;
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
    let (recipient, recipient_pub) = peer.node_info().await?;
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

/// Delete a hosted key across the cluster. Best-effort per peer; reports how many confirmed.
pub async fn delete_hosted_key(peers: &Peers, key_id: &str) -> Result<bool> {
    let ceremony_id = new_id("delkey");
    let mut deleted_anywhere = false;
    for p in peers {
        match p.purge_key(&ceremony_id, key_id).await {
            Ok(d) => deleted_anywhere |= d,
            Err(e) => {
                // Best effort by design: a node that is down keeps its copy until anti-entropy
                // reconciles the tombstone, which is why delete is documented as "the key stops
                // being served", not "the bytes are gone".
                tracing::warn!(peer = ?p.identifier(), key_id, error = %e, "hosted key delete failed on peer");
            }
        }
    }
    Ok(deleted_anywhere)
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
pub async fn repair_hosted_key(node: &Node, peers: &Peers, key_id: &str) -> Result<bool> {
    if node.hosted_exists(key_id) {
        return Ok(true);
    }
    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        let Ok((spec, _pub_der, wrapped)) = p.fetch_key(key_id).await else { continue };
        let Ok(spec) = crate::hosted::HostedSpec::parse(&spec) else { continue };
        match node.hosted_unwrap(key_id, spec, &wrapped) {
            Ok(key) => {
                node.hosted_store(key_id, &key)?;
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

/// One anti-entropy sweep: pull anything this node is missing, and push anything a peer is missing.
///
/// Pushing is what heals an under-quorum write; pulling is what heals a node restored from a stale
/// backup. Applies to hosted keys ONLY — a FROST share must never be copied between nodes, since
/// two nodes holding the same share silently breaks the threshold.
pub async fn anti_entropy_sweep(node: &Node, peers: &Peers) -> Result<(usize, usize)> {
    if !node.hosted_enabled() {
        return Ok((0, 0));
    }
    let mine: std::collections::HashSet<String> = node.hosted_list()?.into_iter().collect();
    let (mut pulled, mut pushed) = (0usize, 0usize);
    // key_id -> how many cosigners hold it. Seeded with this node's own inventory; each reachable
    // peer adds its own. Published as the min at the end — the signal that a below-`n` write
    // quorum has not healed.
    let mut replicas: std::collections::HashMap<String, usize> =
        mine.iter().map(|k| (k.clone(), 1usize)).collect();

    for p in peers {
        if p.identifier() == node.identifier {
            continue;
        }
        let Ok(theirs) = p.list_keys().await else { continue };
        let their_ids: std::collections::HashSet<String> =
            theirs.iter().map(|(id, _, _)| id.clone()).collect();
        for id in &their_ids {
            *replicas.entry(id.clone()).or_insert(0) += 1;
        }

        // Divergence on a shared key is a hard error, never a merge: hosted keys are
        // create-once-immutable, so two different materials under one id means something is wrong
        // that a sweep must not paper over.
        for (key_id, _spec, commitment) in &theirs {
            if let Ok(local) = node.hosted_load(key_id) {
                if node.hosted_commitment(&local)? != *commitment {
                    metrics::counter!(crate::metrics::ANTI_ENTROPY_CONFLICTS).increment(1);
                    tracing::error!(
                        key_id,
                        peer = ?p.identifier(),
                        "hosted key CONFLICT: this node and the peer hold different material \
                         under the same key id — refusing to reconcile automatically"
                    );
                }
            }
        }

        for (key_id, _, _) in &theirs {
            if !mine.contains(key_id) && repair_hosted_key(node, peers, key_id).await.unwrap_or(false) {
                pulled += 1;
            }
        }
        for key_id in &mine {
            if their_ids.contains(key_id) {
                continue;
            }
            let Ok(key) = node.hosted_load(key_id) else { continue };
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
    // Recount after repair so the gauge reflects the healed state, not the state that triggered it.
    let healed: std::collections::HashSet<String> = node.hosted_list()?.into_iter().collect();
    for id in &healed {
        replicas.entry(id.clone()).or_insert(1);
    }
    metrics::gauge!(crate::metrics::HOSTED_KEYS).set(healed.len() as f64);
    metrics::gauge!(crate::metrics::KEY_REPLICAS)
        .set(replicas.values().copied().min().map(|m| m as f64).unwrap_or(f64::NAN));
    Ok((pulled, pushed))
}

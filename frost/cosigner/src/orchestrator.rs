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

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Repairable Threshold Scheme (RTS) — rebuild one cosigner's lost share from `t` survivors.
//!
//! If a cosigner is destroyed and has no backup of its share, `t` of the surviving cosigners can
//! help it recompute exactly its old share — without any of them (or the recovered node) ever
//! learning the group secret. Implements the RTS of <https://eprint.iacr.org/2017/1155> via
//! `frost-ed25519`'s repairable module. Three rounds:
//!
//! 1. [`helper_step1`] — each of the `t` helpers derives a "delta" for every helper (incl. itself).
//! 2. [`helper_step2`] — each helper sums the deltas addressed to it into a "sigma".
//! 3. [`participant_step3`] — the recovering node sums the `t` sigmas into its `SecretShare`, then
//!    into a [`KeyPackage`]. The group public key is unchanged; the node rejoins with its old share.
//!
//! Requires the recovering node's VSS commitment (public — the same for all shares), which any
//! helper can supply. Wiring this over the cosigner mesh needs each node to persist its
//! `SecretShare` (which carries the commitment); the daemon's current DR path is encrypted
//! backup/restore (see the DR runbook), with this networked repair as the follow-up. The primitive
//! is proven by [`crate`]'s tests.

use frost_ed25519 as frost;
use frost::keys::repairable::{repair_share_step_1, repair_share_step_2, repair_share_step_3};
use frost::keys::{KeyPackage, SecretShare, VerifiableSecretSharingCommitment};
use frost::Identifier;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

use crate::Result;

/// The Ed25519 field scalar type used by the RTS delta/sigma values.
pub type Scalar = frost_core::Scalar<frost::Ed25519Sha512>;

/// Step 1 (helper): given the identifiers of all `t` helpers and this helper's share, produce the
/// per-helper delta values used to repair `participant`.
pub fn helper_step1(
    helpers: &[Identifier],
    my_share: &SecretShare,
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Scalar>> {
    Ok(repair_share_step_1::<frost::Ed25519Sha512, _>(helpers, my_share, &mut OsRng, participant)?)
}

/// Step 2 (helper): sum the deltas this helper received (from every helper, including its own) into
/// a sigma to send to the recovering participant.
pub fn helper_step2(deltas_to_me: &[Scalar]) -> Scalar {
    repair_share_step_2(deltas_to_me)
}

/// Step 3 (recovering participant): reconstruct the lost share from the `t` sigmas and the public
/// VSS commitment, and turn it into a usable [`KeyPackage`].
pub fn participant_step3(
    sigmas: &[Scalar],
    participant: Identifier,
    commitment: &VerifiableSecretSharingCommitment,
) -> Result<KeyPackage> {
    let secret_share = repair_share_step_3(sigmas, participant, commitment);
    Ok(KeyPackage::try_from(secret_share)?)
}

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
//! 3. [`participant_step3`] — the recovering node sums the `t` sigmas into its [`KeyPackage`] and
//!    checks its verifying share against the group's public key package. The group public key is unchanged; the node
//!    rejoins with its old share.
//!
//! The helpers need only their key packages and the recovering node the public key package, both of
//! which every node stores. The daemon's current DR path is encrypted backup/restore (see the DR
//! runbook), with this networked repair as the follow-up. The primitive is proven by [`crate`]'s
//! tests.

use frost_ed25519 as frost;
use frost::keys::repairable::{repair_share_part1, repair_share_part2, repair_share_part3, Delta, Sigma};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

use crate::Result;

/// Step 1 (helper): given the identifiers of all `t` helpers and this helper's key package, produce
/// the per-helper deltas used to repair `participant`.
pub fn helper_step1(
    helpers: &[Identifier],
    my_key_package: &KeyPackage,
    participant: Identifier,
) -> Result<BTreeMap<Identifier, Delta>> {
    Ok(repair_share_part1::<frost::Ed25519Sha512, _>(helpers, my_key_package, &mut OsRng, participant)?)
}

/// Step 2 (helper): sum the deltas this helper received (from every helper, including its own) into
/// a sigma to send to the recovering participant.
pub fn helper_step2(deltas_to_me: &[Delta]) -> Sigma {
    repair_share_part2(deltas_to_me)
}

/// Step 3 (recovering participant): rebuild the lost key package from the `t` sigmas and the group's
/// public key package. frost 3 takes the threshold from the package; Rütli's packages leave it unset
/// ([`crate::dkg::without_min_signers`]), so it is supplied here, for this call only.
pub fn participant_step3(
    sigmas: &[Sigma],
    participant: Identifier,
    pkp: &PublicKeyPackage,
    min_signers: u16,
) -> Result<KeyPackage> {
    let n = pkp.verifying_shares().len();
    if min_signers < 2 || usize::from(min_signers) > n {
        return Err(crate::CoreError::Dealer(format!("repair: threshold {min_signers} for {n} shares")));
    }
    let with_threshold =
        PublicKeyPackage::new(pkp.verifying_shares().clone(), *pkp.verifying_key(), Some(min_signers));
    let kp = repair_share_part3(sigmas, participant, &with_threshold)?;
    // frost 3 only sums the sigmas: the result must be the share the group knows for this node.
    if pkp.verifying_shares().get(&participant) != Some(kp.verifying_share()) {
        return Err(crate::CoreError::Dealer(
            "repair: the rebuilt share does not match the group's verifying share for this node — a \
             wrong or tampered sigma"
                .into(),
        ));
    }
    Ok(kp)
}

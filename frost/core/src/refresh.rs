// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Proactive share refresh (dealer-free).
//!
//! Re-randomizes every cosigner's key share while keeping the **same group public key**, so an
//! attacker must compromise ≥ `t` shares *within a single refresh epoch* — shares stolen before the
//! refresh become useless. Canton sees no change (the namespace key's public key and the node's
//! identity are unchanged); only the secret sharing is rotated underneath.
//!
//! Uses `frost-ed25519`'s DKG-based refresh (`refresh_dkg_part1/part2/refresh_dkg_shares`): a fresh
//! sharing of zero is generated distributively — no trusted dealer, mirroring [`crate::dkg`]. Each
//! participant runs the three parts, exchanging packages over the (authenticated) cosigner mesh,
//! and folds the result into its existing key package.
//!
//! Invariant the caller MUST enforce: the new public-key package's group key equals the old one. A
//! mismatch means a bug or a malformed peer package and must abort the refresh (never persist a
//! share whose group key drifted — that would change the node's identity).

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost::keys::dkg::{round1, round2};
use frost::keys::refresh::{refresh_dkg_part1, refresh_dkg_part2, refresh_dkg_shares};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use rand::rngs::OsRng;

use crate::Result;

/// One cosigner's refresh state machine. Same three-part shape as [`crate::dkg::DkgParticipant`],
/// but part 3 folds the fresh zero-sharing into the participant's existing key package.
pub struct RefreshParticipant {
    id: Identifier,
    max_signers: u16,
    min_signers: u16,
    r1_secret: Option<round1::SecretPackage>,
    r2_secret: Option<round2::SecretPackage>,
}

impl RefreshParticipant {
    pub fn new(id: Identifier, max_signers: u16, min_signers: u16) -> Self {
        Self { id, max_signers, min_signers, r1_secret: None, r2_secret: None }
    }

    /// Part 1: commit, to broadcast to every peer.
    pub fn part1(&mut self) -> Result<round1::Package> {
        let (secret, package) =
            refresh_dkg_part1(self.id, self.max_signers, self.min_signers, OsRng)?;
        self.r1_secret = Some(secret);
        Ok(package)
    }

    /// Part 2: given every *other* participant's round-1 package, produce per-peer round-2 packages.
    pub fn part2(
        &mut self,
        round1_packages: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let r1 = self.r1_secret.take().expect("part1 must run before part2");
        let (secret, packages) = refresh_dkg_part2(r1, round1_packages)?;
        self.r2_secret = Some(secret);
        Ok(packages)
    }

    /// Part 3: fold the fresh zero-sharing into `old_key_package`. Returns the refreshed key share
    /// and the (unchanged) group public key package.
    pub fn part3(
        &mut self,
        round1_packages: &BTreeMap<Identifier, round1::Package>,
        round2_packages: &BTreeMap<Identifier, round2::Package>,
        old_public_key_package: PublicKeyPackage,
        old_key_package: KeyPackage,
    ) -> Result<(KeyPackage, PublicKeyPackage)> {
        let r2 = self.r2_secret.take().expect("part2 must run before part3");
        let (key_package, public_key_package) = refresh_dkg_shares(
            &r2,
            round1_packages,
            round2_packages,
            old_public_key_package,
            old_key_package,
        )?;
        Ok((key_package, public_key_package))
    }
}

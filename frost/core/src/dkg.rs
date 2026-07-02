// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Distributed key generation (FROST DKG, trusted-dealer-free).
//!
//! Each cosigner drives its own [`DkgParticipant`] state machine through three parts, exchanging
//! the returned packages over the (authenticated) cosigner mesh:
//!
//! 1. [`DkgParticipant::part1`] → broadcast `round1::Package` to all peers.
//! 2. [`DkgParticipant::part2`] with all peers' round-1 packages → per-peer `round2::Package`s
//!    (sent point-to-point, confidentially).
//! 3. [`DkgParticipant::part3`] with all round-2 packages addressed to us → the final
//!    [`frost::keys::KeyPackage`] (this cosigner's share) + [`frost::keys::PublicKeyPackage`]
//!    (the group public key — what Canton's `getPublicKey` exports).
//!
//! The functions are pure state transitions so the transport layer stays trivial.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost::keys::dkg::{part1, part2, part3, round1, round2};
use frost::Identifier;
use rand::rngs::OsRng;

use crate::Result;

/// One cosigner's DKG state machine. Create with [`DkgParticipant::new`], then call parts in order.
pub struct DkgParticipant {
    id: Identifier,
    max_signers: u16,
    min_signers: u16,
    r1_secret: Option<round1::SecretPackage>,
    r2_secret: Option<round2::SecretPackage>,
}

impl DkgParticipant {
    pub fn new(id: Identifier, max_signers: u16, min_signers: u16) -> Self {
        Self { id, max_signers, min_signers, r1_secret: None, r2_secret: None }
    }

    /// Part 1: generate this participant's commitment package, to broadcast to every peer.
    pub fn part1(&mut self) -> Result<round1::Package> {
        let (secret, package) = part1(self.id, self.max_signers, self.min_signers, OsRng)?;
        self.r1_secret = Some(secret);
        Ok(package)
    }

    /// Part 2: given every *other* participant's round-1 package, produce the per-peer round-2
    /// packages. Each entry must be sent confidentially to the peer it is keyed by.
    pub fn part2(
        &mut self,
        round1_packages: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let r1 = self.r1_secret.take().expect("part1 must run before part2");
        let (secret, packages) = part2(r1, round1_packages)?;
        self.r2_secret = Some(secret);
        Ok(packages)
    }

    /// Part 3: given every other participant's round-1 package and the round-2 packages addressed
    /// to us, finalize. Returns this cosigner's key share and the group public key package.
    pub fn part3(
        &mut self,
        round1_packages: &BTreeMap<Identifier, round1::Package>,
        round2_packages: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<(frost::keys::KeyPackage, frost::keys::PublicKeyPackage)> {
        let r2 = self.r2_secret.take().expect("part2 must run before part3");
        let (key_package, public_key_package) = part3(&r2, round1_packages, round2_packages)?;
        Ok((key_package, public_key_package))
    }
}

/// The group public key as a 32-byte RFC 8032 Ed25519 verifying key — the raw key Canton wraps in
/// a 44-byte X.509 SubjectPublicKeyInfo.
pub fn group_verifying_key_bytes(pkp: &frost::keys::PublicKeyPackage) -> Result<[u8; 32]> {
    let bytes = pkp.verifying_key().serialize()?;
    Ok(<[u8; 32]>::try_from(bytes.as_slice()).expect("ed25519 verifying key is 32 bytes"))
}

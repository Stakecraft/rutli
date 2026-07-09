// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Per-node state and the typed peer operations. The gRPC [`crate::service`] layer and the
//! in-process [`crate::peer::LocalPeer`] both drive these methods; the wire (de)serialization lives
//! only at those edges, so this module stays type-safe.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use frost_ed25519 as frost;
use frost::keys::dkg::{round1, round2};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;

use rutli_frost_core::dkg::{group_verifying_key_bytes, DkgParticipant};
use rutli_frost_core::nonce_store::NonceStore;
use rutli_frost_core::refresh::RefreshParticipant;
use rutli_frost_core::session::{aggregate, Cosigner};

use crate::keystore::{KeyStore, Share};
use crate::{DaemonError, Result};

struct DkgState {
    key_id: String,
    participant: DkgParticipant,
}

struct RefreshState {
    key_id: String,
    participant: RefreshParticipant,
}

/// A per-key ceremony guard: only one DKG/refresh may be in progress for a given key at a time.
/// Owner is the ceremony id; a guard whose ceremony crashed mid-flight is preempted after the
/// orphan timeout (an in-progress ceremony releases its guard at part3 / on clean failure, so this
/// only ever applies to a leader that died between part1 and part3).
struct CeremonyGuard {
    owner: String,
    kind: &'static str,
    started: Instant,
}

/// How long an orphaned ceremony guard blocks a new ceremony for the same key. Longer than any
/// realistic DKG/refresh round-trip; shorter than a human's patience for a crashed ceremony.
const CEREMONY_ORPHAN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub struct Node {
    pub identifier: Identifier,
    pub max_signers: u16,
    pub min_signers: u16,
    keystore: KeyStore,
    cosigners: Mutex<std::collections::HashMap<String, Arc<Cosigner>>>,
    dkg_sessions: Mutex<std::collections::HashMap<String, DkgState>>,
    refresh_sessions: Mutex<std::collections::HashMap<String, RefreshState>>,
    // key_id -> the ceremony currently allowed to (re)write that key's share.
    ceremonies: Mutex<std::collections::HashMap<String, CeremonyGuard>>,
}

impl Node {
    pub fn new(identifier: Identifier, max_signers: u16, min_signers: u16, keystore: KeyStore) -> Self {
        Self {
            identifier,
            max_signers,
            min_signers,
            keystore,
            cosigners: Mutex::new(Default::default()),
            dkg_sessions: Mutex::new(Default::default()),
            refresh_sessions: Mutex::new(Default::default()),
            ceremonies: Mutex::new(Default::default()),
        }
    }

    /// Reserve `key_id` for ceremony `owner`. Fails if a *different*, non-orphaned ceremony holds it
    /// — this is what serializes concurrent DKG/refresh and prevents split-brain shares.
    fn acquire_ceremony(&self, key_id: &str, owner: &str, kind: &'static str) -> Result<()> {
        let mut guards = self.ceremonies.lock().expect("ceremonies lock");
        if let Some(cur) = guards.get(key_id) {
            if cur.owner != owner && cur.started.elapsed() < CEREMONY_ORPHAN_TIMEOUT {
                return Err(DaemonError::CeremonyInProgress {
                    key_id: key_id.to_string(),
                    kind: cur.kind,
                    other: cur.owner.clone(),
                });
            }
        }
        guards.insert(
            key_id.to_string(),
            CeremonyGuard { owner: owner.to_string(), kind, started: Instant::now() },
        );
        Ok(())
    }

    /// Release the guard for `key_id` iff `owner` still holds it.
    fn release_ceremony(&self, key_id: &str, owner: &str) {
        let mut guards = self.ceremonies.lock().expect("ceremonies lock");
        if guards.get(key_id).map(|c| c.owner == owner).unwrap_or(false) {
            guards.remove(key_id);
        }
    }

    /// Load (and cache) this node's cosigner state for `key_id`.
    fn cosigner(&self, key_id: &str) -> Result<Arc<Cosigner>> {
        {
            let map = self.cosigners.lock().expect("cosigners lock");
            if let Some(c) = map.get(key_id) {
                return Ok(c.clone());
            }
        }
        let share = self.keystore.load(key_id)?;
        let nonce_store = NonceStore::open(self.keystore.nonce_dir(key_id))?;
        let cosigner = Arc::new(Cosigner::new(
            share.key_package,
            share.public_key_package,
            nonce_store,
        ));
        self.cosigners
            .lock()
            .expect("cosigners lock")
            .insert(key_id.to_string(), cosigner.clone());
        Ok(cosigner)
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keystore.exists(key_id)
    }

    pub fn group_key(&self, key_id: &str) -> Result<[u8; 32]> {
        Ok(group_verifying_key_bytes(self.cosigner(key_id)?.public_key_package())?)
    }

    pub fn threshold_for(&self, key_id: &str) -> Result<u16> {
        Ok(self.cosigner(key_id)?.min_signers())
    }

    // -- signing peer ops --

    pub fn sign_round1(&self, key_id: &str, session_id: &str) -> Result<SigningCommitments> {
        Ok(self.cosigner(key_id)?.round1(session_id)?)
    }

    pub fn sign_round2(
        &self,
        key_id: &str,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        Ok(self.cosigner(key_id)?.round2(session_id, message, commitments)?)
    }

    /// Leader-side aggregation using this node's copy of the group public key.
    pub fn aggregate(
        &self,
        key_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        shares: &BTreeMap<Identifier, SignatureShare>,
    ) -> Result<[u8; 64]> {
        Ok(aggregate(message, commitments, shares, self.cosigner(key_id)?.public_key_package())?)
    }

    // -- DKG peer ops --

    pub fn dkg_part1(&self, dkg_id: &str, key_id: &str) -> Result<round1::Package> {
        // DKG must never clobber a provisioned key — the namespace key is non-rotatable, so an
        // accidental re-DKG (failover retry, ops mistake) would destroy the node's identity.
        if self.keystore.exists(key_id) {
            return Err(DaemonError::KeyExists(key_id.to_string()));
        }
        // Serialize against any other DKG/refresh for this key (prevents split-brain shares).
        self.acquire_ceremony(key_id, dkg_id, "dkg")?;
        let mut participant = DkgParticipant::new(self.identifier, self.max_signers, self.min_signers);
        match participant.part1() {
            Ok(package) => {
                self.dkg_sessions
                    .lock()
                    .expect("dkg lock")
                    .insert(dkg_id.to_string(), DkgState { key_id: key_id.to_string(), participant });
                Ok(package)
            }
            Err(e) => {
                self.release_ceremony(key_id, dkg_id);
                Err(e.into())
            }
        }
    }

    pub fn dkg_part2(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let (key_id, result) = {
            let mut sessions = self.dkg_sessions.lock().expect("dkg lock");
            let state = sessions.get_mut(dkg_id).ok_or_else(|| DaemonError::UnknownDkg(dkg_id.into()))?;
            let others = without_self(round1_map, self.identifier);
            (state.key_id.clone(), state.participant.part2(&others))
        };
        if result.is_err() {
            self.release_ceremony(&key_id, dkg_id);
        }
        Ok(result?)
    }

    pub fn dkg_part3(
        &self,
        dkg_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let mut state = {
            let mut sessions = self.dkg_sessions.lock().expect("dkg lock");
            sessions.remove(dkg_id).ok_or_else(|| DaemonError::UnknownDkg(dkg_id.into()))?
        };
        let outcome = self.finish_dkg(&mut state, round1_map, round2_for_me);
        self.release_ceremony(&state.key_id, dkg_id); // release on success and failure alike
        outcome
    }

    fn finish_dkg(
        &self,
        state: &mut DkgState,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        // Re-check under the ceremony guard: refuse if the key was provisioned meanwhile.
        if self.keystore.exists(&state.key_id) {
            return Err(DaemonError::KeyExists(state.key_id.clone()));
        }
        let others = without_self(round1_map, self.identifier);
        let (key_package, public_key_package) = state.participant.part3(&others, round2_for_me)?;

        let share = Share { key_package, public_key_package: public_key_package.clone() };
        self.keystore.save(&state.key_id, &share)?;
        // Drop any cached cosigner so it is reloaded fresh from the saved share.
        self.cosigners.lock().expect("cosigners lock").remove(&state.key_id);
        Ok(group_verifying_key_bytes(&public_key_package)?)
    }

    // -- proactive refresh peer ops (same three-part shape as DKG) --

    pub fn refresh_part1(&self, refresh_id: &str, key_id: &str) -> Result<round1::Package> {
        if !self.keystore.exists(key_id) {
            return Err(DaemonError::UnknownKey(key_id.to_string()));
        }
        // Serialize against any other DKG/refresh for this key (prevents split-brain shares).
        self.acquire_ceremony(key_id, refresh_id, "refresh")?;
        let mut participant = RefreshParticipant::new(self.identifier, self.max_signers, self.min_signers);
        match participant.part1() {
            Ok(package) => {
                self.refresh_sessions
                    .lock()
                    .expect("refresh lock")
                    .insert(refresh_id.to_string(), RefreshState { key_id: key_id.to_string(), participant });
                Ok(package)
            }
            Err(e) => {
                self.release_ceremony(key_id, refresh_id);
                Err(e.into())
            }
        }
    }

    pub fn refresh_part2(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
    ) -> Result<BTreeMap<Identifier, round2::Package>> {
        let (key_id, result) = {
            let mut sessions = self.refresh_sessions.lock().expect("refresh lock");
            let state =
                sessions.get_mut(refresh_id).ok_or_else(|| DaemonError::UnknownDkg(refresh_id.into()))?;
            let others = without_self(round1_map, self.identifier);
            (state.key_id.clone(), state.participant.part2(&others))
        };
        if result.is_err() {
            self.release_ceremony(&key_id, refresh_id);
        }
        Ok(result?)
    }

    pub fn refresh_part3(
        &self,
        refresh_id: &str,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let mut state = {
            let mut sessions = self.refresh_sessions.lock().expect("refresh lock");
            sessions.remove(refresh_id).ok_or_else(|| DaemonError::UnknownDkg(refresh_id.into()))?
        };
        let outcome = self.finish_refresh(&mut state, round1_map, round2_for_me);
        self.release_ceremony(&state.key_id, refresh_id);
        outcome
    }

    fn finish_refresh(
        &self,
        state: &mut RefreshState,
        round1_map: &BTreeMap<Identifier, round1::Package>,
        round2_for_me: &BTreeMap<Identifier, round2::Package>,
    ) -> Result<[u8; 32]> {
        let old = self.keystore.load(&state.key_id)?;
        let old_group = group_verifying_key_bytes(&old.public_key_package)?;
        let others = without_self(round1_map, self.identifier);
        let (key_package, public_key_package) = state.participant.part3(
            &others,
            round2_for_me,
            old.public_key_package,
            old.key_package,
        )?;

        let new_group = group_verifying_key_bytes(&public_key_package)?;
        if new_group != old_group {
            // Never persist a share whose group key drifted — that would change the node identity.
            return Err(DaemonError::Disagreement(format!(
                "refresh changed the group key for {} — aborting",
                state.key_id
            )));
        }

        let share = Share { key_package, public_key_package };
        self.keystore.save(&state.key_id, &share)?;
        self.cosigners.lock().expect("cosigners lock").remove(&state.key_id);
        Ok(new_group)
    }
}

fn without_self(
    map: &BTreeMap<Identifier, round1::Package>,
    me: Identifier,
) -> BTreeMap<Identifier, round1::Package> {
    map.iter().filter(|(&id, _)| id != me).map(|(&id, p)| (id, p.clone())).collect()
}

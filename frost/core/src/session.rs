// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Two-round FROST signing.
//!
//! Roles:
//! - Every cosigner holds a [`Cosigner`] (its key share + nonce store) and answers round-1 /
//!   round-2 calls.
//! - The session leader (any cosigner; leader election is the daemon's concern) drives
//!   [`aggregate`] once ≥ `min_signers` shares are in.
//!
//! Flow for one signature over Canton's 34-byte digest `m`:
//!
//! ```text
//! leader                                  each participating cosigner i
//!   │  round1(session)                      │
//!   ├───────────────────────────────────────►  commit: fresh nonces (held in RAM, keyed by
//!   │              commitments_i            │  session), commitments returned
//!   ◄───────────────────────────────────────┤
//!   │  round2(session, m, all commitments)  │
//!   ├───────────────────────────────────────►  BURN session in NonceStore (crash-safe, single
//!   │              share_i                  │  use), then produce the signature share
//!   ◄───────────────────────────────────────┤
//!   │  aggregate(shares) → 64-byte RFC 8032 signature
//! ```
//!
//! The aggregated signature is a standard Ed25519 signature over `m` under the group key —
//! Canton's verifier cannot tell it from a single-signer one.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use frost_ed25519 as frost;
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use rand::rngs::OsRng;

use crate::nonce_store::NonceStore;
use crate::{CoreError, Result};

/// One cosigner's signing-side state: its DKG-produced key share, the group public key package,
/// and the crash-safe nonce guard. In-flight session nonces live only in RAM — a crash simply
/// aborts those sessions (the leader retries with a new session id).
pub struct Cosigner {
    key_package: frost::keys::KeyPackage,
    public_key_package: frost::keys::PublicKeyPackage,
    nonce_store: NonceStore,
    // session id -> (nonces, when round1 minted them). Orphaned entries (round1 without round2 —
    // leader gave up / crashed) are pruned by age so RAM cannot grow unbounded.
    pending: Mutex<BTreeMap<String, (SigningNonces, Instant)>>,
}

/// Max lifetime of an un-completed round-1 session before it is pruned. Comfortably longer than any
/// real sign round-trip; a leader that hasn't finished by then has abandoned the session.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

impl Cosigner {
    pub fn new(
        key_package: frost::keys::KeyPackage,
        public_key_package: frost::keys::PublicKeyPackage,
        nonce_store: NonceStore,
    ) -> Self {
        Self { key_package, public_key_package, nonce_store, pending: Mutex::new(BTreeMap::new()) }
    }

    pub fn identifier(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// The signing threshold `t` this share was generated for.
    pub fn min_signers(&self) -> u16 {
        *self.key_package.min_signers()
    }

    pub fn public_key_package(&self) -> &frost::keys::PublicKeyPackage {
        &self.public_key_package
    }

    /// Round 1: generate fresh nonces for `session_id` and return the commitments.
    ///
    /// Refuses sessions whose nonce was already burned (a replayed session id must never mint new
    /// nonces — the leader generates a fresh UUID per attempt).
    pub fn round1(&self, session_id: &str) -> Result<SigningCommitments> {
        if self.nonce_store.is_consumed(session_id)? {
            return Err(CoreError::NonceReuse(session_id.to_string()));
        }
        let mut pending = self.pending.lock().expect("pending lock");
        // Prune orphaned sessions so pending can't grow without bound.
        pending.retain(|_, (_, started)| started.elapsed() < PENDING_TTL);
        // Refuse to overwrite live nonces for an in-flight session id — a duplicate round1 (replay
        // or a confused/hostile caller) must not silently discard the pending nonces of a session
        // that hasn't reached round2. The caller should use a fresh session id (or abort first).
        if pending.contains_key(session_id) {
            return Err(CoreError::DuplicateSession(session_id.to_string()));
        }
        let (nonces, commitments) =
            frost::round1::commit(self.key_package.signing_share(), &mut OsRng);
        pending.insert(session_id.to_string(), (nonces, Instant::now()));
        Ok(commitments)
    }

    /// Round 2: produce this cosigner's signature share for `message` under the full commitment
    /// set. The session is burned in the [`NonceStore`] *before* the share is computed — this is
    /// the crash-safe single-use guarantee.
    pub fn round2(
        &self,
        session_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SignatureShare> {
        let (nonces, _started) = self
            .pending
            .lock()
            .expect("pending lock")
            .remove(session_id)
            .ok_or_else(|| CoreError::UnknownSession(session_id.to_string()))?;

        // Burn FIRST. If we crash after this point the session is lost, never reused.
        self.nonce_store.consume(session_id)?;

        let signing_package = SigningPackage::new(commitments.clone(), message);
        let share = frost::round2::sign(&signing_package, &nonces, &self.key_package)?;
        Ok(share)
    }

    /// Abort an in-flight session (leader gave up / peer timeout). Frees the RAM nonces; the
    /// session id itself stays usable only if round 2 never ran.
    pub fn abort(&self, session_id: &str) {
        self.pending.lock().expect("pending lock").remove(session_id);
    }

    /// Number of in-flight (round-1, not yet round-2) sessions. For observability/tests.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().expect("pending lock").len()
    }
}

/// Leader-side aggregation: combine ≥ `min_signers` shares into the final 64-byte RFC 8032
/// signature. Verification against the group key happens inside `frost::aggregate` — a corrupt
/// share is detected and attributed.
pub fn aggregate(
    message: &[u8],
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<[u8; 64]> {
    let signing_package = SigningPackage::new(commitments.clone(), message);
    let signature = frost::aggregate(&signing_package, shares, public_key_package)?;
    let bytes = signature.serialize()?;
    Ok(<[u8; 64]>::try_from(bytes.as_slice()).expect("ed25519 signature is 64 bytes"))
}

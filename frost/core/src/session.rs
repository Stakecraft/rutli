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
//!
//! **Session binding.** Round 1 binds the session to a [`SessionBinding`]: the key, the message
//! the leader declares it will sign, the signer set of the attempt, and (once signing intents
//! exist, audit C2) the digest of the verified intent. Round 2 must present exactly the same —
//! and this cosigner's own round-1 commitment, unchanged, in the commitment map — or it is refused
//! **before** the nonce marker burns, and the session's nonces are dropped. So a round 2 can never
//! sign another message or under another commitment set than round 1 was opened for, whoever
//! sends it. Unset fields (a leader from before binding) are not checked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use frost_ed25519 as frost;
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};
use rand::rngs::OsRng;

use crate::nonce_store::NonceStore;
use crate::{CoreError, Result};

/// What round 1 binds a signing session to. Round 2 must match it (see the module docs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionBinding {
    /// The key the session signs with.
    pub key_id: String,
    /// SHA-256 of the message the leader declared at round 1. `None`: not declared (a leader from
    /// before session binding) — any message is accepted at round 2.
    pub message_digest: Option<[u8; 32]>,
    /// The signer set of this attempt as declared at round 1: round 2's commitment map must hold
    /// exactly these identifiers. `None`: not declared.
    pub signers: Option<BTreeSet<Identifier>>,
    /// SHA-256 of the signing intent the cosigner verified at round 1 (audit C2); `None` for a
    /// session opened without one. Round 2 must present the same value.
    pub intent_digest: Option<[u8; 32]>,
}

impl SessionBinding {
    pub fn new(key_id: impl Into<String>) -> Self {
        Self { key_id: key_id.into(), ..Default::default() }
    }

    /// Bind the message the session will sign.
    pub fn with_message(mut self, message: &[u8]) -> Self {
        self.message_digest = Some(sha256(message));
        self
    }

    /// Bind the attempt's signer set.
    pub fn with_signers(mut self, signers: impl IntoIterator<Item = Identifier>) -> Self {
        self.signers = Some(signers.into_iter().collect());
        self
    }

    /// Bind the verified signing intent (audit C2).
    pub fn with_intent_digest(mut self, digest: [u8; 32]) -> Self {
        self.intent_digest = Some(digest);
        self
    }

    /// Whether a round 2 presenting these values matches this binding; `Err` names what differs.
    fn check(
        &self,
        key_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> std::result::Result<(), &'static str> {
        if self.key_id != key_id {
            return Err("another key");
        }
        if self.message_digest.is_some_and(|d| d != sha256(message)) {
            return Err("another message than the leader declared");
        }
        if self.signers.as_ref().is_some_and(|s| !s.iter().eq(commitments.keys())) {
            return Err("another signer set than the leader declared");
        }
        if self.intent_digest.as_ref() != intent_digest {
            return Err("another signing intent");
        }
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// One in-flight session: its nonces, the commitments round 1 returned, when, and its binding.
struct Pending {
    nonces: SigningNonces,
    commitments: SigningCommitments,
    started: Instant,
    binding: SessionBinding,
}

/// One cosigner's signing-side state: its DKG-produced key share, the group public key package,
/// and the crash-safe nonce guard. In-flight session nonces live only in RAM — a crash simply
/// aborts those sessions (the leader retries with a new session id).
pub struct Cosigner {
    key_package: frost::keys::KeyPackage,
    public_key_package: frost::keys::PublicKeyPackage,
    nonce_store: NonceStore,
    // session id -> its nonces, commitments, start and binding. Orphaned entries (round1 without
    // round2 — leader gave up / crashed) are pruned by age so RAM cannot grow unbounded.
    pending: Mutex<BTreeMap<String, Pending>>,
}

/// How many times a [`Cosigner`]'s in-flight session map was recovered after a holder panicked
/// (its sessions dropped), process-wide. The daemon exports it as a metric.
static LOCK_POISON_RECOVERIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// See [`LOCK_POISON_RECOVERIES`].
pub fn lock_poison_recoveries() -> u64 {
    LOCK_POISON_RECOVERIES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Max lifetime of an un-completed round-1 session: pruned after it, and refused at round 2 past it.
/// Comfortably longer than any real sign round-trip; a leader that hasn't finished by then has
/// abandoned the session.
pub const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// How long a burned-session marker is kept before it may be pruned
/// ([`NonceStore::prune_older_than`], which proves why that is safe): the pending TTL plus a
/// margin of twice as much again.
pub const MARKER_RETENTION: Duration = Duration::from_secs(3 * PENDING_TTL.as_secs());

impl Cosigner {
    pub fn new(
        key_package: frost::keys::KeyPackage,
        public_key_package: frost::keys::PublicKeyPackage,
        nonce_store: NonceStore,
    ) -> Self {
        Self { key_package, public_key_package, nonce_store, pending: Mutex::new(BTreeMap::new()) }
    }

    /// The in-flight session map, recovered if a holder panicked (audit L3).
    ///
    /// Every critical section on this map is a single std map operation (or frost's nonce
    /// generation, which panics only if the OS RNG fails), so a panicking holder leaves the map
    /// structurally valid — but rather than trust an entry such a holder may have been inserting or
    /// taking, recovery **drops every in-flight session**: discarding never-used nonces is always
    /// safe (those sessions fail round 2 with an unknown session and the leader retries with fresh
    /// ones), and the burned-session markers on disk, the single-use guarantee, are untouched. The
    /// cosigner keeps serving new sessions instead of every later call panicking on the poison.
    fn pending(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|poisoned| {
            let mut map = poisoned.into_inner();
            map.clear();
            self.pending.clear_poison();
            LOCK_POISON_RECOVERIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            map
        })
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

    /// Round 1: generate fresh nonces for `session_id`, bound to `binding`, and return the
    /// commitments.
    ///
    /// Refuses sessions whose nonce was already burned (a replayed session id must never mint new
    /// nonces — the leader generates a fresh UUID per attempt), and a binding that cannot be
    /// honoured: a declared signer set without this cosigner or smaller than the threshold.
    pub fn round1(&self, session_id: &str, binding: SessionBinding) -> Result<SigningCommitments> {
        if let Some(signers) = &binding.signers {
            if !signers.contains(&self.identifier()) || signers.len() < usize::from(self.min_signers()) {
                return Err(CoreError::InvalidBinding(format!(
                    "the declared signer set has {} member(s) and must include this cosigner and at \
                     least {} signers",
                    signers.len(),
                    self.min_signers()
                )));
            }
        }
        if self.nonce_store.is_consumed(session_id)? {
            return Err(CoreError::NonceReuse(session_id.to_string()));
        }
        let mut pending = self.pending();
        // Prune orphaned sessions so pending can't grow without bound.
        pending.retain(|_, p| p.started.elapsed() < PENDING_TTL);
        // Refuse to overwrite live nonces for an in-flight session id — a duplicate round1 (replay
        // or a confused/hostile caller) must not silently discard the pending nonces of a session
        // that hasn't reached round2. The caller should use a fresh session id (or abort first).
        if pending.contains_key(session_id) {
            return Err(CoreError::DuplicateSession(session_id.to_string()));
        }
        let (nonces, commitments) =
            frost::round1::commit(self.key_package.signing_share(), &mut OsRng);
        pending.insert(
            session_id.to_string(),
            Pending { nonces, commitments, started: Instant::now(), binding },
        );
        Ok(commitments)
    }

    /// Round 2: produce this cosigner's signature share for `message` under the full commitment
    /// set, for the key `key_id` and the signing intent `intent_digest` (`None` for a session
    /// opened without one). Everything must match the session's round-1 [`SessionBinding`], the commitment map
    /// must carry this cosigner's own round-1 commitment unchanged, and it must have at least the
    /// threshold of signers — all checked **before** the marker burns; on a mismatch the session's
    /// nonces are dropped (no share is ever released for it). Then the session is burned in the
    /// [`NonceStore`] *before* the share is computed — this is the crash-safe single-use guarantee.
    pub fn round2(
        &self,
        session_id: &str,
        key_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
    ) -> Result<SignatureShare> {
        self.round2_guarded(session_id, key_id, message, commitments, intent_digest, || Ok(()))
    }

    /// [`Cosigner::round2`] with a `guard` run **after** every binding check passed and **before**
    /// the nonce marker burns — the one point where it is certain that this session will release a
    /// share unless the marker write or the share computation itself fails. The daemon runs its
    /// signing policy there (audit C2: rate limit, durable journal entry), so a refused or
    /// mismatched round 2 is never charged or journaled, and a share never leaves without its
    /// journal entry. A guard error releases nothing: the session's nonces are already out of the
    /// pending map and are dropped, and the marker is not written (the session id stays unusable
    /// anyway — its nonces are gone).
    pub fn round2_guarded<E: From<CoreError>>(
        &self,
        session_id: &str,
        key_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
        guard: impl FnOnce() -> std::result::Result<(), E>,
    ) -> std::result::Result<SignatureShare, E> {
        let p = self
            .pending()
            .remove(session_id)
            .ok_or_else(|| CoreError::UnknownSession(session_id.to_string()))?;
        // An entry past the TTL is dead even if no sweep removed it yet: the marker-pruning proof
        // (NonceStore::prune_older_than) relies on no nonce older than PENDING_TTL ever signing.
        if p.started.elapsed() >= PENDING_TTL {
            return Err(CoreError::UnknownSession(format!("{session_id} (expired)")).into());
        }
        let mismatch = |what| CoreError::BindingMismatch { session: session_id.to_string(), what };
        p.binding.check(key_id, message, commitments, intent_digest).map_err(mismatch)?;
        if commitments.get(&self.identifier()) != Some(&p.commitments) {
            return Err(mismatch("this cosigner's own round-1 commitment is missing or altered").into());
        }
        if commitments.len() < usize::from(self.min_signers()) {
            return Err(mismatch("fewer signers than the threshold").into());
        }

        guard()?;

        // Burn FIRST. If we crash after this point the session is lost, never reused.
        self.nonce_store.consume(session_id)?;

        let signing_package = SigningPackage::new(commitments.clone(), message);
        let share = frost::round2::sign(&signing_package, &p.nonces, &self.key_package).map_err(CoreError::from)?;
        Ok(share)
    }

    /// Abort an in-flight session (leader gave up / peer timeout). Frees the RAM nonces; the
    /// session id itself stays usable only if round 2 never ran.
    pub fn abort(&self, session_id: &str) {
        self.pending().remove(session_id);
    }

    /// Drop in-flight sessions older than the pending TTL — the same sweep `round1` runs on every
    /// call, for a node that is not getting round-1 calls (e.g. one refusing them while its key
    /// store is down). Returns how many were dropped.
    pub fn prune_expired(&self) -> usize {
        let mut pending = self.pending();
        let before = pending.len();
        pending.retain(|_, p| p.started.elapsed() < PENDING_TTL);
        before - pending.len()
    }

    /// Number of in-flight (round-1, not yet round-2) sessions. For observability/tests.
    pub fn pending_count(&self) -> usize {
        self.pending().len()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cosigner(dir: &std::path::Path) -> Cosigner {
        let (shares, pkp) = crate::dealer::split_ed25519_seed(&[5; 32], &[1, 2, 3], 2).unwrap();
        let kp = frost::keys::KeyPackage::try_from(shares[0].clone()).unwrap();
        Cosigner::new(kp, pkp, NonceStore::open(dir).unwrap())
    }

    /// A session past the pending TTL never signs, even before a sweep removed it — the marker
    /// pruning proof (`NonceStore::prune_older_than`) depends on it.
    #[test]
    fn round2_refuses_a_session_older_than_the_pending_ttl_without_burning() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        let mine = c.round1("old", SessionBinding::new("k")).unwrap();
        let Some(long_ago) = Instant::now().checked_sub(PENDING_TTL + Duration::from_secs(1)) else {
            return; // monotonic clock too close to its origin to backdate
        };
        c.pending.lock().unwrap().get_mut("old").unwrap().started = long_ago;
        let commitments = BTreeMap::from([(c.identifier(), mine)]);
        let err = c.round2("old", "k", &[0; 34], &commitments, None).unwrap_err();
        assert!(matches!(err, CoreError::UnknownSession(ref s) if s.contains("expired")), "{err:?}");
        assert!(!c.nonce_store.is_consumed("old").unwrap(), "an expired session is not burned");
        assert_eq!(c.pending_count(), 0);
    }

    /// The round-2 guard runs only once every binding check passed, before the marker burns; a
    /// guard refusal releases nothing and burns nothing, and a binding mismatch never reaches it.
    #[test]
    fn the_round2_guard_runs_after_the_binding_checks_and_before_the_burn() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        let msg = [7u8; 34];

        // Binding mismatch: the guard is never called.
        let mine = c.round1("s1", SessionBinding::new("k").with_message(&msg)).unwrap();
        let commitments = BTreeMap::from([(c.identifier(), mine)]);
        let called = std::cell::Cell::new(false);
        let err = c
            .round2_guarded::<CoreError>("s1", "k", &[8u8; 34], &commitments, None, || {
                called.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err, CoreError::BindingMismatch { .. }), "{err:?}");
        assert!(!called.get());

        // Guard refuses: no marker, the session is gone.
        let (shares, pkp) = crate::dealer::split_ed25519_seed(&[5; 32], &[1, 2, 3], 2).unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let other = Cosigner::new(
            frost::keys::KeyPackage::try_from(shares[1].clone()).unwrap(),
            pkp,
            NonceStore::open(tmp2.path()).unwrap(),
        );
        let mine = c.round1("s2", SessionBinding::new("k").with_message(&msg)).unwrap();
        let theirs = other.round1("s2", SessionBinding::new("k")).unwrap();
        let commitments = BTreeMap::from([(c.identifier(), mine), (other.identifier(), theirs)]);
        let err = c
            .round2_guarded("s2", "k", &msg, &commitments, None, || Err(CoreError::Dealer("refused".into())))
            .unwrap_err();
        assert!(matches!(err, CoreError::Dealer(_)), "{err:?}");
        assert!(!c.nonce_store.is_consumed("s2").unwrap(), "a refused round 2 burns no marker");
        assert_eq!(c.pending_count(), 0);
    }

    /// Audit L3: a panic while the session map is held must not take the cosigner down with it.
    #[test]
    fn a_panicking_holder_of_the_session_map_drops_in_flight_sessions_and_the_cosigner_serves_on() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        c.round1("in-flight", SessionBinding::new("k")).unwrap();
        let before = lock_poison_recoveries();

        let panicked = std::thread::scope(|s| {
            s.spawn(|| {
                let _held = c.pending.lock().unwrap();
                panic!("test: panic while holding the session map");
            })
            .join()
        });
        assert!(panicked.is_err() && c.pending.is_poisoned());

        // The next caller recovers: the in-flight session is dropped (fail closed), a new one works.
        assert_eq!(c.pending_count(), 0);
        assert!(!c.pending.is_poisoned());
        assert!(lock_poison_recoveries() > before);
        c.round1("after", SessionBinding::new("k")).unwrap();
        assert_eq!(c.pending_count(), 1);
        let commitments = BTreeMap::new();
        assert!(matches!(
            c.round2("in-flight", "k", &[0; 34], &commitments, None),
            Err(CoreError::UnknownSession(_))
        ));
    }
}

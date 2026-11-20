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

/// Who opened a sign session on this cosigner. Only the same caller may send its round 2 or abort
/// it: a member of a session knows its id, and must not be able to use up or drop another
/// leader's session on this node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionOwner {
    /// This node's own leader, calling in process. No remote caller is ever this owner.
    Local,
    /// A remote caller, by the Common Name of its client certificate.
    Peer(String),
    /// A remote caller without a certificate (a plaintext dev mesh). Such callers cannot be told
    /// apart, so they are one owner, as before sessions had owners.
    Unidentified,
}

impl std::fmt::Display for SessionOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionOwner::Local => f.write_str("this node's own leader"),
            SessionOwner::Peer(cn) => write!(f, "peer '{cn}'"),
            SessionOwner::Unidentified => f.write_str("an unidentified peer (no client certificate)"),
        }
    }
}

/// Which cap on waiting sessions refused a round 1 ([`CoreError::SessionsFull`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCap {
    /// All openers together, for the key.
    Key,
    /// One opener, for the key.
    Opener,
    /// One opener, for one signing request (an intent's request id).
    Request,
}

impl PendingCap {
    /// The metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            PendingCap::Key => "key",
            PendingCap::Opener => "opener",
            PendingCap::Request => "request",
        }
    }

    pub(crate) fn what(self) -> &'static str {
        match self {
            PendingCap::Key => "for this key from all openers",
            PendingCap::Opener => "for this key from this opener",
            PendingCap::Request => "for this signing request from this opener",
        }
    }
}

/// Most sessions waiting for round 2 at once: per key, per (key, opener) and per (key, opener,
/// request id). Checked in round 1 under the same lock as the insert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingCaps {
    pub per_key: usize,
    pub per_owner: usize,
    pub per_request: usize,
}

impl PendingCaps {
    /// No caps (the TTL still bounds how long a session lives).
    pub const NONE: PendingCaps = PendingCaps { per_key: usize::MAX, per_owner: usize::MAX, per_request: usize::MAX };
}

/// One in-flight session: its nonces, the commitments round 1 returned, when, its binding, who
/// opened it and for which signing request.
struct Pending {
    nonces: SigningNonces,
    commitments: SigningCommitments,
    started: Instant,
    binding: SessionBinding,
    owner: SessionOwner,
    request: Option<String>,
}

/// Whether `pending` has room for one more session of `owner` (and `request`) under `caps`; the
/// caller has dropped expired entries. The opener's own caps are checked first, so an opener at
/// its cap is told so even when the key is full too.
fn check_room(
    pending: &BTreeMap<String, Pending>,
    owner: &SessionOwner,
    request: Option<&str>,
    caps: PendingCaps,
) -> Result<()> {
    let full = |cap_kind, open, cap| Err(CoreError::SessionsFull { cap_kind, open, cap });
    let (mut mine, mut this_request) = (0usize, 0usize);
    for p in pending.values().filter(|p| &p.owner == owner) {
        mine += 1;
        if request.is_some() && p.request.as_deref() == request {
            this_request += 1;
        }
    }
    if request.is_some() && this_request >= caps.per_request {
        return full(PendingCap::Request, this_request, caps.per_request);
    }
    if mine >= caps.per_owner {
        return full(PendingCap::Opener, mine, caps.per_owner);
    }
    if pending.len() >= caps.per_key {
        return full(PendingCap::Key, pending.len(), caps.per_key);
    }
    Ok(())
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

/// The signing share is wiped when the cosigner is dropped (an evicted or replaced cache entry, a
/// refresh, shutdown). frost's `KeyPackage` implements `Zeroize` but does not wipe itself on drop.
impl Drop for Cosigner {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key_package);
    }
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
        self.round1_owned(session_id, binding, SessionOwner::Local, None, PendingCaps::NONE)
    }

    /// [`Cosigner::round1`] for `owner`, who alone may then send the session's round 2 or abort
    /// it, for signing request `request` (an intent's request id; `None` without one). Refused with
    /// [`CoreError::SessionsFull`] when `caps` leave no room, checked under the same lock as the
    /// insert after expired sessions are dropped.
    pub fn round1_owned(
        &self,
        session_id: &str,
        binding: SessionBinding,
        owner: SessionOwner,
        request: Option<String>,
        caps: PendingCaps,
    ) -> Result<SigningCommitments> {
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
        check_room(&pending, &owner, request.as_deref(), caps)?;
        let (nonces, commitments) =
            frost::round1::commit(self.key_package.signing_share(), &mut OsRng);
        pending.insert(
            session_id.to_string(),
            Pending { nonces, commitments, started: Instant::now(), binding, owner, request },
        );
        Ok(commitments)
    }

    /// Whether a round 1 by `owner` for `request` would find room under `caps`, after dropping
    /// expired sessions. A snapshot for refusing early, before the costlier checks; the check that
    /// holds is the one in [`Cosigner::round1_owned`].
    pub fn check_room(&self, owner: &SessionOwner, request: Option<&str>, caps: PendingCaps) -> Result<()> {
        let mut pending = self.pending();
        pending.retain(|_, p| p.started.elapsed() < PENDING_TTL);
        check_room(&pending, owner, request, caps)
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
        self.round2_guarded_as(&SessionOwner::Local, session_id, key_id, message, commitments, intent_digest, guard)
    }

    /// [`Cosigner::round2_guarded`] sent by `caller`. A live session that another caller opened is
    /// refused with [`CoreError::NotSessionOwner`] and left as it is, nonces and all; only then is
    /// the session taken out of the pending map.
    #[allow(clippy::too_many_arguments)]
    pub fn round2_guarded_as<E: From<CoreError>>(
        &self,
        caller: &SessionOwner,
        session_id: &str,
        key_id: &str,
        message: &[u8],
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        intent_digest: Option<&[u8; 32]>,
        guard: impl FnOnce() -> std::result::Result<(), E>,
    ) -> std::result::Result<SignatureShare, E> {
        let p = {
            let mut pending = self.pending();
            match pending.get(session_id) {
                None => return Err(CoreError::UnknownSession(session_id.to_string()).into()),
                Some(p) if &p.owner != caller && p.started.elapsed() < PENDING_TTL => {
                    return Err(not_owner(session_id, &p.owner, caller).into());
                }
                Some(_) => pending.remove(session_id).expect("the entry was just found"),
            }
        };
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

    /// Abort an in-flight session (leader gave up / peer timeout), asked by `caller`. Frees the RAM
    /// nonces; the session id itself stays usable only if round 2 never ran. A live session that
    /// another caller opened is refused with [`CoreError::NotSessionOwner`] and kept. `Ok(true)` if
    /// a session was dropped. There is no unchecked abort.
    pub fn abort_as(&self, session_id: &str, caller: &SessionOwner) -> Result<bool> {
        let mut pending = self.pending();
        match pending.get(session_id) {
            None => Ok(false),
            Some(p) if &p.owner != caller && p.started.elapsed() < PENDING_TTL => {
                Err(not_owner(session_id, &p.owner, caller))
            }
            Some(_) => Ok(pending.remove(session_id).is_some()),
        }
    }

    /// Refuse `caller` if a live session `session_id` belongs to another caller; nothing changes
    /// either way. A snapshot, for refusing before anything is taken; round 2 and abort check again
    /// under the lock that takes the session.
    pub fn check_owner(&self, session_id: &str, caller: &SessionOwner) -> Result<()> {
        match self.pending().get(session_id) {
            Some(p) if &p.owner != caller && p.started.elapsed() < PENDING_TTL => {
                Err(not_owner(session_id, &p.owner, caller))
            }
            _ => Ok(()),
        }
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

    /// Whether this cosigner holds round-1 nonces that round 2 would still use for `session_id`.
    /// An entry past the pending TTL does not count: round 2 refuses it as unknown. Such an entry
    /// is dropped here, as round 2 and the sweeps drop it, so a caller that answers "unknown"
    /// on a `false` leaves nothing behind. The answer is only a snapshot (a round 1 or an abort
    /// may follow), so it must never be the reason to release a share, only to say why none is
    /// released.
    pub fn holds_session(&self, session_id: &str) -> bool {
        let mut pending = self.pending();
        match pending.get(session_id) {
            Some(p) if p.started.elapsed() < PENDING_TTL => true,
            Some(_) => {
                pending.remove(session_id);
                false
            }
            None => false,
        }
    }

    /// Number of in-flight (round-1, not yet round-2) sessions. For observability/tests.
    pub fn pending_count(&self) -> usize {
        self.pending().len()
    }
}

fn not_owner(session_id: &str, owner: &SessionOwner, caller: &SessionOwner) -> CoreError {
    CoreError::NotSessionOwner { session: session_id.to_string(), owner: owner.to_string(), caller: caller.to_string() }
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

    /// Node 2 of the same 2-of-3 sharing as [`cosigner`], with its own nonce store under `dir`.
    fn second_cosigner(dir: &std::path::Path) -> Cosigner {
        let (shares, pkp) = crate::dealer::split_ed25519_seed(&[5; 32], &[1, 2, 3], 2).unwrap();
        let kp = frost::keys::KeyPackage::try_from(shares[1].clone()).unwrap();
        Cosigner::new(kp, pkp, NonceStore::open(dir.join("second")).unwrap())
    }

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

    /// `holds_session` counts only nonces round 2 would still use, and drops an entry past the
    /// TTL instead of leaving it for the next sweep. It leaves live sessions alone.
    #[test]
    fn holds_session_is_true_for_live_nonces_only_and_drops_an_expired_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        c.round1("old", SessionBinding::new("k")).unwrap();
        c.round1("live", SessionBinding::new("k")).unwrap();
        assert!(c.holds_session("old") && c.holds_session("live") && !c.holds_session("never opened"));
        assert_eq!(c.pending_count(), 2, "asking changes nothing while the sessions are live");
        let Some(long_ago) = Instant::now().checked_sub(PENDING_TTL + Duration::from_secs(1)) else {
            return; // monotonic clock too close to its origin to backdate
        };
        c.pending.lock().unwrap().get_mut("old").unwrap().started = long_ago;
        assert!(!c.holds_session("old"), "an expired session is not held");
        assert_eq!(c.pending_count(), 1, "the expired entry is gone, the live one is not");
        assert!(c.holds_session("live"));
        assert!(!c.nonce_store.is_consumed("old").unwrap(), "nothing is burned for it");
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

    /// Only the caller that opened a session may send its round 2 or abort it. Another caller is
    /// refused before anything is taken, with a round 2 that would otherwise sign (valid commitment
    /// map, matching binding): the session keeps its nonces, and its opener's round 2 then signs.
    #[test]
    fn only_the_opener_may_advance_or_abort_a_session() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        let other = second_cosigner(tmp.path());
        let msg = [3u8; 34];
        let (b, mallory) = (SessionOwner::Peer("cosigner2".into()), SessionOwner::Peer("cosigner3".into()));
        let binding = || SessionBinding::new("k").with_message(&msg);
        let mine = c.round1_owned("s", binding(), b.clone(), None, PendingCaps::NONE).unwrap();
        let theirs = other.round1("s", binding()).unwrap();
        let commitments = BTreeMap::from([(c.identifier(), mine), (other.identifier(), theirs)]);

        for caller in [&mallory, &SessionOwner::Local, &SessionOwner::Unidentified] {
            assert!(matches!(c.check_owner("s", caller), Err(CoreError::NotSessionOwner { .. })));
            assert!(matches!(c.abort_as("s", caller), Err(CoreError::NotSessionOwner { .. })), "{caller}");
            let err = c
                .round2_guarded_as::<CoreError>(caller, "s", "k", &msg, &commitments, None, || {
                    panic!("a refused round 2 never reaches the guard")
                })
                .unwrap_err();
            match err {
                CoreError::NotSessionOwner { ref owner, caller: ref who, .. } => {
                    assert_eq!((owner.as_str(), who.as_str()), ("peer 'cosigner2'", caller.to_string().as_str()));
                }
                other => panic!("{other:?}"),
            }
            assert!(c.holds_session("s"), "the session keeps its nonces");
        }
        assert!(!c.nonce_store.is_consumed("s").unwrap());

        // The opener signs with the same request.
        c.round2_guarded_as::<CoreError>(&b, "s", "k", &msg, &commitments, None, || Ok(())).unwrap();
        assert!(c.nonce_store.is_consumed("s").unwrap());
        assert_eq!(c.pending_count(), 0);

        // And the opener's abort drops its session; a second abort finds nothing to refuse.
        c.round1_owned("t", binding(), b.clone(), None, PendingCaps::NONE).unwrap();
        c.check_owner("t", &b).unwrap();
        assert!(c.abort_as("t", &b).unwrap());
        assert!(!c.abort_as("t", &mallory).unwrap(), "nothing left to refuse");
        assert_eq!(c.pending_count(), 0);
    }

    /// An expired session is dead for every caller: neither round 2 nor abort is a refusal then,
    /// and both leave nothing behind.
    #[test]
    fn an_expired_session_is_unknown_to_every_caller() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        let owner = SessionOwner::Peer("cosigner2".into());
        let other = SessionOwner::Peer("cosigner3".into());
        let long_ago = Instant::now()
            .checked_sub(PENDING_TTL + Duration::from_secs(1))
            .expect("the monotonic clock can be backdated by the TTL");
        let commitments = |m| BTreeMap::from([(c.identifier(), m)]);
        let mine = c.round1_owned("old", SessionBinding::new("k"), owner.clone(), None, PendingCaps::NONE).unwrap();
        c.pending.lock().unwrap().get_mut("old").unwrap().started = long_ago;
        c.check_owner("old", &other).unwrap();
        let err = c
            .round2_guarded_as::<CoreError>(&other, "old", "k", &[0; 34], &commitments(mine), None, || Ok(()))
            .unwrap_err();
        assert!(matches!(err, CoreError::UnknownSession(ref s) if s.contains("expired")), "{err:?}");
        assert_eq!(c.pending_count(), 0);

        c.round1_owned("old2", SessionBinding::new("k"), owner, None, PendingCaps::NONE).unwrap();
        c.pending.lock().unwrap().get_mut("old2").unwrap().started = long_ago;
        assert!(c.abort_as("old2", &other).unwrap(), "an expired entry is dropped, not refused");
        assert_eq!(c.pending_count(), 0);
        assert!(!c.nonce_store.is_consumed("old2").unwrap());
    }

    /// The caps on waiting sessions: per request and per opener first, then the key's total. An
    /// opener at its cap leaves the others their room, and an opener's request cap leaves its
    /// other requests theirs.
    #[test]
    fn round1_caps_per_request_per_opener_and_per_key() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cosigner(tmp.path());
        let caps = PendingCaps { per_key: 6, per_owner: 3, per_request: 2 };
        let (a, b, d) =
            (SessionOwner::Peer("a".into()), SessionOwner::Peer("b".into()), SessionOwner::Local);
        let open = |id: &str, who: &SessionOwner, req: Option<&str>| {
            c.round1_owned(id, SessionBinding::new("k"), who.clone(), req.map(str::to_owned), caps)
        };
        let full = |r: Result<SigningCommitments>| match r {
            Err(CoreError::SessionsFull { cap_kind, open, cap }) => (cap_kind, open, cap),
            other => panic!("{other:?}"),
        };
        open("a1", &a, Some("r1")).unwrap();
        open("a2", &a, Some("r1")).unwrap();
        assert_eq!(full(open("a3", &a, Some("r1"))), (PendingCap::Request, 2, 2));
        // Another opener with the same request id is not counted against a's.
        open("b1", &b, Some("r1")).unwrap();
        open("a3", &a, Some("r2")).unwrap();
        assert_eq!(full(open("a4", &a, None)), (PendingCap::Opener, 3, 3));
        assert!(c.check_room(&a, None, caps).is_err());
        assert!(matches!(c.check_room(&b, Some("r1"), PendingCaps { per_request: 1, ..caps }), Err(CoreError::SessionsFull { cap_kind: PendingCap::Request, .. })));
        c.check_room(&b, None, caps).unwrap();
        open("b2", &b, None).unwrap();
        open("d1", &d, None).unwrap();
        // 6 open: the key's total refuses an opener that is under its own cap.
        assert_eq!(full(open("d2", &d, None)), (PendingCap::Key, 6, 6));
        // An opener at its own cap hears about its own cap, not the key's.
        assert_eq!(full(open("a5", &a, None)).0, PendingCap::Opener);
        // Freed room is room again; a refused round 1 opened nothing.
        assert_eq!(c.pending_count(), 6);
        c.abort_as("a1", &a).unwrap();
        open("d2", &d, None).unwrap();
        let msg = CoreError::SessionsFull { cap_kind: PendingCap::Opener, open: 3, cap: 3 }.to_string();
        assert!(msg.contains("from this opener"), "{msg}");
    }
}

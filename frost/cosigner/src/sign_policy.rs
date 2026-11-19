// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The signing policy one node applies to every signature it takes part in (audit C2), wherever
//! the request came from — the driver through this node as leader, or another cosigner's leader
//! over the mesh:
//!
//! * **round 1** ([`SignGuard::authorize_round1`]), before any nonce exists: a signing intent is
//!   verified in full ([`crate::intent::IntentVerifier::verify`]) and the session is bound to it
//!   (its digest and its message); the split ceremony's sign test is accepted only for this node's
//!   own test digest of the key; a round without either is refused when `require_intent` is on,
//!   else accepted and counted;
//! * **round 2** ([`SignGuard::check_round2`]), before the core binding checks: the leader presents
//!   the same intent digest, the message is the intent's, the intent is still valid;
//! * **release** ([`SignGuard::journal_release`]), from inside
//!   [`rutli_frost_core::session::Cosigner::round2_guarded`] after every binding check and before
//!   the nonce marker burns: the per-key rate limit is charged (once per intent request id) and the
//!   share is journaled durably. Nothing is released that is not journaled.
//!
//! And to every DKG/refresh it takes part in ([`SignGuard::authorize_ceremony`], at the fence and
//! at part 1, before the ceremony guard or any session exists): the client's ceremony intent is
//! verified in full ([`crate::intent::IntentVerifier::verify_ceremony`]), including that the
//! ceremony id is the one it names; a ceremony without one is refused when
//! `require_ceremony_intent` is on, else accepted and counted.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::intent::{refused, refused_ceremony, IntentVerifier, VerifiedCeremony, VerifiedIntent};
use crate::node::CeremonyKind;
use crate::pb;
use crate::journal::{JournalEntry, Limits, SignJournal};
use crate::node::Round1Ctx;
use crate::{DaemonError, Result};

/// Whether `now_ms` falls in another wall-clock minute than the last call that returned true for
/// `last` (which holds that minute): a warning logged only then is logged at most once a minute.
fn first_in_minute(last: &AtomicU64, now_ms: u64) -> bool {
    let minute = now_ms / 60_000;
    last.swap(minute, Ordering::Relaxed) != minute
}

/// What authorized one signing session on this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionAuth {
    /// A client's verified intent.
    Intent(VerifiedIntent),
    /// The split ceremony's sign test, over this node's own test digest.
    SignTest,
    /// No intent (an older driver or leader), accepted while `require_intent` is off.
    NoIntent,
}

/// One node's signing policy and sign journal.
pub struct SignGuard {
    verifier: Arc<IntentVerifier>,
    journal: SignJournal,
    require_intent: bool,
    require_ceremony_intent: bool,
    /// The sign test at this node, as a peer: the operator role must not loop it on any node.
    sign_test_limiter: crate::ratelimit::DecryptRateLimiter,
    /// (key id, session id) -> what authorized it. Keyed by both: a session id is the leader's
    /// choice, so the same id opened for another key must never stand in for this one.
    sessions: Mutex<HashMap<(String, String), (Instant, SessionAuth)>>,
    last_absent_warning: AtomicU64,
    last_ceremony_absent_warning: AtomicU64,
}

impl SignGuard {
    pub fn new(
        verifier: Arc<IntentVerifier>,
        journal: SignJournal,
        sign_test_per_min: u32,
    ) -> Self {
        let require_intent = verifier.policy().require_intent;
        // Unset = on, the default of a node that verifies intents; the daemon settles it for a
        // plaintext node ([`crate::config::SigningPolicyConfig::ceremony_intent_required`]).
        let require_ceremony_intent = verifier.policy().require_ceremony_intent.unwrap_or(true);
        Self {
            verifier,
            journal,
            require_intent,
            require_ceremony_intent,
            sign_test_limiter: crate::service::ceremony_sign_test_limiter(sign_test_per_min),
            sessions: Mutex::new(HashMap::new()),
            last_absent_warning: AtomicU64::new(0),
            last_ceremony_absent_warning: AtomicU64::new(0),
        }
    }

    pub fn verifier(&self) -> &Arc<IntentVerifier> {
        &self.verifier
    }

    pub fn journal(&self) -> &SignJournal {
        &self.journal
    }

    pub fn require_intent(&self) -> bool {
        self.require_intent
    }

    pub fn require_ceremony_intent(&self) -> bool {
        self.require_ceremony_intent
    }

    /// A DKG/refresh fence or part 1 for `ceremony_id` of `key_id`: the client's ceremony intent,
    /// verified ([`IntentVerifier::verify_ceremony`]); `None` = none was carried and this node
    /// accepts that (`require_ceremony_intent` off; counted and logged at most once a minute).
    pub fn authorize_ceremony(
        &self,
        kind: CeremonyKind,
        key_id: &str,
        ceremony_id: &str,
        intent: Option<&pb::SignedIntent>,
    ) -> Result<Option<VerifiedCeremony>> {
        if let Some(signed) = intent {
            return self
                .verifier
                .verify_ceremony(signed, kind, key_id, ceremony_id, crate::intent::now_ms())
                .map(Some);
        }
        if self.require_ceremony_intent {
            return Err(refused_ceremony(
                "missing",
                format!(
                    "{} {ceremony_id} of {key_id} carries no ceremony intent and this node requires one \
                     (signing_policy.require_ceremony_intent) — the client or the leading cosigner predates \
                     ceremony intents, or no client asked for this ceremony",
                    kind.as_str()
                ),
            ));
        }
        metrics::counter!(crate::metrics::CEREMONY_INTENT_ABSENT).increment(1);
        if first_in_minute(&self.last_ceremony_absent_warning, crate::intent::now_ms()) {
            tracing::warn!(
                key_id,
                ceremony_id,
                "{} without a ceremony intent accepted (signing_policy.require_ceremony_intent is off) — \
                 expected only until the driver and the refresh job run a release that signs them; then \
                 turn require_ceremony_intent on",
                kind.as_str()
            );
        }
        Ok(None)
    }

    /// Round 1 for `key_id`: what authorizes this session, or a refusal. `own_test_message` is this
    /// node's split-ceremony test digest of the key (only asked for a sign-test round).
    pub fn authorize_round1(
        &self,
        key_id: &str,
        ctx: &Round1Ctx,
        own_test_message: impl FnOnce() -> Result<[u8; 34]>,
    ) -> Result<SessionAuth> {
        if let Some(signed) = &ctx.intent {
            let v = self.verifier.verify(signed, key_id, crate::intent::now_ms())?;
            if ctx.message.as_ref().is_some_and(|m| m != &v.message) {
                return Err(refused(
                    "key",
                    "the leader declares another message than the intent authorizes".into(),
                ));
            }
            return Ok(SessionAuth::Intent(v));
        }
        if ctx.sign_test {
            let mine = own_test_message()?;
            if ctx.message.as_deref() != Some(mine.as_slice()) {
                return Err(refused(
                    "sign-test",
                    format!("a sign-test round for {key_id} must sign this node's own test digest of the key"),
                ));
            }
            self.sign_test_limiter.check(key_id).map_err(|limited| {
                metrics::counter!(crate::metrics::CEREMONY_SIGN_TEST_RATE_LIMITED).increment(1);
                DaemonError::RateLimited(limited.to_string())
            })?;
            return Ok(SessionAuth::SignTest);
        }
        if self.require_intent {
            return Err(refused(
                "missing",
                format!(
                    "sign round 1 for {key_id} carries no signing intent and this node requires one \
                     (signing_policy.require_intent) — the driver or the leading cosigner predates intents"
                ),
            ));
        }
        metrics::counter!(crate::metrics::SIGN_INTENT_ABSENT).increment(1);
        // At most once a minute: a protocol key signs at transaction rate.
        if first_in_minute(&self.last_absent_warning, crate::intent::now_ms()) {
            tracing::warn!(
                key_id,
                "sign round without a signing intent accepted (signing_policy.require_intent is off) — \
                 expected only until the driver runs a release with intents; then turn require_intent on"
            );
        }
        Ok(SessionAuth::NoIntent)
    }

    /// Remember what authorized `session_id` of `key_id` (after its round 1 succeeded).
    pub fn remember(&self, key_id: &str, session_id: &str, auth: SessionAuth) {
        let mut s = self.sessions();
        s.retain(|_, (started, _)| started.elapsed() < rutli_frost_core::session::PENDING_TTL);
        s.insert((key_id.to_string(), session_id.to_string()), (Instant::now(), auth));
    }

    /// What authorized `session_id` of `key_id`, removed (round 2 runs once).
    pub fn take(&self, key_id: &str, session_id: &str) -> Option<SessionAuth> {
        self.sessions().remove(&(key_id.to_string(), session_id.to_string())).map(|(_, a)| a)
    }

    pub fn forget(&self, key_id: &str, session_id: &str) {
        self.sessions().remove(&(key_id.to_string(), session_id.to_string()));
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), (Instant, SessionAuth)>> {
        // A panicking holder leaves at worst a stale entry; dropping them all fails closed (those
        // sessions are refused at round 2 when an intent is required, else signed without one).
        self.sessions.lock().unwrap_or_else(|p| {
            let mut m = p.into_inner();
            m.clear();
            self.sessions.clear_poison();
            m
        })
    }

    /// Round 2's policy checks, before the core binding checks.
    pub fn check_round2(&self, auth: &SessionAuth, message: &[u8], intent_digest: Option<&[u8; 32]>) -> Result<()> {
        match auth {
            SessionAuth::Intent(v) => {
                if intent_digest != Some(&v.digest) {
                    return Err(refused(
                        "key",
                        "round 2 presents another signing intent than round 1 verified".into(),
                    ));
                }
                if message != v.message.as_slice() {
                    return Err(refused("key", "round 2 signs another message than the intent authorizes".into()));
                }
                self.verifier.check_live(v, crate::intent::now_ms())
            }
            SessionAuth::SignTest | SessionAuth::NoIntent => {
                if intent_digest.is_some() {
                    return Err(refused("key", "round 2 presents an intent round 1 never verified".into()));
                }
                Ok(())
            }
        }
    }

    /// The release step: charge the rate limit and journal the share durably, or refuse.
    pub fn journal_release(&self, key_id: &str, session_id: &str, auth: &SessionAuth, message: &[u8]) -> Result<()> {
        let policy = self.verifier.policy();
        let (per_min, per_day) = policy.rate_limit_for(key_id);
        let limits = Limits { per_min, per_day, max_shares_per_charge: policy.max_shares_per_request };
        let mut entry = JournalEntry {
            key_id: key_id.to_string(),
            digest: hex::encode(message),
            session_id: session_id.to_string(),
            ..Default::default()
        };
        match auth {
            SessionAuth::Intent(v) => {
                entry.purpose = crate::journal::PURPOSE_SIGN.into();
                entry.request_id = hex::encode(v.request_id);
                entry.intent_sha256 = hex::encode(v.digest);
                entry.signer_cn = v.signer_cn.clone();
                entry.approvers = v.approvers.clone();
            }
            SessionAuth::SignTest => entry.purpose = crate::journal::PURPOSE_SIGN_TEST.into(),
            SessionAuth::NoIntent => entry.purpose = crate::journal::PURPOSE_NO_INTENT.into(),
        }
        match self.journal.append_charged(entry, limits, crate::intent::now_ms()) {
            Ok(_) => Ok(()),
            Err(e @ DaemonError::RateLimited(_)) => {
                metrics::counter!(crate::metrics::SIGN_RATE_LIMITED).increment(1);
                tracing::warn!(key_id, error = %e, "signature share refused by the sign rate limit");
                Err(e)
            }
            Err(e) => {
                metrics::counter!(crate::metrics::SIGN_JOURNAL_ERRORS).increment(1);
                tracing::error!(key_id, error = %e, "signature share refused: it could not be journaled");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningPolicyConfig;
    use crate::journal::{read_key_dir, Retention};

    const KEY: &str = "frost-k";

    /// A guard with no CA (the paths tested here never verify an intent) over a journal in `dir`.
    fn guard(dir: &std::path::Path, require_intent: bool) -> SignGuard {
        let policy = SigningPolicyConfig { require_intent, ..Default::default() };
        let verifier = IntentVerifier::new(Vec::new(), false, "c".into(), Vec::<String>::new(), &policy).unwrap();
        let journal = SignJournal::open(dir.join("journal"), 1, Retention { days: 90, max_bytes: 1 << 20 }).unwrap();
        SignGuard::new(Arc::new(verifier), journal, 10)
    }

    #[test]
    fn require_intent_follows_the_policy_and_refuses_a_round_without_one() {
        let tmp = tempfile::tempdir().unwrap();
        let strict = guard(tmp.path(), true);
        assert!(strict.require_intent());
        let err = strict.authorize_round1(KEY, &Round1Ctx::default(), || unreachable!()).unwrap_err();
        assert!(matches!(err, DaemonError::PolicyRefused(_)), "{err:?}");
        let lax = guard(&tmp.path().join("lax"), false);
        assert!(!lax.require_intent());
        assert_eq!(lax.authorize_round1(KEY, &Round1Ctx::default(), || unreachable!()).unwrap(), SessionAuth::NoIntent);
    }

    #[test]
    fn a_sign_test_round_signs_only_this_nodes_own_test_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let g = guard(tmp.path(), true);
        let mine = [7u8; 34];
        let ctx = |m: &[u8]| Round1Ctx { message: Some(m.to_vec()), sign_test: true, ..Default::default() };
        assert_eq!(g.authorize_round1(KEY, &ctx(&mine), || Ok(mine)).unwrap(), SessionAuth::SignTest);
        let err = g.authorize_round1(KEY, &ctx(&[8u8; 34]), || Ok(mine)).unwrap_err();
        assert!(matches!(err, DaemonError::PolicyRefused(_)), "{err:?}");
    }

    #[test]
    fn remembered_sessions_are_kept_per_key_until_taken_or_forgotten() {
        let tmp = tempfile::tempdir().unwrap();
        let g = guard(tmp.path(), false);
        g.remember(KEY, "s1", SessionAuth::NoIntent);
        g.remember(KEY, "s2", SessionAuth::SignTest);
        g.remember(KEY, "s3", SessionAuth::NoIntent);
        // A later `remember` sweeps only entries past the TTL, never live ones.
        assert_eq!(g.take(KEY, "s1"), Some(SessionAuth::NoIntent));
        assert_eq!(g.take(KEY, "s1"), None, "round 2 runs once");
        assert_eq!(g.take("frost-other", "s2"), None, "a session id never stands in for another key's");
        g.forget(KEY, "s2");
        assert_eq!(g.take(KEY, "s2"), None);
        assert_eq!(g.take(KEY, "s3"), Some(SessionAuth::NoIntent));
    }

    #[test]
    fn round2_without_a_verified_intent_refuses_one_presented() {
        let tmp = tempfile::tempdir().unwrap();
        let g = guard(tmp.path(), false);
        for auth in [SessionAuth::NoIntent, SessionAuth::SignTest] {
            g.check_round2(&auth, &[1; 34], None).unwrap();
            let err = g.check_round2(&auth, &[1; 34], Some(&[2; 32])).unwrap_err();
            assert!(matches!(err, DaemonError::PolicyRefused(_)), "{err:?}");
        }
    }

    #[test]
    fn a_released_share_is_journaled_with_its_message_session_and_purpose() {
        let tmp = tempfile::tempdir().unwrap();
        let g = guard(tmp.path(), false);
        g.journal_release(KEY, "sess-1", &SessionAuth::NoIntent, &[0xab; 34]).unwrap();
        g.journal_release(KEY, "sess-2", &SessionAuth::SignTest, &[0xcd; 34]).unwrap();
        let entries = read_key_dir(&tmp.path().join("journal").join(KEY)).unwrap().entries;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].digest, "ab".repeat(34));
        assert_eq!(entries[0].session_id, "sess-1");
        assert_eq!(entries[0].purpose, crate::journal::PURPOSE_NO_INTENT);
        assert_eq!(entries[1].digest, "cd".repeat(34));
        assert_eq!(entries[1].session_id, "sess-2");
        assert_eq!(entries[1].purpose, crate::journal::PURPOSE_SIGN_TEST);
        assert!(entries.iter().all(|e| e.key_id == KEY && e.node == 1));
    }

    #[test]
    fn an_absent_intent_warning_is_logged_once_a_minute() {
        let last = AtomicU64::new(0);
        let t = 1_700_000_000_000; // a minute boundary is somewhere after it
        let t = t - t % 60_000;
        assert!(first_in_minute(&last, t + 5_000));
        assert!(!first_in_minute(&last, t + 59_999));
        assert!(first_in_minute(&last, t + 60_000));
        assert!(!first_in_minute(&last, t + 60_001));
        assert!(first_in_minute(&last, t + 3 * 60_000));
    }
}

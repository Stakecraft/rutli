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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::intent::{refused, IntentVerifier, VerifiedIntent};
use crate::journal::{JournalEntry, Limits, SignJournal};
use crate::node::Round1Ctx;
use crate::{DaemonError, Result};

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
    /// The sign test at this node, as a peer: the operator role must not loop it on any node.
    sign_test_limiter: crate::ratelimit::DecryptRateLimiter,
    sessions: Mutex<HashMap<String, (Instant, SessionAuth)>>,
    last_absent_warning: AtomicU64,
}

impl SignGuard {
    pub fn new(
        verifier: Arc<IntentVerifier>,
        journal: SignJournal,
        sign_test_per_min: u32,
    ) -> Self {
        let require_intent = verifier.policy().require_intent;
        Self {
            verifier,
            journal,
            require_intent,
            sign_test_limiter: crate::service::ceremony_sign_test_limiter(sign_test_per_min),
            sessions: Mutex::new(HashMap::new()),
            last_absent_warning: AtomicU64::new(0),
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
        let now = crate::intent::now_ms() / 60_000;
        if self.last_absent_warning.swap(now, Ordering::Relaxed) != now {
            tracing::warn!(
                key_id,
                "sign round without a signing intent accepted (signing_policy.require_intent is off) — \
                 expected only until the driver runs a release with intents; then turn require_intent on"
            );
        }
        Ok(SessionAuth::NoIntent)
    }

    /// Remember what authorized `session_id` (after its round 1 succeeded).
    pub fn remember(&self, session_id: &str, auth: SessionAuth) {
        let mut s = self.sessions();
        s.retain(|_, (started, _)| started.elapsed() < rutli_frost_core::session::PENDING_TTL);
        s.insert(session_id.to_string(), (Instant::now(), auth));
    }

    /// What authorized `session_id`, removed (round 2 runs once).
    pub fn take(&self, session_id: &str) -> Option<SessionAuth> {
        self.sessions().remove(session_id).map(|(_, a)| a)
    }

    pub fn forget(&self, session_id: &str) {
        self.sessions().remove(session_id);
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Instant, SessionAuth)>> {
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

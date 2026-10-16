// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Per-key rate limiting for hosted-key decryption.
//!
//! This exists for one threat: a stolen driver certificate. That certificate authorizes `Decrypt`
//! on the Signer API, and because Canton's encryption keys protect per-view session keys, an
//! attacker holding it can read *retrospectively* — every recorded message ever encrypted to that
//! key. Without a ceiling here the only bound on that is how fast the cluster answers.
//!
//! The driver's signing journal cannot serve this purpose: it runs on the Canton host, so whoever
//! stole the certificate can simply not use the driver. A limit is only meaningful on the cosigner,
//! which is what this is.
//!
//! The buckets are **per node**: cosigners share no limiter state, so a certificate holder who
//! calls every node gets `n ×` the configured budget per key. That is documented rather than
//! engineered away — a distributed limiter would put a consensus round on Canton's decrypt hot
//! path, and dividing a cluster budget by `n` here would starve the driver, which sends all of a
//! key's traffic to one preferred leader. Operators size the per-node value accordingly
//! (`docs/hosted-keys.md` §2 and §5).
//!
//! It is deliberately **not** a load shaper. The default ceiling is far above what a Canton
//! participant does on one key, so in normal operation it never engages; its jobs are to cap an
//! attacker's throughput and — via [`crate::metrics::DECRYPT_RATE_LIMITED`] and the near-limit
//! warning — to make abnormal decryption *loud*.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A continuously-refilling token bucket per key id.
///
/// Capacity equals one minute's allowance, so a burst may spend a full minute's budget at once and
/// then refills smoothly. That suits the real shape of Canton traffic — bursty around topology
/// changes and transaction batches — while still bounding sustained throughput.
pub struct DecryptRateLimiter {
    per_minute: u32,
    labels: Labels,
    /// Cap on `buckets`; see [`MAX_TRACKED_KEYS`]. A field so the tests can use a small one.
    max_tracked: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
}

/// What a limiter guards, for its log and error messages. The same token bucket also caps the
/// split ceremony's `CeremonySignTest` (see [`DecryptRateLimiter::named`]).
#[derive(Debug, Clone, Copy)]
struct Labels {
    /// e.g. "hosted-key decryption".
    what: &'static str,
    /// The config setting that raises the limit.
    setting: &'static str,
    /// What sustained use near the ceiling may mean, appended to the warning.
    hint: &'static str,
}

struct Bucket {
    /// Fractional tokens remaining.
    tokens: f64,
    last_refill: Instant,
    /// When we last warned that this key is running near its ceiling, so the warning cannot itself
    /// become a log flood.
    last_warned: Option<Instant>,
}

/// How often, at most, to warn that a key is approaching its limit.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Fraction of the limit at which sustained use starts warning. Operators should learn they are
/// near the ceiling *before* decryption starts failing.
const WARN_THRESHOLD: f64 = 0.2; // warn once fewer than 20% of tokens remain

/// Most keys a limiter tracks at once. Buckets are keyed by the caller-supplied key id, which is
/// charged BEFORE the id is validated or looked up, so without a cap a certificate holder could
/// grow the map (and the memory behind it) without limit with made-up ids. Real deployments hold a
/// handful of hosted keys; this is orders of magnitude above that.
///
/// At the cap, buckets that have fully refilled are dropped first — that is lossless, since a
/// missing bucket starts full. If every bucket is still draining, a NEW key id is refused instead
/// of evicting a tracked one: evicting would hand an attacker a fresh budget on a real key by
/// flooding made-up ids, while refusing only ever costs a key that is not already being served.
pub const MAX_TRACKED_KEYS: usize = 4096;

impl DecryptRateLimiter {
    /// `per_minute` of 0 disables limiting entirely.
    pub fn new(per_minute: u32) -> Self {
        Self::named(
            per_minute,
            "hosted-key decryption",
            "hosted_keys.decrypt_rate_limit_per_min",
            "what a stolen driver certificate looks like",
        )
    }

    /// A limiter for another operation: `what` names it in messages, `setting` is the config key
    /// that raises it, `hint` is what sustained use near the ceiling may mean if it is not yours.
    pub fn named(per_minute: u32, what: &'static str, setting: &'static str, hint: &'static str) -> Self {
        Self { per_minute, labels: Labels { what, setting, hint }, max_tracked: MAX_TRACKED_KEYS, buckets: Mutex::new(HashMap::new()) }
    }

    pub fn is_enabled(&self) -> bool {
        self.per_minute > 0
    }

    /// Take one token for `key_id`. `Err` means the caller must refuse the operation.
    pub fn check(&self, key_id: &str) -> Result<(), RateLimited> {
        self.check_at(key_id, Instant::now())
    }

    /// [`check`] with an injected clock, so the tests can exercise refill without sleeping.
    pub fn check_at(&self, key_id: &str, now: Instant) -> Result<(), RateLimited> {
        if !self.is_enabled() {
            return Ok(());
        }
        let capacity = self.per_minute as f64;
        let per_sec = capacity / 60.0;

        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        if !buckets.contains_key(key_id) && buckets.len() >= self.max_tracked {
            // Idle buckets are equivalent to no bucket: drop them, then see if there is room.
            buckets.retain(|_, b| {
                let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
                b.tokens + elapsed * per_sec < capacity
            });
            if buckets.len() >= self.max_tracked {
                return Err(RateLimited {
                    key_id: key_id.to_string(),
                    per_minute: self.per_minute,
                    what: self.labels.what,
                    setting: self.labels.setting,
                });
            }
        }
        let bucket = buckets
            .entry(key_id.to_string())
            .or_insert_with(|| Bucket { tokens: capacity, last_refill: now, last_warned: None });

        // Refill for elapsed time, capped at capacity. `saturating_duration_since` keeps a
        // non-monotonic clock reading from producing a negative refill.
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_sec).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens < 1.0 {
            return Err(RateLimited {
                key_id: key_id.to_string(),
                per_minute: self.per_minute,
                what: self.labels.what,
                setting: self.labels.setting,
            });
        }
        bucket.tokens -= 1.0;

        // Near the ceiling: say so, at most once a minute per key. A node that trips this during
        // legitimate traffic needs its limit raised, and finding that out from a warning beats
        // finding it out from failed decryptions.
        if bucket.tokens < capacity * WARN_THRESHOLD {
            let due = bucket.last_warned.is_none_or(|w| now.saturating_duration_since(w) >= WARN_INTERVAL);
            if due {
                bucket.last_warned = Some(now);
                tracing::warn!(
                    key_id,
                    limit_per_min = self.per_minute,
                    remaining = bucket.tokens as u64,
                    "{} is approaching its rate limit — if this is legitimate traffic, raise {}; \
                     if it is not, this is {}",
                    self.labels.what,
                    self.labels.setting,
                    self.labels.hint
                );
            }
        }
        Ok(())
    }

    /// Number of keys currently tracked (for tests/observability).
    pub fn tracked_keys(&self) -> usize {
        self.buckets.lock().expect("rate limiter lock").len()
    }
}

/// The limit was hit for a key.
#[derive(Debug)]
pub struct RateLimited {
    pub key_id: String,
    pub per_minute: u32,
    pub what: &'static str,
    pub setting: &'static str,
}

impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} rate limit reached for {} ({}/min) — retry shortly, or raise {} if this is \
             legitimate load",
            self.what, self.key_id, self.per_minute, self.setting
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_limiter_never_refuses() {
        let rl = DecryptRateLimiter::new(0);
        assert!(!rl.is_enabled());
        for _ in 0..10_000 {
            rl.check("rutli-enc-1").unwrap();
        }
    }

    #[test]
    fn it_allows_a_full_minute_of_budget_then_refuses() {
        let rl = DecryptRateLimiter::new(60);
        let t0 = Instant::now();
        for i in 0..60 {
            rl.check_at("rutli-enc-1", t0).unwrap_or_else(|e| panic!("call {i} refused: {e}"));
        }
        // The 61st within the same instant has no tokens left.
        assert!(rl.check_at("rutli-enc-1", t0).is_err());
    }

    #[test]
    fn tokens_refill_over_time() {
        let rl = DecryptRateLimiter::new(60); // 1/sec
        let t0 = Instant::now();
        for _ in 0..60 {
            rl.check_at("rutli-enc-1", t0).unwrap();
        }
        assert!(rl.check_at("rutli-enc-1", t0).is_err());

        // One second later, one token is back — and only one.
        let t1 = t0 + Duration::from_secs(1);
        rl.check_at("rutli-enc-1", t1).unwrap();
        assert!(rl.check_at("rutli-enc-1", t1).is_err());

        // A long idle period refills to capacity but never beyond it.
        let t2 = t0 + Duration::from_secs(3600);
        for _ in 0..60 {
            rl.check_at("rutli-enc-1", t2).unwrap();
        }
        assert!(rl.check_at("rutli-enc-1", t2).is_err(), "refill must cap at capacity");
    }

    #[test]
    fn limits_are_per_key_not_global() {
        // One key being hammered must not deny service to another — otherwise an attacker with
        // access to one key could deny decryption of every other.
        let rl = DecryptRateLimiter::new(10);
        let t0 = Instant::now();
        for _ in 0..10 {
            rl.check_at("rutli-enc-busy", t0).unwrap();
        }
        assert!(rl.check_at("rutli-enc-busy", t0).is_err());
        rl.check_at("rutli-enc-quiet", t0).expect("a different key has its own budget");
        assert_eq!(rl.tracked_keys(), 2);
    }

    #[test]
    fn a_backwards_clock_does_not_grant_free_tokens() {
        // Instant is monotonic, but the arithmetic must be robust regardless: an earlier reading
        // must not produce a negative elapsed time and refund tokens.
        let rl = DecryptRateLimiter::new(10);
        let t0 = Instant::now() + Duration::from_secs(100);
        for _ in 0..10 {
            rl.check_at("rutli-enc-1", t0).unwrap();
        }
        let earlier = t0 - Duration::from_secs(50);
        assert!(rl.check_at("rutli-enc-1", earlier).is_err());
    }

    #[test]
    fn the_bucket_map_is_bounded_and_idle_buckets_are_evicted() {
        let mut rl = DecryptRateLimiter::new(60); // 1 token/sec
        rl.max_tracked = 4;
        let t0 = Instant::now();
        // Four distinct ids fill the map; each spent one token, so none is idle yet.
        for i in 0..4 {
            rl.check_at(&format!("junk-{i}"), t0).unwrap();
        }
        assert_eq!(rl.tracked_keys(), 4);
        // A fifth, new id is refused while every bucket is still draining ...
        assert!(rl.check_at("junk-4", t0).is_err());
        assert_eq!(rl.tracked_keys(), 4, "a refused id must not be tracked");
        // ... but a tracked key keeps its own budget.
        rl.check_at("junk-0", t0).unwrap();

        // Once the buckets have refilled they are dropped to make room, so the map never exceeds
        // the cap and a new id is served again.
        let t1 = t0 + Duration::from_secs(5);
        rl.check_at("rutli-enc-1", t1).unwrap();
        assert!(rl.tracked_keys() <= 4);
        for i in 0..100 {
            let _ = rl.check_at(&format!("flood-{i}"), t1 + Duration::from_secs(10 * i));
            assert!(rl.tracked_keys() <= 4);
        }
    }

    #[test]
    fn flooding_made_up_ids_cannot_reset_a_real_keys_budget() {
        let mut rl = DecryptRateLimiter::new(10);
        rl.max_tracked = 8;
        let t0 = Instant::now();
        for _ in 0..10 {
            rl.check_at("rutli-enc-1", t0).unwrap();
        }
        assert!(rl.check_at("rutli-enc-1", t0).is_err());
        for i in 0..1000 {
            let _ = rl.check_at(&format!("junk-{i}"), t0);
        }
        assert!(rl.check_at("rutli-enc-1", t0).is_err(), "the drained bucket must survive the flood");
    }

    #[test]
    fn the_default_ceiling_is_far_above_normal_canton_traffic() {
        // 6000/min is 100 decryptions per second sustained on a SINGLE key. The limiter must not
        // engage for anything a participant plausibly does; it exists to cap bulk exfiltration.
        let rl = DecryptRateLimiter::new(crate::config::DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN);
        let t0 = Instant::now();
        for _ in 0..1000 {
            rl.check_at("rutli-enc-1", t0).unwrap();
        }
    }
}

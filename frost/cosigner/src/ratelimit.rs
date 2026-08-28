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
    buckets: Mutex<HashMap<String, Bucket>>,
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

impl DecryptRateLimiter {
    /// `per_minute` of 0 disables limiting entirely.
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute, buckets: Mutex::new(HashMap::new()) }
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
        let bucket = buckets
            .entry(key_id.to_string())
            .or_insert_with(|| Bucket { tokens: capacity, last_refill: now, last_warned: None });

        // Refill for elapsed time, capped at capacity. `saturating_duration_since` keeps a
        // non-monotonic clock reading from producing a negative refill.
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_sec).min(capacity);
        bucket.last_refill = now;

        if bucket.tokens < 1.0 {
            return Err(RateLimited { key_id: key_id.to_string(), per_minute: self.per_minute });
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
                    "hosted-key decryption is approaching its rate limit — if this is legitimate \
                     traffic, raise hosted_keys.decrypt_rate_limit_per_min; if it is not, this is \
                     what a stolen driver certificate looks like"
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
}

impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "decryption rate limit reached for {} ({}/min) — retry shortly, or raise \
             hosted_keys.decrypt_rate_limit_per_min if this is legitimate load",
            self.key_id, self.per_minute
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

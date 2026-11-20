// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the signing policy (issue #121): the sign journal's rate limit and charge
//! window (with restarts), the per-prefix limit lookup, the epoch check's verdicts, and signing
//! intents (canonical bytes, validity window, ceremony ids).

#[path = "common/pki.rs"]
mod pki;

use std::collections::HashMap;

use prost::Message;
use proptest::prelude::*;

use rutli_cosigner::config::{RateLimitRule, SigningPolicyConfig};
use rutli_cosigner::epoch_check::{evaluate, Verdict};
use rutli_cosigner::intent::{self, IntentVerifier, VerifiedIntent};
use rutli_cosigner::journal::{read_key_dir, JournalEntry, Limits, Retention, SignJournal, PURPOSE_NO_INTENT, PURPOSE_SIGN};
use rutli_cosigner::node::CeremonyKind;
use rutli_cosigner::pb::{self, KeyEpochReply};
use rutli_cosigner::DaemonError;

/// `cases` per test, unless `PROPTEST_CASES` is set (a longer local run).
fn config(cases: u32) -> ProptestConfig {
    let mut c = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        c.cases = cases;
    }
    c.failure_persistence = None;
    c
}

const MINUTE: u64 = 60_000;
const DAY: u64 = 24 * 60 * MINUTE;
const T0: u64 = 1_800_000_000_000;
const KEEP: Retention = Retention { days: 90, max_bytes: 64 << 20 };

// ── sign journal: rate limit and charge window ────────────────────────────────────────────────────

/// One release attempt: which charge (an intent, or a sign without one), after how long.
#[derive(Clone, Debug)]
struct Attempt {
    /// Milliseconds since the previous attempt.
    gap_ms: u64,
    /// Index into the charge pool.
    charge: usize,
    /// Reopen the journal (a restart) before this attempt.
    restart: bool,
}

/// The charges: intents (request id + intent digest) and signs without an intent (a session).
fn entry(charge: usize) -> JournalEntry {
    let mut e = JournalEntry {
        key_id: "frost-k".into(),
        digest: "12".repeat(34),
        session_id: format!("sess-{charge}"),
        ..Default::default()
    };
    if charge % 3 == 2 {
        e.purpose = PURPOSE_NO_INTENT.into();
    } else {
        e.purpose = PURPOSE_SIGN.into();
        // Pairs of charges share a request id but not the intent: still two charges.
        e.request_id = format!("{:032x}", charge / 2);
        e.intent_sha256 = format!("{:064x}", charge);
        e.signer_cn = "driver".into();
    }
    e
}

const CHARGES: usize = 8;

fn attempts() -> impl Strategy<Value = Vec<Attempt>> {
    let gap = prop_oneof![
        4 => 0u64..2_000,
        3 => 0u64..(2 * MINUTE),
        1 => 0u64..(8 * 60 * MINUTE),
    ];
    prop::collection::vec(
        (gap, 0..CHARGES, prop::bool::weighted(0.1)).prop_map(|(gap_ms, charge, restart)| Attempt { gap_ms, charge, restart }),
        1..50,
    )
}

fn limits() -> impl Strategy<Value = Limits> {
    (0u32..5, 0u32..12, 1u32..4).prop_map(|(per_min, per_day, max_shares_per_charge)| Limits {
        per_min,
        per_day,
        max_shares_per_charge,
    })
}

/// Runs `attempts`, returning each one's verdict (`true` = released) and the journal's entries.
fn run(attempts: &[Attempt], limits: Limits, honour_restarts: bool) -> (Vec<bool>, Vec<JournalEntry>) {
    let tmp = tempfile::tempdir().unwrap();
    let mut journal = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
    let mut now = T0;
    let mut verdicts = Vec::new();
    // A charge's repeats stay within its intent's validity (minutes, never a day): only then must a
    // restart be invisible, because the ledger is rebuilt from the last 24 h of entries.
    let mut first_use: HashMap<usize, u64> = HashMap::new();
    for a in attempts {
        now += a.gap_ms;
        if honour_restarts && a.restart {
            journal = SignJournal::open(tmp.path(), 1, KEEP).unwrap();
        }
        let start = *first_use.entry(a.charge).or_insert(now);
        if now - start > 10 * MINUTE {
            verdicts.push(false);
            continue;
        }
        match journal.append_charged(entry(a.charge), limits, now) {
            Ok(_) => verdicts.push(true),
            Err(DaemonError::RateLimited(_)) => verdicts.push(false),
            Err(e) => panic!("unexpected journal error: {e}"),
        }
    }
    let entries = read_key_dir(&tmp.path().join("frost-k")).unwrap().entries;
    (verdicts, entries)
}

/// The documented rate limit, independently: a new charge needs room in the last minute and the
/// last 24 h; a known charge (within 24 h of its first release) is capped at
/// `max_shares_per_charge` releases. Returns each attempt's expected verdict.
fn model(attempts: &[Attempt], limits: Limits) -> Vec<bool> {
    let mut now = T0;
    let mut first_use: HashMap<usize, u64> = HashMap::new();
    // charge -> (time of its charge, releases)
    let mut open: HashMap<usize, (u64, u32)> = HashMap::new();
    let mut verdicts = Vec::new();
    for a in attempts {
        now += a.gap_ms;
        let start = *first_use.entry(a.charge).or_insert(now);
        if now - start > 10 * MINUTE {
            verdicts.push(false);
            continue;
        }
        open.retain(|_, (t, _)| *t + DAY > now);
        let ok = match open.get_mut(&a.charge) {
            Some((_, n)) if *n >= limits.max_shares_per_charge => false,
            Some((_, n)) => {
                *n += 1;
                true
            }
            None => {
                let in_minute = open.values().filter(|(t, _)| *t + MINUTE > now).count();
                let room_minute = limits.per_min == 0 || in_minute < limits.per_min as usize;
                let room_day = limits.per_day == 0 || open.len() < limits.per_day as usize;
                if room_minute && room_day {
                    open.insert(a.charge, (now, 1));
                }
                room_minute && room_day
            }
        };
        verdicts.push(ok);
    }
    verdicts
}

fn charge_id(e: &JournalEntry) -> String {
    if e.purpose == PURPOSE_SIGN {
        format!("r:{}:{}", e.request_id, e.intent_sha256)
    } else {
        format!("s:{}", e.session_id)
    }
}

proptest! {
    #![proptest_config(config(48))]

    /// What the journal released never exceeds the configured limits: at most `per_min` new
    /// charges in any minute, `per_day` in any 24 h, and `max_shares_per_charge` releases per
    /// charge within its window. Every release is journaled, in order, on one chain.
    #[test]
    fn releases_stay_within_the_rate_limits(attempts in attempts(), limits in limits()) {
        let (verdicts, entries) = run(&attempts, limits, true);
        prop_assert_eq!(entries.len(), verdicts.iter().filter(|&&v| v).count());
        for (i, e) in entries.iter().enumerate() {
            prop_assert_eq!(e.seq, i as u64 + 1);
            if i > 0 {
                prop_assert_eq!(&e.prev, &entries[i - 1].hash);
                prop_assert!(e.ts_ms >= entries[i - 1].ts_ms);
            }
        }
        // Recompute the charges from the journal itself.
        let mut charges: Vec<u64> = Vec::new();
        let mut open: HashMap<String, (u64, u32)> = HashMap::new();
        for e in &entries {
            let id = charge_id(e);
            match open.get_mut(&id) {
                Some((first, n)) if first.saturating_add(DAY) > e.ts_ms => *n += 1,
                _ => {
                    open.insert(id.clone(), (e.ts_ms, 1));
                    charges.push(e.ts_ms);
                }
            }
            prop_assert!(open[&id].1 <= limits.max_shares_per_charge, "charge {id} released {} shares", open[&id].1);
        }
        for (i, &t) in charges.iter().enumerate() {
            let in_minute = charges[..=i].iter().filter(|&&c| c + MINUTE > t).count();
            let in_day = charges[..=i].iter().filter(|&&c| c + DAY > t).count();
            if limits.per_min > 0 {
                prop_assert!(in_minute <= limits.per_min as usize, "{in_minute} charges in a minute at {t}");
            }
            if limits.per_day > 0 {
                prop_assert!(in_day <= limits.per_day as usize, "{in_day} charges in a day at {t}");
            }
        }
    }

    /// Every decision is the documented one: nothing over the limits is released, and nothing
    /// within them is refused.
    #[test]
    fn decisions_follow_the_documented_rate_limit(attempts in attempts(), limits in limits()) {
        let (verdicts, _) = run(&attempts, limits, true);
        prop_assert_eq!(verdicts, model(&attempts, limits));
    }

    /// A restart (the ledger rebuilt from the journal on disk) changes no decision.
    #[test]
    fn a_restart_does_not_change_any_decision(attempts in attempts(), limits in limits()) {
        let (with_restarts, _) = run(&attempts, limits, true);
        let (without, _) = run(&attempts, limits, false);
        prop_assert_eq!(with_restarts, without);
    }

    /// The limits of a key come from the first `rate_limits` rule whose prefix it has, else the
    /// defaults.
    #[test]
    fn the_first_matching_rate_limit_rule_wins(
        rules in prop::collection::vec(("[ab]{0,3}", 0u32..100, 0u32..100), 0..5),
        key in "[ab]{0,5}",
        default_min in 0u32..100,
        default_day in 0u32..100,
    ) {
        let policy = SigningPolicyConfig {
            sign_rate_limit_per_min: default_min,
            sign_rate_limit_per_day: default_day,
            rate_limits: rules
                .iter()
                .map(|(p, m, d)| RateLimitRule { key_id_prefix: p.clone(), per_min: *m, per_day: *d })
                .collect(),
            ..SigningPolicyConfig::default()
        };
        let expected = rules
            .iter()
            .find(|(p, _, _)| key.starts_with(p.as_str()))
            .map(|(_, m, d)| (*m, *d))
            .unwrap_or((default_min, default_day));
        prop_assert_eq!(policy.rate_limit_for(&key), expected);
    }
}

// ── epoch check ───────────────────────────────────────────────────────────────────────────────────

const GVK: [u8; 32] = [7; 32];

/// A sharing: (epoch, pkp digest). Digests are tied to the epoch except for a few "lying" ones.
fn sharing() -> impl Strategy<Value = (u64, Vec<u8>)> {
    (0u64..5, 0u8..3).prop_map(|(epoch, variant)| (epoch, vec![epoch as u8, variant]))
}

fn view((epoch, pkp_digest): (u64, Vec<u8>)) -> KeyEpochReply {
    KeyEpochReply {
        present: true,
        epoch,
        pkp_digest,
        group_verifying_key: GVK.to_vec(),
        origin: "dkg".into(),
        ..Default::default()
    }
}

/// A peer answer that is no evidence: no key, another group key, or a hosted key.
fn junk() -> impl Strategy<Value = KeyEpochReply> {
    (sharing(), 0u8..3).prop_map(|(s, how)| {
        let mut v = view(s);
        match how {
            0 => v.present = false,
            1 => v.group_verifying_key = vec![8; 32],
            _ => v.origin = "hosted".into(),
        }
        v
    })
}

/// A peer that reports itself stale, on peers' answers or by its own ceremony record. It is not
/// pure noise: it can vouch for the sharing it holds, and its newer claim is doubt.
fn stale_peer() -> impl Strategy<Value = KeyEpochReply> {
    (sharing(), any::<bool>()).prop_map(|(s, by_own_record)| {
        let mut v = view(s);
        v.stale = true;
        v.stale_by_own_record = by_own_record;
        v
    })
}

fn mine() -> impl Strategy<Value = KeyEpochReply> {
    (sharing(), prop::option::of(sharing())).prop_map(|(s, staged)| {
        let mut v = view(s);
        if let Some((e, d)) = staged {
            v.staged = true;
            v.staged_ceremony_id = "refresh-00".into();
            v.staged_new_epoch = e;
            v.staged_new_pkp_digest = d;
        }
        v
    })
}

fn answers() -> impl Strategy<Value = Vec<(u16, KeyEpochReply)>> {
    prop::collection::vec(sharing().prop_map(view), 0..4)
        .prop_map(|v| v.into_iter().enumerate().map(|(i, r)| (i as u16 + 2, r)).collect())
}

proptest! {
    #![proptest_config(config(256))]

    /// This node's own committed ceremony record naming a newer epoch than its share is proof the
    /// share was rolled back, whatever the peers say.
    #[test]
    fn an_own_newer_committed_record_is_always_stale(mine in mine(), ahead in 1u64..5, answers in answers()) {
        let committed = mine.epoch + ahead;
        prop_assert!(matches!(evaluate(&mine, Some(committed), &answers), Verdict::Stale(_)));
    }

    /// Answers that are no evidence (no key, another group key, a hosted key) never change the
    /// verdict, wherever they appear.
    #[test]
    fn answers_that_are_no_evidence_change_nothing(
        mine in mine(),
        committed in prop::option::of(0u64..5),
        answers in answers(),
        noise in prop::collection::vec(junk(), 1..3),
        at in any::<prop::sample::Index>(),
    ) {
        let base = evaluate(&mine, committed, &answers);
        let mut noisy = answers.clone();
        for (i, j) in noise.into_iter().enumerate() {
            let pos = at.index(noisy.len() + 1);
            noisy.insert(pos, (100 + i as u16, j));
        }
        prop_assert_eq!(evaluate(&mine, committed, &noisy), base);
    }

    /// Peers that report themselves stale never bench a node: added anywhere, they can keep or
    /// lift a verdict, or turn it into doubt, but never make it stale.
    #[test]
    fn a_stale_peer_never_makes_a_node_stale(
        mine in mine(),
        committed in prop::option::of(0u64..5),
        answers in answers(),
        stale in prop::collection::vec(stale_peer(), 1..3),
        at in any::<prop::sample::Index>(),
    ) {
        let base = evaluate(&mine, committed, &answers);
        let mut with_stale = answers.clone();
        for (i, j) in stale.into_iter().enumerate() {
            let pos = at.index(with_stale.len() + 1);
            with_stale.insert(pos, (100 + i as u16, j));
        }
        let verdict = evaluate(&mine, committed, &with_stale);
        if matches!(verdict, Verdict::Stale(_)) {
            prop_assert!(matches!(base, Verdict::Stale(_)), "{base:?} -> {verdict:?}");
        }
    }

    /// A node is never benched while a peer vouches for its exact sharing, nor while no peer
    /// reports a newer epoch (and its own records agree).
    #[test]
    fn a_node_is_not_stale_without_evidence(mine in mine(), committed in prop::option::of(0u64..5), answers in answers()) {
        prop_assume!(committed.is_none_or(|c| c <= mine.epoch));
        let vouched = answers.iter().any(|(_, v)| v.epoch == mine.epoch && v.pkp_digest == mine.pkp_digest);
        let newer = answers.iter().any(|(_, v)| v.epoch > mine.epoch);
        let verdict = evaluate(&mine, committed, &answers);
        if vouched || !newer {
            prop_assert!(!matches!(verdict, Verdict::Stale(_)), "{verdict:?}");
        }
        if answers.is_empty() {
            prop_assert_eq!(verdict, Verdict::Inconclusive);
        }
    }
}

// ── signing intents ───────────────────────────────────────────────────────────────────────────────

const CLUSTER: &str = "proptestcluster0";
const KEY: &str = "frost-participant1-namespace";

struct Fixture {
    verifier: IntentVerifier,
    driver: rutli_cosigner::request_auth::NodeSigner,
    skew_ms: u64,
    max_lifetime_ms: u64,
}

fn fixture() -> &'static Fixture {
    static F: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
    F.get_or_init(|| {
        let pki = pki::TestPki::new();
        let policy = SigningPolicyConfig::default();
        let verifier =
            IntentVerifier::new(pki.ca_pem.as_bytes().to_vec(), false, CLUSTER.into(), ["driver".to_string()], &policy).unwrap();
        Fixture {
            driver: pki.signer("driver"),
            skew_ms: policy.clock_skew_secs * 1000,
            max_lifetime_ms: policy.intent_max_lifetime_secs * 1000,
            verifier,
        }
    })
}

fn sign_intent(digest: &[u8], request_id: [u8; 16], issued: u64, not_after: u64) -> pb::SignedIntent {
    let intent = pb::SignIntent {
        version: intent::INTENT_VERSION,
        cluster_id: CLUSTER.into(),
        purpose: intent::PURPOSE_SIGN.into(),
        key_id: KEY.into(),
        digest: digest.to_vec(),
        request_id: request_id.to_vec(),
        issued_at_ms: issued,
        not_after_ms: not_after,
        approval_nonce: Vec::new(),
        approvals: Vec::new(),
        ..Default::default()
    };
    intent::sign_intent(&fixture().driver, &intent).unwrap()
}

fn verified(issued: u64, not_after: u64) -> VerifiedIntent {
    VerifiedIntent {
        digest: [0; 32],
        key_id: KEY.into(),
        message: vec![0; 34],
        request_id: [0; 16],
        signer_cn: "driver".into(),
        signer_spki_sha256: [0; 32],
        issued_at_ms: issued,
        not_after_ms: not_after,
        approvers: Vec::new(),
    }
}

/// Instants around the interesting edges of a validity window, including the ends of `u64`.
fn instant() -> impl Strategy<Value = u64> {
    prop_oneof![
        3 => (T0 - 2 * DAY)..(T0 + 2 * DAY),
        1 => Just(0u64),
        1 => (u64::MAX - 2 * DAY)..=u64::MAX,
    ]
}

proptest! {
    #![proptest_config(config(256))]

    /// An intent is live at `now` exactly when its lifetime is within the maximum and
    /// `issued - skew <= now <= not_after + skew` — computed without overflow at the ends of u64.
    #[test]
    fn the_validity_window_is_exactly_the_documented_one(
        issued in instant(),
        lifetime in prop_oneof![0u64..(10 * MINUTE), any::<u64>()],
        now_offset in -(20 * MINUTE as i64)..(20 * MINUTE as i64),
        absolute_now in prop::option::weighted(0.2, instant()),
    ) {
        let f = fixture();
        let not_after = issued.saturating_add(lifetime);
        let now = absolute_now.unwrap_or_else(|| issued.saturating_add_signed(now_offset));
        let (i, n, w, skew) = (issued as u128, not_after as u128, now as u128, f.skew_ms as u128);
        let expected = n >= i && n - i <= f.max_lifetime_ms as u128 && w + skew >= i && w <= n + skew;
        let got = f.verifier.check_live(&verified(issued, not_after), now);
        prop_assert_eq!(got.is_ok(), expected, "issued {} not_after {} now {}: {:?}", issued, not_after, now, got.err());
    }
}

proptest! {
    #![proptest_config(config(24))]

    /// A signed intent verifies, and binds the session to SHA-256 of exactly its bytes; changing
    /// any byte of the intent or its signature makes it fail verification.
    #[test]
    fn an_intent_verifies_only_unaltered(
        digest in prop::collection::vec(any::<u8>(), 34),
        request_id in any::<[u8; 16]>(),
        lifetime in 1u64..(5 * MINUTE),
        in_intent in any::<bool>(),
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let now = intent::now_ms();
        let signed = sign_intent(&digest, request_id, now, now + lifetime);
        let v = fixture().verifier.verify(&signed, KEY, now).unwrap();
        prop_assert_eq!(v.digest, intent::intent_digest(&signed));
        prop_assert_eq!(&v.message, &digest);
        prop_assert_eq!(v.request_id, request_id);
        prop_assert_eq!(v.signer_cn, "driver");
        // The intent bytes are what the client sent, not a re-encoding: re-encoding the decoded
        // message gives the same bytes (prost writes fields canonically).
        prop_assert_eq!(pb::SignIntent::decode(signed.intent.as_slice()).unwrap().encode_to_vec(), signed.intent.clone());

        let mut tampered = signed.clone();
        let bytes = if in_intent { &mut tampered.intent } else { &mut tampered.signature };
        let i = at.index(bytes.len());
        bytes[i] ^= xor;
        prop_assert!(fixture().verifier.verify(&tampered, KEY, now).is_err());
    }

    /// An intent for one key never verifies for another, and a ceremony id names the kind and the
    /// request id one-to-one.
    #[test]
    fn intents_bind_their_key_and_ceremony_ids_their_request(
        request_id in any::<[u8; 16]>(),
        other in any::<[u8; 16]>(),
        other_key in "frost-[a-z0-9]{1,12}",
    ) {
        let now = intent::now_ms();
        let signed = sign_intent(&[1; 34], request_id, now, now + MINUTE);
        prop_assume!(other_key != KEY);
        prop_assert!(fixture().verifier.verify(&signed, &other_key, now).is_err());

        for kind in [CeremonyKind::Dkg, CeremonyKind::Refresh] {
            let id = intent::ceremony_id_of(&signed, kind).unwrap();
            prop_assert_eq!(&id, &intent::ceremony_id_for(kind, &request_id));
            prop_assert_eq!(id, format!("{}-{}", intent::ceremony_purpose(kind), hex::encode(request_id)));
            prop_assert_eq!(
                intent::ceremony_id_for(kind, &request_id) == intent::ceremony_id_for(kind, &other),
                request_id == other
            );
        }
        prop_assert_ne!(
            intent::ceremony_id_for(CeremonyKind::Dkg, &request_id),
            intent::ceremony_id_for(CeremonyKind::Refresh, &request_id)
        );
    }
}

/// Approval request ids are exactly the driver's formula: hex(SHA-256(key ‖ SHA-256(digest) ‖
/// nonce)); a delete's names `delete:` and the key, so it never equals a sign's.
#[test]
fn approval_request_ids_follow_the_drivers_formula() {
    use sha2::{Digest, Sha256};
    proptest!(config(128), |(key in "[a-z0-9-]{1,20}", digest in prop::collection::vec(any::<u8>(), 0..40), nonce in prop::collection::vec(any::<u8>(), 0..20))| {
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        h.update(Sha256::digest(&digest));
        h.update(&nonce);
        prop_assert_eq!(intent::approval_request_id(&key, &digest, &nonce), hex::encode(h.finalize()));
        let delete = intent::delete_approval_request_id(&key, &digest, &nonce);
        prop_assert_eq!(&delete, &intent::approval_request_id(&format!("delete:{key}"), &digest, &nonce));
        prop_assert_ne!(delete, intent::approval_request_id(&key, &digest, &nonce));
    });
}

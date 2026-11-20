// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the single-use nonce guarantee (issue #121).
//!
//! [`NonceStore`] alone: a session id is consumed at most once, across any number of reopens of the
//! store, and only path-safe ids ever touch the directory.
//!
//! [`Cosigner`] on top of it: random interleavings of round 1, round 2 (matching or mismatched
//! message) and restarts (a new `Cosigner` over the same nonce directory, which loses the in-memory
//! nonces) never release two signature shares from the same nonces, never release two shares for
//! one session id, and agree step by step with a small model of the protocol.
//!
//! Case counts are kept low: every consume fsyncs a file and its directory.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use frost_ed25519 as frost;
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::Identifier;
use proptest::prelude::*;
use rand::rngs::OsRng;

use rutli_frost_core::nonce_store::NonceStore;
use rutli_frost_core::session::{Cosigner, SessionBinding};
use rutli_frost_core::CoreError;

const SESSIONS: &[&str] = &["s-0", "s-1", "s-2", "s-3"];

/// `cases` per test, unless `PROPTEST_CASES` is set (a longer local run).
fn config(cases: u32) -> ProptestConfig {
    let mut c = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        c.cases = cases;
    }
    c.failure_persistence = None;
    c
}

#[derive(Clone, Debug)]
enum StoreOp {
    Consume(usize),
    IsConsumed(usize),
    Reopen,
}

fn store_op() -> impl Strategy<Value = StoreOp> {
    prop_oneof![
        4 => (0..SESSIONS.len()).prop_map(StoreOp::Consume),
        2 => (0..SESSIONS.len()).prop_map(StoreOp::IsConsumed),
        1 => Just(StoreOp::Reopen),
    ]
}

proptest! {
    #![proptest_config(config(24))]

    /// `consume` succeeds exactly once per session id, whatever the order of calls and however
    /// often the store is reopened (a restart); `is_consumed` agrees with what was consumed.
    #[test]
    fn a_session_is_consumed_at_most_once_across_reopens(ops in prop::collection::vec(store_op(), 1..40)) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("k.nonces");
        let mut store = NonceStore::open(&dir).unwrap();
        let mut consumed = HashSet::new();
        for op in ops {
            match op {
                StoreOp::Consume(i) => {
                    let s = SESSIONS[i];
                    match store.consume(s) {
                        Ok(()) => prop_assert!(consumed.insert(s), "{s} consumed twice"),
                        Err(CoreError::NonceReuse(id)) => {
                            prop_assert_eq!(id, s);
                            prop_assert!(consumed.contains(s), "{} refused but never consumed", s);
                        }
                        Err(e) => prop_assert!(false, "unexpected error: {e}"),
                    }
                }
                StoreOp::IsConsumed(i) => {
                    let s = SESSIONS[i];
                    prop_assert_eq!(store.is_consumed(s).unwrap(), consumed.contains(s));
                }
                StoreOp::Reopen => store = NonceStore::open(&dir).unwrap(),
            }
        }
    }

    /// Any string is either refused as a session id (nothing written) or accepted as exactly one
    /// `<id>.used` file inside the store's own directory: an id can never name a path elsewhere.
    #[test]
    fn only_path_safe_session_ids_touch_the_store(id in prop_oneof![
        "[A-Za-z0-9_-]{1,40}",
        ".{0,40}",
        "[./\\\\A-Za-z0-9_-]{1,20}",
    ]) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("k.nonces");
        let store = NonceStore::open(&dir).unwrap();
        let safe = !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        let result = store.consume(&id);
        prop_assert_eq!(result.is_ok(), safe, "{:?}: {:?}", id, result.err());
        let mut inside: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        inside.sort();
        let expected = if safe { vec![format!("{id}.used")] } else { Vec::new() };
        prop_assert_eq!(inside, expected);
        // Nothing beside the store's directory.
        let outside: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        prop_assert_eq!(outside, vec![std::ffi::OsString::from("k.nonces")]);
    }
}

// ── Cosigner sessions ────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum SessionOp {
    Round1(usize),
    /// Round 2 for the session, as bound at round 1 or altered (a binding mismatch, which must drop
    /// the nonces without burning the session or releasing anything).
    Round2(usize, Tamper),
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tamper {
    None,
    Message,
    Key,
    /// An intent digest for a session opened without one.
    IntentDigest,
    /// This cosigner's own commitment left out (fewer signers than the threshold, too).
    DropOwnCommitment,
    /// A signer the round never declared.
    ExtraSigner,
}

fn tamper() -> impl Strategy<Value = Tamper> {
    prop_oneof![
        6 => Just(Tamper::None),
        1 => Just(Tamper::Message),
        1 => Just(Tamper::Key),
        1 => Just(Tamper::IntentDigest),
        1 => Just(Tamper::DropOwnCommitment),
        1 => Just(Tamper::ExtraSigner),
    ]
}

fn session_op() -> impl Strategy<Value = SessionOp> {
    prop_oneof![
        4 => (0..SESSIONS.len()).prop_map(SessionOp::Round1),
        4 => ((0..SESSIONS.len()), tamper()).prop_map(|(i, t)| SessionOp::Round2(i, t)),
        1 => Just(SessionOp::Restart),
    ]
}

struct Keys {
    mine: KeyPackage,
    other: KeyPackage,
    pkp: frost::keys::PublicKeyPackage,
}

fn keys() -> &'static Keys {
    static KEYS: std::sync::OnceLock<Keys> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let (shares, pkp) = frost::keys::generate_with_dealer(2, 2, IdentifierList::Default, OsRng).unwrap();
        let mut packages = shares.into_values().map(|s| KeyPackage::try_from(s).unwrap());
        Keys { mine: packages.next().unwrap(), other: packages.next().unwrap(), pkp }
    })
}

const KEY: &str = "frost-prop";
const MESSAGE: &[u8] = b"the message declared at round 1";
const OTHER_MESSAGE: &[u8] = b"something else";

proptest! {
    #![proptest_config(config(32))]

    /// The nonce single-use property end to end: no two released shares ever come from the same
    /// round-1 nonces, no session id releases two shares, and every call agrees with the model
    /// (round 1 refuses a burned or in-flight id; round 2 releases only for an in-flight id with a
    /// matching binding, and always drops the in-flight nonces).
    #[test]
    fn no_two_shares_from_one_nonce_across_restarts(ops in prop::collection::vec(session_op(), 1..30)) {
        let k = keys();
        let tmp = tempfile::tempdir().unwrap();
        let nonce_dir = tmp.path().join("nonces");
        let open = || Cosigner::new(k.mine.clone(), k.pkp.clone(), NonceStore::open(&nonce_dir).unwrap());
        let mut cosigner = open();
        let me: Identifier = *k.mine.identifier();
        let other: Identifier = *k.other.identifier();

        // Model.
        let mut burned: BTreeSet<&str> = BTreeSet::new();
        let mut in_flight: BTreeMap<&str, SigningCommitments> = BTreeMap::new();
        // Every commitment a released share was computed under (= its nonces).
        let mut released_under: HashSet<Vec<u8>> = HashSet::new();
        let mut releases_per_session: BTreeMap<&str, u32> = BTreeMap::new();

        for op in ops {
            match op {
                SessionOp::Round1(i) => {
                    let s = SESSIONS[i];
                    let binding = SessionBinding::new(KEY).with_message(MESSAGE).with_signers([me, other]);
                    let result = cosigner.round1(s, binding);
                    if burned.contains(s) {
                        prop_assert!(matches!(result, Err(CoreError::NonceReuse(_))), "{s}: {result:?}");
                    } else if in_flight.contains_key(s) {
                        prop_assert!(matches!(result, Err(CoreError::DuplicateSession(_))), "{s}: {result:?}");
                    } else {
                        in_flight.insert(s, result.unwrap());
                    }
                }
                SessionOp::Round2(i, tamper) => {
                    let s = SESSIONS[i];
                    // The other signer's fresh commitment for this attempt.
                    let (_, theirs) = frost::round1::commit(k.other.signing_share(), &mut OsRng);
                    let mut commitments = BTreeMap::from([(other, theirs)]);
                    if let Some(mine) = in_flight.get(s) {
                        commitments.insert(me, *mine);
                    } else {
                        // A leader inventing this cosigner's commitment.
                        let (_, invented) = frost::round1::commit(k.mine.signing_share(), &mut OsRng);
                        commitments.insert(me, invented);
                    }
                    match tamper {
                        Tamper::DropOwnCommitment => {
                            commitments.remove(&me);
                        }
                        Tamper::ExtraSigner => {
                            let third = Identifier::try_from(3u16).unwrap();
                            let (_, c) = frost::round1::commit(k.other.signing_share(), &mut OsRng);
                            commitments.insert(third, c);
                        }
                        _ => {}
                    }
                    let message = if tamper == Tamper::Message { OTHER_MESSAGE } else { MESSAGE };
                    let key = if tamper == Tamper::Key { "frost-another" } else { KEY };
                    let digest = [9u8; 32];
                    let intent = (tamper == Tamper::IntentDigest).then_some(&digest);
                    let result = cosigner.round2(s, key, message, &commitments, intent);
                    let was_in_flight = in_flight.remove(s);
                    match (&was_in_flight, tamper == Tamper::None) {
                        (Some(mine), true) => {
                            prop_assert!(result.is_ok(), "{s}: {result:?}");
                            prop_assert!(burned.insert(s));
                            prop_assert!(
                                released_under.insert(mine.serialize().unwrap()),
                                "two shares released from the same nonces"
                            );
                            *releases_per_session.entry(s).or_default() += 1;
                        }
                        (Some(_), false) => {
                            prop_assert!(matches!(result, Err(CoreError::BindingMismatch { .. })), "{s}: {result:?}");
                        }
                        (None, _) => {
                            prop_assert!(matches!(result, Err(CoreError::UnknownSession(_))), "{s}: {result:?}");
                        }
                    }
                }
                SessionOp::Restart => {
                    cosigner = open();
                    in_flight.clear();
                }
            }
            prop_assert!(releases_per_session.values().all(|&n| n == 1));
            for s in SESSIONS {
                prop_assert_eq!(cosigner.holds_session(s), in_flight.contains_key(s));
            }
        }
    }
}

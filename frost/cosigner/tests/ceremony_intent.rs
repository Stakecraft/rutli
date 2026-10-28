// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Ceremony intents (refresh-fence remediation, layer L2): a DKG or refresh happens only when an
//! authorized client signed for exactly that ceremony, and every node checks it itself.
//!
//! Identities as in the threat model: the driver (signer role), the refresher, the operator, a
//! cosigner (the compromised node), a second key certified under the driver's CN (pinned out), and
//! a "driver" from another CA.

#[path = "common/pki.rs"]
mod pki;

use std::collections::BTreeMap;

use rutli_cosigner::config::SigningPolicyConfig;
use rutli_cosigner::intent::{self, CeremonyRole, IntentVerifier};
use rutli_cosigner::node::CeremonyKind;
use rutli_cosigner::pb;
use rutli_cosigner::request_auth::NodeSigner;
use rutli_cosigner::DaemonError;

const KEY: &str = "frost-participant1-namespace";
const CLUSTER: &str = "c2testcluster000";

/// One certificate + key in PEM, signed by `pki`, with CN and SAN `cn`.
fn leaf(pki: &pki::TestPki, cn: &str) -> (String, String) {
    pki.leaf_custom(|p| {
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.subject_alt_names = vec![rcgen::SanType::DnsName(cn.try_into().unwrap())];
    })
}

struct Ids {
    pki: pki::TestPki,
    pems: BTreeMap<&'static str, (String, String)>,
}

impl Ids {
    fn new() -> Self {
        let pki = pki::TestPki::new();
        let rogue_ca = pki::TestPki::new();
        let mut pems = BTreeMap::new();
        for cn in ["cosigner1", "cosigner2", "cosigner3", "driver", "tenant", "operator", "refresher"] {
            pems.insert(cn, leaf(&pki, cn));
        }
        pems.insert("driver-2", leaf(&pki, "driver"));
        pems.insert("rogue", leaf(&rogue_ca, "driver"));
        Self { pki, pems }
    }

    fn signer(&self, who: &str) -> NodeSigner {
        let (c, k) = &self.pems[who];
        NodeSigner::from_pem(c.as_bytes(), k.as_bytes()).unwrap()
    }

    fn spki_sha256(&self, who: &str) -> String {
        let (c, _) = &self.pems[who];
        let der = rustls_pemfile::certs(&mut c.as_bytes()).next().unwrap().unwrap();
        hex::encode(intent::Caller::from_leaf_der(&der).unwrap().spki_sha256)
    }

    fn verifier(&self, policy: &SigningPolicyConfig) -> IntentVerifier {
        IntentVerifier::new(
            self.pki.ca_pem.as_bytes().to_vec(),
            false,
            CLUSTER.into(),
            ["driver".to_string(), "tenant".to_string()],
            policy,
        )
        .unwrap()
        .with_refreshers(["refresher".to_string()])
    }

    /// A ceremony intent for `kind` of `key`, signed by `who`, with request id 16×`rid`.
    fn ceremony(&self, who: &str, kind: CeremonyKind, key: &str, rid: u8) -> pb::SignedIntent {
        let i = intent::ceremony_intent(CLUSTER, kind, key, [rid; 16], intent::now_ms(), 120_000);
        intent::sign_intent(&self.signer(who), &i).unwrap()
    }

    fn sign_raw(&self, who: &str, i: &pb::SignIntent) -> pb::SignedIntent {
        intent::sign_intent(&self.signer(who), i).unwrap()
    }
}

fn id(kind: CeremonyKind, rid: u8) -> String {
    intent::ceremony_id_for(kind, &[rid; 16])
}

#[track_caller]
fn refused_with(r: rutli_cosigner::Result<impl std::fmt::Debug>, needle: &str) {
    match r {
        Err(DaemonError::PolicyRefused(m)) => assert!(m.contains(needle), "expected {needle:?} in {m:?}"),
        other => panic!("expected a ceremony-intent refusal containing {needle:?}, got {other:?}"),
    }
}

// ── the verifier ───────────────────────────────────────────────────────────────────────────────

/// Who may ask for which ceremony: DKG = the signer role; refresh = the refresher, or the signer
/// role only while `signer_may_refresh`. The operator and the cosigners never.
#[test]
fn ceremony_intents_are_accepted_only_from_the_role_the_kind_needs() {
    let ids = Ids::new();
    let lenient = ids.verifier(&SigningPolicyConfig::default());
    let strict = ids.verifier(&SigningPolicyConfig { signer_may_refresh: false, ..Default::default() });
    let now = intent::now_ms();
    use CeremonyKind::{Dkg, Refresh};

    let v = lenient.verify_ceremony(&ids.ceremony("driver", Dkg, KEY, 1), Dkg, KEY, &id(Dkg, 1), now).unwrap();
    assert_eq!((v.signer_cn.as_str(), v.role, v.ceremony_id.as_str()), ("driver", CeremonyRole::Signer, id(Dkg, 1).as_str()));
    let v = strict.verify_ceremony(&ids.ceremony("refresher", Refresh, KEY, 2), Refresh, KEY, &id(Refresh, 2), now).unwrap();
    assert_eq!(v.role, CeremonyRole::Refresher);
    // The driver refreshes only while signer_may_refresh.
    let by_driver = ids.ceremony("driver", Refresh, KEY, 3);
    assert_eq!(lenient.verify_ceremony(&by_driver, Refresh, KEY, &id(Refresh, 3), now).unwrap().role, CeremonyRole::Signer);
    refused_with(strict.verify_ceremony(&by_driver, Refresh, KEY, &id(Refresh, 3), now), "signer_may_refresh is off");
    // The refresher cannot run a DKG.
    refused_with(
        strict.verify_ceremony(&ids.ceremony("refresher", Dkg, KEY, 4), Dkg, KEY, &id(Dkg, 4), now),
        "not on this node's signer_allowlist",
    );
    // Operator and cosigner certificates: neither kind.
    for who in ["operator", "cosigner2"] {
        for kind in [Dkg, Refresh] {
            refused_with(
                lenient.verify_ceremony(&ids.ceremony(who, kind, KEY, 5), kind, KEY, &id(kind, 5), now),
                &format!("signed by {who:?}"),
            );
        }
    }
    // A "driver" certificate from another CA.
    refused_with(lenient.verify_ceremony(&ids.ceremony("rogue", Dkg, KEY, 6), Dkg, KEY, &id(Dkg, 6), now), "certificate");
}

/// What the intent binds: cluster, purpose == kind, key, ceremony id, validity, no digest, no
/// approvals; and the signature over exactly these bytes.
#[test]
fn a_ceremony_intent_binds_cluster_kind_key_id_and_time() {
    let ids = Ids::new();
    let v = ids.verifier(&SigningPolicyConfig::default());
    let now = intent::now_ms();
    use CeremonyKind::{Dkg, Refresh};
    let good = intent::ceremony_intent(CLUSTER, Refresh, KEY, [7; 16], now, 120_000);
    let rid7 = id(Refresh, 7);

    // Wrong kind: a refresh intent is not a DKG intent, and the id names the other kind anyway.
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &good), Dkg, KEY, &id(Dkg, 7), now), "purpose");
    // Wrong key.
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &good), Refresh, "other-key", &rid7, now), "intent is for key");
    // Wrong ceremony id (a leader running another ceremony under this intent).
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &good), Refresh, KEY, &id(Refresh, 8), now), "names ceremony");
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &good), Refresh, KEY, "refresh-made-up", now), "names ceremony");
    // Wrong cluster.
    let other = pb::SignIntent { cluster_id: "othercluster0000".into(), ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &other), Refresh, KEY, &rid7, now), "intent is for cluster");
    // Expired; issued in the future; a validity above the maximum.
    let expired = pb::SignIntent { issued_at_ms: now - 600_000, not_after_ms: now - 480_000, ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &expired), Refresh, KEY, &rid7, now), "expired");
    let future = pb::SignIntent { issued_at_ms: now + 600_000, not_after_ms: now + 660_000, ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &future), Refresh, KEY, &rid7, now), "future");
    let long = pb::SignIntent { not_after_ms: now + 3_600_000, ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &long), Refresh, KEY, &rid7, now), "exceeds");
    // A digest or approvals: not a ceremony intent.
    let digest = pb::SignIntent { digest: vec![1; 34], ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &digest), Refresh, KEY, &rid7, now), "no digest");
    let approved = pb::SignIntent { approval_nonce: vec![1; 16], ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &approved), Refresh, KEY, &rid7, now), "no digest");
    // A request id that is not 16 bytes.
    let short = pb::SignIntent { request_id: vec![7; 8], ..good.clone() };
    refused_with(v.verify_ceremony(&ids.sign_raw("driver", &short), Refresh, KEY, &rid7, now), "request id");
    // Forged: the bytes changed after signing (a leader rewriting the intent).
    let mut forged = ids.sign_raw("driver", &good);
    forged.intent = pb::SignIntent { key_id: "other-key".into(), ..good.clone() }.encode_to_vec();
    refused_with(v.verify_ceremony(&forged, Refresh, "other-key", &rid7, now), "signature");
    // Signed by one key, presenting another's chain.
    let mut swapped = ids.sign_raw("driver", &good);
    swapped.signer_chain = ids.sign_raw("tenant", &good).signer_chain;
    refused_with(v.verify_ceremony(&swapped, Refresh, KEY, &rid7, now), "signature");
    // The untouched intent passes.
    v.verify_ceremony(&ids.sign_raw("driver", &good), Refresh, KEY, &rid7, now).unwrap();
}

/// The key ACL applies to the signer role (DKG, driver refresh), not to the refresher (as on
/// Signer.Refresh); SPKI pins apply to every role.
#[test]
fn ceremony_intents_honour_the_key_acl_and_the_spki_pins() {
    let ids = Ids::new();
    let now = intent::now_ms();
    use CeremonyKind::{Dkg, Refresh};
    let mut policy = SigningPolicyConfig::default();
    policy.signer_acl.insert("driver".into(), vec!["frost-participant1-".into()]);
    let v = ids.verifier(&policy);
    v.verify_ceremony(&ids.ceremony("driver", Dkg, KEY, 1), Dkg, KEY, &id(Dkg, 1), now).unwrap();
    refused_with(
        v.verify_ceremony(&ids.ceremony("driver", Dkg, "frost-participant2-x", 2), Dkg, "frost-participant2-x", &id(Dkg, 2), now),
        "signer_acl",
    );
    refused_with(
        v.verify_ceremony(&ids.ceremony("driver", Refresh, "frost-participant2-x", 3), Refresh, "frost-participant2-x", &id(Refresh, 3), now),
        "signer_acl",
    );
    v.verify_ceremony(&ids.ceremony("refresher", Refresh, "frost-participant2-x", 4), Refresh, "frost-participant2-x", &id(Refresh, 4), now)
        .unwrap();

    // Pins: the driver's second key and a refresher key other than the pinned one are refused.
    let mut pinned = SigningPolicyConfig::default();
    pinned.signer_pins.insert("driver".into(), vec![ids.spki_sha256("driver")]);
    pinned.signer_pins.insert("refresher".into(), vec![ids.spki_sha256("driver")]); // not its key
    let v = ids.verifier(&pinned).with_delete_policy(intent::DeletePolicy {
        allowlist: ["driver".to_string()].into(),
        ..Default::default()
    });
    v.verify_ceremony(&ids.ceremony("driver", Dkg, KEY, 5), Dkg, KEY, &id(Dkg, 5), now).unwrap();
    // The same pin refuses a delete intent as a delete refusal (not a signing-policy one).
    let delete = pb::SignIntent {
        version: 1,
        cluster_id: CLUSTER.into(),
        purpose: "delete-key".into(),
        key_id: "rutli-enc-1".into(),
        digest: intent::delete_digest("rutli-enc-1").to_vec(),
        request_id: vec![1; 16],
        issued_at_ms: now,
        not_after_ms: now + 60_000,
        ..Default::default()
    };
    match v.verify_delete(&ids.sign_raw("driver-2", &delete), "rutli-enc-1", now, intent::Expiry::Enforce) {
        Err(DaemonError::PolicyRefused(m)) => assert!(m.starts_with("delete intent refused") && m.contains("not pinned"), "{m}"),
        other => panic!("{other:?}"),
    }
    refused_with(v.verify_ceremony(&ids.ceremony("driver-2", Dkg, KEY, 6), Dkg, KEY, &id(Dkg, 6), now), "not pinned");
    refused_with(
        v.verify_ceremony(&ids.ceremony("refresher", Refresh, KEY, 7), Refresh, KEY, &id(Refresh, 7), now),
        "not pinned",
    );
}

/// Domain separation by purpose, both ways: a ceremony intent is never a signing or a delete
/// intent, and a signing intent is never a ceremony intent.
#[test]
fn ceremony_and_signing_intents_cannot_stand_in_for_each_other() {
    let ids = Ids::new();
    let v = ids.verifier(&SigningPolicyConfig::default()).with_delete_policy(intent::DeletePolicy {
        allowlist: ["driver".to_string()].into(),
        ..Default::default()
    });
    let now = intent::now_ms();
    let dkg = ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1);
    refused_with(v.verify(&dkg, KEY, now), "purpose");
    refused_with(v.verify_delete(&dkg, KEY, now, intent::Expiry::Enforce), "purpose");
    let sign = ids.sign_raw(
        "driver",
        &pb::SignIntent {
            version: 1,
            cluster_id: CLUSTER.into(),
            purpose: "sign".into(),
            key_id: KEY.into(),
            digest: rutli_frost_core::dealer::canton_test_message(b"x").to_vec(),
            request_id: vec![1; 16],
            issued_at_ms: now,
            not_after_ms: now + 60_000,
            ..Default::default()
        },
    );
    for kind in [CeremonyKind::Dkg, CeremonyKind::Refresh] {
        refused_with(v.verify_ceremony(&sign, kind, KEY, &id(kind, 1), now), "purpose");
    }
}

use prost::Message as _;

// ── every node enforces it ─────────────────────────────────────────────────────────────────────

use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::journal::{Retention, SignJournal};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{run_dkg, run_dkg_with_intent, run_refresh, run_refresh_with_intent, Peers};
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::ceremony_record::{Phase, StatusInfo};
use rutli_cosigner::sign_policy::SignGuard;

struct Rig {
    ids: Ids,
    nodes: Vec<Arc<Node>>,
    peers: Peers,
    _tmp: tempfile::TempDir,
}

fn guard_for(ids: &Ids, root: &std::path::Path, i: u16, policy: &SigningPolicyConfig) -> Arc<SignGuard> {
    let journal =
        SignJournal::open(root.join(format!("journal-{i}")), i, Retention { days: 90, max_bytes: 64 << 20 }).unwrap();
    Arc::new(SignGuard::new(Arc::new(ids.verifier(policy)), journal, 10))
}

/// Three in-process nodes (2-of-3), node `i` on `policy(i)`, wired as a mesh.
fn rig(policy: impl Fn(u16) -> SigningPolicyConfig) -> Rig {
    rig_with_fence_timeout(policy, rutli_cosigner::node::CEREMONY_FENCE_TIMEOUT)
}

/// [`rig`] with a fence-only guard orphaned after `fence_timeout`.
fn rig_with_fence_timeout(policy: impl Fn(u16) -> SigningPolicyConfig, fence_timeout: std::time::Duration) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let ids = Ids::new();
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let ks = KeyStore::open(tmp.path().join(format!("n{i}"))).unwrap();
            Arc::new(
                Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks)
                    .with_sign_guard(guard_for(&ids, tmp.path(), i, &policy(i)))
                    .with_ceremony_fence_timeout(fence_timeout),
            )
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    Rig { ids, nodes, peers, _tmp: tmp }
}

fn enforcing() -> SigningPolicyConfig {
    SigningPolicyConfig { require_ceremony_intent: Some(true), signer_may_refresh: false, ..Default::default() }
}

impl Rig {
    /// The handles node `leader` (0-based) leads ceremonies through, as the daemon has them: itself
    /// in process, every other node as a mesh peer that sees it as `cosigner<leader+1>`.
    fn led_by(&self, leader: usize) -> Peers {
        self.nodes
            .iter()
            .enumerate()
            .map(|(j, n)| {
                let p = LocalPeer::new(n.clone());
                let p = if j == leader { p } else { p.on_behalf_of(self.nodes[leader].clone()) };
                Arc::new(p) as Arc<dyn PeerApi>
            })
            .collect()
    }

    /// The sharing every node holds of `key` (what a refresh fence expects).
    fn expect(&self, key: &str) -> Option<(u64, [u8; 32])> {
        let e = self.nodes[0].key_epoch(key).unwrap();
        e.present.then(|| (e.epoch, e.pkp_digest.as_slice().try_into().unwrap()))
    }

    /// Prove node `n` holds no guard for `key` (and so took none): a fresh, valid ceremony fences
    /// it at once — a fence-only guard of another ceremony would refuse it for a minute — and is
    /// released again.
    async fn assert_unguarded(&self, n: usize, kind: CeremonyKind, key: &str, rid: u8) {
        let who = if kind == CeremonyKind::Dkg { "driver" } else { "refresher" };
        let i = self.ids.ceremony(who, kind, key, rid);
        let cid = id(kind, rid);
        self.peers[n].ceremony_begin(&cid, key, kind, self.expect(key), Some(&i)).await.unwrap();
        self.peers[n].ceremony_release(&cid, key).await.unwrap();
    }
}

/// The end-to-end path: a DKG and a refresh run only with intents on enforcing nodes, each under
/// the id its intent names; the same refresh without one is refused by every node.
#[tokio::test]
async fn enforcing_nodes_run_a_dkg_and_a_refresh_only_with_a_client_intent() {
    let r = rig(|_| enforcing());
    assert!(matches!(run_dkg(&r.peers, KEY).await, Err(DaemonError::PolicyRefused(_))));
    let dkg = r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1);
    let group = run_dkg_with_intent(&r.peers, KEY, Some(dkg)).await.unwrap();
    for n in &r.nodes {
        assert!(n.ceremony_record(&id(CeremonyKind::Dkg, 1)).is_some(), "the DKG ran under its intent's id");
    }
    refused_with(run_refresh(&r.peers, KEY).await, "carries no ceremony intent");
    let refresh = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 2);
    assert_eq!(run_refresh_with_intent(&r.peers, KEY, Some(refresh.clone())).await.unwrap(), group);
    for n in &r.nodes {
        assert_eq!(n.committed_epoch(KEY), Some(2));
        assert!(n.ceremony_record(&id(CeremonyKind::Refresh, 2)).is_some());
    }
    // Replayed: the id it names is spent on every node — one intent, one ceremony.
    let err = run_refresh_with_intent(&r.peers, KEY, Some(refresh)).await.unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(ref m) if m.contains("already used")), "{err:?}");
    // A signed refresh intent cannot run a DKG, nor a DKG intent a refresh.
    let wrong = r.ids.ceremony("refresher", CeremonyKind::Dkg, KEY, 3);
    refused_with(run_refresh_with_intent(&r.peers, KEY, Some(wrong)).await, "purpose");
    assert_eq!(r.nodes[0].committed_epoch(KEY), Some(2));
}

/// A compromised cosigner (its share, its certificate, the Peer API of every honest node) calls
/// the fence and part 1 directly, for a refresh and for a DKG, with no intent, a forged one, one
/// signed by a key that may not ask (its own cosigner certificate, the operator), the wrong kind,
/// an expired one, another cluster's, and a valid one under another ceremony id. Every honest
/// node refuses each before it takes a guard or opens a session.
#[tokio::test]
async fn a_compromised_peer_gets_no_guard_and_no_session_without_a_valid_intent() {
    let r = rig(|_| enforcing());
    run_dkg_with_intent(&r.peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let now = intent::now_ms();
    for (kind, key) in [(CeremonyKind::Refresh, KEY), (CeremonyKind::Dkg, "frost-participant1-new")] {
        let who = if kind == CeremonyKind::Dkg { "driver" } else { "refresher" };
        let other = if kind == CeremonyKind::Dkg { CeremonyKind::Refresh } else { CeremonyKind::Dkg };
        let base = intent::ceremony_intent(CLUSTER, kind, key, [9; 16], now, 120_000);
        let mut forged = r.ids.sign_raw(who, &base);
        forged.intent = pb::SignIntent { request_id: vec![8; 16], ..base.clone() }.encode_to_vec();
        let attempts: Vec<(&str, String, Option<pb::SignedIntent>, &str)> = vec![
            ("none", format!("{}-attacker", kind.as_str()), None, "carries no ceremony intent"),
            ("forged", id(kind, 8), Some(forged), "signature"),
            ("cosigner cert", id(kind, 9), Some(r.ids.sign_raw("cosigner3", &base)), "signed by \"cosigner3\""),
            ("operator", id(kind, 9), Some(r.ids.sign_raw("operator", &base)), "signed by \"operator\""),
            (
                "wrong kind",
                id(kind, 9),
                Some(r.ids.sign_raw(who, &intent::ceremony_intent(CLUSTER, other, key, [9; 16], now, 120_000))),
                "purpose",
            ),
            (
                "expired",
                id(kind, 9),
                Some(r.ids.sign_raw(who, &pb::SignIntent { issued_at_ms: now - 900_000, not_after_ms: now - 780_000, ..base.clone() })),
                "expired",
            ),
            (
                "wrong cluster",
                id(kind, 9),
                Some(r.ids.sign_raw(who, &pb::SignIntent { cluster_id: "othercluster0000".into(), ..base.clone() })),
                "cluster",
            ),
            ("another id", id(kind, 10), Some(r.ids.sign_raw(who, &base)), "names ceremony"),
        ];
        for n in 0..3 {
            let records = r.nodes[n].all_records().len();
            for (what, cid, i, why) in &attempts {
                let fence = r.nodes[n].ceremony_begin(cid, key, kind, r.expect(key), i.as_ref());
                assert!(matches!(&fence, Err(DaemonError::PolicyRefused(m)) if m.contains(why)), "{what} fence on node {}: {fence:?}", n + 1);
                let part1 = r.nodes[n].ceremony_part1(cid, key, kind, &[1, 2, 3], i.as_ref());
                assert!(matches!(&part1, Err(DaemonError::PolicyRefused(m)) if m.contains(why)), "{what} part 1 on node {}: {part1:?}", n + 1);
                assert!(r.nodes[n].ceremony_record(cid).is_none(), "{what}: no vote, no record");
            }
            assert_eq!(r.nodes[n].all_records().len(), records);
            r.assert_unguarded(n, kind, key, 20 + n as u8).await;
        }
    }
    // Nothing changed: the key is on its DKG epoch everywhere.
    for n in &r.nodes {
        assert_eq!(n.committed_epoch(KEY), Some(1));
    }
}

/// Malformed or oversized ids from a peer are refused by pure checks before the intent is even
/// looked at, so they never reach a refusal message or a log line in full (no amplification, no
/// forged lines).
#[tokio::test]
async fn malformed_ids_are_refused_before_the_intent_check_and_never_echoed_in_full() {
    let r = rig(|_| enforcing());
    let huge = "a".repeat(100_000);
    let forged = "refresh-x\n2026-10-18T00:00:00Z INFO dkg fence: ceremony intent verified requested_by=driver";
    let cases: [(&str, &str); 4] = [(&huge, KEY), (forged, KEY), ("refresh-ok", &huge), ("refresh-ok", "key\nINFO forged")];
    for n in &r.nodes {
        for (cid, key) in cases {
            for result in [
                n.ceremony_begin(cid, key, CeremonyKind::Refresh, None, None).map(|_| ()),
                n.ceremony_part1(cid, key, CeremonyKind::Refresh, &[1, 2, 3], None).map(|_| ()),
            ] {
                match result {
                    Err(DaemonError::Config(m)) => {
                        assert!(m.len() < 300, "an oversized id is echoed: {} bytes", m.len());
                        assert!(!m.contains('\n'), "a raw newline is echoed: {m:?}");
                    }
                    other => panic!("expected a pure id refusal, got {other:?}"),
                }
            }
        }
    }
    let long_key = "k".repeat(rutli_cosigner::keystore::MAX_CEREMONY_KEY_ID_LEN + 1);
    assert!(rutli_cosigner::keystore::validate_key_id(&long_key).is_err());
    rutli_cosigner::keystore::validate_key_id(KEY).unwrap();
}

/// Replay at the Node level: the intent of a completed refresh cannot fence again (its id has a
/// record), and an intent for one key cannot fence another.
#[tokio::test]
async fn a_spent_or_misdirected_intent_cannot_fence_again() {
    let r = rig(|_| enforcing());
    run_dkg_with_intent(&r.peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let refresh = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 2);
    run_refresh_with_intent(&r.peers, KEY, Some(refresh.clone())).await.unwrap();
    for n in &r.nodes {
        let err = n.ceremony_begin(&id(CeremonyKind::Refresh, 2), KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&refresh)).unwrap_err();
        assert!(matches!(err, DaemonError::CeremonyRefused(ref m) if m.contains("already used")), "{err:?}");
        let err = n.ceremony_part1(&id(CeremonyKind::Refresh, 2), KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&refresh)).unwrap_err();
        assert!(matches!(err, DaemonError::CeremonyRefused(ref m) if m.contains("already used")), "{err:?}");
        refused_with(
            n.ceremony_begin(&id(CeremonyKind::Refresh, 2), "frost-participant1-other", CeremonyKind::Refresh, None, Some(&refresh)),
            "intent is for key",
        );
    }
}

/// A ceremony whose fence is refused somewhere leaves its intent spent: the leader's rollback
/// aborts the id on every node (a durable no-vote), so nobody — a compromised cosigner that refused
/// its own fence, say — can later lead the same ceremony with the still-valid intent.
#[tokio::test]
async fn a_refused_fence_spends_the_intent_on_every_node() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    // Node 3 is busy with another (valid) refresh's fence, so the leader's fence is refused there.
    let busy = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 2);
    r.peers[2].ceremony_begin(&id(CeremonyKind::Refresh, 2), KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&busy)).await.unwrap();
    let x = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 3);
    let err = run_refresh_with_intent(&r.peers, KEY, Some(x.clone())).await.unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyInProgress { .. }), "{err:?}");
    for n in &r.nodes {
        let rec = n.ceremony_record(&id(CeremonyKind::Refresh, 3)).expect("the refused ceremony's id is burned here");
        assert_eq!(StatusInfo::from_record(&rec).phase, Phase::Aborted);
    }
    r.peers[2].ceremony_release(&id(CeremonyKind::Refresh, 2), KEY).await.unwrap();
    // A second leader (here node 3, the one that refused) presenting the same intent gets nowhere.
    let second: Peers = vec![r.peers[2].clone(), r.peers[0].clone(), r.peers[1].clone()];
    let err = run_refresh_with_intent(&second, KEY, Some(x)).await.unwrap_err();
    assert!(matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("already used")), "{err:?}");
    // A fresh intent runs.
    let fresh = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 4);
    assert_eq!(run_refresh_with_intent(&r.peers, KEY, Some(fresh)).await.unwrap(), group);
}

/// Two leaders on one intent (one ceremony id): the second leader's fence is refused on a node the
/// first already fenced — never joined — so two leaders can never drive one ceremony id.
#[tokio::test]
async fn two_leaders_never_drive_one_intent() {
    let r = rig(|_| enforcing());
    run_dkg_with_intent(&r.peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let x = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 5);
    let xid = id(CeremonyKind::Refresh, 5);
    // Leader A has fenced every node for X.
    for p in &r.peers {
        p.ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).await.unwrap();
    }
    // Leader B, with the same intent, is refused at every node.
    for n in &r.nodes {
        let err = n.ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).unwrap_err();
        assert!(matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("second leader")), "{err:?}");
    }
    // Through the orchestrator, leader B's refused fence spends X on every node, which ends A's
    // run too: a peer can stop a requested ceremony (it can always veto by refusing), never take
    // it over.
    let err = run_refresh_with_intent(&r.peers, KEY, Some(x.clone())).await.unwrap_err();
    assert!(matches!(err, DaemonError::CeremonyRefused(_)), "{err:?}");
    for n in &r.nodes {
        assert!(n.ceremony_record(&xid).is_some());
        let err = n.ceremony_part1(&xid, KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&x)).unwrap_err();
        assert!(matches!(&err, DaemonError::CeremonyRefused(m) if m.contains("already used")), "{err:?}");
    }
}

/// Who may refresh, at every node: the refresher; the driver only while `signer_may_refresh`; the
/// operator never (unless it is on refresh_allowlist).
#[tokio::test]
async fn only_the_refresher_role_refreshes_unless_signer_may_refresh() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    refused_with(
        run_refresh_with_intent(&r.peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Refresh, KEY, 2))).await,
        "signer_may_refresh is off",
    );
    refused_with(
        run_refresh_with_intent(&r.peers, KEY, Some(r.ids.ceremony("operator", CeremonyKind::Refresh, KEY, 3))).await,
        "signed by \"operator\"",
    );
    assert_eq!(
        run_refresh_with_intent(&r.peers, KEY, Some(r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 4))).await.unwrap(),
        group
    );
    // With signer_may_refresh, the driver may.
    let lenient_role = rig(|_| SigningPolicyConfig { require_ceremony_intent: Some(true), ..Default::default() });
    let group = run_dkg_with_intent(&lenient_role.peers, KEY, Some(lenient_role.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1)))
        .await
        .unwrap();
    let by_driver = lenient_role.ids.ceremony("driver", CeremonyKind::Refresh, KEY, 2);
    assert_eq!(run_refresh_with_intent(&lenient_role.peers, KEY, Some(by_driver)).await.unwrap(), group);
}

/// SPKI pins are checked by every node on the intent's signer (before, only the called node checked
/// the caller's pin): a revoked driver key is refused by each node itself, and one node that pins it
/// out is enough to refuse the ceremony.
#[tokio::test]
async fn a_pinned_out_key_is_refused_at_every_node() {
    let r = rig(|_| enforcing());
    let pin = r.ids.spki_sha256("driver");
    let pinned = |pin: &str| {
        let mut p = enforcing();
        p.signer_pins.insert("driver".into(), vec![pin.to_string()]);
        p
    };
    // Re-open the nodes' guards with the pin: every node, then only node 3.
    for only_node3 in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let nodes: Vec<Arc<Node>> = (1..=3u16)
            .map(|i| {
                let ks = KeyStore::open(tmp.path().join(format!("n{i}"))).unwrap();
                let policy = if !only_node3 || i == 3 { pinned(&pin) } else { enforcing() };
                Arc::new(Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks).with_sign_guard(guard_for(&r.ids, tmp.path(), i, &policy)))
            })
            .collect();
        rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
        let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
        let stolen = r.ids.ceremony("driver-2", CeremonyKind::Dkg, KEY, 1);
        if only_node3 {
            refused_with(run_dkg_with_intent(&peers, KEY, Some(stolen)).await, "not pinned");
            // Nodes 1 and 2 were fenced first and released by the leader's rollback.
            for p in &peers[..2] {
                p.ceremony_begin(&id(CeremonyKind::Dkg, 2), KEY, CeremonyKind::Dkg, None, Some(&r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 2))).await.unwrap();
                p.ceremony_release(&id(CeremonyKind::Dkg, 2), KEY).await.unwrap();
            }
        } else {
            for n in &nodes {
                refused_with(n.ceremony_begin(&id(CeremonyKind::Dkg, 1), KEY, CeremonyKind::Dkg, None, Some(&stolen)), "not pinned");
                refused_with(n.ceremony_part1(&id(CeremonyKind::Dkg, 1), KEY, CeremonyKind::Dkg, &[1, 2, 3], Some(&stolen)), "not pinned");
            }
            // A pin refusal of a ceremony intent is a ceremony-intent refusal: its message (what the
            // peer handler matches to log the asking peer) and its counter (what
            // RutliCeremonyIntentRefused alerts on) — not the signing policy's.
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let g = nodes[0].sign_guard().unwrap().clone();
            let err = metrics::with_local_recorder(&recorder, || {
                g.authorize_ceremony(CeremonyKind::Dkg, KEY, &id(CeremonyKind::Dkg, 1), Some(&stolen)).unwrap_err()
            });
            assert!(matches!(&err, DaemonError::PolicyRefused(m) if m.starts_with("ceremony intent refused") && m.contains("not pinned")), "{err:?}");
            let out = handle.render();
            assert!(out.contains(r#"rutli_ceremony_intent_refusals_total{reason="pin"} 1"#), "{out}");
            assert!(!out.contains("rutli_sign_policy_refusals_total"), "{out}");
        }
        // The pinned key runs it.
        run_dkg_with_intent(&peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 3))).await.unwrap();
    }
}

/// Verify-if-present (`require_ceremony_intent: false`, the explicit opt-out; the default before
/// 0.4.0-rc.6): a ceremony without an intent is accepted and counted; a present one is verified in
/// full and refused if invalid.
#[tokio::test]
async fn without_enforcement_an_absent_intent_is_counted_and_a_present_one_verified() {
    let r = rig(|_| SigningPolicyConfig { require_ceremony_intent: Some(false), ..Default::default() });
    let group = run_dkg(&r.peers, KEY).await.unwrap();
    assert_eq!(run_refresh(&r.peers, KEY).await.unwrap(), group);
    // A present but invalid intent is refused by every node.
    refused_with(
        run_refresh_with_intent(&r.peers, KEY, Some(r.ids.ceremony("operator", CeremonyKind::Refresh, KEY, 1))).await,
        "signed by \"operator\"",
    );
    let mut forged = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 2);
    forged.signature[8] ^= 1;
    refused_with(run_refresh_with_intent(&r.peers, KEY, Some(forged)).await, "signature");
    assert_eq!(run_refresh_with_intent(&r.peers, KEY, Some(r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 3))).await.unwrap(), group);

    // The counters, on one node's guard.
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let g = r.nodes[0].sign_guard().unwrap().clone();
    metrics::with_local_recorder(&recorder, || {
        assert!(g.authorize_ceremony(CeremonyKind::Refresh, KEY, "refresh-legacy", None).unwrap().is_none());
        let bad = r.ids.ceremony("cosigner2", CeremonyKind::Refresh, KEY, 4);
        assert!(g.authorize_ceremony(CeremonyKind::Refresh, KEY, &id(CeremonyKind::Refresh, 4), Some(&bad)).is_err());
    });
    let out = handle.render();
    assert!(out.contains("rutli_ceremony_intent_absent_total 1"), "{out}");
    assert!(out.contains(r#"rutli_ceremony_intent_refusals_total{reason="signer"} 1"#), "{out}");
}

#[track_caller]
fn not_the_leader(r: rutli_cosigner::Result<impl std::fmt::Debug>) {
    match r {
        Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("only the leader that fenced"), "{m:?}"),
        other => panic!("expected a refusal of a caller that is not the ceremony's leader, got {other:?}"),
    }
}

/// A fenced peer sees the client's intent at its fence, and could present it to the other nodes.
/// Every node binds the ceremony to the leader whose fence took its guard, so parts 1–3 from any
/// other peer are refused — before they touch the session — and the leader's ceremony completes.
#[tokio::test]
async fn only_the_leader_that_fenced_a_ceremony_runs_it() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let (x, xid) = (r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 6), id(CeremonyKind::Refresh, 6));
    let (leader, node3) = (r.led_by(0), r.led_by(2));
    for p in &leader {
        p.ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).await.unwrap();
    }
    // Node 3 runs part 1 on node 1 (the leader itself) and node 2 with the intent it was shown.
    for p in &node3[..2] {
        not_the_leader(p.ceremony_part1(&xid, KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&x)).await);
    }
    let mut map = BTreeMap::new();
    for p in &leader {
        map.insert(p.identifier(), p.ceremony_part1(&xid, KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&x)).await.unwrap());
    }
    for p in &node3[..2] {
        not_the_leader(p.ceremony_part2(&xid, &map).await);
        // Nor can it abort the leader's live session there.
        not_the_leader(p.ceremony_abort(&xid).await);
    }
    // Node 3's release of the leader's fence is a no-op: the leader's part 2 still finds its guard.
    for p in &node3[..2] {
        p.ceremony_release(&xid, KEY).await.unwrap();
    }
    let mut digest = [0u8; 32];
    for p in &leader {
        digest = p.ceremony_part2(&xid, &map).await.unwrap().round1_digest;
    }
    for p in &node3[..2] {
        not_the_leader(p.ceremony_part3(&xid, &digest).await);
    }
    for p in &leader {
        p.ceremony_part3(&xid, &digest).await.unwrap();
    }
    for p in &leader {
        p.ceremony_commit(&xid).await.unwrap();
    }
    for n in &r.nodes {
        let rec = n.ceremony_record(&xid).unwrap();
        assert_eq!(StatusInfo::from_record(&rec).phase, Phase::Committed);
        assert_eq!(n.group_key(KEY).unwrap(), group);
    }
    // And the orchestrator's own run, led by node 2, as the daemon wires it.
    let y = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 7);
    assert_eq!(run_refresh_with_intent(&r.led_by(1), KEY, Some(y)).await.unwrap(), group);
}

/// Under ceremony intents part 1 never creates the guard: a ceremony starts with its leader's fence,
/// so a peer cannot skip the fence to bind a node to itself. Nothing is left behind by the refusal.
#[tokio::test]
async fn under_ceremony_intents_part1_needs_the_leaders_fence() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let (x, xid) = (r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 8), id(CeremonyKind::Refresh, 8));
    for p in &r.led_by(2) {
        match p.ceremony_part1(&xid, KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&x)).await {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("has no fence"), "{m:?}"),
            other => panic!("expected a refusal of an unfenced part 1, got {other:?}"),
        }
    }
    for n in 0..3 {
        r.assert_unguarded(n, CeremonyKind::Refresh, KEY, 9).await;
    }
    // The intent was not spent: its leader runs it.
    assert_eq!(run_refresh_with_intent(&r.led_by(0), KEY, Some(x)).await.unwrap(), group);
    // Without enforcement a part 1 may still open its own guard (bound to its caller), as before.
    let lenient = rig(|_| SigningPolicyConfig { require_ceremony_intent: Some(false), ..Default::default() });
    lenient.nodes[1].ceremony_part1("dkg-unfenced", KEY, CeremonyKind::Dkg, &[1, 2, 3], None).unwrap();
}

/// Failover: the driver's first leader fences and dies; the next leader, with a fresh intent, runs
/// the ceremony once the dead leader's fences time out — the binding is per ceremony id.
#[tokio::test]
async fn a_failover_leader_runs_the_ceremony_after_the_first_leader_died() {
    let fence_timeout = std::time::Duration::from_secs(2);
    let r = rig_with_fence_timeout(|_| enforcing(), fence_timeout);
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let (x, xid) = (r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 10), id(CeremonyKind::Refresh, 10));
    for p in &r.led_by(0) {
        p.ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).await.unwrap();
    }
    // Leader 1 is gone. Its fences hold the key until they time out...
    let y = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 11);
    assert!(run_refresh_with_intent(&r.led_by(1), KEY, Some(y)).await.is_err());
    tokio::time::sleep(fence_timeout + std::time::Duration::from_millis(250)).await;
    // ...then leader 2 runs a fresh ceremony to the end.
    let z = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 12);
    assert_eq!(run_refresh_with_intent(&r.led_by(1), KEY, Some(z)).await.unwrap(), group);
    for n in &r.nodes {
        assert_eq!(n.key_epoch(KEY).unwrap().epoch, 2);
    }
}

/// The leader's handle to a compromised node 1: when the leader's fence shows it the client's
/// intent, node 1 first races the leader with it — on the leader's own node and on node 2, as
/// `cosigner1` — and only then answers the fence. What each attempt returned is kept.
struct Racer {
    inner: Arc<dyn PeerApi>,
    /// Node 1's handles to every node (`cosigner1` to the others).
    attacker: Peers,
    log: std::sync::Mutex<Vec<(usize, &'static str, bool)>>,
}

#[async_trait::async_trait]
impl PeerApi for Racer {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(
        &self,
        k: &str,
        s: &str,
        ctx: &rutli_cosigner::node::Round1Ctx,
    ) -> rutli_cosigner::Result<frost_ed25519::round1::SigningCommitments> {
        self.inner.sign_round1(k, s, ctx).await
    }
    async fn sign_round2(
        &self,
        k: &str,
        s: &str,
        m: &[u8],
        c: &BTreeMap<Identifier, frost_ed25519::round1::SigningCommitments>,
        d: Option<&[u8; 32]>,
    ) -> rutli_cosigner::Result<frost_ed25519::round2::SignatureShare> {
        self.inner.sign_round2(k, s, m, c, d).await
    }
    async fn abort_sign(&self, k: &str, s: &str) -> rutli_cosigner::Result<()> {
        self.inner.abort_sign(k, s).await
    }
    async fn ceremony_fence(&self, c: &str, k: &str, kind: &'static str) -> rutli_cosigner::Result<()> {
        self.inner.ceremony_fence(c, k, kind).await
    }
    async fn ceremony_release(&self, c: &str, k: &str) -> rutli_cosigner::Result<()> {
        self.inner.ceremony_release(c, k).await
    }
    async fn node_info(&self) -> rutli_cosigner::Result<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(
        &self,
        a: &str,
        b: &str,
        s: &str,
        d: &[u8],
        w: &rutli_cosigner::wrap::Wrapped,
    ) -> rutli_cosigner::Result<Vec<u8>> {
        self.inner.replicate_key(a, b, s, d, w).await
    }
    async fn fetch_key(&self, k: &str) -> rutli_cosigner::Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(k).await
    }
    async fn list_keys(&self) -> rutli_cosigner::Result<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, c: &str, k: &str) -> rutli_cosigner::Result<bool> {
        self.inner.purge_key(c, k).await
    }
    async fn key_epoch(&self, k: &str) -> rutli_cosigner::Result<pb::KeyEpochReply> {
        self.inner.key_epoch(k).await
    }
    async fn ceremony_begin(
        &self,
        cid: &str,
        key: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
        intent: Option<&pb::SignedIntent>,
    ) -> rutli_cosigner::Result<()> {
        // Node 3 leads; node 1 now holds the intent and attacks nodes 3 and 2, in that order.
        for n in [2usize, 1] {
            let p = &self.attacker[n];
            p.ceremony_release(cid, key).await.unwrap(); // a no-op where another leader holds it
            let fenced = p.ceremony_begin(cid, key, kind, expect, intent).await.is_ok();
            let part1 = p.ceremony_part1(cid, key, kind, &[1, 2, 3], intent).await.is_ok();
            let mut log = self.log.lock().unwrap();
            log.push((n, "fence", fenced));
            log.push((n, "part1", part1));
        }
        self.inner.ceremony_begin(cid, key, kind, expect, intent).await
    }
    async fn ceremony_commit(&self, c: &str) -> rutli_cosigner::Result<StatusInfo> {
        self.inner.ceremony_commit(c).await
    }
    async fn ceremony_status(&self, c: &str) -> rutli_cosigner::Result<StatusInfo> {
        self.inner.ceremony_status(c).await
    }
    async fn ceremony_abort(&self, c: &str) -> rutli_cosigner::Result<StatusInfo> {
        self.inner.ceremony_abort(c).await
    }
    async fn ceremony_protocol(&self) -> rutli_cosigner::Result<u32> {
        self.inner.ceremony_protocol().await
    }
    async fn ceremony_part1(
        &self,
        c: &str,
        k: &str,
        kind: CeremonyKind,
        roster: &[u16],
        i: Option<&pb::SignedIntent>,
    ) -> rutli_cosigner::Result<frost_ed25519::keys::dkg::round1::Package> {
        self.inner.ceremony_part1(c, k, kind, roster, i).await
    }
    async fn ceremony_part2(
        &self,
        c: &str,
        m: &BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>,
    ) -> rutli_cosigner::Result<rutli_cosigner::ceremony::Part2Outcome> {
        self.inner.ceremony_part2(c, m).await
    }
    async fn ceremony_part3(&self, c: &str, d: &[u8; 32]) -> rutli_cosigner::Result<rutli_cosigner::node::StagedOutcome> {
        self.inner.ceremony_part3(c, d).await
    }
}

/// The race behind the leader binding: a fenced peer that answers its fence late and uses the
/// intent first. The leader fences its own node before any peer sees the intent, so the peer can
/// neither release, fence nor start that node; binding node 2 to itself only stops the ceremony.
/// Nothing is staged or committed under the attacker, and the next refresh runs.
#[tokio::test]
async fn a_peer_racing_the_leaders_fences_stops_the_ceremony_but_never_runs_it() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let before = r.expect(KEY);
    // Node 3 leads, through the daemon's handles; its handle to node 1 is the racer.
    let mut leader = r.led_by(2);
    let racer = Arc::new(Racer { inner: leader[0].clone(), attacker: r.led_by(0), log: Default::default() });
    leader[0] = racer.clone();
    let (x, xid) = (r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 13), id(CeremonyKind::Refresh, 13));
    assert!(run_refresh_with_intent(&leader, KEY, Some(x)).await.is_err());
    assert_eq!(
        *racer.log.lock().unwrap(),
        vec![(2, "fence", false), (2, "part1", false), (1, "fence", true), (1, "part1", true)],
        "the leader's own node refused everything; node 2 was bound to node 1"
    );
    for n in &r.nodes {
        if let Some(rec) = n.ceremony_record(&xid) {
            assert_eq!(StatusInfo::from_record(&rec).phase, Phase::Aborted);
        }
        assert_eq!(n.group_key(KEY).unwrap(), group);
    }
    assert_eq!(r.expect(KEY), before, "no node moved to a new sharing");
    // Node 1's session on node 2 is node 1's: the leader's abort cannot touch it (only node 1, or
    // the orphan timeout, ends it). Once node 1 gives it up, a fresh refresh runs.
    not_the_leader(r.led_by(2)[1].ceremony_abort(&xid).await);
    r.led_by(0)[1].ceremony_abort(&xid).await.unwrap();
    let y = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 14);
    assert_eq!(run_refresh_with_intent(&r.led_by(2), KEY, Some(y)).await.unwrap(), group);
}

/// Where a compromised node 1 makes the leader wait (for up to the peer RPC timeout) while it tries
/// to run the leader's ceremony itself, after the leader's fence on node 2 failed.
#[derive(Clone, Copy, PartialEq)]
enum Stall {
    /// In the leader's rollback release of node 1's fence (node 3's own fence is already gone).
    Release,
    /// In the leader's abort of the id on node 1 (node 1 asked before node 3, in roster order).
    Abort,
    /// Nowhere: the test body tries once the leader has given up.
    Never,
}

/// What the racer was shown at its fence: the ceremony id, the expected sharing, the intent.
type Seen = (String, Option<(u64, [u8; 32])>, pb::SignedIntent);

/// The leader's handle to a compromised node 1. Shown the client's intent at its fence, node 1
/// binds node 2 to itself first, so the leader's fence there fails and the leader rolls back; then,
/// at `stall`, it tries to fence node 3 (the leader's own) and itself with the intent and run the
/// ceremony as its leader.
struct RollbackRacer {
    inner: Arc<dyn PeerApi>,
    attacker: Peers,
    stall: Stall,
    seen: std::sync::Mutex<Option<Seen>>,
    /// (node, fence accepted) for each fence it tried, and whether it ran the ceremony.
    log: std::sync::Mutex<Vec<(usize, bool)>>,
    ran: std::sync::atomic::AtomicBool,
}

impl RollbackRacer {
    async fn take_over(&self) {
        let Some((cid, expect, intent)) = self.seen.lock().unwrap().clone() else { return };
        let (a, kind) = (&self.attacker, CeremonyKind::Refresh);
        for n in [2usize, 0] {
            let ok = a[n].ceremony_begin(&cid, KEY, kind, expect, Some(&intent)).await.is_ok();
            self.log.lock().unwrap().push((n, ok));
        }
        let mut map = BTreeMap::new();
        for p in a.iter() {
            match p.ceremony_part1(&cid, KEY, kind, &[1, 2, 3], Some(&intent)).await {
                Ok(pkg) => map.insert(p.identifier(), pkg),
                Err(_) => return,
            };
        }
        let mut digest = [0u8; 32];
        for p in a.iter() {
            match p.ceremony_part2(&cid, &map).await {
                Ok(out) => digest = out.round1_digest,
                Err(_) => return,
            }
        }
        for p in a.iter() {
            if p.ceremony_part3(&cid, &digest).await.is_err() {
                return;
            }
        }
        for p in a.iter() {
            let _ = p.ceremony_commit(&cid).await;
        }
        self.ran.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl PeerApi for RollbackRacer {
    fn identifier(&self) -> Identifier {
        self.inner.identifier()
    }
    async fn sign_round1(
        &self,
        k: &str,
        s: &str,
        ctx: &rutli_cosigner::node::Round1Ctx,
    ) -> rutli_cosigner::Result<frost_ed25519::round1::SigningCommitments> {
        self.inner.sign_round1(k, s, ctx).await
    }
    async fn sign_round2(
        &self,
        k: &str,
        s: &str,
        m: &[u8],
        c: &BTreeMap<Identifier, frost_ed25519::round1::SigningCommitments>,
        d: Option<&[u8; 32]>,
    ) -> rutli_cosigner::Result<frost_ed25519::round2::SignatureShare> {
        self.inner.sign_round2(k, s, m, c, d).await
    }
    async fn abort_sign(&self, k: &str, s: &str) -> rutli_cosigner::Result<()> {
        self.inner.abort_sign(k, s).await
    }
    async fn ceremony_fence(&self, c: &str, k: &str, kind: &'static str) -> rutli_cosigner::Result<()> {
        self.inner.ceremony_fence(c, k, kind).await
    }
    async fn ceremony_release(&self, c: &str, k: &str) -> rutli_cosigner::Result<()> {
        self.inner.ceremony_release(c, k).await?;
        if self.stall == Stall::Release {
            self.take_over().await;
        }
        Ok(())
    }
    async fn node_info(&self) -> rutli_cosigner::Result<(u16, [u8; 32])> {
        self.inner.node_info().await
    }
    async fn replicate_key(
        &self,
        a: &str,
        b: &str,
        s: &str,
        d: &[u8],
        w: &rutli_cosigner::wrap::Wrapped,
    ) -> rutli_cosigner::Result<Vec<u8>> {
        self.inner.replicate_key(a, b, s, d, w).await
    }
    async fn fetch_key(&self, k: &str) -> rutli_cosigner::Result<(String, Vec<u8>, rutli_cosigner::wrap::Wrapped)> {
        self.inner.fetch_key(k).await
    }
    async fn list_keys(&self) -> rutli_cosigner::Result<Vec<(String, String, Vec<u8>)>> {
        self.inner.list_keys().await
    }
    async fn purge_key(&self, c: &str, k: &str) -> rutli_cosigner::Result<bool> {
        self.inner.purge_key(c, k).await
    }
    async fn key_epoch(&self, k: &str) -> rutli_cosigner::Result<pb::KeyEpochReply> {
        self.inner.key_epoch(k).await
    }
    async fn ceremony_begin(
        &self,
        cid: &str,
        key: &str,
        kind: CeremonyKind,
        expect: Option<(u64, [u8; 32])>,
        intent: Option<&pb::SignedIntent>,
    ) -> rutli_cosigner::Result<()> {
        // Node 2 bound to node 1, so the leader's fence there fails and it rolls back.
        self.attacker[1].ceremony_begin(cid, key, kind, expect, intent).await.unwrap();
        *self.seen.lock().unwrap() = Some((cid.to_string(), expect, intent.cloned().unwrap()));
        self.inner.ceremony_begin(cid, key, kind, expect, intent).await
    }
    async fn ceremony_commit(&self, c: &str) -> rutli_cosigner::Result<StatusInfo> {
        self.inner.ceremony_commit(c).await
    }
    async fn ceremony_status(&self, c: &str) -> rutli_cosigner::Result<StatusInfo> {
        self.inner.ceremony_status(c).await
    }
    async fn ceremony_abort(&self, c: &str) -> rutli_cosigner::Result<StatusInfo> {
        if self.stall == Stall::Abort {
            self.take_over().await;
        }
        self.inner.ceremony_abort(c).await
    }
    async fn ceremony_protocol(&self) -> rutli_cosigner::Result<u32> {
        self.inner.ceremony_protocol().await
    }
    async fn ceremony_part1(
        &self,
        c: &str,
        k: &str,
        kind: CeremonyKind,
        roster: &[u16],
        i: Option<&pb::SignedIntent>,
    ) -> rutli_cosigner::Result<frost_ed25519::keys::dkg::round1::Package> {
        self.inner.ceremony_part1(c, k, kind, roster, i).await
    }
    async fn ceremony_part2(
        &self,
        c: &str,
        m: &BTreeMap<Identifier, frost_ed25519::keys::dkg::round1::Package>,
    ) -> rutli_cosigner::Result<rutli_cosigner::ceremony::Part2Outcome> {
        self.inner.ceremony_part2(c, m).await
    }
    async fn ceremony_part3(&self, c: &str, d: &[u8; 32]) -> rutli_cosigner::Result<rutli_cosigner::node::StagedOutcome> {
        self.inner.ceremony_part3(c, d).await
    }
}

/// Node 3 leads a refresh whose fence on node 2 fails because node 1 bound node 2 to itself, and
/// node 1 then tries to lead the very ceremony while the leader rolls back. Returns the racer.
async fn rollback_race(r: &Rig, stall: Stall, rid: u8) -> Arc<RollbackRacer> {
    let mut leader = r.led_by(2);
    let racer = Arc::new(RollbackRacer {
        inner: leader[0].clone(),
        attacker: r.led_by(0),
        stall,
        seen: Default::default(),
        log: Default::default(),
        ran: Default::default(),
    });
    leader[0] = racer.clone();
    let x = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, rid);
    assert!(run_refresh_with_intent(&leader, KEY, Some(x)).await.is_err());
    if stall == Stall::Never {
        racer.take_over().await;
    }
    racer
}

/// What none of the rollback races may achieve: the leader's own node (3) refuses node 1's fence
/// under the leader's ceremony id — its fence mark outlives the guard the rollback released — so
/// node 1 never runs the ceremony and no node moves to a new sharing.
fn assert_not_taken_over(r: &Rig, racer: &RollbackRacer, xid: &str, group: [u8; 32], before: Option<(u64, [u8; 32])>) {
    let log = racer.log.lock().unwrap().clone();
    assert_eq!(log.first(), Some(&(2, false)), "node 3 must refuse node 1's fence under the leader's id: {log:?}");
    assert!(!racer.ran.load(std::sync::atomic::Ordering::SeqCst), "node 1 ran the leader's ceremony");
    let _ = xid;
    for n in &r.nodes {
        assert_eq!(n.group_key(KEY).unwrap(), group);
    }
    assert_eq!(r.expect(KEY), before, "a node moved to a sharing led by node 1");
}

/// Review (rc.6): the leader's rollback released its own fence before the id was spent on its node,
/// and node 1 held the leader in its own release meanwhile — then fenced the leader's node under the
/// same id, bound it to itself and led the ceremony. Now an intent's fence is marked durably, and
/// the mark outlives the guard.
#[tokio::test]
async fn a_peer_cannot_take_over_during_the_leaders_fence_rollback() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let before = r.expect(KEY);
    let racer = rollback_race(&r, Stall::Release, 20).await;
    assert_not_taken_over(&r, &racer, &id(CeremonyKind::Refresh, 20), group, before);
}

/// The same race held in the leader's abort, which reaches node 1 before node 3 (roster order).
#[tokio::test]
async fn a_peer_cannot_take_over_while_holding_the_leaders_abort() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let before = r.expect(KEY);
    let racer = rollback_race(&r, Stall::Abort, 21).await;
    assert_not_taken_over(&r, &racer, &id(CeremonyKind::Refresh, 21), group, before);
}

/// No timing at all: the leader's abort on its own node is a capped no-vote for an id with no
/// session, and a peer can fill that cap. The fence mark does not depend on it, so even with the
/// cap full node 1 cannot fence the leader's node under the id once the leader gave up.
#[tokio::test]
async fn a_full_no_vote_cap_does_not_leave_the_leaders_id_unspent() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let before = r.expect(KEY);
    // Fill node 3's caps on no-votes for unknown ids asked in process (the bucket its own leader's
    // aborts use) and in total.
    for i in 0..rutli_cosigner::node::MAX_UNKNOWN_NO_VOTES_PER_ASKER {
        r.nodes[2].ceremony_abort(&format!("refresh-filler-{i}")).unwrap();
    }
    assert!(r.nodes[2].ceremony_abort("refresh-filler-x").is_err(), "the cap is full");
    let racer = rollback_race(&r, Stall::Never, 22).await;
    assert_not_taken_over(&r, &racer, &id(CeremonyKind::Refresh, 22), group, before);
}

/// A fence mark survives a restart (the guard does not): after node 2 restarts, nobody — another
/// cosigner, nor the leader that fenced it — can fence it or start part 1 under that intent's id
/// again. The leader cannot resume either: the restarted node lost the ceremony's state, so the
/// client retries with a fresh intent, which runs.
#[tokio::test]
async fn a_fence_mark_survives_a_restart() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let (x, xid) = (r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 30), id(CeremonyKind::Refresh, 30));
    r.led_by(0)[1].ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).await.unwrap();
    // Node 2 restarts: a new process over the same key store, no guards.
    let restarted = Arc::new(
        Node::new(Identifier::try_from(2u16).unwrap(), 3, 2, KeyStore::open(r._tmp.path().join("n2")).unwrap())
            .with_sign_guard(guard_for(&r.ids, r._tmp.path(), 2, &enforcing())),
    );
    for (who, as_who) in [("node 3", 2usize), ("the leader, node 1", 0)] {
        let p = LocalPeer::new(restarted.clone()).on_behalf_of(r.nodes[as_who].clone());
        match p.ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).await {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("already fenced"), "{who}: {m}"),
            other => panic!("{who}: a fence under a marked id must be refused, got {other:?}"),
        }
        assert!(p.ceremony_part1(&xid, KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&x)).await.is_err(), "{who}");
    }
    // The leader gives up (its rollback releases its fences); a fresh intent runs.
    r.led_by(0)[1].ceremony_release(&xid, KEY).await.unwrap();
    r.led_by(0)[0].ceremony_release(&xid, KEY).await.unwrap();
    let y = r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 31);
    assert_eq!(run_refresh_with_intent(&r.led_by(0), KEY, Some(y)).await.unwrap(), group);
}

/// Review (rc.6, round 3): a leader node that opted out of ceremony intents next to enforcing ones.
/// After the leader's rollback released its own guard, node 3 fenced the leader's node under the
/// client's ceremony id WITHOUT an intent (the fence mark was consulted only for intent-carrying
/// fences) and drove the client's DKG to commit as its leader. Now a marked id refuses every fence
/// and every guard-creating part 1, with or without an intent.
#[tokio::test]
async fn an_opted_out_leader_node_still_refuses_a_marked_id_without_an_intent() {
    let lenient = SigningPolicyConfig { require_ceremony_intent: Some(false), ..Default::default() };
    let r = rig(move |i| if i == 1 { lenient.clone() } else { enforcing() });
    let key = "frost-participant1-victim";
    let (x, xid) = (r.ids.ceremony("driver", CeremonyKind::Dkg, key, 41), id(CeremonyKind::Dkg, 41));
    let (leader, p3) = (r.led_by(0), r.led_by(2));
    leader[0].ceremony_begin(&xid, key, CeremonyKind::Dkg, None, Some(&x)).await.unwrap();
    // Node 3, shown the intent at its fence, races node 2 with it; the leader's fence there fails
    // and its rollback releases its own fence.
    p3[2].ceremony_begin(&xid, key, CeremonyKind::Dkg, None, Some(&x)).await.unwrap();
    p3[1].ceremony_begin(&xid, key, CeremonyKind::Dkg, None, Some(&x)).await.unwrap();
    assert!(leader[1].ceremony_begin(&xid, key, CeremonyKind::Dkg, None, Some(&x)).await.is_err());
    leader[0].ceremony_release(&xid, key).await.unwrap();
    // Node 3 tries the leader's (opted-out) node under the same id, without and with the intent.
    for intent in [None, Some(&x)] {
        match p3[0].ceremony_begin(&xid, key, CeremonyKind::Dkg, None, intent).await {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("already fenced"), "{m}"),
            other => panic!("a fence under a marked id must be refused, got {other:?}"),
        }
        match p3[0].ceremony_part1(&xid, key, CeremonyKind::Dkg, &[1, 2, 3], intent).await {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("already fenced"), "{m}"),
            other => panic!("a part 1 under a marked id must be refused, got {other:?}"),
        }
    }
    assert!(r.nodes.iter().all(|n| !n.has_key(key)), "no node holds a share of the client's key");
}

/// Review (rc.6, round 3): the leader-bound abort looked at whichever guard carried the ceremony id.
/// Node 3 planted hosted-key fences under the client's ceremony id on other keys, bound to itself,
/// and its abort then killed the leader's session. Now one ceremony id guards one key, and an abort
/// is refused while any live guard under the id is bound to another leader.
#[tokio::test]
async fn a_same_id_guard_on_another_key_cannot_stand_in_for_the_leaders() {
    let r = rig(|_| enforcing());
    let group =
        run_dkg_with_intent(&r.led_by(0), KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 1))).await.unwrap();
    let (x, xid) = (r.ids.ceremony("refresher", CeremonyKind::Refresh, KEY, 42), id(CeremonyKind::Refresh, 42));
    let (leader, p3) = (r.led_by(0), r.led_by(2));
    for p in &leader {
        p.ceremony_begin(&xid, KEY, CeremonyKind::Refresh, r.expect(KEY), Some(&x)).await.unwrap();
    }
    let mut map = BTreeMap::new();
    for p in &leader {
        map.insert(p.identifier(), p.ceremony_part1(&xid, KEY, CeremonyKind::Refresh, &[1, 2, 3], Some(&x)).await.unwrap());
    }
    for i in 0..8 {
        match p3[1].ceremony_fence(&xid, &format!("rutli-enc-planted-{i}"), "genkey").await {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("one ceremony id guards one key"), "{m}"),
            other => panic!("a second key under the ceremony id must be refused, got {other:?}"),
        }
    }
    not_the_leader(p3[1].ceremony_abort(&xid).await);
    let mut digest = [0u8; 32];
    for p in &leader {
        digest = p.ceremony_part2(&xid, &map).await.unwrap().round1_digest;
    }
    for p in &leader {
        p.ceremony_part3(&xid, &digest).await.unwrap();
    }
    for p in &leader {
        p.ceremony_commit(&xid).await.unwrap();
    }
    for n in &r.nodes {
        assert_eq!(StatusInfo::from_record(&n.ceremony_record(&xid).unwrap()).phase, Phase::Committed);
        assert_eq!(n.group_key(KEY).unwrap(), group);
    }
}

/// Where intents are not required, a part 1 with an intent may take the guard itself — and then
/// marks the id like a fence does: after the guard is gone (here: a restart), the same id is
/// refused at part 1 and at the fence, with or without the intent.
#[tokio::test]
async fn an_opted_out_part1_that_takes_the_guard_marks_the_id() {
    let lenient = || SigningPolicyConfig { require_ceremony_intent: Some(false), ..Default::default() };
    let r = rig(move |_| lenient());
    let key = "frost-participant1-lenient";
    let (x, xid) = (r.ids.ceremony("driver", CeremonyKind::Dkg, key, 43), id(CeremonyKind::Dkg, 43));
    r.nodes[1].ceremony_part1(&xid, key, CeremonyKind::Dkg, &[1, 2, 3], Some(&x)).unwrap();
    let restarted = Arc::new(
        Node::new(Identifier::try_from(2u16).unwrap(), 3, 2, KeyStore::open(r._tmp.path().join("n2")).unwrap())
            .with_sign_guard(guard_for(&r.ids, r._tmp.path(), 2, &lenient())),
    );
    for intent in [Some(&x), None] {
        match restarted.ceremony_part1(&xid, key, CeremonyKind::Dkg, &[1, 2, 3], intent) {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("already fenced"), "{m}"),
            other => panic!("part 1 under a marked id must be refused, got {other:?}"),
        }
        match restarted.ceremony_begin(&xid, key, CeremonyKind::Dkg, None, intent) {
            Err(DaemonError::CeremonyRefused(m)) => assert!(m.contains("already fenced"), "{m}"),
            other => panic!("a fence under a marked id must be refused, got {other:?}"),
        }
    }
}

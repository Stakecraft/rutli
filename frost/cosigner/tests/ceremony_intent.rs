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
    let v = ids.verifier(&pinned);
    v.verify_ceremony(&ids.ceremony("driver", Dkg, KEY, 5), Dkg, KEY, &id(Dkg, 5), now).unwrap();
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
    let tmp = tempfile::tempdir().unwrap();
    let ids = Ids::new();
    let nodes: Vec<Arc<Node>> = (1..=3u16)
        .map(|i| {
            let ks = KeyStore::open(tmp.path().join(format!("n{i}"))).unwrap();
            Arc::new(
                Node::new(Identifier::try_from(i).unwrap(), 3, 2, ks)
                    .with_sign_guard(guard_for(&ids, tmp.path(), i, &policy(i))),
            )
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).unwrap();
    let peers: Peers = nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    Rig { ids, nodes, peers, _tmp: tmp }
}

fn enforcing() -> SigningPolicyConfig {
    SigningPolicyConfig { require_ceremony_intent: true, signer_may_refresh: false, ..Default::default() }
}

impl Rig {
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
    let lenient_role = rig(|_| SigningPolicyConfig { require_ceremony_intent: true, ..Default::default() });
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
        }
        // The pinned key runs it.
        run_dkg_with_intent(&peers, KEY, Some(r.ids.ceremony("driver", CeremonyKind::Dkg, KEY, 3))).await.unwrap();
    }
}

/// Verify-if-present (`require_ceremony_intent` off, this release's default): a ceremony without an
/// intent is accepted and counted; a present one is verified in full and refused if invalid.
#[tokio::test]
async fn without_enforcement_an_absent_intent_is_counted_and_a_present_one_verified() {
    let r = rig(|_| SigningPolicyConfig::default());
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

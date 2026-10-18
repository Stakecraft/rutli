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

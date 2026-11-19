// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner verify-hosted`: does every cosigner hold the same cluster-hosted key, and is it
//! the Canton key the operator expects? Run after `import-key` (once anti-entropy has had an
//! interval to replicate it) and before registering the key on the new participant.
//!
//! The command asks each node for [`crate::pb::HostedKeyStatusReply`] — its own key file, public
//! half only, with no read-repair (a node that lacks the key says so) — and [`check_hosted_views`]
//! cross-checks the answers:
//!
//! - every node of the roster answers, as the identifier it is configured as, and holds the key;
//! - every node serves the same spec and a byte-identical public key (SPKI DER);
//! - that public key is one Canton reads, and its Canton fingerprint is the expected one — the
//!   fingerprint the participant will compute when it registers the key by KMS id
//!   (`RegisterKmsEncryptionKey`), and the one the old node's topology published.
//!
//! Each node reports the public key its private key derives, and refuses to answer for a key file
//! whose stored public half disagrees ([`crate::hosted::HostedKey::derived_public_key_der`]). For
//! an EC or RSA key the public key determines the private one, so on honest nodes a byte-identical
//! SPKI everywhere means every node decrypts with the same key, and a node that holds different
//! material under the id (anti-entropy refuses to merge such a conflict) shows up as a mismatch.
//!
//! **What it cannot catch: a compromised node.** Every answer is that node's self-report; a node
//! whose software or host is under someone else's control can report whatever public key it likes,
//! whatever it holds. This verifies the honest cluster's state, not an adversary's.
//! Public values only: the operator role (`operator_allowlist`) can run it.
//!
//! `rutli-cosigner key show` runs the same checks and may leave the expectation out. Then a
//! symmetric key, which has no public key, is no problem in itself: the report says every node
//! holds a key of that spec under the id — and nothing about whether it is the same key.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::pb::HostedKeyStatusReply;

/// One node's answer (or the error asking it), as collected by the caller.
pub struct HostedView {
    pub identifier: u16,
    pub endpoint: String,
    pub status: std::result::Result<HostedKeyStatusReply, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedRow {
    pub identifier: u16,
    pub endpoint: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub spec: String,
    /// The Canton fingerprint of the public key this node serves (empty if none).
    pub fingerprint: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedReport {
    pub key_id: String,
    /// `hosted`: which of the two report shapes `key show --json` printed.
    pub kind: &'static str,
    /// Absent when the caller gave none (`key show` without `--expect-fingerprint`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_fingerprint: Option<String>,
    pub ok: bool,
    pub problems: Vec<String>,
    /// The spec and public key every node agrees on, once they do.
    pub spec: Option<String>,
    /// Hex SPKI DER; empty for a symmetric key.
    pub public_key_der: Option<String>,
    /// The Canton fingerprint of that public key, if it is one Canton reads.
    pub fingerprint: Option<String>,
    pub nodes: Vec<HostedRow>,
}

/// Check every node's view against the expectation and against each other. `roster` comes from the
/// operator's own configuration, not from any node. With no `expected_fingerprint` (`key show`)
/// every check but that comparison still runs.
pub fn check_hosted_views(
    key_id: &str,
    expected_fingerprint: Option<&str>,
    roster: &[u16],
    views: &[HostedView],
) -> HostedReport {
    let mut problems = Vec::new();
    let expected = expected_fingerprint.map(|given| {
        crate::share_delivery::canonical_fingerprint(given).unwrap_or_else(|e| {
            problems.push(format!("--expect-fingerprint: {e}"));
            given.trim().to_string()
        })
    });
    let expected_ids: BTreeSet<u16> = roster.iter().copied().collect();
    let seen_ids: BTreeSet<u16> = views.iter().map(|v| v.identifier).collect();
    if seen_ids != expected_ids || views.len() != roster.len() {
        problems.push(format!("asked nodes {seen_ids:?}, but the roster is {expected_ids:?}"));
    }

    // (spec, SPKI) -> the nodes serving it.
    let mut served: BTreeMap<(String, Vec<u8>), Vec<u16>> = BTreeMap::new();
    let mut rows = Vec::new();
    for v in views {
        let mut row = HostedRow {
            identifier: v.identifier,
            endpoint: v.endpoint.clone(),
            present: false,
            error: None,
            spec: String::new(),
            fingerprint: String::new(),
            created_at: 0,
        };
        let outcome = match &v.status {
            Err(e) => Err(e.clone()),
            Ok(s) => {
                row.present = s.present;
                row.spec = s.spec.clone();
                row.created_at = s.created_at;
                // Every copy counts towards "one key across the cluster", whatever else is wrong
                // with it.
                if s.present {
                    served.entry((s.spec.clone(), s.public_key_der.clone())).or_default().push(v.identifier);
                }
                check_one(v.identifier, s, expected.as_deref(), &mut row)
            }
        };
        if let Err(e) = outcome {
            problems.push(format!("node {}: {e}", v.identifier));
            row.error = Some(e);
        }
        rows.push(row);
    }
    if served.len() > 1 {
        let groups: Vec<String> = served
            .iter()
            .map(|((spec, der), nodes)| format!("nodes {nodes:?}: {spec} {}", short_sha256(der)))
            .collect();
        problems.push(format!(
            "nodes serve {} different public keys under one id — the key is not one key across the \
             cluster ({}); anti-entropy will not merge this, see docs/hosted-keys.md",
            served.len(),
            groups.join("; ")
        ));
    }
    let agreed = (served.len() == 1).then(|| served.keys().next().cloned()).flatten();
    let fingerprint = agreed
        .as_ref()
        .and_then(|(_, der)| rutli_canton_key::PublicKey::from_spki_der(der).ok())
        .map(|public| public.fingerprint());
    HostedReport {
        key_id: key_id.into(),
        kind: crate::key_cli::KeyKind::Hosted.as_str(),
        expected_fingerprint: expected,
        ok: problems.is_empty(),
        problems,
        spec: agreed.as_ref().map(|(spec, _)| spec.clone()),
        public_key_der: agreed.map(|(_, der)| hex::encode(der)),
        fingerprint,
        nodes: rows,
    }
}

fn check_one(
    identifier: u16,
    s: &HostedKeyStatusReply,
    expected: Option<&str>,
    row: &mut HostedRow,
) -> std::result::Result<(), String> {
    if s.identifier != u32::from(identifier) {
        return Err(format!("answers as node {}, but is configured as node {identifier}", s.identifier));
    }
    if !s.present {
        return Err("does not hold the key".into());
    }
    if s.public_key_der.is_empty() {
        // Nothing to compare an expectation with. Without one, only a symmetric spec may come
        // without a public key.
        return match expected {
            None if crate::hosted::HostedSpec::parse(&s.spec).is_ok_and(|spec| !spec.is_asymmetric()) => Ok(()),
            None => Err(format!("holds a {} key but serves no public key for it", s.spec)),
            Some(_) => {
                Err(format!("{} is a symmetric key — it has no public key or Canton fingerprint", s.spec))
            }
        };
    }
    let public = rutli_canton_key::PublicKey::from_spki_der(&s.public_key_der)
        .map_err(|e| format!("serves a public key Canton could not read: {e}"))?;
    row.fingerprint = public.fingerprint();
    if let Some(expected) = expected.filter(|e| *e != row.fingerprint) {
        return Err(format!("its public key has Canton fingerprint {}, not the expected {expected}", row.fingerprint));
    }
    Ok(())
}

fn short_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("spki sha256 {}", &hex::encode(Sha256::digest(bytes))[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::{HostedKey, HostedSpec};

    const KEY: &str = "rutli-enc-imported";

    fn reply(id: u16, key: &HostedKey) -> HostedKeyStatusReply {
        HostedKeyStatusReply {
            identifier: u32::from(id),
            present: true,
            spec: key.spec.as_str().into(),
            public_key_der: key.public_key_der().unwrap_or_default(),
            created_at: 7,
        }
    }

    /// Three nodes all holding `key`, and its fingerprint.
    fn views(key: &HostedKey) -> (Vec<HostedView>, String) {
        let fp = rutli_canton_key::PublicKey::from_spki_der(&key.public_key_der().unwrap()).unwrap().fingerprint();
        let views = (1..=3u16)
            .map(|id| HostedView { identifier: id, endpoint: format!("https://n{id}"), status: Ok(reply(id, key)) })
            .collect();
        (views, fp)
    }

    #[test]
    fn a_cluster_serving_one_key_with_the_expected_fingerprint_passes() {
        let key = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
        let (v, fp) = views(&key);
        let r = check_hosted_views(KEY, Some(&fp.to_uppercase()), &[1, 2, 3], &v);
        assert!(r.ok, "{:?}", r.problems);
        assert_eq!(r.spec.as_deref(), Some("ec-p256-ecies"));
        assert_eq!(r.public_key_der, Some(hex::encode(key.public_key_der().unwrap())));
        assert!(r.nodes.iter().all(|n| n.fingerprint == fp));
    }

    /// `key show` without `--expect-fingerprint`: the same checks, compared with nothing.
    #[test]
    fn without_an_expectation_the_report_shows_the_key_and_still_checks_everything_else() {
        let key = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
        let other = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
        let (v, fp) = views(&key);
        let shown = check_hosted_views(KEY, None, &[1, 2, 3], &v);
        assert!(shown.ok, "{:?}", shown.problems);
        assert_eq!((shown.kind, shown.expected_fingerprint.as_deref()), ("hosted", None));
        assert_eq!(shown.fingerprint.as_deref(), Some(fp.as_str()));
        assert_eq!(shown.public_key_der, Some(hex::encode(key.public_key_der().unwrap())));
        // With the right expectation: the same report, plus the expectation.
        let verified = check_hosted_views(KEY, Some(&fp), &[1, 2, 3], &v);
        let mut json = serde_json::to_value(&verified).unwrap();
        assert_eq!(json.as_object_mut().unwrap().remove("expected_fingerprint"), Some(fp.clone().into()));
        assert_eq!(json, serde_json::to_value(&shown).unwrap());

        let problems = |v: &[HostedView]| {
            let r = check_hosted_views(KEY, None, &[1, 2, 3], v);
            assert!(!r.ok);
            (r.problems.join(" | "), r.fingerprint)
        };
        // A node without the key, and one that cannot be asked: the two that answer still agree.
        let (mut v, _) = views(&key);
        v[1].status = Ok(HostedKeyStatusReply { present: false, ..reply(2, &key) });
        let (p, shown_fp) = problems(&v);
        assert!(p.contains("node 2: does not hold the key") && shown_fp.as_deref() == Some(fp.as_str()), "{p}");
        // Another key under the id on one node: no fingerprint is reported as the cluster's.
        let (mut v, _) = views(&key);
        v[2].status = Ok(reply(3, &other));
        let (p, shown_fp) = problems(&v);
        assert!(p.contains("2 different public keys") && shown_fp.is_none(), "{p}");
        let (mut v, _) = views(&key);
        v[0].status = Ok(reply(2, &key));
        assert!(problems(&v).0.contains("answers as node 2"));
        let (mut v, _) = views(&key);
        v.pop();
        assert!(problems(&v).0.contains("the roster is"));
        let (mut v, _) = views(&key);
        v[0].status = Ok(HostedKeyStatusReply { public_key_der: vec![0x30, 0x00], ..reply(1, &key) });
        assert!(problems(&v).0.contains("could not read"));
        // An asymmetric spec with no public key is not a symmetric key.
        let (mut v, _) = views(&key);
        v[0].status = Ok(HostedKeyStatusReply { public_key_der: Vec::new(), ..reply(1, &key) });
        assert!(problems(&v).0.contains("serves no public key"));
    }

    /// A symmetric key has nothing to fingerprint. Shown without an expectation it is no problem —
    /// and the report claims no public key and no fingerprint for it. With one it fails, as ever.
    #[test]
    fn a_symmetric_key_is_shown_without_a_fingerprint_and_never_matches_an_expected_one() {
        let aes = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let views = || -> Vec<HostedView> {
            (1..=3u16)
                .map(|id| HostedView { identifier: id, endpoint: format!("https://n{id}"), status: Ok(reply(id, &aes)) })
                .collect()
        };
        let r = check_hosted_views(KEY, None, &[1, 2, 3], &views());
        assert!(r.ok, "{:?}", r.problems);
        assert_eq!((r.spec.as_deref(), r.public_key_der.as_deref(), r.fingerprint), (Some("aes-256-gcm"), Some(""), None));
        assert!(r.nodes.iter().all(|n| n.present && n.fingerprint.is_empty()));
        // One node holds an asymmetric key under the id: two "keys", a problem.
        let mut v = views();
        v[0].status = Ok(reply(1, &HostedKey::generate(HostedSpec::EcP256, 1).unwrap()));
        assert!(!check_hosted_views(KEY, None, &[1, 2, 3], &v).ok);
        let fp = format!("1220{}", "0".repeat(64));
        let r = check_hosted_views(KEY, Some(&fp), &[1, 2, 3], &views());
        assert!(!r.ok && r.problems.iter().all(|p| p.contains("symmetric")), "{:?}", r.problems);
    }

    #[test]
    fn every_inconsistency_is_reported() {
        let key = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
        let other = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
        let (_, fp) = views(&key);
        let problems = |v: &[HostedView], fp: &str| {
            let r = check_hosted_views(KEY, Some(fp), &[1, 2, 3], v);
            assert!(!r.ok && r.spec.is_none() == r.problems.iter().any(|p| p.contains("different public keys")));
            r.problems.join(" | ")
        };

        // A node without the key (not yet replicated), and one that cannot be asked.
        let (mut v, _) = views(&key);
        v[1].status = Ok(HostedKeyStatusReply { present: false, ..reply(2, &key) });
        v[2].status = Err("unreachable: connection refused".into());
        let p = problems(&v, &fp);
        assert!(p.contains("node 2: does not hold the key") && p.contains("node 3: unreachable"), "{p}");
        // Another key under the same id on one node: neither fingerprint nor SPKI agree.
        let (mut v, _) = views(&key);
        v[2].status = Ok(reply(3, &other));
        let p = problems(&v, &fp);
        assert!(p.contains("node 3: its public key has Canton fingerprint") && p.contains("2 different public keys"), "{p}");
        // The right key everywhere, but not the one the operator expects.
        let (v, other_fp) = views(&other);
        assert!(problems(&v, &fp).contains("not the expected"));
        assert!(check_hosted_views(KEY, Some(&other_fp), &[1, 2, 3], &v).ok);
        // A node answering as someone else; a node missing from the answers.
        let (mut v, _) = views(&key);
        v[0].status = Ok(reply(2, &key));
        assert!(problems(&v, &fp).contains("answers as node 2"));
        let (mut v, _) = views(&key);
        v.pop();
        assert!(problems(&v, &fp).contains("the roster is"));
        // A symmetric key has no fingerprint to check; garbage is not a Canton key.
        let aes = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let (mut v, _) = views(&key);
        v[0].status = Ok(reply(1, &aes));
        assert!(problems(&v, &fp).contains("symmetric"));
        let (mut v, _) = views(&key);
        v[0].status = Ok(HostedKeyStatusReply { public_key_der: vec![0x30, 0x00], ..reply(1, &key) });
        assert!(problems(&v, &fp).contains("could not read"));
        // A malformed expectation.
        let (v, _) = views(&key);
        assert!(problems(&v, "1220abc").contains("not a 1220"));
    }
}

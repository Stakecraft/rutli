// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner verify-key`: does every cosigner hold a consistent share of the key the operator
//! expects? Run after the split ceremony's installs, after every refresh, and whenever in doubt.
//!
//! The command asks each node's Signer API for [`crate::pb::KeyStatusReply`] (public values only),
//! then [`check_views`] verifies, independently of what any node claims about itself:
//!
//! - the key is present on all `n` nodes, each answering with the identifier it is configured as;
//! - every node's group key has the expected Canton fingerprint;
//! - every node holds the same public key package (same digest), recomputed from the package it
//!   sent, for the configured roster and threshold;
//! - each node's own verifying share is the package's entry for it — a node whose secret share
//!   does not match the package would make every signature it joins fail;
//! - the package interpolates: every `t`-subset of verifying shares yields the group key;
//! - provenance agrees (origin, ceremony id, refresh count).
//!
//! With `--sign-test`, each node then leads one signature over [`verify_message`], verified with
//! `verify_strict` under the Canton key — the end-to-end proof that any quorum signs. The message
//! is `0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖ key_id)`: Canton-shaped (the cosigners
//! sign nothing else), and not the hash of any Canton topology transaction — Canton's hashes start
//! with a 4-byte hash purpose, which these ASCII bytes are not.

use std::collections::BTreeSet;

use frost_ed25519 as frost;
use frost::keys::PublicKeyPackage;
use frost::Identifier;
use serde::Serialize;

use crate::pb::KeyStatusReply;

/// One node's answer (or the error asking it), as collected by the caller.
pub struct NodeView {
    pub identifier: u16,
    pub endpoint: String,
    pub status: std::result::Result<KeyStatusReply, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeRow {
    pub identifier: u16,
    pub endpoint: String,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub fingerprint: String,
    pub pkp_digest: String,
    pub own_share_in_package: bool,
    pub origin: String,
    pub ceremony_id: String,
    pub refresh_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignRow {
    pub leader: u16,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub key_id: String,
    pub expected_fingerprint: String,
    pub ok: bool,
    pub problems: Vec<String>,
    pub group_verifying_key: Option<String>,
    pub pkp_digest: Option<String>,
    pub threshold: u16,
    pub origin: Option<String>,
    pub ceremony_id: Option<String>,
    pub refresh_count: Option<u64>,
    pub nodes: Vec<NodeRow>,
    pub sign_test: Vec<SignRow>,
}

impl VerifyReport {
    /// The group key, once [`check_views`] found every node agreeing on the expected one.
    pub fn agreed_group_key(&self) -> Option<[u8; 32]> {
        if !self.ok {
            return None;
        }
        self.group_verifying_key.as_ref().and_then(|h| hex::decode(h).ok()?.try_into().ok())
    }

    /// Record one `--sign-test` signature: `signature` (or the error getting it) from `leader`.
    pub fn record_signature(
        &mut self,
        leader: u16,
        message: &[u8],
        signature: std::result::Result<Vec<u8>, String>,
    ) {
        let outcome = signature.and_then(|sig| {
            let group = self.agreed_group_key().ok_or("no agreed group key")?;
            if signature_verifies(&group, message, &sig) {
                Ok(())
            } else {
                Err("signature does not verify (verify_strict) under the Canton key".to_string())
            }
        });
        if let Err(e) = &outcome {
            self.ok = false;
            self.problems.push(format!("sign test led by node {leader}: {e}"));
        }
        self.sign_test.push(SignRow { leader, ok: outcome.is_ok(), error: outcome.err() });
    }
}

/// The `--sign-test` message for a key: `0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖
/// key_id)`. `ceremony_id` is empty for a DKG key.
pub fn verify_message(ceremony_id: &str, key_id: &str) -> [u8; 34] {
    let mut label = b"rutli-verify-key/".to_vec();
    label.extend_from_slice(ceremony_id.as_bytes());
    label.extend_from_slice(key_id.as_bytes());
    rutli_frost_core::dealer::canton_test_message(&label)
}

/// `verify_strict` of a 64-byte Ed25519 signature under a 32-byte public key.
pub fn signature_verifies(public: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(signature) else { return false };
    ed25519_dalek::VerifyingKey::from_bytes(public)
        .map(|vk| vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
        .unwrap_or(false)
}

/// Check every node's view against the expectation and against each other. `roster` and
/// `threshold` come from the operator's own configuration, not from any node.
pub fn check_views(
    key_id: &str,
    expected_fingerprint: &str,
    roster: &[u16],
    threshold: u16,
    views: &[NodeView],
) -> VerifyReport {
    let mut problems = Vec::new();
    let mut rows = Vec::new();
    let expected_ids: BTreeSet<u16> = roster.iter().copied().collect();
    let seen_ids: BTreeSet<u16> = views.iter().map(|v| v.identifier).collect();
    if seen_ids != expected_ids || views.len() != roster.len() {
        problems.push(format!("asked nodes {seen_ids:?}, but the roster is {expected_ids:?}"));
    }

    let mut digests = BTreeSet::new();
    let mut groups = BTreeSet::new();
    let mut provenance = BTreeSet::new();
    for v in views {
        let mut row = NodeRow {
            identifier: v.identifier,
            endpoint: v.endpoint.clone(),
            present: false,
            error: None,
            fingerprint: String::new(),
            pkp_digest: String::new(),
            own_share_in_package: false,
            origin: String::new(),
            ceremony_id: String::new(),
            refresh_count: 0,
        };
        match &v.status {
            Err(e) => {
                row.error = Some(e.clone());
                problems.push(format!("node {}: {e}", v.identifier));
            }
            Ok(s) => {
                row.present = true;
                row.origin = s.origin.clone();
                row.ceremony_id = s.ceremony_id.clone();
                row.refresh_count = s.refresh_count;
                provenance.insert((s.origin.clone(), s.ceremony_id.clone(), s.refresh_count));
                if let Err(e) = check_one(v.identifier, s, expected_fingerprint, roster, threshold, &mut row) {
                    problems.push(format!("node {}: {e}", v.identifier));
                }
                digests.insert(row.pkp_digest.clone());
                groups.insert(hex::encode(&s.group_verifying_key));
            }
        }
        rows.push(row);
    }
    if digests.len() > 1 {
        problems.push(format!(
            "nodes hold {} different public key packages — the sharing is inconsistent",
            digests.len()
        ));
    }
    if provenance.len() > 1 {
        problems.push(format!("nodes disagree on provenance (origin, ceremony, refreshes): {provenance:?}"));
    }
    let single = |set: &BTreeSet<String>| (set.len() == 1).then(|| set.iter().next().cloned()).flatten();
    let (origin, ceremony_id, refresh_count) = match provenance.iter().next() {
        Some((o, c, r)) if provenance.len() == 1 => (Some(o.clone()), Some(c.clone()), Some(*r)),
        _ => (None, None, None),
    };
    VerifyReport {
        key_id: key_id.into(),
        expected_fingerprint: expected_fingerprint.into(),
        ok: problems.is_empty(),
        problems,
        group_verifying_key: single(&groups),
        pkp_digest: single(&digests),
        threshold,
        origin,
        ceremony_id,
        refresh_count,
        nodes: rows,
        sign_test: Vec::new(),
    }
}

fn check_one(
    identifier: u16,
    s: &KeyStatusReply,
    expected_fingerprint: &str,
    roster: &[u16],
    threshold: u16,
    row: &mut NodeRow,
) -> std::result::Result<(), String> {
    let me = Identifier::try_from(identifier).map_err(|e| format!("bad identifier: {e}"))?;
    if s.identifier != me.serialize() {
        return Err("answers with a different FROST identifier than it is configured as".into());
    }
    let group: [u8; 32] = s
        .group_verifying_key
        .as_slice()
        .try_into()
        .map_err(|_| "group key is not 32 bytes".to_string())?;
    row.fingerprint = crate::share_delivery::ed25519_fingerprint(&group);
    if row.fingerprint != expected_fingerprint {
        return Err(format!(
            "group key fingerprint {} is not the expected {expected_fingerprint}",
            row.fingerprint
        ));
    }
    let pkp: PublicKeyPackage = serde_json::from_slice(&s.public_key_package)
        .map_err(|e| format!("unreadable public key package: {e}"))?;
    let digest = rutli_frost_core::dealer::pkp_digest(&pkp).map_err(|e| e.to_string())?;
    row.pkp_digest = hex::encode(digest);
    if s.pkp_digest != digest {
        return Err("reported pkp digest does not match the package it sent".into());
    }
    if rutli_frost_core::dkg::group_verifying_key_bytes(&pkp).map_err(|e| e.to_string())? != group {
        return Err("reported group key does not match its package".into());
    }
    let ids: BTreeSet<Identifier> = roster
        .iter()
        .map(|&i| Identifier::try_from(i).map_err(|e| e.to_string()))
        .collect::<std::result::Result<_, _>>()?;
    if pkp.verifying_shares().keys().copied().collect::<BTreeSet<_>>() != ids {
        return Err(format!("public key package is not for roster {roster:?}"));
    }
    if s.threshold != u32::from(threshold) {
        return Err(format!("share threshold {} ≠ configured {threshold}", s.threshold));
    }
    row.own_share_in_package = pkp
        .verifying_shares()
        .get(&me)
        .and_then(|vs| vs.serialize().ok())
        .is_some_and(|b| b == s.own_verifying_share);
    if !row.own_share_in_package {
        return Err("its own verifying share is not the package's entry for it".into());
    }
    rutli_frost_core::dealer::check_public_key_package(&pkp, threshold).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "frost-import-x";

    /// Statuses as three healthy nodes holding a 2-of-3 split of `seed` would report them.
    fn views(seed: [u8; 32]) -> (Vec<NodeView>, String) {
        let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&seed, &[1, 2, 3], 2).unwrap();
        let group = rutli_frost_core::dkg::group_verifying_key_bytes(&pkp).unwrap();
        let fp = crate::share_delivery::ed25519_fingerprint(&group);
        let views = shares
            .iter()
            .zip(1u16..)
            .map(|(s, id)| {
                let kp = frost::keys::KeyPackage::try_from(s.clone()).unwrap();
                NodeView {
                    identifier: id,
                    endpoint: format!("https://n{id}"),
                    status: Ok(KeyStatusReply {
                        identifier: kp.identifier().serialize(),
                        group_verifying_key: group.to_vec(),
                        own_verifying_share: kp.verifying_share().serialize().unwrap(),
                        pkp_digest: rutli_frost_core::dealer::pkp_digest(&pkp).unwrap().to_vec(),
                        threshold: 2,
                        public_key_package: serde_json::to_vec(&pkp).unwrap(),
                        origin: "dealer-split".into(),
                        ceremony_id: "c".into(),
                        canton_fingerprint: fp.clone(),
                        installed_at: 1,
                        refresh_count: 0,
                    }),
                }
            })
            .collect();
        (views, fp)
    }

    #[test]
    fn a_consistent_cluster_passes() {
        let (v, fp) = views([1u8; 32]);
        let r = check_views(KEY, &fp, &[1, 2, 3], 2, &v);
        assert!(r.ok, "{:?}", r.problems);
        assert!(r.agreed_group_key().is_some());
        assert_eq!(r.refresh_count, Some(0));
    }

    #[test]
    fn every_inconsistency_is_reported() {
        let (_, fp) = views([1u8; 32]);
        // A missing node.
        let (mut v, _) = views([1u8; 32]);
        v[2].status = Err("NOT_FOUND: unknown key id".into());
        assert!(!check_views(KEY, &fp, &[1, 2, 3], 2, &v).ok);
        // The wrong key everywhere.
        let (v, _) = views([2u8; 32]);
        let r = check_views(KEY, &fp, &[1, 2, 3], 2, &v);
        assert!(r.problems.iter().any(|p| p.contains("fingerprint")), "{:?}", r.problems);
        // One node from a different split of the same key: same group key, different package.
        let (mut v, _) = views([1u8; 32]);
        let (other, _) = views([1u8; 32]);
        v.pop();
        v.push(other.into_iter().nth(2).unwrap());
        let r = check_views(KEY, &fp, &[1, 2, 3], 2, &v);
        assert!(r.problems.iter().any(|p| p.contains("different public key packages")), "{:?}", r.problems);
        // A node whose own share is not in the package (e.g. a mis-installed bundle).
        let (mut v, _) = views([1u8; 32]);
        let s1 = v[0].status.as_ref().unwrap().own_verifying_share.clone();
        v[1].status.as_mut().unwrap().own_verifying_share = s1;
        assert!(!check_views(KEY, &fp, &[1, 2, 3], 2, &v).ok);
        // A node answering as someone else.
        let (mut v, _) = views([1u8; 32]);
        v[0].identifier = 2;
        assert!(!check_views(KEY, &fp, &[1, 2, 3], 2, &v).ok);
        // Provenance disagreement (one node refreshed, others not — a half-applied refresh).
        let (mut v, _) = views([1u8; 32]);
        v[0].status.as_mut().unwrap().refresh_count = 1;
        assert!(!check_views(KEY, &fp, &[1, 2, 3], 2, &v).ok);
        // Wrong configured threshold.
        let (v, _) = views([1u8; 32]);
        assert!(!check_views(KEY, &fp, &[1, 2, 3], 3, &v).ok);
    }

    #[test]
    fn signatures_are_checked_strictly_and_failures_fail_the_report() {
        let (v, fp) = views([1u8; 32]);
        let mut r = check_views(KEY, &fp, &[1, 2, 3], 2, &v);
        let msg = verify_message("c", KEY);
        r.record_signature(1, &msg, Err("UNAVAILABLE".into()));
        r.record_signature(2, &msg, Ok(vec![0u8; 64]));
        assert!(!r.ok);
        assert_eq!(r.sign_test.iter().filter(|s| !s.ok).count(), 2);
        assert_eq!(&msg[..2], &[0x12, 0x20]);
        assert_ne!(verify_message("c", KEY), verify_message("d", KEY));
    }
}

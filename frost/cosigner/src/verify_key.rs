// Copyright 2026 StakeCraft LLC
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
//! - provenance agrees (origin, ceremony id, refresh count, and what the key was carried for).
//!
//! `rutli-cosigner key show` runs the same checks and may leave the expectation out: the report
//! then says what the nodes hold and that they agree, and is compared with nothing. Every answer
//! is a node's self-report, so a fingerprint read this way is never the `--expect-fingerprint` of
//! an import or a migration — that one comes from the old node or from Canton's topology.
//!
//! A public view can be perfect while a node's *secret* share is wrong, so with `--sign-test` the
//! command then has the cluster sign with **every `t`-subset** of cosigners in turn
//! ([`sign_test_plan`], `Signer.CeremonySignTest`, leader rotating), each verified with
//! `verify_strict` under the Canton key — the end-to-end proof that every quorum that may ever
//! have to sign can. (A "first `t` responders" quorum would use the same `t` nodes every time and
//! never touch the others' shares.) The cosigner computes the message itself from the key's
//! recorded provenance, `0x1220 ‖ SHA-256("rutli-verify-key/" ‖ ceremony_id ‖ key_id)`
//! ([`verify_message`]), and only for imported keys: Canton-shaped (the cosigners sign nothing
//! else), never chosen by the caller, and domain-separated from every hash Canton builds. Canton
//! hashes `be_i32(HashPurpose.id) ‖ content` (`HashBuilder.scala:192-205`), and every purpose
//! Canton 3.6.1 defines is 1–68, or −1 for test hashes (`HashPurpose.scala:52-123`); this
//! preimage starts with the ASCII bytes `rutl`, which as a purpose would be 0x7275746C =
//! 1 920 300 140. Equal digests would take a SHA-256 collision. That is what lets the **operator**
//! role (`operator_allowlist`) run it without a credential that can `Sign`.

use std::collections::BTreeSet;

use frost::keys::PublicKeyPackage;
use frost::Identifier;
use frost_ed25519 as frost;
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
    /// `namespace` / `protocol` for a key from a B6 dealer, empty otherwise.
    pub carried_for: String,
    pub recorded_usage: String,
    /// The sharing this node holds (1 after DKG, +1 per refresh; 0 = pre-epoch or dealt).
    pub epoch: u64,
    /// The node's epoch check found its share stale: it refuses to sign with it.
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignRow {
    pub leader: u16,
    /// The exact quorum that signed.
    pub signers: Vec<u16>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub key_id: String,
    /// `frost`: which of the two report shapes `key show --json` printed.
    pub kind: &'static str,
    /// Absent when the caller gave none (`key show` without `--expect-fingerprint`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_fingerprint: Option<String>,
    pub ok: bool,
    pub problems: Vec<String>,
    pub group_verifying_key: Option<String>,
    /// The Canton fingerprint of the group key, only when every check passed (`ok`): a report with
    /// problems names no fingerprint as the cluster's. Each node's own is in its row.
    pub fingerprint: Option<String>,
    pub pkp_digest: Option<String>,
    pub threshold: u16,
    pub origin: Option<String>,
    pub ceremony_id: Option<String>,
    pub refresh_count: Option<u64>,
    pub carried_for: Option<String>,
    pub recorded_usage: Option<String>,
    /// The epoch every node reports, when they agree.
    pub epoch: Option<u64>,
    pub nodes: Vec<NodeRow>,
    pub sign_test: Vec<SignRow>,
}

impl VerifyReport {
    /// The group key, once [`check_views`] found every node agreeing on the expected one.
    pub fn agreed_group_key(&self) -> Option<[u8; 32]> {
        if !self.ok {
            return None;
        }
        self.group_verifying_key
            .as_ref()
            .and_then(|h| hex::decode(h).ok()?.try_into().ok())
    }

    /// Record one `CeremonySignTest` result: `(message, signature)` as the cluster returned them
    /// (or the error), for quorum `signers` led by `leader`. The message must be the one this side
    /// computes independently ([`verify_message`] over the agreed ceremony id), and the signature
    /// must pass `verify_strict` under the agreed (expected) group key.
    pub fn record_signature(
        &mut self,
        leader: u16,
        signers: &[u16],
        result: std::result::Result<(Vec<u8>, Vec<u8>), String>,
    ) {
        let expected = verify_message(self.ceremony_id.as_deref().unwrap_or(""), &self.key_id);
        let outcome = result.and_then(|(message, sig)| {
            let group = self.agreed_group_key().ok_or("no agreed group key")?;
            if message != expected {
                return Err(
                    "the cluster signed a different message than the ceremony test digest".into(),
                );
            }
            if signature_verifies(&group, &expected, &sig) {
                Ok(())
            } else {
                Err("signature does not verify (verify_strict) under the Canton key".to_string())
            }
        });
        if let Err(e) = &outcome {
            self.ok = false;
            // A report with a problem names no fingerprint as the cluster's.
            self.fingerprint = None;
            self.problems.push(format!(
                "sign test by {signers:?} (led by node {leader}): {e}"
            ));
        }
        self.sign_test.push(SignRow {
            leader,
            signers: signers.to_vec(),
            ok: outcome.is_ok(),
            error: outcome.err(),
        });
    }
}

/// The `--sign-test` plan: every `t`-subset of `roster` (so every share is exercised, and every
/// quorum that may one day have to sign is proven to), each led by a different node in turn.
pub fn sign_test_plan(roster: &[u16], t: u16) -> Vec<(u16, Vec<u16>)> {
    fn go(start: usize, roster: &[u16], k: usize, cur: &mut Vec<u16>, out: &mut Vec<Vec<u16>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for (i, id) in roster.iter().enumerate().skip(start) {
            cur.push(*id);
            go(i + 1, roster, k, cur, out);
            cur.pop();
        }
    }
    let mut subsets = Vec::new();
    if roster.is_empty() {
        return Vec::new();
    }
    go(0, roster, usize::from(t), &mut Vec::new(), &mut subsets);
    subsets
        .into_iter()
        .enumerate()
        .filter_map(|(k, s)| roster.get(k % roster.len()).map(|&leader| (leader, s)))
        .collect()
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
    let Ok(sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    ed25519_dalek::VerifyingKey::from_bytes(public).is_ok_and(|vk| {
        vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
            .is_ok()
    })
}

/// Check every node's view against the expectation and against each other. `roster` and
/// `threshold` come from the operator's own configuration, not from any node. With no
/// `expected_fingerprint` (`key show`) every check but that comparison still runs.
pub fn check_views(
    key_id: &str,
    expected_fingerprint: Option<&str>,
    roster: &[u16],
    threshold: u16,
    views: &[NodeView],
) -> VerifyReport {
    let mut acc = ViewAcc::default();
    let expected_fingerprint =
        canonical_expected_fingerprint(expected_fingerprint, &mut acc.problems);
    let mut rows = Vec::new();
    check_roster(&mut acc.problems, roster, views);

    for v in views {
        let mut row = empty_node_row(v);
        match &v.status {
            Err(e) => {
                row.error = Some(e.clone());
                acc.problems.push(format!("node {}: {e}", v.identifier));
            }
            Ok(s) => {
                let expected = expected_fingerprint.as_deref();
                let id = v.identifier;
                check_node_status(id, s, expected, roster, threshold, &mut row, &mut acc);
            }
        }
        rows.push(row);
    }
    flag_disagreements(&mut acc);
    build_report(key_id, expected_fingerprint, threshold, rows, acc)
}

/// What [`check_views`] collects over the nodes' views.
#[derive(Default)]
struct ViewAcc {
    problems: Vec<String>,
    digests: BTreeSet<String>,
    groups: BTreeSet<String>,
    provenance: BTreeSet<(String, String, u64, String, String)>,
    epochs: BTreeSet<u64>,
}

/// The expected fingerprint in canonical form (trimmed, lower case) like every fingerprint
/// computed here; a malformed one is a problem of its own and matches nothing.
fn canonical_expected_fingerprint(
    expected_fingerprint: Option<&str>,
    problems: &mut Vec<String>,
) -> Option<String> {
    expected_fingerprint.map(|given| {
        crate::share_delivery::canonical_fingerprint(given).unwrap_or_else(|e| {
            problems.push(format!("--expect-fingerprint: {e}"));
            given.trim().to_string()
        })
    })
}

/// Record a problem when the nodes asked are not exactly the roster.
fn check_roster(problems: &mut Vec<String>, roster: &[u16], views: &[NodeView]) {
    let expected_ids: BTreeSet<u16> = roster.iter().copied().collect();
    let seen_ids: BTreeSet<u16> = views.iter().map(|v| v.identifier).collect();
    if seen_ids != expected_ids || views.len() != roster.len() {
        problems.push(format!(
            "asked nodes {seen_ids:?}, but the roster is {expected_ids:?}"
        ));
    }
}

/// A row for a node, before its answer is read.
fn empty_node_row(v: &NodeView) -> NodeRow {
    NodeRow {
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
        carried_for: String::new(),
        recorded_usage: String::new(),
        epoch: 0,
        stale: false,
    }
}

/// Read a node's answer into its row and into what is compared across the nodes.
fn check_node_status(
    identifier: u16,
    s: &KeyStatusReply,
    expected_fingerprint: Option<&str>,
    roster: &[u16],
    threshold: u16,
    row: &mut NodeRow,
    acc: &mut ViewAcc,
) {
    row.present = true;
    row.origin = s.origin.clone();
    row.ceremony_id = s.ceremony_id.clone();
    row.refresh_count = s.refresh_count;
    row.carried_for = s.carried_for.clone();
    row.recorded_usage = s.recorded_usage.clone();
    row.epoch = s.epoch;
    row.stale = s.stale;
    if s.stale {
        acc.problems.push(format!(
            "node {identifier}: its share is stale (a newer sharing is committed elsewhere) — it \
             refuses to sign"
        ));
    }
    acc.epochs.insert(s.epoch);
    acc.provenance.insert((
        s.origin.clone(),
        s.ceremony_id.clone(),
        s.refresh_count,
        s.carried_for.clone(),
        s.recorded_usage.clone(),
    ));
    if let Err(e) = check_one(identifier, s, expected_fingerprint, roster, threshold, row) {
        acc.problems.push(format!("node {identifier}: {e}"));
    }
    acc.digests.insert(row.pkp_digest.clone());
    acc.groups.insert(hex::encode(&s.group_verifying_key));
}

/// Record a problem for each thing the nodes do not agree on: public key package, epoch, provenance.
fn flag_disagreements(acc: &mut ViewAcc) {
    if acc.digests.len() > 1 {
        acc.problems.push(format!(
            "nodes hold {} different public key packages — the sharing is inconsistent",
            acc.digests.len()
        ));
    }
    if acc.epochs.len() > 1 {
        let epochs = &acc.epochs;
        acc.problems.push(format!(
            "nodes are on different epochs {epochs:?} — mixed sharings never combine"
        ));
    }
    if acc.provenance.len() > 1 {
        let provenance = &acc.provenance;
        acc.problems.push(format!(
            "nodes disagree on provenance (origin, ceremony, refreshes, carried for, usage): {provenance:?}"
        ));
    }
}

/// The only value of a set, when it holds exactly one.
fn single_value(set: &BTreeSet<String>) -> Option<String> {
    (set.len() == 1)
        .then(|| set.iter().next().cloned())
        .flatten()
}

/// The report: what every node agrees on, and the problems where they do not.
fn build_report(
    key_id: &str,
    expected_fingerprint: Option<String>,
    threshold: u16,
    rows: Vec<NodeRow>,
    acc: ViewAcc,
) -> VerifyReport {
    let (origin, ceremony_id, refresh_count, carried_for, recorded_usage) =
        match acc.provenance.iter().next() {
            Some((o, c, r, f, u)) if acc.provenance.len() == 1 => (
                Some(o.clone()),
                Some(c.clone()),
                Some(*r),
                Some(f.clone()),
                Some(u.clone()),
            ),
            _ => (None, None, None, None, None),
        };
    let group_verifying_key = single_value(&acc.groups);
    let fingerprint = group_verifying_key
        .as_ref()
        .filter(|_| acc.problems.is_empty())
        .and_then(|h| <[u8; 32]>::try_from(hex::decode(h).ok()?).ok())
        .map(|g| crate::share_delivery::ed25519_fingerprint(&g));
    VerifyReport {
        key_id: key_id.into(),
        kind: crate::key_cli::KeyKind::Frost.as_str(),
        expected_fingerprint,
        ok: acc.problems.is_empty(),
        problems: acc.problems,
        group_verifying_key,
        fingerprint,
        pkp_digest: single_value(&acc.digests),
        threshold,
        origin,
        ceremony_id,
        refresh_count,
        carried_for,
        recorded_usage,
        epoch: (acc.epochs.len() == 1)
            .then(|| acc.epochs.iter().next().copied())
            .flatten(),
        nodes: rows,
        sign_test: Vec::new(),
    }
}

fn check_one(
    identifier: u16,
    s: &KeyStatusReply,
    expected_fingerprint: Option<&str>,
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
    if let Some(expected) = expected_fingerprint.filter(|e| *e != row.fingerprint) {
        return Err(format!(
            "group key fingerprint {} is not the expected {expected}",
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
    if pkp
        .verifying_shares()
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != ids
    {
        return Err(format!("public key package is not for roster {roster:?}"));
    }
    if s.threshold != u32::from(threshold) {
        return Err(format!(
            "share threshold {} ≠ configured {threshold}",
            s.threshold
        ));
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

    #[test]
    fn the_sign_test_plan_covers_every_subset_and_never_panics_on_odd_input() {
        let plan = sign_test_plan(&[1, 2, 3], 2);
        let subsets: Vec<Vec<u16>> = plan.iter().map(|(_, s)| s.clone()).collect();
        assert_eq!(subsets, vec![vec![1, 2], vec![1, 3], vec![2, 3]]);
        assert_eq!(
            plan.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the leader rotates"
        );
        assert_eq!(sign_test_plan(&[], 2), [] as [(u16, std::vec::Vec<u16>); 0]);
        assert!(
            sign_test_plan(&[1, 2], 3).is_empty(),
            "a threshold above the roster has no subset"
        );
    }

    /// Statuses as three healthy nodes holding a 2-of-3 split of `seed` would report them.
    fn views(seed: [u8; 32]) -> (Vec<NodeView>, String) {
        let (shares, pkp) =
            rutli_frost_core::dealer::split_ed25519_seed(&seed, &[1, 2, 3], 2).unwrap();
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
                        carried_for: "namespace".into(),
                        recorded_usage: "namespace".into(),
                        epoch: 0,
                        stale: false,
                    }),
                }
            })
            .collect();
        (views, fp)
    }

    #[test]
    fn a_consistent_cluster_passes() {
        let (v, fp) = views([1u8; 32]);
        let r = check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v);
        assert!(r.ok, "{:?}", r.problems);
        assert!(r.agreed_group_key().is_some());
        assert_eq!(r.refresh_count, Some(0));
        assert_eq!(
            (r.carried_for.as_deref(), r.recorded_usage.as_deref()),
            (Some("namespace"), Some("namespace"))
        );
        // The operator's fingerprint is compared in canonical form (2026-10-15 review, L2).
        let r = check_views(
            KEY,
            Some(&format!(" {} ", fp.to_uppercase())),
            &[1, 2, 3],
            2,
            &v,
        );
        assert!(r.ok, "{:?}", r.problems);
        assert_eq!(r.expected_fingerprint.as_deref(), Some(fp.as_str()));
        let r = check_views(KEY, Some("1220zz"), &[1, 2, 3], 2, &v);
        assert!(
            !r.ok && r.problems.iter().any(|p| p.contains("not a 1220")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn every_inconsistency_is_reported() {
        let (_, fp) = views([1u8; 32]);
        // A missing node.
        let (mut v, _) = views([1u8; 32]);
        v[2].status = Err("NOT_FOUND: unknown key id".into());
        assert!(!check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v).ok);
        // The wrong key everywhere.
        let (v, _) = views([2u8; 32]);
        let r = check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v);
        assert!(
            r.problems.iter().any(|p| p.contains("fingerprint")),
            "{:?}",
            r.problems
        );
        // One node from a different split of the same key: same group key, different package.
        let (mut v, _) = views([1u8; 32]);
        let (other, _) = views([1u8; 32]);
        v.pop();
        v.push(other.into_iter().nth(2).unwrap());
        let r = check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v);
        assert!(
            r.problems
                .iter()
                .any(|p| p.contains("different public key packages")),
            "{:?}",
            r.problems
        );
        // A node whose own share is not in the package (e.g. a mis-installed bundle).
        let (mut v, _) = views([1u8; 32]);
        let s1 = v[0].status.as_ref().unwrap().own_verifying_share.clone();
        v[1].status.as_mut().unwrap().own_verifying_share = s1;
        assert!(!check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v).ok);
        // A node answering as someone else.
        let (mut v, _) = views([1u8; 32]);
        v[0].identifier = 2;
        assert!(!check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v).ok);
        // Provenance disagreement (one node refreshed, others not — a half-applied refresh).
        let (mut v, _) = views([1u8; 32]);
        v[0].status.as_mut().unwrap().refresh_count = 1;
        assert!(!check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v).ok);
        // ... or on what the key was carried for.
        let (mut v, _) = views([1u8; 32]);
        v[2].status.as_mut().unwrap().carried_for = "protocol".into();
        let r = check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v);
        assert!(
            r.problems.iter().any(|p| p.contains("carried for")),
            "{:?}",
            r.problems
        );
        // Wrong configured threshold.
        let (v, _) = views([1u8; 32]);
        assert!(!check_views(KEY, Some(&fp), &[1, 2, 3], 3, &v).ok);
    }

    /// `key show` without `--expect-fingerprint`: the same checks, compared with nothing.
    #[test]
    fn without_an_expectation_the_report_shows_the_key_and_still_checks_everything_else() {
        let (v, fp) = views([1u8; 32]);
        let shown = check_views(KEY, None, &[1, 2, 3], 2, &v);
        assert!(shown.ok, "{:?}", shown.problems);
        assert_eq!(
            (shown.kind, shown.expected_fingerprint.as_deref()),
            ("frost", None)
        );
        assert_eq!(shown.fingerprint.as_deref(), Some(fp.as_str()));
        assert!(shown
            .nodes
            .iter()
            .all(|n| n.fingerprint == fp && n.own_share_in_package));
        assert_eq!(
            (shown.origin.as_deref(), shown.epoch, shown.threshold),
            (Some("dealer-split"), Some(0), 2)
        );
        // With the right expectation: the same report, plus the expectation.
        let verified = check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v);
        let mut json = serde_json::to_value(&verified).unwrap();
        assert_eq!(
            json.as_object_mut().unwrap().remove("expected_fingerprint"),
            Some(fp.clone().into())
        );
        assert_eq!(json, serde_json::to_value(&shown).unwrap());

        // Everything `verify-key` catches other than "not the expected key" is caught here too,
        // and a report with a problem names no fingerprint as the cluster's.
        let problems = |v: &[NodeView]| {
            let r = check_views(KEY, None, &[1, 2, 3], 2, v);
            assert!(!r.ok && r.fingerprint.is_none(), "{:?}", r.fingerprint);
            r.problems.join(" | ")
        };
        let (mut v, _) = views([1u8; 32]);
        v[2].status = Err("NOT_FOUND: unknown key id".into());
        assert!(problems(&v).contains("node 3: NOT_FOUND"));
        // Two nodes on one key, the third on another: no fingerprint is reported as the cluster's.
        let (mut v, _) = views([1u8; 32]);
        let (other, other_fp) = views([2u8; 32]);
        v[2] = other.into_iter().nth(2).unwrap();
        let r = check_views(KEY, None, &[1, 2, 3], 2, &v);
        assert!(
            !r.ok && r.fingerprint.is_none() && r.group_verifying_key.is_none(),
            "{:?}",
            r.problems
        );
        assert!(
            r.problems
                .iter()
                .any(|p| p.contains("different public key packages")),
            "{:?}",
            r.problems
        );
        assert_eq!(
            (
                r.nodes[0].fingerprint.as_str(),
                r.nodes[2].fingerprint.as_str()
            ),
            (fp.as_str(), other_fp.as_str())
        );
        let (mut v, _) = views([1u8; 32]);
        let s1 = v[0].status.as_ref().unwrap().own_verifying_share.clone();
        v[1].status.as_mut().unwrap().own_verifying_share = s1;
        assert!(problems(&v).contains("own verifying share"));
        let (mut v, _) = views([1u8; 32]);
        v[0].status.as_mut().unwrap().epoch = 1;
        assert!(problems(&v).contains("different epochs"));
        let (mut v, _) = views([1u8; 32]);
        v[1].status.as_mut().unwrap().stale = true;
        assert!(problems(&v).contains("stale"));
        let (mut v, _) = views([1u8; 32]);
        v[0].status.as_mut().unwrap().refresh_count = 1;
        assert!(problems(&v).contains("provenance"));
        let (mut v, _) = views([1u8; 32]);
        v.pop();
        assert!(problems(&v).contains("the roster is"));
        let (v, _) = views([1u8; 32]);
        assert!(!check_views(KEY, None, &[1, 2, 3], 3, &v).ok);
        // Nor does a wrong or malformed expectation: every node agrees, the report still names none.
        let wrong = format!("1220{}", "0".repeat(64));
        for expected in [wrong.as_str(), "1220zz"] {
            let r = check_views(KEY, Some(expected), &[1, 2, 3], 2, &v);
            assert!(
                !r.ok && r.fingerprint.is_none() && r.group_verifying_key.is_some(),
                "{:?}",
                r.problems
            );
            assert!(r.nodes.iter().all(|n| n.fingerprint == fp));
        }
    }

    #[test]
    fn signatures_are_checked_strictly_and_failures_fail_the_report() {
        let (v, fp) = views([1u8; 32]);
        let mut r = check_views(KEY, Some(&fp), &[1, 2, 3], 2, &v);
        let msg = verify_message("c", KEY);
        assert_eq!(r.fingerprint.as_deref(), Some(fp.as_str()));
        r.record_signature(1, &[1, 2], Err("UNAVAILABLE".into()));
        assert!(!r.ok && r.fingerprint.is_none());
        r.record_signature(2, &[1, 3], Ok((msg.to_vec(), vec![0u8; 64])));
        // A valid-looking reply over a message the operator did not expect is a failure too.
        r.record_signature(
            3,
            &[2, 3],
            Ok((verify_message("other", KEY).to_vec(), vec![0u8; 64])),
        );
        assert!(!r.ok);
        assert_eq!(r.sign_test.iter().filter(|s| !s.ok).count(), 3);
        assert_eq!(&msg[..2], &[0x12, 0x20]);
        assert_ne!(verify_message("c", KEY), verify_message("d", KEY));
    }

    #[test]
    fn the_plan_covers_every_quorum_and_rotates_the_leader() {
        assert_eq!(
            sign_test_plan(&[1, 2, 3], 2),
            vec![(1, vec![1, 2]), (2, vec![1, 3]), (3, vec![2, 3])]
        );
        let plan = sign_test_plan(&[1, 2, 3, 4, 5], 3);
        assert_eq!(plan.len(), 10);
        let leaders: std::collections::BTreeSet<u16> = plan.iter().map(|(l, _)| *l).collect();
        assert_eq!(leaders.len(), 5);
    }
}

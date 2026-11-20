// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The production profile (`"profile": "production"`): one setting that requires every enforcement
//! setting the threat model assumes, and refuses to start otherwise.
//!
//! Several enforcement settings are off by default so that rolling upgrades and labs keep working.
//! [`findings`] lists every one that is not at its production value, as one [`Finding`] each. Under
//! `"profile": "production"` a node refuses to start while any [`Level::Required`] finding is left,
//! and names each one. [`Level::Advisory`] findings are reported and never refuse a start.
//! `rutli-cosigner check-config` prints the same list whatever the profile.
//!
//! A new enforcement setting adds a row here. The tests build a fully enforced config, check that
//! it has no finding, and then break each setting in turn and check that exactly its own row fires.
//! docs/production-profile.md has the same table for operators.

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// `profile`: what the operator says this node is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Every [`Level::Required`] finding refuses the start.
    Production,
    /// A lab, compose or LocalNet node: findings are logged at startup, nothing is refused.
    Lab,
}

/// How much a finding weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Refuses the start under `"profile": "production"`.
    Required,
    /// Reported only: a deployment decision the profile does not make for the operator.
    Advisory,
}

/// One setting that is not at its production value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    /// The config key, as it is written in the file.
    pub setting: &'static str,
    /// What the file says (or that the key is missing).
    pub found: String,
    /// What the production profile requires.
    pub required: &'static str,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.level {
            Level::Required => "required",
            Level::Advisory => "advisory",
        };
        write!(f, "[{tag}] {}: {} — production requires {}", self.setting, self.found, self.required)
    }
}

/// Where the refusal message and `check-config` send the operator.
pub const DOC: &str = "docs/production-profile.md";

/// Every setting of `cfg` that is not at its production value. Reads nothing but `cfg` (no file the
/// config names), so it can run anywhere, before an upgrade.
pub fn findings(cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut req = |setting: &'static str, found: String, required: &'static str| {
        out.push(Finding { level: Level::Required, setting, found, required })
    };
    let tls = cfg.tls.is_some();
    let p = &cfg.signing_policy;
    let signers: Vec<String> = cfg.signer_allowlist.clone().unwrap_or_default();
    let listed = |v: &Option<Vec<String>>| v.as_ref().is_some_and(|a| !a.is_empty());

    match &cfg.tls {
        None => req("tls", "missing (plaintext)".into(), "mutual TLS"),
        Some(t) if t.allow_expired_ca => req("tls.allow_expired_ca", "true".into(), "false"),
        Some(_) => {}
    }
    match &cfg.share_seal {
        None => req("share_seal", "missing (key files in plaintext)".into(), "share_seal.secret_file (a per-node seal bundle)"),
        Some(s) if s.secret_env.is_some() => req(
            "share_seal.secret_env",
            "set (the legacy shared master secret)".into(),
            "share_seal.secret_file (a per-node seal bundle) instead",
        ),
        Some(s) if s.secret_file.is_none() => {
            req("share_seal.secret_file", "missing".into(), "a per-node seal bundle")
        }
        Some(_) => {}
    }
    if signers.is_empty() {
        req("signer_allowlist", "missing or empty".into(), "the driver certificate CN(s)");
    }
    if !listed(&cfg.operator_allowlist) {
        req("operator_allowlist", "missing or empty".into(), "the operator certificate CN(s)");
    }
    if !listed(&cfg.refresh_allowlist) {
        req("refresh_allowlist", "missing or empty".into(), "the refresh job's certificate CN(s)");
    }
    if p.signer_may_refresh {
        req("signing_policy.signer_may_refresh", "true (the default)".into(), "false");
    }
    // Without TLS the intent switches cannot be on; the `tls` row already says so.
    if tls && !p.intent_required(tls) {
        req("signing_policy.require_intent", effective(p.require_intent, tls), "on (unset or true, with TLS)");
    }
    if tls && !p.ceremony_intent_required(tls) {
        req(
            "signing_policy.require_ceremony_intent",
            effective(p.require_ceremony_intent, tls),
            "on (unset or true, with TLS)",
        );
    }
    if !p.require_epoch_match {
        req("signing_policy.require_epoch_match", "false (the default)".into(), "true");
    }
    if !p.signer_acl_required {
        req("signing_policy.signer_acl_required", "false (the default)".into(), "true");
    }
    let no_acl: Vec<&str> = signers.iter().filter(|cn| !p.signer_acl.contains_key(*cn)).map(String::as_str).collect();
    if !no_acl.is_empty() {
        req("signing_policy.signer_acl", format!("no entry for {}", no_acl.join(", ")), "an entry for every signer_allowlist CN");
    }
    let no_pin: Vec<&str> = signers.iter().filter(|cn| !p.signer_pins.contains_key(*cn)).map(String::as_str).collect();
    if !no_pin.is_empty() {
        req("signing_policy.signer_pins", format!("no pin for {}", no_pin.join(", ")), "a pin for every signer_allowlist CN");
    }
    if p.sign_rate_limit_per_min == 0 {
        req("signing_policy.sign_rate_limit_per_min", "0 (off)".into(), "a limit above 0");
    }
    if p.sign_rate_limit_per_day == 0 {
        req("signing_policy.sign_rate_limit_per_day", "0 (off)".into(), "a limit above 0");
    }
    let unlimited: Vec<&str> =
        p.rate_limits.iter().filter(|r| r.per_min == 0 || r.per_day == 0).map(|r| r.key_id_prefix.as_str()).collect();
    if !unlimited.is_empty() {
        req(
            "signing_policy.rate_limits",
            format!("a 0 (off) limit for prefix(es) {:?}", unlimited),
            "per_min and per_day above 0 in every rule",
        );
    }
    if cfg.ceremony_sign_test_rate_limit_per_min == 0 {
        req("ceremony_sign_test_rate_limit_per_min", "0 (off)".into(), "a limit above 0");
    }
    if cfg.keyfile.write_version != 2 {
        req("keyfile.write_version", cfg.keyfile.write_version.to_string(), "2");
    }
    if cfg.keyfile.cluster_uuid.is_none() {
        req("keyfile.cluster_uuid", "missing".into(), "the cluster's UUID, the same on every node");
    }
    if cfg.keyfile.accept_v1 {
        req("keyfile.accept_v1", "true (the default)".into(), "false, once every key file is v2");
    }
    if cfg.cluster_id.is_none() {
        req("cluster_id", "derived from tls.ca_cert".into(), "set explicitly, so a CA rotation cannot change it");
    }
    if cfg.cluster_id_change_allowed {
        req("cluster_id_change_allowed", "true".into(), "false (only for one deliberate start)");
    }
    if let Some(h) = cfg.hosted_keys.as_ref().filter(|h| h.enabled) {
        if h.decrypt_rate_limit_per_min == 0 {
            req("hosted_keys.decrypt_rate_limit_per_min", "0 (off)".into(), "a limit above 0");
        }
        if !h.delete_allowlist.is_empty() && h.delete_approval_threshold == 0 {
            req(
                "hosted_keys.delete_approval_threshold",
                "0 while hosted_keys.delete_allowlist is set".into(),
                "at least 1",
            );
        }
        if h.commitment_key.is_none() {
            req("hosted_keys.commitment_key", "missing".into(), "the cluster-wide commitment key");
        }
    }

    if !p.rules.iter().any(|r| r.mode == "quorum" && covers_namespace_key(&r.key_id_prefix)) {
        out.push(Finding {
            level: Level::Advisory,
            setting: "signing_policy.rules",
            found: "no quorum rule for a namespace key (`<prefix>frost-namespace`)".into(),
            required: "a quorum approval rule for the namespace key (docs/approval-quorum.md)",
        });
    }
    out
}

/// Whether a rule's key-id prefix covers a namespace key: the driver names it
/// `<frost.key-prefix>frost-namespace`, and this node does not know the participant's prefix. So a
/// prefix of `frost-namespace` itself (`""`, `frost-`, …) counts, and so does one that ends in a
/// prefix of it after a participant prefix (`participant1-frost-namespace`, `participant1-frost-`).
fn covers_namespace_key(prefix: &str) -> bool {
    const NS: &str = "frost-namespace";
    NS.starts_with(prefix) || prefix.find("frost-").is_some_and(|i| NS.starts_with(&prefix[i..]))
}

fn effective(set: Option<bool>, _tls: bool) -> String {
    match set {
        Some(false) => "false (the explicit opt-out)".into(),
        _ => "on".into(),
    }
}

/// The required findings of `cfg` (empty when the node meets the profile).
pub fn required(cfg: &Config) -> Vec<Finding> {
    findings(cfg).into_iter().filter(|f| f.level == Level::Required).collect()
}

/// The refusal message for a production node with required findings: one line per setting.
pub fn refusal(required: &[Finding]) -> String {
    let mut s = format!(
        "profile is \"production\" but {} enforcement setting(s) are not at their production value \
         ({DOC}; run `rutli-cosigner check-config` to list them; set \"profile\": \"lab\" only for a lab):",
        required.len()
    );
    for f in required {
        s.push_str("\n  - ");
        s.push_str(&f.to_string());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ApprovalRuleConfig, HostedKeysConfig, KeyFileConfig, RateLimitRule, ShareSealConfig, SigningPolicyConfig,
    };
    use std::collections::BTreeMap;

    /// A config with every enforcement setting at its production value (as the Helm chart's
    /// `production` values render it). Parsed from JSON so it also pins the file format.
    pub(crate) fn enforced() -> Config {
        serde_json::from_value(serde_json::json!({
            "profile": "production",
            "identifier": 1,
            "listen": "0.0.0.0:9101",
            "threshold": 2,
            "data_dir": "/data",
            "peers": [
                {"identifier": 1, "endpoint": "https://a:9101"},
                {"identifier": 2, "endpoint": "https://b:9101"},
                {"identifier": 3, "endpoint": "https://c:9101"}
            ],
            "tls": {"ca_cert": "/tls/ca.crt", "cert": "/tls/tls.crt", "key": "/tls/tls.key"},
            "share_seal": {"secret_file": "/run/rutli/seal/node.json"},
            "signer_allowlist": ["driver"],
            "peer_allowlist": ["cosigner1", "cosigner2", "cosigner3"],
            "operator_allowlist": ["operator"],
            "refresh_allowlist": ["refresher"],
            "cluster_id": "0123456789abcdef",
            "keyfile": {"write_version": 2, "cluster_uuid": "6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b", "accept_v1": false},
            "signing_policy": {
                "require_epoch_match": true,
                "signer_acl_required": true,
                "signer_may_refresh": false,
                "signer_acl": {"driver": [""]},
                "signer_pins": {"driver": ["00".repeat(32)]},
                "rules": [{"key_id_prefix": "frost-namespace", "mode": "quorum", "threshold": 1}],
                // A public key only (the one config.rs tests use), so the quorum rule validates.
                "approvers": [{"id": "alice", "public_key_spki_b64": "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="}]
            }
        }))
        .unwrap()
    }

    #[test]
    fn a_fully_enforced_config_has_no_finding() {
        assert_eq!(findings(&enforced()), vec![], "{:#?}", findings(&enforced()));
    }

    /// Each break flips one setting; exactly that setting's row must fire, at the given level.
    #[test]
    fn each_setting_breaks_exactly_its_own_row() {
        type Break = (&'static str, Level, fn(&mut Config));
        let breaks: Vec<Break> = vec![
            ("tls", Level::Required, |c| c.tls = None),
            ("tls.allow_expired_ca", Level::Required, |c| c.tls.as_mut().unwrap().allow_expired_ca = true),
            ("share_seal", Level::Required, |c| c.share_seal = None),
            ("share_seal.secret_env", Level::Required, |c| {
                c.share_seal = Some(ShareSealConfig { secret_env: Some("SEAL".into()), secret_file: None })
            }),
            ("share_seal.secret_file", Level::Required, |c| c.share_seal = Some(ShareSealConfig::default())),
            ("operator_allowlist", Level::Required, |c| c.operator_allowlist = None),
            ("refresh_allowlist", Level::Required, |c| c.refresh_allowlist = Some(vec![])),
            ("signing_policy.signer_may_refresh", Level::Required, |c| c.signing_policy.signer_may_refresh = true),
            ("signing_policy.require_intent", Level::Required, |c| c.signing_policy.require_intent = Some(false)),
            ("signing_policy.require_ceremony_intent", Level::Required, |c| {
                c.signing_policy.require_ceremony_intent = Some(false)
            }),
            ("signing_policy.require_epoch_match", Level::Required, |c| c.signing_policy.require_epoch_match = false),
            ("signing_policy.signer_acl_required", Level::Required, |c| c.signing_policy.signer_acl_required = false),
            ("signing_policy.signer_acl", Level::Required, |c| c.signing_policy.signer_acl = BTreeMap::new()),
            ("signing_policy.signer_pins", Level::Required, |c| c.signing_policy.signer_pins = BTreeMap::new()),
            ("signing_policy.sign_rate_limit_per_min", Level::Required, |c| c.signing_policy.sign_rate_limit_per_min = 0),
            ("signing_policy.sign_rate_limit_per_day", Level::Required, |c| c.signing_policy.sign_rate_limit_per_day = 0),
            ("signing_policy.rate_limits", Level::Required, |c| {
                c.signing_policy.rate_limits = vec![RateLimitRule { key_id_prefix: "frost-".into(), per_min: 0, per_day: 10 }]
            }),
            ("ceremony_sign_test_rate_limit_per_min", Level::Required, |c| c.ceremony_sign_test_rate_limit_per_min = 0),
            ("keyfile.write_version", Level::Required, |c| c.keyfile.write_version = 1),
            ("keyfile.cluster_uuid", Level::Required, |c| c.keyfile.cluster_uuid = None),
            ("keyfile.accept_v1", Level::Required, |c| c.keyfile.accept_v1 = true),
            ("cluster_id", Level::Required, |c| c.cluster_id = None),
            ("cluster_id_change_allowed", Level::Required, |c| c.cluster_id_change_allowed = true),
            ("hosted_keys.decrypt_rate_limit_per_min", Level::Required, |c| {
                c.hosted_keys = Some(HostedKeysConfig { decrypt_rate_limit_per_min: 0, ..hosted() })
            }),
            ("hosted_keys.delete_approval_threshold", Level::Required, |c| {
                c.hosted_keys = Some(HostedKeysConfig { delete_allowlist: vec!["operator".into()], ..hosted() })
            }),
            ("hosted_keys.commitment_key", Level::Required, |c| {
                c.hosted_keys = Some(HostedKeysConfig { commitment_key: None, ..hosted() })
            }),
            ("signing_policy.rules", Level::Advisory, |c| {
                c.signing_policy.rules = vec![ApprovalRuleConfig { key_id_prefix: "x".into(), mode: "auto".into(), threshold: 0 }]
            }),
            // A quorum rule for another key does not cover the namespace key.
            ("signing_policy.rules", Level::Advisory, |c| c.signing_policy.rules[0].key_id_prefix = "p1-rutli-enc-".into()),
        ];
        // A well-formed hosted-keys block on its own fires nothing.
        let mut ok = enforced();
        ok.hosted_keys = Some(hosted());
        assert_eq!(findings(&ok), vec![]);
        for (setting, level, brk) in breaks {
            let mut c = enforced();
            brk(&mut c);
            let f = findings(&c);
            assert_eq!(f.len(), 1, "{setting}: {f:#?}");
            assert_eq!((f[0].setting, f[0].level), (setting, level), "{f:#?}");
        }
    }

    #[test]
    fn which_rule_prefixes_cover_the_namespace_key() {
        for yes in ["", "frost-", "frost-namespace", "p1-frost-namespace", "p1-frost-", "participant1-frost-n"] {
            assert!(covers_namespace_key(yes), "{yes}");
        }
        for no in ["p1-", "rutli-", "frost-signing", "p1-frost-signing", "p1-rutli-enc-"] {
            assert!(!covers_namespace_key(no), "{no}");
        }
    }

    fn hosted() -> HostedKeysConfig {
        let mut h: HostedKeysConfig = serde_json::from_value(serde_json::json!({"enabled": true})).unwrap();
        h.commitment_key = Some("11".repeat(32));
        h
    }

    #[test]
    fn a_production_node_refuses_to_start_naming_each_gap_and_a_lab_node_does_not() {
        enforced().validate().expect("a fully enforced production config validates");
        let mut c = enforced();
        c.signing_policy.require_epoch_match = false;
        c.keyfile.accept_v1 = true;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("signing_policy.require_epoch_match") && err.contains("keyfile.accept_v1"), "{err}");
        c.profile = Some(Profile::Lab);
        c.validate().expect("lab: findings do not refuse");
        c.profile = None;
        c.validate().expect("unset: findings do not refuse (until 0.6)");
        // Advisory findings never refuse, not even under production.
        let mut a = enforced();
        a.signing_policy.rules.clear();
        assert_eq!(findings(&a).len(), 1);
        a.validate().expect("advisory only");
    }

    #[test]
    fn plaintext_and_an_empty_allowlist_name_every_gap() {
        // A plaintext lab config: the intent switches read as off without TLS.
        let mut c = enforced();
        c.tls = None;
        c.signer_allowlist = None;
        let names: Vec<_> = findings(&c).iter().map(|f| f.setting).collect();
        assert_eq!(names, vec!["tls", "signer_allowlist"], "the tls row covers the intent switches");
    }

    #[test]
    fn the_refusal_names_each_setting_and_points_to_the_doc() {
        let mut c = enforced();
        c.keyfile = KeyFileConfig::default();
        c.signing_policy = SigningPolicyConfig { rules: c.signing_policy.rules.clone(), ..Default::default() };
        let r = required(&c);
        let msg = refusal(&r);
        for f in &r {
            assert!(msg.contains(f.setting), "{msg}");
        }
        assert!(msg.contains(DOC) && msg.contains("check-config"), "{msg}");
        assert!(msg.contains("keyfile.write_version: 1 — production requires 2"), "{msg}");
    }
}

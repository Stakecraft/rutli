// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Static cluster configuration for one cosigner node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// This node's FROST identifier (1..=n).
    pub identifier: u16,
    /// Address this node's gRPC server listens on (host:port).
    pub listen: String,
    /// Signing threshold `t`.
    pub threshold: u16,
    /// Directory for key shares and nonce-store markers (must be durable).
    pub data_dir: PathBuf,
    /// The full cosigner roster, including this node.
    pub peers: Vec<PeerConfig>,
    /// Mutual-TLS config. When present, the gRPC server requires client certs and peer clients
    /// present ours; when absent, the node runs plaintext (dev only).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Share sealing (encryption-at-rest for key shares). When present, shares are stored as
    /// AES-256-GCM envelopes keyed from the referenced secret; when absent, shares are plaintext
    /// JSON (dev only).
    #[serde(default)]
    pub share_seal: Option<ShareSealConfig>,
    /// Client-certificate Common Names allowed to call the Signer API (Dkg/Sign/Refresh/GroupKey) —
    /// typically just the driver's cert CN. When absent, any cluster-CA-signed client may call it
    /// (mTLS still required; the ceremony guard still applies). Set this in production so a cosigner
    /// cert cannot request arbitrary signatures. The mesh Peer API is unaffected.
    #[serde(default)]
    pub signer_allowlist: Option<Vec<String>>,
    /// Client-certificate Common Names allowed to call the mesh-internal Peer API (the raw FROST
    /// round RPCs) — i.e. the OTHER cosigners, and only them. The Peer API is the unmediated
    /// protocol layer: a caller that reaches `SignRound1`/`SignRound2` on `threshold` nodes can
    /// aggregate a signature over ANY message, bypassing the Signer API's Canton-digest guard and
    /// the ceremony fence. The driver's cert is signed by the same cluster CA, so transport mTLS
    /// alone does NOT separate these roles — this allowlist is what keeps a Signer-API client
    /// (or any other cluster-CA holder) off the mesh. Required when TLS is enabled.
    #[serde(default)]
    pub peer_allowlist: Option<Vec<String>>,
    /// Client-certificate Common Names of the **operator** role: allowed `KeyStatus` and
    /// `CeremonySignTest` (the split ceremony's `verify-key`) and nothing else on the Signer API —
    /// in particular not `Sign`, so verifying a ceremony needs no credential that can sign
    /// arbitrary digests with a namespace key. Optional; must not share a CN with
    /// `signer_allowlist` or `peer_allowlist`.
    #[serde(default)]
    pub operator_allowlist: Option<Vec<String>>,
    /// Client-certificate Common Names of the **refresher** role: `Refresh` and `KeyStatus` only —
    /// never `Sign` — for the proactive-refresh job, so the credential a CronJob carries cannot
    /// sign (audit C2). Must not share a CN with `signer_allowlist` or `peer_allowlist`; may share
    /// one with `operator_allowlist` (both roles cannot sign), which lets the operator certificate
    /// run refreshes until a `refresher` certificate is issued. The signer role keeps `Refresh`
    /// while `signing_policy.signer_may_refresh` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_allowlist: Option<Vec<String>>,
    /// Ceiling on `CeremonySignTest` calls this node leads, per key per minute (token bucket,
    /// burst = one minute's allowance). Every call burns a durable nonce marker on each signer, so
    /// the operator role must not be able to loop it. One `verify-key --sign-test` needs C(n,t)
    /// calls (3 for 2-of-3, 10 for 3-of-5). `0` disables the limit.
    #[serde(default = "default_ceremony_sign_test_rate_limit")]
    pub ceremony_sign_test_rate_limit_per_min: u32,
    /// Address for the plaintext Prometheus /metrics endpoint (e.g. "0.0.0.0:9200"). When absent,
    /// no metrics endpoint is served. Metrics carry operation counts/latencies only — never key
    /// material, digests, or session ids — so plaintext HTTP is acceptable on a trusted network;
    /// still, do not expose this port publicly.
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// Cluster-hosted (non-FROST) keys: RSA-2048 encryption and AES-256-GCM symmetric keys held by
    /// the cluster so a participant needs no HSM and no local key state. Off by default.
    #[serde(default)]
    pub hosted_keys: Option<HostedKeysConfig>,
    /// Explicit cluster identity that envelopes are bound to (hosted-key replication, split-ceremony
    /// recipient requests and share bundles). When unset it is derived from the `tls.ca_cert` file
    /// bytes ([`crate::wrap::cluster_id_from_ca`]), or `plaintext-dev` without TLS — so any change
    /// to the CA file, including adding a second CA for a rotation, would change it.
    ///
    /// Pin it to the **current derived value** (`shasum -a 256 ca.crt | cut -c1-16`) *before* changing
    /// the CA file (CA rotation, docs/ca-rotation.md), and never change it afterwards: it must be
    /// identical on every node, and in-flight split-ceremony recipient files carry it. Exactly 16
    /// lowercase hex characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    /// Allow this start to run under a different cluster id than the one recorded in
    /// `data_dir/cluster-id` at an earlier start ([`crate::cluster_identity`]). Without it a node
    /// whose effective id changed — typically a `helm upgrade` that dropped `clusterId` — refuses
    /// to start. Only for a deliberate change (a node moved to another cluster, a dev cluster
    /// started over); set it for one start, then remove it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cluster_id_change_allowed: bool,
    /// What this node demands of the leaders it signs for.
    #[serde(default)]
    pub signing_policy: SigningPolicyConfig,
}

/// Cosigner-side signing policy (`signing_policy`): what this node demands before it takes part in
/// a signature (audit H1 epochs, audit C2 signing intents). Every node enforces its own copy; the
/// cluster is only as strict as its most lenient node that a quorum can reach, so set the same
/// policy everywhere.
///
/// **Enforcement switches** (`require_intent`, `signer_acl_required`, and `signer_may_refresh`
/// turned off) default to the lenient side in this release, so a rolling upgrade and a driver that
/// predates intents keep working. Turn them on, on every node, once every cosigner and the driver
/// run this release (docs/approval-quorum.md, "Switching enforcement on").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningPolicyConfig {
    /// Refuse sign round 1 from a leader that does not say which sharing (epoch, PKP digest) of the
    /// key it signs with. Off by default in this release so leaders on the previous release keep
    /// signing during a rolling upgrade (the check is then skipped with a warning and
    /// `rutli_epoch_check_skipped_total`); turn it on once every cosigner runs this release. A
    /// leader that does send its sharing is always checked.
    #[serde(default)]
    pub require_epoch_match: bool,
    /// Refuse to take part in a signature without a valid client-signed intent (audit C2). Off:
    /// an intent that is present is verified in full (and refused if invalid); a sign without one
    /// is accepted and counted in `rutli_sign_intent_absent_total`. On: absence is refusal.
    /// Requires TLS (intents are verified against the cluster CA).
    #[serde(default)]
    pub require_intent: bool,
    /// Refuse every key operation by a Signer client CN that has no `signer_acl` entry. Off: a CN
    /// without an entry may use every key (counted in `rutli_signer_acl_absent_total`).
    #[serde(default)]
    pub signer_acl_required: bool,
    /// Let the signer role (`signer_allowlist`, the driver) call `Refresh` too, as before this
    /// release. Turn it off once the refresh job runs with a `refresh_allowlist` certificate, so a
    /// stolen driver certificate cannot drive share refreshes.
    #[serde(default = "default_true")]
    pub signer_may_refresh: bool,
    /// Per-client key ACL: Signer client CN -> the key-id prefixes it may use (`""` = every key).
    /// Checked on every key-scoped Signer RPC at the node the client calls, and on the intent's
    /// signer by every node in a signature. Multi-tenant clusters give each participant's driver
    /// certificate its own CN and prefix (`frost.key-prefix`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signer_acl: BTreeMap<String, Vec<String>>,
    /// SPKI pins: client CN -> SHA-256 hex of the SubjectPublicKeyInfo of every certificate key
    /// that may act under that CN (`openssl x509 -in driver.crt -noout -pubkey | openssl pkey
    /// -pubin -outform DER | sha256sum`). A CN listed here is refused on the Signer API and as an
    /// intent signer with any other key, however valid its certificate — revocation without the
    /// CA: rotate a stolen driver key by issuing a new certificate and replacing the pin.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signer_pins: BTreeMap<String, Vec<String>>,
    /// Longest validity (`not_after - issued_at`) an intent may claim.
    #[serde(default = "default_intent_max_lifetime")]
    pub intent_max_lifetime_secs: u64,
    /// Clock skew tolerated between the driver and this node, both ways, on intent times.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,
    /// Per-key signing ceiling on this node, per minute and per rolling 24 hours, charged once per
    /// intent request id (retries, subsets and failover leaders of one driver call share a charge)
    /// or per session for a sign without an intent. Durable across restarts (rebuilt from the sign
    /// journal). `0` disables a limit. A key matching a `rate_limits` rule uses the rule instead.
    #[serde(default = "default_sign_rate_per_min")]
    pub sign_rate_limit_per_min: u32,
    #[serde(default = "default_sign_rate_per_day")]
    pub sign_rate_limit_per_day: u32,
    /// Per-prefix ceilings (first match wins): e.g. a tight one for the namespace key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<RateLimitRule>,
    /// Most signature shares this node releases for one intent request id (a valid intent re-used
    /// by a compromised leader buys at most this many signatures over the same digest).
    #[serde(default = "default_max_shares_per_request")]
    pub max_shares_per_request: u32,
    /// Sign journal (`data_dir/journal/<key_id>/`): segments older than this are deleted...
    #[serde(default = "default_journal_retention_days")]
    pub journal_retention_days: u32,
    /// ...and so are the oldest segments of a key past this total size.
    #[serde(default = "default_journal_max_mib_per_key")]
    pub journal_max_mib_per_key: u32,
    /// Approval rules, as the driver's `approval.rules` (key-id prefix, first match wins): a key a
    /// `quorum` rule matches needs `threshold` distinct `approvers` signatures in the intent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ApprovalRuleConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<ApproverConfig>,
}

impl Default for SigningPolicyConfig {
    fn default() -> Self {
        Self {
            require_epoch_match: false,
            require_intent: false,
            signer_acl_required: false,
            signer_may_refresh: true,
            signer_acl: BTreeMap::new(),
            signer_pins: BTreeMap::new(),
            intent_max_lifetime_secs: default_intent_max_lifetime(),
            clock_skew_secs: default_clock_skew(),
            sign_rate_limit_per_min: default_sign_rate_per_min(),
            sign_rate_limit_per_day: default_sign_rate_per_day(),
            rate_limits: Vec::new(),
            max_shares_per_request: default_max_shares_per_request(),
            journal_retention_days: default_journal_retention_days(),
            journal_max_mib_per_key: default_journal_max_mib_per_key(),
            rules: Vec::new(),
            approvers: Vec::new(),
        }
    }
}

/// A per-prefix sign rate limit (`signing_policy.rate_limits`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub key_id_prefix: String,
    pub per_min: u32,
    pub per_day: u32,
}

/// An approval rule (`signing_policy.rules`), the same shape as the driver's `approval.rules`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRuleConfig {
    pub key_id_prefix: String,
    /// "quorum" (needs `threshold` approvals) or "auto" (carves an exception out of a broader rule).
    #[serde(default = "default_quorum_mode")]
    pub mode: String,
    #[serde(default = "default_quorum_threshold")]
    pub threshold: u32,
}

/// An approver (`signing_policy.approvers`): the id and Ed25519 key of the driver's
/// `approval.approvers` entry (base64 DER SubjectPublicKeyInfo, the same value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverConfig {
    pub id: String,
    pub public_key_spki_b64: String,
}

fn default_true() -> bool {
    true
}
fn default_quorum_mode() -> String {
    "quorum".into()
}
fn default_quorum_threshold() -> u32 {
    2
}
/// The driver's intents live 180 s; 300 s leaves room without letting one live long.
pub const DEFAULT_INTENT_MAX_LIFETIME_SECS: u64 = 300;
fn default_intent_max_lifetime() -> u64 {
    DEFAULT_INTENT_MAX_LIFETIME_SECS
}
/// Generous: an intent refused for skew is an outage, and the expiry only bounds replay.
pub const DEFAULT_CLOCK_SKEW_SECS: u64 = 120;
fn default_clock_skew() -> u64 {
    DEFAULT_CLOCK_SKEW_SECS
}
/// 300 per minute (5/s bursts) and 20 000 per day per key, on each node: far above a namespace
/// key's handful a day and above a DevNet validator's protocol-key traffic, low enough that a
/// stolen driver certificate cannot turn a key into a bulk oracle unnoticed — and ~8 MB/day of
/// journal at the ceiling. Put a tight `rate_limits` rule on namespace keys.
pub const DEFAULT_SIGN_RATE_LIMIT_PER_MIN: u32 = 300;
pub const DEFAULT_SIGN_RATE_LIMIT_PER_DAY: u32 = 20_000;
fn default_sign_rate_per_min() -> u32 {
    DEFAULT_SIGN_RATE_LIMIT_PER_MIN
}
fn default_sign_rate_per_day() -> u32 {
    DEFAULT_SIGN_RATE_LIMIT_PER_DAY
}
/// One driver call through the t-subset retry and leader failover releases a share from one node
/// at most a few times (2-of-3: two subsets per node per leader).
pub const DEFAULT_MAX_SHARES_PER_REQUEST: u32 = 8;
fn default_max_shares_per_request() -> u32 {
    DEFAULT_MAX_SHARES_PER_REQUEST
}
pub const DEFAULT_JOURNAL_RETENTION_DAYS: u32 = 90;
fn default_journal_retention_days() -> u32 {
    DEFAULT_JOURNAL_RETENTION_DAYS
}
/// 64 MiB per key: on the shipped 1 Gi volume, a handful of signing keys stays far below it.
pub const DEFAULT_JOURNAL_MAX_MIB_PER_KEY: u32 = 64;
fn default_journal_max_mib_per_key() -> u32 {
    DEFAULT_JOURNAL_MAX_MIB_PER_KEY
}

impl SigningPolicyConfig {
    /// The (per minute, per day) ceiling for `key_id`.
    pub fn rate_limit_for(&self, key_id: &str) -> (u32, u32) {
        match self.rate_limits.iter().find(|r| key_id.starts_with(&r.key_id_prefix)) {
            Some(r) => (r.per_min, r.per_day),
            None => (self.sign_rate_limit_per_min, self.sign_rate_limit_per_day),
        }
    }

    /// The approvals `key_id` needs (first matching rule), or `None`.
    pub fn approval_threshold_for(&self, key_id: &str) -> Option<u32> {
        self.rules
            .iter()
            .find(|r| key_id.starts_with(&r.key_id_prefix))
            .filter(|r| r.mode == "quorum")
            .map(|r| r.threshold)
    }

    /// The pins of `cn`, decoded; `None` when the CN is not pinned.
    pub fn pins_for(&self, cn: &str) -> Option<Vec<[u8; 32]>> {
        self.signer_pins.get(cn).map(|list| {
            list.iter().filter_map(|h| hex32("signer_pins", h).ok()).collect()
        })
    }

    fn validate(&self, signers: &[String], tls: bool) -> crate::Result<()> {
        use crate::DaemonError::Config;
        if self.require_intent && !tls {
            return Err(Config(
                "signing_policy.require_intent needs tls: intents are verified against the cluster CA".into(),
            ));
        }
        if self.intent_max_lifetime_secs == 0 || self.intent_max_lifetime_secs > 3600 {
            return Err(Config("signing_policy.intent_max_lifetime_secs must be 1..=3600".into()));
        }
        if self.clock_skew_secs > 3600 {
            return Err(Config("signing_policy.clock_skew_secs must be at most 3600".into()));
        }
        if self.max_shares_per_request == 0 {
            return Err(Config("signing_policy.max_shares_per_request must be at least 1".into()));
        }
        if self.journal_max_mib_per_key < 4 {
            return Err(Config("signing_policy.journal_max_mib_per_key must be at least 4".into()));
        }
        if self.journal_retention_days == 0 {
            return Err(Config("signing_policy.journal_retention_days must be at least 1".into()));
        }
        for cn in self.signer_acl.keys() {
            if !signers.contains(cn) {
                return Err(Config(format!(
                    "signing_policy.signer_acl names {cn:?}, which is not in signer_allowlist"
                )));
            }
        }
        if self.signer_acl_required {
            if let Some(cn) = signers.iter().find(|cn| !self.signer_acl.contains_key(*cn)) {
                return Err(Config(format!(
                    "signing_policy.signer_acl_required is set but signer {cn:?} has no signer_acl \
                     entry — it could use no key; give it its prefixes (\"\" = every key)"
                )));
            }
        }
        for (cn, pins) in &self.signer_pins {
            if pins.is_empty() {
                return Err(Config(format!("signing_policy.signer_pins.{cn} is empty — omit the CN or pin a key")));
            }
            for h in pins {
                hex32(&format!("signing_policy.signer_pins.{cn}"), h)?;
            }
        }
        let mut ids = std::collections::HashSet::new();
        for a in &self.approvers {
            if !ids.insert(a.id.as_str()) {
                return Err(Config(format!("signing_policy.approvers lists {:?} twice", a.id)));
            }
            crate::intent::ed25519_key_from_spki_b64(&a.public_key_spki_b64).map_err(|e| {
                Config(format!("signing_policy.approvers[{}].public_key_spki_b64: {e}", a.id))
            })?;
        }
        for r in &self.rules {
            match r.mode.as_str() {
                "auto" => {}
                "quorum" if r.threshold >= 1 && (r.threshold as usize) <= self.approvers.len() => {}
                "quorum" => {
                    return Err(Config(format!(
                        "signing_policy.rules[{:?}]: threshold {} must be between 1 and the number of \
                         approvers ({})",
                        r.key_id_prefix,
                        r.threshold,
                        self.approvers.len()
                    )))
                }
                other => {
                    return Err(Config(format!(
                        "signing_policy.rules[{:?}]: mode must be \"quorum\" or \"auto\", got {other:?}",
                        r.key_id_prefix
                    )))
                }
            }
        }
        Ok(())
    }
}

/// Cluster-hosted key settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedKeysConfig {
    #[serde(default)]
    pub enabled: bool,
    /// How many cosigners must hold a new key before it is reported created. Defaults to 2 — the
    /// cluster's own fault model. Requiring all nodes would block key rotation whenever any node
    /// is down, which is worse than the single copy an HSM provides.
    #[serde(default = "default_write_quorum")]
    pub write_quorum: usize,
    /// How often to reconcile hosted keys with peers (pull what we lack, push what they lack).
    /// This is what heals an under-quorum write, so it is not optional in practice.
    #[serde(default = "default_anti_entropy_secs")]
    pub anti_entropy_interval_secs: u64,
    /// Ceiling on decryptions per key per minute, enforced by the cosigner. `0` disables it.
    ///
    /// This bounds a stolen driver certificate: that certificate authorizes `Decrypt`, and because
    /// Canton's encryption keys protect per-view session keys, it can read *retrospectively* —
    /// every recorded message ever encrypted to that key. The driver's own signing journal cannot
    /// help, since whoever stole the certificate need not use the driver at all.
    ///
    /// The default is deliberately far above real traffic (100/s sustained on a single key), so it
    /// caps bulk exfiltration without shaping normal load. Raise it if a legitimate node warns that
    /// it is approaching the ceiling; the warning fires well before requests start failing.
    ///
    /// **Per node, not per cluster.** Each cosigner keeps its own buckets and nodes share no limiter
    /// state, so a holder of the driver certificate who calls every node directly gets `n` times
    /// this budget per key (n = cosigners serving hosted keys). The driver itself sends a key's
    /// traffic to one preferred leader at a time, so this value must cover the full legitimate rate
    /// on one node. Size it as `cluster_budget / n`, and check that this still clears the legitimate
    /// peak with headroom; the effective cluster-wide ceiling is `n ×` this value.
    #[serde(default = "default_decrypt_rate_limit")]
    pub decrypt_rate_limit_per_min: u32,
    /// The cluster-wide key hosted-key commitments are keyed by (64 hex chars, public). Every node
    /// must use the same value. Required with `share_seal.secret_file`; on the legacy master it is
    /// derived (and, if set, checked). `rutli-cosigner seal split-legacy` prints the value a legacy
    /// cluster already uses; a new cluster generates one (`openssl rand -hex 32`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_key: Option<String>,
}

impl HostedKeysConfig {
    pub fn commitment_key_bytes(&self) -> crate::Result<Option<[u8; 32]>> {
        self.commitment_key.as_deref().map(|h| hex32("hosted_keys.commitment_key", h)).transpose()
    }
}

/// Parse a 32-byte public value given as 64 hex chars.
fn hex32(field: &str, value: &str) -> crate::Result<[u8; 32]> {
    hex::decode(value.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| crate::DaemonError::Config(format!("{field} must be 64 hex chars (32 bytes)")))
}

/// Room for one `verify-key --sign-test` of a cluster up to 3-of-5 per minute, and little else.
pub const DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN: u32 = 10;

fn default_ceremony_sign_test_rate_limit() -> u32 {
    DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN
}

fn default_write_quorum() -> usize {
    2
}

fn default_anti_entropy_secs() -> u64 {
    300
}

/// 6000/min = 100 decryptions per second, sustained, on ONE key. Far above what a Canton
/// participant does; low enough to matter against bulk exfiltration.
pub const DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN: u32 = 6000;

fn default_decrypt_rate_limit() -> u32 {
    DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN
}

/// Where this node's seal keys come from — exactly one of the two. Never the keys themselves: this
/// config file is not secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShareSealConfig {
    /// Path of this node's seal bundle (`crate::seal::NodeSealBundle`): its own DEK and hosted-key
    /// distribution seed, nothing of any other node. Mount it from a per-node secret as a file
    /// (0400/0440), never through an env var. Requires a `dist_public_key` on every peer and
    /// `hosted_keys.commitment_key` when hosted keys are on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_file: Option<PathBuf>,
    /// **Deprecated (legacy):** name of the environment variable holding the one master secret every
    /// node derives its keys from. Anything that can read that secret (or exec into any node and
    /// read its env) can derive every node's DEK. Kept so existing clusters run unchanged until
    /// they migrate (`rutli-cosigner seal split-legacy`, docs/runbook-per-node-seal.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_env: Option<String>,
}

/// Mutual-TLS material for the cosigner mesh (and the driver→cluster hop). All peers and the driver
/// present certs signed by the cluster CA; the CA file holds the trust anchors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// PEM file of the CA certificate(s) that must sign every peer/client certificate: one CA, or
    /// during a CA rotation the bundle old + new. Every block must be a currently valid CA
    /// certificate, or the node refuses to start ([`crate::trust::load_trust_anchors`]).
    pub ca_cert: PathBuf,
    /// PEM certificate this node presents (as server, and as client to peers).
    pub cert: PathBuf,
    /// PEM private key for `cert`.
    pub key: PathBuf,
    /// TLS server name the operator CLI (`refresh`, `verify-key`) verifies when it dials a target
    /// that is not a roster peer. **Not** used for the mesh: each peer is dialled with its own
    /// [`PeerConfig::server_name`], so a cosigner certificate can never stand in for another node
    /// (audit M3). The old shared `rutli-cosigner` SAN is accepted here but no longer needed.
    #[serde(default)]
    pub domain: Option<String>,
    /// Accept an expired or not-yet-valid CA in `ca_cert` (it is still refused if it is not a CA).
    /// Emergency use only: a rotation away from a CA that has already expired, where the old CA
    /// must stay in the bundle until every leaf is swapped (docs/ca-rotation.md). Remove it after.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_expired_ca: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub identifier: u16,
    /// gRPC endpoint of the peer (e.g. http://host:port). Ignored for this node itself.
    pub endpoint: String,
    /// The peer's hosted-key distribution public key (64 hex chars, public), pinned. Required for
    /// every peer when this node runs on a seal bundle (`share_seal.secret_file`) with hosted keys
    /// on: such a node cannot derive its peers' keys. This node's own entry is checked against its
    /// seal keys at startup. Printed by `rutli-cosigner seal split-legacy` / `seal inspect`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dist_public_key: Option<String>,
    /// The TLS server name (certificate SAN) this peer must present when dialled. Defaults to
    /// `cosigner<identifier>`, which every certificate from scripts/gen-frost-certs.sh carries.
    /// Per peer, never one shared name: with a shared name any cosigner certificate verifies as any
    /// peer, so a node holding one cert could answer for another (audit M3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    /// The client-certificate Common Name this peer presents when it calls this node. Defaults to
    /// `cosigner<identifier>`. A mesh caller is identified by an EXACT match on this, never by
    /// parsing digits out of whatever CN it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_cn: Option<String>,
}

impl PeerConfig {
    pub fn new(identifier: u16, endpoint: impl Into<String>) -> Self {
        Self {
            identifier,
            endpoint: endpoint.into(),
            dist_public_key: None,
            tls_server_name: None,
            tls_client_cn: None,
        }
    }

    /// The server name to verify when dialling this peer.
    pub fn server_name(&self) -> String {
        self.tls_server_name.clone().unwrap_or_else(|| format!("cosigner{}", self.identifier))
    }

    /// The client-certificate CN this peer calls with.
    pub fn client_cn(&self) -> String {
        self.tls_client_cn.clone().unwrap_or_else(|| format!("cosigner{}", self.identifier))
    }

    pub fn dist_public_key_bytes(&self) -> crate::Result<Option<[u8; 32]>> {
        self.dist_public_key
            .as_deref()
            .map(|h| hex32(&format!("peer {} dist_public_key", self.identifier), h))
            .transpose()
    }
}

impl Config {
    pub fn max_signers(&self) -> u16 {
        self.peers.len() as u16
    }

    /// The cluster identity envelopes are bound to: the pinned [`Config::cluster_id`] when set,
    /// else [`Config::derived_cluster_id`].
    pub fn cluster_id(&self) -> crate::Result<String> {
        match &self.cluster_id {
            Some(pinned) => Ok(pinned.clone()),
            None => self.derived_cluster_id(),
        }
    }

    /// Where [`Config::cluster_id`] comes from, as the startup log and error messages say it.
    pub fn cluster_id_source(&self) -> &'static str {
        match (&self.cluster_id, &self.tls) {
            (Some(_), _) => "pinned in config",
            (None, Some(_)) => "derived from tls.ca_cert",
            (None, None) => "plaintext-dev, no TLS",
        }
    }

    /// The cluster identity the CA file implies: [`crate::wrap::cluster_id_from_ca`] of the
    /// `tls.ca_cert` bytes, or `plaintext-dev` without TLS. Reads the CA file. Ignores the pin.
    pub fn derived_cluster_id(&self) -> crate::Result<String> {
        Ok(match &self.tls {
            Some(t) => crate::wrap::cluster_id_from_ca(&std::fs::read(&t.ca_cert)?),
            None => "plaintext-dev".to_string(),
        })
    }

    /// Mesh caller identity: client-certificate CN → roster identifier, exact match only.
    pub fn peer_identities(&self) -> std::collections::HashMap<String, u16> {
        self.peers.iter().map(|p| (p.client_cn(), p.identifier)).collect()
    }

    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = serde_json::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> crate::Result<()> {
        use crate::DaemonError::Config;
        if let Some(pinned) = &self.cluster_id {
            crate::wrap::check_cluster_id(pinned).map_err(|e| match e {
                Config(msg) => Config(format!("cluster_id: {msg}")),
                other => other,
            })?;
        }
        if self.peers.is_empty() {
            return Err(Config("peer roster is empty".into()));
        }
        // A roster is a set. A repeated identifier would make `max_signers` and the threshold
        // check count a node twice, and a repeated endpoint would send two rounds to one node (the
        // second fails with UnknownSession and the quorum is silently one short).
        let mut seen_ids = std::collections::HashSet::new();
        for p in &self.peers {
            if !seen_ids.insert(p.identifier) {
                return Err(Config(if p.identifier == self.identifier {
                    format!("this node's identifier {} is listed more than once in the peer roster", p.identifier)
                } else {
                    format!("peer identifier {} is listed more than once in the peer roster", p.identifier)
                }));
            }
        }
        let mut seen_endpoints = std::collections::HashSet::new();
        for p in &self.peers {
            // Compared loosely (case, trailing slash) so trivial respellings of one address count.
            let norm = p.endpoint.trim().trim_end_matches('/').to_ascii_lowercase();
            if !seen_endpoints.insert(norm) {
                return Err(Config(format!(
                    "peer endpoint {:?} (identifier {}) is listed more than once in the peer roster",
                    p.endpoint, p.identifier
                )));
            }
        }
        if self.threshold < 1 || self.threshold > self.max_signers() {
            return Err(Config(format!(
                "threshold {} out of range 1..={}",
                self.threshold,
                self.max_signers()
            )));
        }
        if !self.peers.iter().any(|p| p.identifier == self.identifier) {
            return Err(Config(format!(
                "this node's identifier {} is not in the peer roster",
                self.identifier
            )));
        }
        // With TLS enabled the Signer API is reachable by any cluster-CA-signed client, so a
        // signer_allowlist (the driver cert CN) is mandatory — otherwise a cosigner cert could
        // request arbitrary signatures. Plaintext (dev) may omit it.
        if self.tls.is_some()
            && self.signer_allowlist.as_ref().map(|a| a.is_empty()).unwrap_or(true)
        {
            return Err(Config(
                "signer_allowlist must be set (non-empty) when tls is enabled — list the driver \
                 cert CN(s) permitted to call the Signer API"
                    .into(),
            ));
        }
        // The Peer (mesh) API is the raw FROST protocol with no Canton-digest guard; without an
        // allowlist any cluster-CA cert (including the driver's) could drive it directly and forge
        // a namespace signature over an arbitrary message. Require the cosigner CN allowlist under
        // TLS. Plaintext (dev) may omit it.
        if self.tls.is_some()
            && self.peer_allowlist.as_ref().map(|a| a.is_empty()).unwrap_or(true)
        {
            return Err(Config(
                "peer_allowlist must be set (non-empty) when tls is enabled — list the cosigner \
                 cert CNs permitted to call the mesh Peer API (typically every cosigner)"
                    .into(),
            ));
        }
        // Mesh identities: one server name and one client CN per node. Two peers sharing either
        // would make them interchangeable on the wire — the hole per-peer names close (M3).
        let mut names = std::collections::HashSet::new();
        let mut cns = std::collections::HashSet::new();
        for p in &self.peers {
            if !names.insert(p.server_name()) {
                return Err(Config(format!(
                    "tls_server_name {:?} (peer {}) is used by more than one peer",
                    p.server_name(),
                    p.identifier
                )));
            }
            if !cns.insert(p.client_cn()) {
                return Err(Config(format!(
                    "tls_client_cn {:?} (peer {}) is used by more than one peer",
                    p.client_cn(),
                    p.identifier
                )));
            }
        }
        // The mesh allowlist is exactly the roster's client CNs: a CN on it that names no roster
        // node could drive the raw FROST rounds as nobody in particular, and a roster node missing
        // from it could not take part.
        if self.tls.is_some() {
            if let Some(allow) = &self.peer_allowlist {
                let allow: std::collections::HashSet<&String> = allow.iter().collect();
                let roster: std::collections::HashSet<&String> = cns.iter().collect();
                if allow != roster {
                    let mut extra: Vec<_> = allow.difference(&roster).collect();
                    let mut missing: Vec<_> = roster.difference(&allow).collect();
                    extra.sort();
                    missing.sort();
                    return Err(Config(format!(
                        "peer_allowlist must list exactly the roster's client CNs (cosigner<id> \
                         unless a peer sets tls_client_cn): not in the roster {extra:?}, roster \
                         nodes missing {missing:?}"
                    )));
                }
            }
        }
        // The Signer API and the mesh Peer API are separate roles: a CN in both would put a
        // cosigner cert on the Signer API (or the driver on the raw FROST rounds).
        if let (Some(signers), Some(peers)) = (&self.signer_allowlist, &self.peer_allowlist) {
            if let Some(cn) = signers.iter().find(|cn| peers.contains(cn)) {
                return Err(Config(format!(
                    "CN {cn:?} is in both signer_allowlist and peer_allowlist — a cosigner identity \
                     must not also be a Signer API client (and the driver must not be a mesh peer)"
                )));
            }
        }
        // The operator role exists to be weaker than the driver role; a CN in two role lists
        // would quietly be the stronger one (and a cosigner CN would put a mesh cert on the
        // Signer API).
        if let Some(ops) = &self.operator_allowlist {
            if ops.is_empty() {
                return Err(Config(
                    "operator_allowlist is empty — omit it, or list the operator cert CN(s)".into(),
                ));
            }
            let other: Vec<&String> = self
                .signer_allowlist
                .iter()
                .chain(self.peer_allowlist.iter())
                .flatten()
                .collect();
            if let Some(cn) = ops.iter().find(|cn| other.contains(cn)) {
                return Err(Config(format!(
                    "operator_allowlist CN {cn:?} is also in signer_allowlist or peer_allowlist — \
                     give the operator its own certificate"
                )));
            }
        }
        // The refresher role cannot sign; it may coincide with the operator role (which cannot
        // either) but never with the signer or mesh role.
        if let Some(refresh) = &self.refresh_allowlist {
            if refresh.is_empty() {
                return Err(Config(
                    "refresh_allowlist is empty — omit it, or list the refresher cert CN(s)".into(),
                ));
            }
            let other: Vec<&String> =
                self.signer_allowlist.iter().chain(self.peer_allowlist.iter()).flatten().collect();
            if let Some(cn) = refresh.iter().find(|cn| other.contains(cn)) {
                return Err(Config(format!(
                    "refresh_allowlist CN {cn:?} is also in signer_allowlist or peer_allowlist — the \
                     refresher must be a certificate that cannot sign (its own, or the operator's)"
                )));
            }
        }
        let signers: Vec<String> = self.signer_allowlist.clone().unwrap_or_default();
        self.signing_policy.validate(&signers, self.tls.is_some())?;
        if let Some(seal) = &self.share_seal {
            if seal.secret_env.is_some() == seal.secret_file.is_some() {
                return Err(Config(
                    "share_seal needs exactly one of secret_file (a per-node seal bundle) or \
                     secret_env (the legacy shared master)"
                        .into(),
                ));
            }
        }
        // Pinned distribution keys: well-formed, and one per node (two nodes with one key would
        // let either open the other's envelopes).
        let mut seen_keys = std::collections::HashSet::new();
        for p in &self.peers {
            if let Some(k) = p.dist_public_key_bytes()? {
                if !seen_keys.insert(k) {
                    return Err(Config(format!(
                        "peer {} has the same dist_public_key as another peer",
                        p.identifier
                    )));
                }
            }
        }
        let hosted_on = self.hosted_keys.as_ref().map(|h| h.enabled).unwrap_or(false);
        if let Some(h) = &self.hosted_keys {
            h.commitment_key_bytes()?;
        }
        let on_bundle = self.share_seal.as_ref().is_some_and(|s| s.secret_file.is_some());
        if hosted_on && on_bundle {
            if let Some(p) = self.peers.iter().find(|p| p.dist_public_key.is_none()) {
                return Err(Config(format!(
                    "peer {} has no dist_public_key — with share_seal.secret_file and hosted keys \
                     on, every peer's distribution key must be pinned (rutli-cosigner seal \
                     split-legacy / seal inspect print them)",
                    p.identifier
                )));
            }
            if self.hosted_keys.as_ref().and_then(|h| h.commitment_key.as_ref()).is_none() {
                return Err(Config(
                    "hosted_keys.commitment_key is required with share_seal.secret_file".into(),
                ));
            }
        }
        // Hosted keys are whole private keys at rest on every node. Refusing to hold them
        // unsealed is the whole point of the feature — an unsealed replica would be strictly worse
        // than the HSM delegate it replaces.
        if hosted_on {
            if self.share_seal.is_none() {
                return Err(Config(
                    "hosted_keys.enabled requires share_seal — cluster-hosted private keys are \
                     never stored unsealed"
                        .into(),
                ));
            }
            let q = self.hosted_keys.as_ref().map(|h| h.write_quorum).unwrap_or(2);
            if q < 1 || q > self.max_signers() as usize {
                return Err(Config(format!(
                    "hosted_keys.write_quorum {q} out of range 1..={}",
                    self.max_signers()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(tls: Option<TlsConfig>, allow: Option<Vec<String>>) -> Config {
        Config {
            identifier: 1,
            listen: "127.0.0.1:9101".into(),
            threshold: 2,
            data_dir: "/tmp/x".into(),
            peers: vec![
                PeerConfig::new(1, "https://a:9101"),
                PeerConfig::new(2, "https://b:9101"),
                PeerConfig::new(3, "https://c:9101"),
            ],
            tls,
            share_seal: None,
            signer_allowlist: allow.clone(),
            hosted_keys: None,
            peer_allowlist: allow,
            metrics_listen: None,
            operator_allowlist: None,
            refresh_allowlist: None,
            ceremony_sign_test_rate_limit_per_min: DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN,
            cluster_id: None,
            cluster_id_change_allowed: false,
            signing_policy: Default::default(),
        }
    }

    fn tls() -> TlsConfig {
        TlsConfig {
            ca_cert: "/ca".into(),
            allow_expired_ca: false,
            cert: "/cert".into(),
            key: "/key".into(),
            domain: Some("rutli-cosigner".into()),
        }
    }

    #[test]
    fn tls_without_allowlist_is_rejected() {
        assert!(base(Some(tls()), None).validate().is_err());
        assert!(base(Some(tls()), Some(vec![])).validate().is_err());
    }

    #[test]
    fn tls_with_allowlist_is_ok() {
        let mut c = base(Some(tls()), Some(vec!["driver".into()]));
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);
        c.validate().unwrap();
    }

    #[test]
    fn plaintext_without_allowlist_is_ok() {
        base(None, None).validate().unwrap();
    }

    #[test]
    fn tls_requires_peer_allowlist_too() {
        // signer_allowlist present but peer_allowlist missing/empty is rejected under TLS.
        let mut c = base(Some(tls()), Some(vec!["driver".into()]));
        c.peer_allowlist = None;
        assert!(c.validate().is_err(), "missing peer_allowlist under TLS must fail");
        c.peer_allowlist = Some(vec![]);
        assert!(c.validate().is_err(), "empty peer_allowlist under TLS must fail");
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);
        c.validate().unwrap();
    }

    fn mesh_ok() -> Config {
        let mut c = base(Some(tls()), Some(vec!["driver".into()]));
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);
        c
    }

    #[test]
    fn each_peer_is_dialled_and_identified_by_its_own_name() {
        let c = mesh_ok();
        c.validate().unwrap();
        assert_eq!(c.peers[1].server_name(), "cosigner2");
        assert_eq!(c.peers[1].client_cn(), "cosigner2");
        assert_eq!(c.peer_identities().get("cosigner3"), Some(&3));
        assert_eq!(c.peer_identities().get("cosigner03"), None, "exact match only");
        // The legacy tls.domain is not a mesh name.
        assert_ne!(c.peers[0].server_name(), "rutli-cosigner");
    }

    /// Audit C2: the refresher role cannot sign, so it may share the operator's CN but never the
    /// signer's or a cosigner's.
    #[test]
    fn the_refresher_role_may_be_the_operator_but_never_a_signer_or_a_peer() {
        let mut c = mesh_ok();
        c.operator_allowlist = Some(vec!["operator".into()]);
        c.refresh_allowlist = Some(vec!["operator".into()]);
        c.validate().unwrap();
        c.refresh_allowlist = Some(vec!["driver".into()]);
        assert!(c.validate().unwrap_err().to_string().contains("refresh_allowlist"));
        c.refresh_allowlist = Some(vec!["cosigner2".into()]);
        assert!(c.validate().unwrap_err().to_string().contains("refresh_allowlist"));
        c.refresh_allowlist = Some(vec![]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn the_signing_policy_is_validated() {
        use super::{ApprovalRuleConfig, ApproverConfig};
        // Defaults: lenient switches, the documented limits.
        let d = SigningPolicyConfig::default();
        assert!(!d.require_intent && !d.signer_acl_required && d.signer_may_refresh);
        assert_eq!((d.sign_rate_limit_per_min, d.sign_rate_limit_per_day), (300, 20_000));
        let parsed: SigningPolicyConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.max_shares_per_request, d.max_shares_per_request);
        assert!(parsed.signer_may_refresh, "absent = on, like Default");

        // require_intent needs TLS.
        let mut plain = base(None, None);
        plain.signing_policy.require_intent = true;
        assert!(plain.validate().unwrap_err().to_string().contains("require_intent"));

        let mut c = mesh_ok();
        c.signing_policy.signer_acl.insert("nobody".into(), vec!["".into()]);
        assert!(c.validate().unwrap_err().to_string().contains("not in signer_allowlist"));
        let mut c = mesh_ok();
        c.signing_policy.signer_acl_required = true;
        assert!(c.validate().unwrap_err().to_string().contains("no signer_acl"));
        c.signing_policy.signer_acl.insert("driver".into(), vec!["participant1-".into()]);
        c.validate().unwrap();

        let mut c = mesh_ok();
        c.signing_policy.signer_pins.insert("driver".into(), vec!["zz".into()]);
        assert!(c.validate().is_err());

        let key = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
        let mut c = mesh_ok();
        c.signing_policy.approvers = vec![ApproverConfig { id: "alice".into(), public_key_spki_b64: key.into() }];
        c.signing_policy.rules =
            vec![ApprovalRuleConfig { key_id_prefix: "p1-".into(), mode: "quorum".into(), threshold: 2 }];
        assert!(c.validate().unwrap_err().to_string().contains("threshold"));
        c.signing_policy.rules[0].threshold = 1;
        c.validate().unwrap();
        assert_eq!(c.signing_policy.approval_threshold_for("p1-namespace"), Some(1));
        assert_eq!(c.signing_policy.approval_threshold_for("p2-namespace"), None);
        c.signing_policy.approvers[0].public_key_spki_b64 = "not a key".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn mesh_names_must_be_unique() {
        let mut c = mesh_ok();
        c.peers[2].tls_server_name = Some("cosigner2".into());
        assert!(c.validate().unwrap_err().to_string().contains("tls_server_name"));
        let mut c = mesh_ok();
        c.peers[0].tls_server_name = Some("rutli-cosigner".into());
        c.peers[1].tls_server_name = Some("rutli-cosigner".into());
        assert!(c.validate().is_err(), "one shared name for two peers is exactly M3");
        let mut c = mesh_ok();
        c.peers[2].tls_client_cn = Some("cosigner2".into());
        assert!(c.validate().unwrap_err().to_string().contains("tls_client_cn"));
    }

    #[test]
    fn the_peer_allowlist_is_exactly_the_roster() {
        let mut c = mesh_ok();
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into()]);
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("missing") && e.contains("cosigner3"), "{e}");
        c.peer_allowlist =
            Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into(), "cosigner4".into()]);
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("cosigner4"), "{e}");
        // A custom client CN must be what the allowlist names.
        let mut c = mesh_ok();
        c.peers[2].tls_client_cn = Some("node-c.example".into());
        assert!(c.validate().is_err());
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "node-c.example".into()]);
        c.validate().unwrap();
    }

    #[test]
    fn a_pinned_cluster_id_overrides_the_ca_derived_one() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, b"-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n").unwrap();
        let mut c = base(Some(TlsConfig { ca_cert: ca.clone(), ..tls() }), Some(vec!["driver".into()]));
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);

        // Unset: derived from the CA file's bytes, as before.
        let derived = crate::wrap::cluster_id_from_ca(&std::fs::read(&ca).unwrap());
        assert_eq!(c.cluster_id().unwrap(), derived);
        assert_eq!(c.derived_cluster_id().unwrap(), derived);

        // Pinned to the derived value, then the CA file becomes a rotation bundle: the id holds.
        c.cluster_id = Some(derived.clone());
        c.validate().unwrap();
        let mut bundle = std::fs::read(&ca).unwrap();
        bundle.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n");
        std::fs::write(&ca, &bundle).unwrap();
        assert_eq!(c.cluster_id().unwrap(), derived);
        assert_ne!(c.derived_cluster_id().unwrap(), derived, "the file changed, the pin did not");

        // Without TLS, a pin wins over plaintext-dev too.
        let mut p = base(None, None);
        assert_eq!(p.cluster_id().unwrap(), "plaintext-dev");
        p.cluster_id = Some("453bb4aea2088bb5".into());
        assert_eq!(p.cluster_id().unwrap(), "453bb4aea2088bb5");
    }

    #[test]
    fn a_malformed_cluster_id_pin_is_rejected() {
        let mut c = base(Some(tls()), Some(vec!["driver".into()]));
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);
        c.cluster_id = Some("453bb4aea2088bb5".into());
        c.validate().unwrap();
        for bad in ["453BB4AEA2088BB5", "453bb4aea2088bb", "453bb4aea2088bb5a", "453bb4aea2088bbz", ""] {
            c.cluster_id = Some(bad.into());
            let e = c.validate().unwrap_err().to_string();
            assert!(e.contains("cluster_id") && e.contains("shasum -a 256 ca.crt | cut -c1-16"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn cluster_id_is_optional_in_json_and_omitted_when_unset() {
        let json = r#"{"identifier":1,"listen":"127.0.0.1:9101","threshold":1,"data_dir":"/tmp/x",
                       "peers":[{"identifier":1,"endpoint":"http://a:9101"}]}"#;
        let c: Config = serde_json::from_str(json).unwrap();
        assert_eq!(c.cluster_id, None);
        assert!(!serde_json::to_string(&c).unwrap().contains("cluster_id"));
        let pinned: Config =
            serde_json::from_str(&json.replacen('{', r#"{"cluster_id":"453bb4aea2088bb5","#, 1)).unwrap();
        assert_eq!(pinned.cluster_id().unwrap(), "453bb4aea2088bb5");
    }

    #[test]
    fn duplicate_peer_identifiers_are_rejected() {
        let mut c = base(None, None);
        c.peers[2].identifier = 2;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("peer identifier 2") && e.contains("more than once"), "{e}");
    }

    #[test]
    fn this_node_listed_twice_is_rejected() {
        let mut c = base(None, None);
        c.peers.push(PeerConfig::new(1, "https://a2:9101"));
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("this node's identifier 1"), "{e}");
    }

    #[test]
    fn duplicate_peer_endpoints_are_rejected() {
        let mut c = base(None, None);
        c.peers[2].endpoint = "https://b:9101".into();
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("endpoint") && e.contains("more than once"), "{e}");
        // Trivial respellings of one address count as the same endpoint.
        c.peers[2].endpoint = "HTTPS://B:9101/".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn signer_and_peer_allowlists_must_not_overlap() {
        let mut c = base(Some(tls()), Some(vec!["driver".into()]));
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);
        c.validate().unwrap();
        c.signer_allowlist = Some(vec!["driver".into(), "cosigner2".into()]);
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("cosigner2") && e.contains("signer_allowlist") && e.contains("peer_allowlist"), "{e}");
        c.signer_allowlist = Some(vec!["driver".into()]);
        c.peer_allowlist = Some(vec!["driver".into(), "cosigner1".into()]);
        assert!(c.validate().is_err(), "the driver must not be a mesh peer either");
    }

    #[test]
    fn the_operator_role_must_be_its_own_identity() {
        let mut c = base(Some(tls()), Some(vec!["driver".into()]));
        c.peer_allowlist = Some(vec!["cosigner1".into(), "cosigner2".into(), "cosigner3".into()]);
        c.operator_allowlist = Some(vec!["operator".into()]);
        c.validate().unwrap();
        for bad in [vec![], vec!["driver".to_string()], vec!["operator".into(), "cosigner2".into()]] {
            c.operator_allowlist = Some(bad.clone());
            assert!(c.validate().is_err(), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod hosted_config_tests {
    use super::*;

    fn cfg(hosted: Option<HostedKeysConfig>, seal: bool) -> Config {
        Config {
            identifier: 1,
            listen: "127.0.0.1:9101".into(),
            threshold: 2,
            data_dir: "/tmp/x".into(),
            peers: vec![
                PeerConfig::new(1, "http://a:9101"),
                PeerConfig::new(2, "http://b:9101"),
                PeerConfig::new(3, "http://c:9101"),
            ],
            tls: None,
            share_seal: seal.then(|| ShareSealConfig {
                secret_env: Some("RUTLI_SEAL_SECRET".into()),
                secret_file: None,
            }),
            signer_allowlist: None,
            peer_allowlist: None,
            metrics_listen: None,
            operator_allowlist: None,
            refresh_allowlist: None,
            ceremony_sign_test_rate_limit_per_min: DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN,
            hosted_keys: hosted,
            cluster_id: None,
            cluster_id_change_allowed: false,
            signing_policy: Default::default(),
        }
    }

    fn hosted(enabled: bool, quorum: usize) -> HostedKeysConfig {
        HostedKeysConfig {
            enabled,
            write_quorum: quorum,
            anti_entropy_interval_secs: 300,
            decrypt_rate_limit_per_min: DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN,
            commitment_key: None,
        }
    }

    #[test]
    fn hosted_keys_require_sealing() {
        // A hosted key is a whole private key; storing one unsealed would be strictly worse than
        // the HSM delegate it replaces.
        assert!(cfg(Some(hosted(true, 2)), false).validate().is_err());
        cfg(Some(hosted(true, 2)), true).validate().unwrap();
        // Disabled hosted keys don't force sealing on a dev cluster.
        cfg(Some(hosted(false, 2)), false).validate().unwrap();
    }

    #[test]
    fn write_quorum_must_be_reachable() {
        assert!(cfg(Some(hosted(true, 0)), true).validate().is_err(), "quorum 0 is meaningless");
        assert!(cfg(Some(hosted(true, 4)), true).validate().is_err(), "quorum > cluster size");
        cfg(Some(hosted(true, 3)), true).validate().unwrap();
    }

    #[test]
    fn the_decrypt_rate_limit_defaults_on_and_can_be_disabled() {
        // Secure by default: an operator who writes only `enabled: true` still gets a ceiling.
        let c = cfg(Some(hosted(true, 2)), true);
        assert_eq!(
            c.hosted_keys.as_ref().unwrap().decrypt_rate_limit_per_min,
            DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN
        );

        // 0 is a valid explicit opt-out, not a validation error — some operators will have their
        // own throttle in front.
        let mut off = hosted(true, 2);
        off.decrypt_rate_limit_per_min = 0;
        cfg(Some(off), true).validate().unwrap();
    }

    const K1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const K2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const K3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn on_bundle(mut c: Config) -> Config {
        c.share_seal = Some(ShareSealConfig { secret_env: None, secret_file: Some("/run/rutli/seal/node.json".into()) });
        c
    }

    #[test]
    fn share_seal_takes_exactly_one_source() {
        let mut c = cfg(None, true);
        c.validate().unwrap();
        c.share_seal = Some(ShareSealConfig::default());
        assert!(c.validate().unwrap_err().to_string().contains("exactly one"));
        c.share_seal = Some(ShareSealConfig {
            secret_env: Some("S".into()),
            secret_file: Some("/f".into()),
        });
        assert!(c.validate().is_err(), "both sources at once is ambiguous");
        on_bundle(cfg(None, false)).validate().unwrap();
    }

    #[test]
    fn a_legacy_secret_env_config_still_parses() {
        // The soak's rendered ConfigMap: must keep loading unchanged until it migrates.
        let c: Config = serde_json::from_str(
            r#"{"identifier":1,"listen":"127.0.0.1:9101","threshold":2,"data_dir":"/tmp/x",
                "peers":[{"identifier":1,"endpoint":"http://a:9101"},
                         {"identifier":2,"endpoint":"http://b:9101"}],
                "share_seal":{"secret_env":"RUTLI_SEAL_SECRET"},
                "hosted_keys":{"enabled":true}}"#,
        )
        .unwrap();
        assert_eq!(c.share_seal.as_ref().unwrap().secret_env.as_deref(), Some("RUTLI_SEAL_SECRET"));
        c.validate().unwrap();
    }

    #[test]
    fn a_bundle_with_hosted_keys_needs_every_pin_and_the_commitment_key() {
        let mut c = on_bundle(cfg(Some(hosted(true, 2)), false));
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("dist_public_key"), "{e}");
        for (p, k) in c.peers.iter_mut().zip([K1, K2, K3]) {
            p.dist_public_key = Some(k.into());
        }
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("commitment_key"), "{e}");
        c.hosted_keys.as_mut().unwrap().commitment_key = Some(K1.into());
        c.validate().unwrap();
        // The legacy master derives them, so it needs neither.
        cfg(Some(hosted(true, 2)), true).validate().unwrap();
    }

    #[test]
    fn pins_must_be_well_formed_and_distinct() {
        let mut c = cfg(Some(hosted(true, 2)), true);
        c.peers[0].dist_public_key = Some("abcd".into());
        assert!(c.validate().is_err(), "short key");
        c.peers[0].dist_public_key = Some(K1.into());
        c.peers[1].dist_public_key = Some(K1.into());
        assert!(c.validate().unwrap_err().to_string().contains("same dist_public_key"));
        c.peers[1].dist_public_key = Some(K2.into());
        c.validate().unwrap();
        c.hosted_keys.as_mut().unwrap().commitment_key = Some("zz".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn defaults_are_applied_when_the_block_is_partial() {
        let c: Config = serde_json::from_str(
            r#"{"identifier":1,"listen":"127.0.0.1:9101","threshold":2,"data_dir":"/tmp/x",
                "peers":[{"identifier":1,"endpoint":"http://a:9101"},
                         {"identifier":2,"endpoint":"http://b:9101"}],
                "share_seal":{"secret_env":"S"},
                "hosted_keys":{"enabled":true}}"#,
        )
        .unwrap();
        let h = c.hosted_keys.as_ref().unwrap();
        assert_eq!(h.write_quorum, 2, "quorum defaults to the cluster fault model, not all-nodes");
        assert_eq!(h.anti_entropy_interval_secs, 300);
        assert_eq!(h.decrypt_rate_limit_per_min, DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN);
        c.validate().unwrap();
    }
}

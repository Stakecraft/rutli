// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
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
    #[serde(default = "default_decrypt_rate_limit")]
    pub decrypt_rate_limit_per_min: u32,
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

/// Where the share-sealing master secret comes from. The secret must be injected at runtime (secret
/// manager, systemd credential, enclave bootstrap) — never stored in this config file or on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSealConfig {
    /// Name of the environment variable holding the master secret (e.g. `openssl rand -hex 32`).
    pub secret_env: String,
}

/// Mutual-TLS material for the cosigner mesh (and the driver→cluster hop). All peers and the driver
/// present certs signed by the same cluster CA; the CA cert is the single trust anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// PEM CA certificate that must sign every peer/client certificate (the trust anchor).
    pub ca_cert: PathBuf,
    /// PEM certificate this node presents (as server, and as client to peers).
    pub cert: PathBuf,
    /// PEM private key for `cert`.
    pub key: PathBuf,
    /// Expected TLS server-name (SNI/SAN) when dialing peers. Peer endpoints use `https://`.
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub identifier: u16,
    /// gRPC endpoint of the peer (e.g. http://host:port). Ignored for this node itself.
    pub endpoint: String,
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

    /// The cluster identity the CA file implies: [`crate::wrap::cluster_id_from_ca`] of the
    /// `tls.ca_cert` bytes, or `plaintext-dev` without TLS. Reads the CA file. Ignores the pin.
    pub fn derived_cluster_id(&self) -> crate::Result<String> {
        Ok(match &self.tls {
            Some(t) => crate::wrap::cluster_id_from_ca(&std::fs::read(&t.ca_cert)?),
            None => "plaintext-dev".to_string(),
        })
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
        // Hosted keys are whole private keys at rest on every node. Refusing to hold them
        // unsealed is the whole point of the feature — an unsealed replica would be strictly worse
        // than the HSM delegate it replaces.
        if self.hosted_keys.as_ref().map(|h| h.enabled).unwrap_or(false) {
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
                PeerConfig { identifier: 1, endpoint: "https://a:9101".into() },
                PeerConfig { identifier: 2, endpoint: "https://b:9101".into() },
                PeerConfig { identifier: 3, endpoint: "https://c:9101".into() },
            ],
            tls,
            share_seal: None,
            signer_allowlist: allow.clone(),
            hosted_keys: None,
            peer_allowlist: allow,
            metrics_listen: None,
            operator_allowlist: None,
            ceremony_sign_test_rate_limit_per_min: DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN,
            cluster_id: None,
        }
    }

    fn tls() -> TlsConfig {
        TlsConfig {
            ca_cert: "/ca".into(),
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
        base(Some(tls()), Some(vec!["driver".into()])).validate().unwrap();
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

    #[test]
    fn a_pinned_cluster_id_overrides_the_ca_derived_one() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, b"-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n").unwrap();
        let mut c = base(Some(TlsConfig { ca_cert: ca.clone(), ..tls() }), Some(vec!["driver".into()]));

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
                PeerConfig { identifier: 1, endpoint: "http://a:9101".into() },
                PeerConfig { identifier: 2, endpoint: "http://b:9101".into() },
                PeerConfig { identifier: 3, endpoint: "http://c:9101".into() },
            ],
            tls: None,
            share_seal: seal.then(|| ShareSealConfig { secret_env: "RUTLI_SEAL_SECRET".into() }),
            signer_allowlist: None,
            peer_allowlist: None,
            metrics_listen: None,
            operator_allowlist: None,
            ceremony_sign_test_rate_limit_per_min: DEFAULT_CEREMONY_SIGN_TEST_RATE_LIMIT_PER_MIN,
            hosted_keys: hosted,
            cluster_id: None,
        }
    }

    fn hosted(enabled: bool, quorum: usize) -> HostedKeysConfig {
        HostedKeysConfig {
            enabled,
            write_quorum: quorum,
            anti_entropy_interval_secs: 300,
            decrypt_rate_limit_per_min: DEFAULT_DECRYPT_RATE_LIMIT_PER_MIN,
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

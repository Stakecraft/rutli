// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Share sealing: encryption-at-rest for this node's key shares.
//!
//! A [`Sealer`] wraps share bytes in AES-256-GCM under this node's data-encryption key (DEK). The
//! DEK comes from one of two places (`share_seal` in the config, see [`SealKeys`]):
//!
//! - **Node seal bundle** (`secret_file`, preferred): a small JSON file holding *this node's* DEK and
//!   hosted-key distribution seed and nothing else ([`NodeSealBundle`]), mounted as a file from a
//!   per-node secret. Compromising one node's secret yields one node's keys.
//! - **Legacy shared master** (`secret_env`, deprecated): one operator master secret in an env var,
//!   from which each node derives its DEK via HKDF-SHA256 with a salt bound to its identifier. Every
//!   node, and anything that can read that one secret, can derive every node's DEK — which is why
//!   a Kubernetes deployment must not use it (audit C3). `seal split-legacy` turns a master into
//!   per-node bundles with the *same* derivations, so existing sealed files open unchanged.
//!
//! Threat model: this closes the *at-rest* exposure — a copied disk, snapshot, or stray backup of
//! `data_dir` no longer yields a usable key share. It does not protect share memory during signing;
//! that requires enclave/HSM sealing ("MPC-of-HSM"), for which this module is the software seam:
//! swap the [`Sealer`] implementation, keep the file format.
//!
//! File format (JSON): `{"v":1,"sealed":true,"nonce":<hex 12B>,"ct":<hex>}`. Legacy plaintext share
//! files are still readable when sealing is enabled, so an operator can turn sealing on and have
//! shares re-sealed on the next write (or via re-save), but new writes are always sealed.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::config::ShareSealConfig;
use crate::{DaemonError, Result};

const NONCE_LEN: usize = 12;

/// Minimum length of a legacy master secret (chars of the env var). `openssl rand -hex 32` gives 64.
const MIN_MASTER_LEN: usize = 32;

/// This node's share DEK under the legacy shared master.
///
/// The derivation every legacy cluster's sealed files are keyed by, so it must never change:
/// `seal split-legacy` copies its output into the node's bundle.
pub fn derive_share_dek(master: &[u8], node_identifier: u16) -> Zeroizing<[u8; 32]> {
    let salt = format!("rutli-share-seal/node-{node_identifier}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"share-dek-v1", key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Read a legacy master secret from `env_var`, exactly as the daemon always has: the env string's
/// UTF-8 bytes, at least [`MIN_MASTER_LEN`] chars.
pub fn read_master_env(env_var: &str) -> Result<Zeroizing<String>> {
    let master = Zeroizing::new(std::env::var(env_var).map_err(|_| {
        DaemonError::Config(format!("share sealing enabled but env var {env_var} is not set"))
    })?);
    // Prefer ≥ 32 bytes of entropy (`openssl rand -hex 32` → 64 hex chars). Reject short
    // operator secrets so a typo / weak password cannot silently become the cluster DEK root.
    if master.len() < MIN_MASTER_LEN {
        return Err(DaemonError::Config(format!(
            "share-seal secret in {env_var} is too short ({} chars); use at least {MIN_MASTER_LEN}, e.g. `openssl rand -hex 32`",
            master.len()
        )));
    }
    Ok(master)
}

/// Sealed-share envelope as stored on disk.
#[derive(Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub v: u8,
    pub sealed: bool,
    pub nonce: String,
    pub ct: String,
}

pub struct Sealer {
    key: Zeroizing<[u8; 32]>,
    /// Retired DEKs that may still open files (never used to seal). Empty unless a bundle lists
    /// `previous_share_deks` during a DEK rotation.
    previous: Vec<Zeroizing<[u8; 32]>>,
}

impl Sealer {
    /// Derive this node's data-encryption key from the master secret and the node identifier.
    /// The identifier salt makes per-node keys distinct under one master secret.
    pub fn from_master_secret(master: &[u8], node_identifier: u16) -> Self {
        Self::from_dek(derive_share_dek(master, node_identifier))
    }

    /// A sealer over an explicit 32-byte DEK (a node seal bundle's `share_dek`).
    pub fn from_dek(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key, previous: Vec::new() }
    }

    /// Read the master secret from `env_var` (utf-8; recommended ≥ 32 bytes of entropy, e.g.
    /// `openssl rand -hex 32`).
    pub fn from_env(env_var: &str, node_identifier: u16) -> Result<Self> {
        let master = read_master_env(env_var)?;
        Ok(Self::from_master_secret(master.as_bytes(), node_identifier))
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_ref()));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| DaemonError::Config("share sealing failed".into()))?;
        let envelope = SealedEnvelope {
            v: 1,
            sealed: true,
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
        };
        Ok(serde_json::to_vec_pretty(&envelope)?)
    }

    pub fn unseal(&self, file_bytes: &[u8]) -> Result<Vec<u8>> {
        let envelope: SealedEnvelope = serde_json::from_slice(file_bytes)
            .map_err(|e| DaemonError::Config(format!("not a sealed share envelope: {e}")))?;
        if envelope.v != 1 || !envelope.sealed {
            return Err(DaemonError::Config(format!(
                "unsupported sealed envelope (v={}, sealed={})",
                envelope.v, envelope.sealed
            )));
        }
        let nonce_bytes = hex::decode(&envelope.nonce)
            .map_err(|e| DaemonError::Config(format!("bad nonce hex: {e}")))?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(DaemonError::Config("bad nonce length".into()));
        }
        let ct = hex::decode(&envelope.ct)
            .map_err(|e| DaemonError::Config(format!("bad ciphertext hex: {e}")))?;
        // The current DEK first; a retired one only while a rotation is in progress.
        for key in std::iter::once(&self.key).chain(self.previous.iter()) {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
            if let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce_bytes), ct.as_slice()) {
                return Ok(plain);
            }
        }
        Err(DaemonError::Config(
            "share unseal failed — wrong seal secret or corrupted/tampered share file".into(),
        ))
    }

    /// Whether `file_bytes` look like a sealed envelope (vs. a legacy plaintext share).
    pub fn is_sealed(file_bytes: &[u8]) -> bool {
        serde_json::from_slice::<SealedEnvelope>(file_bytes)
            .map(|e| e.sealed)
            .unwrap_or(false)
    }
}

// ── node seal bundle ───────────────────────────────────────────────────────────────────────────

/// `kind` of a node seal bundle file.
pub const BUNDLE_KIND: &str = "rutli-node-seal";

/// One node's seal keys, and nothing of any other node's: what `share_seal.secret_file` points at.
///
/// ```json
/// {"v":1,"kind":"rutli-node-seal","node":2,"share_dek":"<64 hex>","dist_seed":"<64 hex>",
///  "previous_share_deks":[]}
/// ```
///
/// `share_dek` keys this node's sealed key files; `dist_seed` is the X25519 seed of its hosted-key
/// distribution key ([`crate::wrap::DistKey::from_seed`]). Made offline by `rutli-cosigner seal
/// split-legacy` (from a legacy master, with the current derivations, so nothing is re-sealed) or
/// `seal new-node` (random keys, for a fresh install). `node` must equal the config's identifier,
/// which catches a bundle mounted into the wrong node.
pub struct NodeSealBundle {
    pub node: u16,
    share_dek: Zeroizing<[u8; 32]>,
    dist_seed: Zeroizing<[u8; 32]>,
    previous_share_deks: Vec<Zeroizing<[u8; 32]>>,
}

/// The on-disk shape. Strict: an unknown field is refused rather than ignored, so a bundle written
/// by a newer release is never half-understood.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    v: u8,
    kind: String,
    node: u16,
    share_dek: String,
    dist_seed: String,
    #[serde(default)]
    previous_share_deks: Vec<String>,
}

impl Drop for BundleFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.share_dek.zeroize();
        self.dist_seed.zeroize();
        self.previous_share_deks.iter_mut().for_each(|k| k.zeroize());
    }
}

fn key32(field: &str, hex_str: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        hex::decode(hex_str.trim())
            .map_err(|_| DaemonError::Config(format!("seal bundle: {field} is not hex")))?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err(DaemonError::Config(format!(
            "seal bundle: {field} must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl NodeSealBundle {
    /// Node `node`'s bundle under a legacy shared master: the DEK and distribution seed the node
    /// already uses, so its sealed files and its peers' envelopes keep opening.
    pub fn from_legacy_master(master: &[u8], node: u16) -> Self {
        Self {
            node,
            share_dek: derive_share_dek(master, node),
            dist_seed: crate::wrap::derive_dist_seed(master, node),
            previous_share_deks: Vec::new(),
        }
    }

    /// A bundle of fresh random keys, for a node of a new cluster.
    pub fn random(node: u16) -> Self {
        use rand::RngCore;
        let (mut dek, mut seed) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
        rand::rngs::OsRng.fill_bytes(dek.as_mut());
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self { node, share_dek: dek, dist_seed: seed, previous_share_deks: Vec::new() }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let f: BundleFile = serde_json::from_slice(bytes)
            .map_err(|e| DaemonError::Config(format!("not a node seal bundle: {e}")))?;
        if f.v != 1 || f.kind != BUNDLE_KIND {
            return Err(DaemonError::Config(format!(
                "unsupported seal bundle (v={}, kind={:?}; this node reads v=1 {BUNDLE_KIND:?})",
                f.v, f.kind
            )));
        }
        let previous_share_deks = f
            .previous_share_deks
            .iter()
            .map(|k| key32("previous_share_deks[]", k))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            node: f.node,
            share_dek: key32("share_dek", &f.share_dek)?,
            dist_seed: key32("dist_seed", &f.dist_seed)?,
            previous_share_deks,
        })
    }

    /// The bundle as file bytes (pretty JSON). Holds secrets: write it owner-only.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let f = BundleFile {
            v: 1,
            kind: BUNDLE_KIND.to_string(),
            node: self.node,
            share_dek: hex::encode(*self.share_dek),
            dist_seed: hex::encode(*self.dist_seed),
            previous_share_deks: self.previous_share_deks.iter().map(|k| hex::encode(**k)).collect(),
        };
        let mut out = serde_json::to_vec_pretty(&f)?;
        out.push(b'\n');
        Ok(Zeroizing::new(out))
    }

    /// Read this node's bundle from `path`. Refuses a bundle for another node, and a file any
    /// user on the host may read (a Kubernetes Secret volume gives 0400/0440).
    ///
    /// The file is left in place: an init container does not re-run when the cosigner container
    /// restarts, so a consumed file would strand the node.
    pub fn read_file(path: &std::path::Path, expected_node: u16) -> Result<Self> {
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| {
            DaemonError::Config(format!("cannot read seal bundle {}: {e}", path.display()))
        })?);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o007 != 0 {
                return Err(DaemonError::Config(format!(
                    "seal bundle {} is accessible to every user on the host (mode {:o}); it holds \
                     this node's DEK — make it 0400 or 0440",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let bundle = Self::parse(&bytes)?;
        if bundle.node != expected_node {
            return Err(DaemonError::Config(format!(
                "seal bundle {} is for node {}, but this node is {expected_node} — wrong Secret \
                 mounted",
                path.display(),
                bundle.node
            )));
        }
        Ok(bundle)
    }

    pub fn sealer(&self) -> Sealer {
        Sealer {
            key: self.share_dek.clone(),
            previous: self.previous_share_deks.clone(),
        }
    }

    pub fn dist_key(&self) -> crate::wrap::DistKey {
        crate::wrap::DistKey::from_seed(&self.dist_seed, self.node)
    }

    /// The public half of this node's distribution key: what every peer pins as this node's
    /// `dist_public_key`.
    pub fn dist_public_key(&self) -> [u8; 32] {
        self.dist_key().public_bytes()
    }
}

// ── where this node's seal keys come from ──────────────────────────────────────────────────────

/// This node's seal keys as configured by `share_seal`, read once at startup (or by an offline
/// command). Drop it once the [`Sealer`] and the hosted-key keyring are built.
pub enum SealKeys {
    /// `secret_env`: the legacy shared cluster master. Deprecated (audit C3).
    LegacyMaster { env: String, master: Zeroizing<String> },
    /// `secret_file`: this node's own [`NodeSealBundle`].
    Bundle { path: std::path::PathBuf, bundle: NodeSealBundle },
}

impl SealKeys {
    pub fn load(cfg: &ShareSealConfig, node_identifier: u16) -> Result<Self> {
        match (&cfg.secret_env, &cfg.secret_file) {
            (Some(env), None) => {
                Ok(Self::LegacyMaster { env: env.clone(), master: read_master_env(env)? })
            }
            (None, Some(path)) => Ok(Self::Bundle {
                path: path.clone(),
                bundle: NodeSealBundle::read_file(path, node_identifier)?,
            }),
            _ => Err(DaemonError::Config(
                "share_seal needs exactly one of secret_file (a per-node seal bundle) or \
                 secret_env (the legacy shared master)"
                    .into(),
            )),
        }
    }

    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::LegacyMaster { .. })
    }

    /// Where the keys came from, for the startup log. Never the keys.
    pub fn describe(&self) -> String {
        match self {
            Self::LegacyMaster { env, .. } => format!("legacy shared master env={env}"),
            Self::Bundle { path, bundle } => {
                format!("bundle node={} file={}", bundle.node, path.display())
            }
        }
    }

    pub fn sealer(&self, node_identifier: u16) -> Sealer {
        match self {
            Self::LegacyMaster { master, .. } => {
                Sealer::from_master_secret(master.as_bytes(), node_identifier)
            }
            Self::Bundle { bundle, .. } => bundle.sealer(),
        }
    }

    /// The hosted-key keyring for the node `cfg` describes: its own distribution key, the
    /// cluster-wide commitment key, and the distribution public key of every roster node.
    ///
    /// On a bundle every peer's key and the commitment key are pinned in config (the node cannot
    /// derive them). On the legacy master they are derived as before; a pinned value, where
    /// present, must agree for this node and the commitment key (a mismatch is a pasted-wrong
    /// value or the wrong master), and a peer's pin wins over the derivation — that peer runs its
    /// own bundle.
    pub fn hosted_keyring(&self, cfg: &crate::config::Config) -> Result<crate::node::HostedKeyring> {
        use crate::wrap::DistKey;
        let me = cfg.identifier;
        let dist_key = match self {
            Self::LegacyMaster { master, .. } => DistKey::derive(master.as_bytes(), me),
            Self::Bundle { bundle, .. } => bundle.dist_key(),
        };
        let hosted = cfg.hosted_keys.as_ref();
        let configured_commitment =
            hosted.map(|h| h.commitment_key_bytes()).transpose()?.flatten();
        let commitment_key = match (self, configured_commitment) {
            (Self::LegacyMaster { master, .. }, configured) => {
                let derived = crate::wrap::legacy_commitment_key(master.as_bytes());
                if configured.is_some_and(|c| c != derived) {
                    return Err(DaemonError::Config(
                        "hosted_keys.commitment_key does not match the value derived from the \
                         legacy master in share_seal.secret_env — a wrong value was pasted, or \
                         this is the wrong master"
                            .into(),
                    ));
                }
                derived
            }
            (Self::Bundle { .. }, Some(c)) => c,
            (Self::Bundle { .. }, None) => {
                return Err(DaemonError::Config(
                    "hosted_keys.commitment_key is required with share_seal.secret_file (print it \
                     with `rutli-cosigner seal split-legacy`, or generate one for a new cluster)"
                        .into(),
                ))
            }
        };
        let mut peer_dist_keys = std::collections::BTreeMap::new();
        for p in &cfg.peers {
            let pinned = p.dist_public_key_bytes()?;
            let key = match (self, pinned) {
                _ if p.identifier == me => {
                    let own = dist_key.public_bytes();
                    if pinned.is_some_and(|k| k != own) {
                        return Err(DaemonError::Config(format!(
                            "peers[{me}].dist_public_key does not match this node's seal keys \
                             ({}) — the wrong seal bundle is mounted, or the pin is wrong",
                            hex::encode(own)
                        )));
                    }
                    own
                }
                (_, Some(k)) => k,
                (Self::LegacyMaster { master, .. }, None) => {
                    DistKey::derive(master.as_bytes(), p.identifier).public_bytes()
                }
                (Self::Bundle { .. }, None) => {
                    return Err(DaemonError::Config(format!(
                        "peer {} has no dist_public_key — required with share_seal.secret_file",
                        p.identifier
                    )))
                }
            };
            peer_dist_keys.insert(p.identifier, key);
        }
        Ok(crate::node::HostedKeyring { dist_key, commitment_key, peer_dist_keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let s = Sealer::from_master_secret(b"correct horse battery staple", 1);
        let sealed = s.seal(b"share bytes").unwrap();
        assert!(Sealer::is_sealed(&sealed));
        assert_eq!(s.unseal(&sealed).unwrap(), b"share bytes");
    }

    #[test]
    fn wrong_key_fails() {
        let a = Sealer::from_master_secret(b"secret-a", 1);
        let b = Sealer::from_master_secret(b"secret-b", 1);
        let sealed = a.seal(b"share bytes").unwrap();
        assert!(b.unseal(&sealed).is_err());
    }

    #[test]
    fn same_secret_different_node_gives_different_key() {
        let a = Sealer::from_master_secret(b"one master secret", 1);
        let b = Sealer::from_master_secret(b"one master secret", 2);
        let sealed = a.seal(b"share bytes").unwrap();
        assert!(b.unseal(&sealed).is_err(), "node-2 key must not open node-1 shares");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let s = Sealer::from_master_secret(b"correct horse battery staple", 1);
        let sealed = s.seal(b"share bytes").unwrap();
        let mut env: SealedEnvelope = serde_json::from_slice(&sealed).unwrap();
        let mut ct = hex::decode(&env.ct).unwrap();
        ct[0] ^= 0x01;
        env.ct = hex::encode(ct);
        let tampered = serde_json::to_vec(&env).unwrap();
        assert!(s.unseal(&tampered).is_err());
    }

    #[test]
    fn plaintext_is_not_sealed() {
        assert!(!Sealer::is_sealed(b"{\"key_package\": {}}"));
    }

    const MASTER: &[u8] = b"golden master secret for seal tests!";

    #[test]
    fn the_legacy_share_dek_derivation_is_unchanged_golden() {
        // Every legacy cluster's sealed files are keyed by this; split-legacy copies it.
        assert_eq!(
            hex::encode(*derive_share_dek(MASTER, 1)),
            "75d3067f8a3cdb7e7f9a20e5382a9bc2078b2d98116c027a0cc337a74db3a1ce"
        );
    }

    #[test]
    fn a_file_sealed_under_the_legacy_master_opens_under_the_split_bundle_and_back() {
        for node in [1u16, 2, 3] {
            let legacy = Sealer::from_master_secret(MASTER, node);
            let bundle = NodeSealBundle::parse(&NodeSealBundle::from_legacy_master(MASTER, node).to_json().unwrap())
                .unwrap();
            assert_eq!(bundle.node, node);
            let sealed = legacy.seal(b"share bytes").unwrap();
            assert_eq!(bundle.sealer().unseal(&sealed).unwrap(), b"share bytes");
            // ...and a file the bundle node writes still opens under the master (rollback).
            let resealed = bundle.sealer().seal(b"refreshed share").unwrap();
            assert_eq!(legacy.unseal(&resealed).unwrap(), b"refreshed share");
            // The bundle's distribution key is the one peers already derive for this node.
            assert_eq!(
                bundle.dist_public_key(),
                crate::wrap::DistKey::derive(MASTER, node).public_bytes()
            );
        }
        // One node's bundle opens nothing of another's.
        let b2 = NodeSealBundle::from_legacy_master(MASTER, 2);
        let sealed1 = Sealer::from_master_secret(MASTER, 1).seal(b"x").unwrap();
        assert!(b2.sealer().unseal(&sealed1).is_err());
    }

    #[test]
    fn a_random_bundle_round_trips_and_is_unique() {
        let a = NodeSealBundle::random(4);
        let b = NodeSealBundle::random(4);
        assert_ne!(a.dist_public_key(), b.dist_public_key());
        let a2 = NodeSealBundle::parse(&a.to_json().unwrap()).unwrap();
        assert_eq!(a2.dist_public_key(), a.dist_public_key());
        assert_eq!(a2.sealer().unseal(&a.sealer().seal(b"k").unwrap()).unwrap(), b"k");
    }

    #[test]
    fn previous_deks_open_but_never_seal() {
        let old = NodeSealBundle::random(1);
        let sealed_old = old.sealer().seal(b"old").unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&NodeSealBundle::random(1).to_json().unwrap()).unwrap();
        json["previous_share_deks"] = serde_json::json!([hex::encode(*old.share_dek)]);
        let rotated = NodeSealBundle::parse(json.to_string().as_bytes()).unwrap();
        assert_eq!(rotated.sealer().unseal(&sealed_old).unwrap(), b"old");
        let sealed_new = rotated.sealer().seal(b"new").unwrap();
        assert!(old.sealer().unseal(&sealed_new).is_err(), "new writes use the current DEK only");
    }

    #[test]
    fn malformed_bundles_are_refused() {
        let good: serde_json::Value =
            serde_json::from_slice(&NodeSealBundle::random(1).to_json().unwrap()).unwrap();
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            f(&mut v);
            NodeSealBundle::parse(v.to_string().as_bytes())
        };
        assert!(mutate(&|v| v["v"] = 2.into()).is_err(), "future version");
        assert!(mutate(&|v| v["kind"] = "something-else".into()).is_err(), "wrong kind");
        assert!(mutate(&|v| v["share_dek"] = "abcd".into()).is_err(), "short key");
        assert!(mutate(&|v| v["dist_seed"] = "zz".repeat(32).into()).is_err(), "not hex");
        assert!(mutate(&|v| v["master"] = "oops".into()).is_err(), "unknown field");
        assert!(mutate(&|v| { v.as_object_mut().unwrap().remove("dist_seed"); }).is_err());
        assert!(mutate(&|_| {}).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn read_file_checks_the_node_and_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        std::fs::write(&path, &*NodeSealBundle::from_legacy_master(MASTER, 2).to_json().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o440)).unwrap();
        assert_eq!(NodeSealBundle::read_file(&path, 2).unwrap().node, 2);
        let e = NodeSealBundle::read_file(&path, 3).err().unwrap().to_string();
        assert!(e.contains("for node 2") && e.contains("wrong Secret"), "{e}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = NodeSealBundle::read_file(&path, 2).err().unwrap().to_string();
        assert!(e.contains("every user"), "{e}");
    }

    fn cfg_with(seal: ShareSealConfig, pins: [Option<[u8; 32]>; 3], commitment: Option<[u8; 32]>) -> crate::config::Config {
        let mut peers: Vec<_> = (1..=3)
            .map(|i| crate::config::PeerConfig::new(i, format!("http://n{i}:9101")))
            .collect();
        for (p, k) in peers.iter_mut().zip(pins) {
            p.dist_public_key = k.map(hex::encode);
        }
        crate::config::Config {
            identifier: 2,
            listen: "127.0.0.1:0".into(),
            threshold: 2,
            data_dir: "/tmp/x".into(),
            peers,
            tls: None,
            share_seal: Some(seal),
            signer_allowlist: None,
            peer_allowlist: None,
            operator_allowlist: None,
            ceremony_sign_test_rate_limit_per_min: 0,
            metrics_listen: None,
            hosted_keys: Some(crate::config::HostedKeysConfig {
                enabled: true,
                write_quorum: 2,
                anti_entropy_interval_secs: 300,
                decrypt_rate_limit_per_min: 0,
                commitment_key: commitment.map(hex::encode),
            }),
            cluster_id: None,
            cluster_id_change_allowed: false,
            signing_policy: Default::default(),
        }
    }

    fn pins() -> [Option<[u8; 32]>; 3] {
        [1, 2, 3].map(|i| Some(crate::wrap::DistKey::derive(MASTER, i).public_bytes()))
    }

    #[test]
    fn a_bundle_keyring_equals_the_legacy_keyring() {
        // Mixed cluster: a node on its split bundle and a node on the master hold the same view of
        // every distribution key and the same commitment key, byte for byte.
        let legacy = SealKeys::LegacyMaster {
            env: "E".into(),
            master: Zeroizing::new(String::from_utf8(MASTER.to_vec()).unwrap()),
        };
        let bundle = SealKeys::Bundle {
            path: "/b".into(),
            bundle: NodeSealBundle::from_legacy_master(MASTER, 2),
        };
        let commitment = crate::wrap::legacy_commitment_key(MASTER);
        let cfg_legacy = cfg_with(ShareSealConfig { secret_env: Some("E".into()), secret_file: None }, [None; 3], None);
        let cfg_bundle = cfg_with(ShareSealConfig { secret_env: None, secret_file: Some("/b".into()) }, pins(), Some(commitment));
        let a = legacy.hosted_keyring(&cfg_legacy).unwrap();
        let b = bundle.hosted_keyring(&cfg_bundle).unwrap();
        assert_eq!(a.peer_dist_keys, b.peer_dist_keys);
        assert_eq!(a.commitment_key, b.commitment_key);
        assert_eq!(a.dist_key.public_bytes(), b.dist_key.public_bytes());
        // The legacy node also accepts the pins and the commitment key when they are right.
        legacy.hosted_keyring(&cfg_bundle).unwrap();
    }

    #[test]
    fn a_wrong_own_pin_or_commitment_key_refuses_to_start() {
        let bundle = SealKeys::Bundle {
            path: "/b".into(),
            bundle: NodeSealBundle::from_legacy_master(MASTER, 2),
        };
        let file = || ShareSealConfig { secret_env: None, secret_file: Some("/b".into()) };
        let commitment = crate::wrap::legacy_commitment_key(MASTER);
        let mut wrong = pins();
        wrong[1] = Some([7u8; 32]);
        let e = bundle.hosted_keyring(&cfg_with(file(), wrong, Some(commitment))).err().unwrap().to_string();
        assert!(e.contains("wrong seal bundle"), "{e}");
        let e = bundle.hosted_keyring(&cfg_with(file(), pins(), None)).err().unwrap().to_string();
        assert!(e.contains("commitment_key is required"), "{e}");
        let mut missing = pins();
        missing[2] = None;
        assert!(bundle.hosted_keyring(&cfg_with(file(), missing, Some(commitment))).is_err());

        let legacy = SealKeys::LegacyMaster {
            env: "E".into(),
            master: Zeroizing::new(String::from_utf8(MASTER.to_vec()).unwrap()),
        };
        let env = ShareSealConfig { secret_env: Some("E".into()), secret_file: None };
        let e = legacy.hosted_keyring(&cfg_with(env, [None; 3], Some([9u8; 32]))).err().unwrap().to_string();
        assert!(e.contains("does not match"), "{e}");
    }
}

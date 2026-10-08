// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Getting dealer shares to cosigners in the split ceremony (docs/split-ceremony.md, B2).
//!
//! The offline dealer (`rutli-dealer`) splits an existing Canton key into one FROST share per
//! cosigner. Each share must reach exactly one node, readable by that node only, and must not be
//! usable anywhere else or later. The flow:
//!
//! 1. **Recipient request** (`rutli-cosigner share-recipient`). Each node mints a fresh X25519
//!    keypair *for this ceremony and this key id only*, stores the secret half sealed under its own
//!    seal key at `data_dir/ceremony/<key_id>.recipient` ([`create_recipient`]), and prints a
//!    public [`RecipientRequest`] carrying the public half plus everything the dealer must agree on:
//!    cluster, key id, ceremony id, this node's identifier, threshold, roster.
//! 2. **Share bundle** (`rutli-dealer split-key`). For each request the dealer seals the node's
//!    [`SecretShare`] to `recipient_pub` ([`seal_share`]) with [`crate::wrap::seal_to`], under an
//!    AAD that binds the recipient, cluster, key id, spec, ceremony id, group key, Canton
//!    fingerprint and public-key-package digest. The [`ShareBundle`] carries the public key
//!    package in clear so it can be checked before anything is decrypted.
//! 3. **Install** (`rutli-cosigner import-share`) opens the bundle with the stored secret
//!    ([`ShareBundle::open`]) and deletes the secret once the share is installed. A bundle is then
//!    undecryptable by anyone, including the node itself — replay after install is impossible.
//!
//! # Why ephemeral recipient keys, not the hosted-key `DistKey`
//!
//! Hosted-key replication wraps to a node's static `DistKey`, derived from the cluster's shared
//! seal master secret. For dealer shares that is the wrong key: the dealer would need the master
//! secret to derive the recipients' public keys, and anyone holding the master secret plus two
//! bundles would hold the key forever, since the static keys never change. Under a shared master
//! there is no per-node binding at all. A per-ceremony key that lives only until install has none
//! of these problems, and the public half travels in the request, so the dealer needs no secret.
//!
//! # Forged requests (dealer side): the request is signed
//!
//! The dangerous forgery runs the other way. A request names the key the dealer seals a real share
//! to; whoever substitutes `t` request files between the pods and the dealer receives `t` real
//! shares and reconstructs the key. So every request is signed with the node's mTLS leaf key and
//! carries its certificate chain, and the dealer refuses any request that does not verify up to the
//! cluster CA as coming from the cosigner it names ([`crate::request_auth`]). Independently, each
//! request has a short authentication string (SAS) that witnesses read from the pod and the dealer
//! operator must confirm before anything is sealed (Gate 0 of the runbook). Defeating both needs a
//! CA-issued cosigner key **and** a witness who confirms the wrong SAS.
//!
//! # Forged bundles (node side): the envelope does not authenticate the dealer
//!
//! Sealing to a public key gives confidentiality, not sender authentication: anyone who sees a
//! request can mint a bundle that opens. Authenticity comes from the checks around it — the group
//! key must equal the Canton key the operator expects (`--expect-fingerprint`), the share must pass
//! VSS against the package's commitment and interpolate with it, and `verify-key` compares the
//! package digest across every node and signs with every `t`-subset. Someone who forges bundles
//! without the real key can know at most `t − 1` shares of a sharing whose secret they do not know;
//! the result fails verification and cannot sign. But a bundle that fails authentication at install
//! also means *someone else had a way into the path*: treat it as a possible exposure of the real
//! bundles and investigate before any re-deal (runbook failure table).

use std::path::{Path, PathBuf};

use frost_ed25519 as frost;
use frost::keys::{PublicKeyPackage, SecretShare};
use frost::Identifier;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::seal::Sealer;
use crate::wrap::{self, Wrapped};
use crate::{DaemonError, Result};

/// The `spec` field of every share envelope and its AAD. No hosted-key spec equals it, so a
/// hosted-key envelope can never be presented as a share envelope or vice versa.
pub const SHARE_SPEC: &str = "frost-ed25519-share";

/// The marker in every imported key id: `<prefix>frost-import-<suffix>`. DKG refuses ids that
/// contain it, so an import id can never be minted by DKG and a DKG id can never be imported.
pub const IMPORT_MARKER: &str = "frost-import-";

pub const RECIPIENT_KIND: &str = "rutli-share-recipient";
pub const RECIPIENT_VERSION: u8 = 1;
pub const BUNDLE_KIND: &str = "rutli-frost-share";
pub const BUNDLE_VERSION: u8 = 1;
/// Envelope version of a share bundle. Version 1 is the hosted-key envelope; 2 is the same
/// construction with the split ceremony's extra AAD fields ([`share_aad`]).
pub const SHARE_WRAP_VERSION: u32 = 2;

const SECRET_KIND: &str = "rutli-share-recipient-secret";

/// True for a key id the split ceremony may install: `^[A-Za-z0-9_-]*frost-import-[A-Za-z0-9_-]+$`.
/// The prefix is the driver's `frost.key-prefix` (empty by default); the driver routes the id to the
/// FROST backend because it starts with `<prefix>frost-`.
pub fn is_import_key_id(key_id: &str) -> bool {
    let alphabet = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    key_id.chars().all(alphabet)
        && key_id.find(IMPORT_MARKER).is_some_and(|i| key_id.len() > i + IMPORT_MARKER.len())
}

/// True for a key id DKG must refuse: anything containing [`IMPORT_MARKER`].
pub fn is_reserved_for_import(key_id: &str) -> bool {
    key_id.contains(IMPORT_MARKER)
}

/// Ceremony ids go into AADs, file contents and logs: keep them short and boring.
pub fn validate_ceremony_id(ceremony_id: &str) -> Result<()> {
    let ok = !ceremony_id.is_empty()
        && ceremony_id.len() <= 64
        && ceremony_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(DaemonError::Ceremony(format!(
            "invalid ceremony id {ceremony_id:?}: use 1-64 characters of [A-Za-z0-9_-]"
        )))
    }
}

/// What one cosigner tells the dealer: who it is, what it expects, and where to seal its share.
/// Public; safe to print, mail and archive in the ceremony record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientRequest {
    pub v: u8,
    pub kind: String,
    pub ceremony_id: String,
    pub key_id: String,
    /// `wrap::cluster_id_from_ca` of the node's CA certificate (`plaintext-dev` without TLS).
    pub cluster_id: String,
    /// This node's configured FROST identifier.
    pub identifier: u16,
    pub threshold: u16,
    pub max_signers: u16,
    /// Every configured identifier in the cluster, sorted.
    pub roster: Vec<u16>,
    /// Hex X25519 public key, minted for this ceremony.
    pub recipient_pub: String,
    /// How `signature` was made: `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, `ed25519` or
    /// `rsa-pkcs1-sha256` (the node's mTLS leaf key type).
    pub signature_alg: String,
    /// The node's mTLS certificate chain, base64 DER, leaf first.
    pub signer_chain: Vec<String>,
    /// Base64 signature by the leaf key over [`crate::request_auth::canonical_bytes`] — every field
    /// above `signature_alg`. Verified by the dealer against the cluster CA.
    pub signature: String,
}

impl RecipientRequest {
    /// The parameters every node of one ceremony must agree on (everything but the node's own
    /// identifier and key).
    pub fn ceremony_params(&self) -> (&str, &str, &str, u16, u16, &[u16]) {
        (
            &self.ceremony_id,
            &self.key_id,
            &self.cluster_id,
            self.threshold,
            self.max_signers,
            &self.roster,
        )
    }

    /// Structural checks on a request read from a file.
    pub fn validate(&self) -> Result<()> {
        if self.kind != RECIPIENT_KIND || self.v != RECIPIENT_VERSION {
            return Err(DaemonError::Ceremony(format!(
                "not a v{RECIPIENT_VERSION} share-recipient request (kind {:?}, v {})",
                self.kind, self.v
            )));
        }
        validate_ceremony_id(&self.ceremony_id)?;
        if !is_import_key_id(&self.key_id) {
            return Err(DaemonError::Ceremony(format!(
                "key id {:?} is not an import id (<prefix>{IMPORT_MARKER}<name>)",
                self.key_id
            )));
        }
        let mut sorted = self.roster.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted != self.roster
            || self.roster.len() != usize::from(self.max_signers)
            || !self.roster.contains(&self.identifier)
            || self.roster.contains(&0)
            || self.threshold < 2
            || self.threshold > self.max_signers
        {
            return Err(DaemonError::Ceremony(format!(
                "inconsistent request: identifier {} threshold {} max_signers {} roster {:?}",
                self.identifier, self.threshold, self.max_signers, self.roster
            )));
        }
        self.public_key().map(|_| ())
    }

    pub fn public_key(&self) -> Result<[u8; 32]> {
        hex32(&self.recipient_pub, "recipient_pub")
    }
}

/// A node's pending recipient: the request it published and the matching secret.
pub struct RecipientState {
    pub request: RecipientRequest,
    secret: StaticSecret, // zeroized on drop
}

/// The sealed file holding a pending recipient secret.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientSecretFile {
    v: u8,
    kind: String,
    request: RecipientRequest,
    secret: String,
    created_at: u64,
}

/// `data_dir/ceremony`: outside `data_dir/keys`, so the key store, its readiness probe and
/// `rutli-cosigner backup` never see a recipient secret.
pub fn ceremony_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("ceremony")
}

pub fn recipient_path(data_dir: &Path, key_id: &str) -> Result<PathBuf> {
    if !key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') || key_id.is_empty() {
        return Err(DaemonError::Config(format!("invalid key id: {key_id:?}")));
    }
    Ok(ceremony_dir(data_dir).join(format!("{key_id}.recipient")))
}

/// Mint a recipient keypair for `template` (all fields but `recipient_pub` and the signature, which
/// are filled in), sign the request with the node's mTLS identity, store the secret sealed, and
/// return the public request. Refuses to replace a pending recipient file unless `replace` — a
/// second request would orphan a bundle the dealer may already have made.
pub fn create_recipient(
    data_dir: &Path,
    sealer: &Sealer,
    signer: &crate::request_auth::NodeSigner,
    mut template: RecipientRequest,
    replace: bool,
) -> Result<RecipientRequest> {
    let path = recipient_path(data_dir, &template.key_id)?;
    if path.try_exists()? && !replace {
        return Err(DaemonError::Ceremony(format!(
            "a recipient for {} is already pending at {} — finish or abort that ceremony \
             (abort-import), or pass --replace to discard it",
            template.key_id,
            path.display()
        )));
    }
    let secret = StaticSecret::random_from_rng(OsRng);
    template.recipient_pub = hex::encode(PublicKey::from(&secret).as_bytes());
    template.validate()?;
    signer.sign(&mut template)?;

    let file = RecipientSecretFile {
        v: 1,
        kind: SECRET_KIND.into(),
        request: template.clone(),
        secret: hex::encode(secret.as_bytes()),
        created_at: crate::hosted::now_secs(),
    };
    let plain = to_json_zeroizing(&file)?;
    drop(Zeroizing::new(file.secret)); // wipe the hex copy
    let sealed = sealer.seal(&plain)?;
    write_private_atomic(&path, &sealed)?;
    Ok(template)
}

/// Read and unseal the pending recipient for `key_id`.
pub fn load_recipient(data_dir: &Path, sealer: &Sealer, key_id: &str) -> Result<RecipientState> {
    let path = recipient_path(data_dir, key_id)?;
    if !path.try_exists()? {
        return Err(DaemonError::Ceremony(format!(
            "no pending recipient for {key_id} at {} — run share-recipient first (or the share \
             was already installed and its recipient secret deleted)",
            path.display()
        )));
    }
    let bytes = std::fs::read(&path)?;
    if !Sealer::is_sealed(&bytes) {
        return Err(DaemonError::Ceremony(format!("{} is not sealed — refusing it", path.display())));
    }
    let plain = Zeroizing::new(sealer.unseal(&bytes)?);
    let file: RecipientSecretFile = serde_json::from_slice(&plain)?;
    let secret_hex = Zeroizing::new(file.secret);
    if file.kind != SECRET_KIND || file.v != 1 || file.request.key_id != key_id {
        return Err(DaemonError::Ceremony(format!(
            "{} does not hold the recipient secret for {key_id}",
            path.display()
        )));
    }
    let secret = StaticSecret::from(*Zeroizing::new(hex32(&secret_hex, "recipient secret")?));
    file.request.validate()?;
    if PublicKey::from(&secret).as_bytes() != &file.request.public_key()? {
        return Err(DaemonError::Ceremony("recipient secret does not match its public key".into()));
    }
    Ok(RecipientState { request: file.request, secret })
}

/// Remove the pending recipient for `key_id`. Returns whether there was one. Best-effort erasure:
/// the file is sealed, and on copy-on-write or wear-levelled storage the bytes may survive.
pub fn delete_recipient(data_dir: &Path, key_id: &str) -> Result<bool> {
    let path = recipient_path(data_dir, key_id)?;
    if !path.try_exists()? {
        return Ok(false);
    }
    std::fs::remove_file(&path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(true)
}

/// The envelope part of a bundle, hex-encoded for JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEnvelope {
    pub epk: String,
    pub ct: String,
    pub version: u32,
}

/// One node's share, sealed to its ceremony recipient key. Written by the dealer as
/// `share-<key_id>-node<identifier>.json`; everything but `wrapped` is public.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareBundle {
    pub v: u8,
    pub kind: String,
    pub key_id: String,
    pub cluster_id: String,
    pub ceremony_id: String,
    pub recipient: u16,
    pub recipient_pub: String,
    pub spec: String,
    pub threshold: u16,
    pub max_signers: u16,
    pub canton_fingerprint: String,
    /// Hex 32-byte Ed25519 group verifying key.
    pub group_verifying_key: String,
    pub public_key_package: PublicKeyPackage,
    /// Hex SHA-256 of the package's canonical serialization ([`rutli_frost_core::dealer::pkp_digest`]).
    pub pkp_digest: String,
    pub wrapped: BundleEnvelope,
}

/// The share envelope's AAD: the hosted-key fields (cluster, key id, spec, recipient) plus
/// `ceremony_id`, the raw 32-byte group key, the Canton fingerprint string and the raw 32-byte
/// package digest — each length-prefixed (see [`crate::wrap::aad`]).
pub fn share_aad(
    recipient: u16,
    cluster_id: &str,
    key_id: &str,
    ceremony_id: &str,
    group_verifying_key: &[u8; 32],
    canton_fingerprint: &str,
    pkp_digest: &[u8; 32],
) -> Vec<u8> {
    wrap::aad(
        cluster_id,
        key_id,
        SHARE_SPEC,
        recipient,
        &[
            ceremony_id.as_bytes(),
            group_verifying_key,
            canton_fingerprint.as_bytes(),
            pkp_digest,
        ],
    )
}

/// The Canton fingerprint of an Ed25519 group key.
pub fn ed25519_fingerprint(group_verifying_key: &[u8; 32]) -> String {
    rutli_canton_key::fingerprint(&rutli_canton_key::PublicKey::Ed25519(*group_verifying_key))
}

/// Seal `share` for the node that published `request` (dealer side).
pub fn seal_share(
    request: &RecipientRequest,
    share: &SecretShare,
    pkp: &PublicKeyPackage,
    canton_fingerprint: &str,
) -> Result<ShareBundle> {
    request.validate()?;
    if *share.identifier() != ident(request.identifier)? {
        return Err(DaemonError::Ceremony(format!(
            "share is not for node {}",
            request.identifier
        )));
    }
    let group = rutli_frost_core::dkg::group_verifying_key_bytes(pkp)?;
    let digest = rutli_frost_core::dealer::pkp_digest(pkp)?;
    let aad = share_aad(
        request.identifier,
        &request.cluster_id,
        &request.key_id,
        &request.ceremony_id,
        &group,
        canton_fingerprint,
        &digest,
    );
    let plain = to_json_zeroizing(share)?;
    let (epk, ct) = wrap::seal_to(&request.public_key()?, &plain, &aad)?;
    Ok(ShareBundle {
        v: BUNDLE_VERSION,
        kind: BUNDLE_KIND.into(),
        key_id: request.key_id.clone(),
        cluster_id: request.cluster_id.clone(),
        ceremony_id: request.ceremony_id.clone(),
        recipient: request.identifier,
        recipient_pub: request.recipient_pub.clone(),
        spec: SHARE_SPEC.into(),
        threshold: request.threshold,
        max_signers: request.max_signers,
        canton_fingerprint: canton_fingerprint.to_string(),
        group_verifying_key: hex::encode(group),
        public_key_package: pkp.clone(),
        pkp_digest: hex::encode(digest),
        wrapped: BundleEnvelope {
            epk: hex::encode(epk),
            ct: hex::encode(ct),
            version: SHARE_WRAP_VERSION,
        },
    })
}

impl ShareBundle {
    /// The raw group key. Checked against the package by [`ShareBundle::check_against`].
    pub fn group_key(&self) -> Result<[u8; 32]> {
        hex32(&self.group_verifying_key, "group_verifying_key")
    }

    /// Every check that needs no secret: format, the bundle matches `request` field by field (this
    /// node, this cluster, this key id, this ceremony, same threshold, size and roster), and the
    /// cleartext package agrees with the bundle's group key, fingerprint and digest.
    pub fn check_against(&self, request: &RecipientRequest) -> Result<()> {
        if self.kind != BUNDLE_KIND || self.v != BUNDLE_VERSION || self.spec != SHARE_SPEC {
            return Err(DaemonError::Ceremony(format!(
                "not a v{BUNDLE_VERSION} {BUNDLE_KIND} bundle (kind {:?}, v {}, spec {:?})",
                self.kind, self.v, self.spec
            )));
        }
        if self.wrapped.version != SHARE_WRAP_VERSION {
            return Err(DaemonError::Ceremony(format!(
                "unsupported share envelope version {} (this node speaks {SHARE_WRAP_VERSION})",
                self.wrapped.version
            )));
        }
        let mismatch = |what: &str, got: &dyn std::fmt::Debug, want: &dyn std::fmt::Debug| {
            Err(DaemonError::Ceremony(format!(
                "bundle {what} is {got:?}, this node expects {want:?}"
            )))
        };
        if self.recipient != request.identifier {
            return mismatch("recipient", &self.recipient, &request.identifier);
        }
        if self.cluster_id != request.cluster_id {
            return mismatch("cluster_id", &self.cluster_id, &request.cluster_id);
        }
        if self.key_id != request.key_id {
            return mismatch("key_id", &self.key_id, &request.key_id);
        }
        if self.ceremony_id != request.ceremony_id {
            return mismatch("ceremony_id", &self.ceremony_id, &request.ceremony_id);
        }
        if self.recipient_pub != request.recipient_pub {
            return mismatch("recipient_pub", &self.recipient_pub, &request.recipient_pub);
        }
        if self.threshold != request.threshold {
            return mismatch("threshold", &self.threshold, &request.threshold);
        }
        if self.max_signers != request.max_signers {
            return mismatch("max_signers", &self.max_signers, &request.max_signers);
        }
        let roster: Vec<u16> = request.roster.clone();
        let ids: std::collections::BTreeSet<Identifier> =
            roster.iter().map(|&i| ident(i)).collect::<Result<_>>()?;
        let pkp_ids: std::collections::BTreeSet<Identifier> =
            self.public_key_package.verifying_shares().keys().copied().collect();
        if pkp_ids != ids {
            return Err(DaemonError::Ceremony(format!(
                "the bundle's public key package is not for roster {roster:?}"
            )));
        }

        let group = self.group_key()?;
        if rutli_frost_core::dkg::group_verifying_key_bytes(&self.public_key_package)? != group {
            return Err(DaemonError::Ceremony(
                "group_verifying_key does not match the public key package".into(),
            ));
        }
        if ed25519_fingerprint(&group) != self.canton_fingerprint {
            return Err(DaemonError::Ceremony(
                "canton_fingerprint is not the fingerprint of the group key".into(),
            ));
        }
        let digest = rutli_frost_core::dealer::pkp_digest(&self.public_key_package)?;
        if hex::encode(digest) != self.pkp_digest {
            return Err(DaemonError::Ceremony(
                "pkp_digest does not match the public key package".into(),
            ));
        }
        Ok(())
    }

    /// Decrypt this node's share with its pending recipient secret. Runs
    /// [`ShareBundle::check_against`] first; the AAD is rebuilt from the bundle's own fields, so
    /// relabelling any of them (group key, fingerprint, digest, ceremony, key, cluster, recipient)
    /// fails authentication even where a field-level check would not notice.
    pub fn open(&self, state: &RecipientState) -> Result<SecretShare> {
        self.check_against(&state.request)?;
        let aad = share_aad(
            self.recipient,
            &self.cluster_id,
            &self.key_id,
            &self.ceremony_id,
            &self.group_key()?,
            &self.canton_fingerprint,
            &hex32(&self.pkp_digest, "pkp_digest")?,
        );
        let w = Wrapped {
            recipient: self.recipient,
            encapsulated_key: hex::decode(&self.wrapped.epk)
                .map_err(|_| DaemonError::Ceremony("bad envelope epk hex".into()))?,
            ciphertext: hex::decode(&self.wrapped.ct)
                .map_err(|_| DaemonError::Ceremony("bad envelope ct hex".into()))?,
            version: self.wrapped.version,
        };
        let plain = wrap::open_with(&state.secret, &state.request.public_key()?, &w, &aad)
            .map_err(|_| {
                DaemonError::Ceremony(
                    "share envelope failed authentication — not sealed to this node's pending \
                     recipient key, or a bundle field was altered"
                        .into(),
                )
            })?;
        let share: SecretShare = serde_json::from_slice(&plain)
            .map_err(|_| DaemonError::Ceremony("decrypted share is malformed".into()))?;
        if *share.identifier() != ident(self.recipient)? {
            return Err(DaemonError::Ceremony(format!(
                "the sealed share is not for node {}",
                self.recipient
            )));
        }
        Ok(share)
    }
}

/// JSON of a secret-bearing value into a zeroize-on-drop buffer that is never reallocated: the
/// exact size is measured first, so no partially filled copy is freed unwiped as the buffer grows.
/// (serde_json's own per-field temporaries — e.g. a share's hex string — are outside our reach;
/// the dealer's process isolation covers those.)
pub fn to_json_zeroizing<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(count.0));
    serde_json::to_writer(&mut *buf, value)?;
    debug_assert_eq!(buf.capacity(), count.0, "the buffer must not have been reallocated");
    Ok(buf)
}

fn ident(id: u16) -> Result<Identifier> {
    Identifier::try_from(id).map_err(DaemonError::Frost)
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = Zeroizing::new(
        hex::decode(s).map_err(|_| DaemonError::Ceremony(format!("{what} is not hex")))?,
    );
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| DaemonError::Ceremony(format!("{what} is not 32 bytes")))
}

/// Write `bytes` to `path` with owner-only permissions, durably and atomically: a unique temp file
/// (0600 from creation), fsync, rename over `path`, fsync the directory. Creates the parent
/// directory 0700.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| DaemonError::Config(format!("{} has no parent", path.display())))?;
    create_private_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
        uuid::Uuid::new_v4()
    ));
    {
        let mut f = private_create_new(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// `create_new` + 0600: never follows or clobbers an existing file, never briefly world-readable.
pub fn private_create_new(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(opts.open(path)?)
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "0123456789abcdef";
    const KEY: &str = "frost-import-1220cb0e";
    const CEREMONY: &str = "b2-2026-10-08";
    const SEED: [u8; 32] = [7u8; 32];

    fn sealer(node: u16) -> Sealer {
        Sealer::from_master_secret(b"share delivery test master secret", node)
    }

    fn signer(node: u16) -> crate::request_auth::NodeSigner {
        crate::test_pki::TestPki::new().signer(&format!("cosigner{node}"))
    }

    fn template(identifier: u16) -> RecipientRequest {
        RecipientRequest {
            v: RECIPIENT_VERSION,
            kind: RECIPIENT_KIND.into(),
            ceremony_id: CEREMONY.into(),
            key_id: KEY.into(),
            cluster_id: CLUSTER.into(),
            identifier,
            threshold: 2,
            max_signers: 3,
            roster: vec![1, 2, 3],
            recipient_pub: String::new(),
            signature_alg: String::new(),
            signer_chain: Vec::new(),
            signature: String::new(),
        }
    }

    struct Node {
        dir: tempfile::TempDir,
        id: u16,
        request: RecipientRequest,
    }

    impl Node {
        fn new(id: u16) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let request = create_recipient(dir.path(), &sealer(id), &signer(id), template(id), false).unwrap();
            Self { dir, id, request }
        }
        fn state(&self) -> Result<RecipientState> {
            load_recipient(self.dir.path(), &sealer(self.id), KEY)
        }
    }

    /// A 2-of-3 split of SEED and a bundle per node.
    fn deal(nodes: &[Node]) -> (Vec<ShareBundle>, PublicKeyPackage, Vec<SecretShare>) {
        let ids: Vec<u16> = nodes.iter().map(|n| n.id).collect();
        let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&SEED, &ids, 2).unwrap();
        let fp = ed25519_fingerprint(&rutli_frost_core::dkg::group_verifying_key_bytes(&pkp).unwrap());
        let bundles = nodes
            .iter()
            .zip(&shares)
            .map(|(n, s)| seal_share(&n.request, s, &pkp, &fp).unwrap())
            .collect();
        (bundles, pkp, shares)
    }

    fn nodes() -> Vec<Node> {
        (1..=3).map(Node::new).collect()
    }

    #[test]
    fn a_bundle_round_trips_to_its_node() {
        let nodes = nodes();
        let (bundles, _, shares) = deal(&nodes);
        for ((n, b), s) in nodes.iter().zip(&bundles).zip(&shares) {
            // Through JSON, as the files travel.
            let b: ShareBundle = serde_json::from_slice(&serde_json::to_vec(b).unwrap()).unwrap();
            assert_eq!(&b.open(&n.state().unwrap()).unwrap(), s);
        }
    }

    #[test]
    fn another_node_cannot_open_a_bundle_even_relabelled() {
        let nodes = nodes();
        let (bundles, _, _) = deal(&nodes);
        let for_two = &bundles[1];
        assert!(for_two.open(&nodes[2].state().unwrap()).is_err(), "wrong node");

        // Relabelled to node 3, with node 3's public key: the field checks pass, the AEAD does not.
        let mut relabelled = for_two.clone();
        relabelled.recipient = 3;
        relabelled.recipient_pub = nodes[2].request.recipient_pub.clone();
        let err = relabelled.open(&nodes[2].state().unwrap()).unwrap_err().to_string();
        assert!(err.contains("authentication"), "{err}");
    }

    #[test]
    fn relabelling_any_bound_field_is_refused() {
        let nodes = nodes();
        let (bundles, pkp, shares) = deal(&nodes);
        let state = nodes[0].state().unwrap();
        let b = &bundles[0];

        // Fields the node also knows independently: refused before decryption.
        for mutate in [
            (|b: &mut ShareBundle| b.key_id = "frost-import-other".into()) as fn(&mut ShareBundle),
            |b| b.ceremony_id = "another-ceremony".into(),
            |b| b.cluster_id = "fedcba9876543210".into(),
            |b| b.threshold = 3,
            |b| b.pkp_digest = hex::encode([0u8; 32]),
            |b| b.canton_fingerprint = format!("1220{}", "00".repeat(32)),
            |b| b.group_verifying_key = hex::encode([9u8; 32]),
        ] {
            let mut bad = b.clone();
            mutate(&mut bad);
            assert!(bad.open(&state).is_err());
        }

        // A bundle whose public parts are all self-consistent but describe a DIFFERENT sharing
        // (another key): the package, group key, fingerprint and digest swapped together. Only the
        // AEAD can notice, and it does.
        let (_, other_pkp) = rutli_frost_core::dealer::split_ed25519_seed(&[8u8; 32], &[1, 2, 3], 2).unwrap();
        let other_group = rutli_frost_core::dkg::group_verifying_key_bytes(&other_pkp).unwrap();
        let mut swapped = b.clone();
        swapped.public_key_package = other_pkp.clone();
        swapped.group_verifying_key = hex::encode(other_group);
        swapped.canton_fingerprint = ed25519_fingerprint(&other_group);
        swapped.pkp_digest = hex::encode(rutli_frost_core::dealer::pkp_digest(&other_pkp).unwrap());
        swapped.check_against(&state.request).expect("public parts are consistent");
        let err = swapped.open(&state).unwrap_err().to_string();
        assert!(err.contains("authentication"), "{err}");

        // Same key, refreshed-looking package (same group key, different shares): digest differs,
        // the AEAD binds the digest.
        let (_, fresh_pkp) = rutli_frost_core::dealer::split_ed25519_seed(&SEED, &[1, 2, 3], 2).unwrap();
        assert_ne!(fresh_pkp, pkp);
        let mut repackaged = b.clone();
        repackaged.public_key_package = fresh_pkp.clone();
        repackaged.pkp_digest = hex::encode(rutli_frost_core::dealer::pkp_digest(&fresh_pkp).unwrap());
        assert!(repackaged.open(&state).is_err());

        // Untouched, it still opens.
        assert_eq!(b.open(&state).unwrap(), shares[0]);
    }

    #[test]
    fn a_tampered_ciphertext_is_refused() {
        let nodes = nodes();
        let (bundles, _, _) = deal(&nodes);
        let mut bad = bundles[0].clone();
        let mut ct = hex::decode(&bad.wrapped.ct).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        bad.wrapped.ct = hex::encode(ct);
        assert!(bad.open(&nodes[0].state().unwrap()).is_err());
    }

    #[test]
    fn future_versions_are_refused_not_misparsed() {
        let nodes = nodes();
        let (bundles, _, _) = deal(&nodes);
        let state = nodes[0].state().unwrap();
        let mut b = bundles[0].clone();
        b.v = BUNDLE_VERSION + 1;
        assert!(b.open(&state).is_err());
        let mut b = bundles[0].clone();
        b.wrapped.version = SHARE_WRAP_VERSION + 1;
        assert!(b.open(&state).is_err());
        let mut b = bundles[0].clone();
        b.wrapped.version = crate::wrap::WRAP_VERSION; // a hosted-key envelope version
        assert!(b.open(&state).is_err());
        // Unknown fields are refused too (deny_unknown_fields), so a newer format fails loudly.
        let mut v = serde_json::to_value(&bundles[0]).unwrap();
        v["new_field"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ShareBundle>(v).is_err());
    }

    #[test]
    fn once_the_recipient_secret_is_deleted_the_bundle_is_dead() {
        let nodes = nodes();
        let (bundles, _, _) = deal(&nodes);
        assert!(delete_recipient(nodes[0].dir.path(), KEY).unwrap());
        assert!(nodes[0].state().is_err(), "no secret, no replay");
        assert!(!delete_recipient(nodes[0].dir.path(), KEY).unwrap(), "idempotent");
        // A NEW recipient for the same key cannot open the old bundle either.
        let fresh = create_recipient(nodes[0].dir.path(), &sealer(1), &signer(1), template(1), false).unwrap();
        assert_ne!(fresh.recipient_pub, nodes[0].request.recipient_pub);
        assert!(bundles[0].open(&nodes[0].state().unwrap()).is_err());
    }

    #[test]
    fn the_recipient_secret_is_sealed_on_disk_and_outside_the_key_store() {
        let node = Node::new(1);
        let path = recipient_path(node.dir.path(), KEY).unwrap();
        assert!(path.starts_with(node.dir.path().join("ceremony")));
        let raw = std::fs::read(&path).unwrap();
        assert!(Sealer::is_sealed(&raw));
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains(&node.request.recipient_pub), "not even the public half in clear");
        // Another node's seal key cannot read it.
        assert!(load_recipient(node.dir.path(), &sealer(2), KEY).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            let dir = std::fs::metadata(path.parent().unwrap()).unwrap();
            assert_eq!(dir.permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn a_pending_recipient_is_not_replaced_unless_asked() {
        let node = Node::new(1);
        let err = create_recipient(node.dir.path(), &sealer(1), &signer(1), template(1), false).unwrap_err();
        assert!(err.to_string().contains("already pending"), "{err}");
        let replaced = create_recipient(node.dir.path(), &sealer(1), &signer(1), template(1), true).unwrap();
        assert_ne!(replaced.recipient_pub, node.request.recipient_pub);
        assert_eq!(node.state().unwrap().request, replaced);
    }

    #[test]
    fn requests_are_validated() {
        let mut bad = template(4); // not in the roster
        bad.recipient_pub = hex::encode([1u8; 32]);
        assert!(bad.validate().is_err());
        let mut bad = template(1);
        bad.recipient_pub = hex::encode([1u8; 32]);
        bad.key_id = "frost-namespace".into(); // not an import id
        assert!(bad.validate().is_err());
        let mut bad = template(1);
        bad.recipient_pub = hex::encode([1u8; 32]);
        bad.threshold = 1;
        assert!(bad.validate().is_err());
        let mut ok = template(1);
        ok.recipient_pub = hex::encode([1u8; 32]);
        ok.validate().unwrap();
    }

    #[test]
    fn import_key_ids_follow_the_reserved_pattern() {
        for ok in ["frost-import-1220cb0e", "p1-frost-import-x", "frost-import-a_b-c"] {
            assert!(is_import_key_id(ok), "{ok}");
            assert!(is_reserved_for_import(ok));
        }
        for bad in ["frost-namespace", "frost-import-", "frost-import-a.b", "x frost-import-a", ""] {
            assert!(!is_import_key_id(bad), "{bad}");
        }
        assert!(!is_reserved_for_import("frost-namespace"));
        assert!(validate_ceremony_id("b2-2026_10").is_ok());
        assert!(validate_ceremony_id("").is_err());
        assert!(validate_ceremony_id("a/b").is_err());
    }
}

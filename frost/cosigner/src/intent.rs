// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Signing intents (audit C2): a client's signed authorization for one signature, verified by
//! **every** cosigner that takes part in it.
//!
//! Before this, a cosigner released a signature share for any 34-byte digest an allowlisted mesh
//! peer asked for, so one compromised cosigner (its share plus its `cosigner<N>` certificate) could
//! drive one honest peer through both rounds and aggregate a namespace signature over anything; and
//! approvals, rate limits and the journal lived only in the driver JVM, so a stolen driver
//! certificate bypassed all of them by calling the cluster directly.
//!
//! Now the driver signs a [`pb::SignIntent`] — cluster, key, the exact digest, a random request id,
//! a short validity, and the approvals its ApprovalGate collected — with its **mTLS leaf key**
//! (`"rutli-intent-v1\n" ‖ intent bytes`), and every participating node checks it itself
//! ([`IntentVerifier::verify`]):
//!
//! 1. the certificate chain verifies to the cluster CA (the same rule as split-ceremony requests,
//!    [`crate::request_auth::verify_chain`]); the leaf allows clientAuth; its CN is on this node's
//!    `signer_allowlist` (so a cosigner certificate can never sign one); its key is pinned if the
//!    CN has `signing_policy.signer_pins`;
//! 2. the signature;
//! 3. version, this node's cluster id, purpose `sign`, the key the round is for, a 34-byte digest,
//!    a 16-byte request id;
//! 4. `issued_at - skew <= now <= not_after + skew` and a lifetime within the configured maximum;
//! 5. the signer CN's key ACL (`signing_policy.signer_acl`);
//! 6. for a key an approval rule gates: at least `threshold` distinct configured approvers signed
//!    `requestId = hex(SHA-256(key_id ‖ SHA-256(digest) ‖ approval_nonce))` — byte for byte what the
//!    driver's `FileApprovalGate.requestIdFor` computes and `rutli-approve` signs.
//!
//! A leader or a peer can forward an intent but cannot mint or alter one: it holds no allowlisted
//! signer key. What a valid intent still allows a compromised node is re-using it, within its
//! validity, for another signature over the **same** digest — bounded by
//! `signing_policy.max_shares_per_request` and harmless.

use std::collections::{HashMap, HashSet};

use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
use base64::Engine;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::config::SigningPolicyConfig;
use crate::node::CeremonyKind;
use crate::pb;
use crate::{DaemonError, Result};

/// Domain separation: the intent signature can never be a TLS transcript, a split-ceremony request
/// or anything else the leaf key signs.
pub const INTENT_CONTEXT: &[u8] = b"rutli-intent-v1\n";
pub const INTENT_VERSION: u32 = 1;
pub const PURPOSE_SIGN: &str = "sign";
/// A hosted-key delete (audit M2): the intent names the key, its digest is [`delete_digest`].
pub const PURPOSE_DELETE_KEY: &str = "delete-key";
/// Domain separation of a delete intent's digest.
pub const DELETE_DIGEST_CONTEXT: &[u8] = b"rutli-delete-key-v1\n";
/// Sign round 1 for the split ceremony's `CeremonySignTest` (no intent; the node's own test digest).
pub const PURPOSE_SIGN_TEST: &str = "sign-test";
/// A ceremony intent for one DKG of `key_id` (see [`IntentVerifier::verify_ceremony`]).
pub const PURPOSE_DKG: &str = "dkg";
/// A ceremony intent for one share refresh of `key_id`.
pub const PURPOSE_REFRESH: &str = "refresh";
pub const REQUEST_ID_LEN: usize = 16;
/// Far above a real intent (a few hundred bytes plus approvals), small enough to bound the work a
/// hostile caller can make a node do before anything is verified.
pub const MAX_INTENT_BYTES: usize = 16 * 1024;

/// The digest a delete intent for `key_id` carries (and approvals of it are over):
/// SHA-256("rutli-delete-key-v1\n" ‖ key_id).
pub fn delete_digest(key_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DELETE_DIGEST_CONTEXT);
    h.update(key_id.as_bytes());
    h.finalize().into()
}

/// Whether a check of an intent's validity window applies in full ([`Expiry::Enforce`]: a live
/// request) or as of the delete ([`Expiry::Propagated`]: a tombstone a peer propagates days later,
/// whose intent expired long ago but was valid when the delete happened).
///
/// A propagated tombstone (audit F7) is accepted only if its deletion time lies within its
/// intent's validity window (skew included), and the intent was issued no earlier than this node
/// last saw its signer's delete capability change ([`DeleteGrants`]) — so an intent that was refused
/// when made (the driver signs one for every Canton `deleteKey`, normally without the delete role)
/// cannot be replayed into a delete once the role is granted later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    Enforce,
    Propagated { deleted_at_ms: u64 },
}

/// When this node last saw each delete-role CN's delete capability change (granted, its ACL, the
/// approval threshold or the approver set), from `data_dir/delete-policy.json` (audit F7). A CN
/// already on the role when the file was first written counts as "since 0" (no restriction: the
/// grant predates what this node can know, and a restored node must still receive the tombstones
/// it missed); every later change counts from the start that saw it.
#[derive(Clone, Debug, Default)]
pub struct DeleteGrants {
    since_ms: HashMap<String, u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct GrantsFile {
    #[serde(default)]
    signers: std::collections::BTreeMap<String, GrantEntry>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
struct GrantEntry {
    fingerprint: String,
    since_ms: u64,
}

impl DeleteGrants {
    /// Load `path`, compare every delete-role CN's capability fingerprint under `policy` and
    /// `approvers`, record what changed as of `now_ms`, and write the file back (atomically) if
    /// anything did.
    pub fn load_and_update(path: &std::path::Path, policy: &DeletePolicy, approvers: &SigningPolicyConfig, now_ms: u64) -> Result<Self> {
        let existing: Option<GrantsFile> = match std::fs::read(path) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes).map_err(|e| {
                DaemonError::Config(format!("{} does not parse ({e}) — move it aside to reset it", path.display()))
            })?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let first = existing.is_none();
        let old = existing.unwrap_or_default();
        let mut approver_keys: Vec<(String, String)> =
            approvers.approvers.iter().map(|a| (a.id.clone(), a.public_key_spki_b64.trim().to_string())).collect();
        approver_keys.sort();
        let mut new = GrantsFile::default();
        for cn in &policy.allowlist {
            let mut acl = policy.acl.get(cn).cloned();
            if let Some(a) = acl.as_mut() {
                a.sort();
            }
            let fingerprint = hex::encode(Sha256::digest(
                serde_json::to_vec(&(acl, policy.approval_threshold, &approver_keys)).expect("serializes"),
            ));
            let since_ms = match old.signers.get(cn) {
                Some(e) if e.fingerprint == fingerprint => e.since_ms,
                _ if first => 0,
                _ => now_ms,
            };
            new.signers.insert(cn.clone(), GrantEntry { fingerprint, since_ms });
        }
        if first || new.signers != old.signers {
            for (cn, e) in &new.signers {
                if e.since_ms == now_ms && !first {
                    tracing::warn!(
                        cn,
                        "hosted-key delete capability of this client changed: peers' tombstones whose delete \
                         intent it issued before now are no longer accepted by anti-entropy (re-issue such a delete)"
                    );
                }
            }
            let tmp = path.with_extension("json.tmp");
            {
                use std::io::Write;
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(&serde_json::to_vec_pretty(&new)?)?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, path)?;
            if let Some(dir) = path.parent() {
                std::fs::File::open(dir)?.sync_all()?;
            }
        }
        Ok(Self { since_ms: new.signers.into_iter().map(|(cn, e)| (cn, e.since_ms)).collect() })
    }

    /// For tests: explicit grant times.
    pub fn from_map(since_ms: HashMap<String, u64>) -> Self {
        Self { since_ms }
    }

    fn since(&self, cn: &str) -> u64 {
        self.since_ms.get(cn).copied().unwrap_or(0)
    }
}

/// Who may delete hosted keys (`hosted_keys.delete_*`): a role of its own, so the driver
/// certificate cannot delete unless an operator lists it.
#[derive(Clone, Debug, Default)]
pub struct DeletePolicy {
    /// `hosted_keys.delete_allowlist`. Empty: deletes are disabled.
    pub allowlist: HashSet<String>,
    /// `hosted_keys.delete_acl`: key-id prefixes per CN. A CN without an entry may delete any
    /// hosted key.
    pub acl: HashMap<String, Vec<String>>,
    /// `hosted_keys.delete_approval_threshold`: distinct `signing_policy.approvers` that must have
    /// approved the delete (0 = none).
    pub approval_threshold: u32,
}

impl DeletePolicy {
    pub fn from_config(h: &crate::config::HostedKeysConfig) -> Self {
        Self {
            allowlist: h.delete_allowlist.iter().cloned().collect(),
            acl: h.delete_acl.clone().into_iter().collect(),
            approval_threshold: h.delete_approval_threshold,
        }
    }
}

/// SHA-256 of the serialized intent: what round 1 binds the session to and round 2 presents.
pub fn intent_digest(signed: &pb::SignedIntent) -> [u8; 32] {
    Sha256::digest(&signed.intent).into()
}

/// The approval request id for (`key_id`, `digest`, `nonce`): `hex(SHA-256(key_id ‖ SHA-256(digest)
/// ‖ nonce))`, exactly the driver's `FileApprovalGate.requestIdFor(keyId, sha256(data), nonce)`.
/// Approvers sign its UTF-8 bytes.
pub fn approval_request_id(key_id: &str, digest: &[u8], nonce: &[u8]) -> String {
    let op_digest: [u8; 32] = Sha256::digest(digest).into();
    let mut h = Sha256::new();
    h.update(key_id.as_bytes());
    h.update(op_digest);
    h.update(nonce);
    hex::encode(h.finalize())
}

/// What a delete approval's request id names instead of the bare key id (audit F6): `delete:` and
/// the key. Key ids never contain `:`, so no sign approval's request id is ever a delete's — an
/// approver shown a "sign" request cannot be approving a delete — and `rutli-approve` reads the
/// operation out of the very field the request id is computed over.
pub const DELETE_APPROVAL_KEY_PREFIX: &str = "delete:";

/// The approval request id of a delete of hosted key `key_id`:
/// [`approval_request_id`]`("delete:" ‖ key_id, delete_digest, nonce)`. Sign approvals keep the
/// driver's format unchanged.
pub fn delete_approval_request_id(key_id: &str, delete_digest: &[u8], nonce: &[u8]) -> String {
    approval_request_id(&format!("{DELETE_APPROVAL_KEY_PREFIX}{key_id}"), delete_digest, nonce)
}

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE { SEQUENCE { 1.3.101.112 },
/// BIT STRING 0x00 ‖ key }.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The raw 32-byte Ed25519 key of an approver, from the base64 DER SubjectPublicKeyInfo the
/// driver's approval policy also uses.
pub fn ed25519_key_from_spki_b64(b64: &str) -> std::result::Result<[u8; 32], String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| "not base64".to_string())?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return Err("not an Ed25519 SubjectPublicKeyInfo (44 bytes DER)".into());
    }
    Ok(der[12..].try_into().expect("32 bytes"))
}

/// Sign `intent` with `signer` (an mTLS identity): what the driver does with its own key. For
/// tests and tools; the driver has its own implementation (FrostBackend, Scala).
pub fn sign_intent(signer: &crate::request_auth::NodeSigner, intent: &pb::SignIntent) -> Result<pb::SignedIntent> {
    let bytes = intent.encode_to_vec();
    let mut msg = INTENT_CONTEXT.to_vec();
    msg.extend_from_slice(&bytes);
    Ok(pb::SignedIntent {
        intent: bytes,
        signature_alg: signer.signature_alg().to_string(),
        signature: signer.sign_bytes(&msg)?,
        signer_chain: signer.chain_der().to_vec(),
    })
}

/// The intent purpose of a ceremony kind (`dkg` / `refresh`): the same words as the kind.
pub fn ceremony_purpose(kind: CeremonyKind) -> &'static str {
    match kind {
        CeremonyKind::Dkg => PURPOSE_DKG,
        CeremonyKind::Refresh => PURPOSE_REFRESH,
    }
}

/// The ceremony id a ceremony intent names: `<kind>-<hex(request_id)>` (e.g. `refresh-0101…`).
/// One intent therefore names exactly one ceremony id on every node, and ceremony ids are used
/// once per node (durable ceremony records) — so one intent runs at most one ceremony.
pub fn ceremony_id_for(kind: CeremonyKind, request_id: &[u8; REQUEST_ID_LEN]) -> String {
    format!("{}-{}", kind.as_str(), hex::encode(request_id))
}

/// The ceremony id `signed` names for `kind`, from its request id — **unverified**: what a leader
/// uses to name the ceremony it runs for a client. Every node verifies the intent and the binding
/// itself ([`IntentVerifier::verify_ceremony`]), so a leader that derives another id is refused.
pub fn ceremony_id_of(signed: &pb::SignedIntent, kind: CeremonyKind) -> Result<String> {
    if signed.intent.is_empty() || signed.intent.len() > MAX_INTENT_BYTES {
        return Err(refused_ceremony("malformed", format!("intent of {} bytes", signed.intent.len())));
    }
    let intent = pb::SignIntent::decode(signed.intent.as_slice())
        .map_err(|e| refused_ceremony("malformed", format!("intent does not decode: {e}")))?;
    let request_id: [u8; REQUEST_ID_LEN] = intent
        .request_id
        .as_slice()
        .try_into()
        .map_err(|_| refused_ceremony("malformed", format!("request id of {} bytes", intent.request_id.len())))?;
    Ok(ceremony_id_for(kind, &request_id))
}

/// Which role a ceremony intent's signer acted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyRole {
    /// `signer_allowlist` (the driver): any DKG, or a refresh while `signer_may_refresh`; both
    /// under its `signer_acl`.
    Signer,
    /// `refresh_allowlist`: refreshes only, no key ACL (as on `Signer.Refresh`).
    Refresher,
}

/// A ceremony intent this node verified ([`IntentVerifier::verify_ceremony`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCeremony {
    pub kind: CeremonyKind,
    pub key_id: String,
    /// `<kind>-<hex(request_id)>`.
    pub ceremony_id: String,
    pub request_id: [u8; REQUEST_ID_LEN],
    pub signer_cn: String,
    pub signer_spki_sha256: [u8; 32],
    pub role: CeremonyRole,
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
}

/// An intent this node verified, with what the rest of the signature needs from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIntent {
    /// SHA-256 of the intent bytes ([`intent_digest`]).
    pub digest: [u8; 32],
    pub key_id: String,
    /// The 34-byte digest the signature is over.
    pub message: Vec<u8>,
    pub request_id: [u8; REQUEST_ID_LEN],
    pub signer_cn: String,
    pub signer_spki_sha256: [u8; 32],
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
    /// The approvers whose signatures counted (gated keys only), sorted.
    pub approvers: Vec<String>,
}

/// The mTLS identity of a Signer API caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub cn: String,
    /// SHA-256 of its certificate's SubjectPublicKeyInfo.
    pub spki_sha256: [u8; 32],
}

impl Caller {
    /// The caller of a request, from its leaf certificate (DER). `None` without one.
    pub fn from_leaf_der(der: &[u8]) -> Option<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        Some(Self {
            cn: crate::tls::subject_cn(&cert)?,
            spki_sha256: Sha256::digest(cert.public_key().raw).into(),
        })
    }
}

/// This node's client policy: who may sign intents and with which key, for which keys, with
/// which approvals, under which cluster id and clock rules.
pub struct IntentVerifier {
    /// The cluster CA file (`tls.ca_cert`) bytes: the trust anchors an intent's chain must reach.
    ca_pem: Vec<u8>,
    allow_expired_ca: bool,
    cluster_id: String,
    /// `signer_allowlist`.
    signers: HashSet<String>,
    /// `refresh_allowlist` (top-level config): who may sign a refresh ceremony intent besides the
    /// signer role while `signer_may_refresh`.
    refreshers: HashSet<String>,
    acl: HashMap<String, Vec<String>>,
    acl_required: bool,
    pins: HashMap<String, Vec<[u8; 32]>>,
    max_lifetime_ms: u64,
    skew_ms: u64,
    approvers: HashMap<String, [u8; 32]>,
    policy: SigningPolicyConfig,
    delete: DeletePolicy,
    delete_grants: DeleteGrants,
}

impl IntentVerifier {
    /// Build from the node's configuration. `ca_pem` is the `tls.ca_cert` file; `signers` the
    /// `signer_allowlist`.
    pub fn new(
        ca_pem: Vec<u8>,
        allow_expired_ca: bool,
        cluster_id: String,
        signers: impl IntoIterator<Item = String>,
        policy: &SigningPolicyConfig,
    ) -> Result<Self> {
        let approvers = policy
            .approvers
            .iter()
            .map(|a| {
                ed25519_key_from_spki_b64(&a.public_key_spki_b64)
                    .map(|k| (a.id.clone(), k))
                    .map_err(|e| DaemonError::Config(format!("approver {}: {e}", a.id)))
            })
            .collect::<Result<_>>()?;
        let pins = policy
            .signer_pins
            .keys()
            .map(|cn| (cn.clone(), policy.pins_for(cn).unwrap_or_default()))
            .collect();
        Ok(Self {
            ca_pem,
            allow_expired_ca,
            cluster_id,
            signers: signers.into_iter().collect(),
            refreshers: HashSet::new(),
            acl: policy.signer_acl.clone().into_iter().collect(),
            acl_required: policy.signer_acl_required,
            pins,
            max_lifetime_ms: policy.intent_max_lifetime_secs.saturating_mul(1000),
            skew_ms: policy.clock_skew_secs.saturating_mul(1000),
            approvers,
            policy: policy.clone(),
            delete: DeletePolicy::default(),
            delete_grants: DeleteGrants::default(),
        })
    }

    /// The refresher role (`refresh_allowlist`): CNs that may sign refresh ceremony intents.
    pub fn with_refreshers(mut self, refreshers: impl IntoIterator<Item = String>) -> Self {
        self.refreshers = refreshers.into_iter().collect();
        self
    }

    /// Who may delete hosted keys ([`DeletePolicy`]).
    pub fn with_delete_policy(mut self, delete: DeletePolicy) -> Self {
        self.delete = delete;
        self
    }

    /// When each delete-role CN's capability last changed ([`DeleteGrants`]).
    pub fn with_delete_grants(mut self, grants: DeleteGrants) -> Self {
        self.delete_grants = grants;
        self
    }

    /// Who may delete hosted keys here.
    pub fn delete_policy(&self) -> &DeletePolicy {
        &self.delete
    }

    /// Whether any client may delete hosted keys here.
    pub fn deletes_enabled(&self) -> bool {
        !self.delete.allowlist.is_empty()
    }

    /// Is `cn` on the delete role?
    pub fn may_delete(&self, cn: &str) -> bool {
        self.delete.allowlist.contains(cn)
    }

    /// The clock skew allowance, in milliseconds.
    pub fn skew_ms(&self) -> u64 {
        self.skew_ms
    }

    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub fn policy(&self) -> &SigningPolicyConfig {
        &self.policy
    }

    /// The key ACL: may client `cn` use `key_id`? A CN without an entry may use every key unless
    /// `signer_acl_required` (counted, so an operator sees the ACL is not doing anything yet).
    pub fn check_acl(&self, cn: &str, key_id: &str) -> Result<()> {
        self.check_acl_with(cn, key_id, refused)
    }

    fn check_acl_with(&self, cn: &str, key_id: &str, refused: fn(&'static str, String) -> DaemonError) -> Result<()> {
        match self.acl.get(cn) {
            Some(prefixes) if prefixes.iter().any(|p| key_id.starts_with(p.as_str())) => Ok(()),
            Some(_) => Err(refused(
                "acl",
                format!("client {cn:?} may not use key {key_id} (signing_policy.signer_acl)"),
            )),
            None if self.acl_required => Err(refused(
                "acl",
                format!(
                    "client {cn:?} has no signing_policy.signer_acl entry and signer_acl_required is set"
                ),
            )),
            None => {
                metrics::counter!(crate::metrics::SIGNER_ACL_ABSENT).increment(1);
                Ok(())
            }
        }
    }

    /// The SPKI pins: a pinned CN acts only with a pinned key.
    pub fn check_pin(&self, cn: &str, spki_sha256: &[u8; 32]) -> Result<()> {
        self.check_pin_with(cn, spki_sha256, refused)
    }

    /// [`IntentVerifier::check_pin`], refused (and counted) as `refused` says: a delete or a
    /// ceremony intent's pin refusal is that kind's refusal, not a signing-policy one.
    fn check_pin_with(
        &self,
        cn: &str,
        spki_sha256: &[u8; 32],
        refused: fn(&'static str, String) -> DaemonError,
    ) -> Result<()> {
        match self.pins.get(cn) {
            Some(pins) if !pins.contains(spki_sha256) => Err(refused(
                "pin",
                format!(
                    "the certificate key of {cn:?} (spki sha256 {}) is not pinned in \
                     signing_policy.signer_pins — revoked or not yet rolled out",
                    hex::encode(spki_sha256)
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Who signed `signed`, checked: a client certificate of this cluster, its CN accepted by
    /// `role` (`Err` names why not), its key pinned if the CN is, and the signature over exactly
    /// the intent bytes. Then the decoded intent, of this version and cluster.
    fn verify_signer(
        &self,
        signed: &pb::SignedIntent,
        role: impl Fn(&str) -> std::result::Result<(), String>,
        refuse: fn(&'static str, String) -> DaemonError,
    ) -> Result<(String, [u8; 32], pb::SignIntent)> {
        if signed.intent.is_empty() || signed.intent.len() > MAX_INTENT_BYTES {
            return Err(refuse("malformed", format!("intent of {} bytes", signed.intent.len())));
        }
        let leaf = crate::request_auth::verify_chain(&signed.signer_chain, &self.ca_pem, self.allow_expired_ca)
            .map_err(|e| refuse("certificate", format!("certificate: {e}")))?;
        if leaf.client_auth == Some(false) {
            return Err(refuse(
                "certificate",
                "the signing certificate's extendedKeyUsage lacks clientAuth".into(),
            ));
        }
        let cn = leaf.cn.clone().ok_or_else(|| refuse("certificate", "the signing certificate has no CN".into()))?;
        role(&cn).map_err(|why| refuse("signer", why))?;
        self.check_pin_with(&cn, &leaf.spki_sha256, refuse)?;
        let mut msg = Vec::with_capacity(INTENT_CONTEXT.len() + signed.intent.len());
        msg.extend_from_slice(INTENT_CONTEXT);
        msg.extend_from_slice(&signed.intent);
        leaf.verify(&signed.signature_alg, &msg, &signed.signature)
            .map_err(|e| refuse("signature", e.replace("{signer}", &format!("by {cn:?}"))))?;
        let intent = pb::SignIntent::decode(signed.intent.as_slice())
            .map_err(|e| refuse("malformed", format!("intent does not decode: {e}")))?;
        if intent.version != INTENT_VERSION {
            return Err(refuse("malformed", format!("intent version {} (this node knows 1)", intent.version)));
        }
        if intent.cluster_id != self.cluster_id {
            return Err(refuse(
                "cluster",
                format!("intent is for cluster {:?}, this is {}", intent.cluster_id, self.cluster_id),
            ));
        }
        Ok((cn, leaf.spki_sha256, intent))
    }

    /// Verify a hosted-key delete intent for `key_id` at `now_ms` (audit M2): signed by a client on
    /// the delete role (`hosted_keys.delete_allowlist`, never merely the signer role), for this
    /// cluster, purpose `delete-key`, this key and its [`delete_digest`], within its validity
    /// (or, for [`Expiry::Propagated`], as of the delete — see there), the delete ACL, and the delete
    /// approvals. Every failure is [`DaemonError::PolicyRefused`].
    pub fn verify_delete(&self, signed: &pb::SignedIntent, key_id: &str, now_ms: u64, expiry: Expiry) -> Result<VerifiedIntent> {
        if !self.deletes_enabled() {
            return Err(refused_delete(
                "disabled",
                "hosted-key deletes are disabled on this node (hosted_keys.delete_allowlist is empty)".into(),
            ));
        }
        let (cn, spki, intent) = self.verify_signer(
            signed,
            |cn| {
                if self.may_delete(cn) {
                    Ok(())
                } else {
                    Err(format!("signed by {cn:?}, which is not on this node's hosted_keys.delete_allowlist"))
                }
            },
            refused_delete,
        )?;
        if intent.purpose != PURPOSE_DELETE_KEY {
            return Err(refused_delete("purpose", format!("intent purpose {:?}, expected \"delete-key\"", intent.purpose)));
        }
        if intent.key_id != key_id {
            return Err(refused_delete("key", format!("intent deletes {}, not {key_id}", intent.key_id)));
        }
        if intent.digest != delete_digest(key_id) {
            return Err(refused_delete("malformed", "intent digest is not the delete digest of the key".into()));
        }
        let request_id: [u8; REQUEST_ID_LEN] = intent
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| refused_delete("malformed", format!("request id of {} bytes", intent.request_id.len())))?;
        match expiry {
            Expiry::Enforce => self.check_times_with(intent.issued_at_ms, intent.not_after_ms, now_ms, refused_delete)?,
            // Long expired is fine for a propagated tombstone; a validity window that was never
            // acceptable, an issue time in the future, or a deletion outside the window is not.
            Expiry::Propagated { deleted_at_ms } => {
                if intent.not_after_ms < intent.issued_at_ms
                    || intent.not_after_ms - intent.issued_at_ms > self.max_lifetime_ms
                    || intent.issued_at_ms > now_ms.saturating_add(self.skew_ms)
                {
                    return Err(refused_delete("expiry", "the intent's validity window is not acceptable".into()));
                }
                if deleted_at_ms.saturating_add(self.skew_ms) < intent.issued_at_ms
                    || deleted_at_ms > intent.not_after_ms.saturating_add(self.skew_ms)
                    || deleted_at_ms > now_ms.saturating_add(self.skew_ms)
                {
                    return Err(refused_delete(
                        "expiry",
                        format!(
                            "the tombstone says {key_id} was deleted at {deleted_at_ms} ms, outside its delete intent's \
                             validity [{}, {}] ms",
                            intent.issued_at_ms, intent.not_after_ms
                        ),
                    ));
                }
                let since = self.delete_grants.since(&cn);
                if intent.issued_at_ms.saturating_add(self.skew_ms) < since {
                    return Err(refused_delete(
                        "policy-changed",
                        format!(
                            "the delete intent for {key_id} was issued at {} ms, before this node's delete policy \
                             for {cn:?} last changed ({since} ms) — a tombstone from before that change is not \
                             accepted from peers; re-issue the delete if it is still wanted",
                            intent.issued_at_ms
                        ),
                    ));
                }
            }
        }
        match self.delete.acl.get(&cn) {
            Some(prefixes) if !prefixes.iter().any(|p| key_id.starts_with(p.as_str())) => {
                return Err(refused_delete(
                    "acl",
                    format!("client {cn:?} may not delete {key_id} (hosted_keys.delete_acl)"),
                ))
            }
            _ => {}
        }
        let approvers = match self.delete.approval_threshold {
            0 => Vec::new(),
            t => {
                let request_id = delete_approval_request_id(&intent.key_id, &intent.digest, &intent.approval_nonce);
                self.count_approvals(&intent, &request_id, t, refused_delete)?
            }
        };
        Ok(VerifiedIntent {
            digest: intent_digest(signed),
            key_id: intent.key_id,
            message: intent.digest,
            request_id,
            signer_cn: cn,
            signer_spki_sha256: spki,
            issued_at_ms: intent.issued_at_ms,
            not_after_ms: intent.not_after_ms,
            approvers,
        })
    }

    /// Verify a ceremony intent (DKG or refresh) at `now_ms`: signed by a client in the role the
    /// kind needs — **dkg**: the signer role (`signer_allowlist`); **refresh**: the refresher role
    /// (`refresh_allowlist`), or the signer role while `signing_policy.signer_may_refresh` — so an
    /// operator-only or cosigner certificate never can; its key pinned if the CN is; for this
    /// cluster, purpose == `kind`, this key, no digest and no approvals, a 16-byte request id,
    /// within its validity; the signer's `signer_acl` (signer role only, as on `Signer.Refresh`);
    /// and `ceremony_id` exactly the id the intent names ([`ceremony_id_for`]). Every failure is
    /// [`DaemonError::PolicyRefused`], counted in `rutli_ceremony_intent_refusals_total{reason}`.
    pub fn verify_ceremony(
        &self,
        signed: &pb::SignedIntent,
        kind: CeremonyKind,
        key_id: &str,
        ceremony_id: &str,
        now_ms: u64,
    ) -> Result<VerifiedCeremony> {
        let signer_may_refresh = self.policy.signer_may_refresh;
        let mut role = CeremonyRole::Signer;
        let (cn, spki, intent) = self.verify_signer(
            signed,
            |cn| match kind {
                CeremonyKind::Dkg if self.signers.contains(cn) => Ok(()),
                CeremonyKind::Dkg => {
                    Err(format!("DKG intent signed by {cn:?}, which is not on this node's signer_allowlist"))
                }
                CeremonyKind::Refresh if self.refreshers.contains(cn) => Ok(()),
                CeremonyKind::Refresh if self.signers.contains(cn) && signer_may_refresh => Ok(()),
                CeremonyKind::Refresh if self.signers.contains(cn) => Err(format!(
                    "refresh intent signed by {cn:?}: only the refresher role (refresh_allowlist) may \
                     refresh, signing_policy.signer_may_refresh is off"
                )),
                CeremonyKind::Refresh => Err(format!(
                    "refresh intent signed by {cn:?}, which is on neither this node's refresh_allowlist \
                     nor (with signer_may_refresh) its signer_allowlist"
                )),
            },
            refused_ceremony,
        )?;
        if kind == CeremonyKind::Refresh && self.refreshers.contains(&cn) {
            role = CeremonyRole::Refresher;
        }
        let purpose = ceremony_purpose(kind);
        if intent.purpose != purpose {
            return Err(refused_ceremony(
                "purpose",
                format!("intent purpose {:?}, expected {purpose:?}", intent.purpose),
            ));
        }
        if intent.key_id != key_id {
            return Err(refused_ceremony(
                "key",
                format!("intent is for key {}, the ceremony is for {key_id}", intent.key_id),
            ));
        }
        if !intent.digest.is_empty() || !intent.approval_nonce.is_empty() || !intent.approvals.is_empty() {
            return Err(refused_ceremony(
                "malformed",
                "a ceremony intent carries no digest and no approvals".into(),
            ));
        }
        let request_id: [u8; REQUEST_ID_LEN] = intent
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| refused_ceremony("malformed", format!("request id of {} bytes", intent.request_id.len())))?;
        self.check_times_with(intent.issued_at_ms, intent.not_after_ms, now_ms, refused_ceremony)?;
        if role == CeremonyRole::Signer {
            self.check_acl_with(&cn, key_id, refused_ceremony)?;
        }
        let named = ceremony_id_for(kind, &request_id);
        if ceremony_id != named {
            return Err(refused_ceremony(
                "ceremony-id",
                format!("the intent names ceremony {named}, the leader runs {ceremony_id}"),
            ));
        }
        Ok(VerifiedCeremony {
            kind,
            key_id: intent.key_id,
            ceremony_id: named,
            request_id,
            signer_cn: cn,
            signer_spki_sha256: spki,
            role,
            issued_at_ms: intent.issued_at_ms,
            not_after_ms: intent.not_after_ms,
        })
    }

    /// Verify `signed` for a signature with `key_id` at `now_ms` (Unix epoch milliseconds). Every
    /// failure is [`DaemonError::PolicyRefused`].
    pub fn verify(&self, signed: &pb::SignedIntent, key_id: &str, now_ms: u64) -> Result<VerifiedIntent> {
        // 1–2. Who signed it (a client certificate of this cluster on the signer allowlist) and
        // the signature, over exactly these bytes; version and cluster.
        let (cn, spki, intent) = self.verify_signer(
            signed,
            |cn| {
                if self.signers.contains(cn) {
                    Ok(())
                } else {
                    Err(format!("signed by {cn:?}, which is not on this node's signer_allowlist"))
                }
            },
            refused,
        )?;
        // 3. What it authorizes.
        if intent.purpose != PURPOSE_SIGN {
            return Err(refused("purpose", format!("intent purpose {:?}, expected \"sign\"", intent.purpose)));
        }
        if intent.key_id != key_id {
            return Err(refused("key", format!("intent is for key {}, the round is for {key_id}", intent.key_id)));
        }
        if intent.digest.len() != crate::orchestrator::CANTON_DIGEST_LEN {
            return Err(refused("malformed", format!("intent digest of {} bytes", intent.digest.len())));
        }
        let request_id: [u8; REQUEST_ID_LEN] = intent
            .request_id
            .as_slice()
            .try_into()
            .map_err(|_| refused("malformed", format!("request id of {} bytes", intent.request_id.len())))?;
        // 4. When.
        self.check_times(intent.issued_at_ms, intent.not_after_ms, now_ms)?;
        // 5. Which keys this client may use.
        self.check_acl(&cn, key_id)?;
        // 6. Approvals, for a gated key.
        let approvers = match self.policy.approval_threshold_for(key_id) {
            None => Vec::new(),
            Some(threshold) => {
                let request_id = approval_request_id(&intent.key_id, &intent.digest, &intent.approval_nonce);
                self.count_approvals(&intent, &request_id, threshold, refused)?
            }
        };
        Ok(VerifiedIntent {
            digest: intent_digest(signed),
            key_id: intent.key_id,
            message: intent.digest,
            request_id,
            signer_cn: cn,
            signer_spki_sha256: spki,
            issued_at_ms: intent.issued_at_ms,
            not_after_ms: intent.not_after_ms,
            approvers,
        })
    }

    /// Round 2's re-check of a verified intent: still within its validity (skew included).
    pub fn check_live(&self, v: &VerifiedIntent, now_ms: u64) -> Result<()> {
        self.check_times(v.issued_at_ms, v.not_after_ms, now_ms)
    }

    fn check_times(&self, issued_at_ms: u64, not_after_ms: u64, now_ms: u64) -> Result<()> {
        self.check_times_with(issued_at_ms, not_after_ms, now_ms, refused)
    }

    fn check_times_with(
        &self,
        issued_at_ms: u64,
        not_after_ms: u64,
        now_ms: u64,
        refused: fn(&'static str, String) -> DaemonError,
    ) -> Result<()> {
        if not_after_ms < issued_at_ms || not_after_ms - issued_at_ms > self.max_lifetime_ms {
            return Err(refused(
                "expiry",
                format!(
                    "intent validity {} ms exceeds signing_policy.intent_max_lifetime_secs ({} s) or is negative",
                    not_after_ms as i128 - issued_at_ms as i128,
                    self.max_lifetime_ms / 1000
                ),
            ));
        }
        if now_ms.saturating_add(self.skew_ms) < issued_at_ms {
            return Err(refused(
                "expiry",
                format!(
                    "intent issued {} ms in the future (clock skew beyond {} s — check NTP on the driver and this node)",
                    issued_at_ms - now_ms,
                    self.skew_ms / 1000
                ),
            ));
        }
        if now_ms > not_after_ms.saturating_add(self.skew_ms) {
            return Err(refused(
                "expiry",
                format!("intent expired {} ms ago", now_ms - not_after_ms),
            ));
        }
        Ok(())
    }

    /// The distinct configured approvers with a valid signature over `request_id` (the intent's
    /// approval request id for its purpose); refused below `threshold`.
    fn count_approvals(
        &self,
        intent: &pb::SignIntent,
        request_id: &str,
        threshold: u32,
        refused: fn(&'static str, String) -> DaemonError,
    ) -> Result<Vec<String>> {
        let mut valid: Vec<String> = intent
            .approvals
            .iter()
            .filter(|a| {
                self.approvers.get(&a.approver_id).is_some_and(|key| {
                    UnparsedPublicKey::new(&ED25519, key).verify(request_id.as_bytes(), &a.signature).is_ok()
                })
            })
            .map(|a| a.approver_id.clone())
            .collect();
        valid.sort();
        valid.dedup();
        if intent.approval_nonce.is_empty() || (valid.len() as u32) < threshold {
            return Err(refused(
                "approval",
                format!(
                    "approval required: key {} needs {threshold} approval(s) by distinct configured \
                     approvers (signing_policy.rules, hosted_keys.delete_approval_threshold), the intent carries {} valid",
                    intent.key_id,
                    valid.len()
                ),
            ));
        }
        Ok(valid)
    }
}

/// A policy refusal, counted by reason.
pub fn refused(reason: &'static str, msg: String) -> DaemonError {
    metrics::counter!(crate::metrics::SIGN_POLICY_REFUSALS, "reason" => reason).increment(1);
    DaemonError::PolicyRefused(format!("signing intent refused: {msg}"))
}

/// A delete-intent refusal, counted by reason (`rutli_delete_intent_refusals_total`).
pub fn refused_delete(reason: &'static str, msg: String) -> DaemonError {
    metrics::counter!(crate::metrics::DELETE_INTENT_REFUSALS, "reason" => reason).increment(1);
    DaemonError::PolicyRefused(format!("delete intent refused: {msg}"))
}

/// A ceremony-intent refusal, counted by reason (`rutli_ceremony_intent_refusals_total`).
pub fn refused_ceremony(reason: &'static str, msg: String) -> DaemonError {
    metrics::counter!(crate::metrics::CEREMONY_INTENT_REFUSALS, "reason" => reason).increment(1);
    DaemonError::PolicyRefused(format!("ceremony intent refused: {msg}"))
}

/// A ceremony intent for `kind` of `key_id`, unsigned: version 1, `cluster_id`, purpose = kind,
/// `request_id`, valid from `issued_at_ms` for `lifetime_ms`. What the driver
/// (`FrostIntentSigner.ceremonyIntent`) and `rutli-cosigner refresh` build.
pub fn ceremony_intent(
    cluster_id: &str,
    kind: CeremonyKind,
    key_id: &str,
    request_id: [u8; REQUEST_ID_LEN],
    issued_at_ms: u64,
    lifetime_ms: u64,
) -> pb::SignIntent {
    pb::SignIntent {
        version: INTENT_VERSION,
        cluster_id: cluster_id.to_string(),
        purpose: ceremony_purpose(kind).to_string(),
        key_id: key_id.to_string(),
        request_id: request_id.to_vec(),
        issued_at_ms,
        not_after_ms: issued_at_ms.saturating_add(lifetime_ms),
        ..Default::default()
    }
}

/// The cluster id a client believes from its roster's `Capabilities.cluster_id` answers (empty
/// ones ignored): the value at least two answers agree on (the lone node of a one-node roster
/// counts alone) and that more answers report than any other value — the driver's rule (audit F5),
/// so one compromised or misconfigured cosigner cannot set the id its honest peers then refuse.
pub fn agree_on_cluster_id(answers: &[String], roster_len: usize) -> Option<String> {
    let required = if roster_len <= 1 { 1 } else { 2 };
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for a in answers.iter().filter(|a| !a.is_empty()) {
        *counts.entry(a.as_str()).or_default() += 1;
    }
    let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
    ranked.sort_by_key(|r| std::cmp::Reverse(r.1));
    match ranked.as_slice() {
        [(id, n), rest @ ..] if *n >= required && rest.first().is_none_or(|(_, m)| m < n) => Some(id.to_string()),
        _ => None,
    }
}

/// A fresh random request id.
pub fn new_request_id() -> [u8; REQUEST_ID_LEN] {
    let mut id = [0u8; REQUEST_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    id
}

/// Now, in Unix epoch milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parity with the driver: `FileApprovalGate.requestIdFor("participant1-frost-namespace",
    /// sha256(0x1220 ‖ 32×0xab), 16×0x01)`. The Scala side pins the same vector
    /// (ApprovalGateSpec, "requestIdFor matches the cosigner's golden vector").
    #[test]
    fn the_approval_request_id_matches_the_drivers_golden_vector() {
        let mut digest = vec![0x12, 0x20];
        digest.extend_from_slice(&[0xab; 32]);
        let id = approval_request_id("participant1-frost-namespace", &digest, &[0x01; 16]);
        assert_eq!(id, GOLDEN_REQUEST_ID);
    }

    /// The vector both test trees pin (see the test above).
    pub const GOLDEN_REQUEST_ID: &str = "e51b7d9a70d36a6b10e31ab7cf1da987175195c3862bf25f43f2a33a27a096cf";

    /// Audit F6: a delete approval's request id is domain-separated from every sign approval's —
    /// the key field carries `delete:` — while the sign format stays the driver's (golden vector
    /// above). ApprovalGateSpec pins the same delete vector on the approver side.
    #[test]
    fn delete_approvals_are_domain_separated_from_sign_approvals() {
        let key = "participant1-rutli-enc-golden";
        let digest = delete_digest(key);
        let nonce = [0x02; 16];
        let delete = delete_approval_request_id(key, &digest, &nonce);
        assert_eq!(delete, approval_request_id("delete:participant1-rutli-enc-golden", &digest, &nonce));
        assert_ne!(delete, approval_request_id(key, &digest, &nonce), "never the sign id over the same digest");
        assert_eq!(delete, GOLDEN_DELETE_REQUEST_ID);
    }

    pub const GOLDEN_DELETE_REQUEST_ID: &str = "5d1234a946bdaaad6c6103902b7fa4b6a92468e9dba71346504832a6f6335c1a";

    /// Audit F7: the grant ledger counts a CN present at first write as "since 0", every later
    /// change of its delete capability (granted, ACL, threshold, approvers) from the start that saw
    /// it, and forgets a CN removed from the role (a re-grant is a change).
    #[test]
    fn delete_grants_record_when_a_capability_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("delete-policy.json");
        let cfg = SigningPolicyConfig::default();
        let policy = |cns: &[&str], threshold: u32| DeletePolicy {
            allowlist: cns.iter().map(|c| c.to_string()).collect(),
            acl: HashMap::new(),
            approval_threshold: threshold,
        };
        let g = DeleteGrants::load_and_update(&path, &policy(&["operator"], 0), &cfg, 100).unwrap();
        assert_eq!(g.since("operator"), 0, "present at first write");
        let g = DeleteGrants::load_and_update(&path, &policy(&["operator"], 0), &cfg, 200).unwrap();
        assert_eq!(g.since("operator"), 0, "unchanged");
        let g = DeleteGrants::load_and_update(&path, &policy(&["operator", "driver"], 0), &cfg, 300).unwrap();
        assert_eq!((g.since("operator"), g.since("driver")), (0, 300), "a grant");
        let g = DeleteGrants::load_and_update(&path, &policy(&["operator", "driver"], 1), &cfg, 400).unwrap();
        assert_eq!((g.since("operator"), g.since("driver")), (400, 400), "the threshold changed for everyone");
        let mut acl = policy(&["operator", "driver"], 1);
        acl.acl.insert("driver".into(), vec!["rutli-a-".into()]);
        let g = DeleteGrants::load_and_update(&path, &acl, &cfg, 500).unwrap();
        assert_eq!((g.since("operator"), g.since("driver")), (400, 500), "an ACL change");
        DeleteGrants::load_and_update(&path, &policy(&["operator"], 1), &cfg, 600).unwrap();
        let g = DeleteGrants::load_and_update(&path, &acl, &cfg, 700).unwrap();
        assert_eq!(g.since("driver"), 700, "removed, then granted again");
        std::fs::write(&path, b"{ torn").unwrap();
        assert!(DeleteGrants::load_and_update(&path, &acl, &cfg, 800).is_err(), "never silently reset");
    }

    /// Parity with the driver: `FrostIntentSigner.ceremonyIntent("c2testcluster000", "refresh",
    /// "participant1-frost-golden", 16×0x01, 1_700_000_000_000, 120_000)` serializes to exactly these
    /// bytes, and `FrostIntentSigner.ceremonyId` names the same ceremony (FrostSigningIntentSpec
    /// pins both). The cosigners verify the signature over these bytes, so any serialization
    /// difference would be a refusal, not a silent mismatch — this pins the field layout.
    #[test]
    fn ceremony_intents_match_the_drivers_golden_vector() {
        let rid = [0x01; REQUEST_ID_LEN];
        let refresh =
            ceremony_intent("c2testcluster000", CeremonyKind::Refresh, "participant1-frost-golden", rid, 1_700_000_000_000, 120_000);
        assert_eq!(hex::encode(refresh.encode_to_vec()), GOLDEN_REFRESH_INTENT);
        assert_eq!(ceremony_id_for(CeremonyKind::Refresh, &rid), "refresh-01010101010101010101010101010101");
        let dkg = ceremony_intent("c2testcluster000", CeremonyKind::Dkg, "participant1-frost-golden", rid, 1_700_000_000_000, 120_000);
        assert_eq!(hex::encode(dkg.encode_to_vec()), GOLDEN_DKG_INTENT);
        assert_eq!(ceremony_id_for(CeremonyKind::Dkg, &rid), "dkg-01010101010101010101010101010101");
        // Every derived id is a valid ceremony id (charset, length).
        crate::keystore::validate_ceremony_id(&ceremony_id_for(CeremonyKind::Refresh, &[0xff; REQUEST_ID_LEN])).unwrap();
    }

    pub const GOLDEN_REFRESH_INTENT: &str = "08011210633274657374636c75737465723030301a077265667265736822197061727469636970616e74312d66726f73742d676f6c64656e3210010101010101010101010101010101013880d095ffbc3140c0f99cffbc31";
    pub const GOLDEN_DKG_INTENT: &str = "08011210633274657374636c75737465723030301a03646b6722197061727469636970616e74312d66726f73742d676f6c64656e3210010101010101010101010101010101013880d095ffbc3140c0f99cffbc31";

    /// The leader names the ceremony from the (unverified) intent; a malformed one is refused.
    #[test]
    fn the_leader_derives_the_ceremony_id_from_the_intent() {
        let i = ceremony_intent("c", CeremonyKind::Dkg, "k", [0xab; REQUEST_ID_LEN], 1, 2);
        let signed = pb::SignedIntent { intent: i.encode_to_vec(), ..Default::default() };
        assert_eq!(ceremony_id_of(&signed, CeremonyKind::Dkg).unwrap(), format!("dkg-{}", "ab".repeat(16)));
        assert_eq!(ceremony_id_of(&signed, CeremonyKind::Refresh).unwrap(), format!("refresh-{}", "ab".repeat(16)));
        let short = pb::SignIntent { request_id: vec![1; 8], ..i };
        let signed = pb::SignedIntent { intent: short.encode_to_vec(), ..Default::default() };
        assert!(matches!(ceremony_id_of(&signed, CeremonyKind::Dkg), Err(DaemonError::PolicyRefused(_))));
        assert!(ceremony_id_of(&pb::SignedIntent::default(), CeremonyKind::Dkg).is_err());
        assert!(ceremony_id_of(&pb::SignedIntent { intent: vec![0xff; 3], ..Default::default() }, CeremonyKind::Dkg).is_err());
    }

    /// `rutli-cosigner refresh` learns the cluster id like the driver: a majority of at least two.
    #[test]
    fn the_cluster_id_is_what_a_majority_of_the_roster_reports() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(agree_on_cluster_id(&s(&["a", "a", "a"]), 3).as_deref(), Some("a"));
        assert_eq!(agree_on_cluster_id(&s(&["a", "a", "b"]), 3).as_deref(), Some("a"));
        assert_eq!(agree_on_cluster_id(&s(&["a", ""]), 3), None, "one answer is one cosigner's word");
        assert_eq!(agree_on_cluster_id(&s(&["a", "b"]), 3), None);
        assert_eq!(agree_on_cluster_id(&s(&["a", "a", "b", "b"]), 5), None, "a tie is no majority");
        assert_eq!(agree_on_cluster_id(&s(&["a"]), 1).as_deref(), Some("a"), "a one-node dev roster");
        assert_eq!(agree_on_cluster_id(&s(&[]), 3), None);
    }

    /// Parity with the driver's `FrostIntentSigner.deleteDigest` (FrostSigningIntentSpec pins it).
    #[test]
    fn the_delete_digest_matches_the_drivers_golden_vector() {
        assert_eq!(
            hex::encode(delete_digest("participant1-rutli-enc-golden")),
            "10e118018ec6f17f27279a2c5030ae03c65ade57a2174b5f097cb4a5d00c3877"
        );
    }
}

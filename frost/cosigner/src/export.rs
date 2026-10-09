// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Portable export/import of cluster-hosted keys.
//!
//! This is deliberately **not** the same thing as `backup`, and the two solve different problems:
//!
//! - `backup` copies the sealed files as they sit on disk. The artifact is ciphertext under the
//!   cluster's seal master secret, and it restores only onto the node it came from (the DEK is
//!   derived from the master secret salted by node id). It is the routine durability path.
//! - **export** produces a *portable* artifact that does not depend on the cluster's seal secret or
//!   node identity at all. That is the point: it covers the two cases `backup` cannot — restoring
//!   into a different cluster, and recovering after the seal master secret is lost.
//!
//! Because the artifact is portable, it is as dangerous as the key itself. Two deliberate choices
//! follow:
//!
//! 1. **Offline only.** There is no export/import RPC and there must never be one. An export RPC
//!    would turn a stolen driver certificate from an online, rate-limited, journalled decrypt
//!    *oracle* into permanent silent possession of the key. As a CLI subcommand the operation needs
//!    host access *and* the seal secret (which the operator already keeps in a separate trust
//!    domain), and adds no network attack surface.
//! 2. **Encrypted by default.** The export is sealed under an operator passphrase via Argon2id +
//!    AES-256-GCM, so the artifact is safe to write to media and the operator can Shamir-split or
//!    escrow the passphrase as they see fit. `--unsafe-plaintext` exists for piping into another
//!    KMS/HSM import tool, and says so loudly.
//!
//! **Importing from Canton.** Besides its own envelope, `import-key` reads an existing Canton
//! node's EC P-256 encryption key ([`import_canton`]), so a node can move into the cluster without
//! rotating its encryption key. Same rules: offline, create-once, never an RPC.
//!
//! **Hosted keys only.** A FROST share is not a whole key — there is nothing to export, and
//! exporting one node's share would be both useless and dangerous. The commands refuse it, and no
//! other path exports a share either. The only way a share enters a node from outside is the split
//! ceremony's `import-share` ([`crate::share_import`]) — offline too, for the same reasons as here.

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hosted::HostedKey;
use crate::{DaemonError, Result};

/// Envelope written by `export-key` and read by `import-key`.
///
/// Versioned: an exported key may sit in a safe for years and must still be importable by a much
/// later build, so the reader refuses an unknown version rather than guessing.
#[derive(Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub v: u8,
    /// Fixed marker so a mis-pointed `--in` fails with a clear message instead of a parse error.
    pub kind: String,
    pub key_id: String,
    pub spec: String,
    /// When the key itself was created (carried through so an import preserves provenance).
    pub created_at: u64,
    /// Argon2id parameters, or `None` for a plaintext export.
    pub kdf: Option<Kdf>,
    /// Hex AES-256-GCM nonce (encrypted exports only).
    #[serde(default)]
    pub nonce: String,
    /// Hex payload: AES-256-GCM ciphertext of the key JSON, or the key JSON itself when `kdf` is
    /// `None`.
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
pub struct Kdf {
    pub algo: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

pub const ENVELOPE_VERSION: u8 = 1;
pub const ENVELOPE_KIND: &str = "rutli-key-export";

/// Argon2id parameters. Deliberately costly: the passphrase is the only thing standing between an
/// exported artifact and the key, and unlike an online login this is a once-per-ceremony operation
/// where a second of CPU is free.
const ARGON2_M_COST: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const SALT_LEN: usize = 16;

/// Minimum passphrase length. An export protected by a guessable passphrase is worse than useless:
/// it looks protected.
const MIN_PASSPHRASE_LEN: usize = 12;

/// Produce a portable, passphrase-encrypted export of `key`.
pub fn export_encrypted(key_id: &str, key: &HostedKey, passphrase: &str) -> Result<ExportEnvelope> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(DaemonError::Config(format!(
            "export passphrase must be at least {MIN_PASSPHRASE_LEN} characters — this is the only \
             protection on a portable copy of a private key"
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let dek = derive_dek(passphrase, &salt)?;

    let plain = Zeroizing::new(serde_json::to_vec(key)?);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_ref()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // Bind the ciphertext to the identity fields, so an artifact cannot be relabelled to another
    // key id or spec and imported as something it is not.
    let aad = aad(key_id, key.spec.as_str());
    let ct = cipher
        .encrypt(&nonce, Payload { msg: &plain, aad: &aad })
        .map_err(|_| DaemonError::Config("export encryption failed".into()))?;

    Ok(ExportEnvelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        key_id: key_id.to_string(),
        spec: key.spec.as_str().to_string(),
        created_at: key.created_at,
        kdf: Some(Kdf {
            algo: "argon2id".into(),
            salt: hex::encode(salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }),
        nonce: hex::encode(nonce),
        payload: hex::encode(&ct),
    })
}

/// Produce an UNENCRYPTED export. The artifact is the private key in the clear.
pub fn export_plaintext(key_id: &str, key: &HostedKey) -> Result<ExportEnvelope> {
    Ok(ExportEnvelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        key_id: key_id.to_string(),
        spec: key.spec.as_str().to_string(),
        created_at: key.created_at,
        kdf: None,
        nonce: String::new(),
        payload: hex::encode(serde_json::to_vec(key)?),
    })
}

/// Recover the key from an envelope. `passphrase` must be supplied iff the envelope is encrypted.
pub fn import(envelope: &ExportEnvelope, passphrase: Option<&str>) -> Result<HostedKey> {
    if envelope.kind != ENVELOPE_KIND {
        return Err(DaemonError::Config(format!(
            "not a Rütli key export (kind = {:?})",
            envelope.kind
        )));
    }
    if envelope.v != ENVELOPE_VERSION {
        return Err(DaemonError::Config(format!(
            "unsupported export format version {} (this build reads {ENVELOPE_VERSION})",
            envelope.v
        )));
    }
    let bytes = hex::decode(&envelope.payload)
        .map_err(|e| DaemonError::Config(format!("corrupt export payload: {e}")))?;

    let plain: Zeroizing<Vec<u8>> = match (&envelope.kdf, passphrase) {
        (Some(kdf), Some(pass)) => {
            if kdf.algo != "argon2id" {
                return Err(DaemonError::Config(format!("unsupported export KDF {:?}", kdf.algo)));
            }
            let salt = hex::decode(&kdf.salt)
                .map_err(|e| DaemonError::Config(format!("corrupt export salt: {e}")))?;
            let dek = derive_dek_with(pass, &salt, kdf.m_cost, kdf.t_cost, kdf.p_cost)?;
            let nonce = hex::decode(&envelope.nonce)
                .map_err(|e| DaemonError::Config(format!("corrupt export nonce: {e}")))?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.as_ref()));
            let aad = aad(&envelope.key_id, &envelope.spec);
            Zeroizing::new(
                cipher
                    .decrypt(Nonce::from_slice(&nonce), Payload { msg: &bytes, aad: &aad })
                    // One opaque error: a wrong passphrase and a tampered artifact are the same
                    // answer to the caller.
                    .map_err(|_| {
                        DaemonError::Config(
                            "could not open the export — wrong passphrase, or the file was altered"
                                .into(),
                        )
                    })?,
            )
        }
        (Some(_), None) => {
            return Err(DaemonError::Config(
                "this export is passphrase-protected — supply it with --passphrase-env".into(),
            ))
        }
        (None, _) => Zeroizing::new(bytes),
    };

    let key: HostedKey = serde_json::from_slice(&plain)?;
    // The header is what an operator reads; if it disagrees with the sealed material, refuse rather
    // than importing something other than what the file claims to be.
    if key.spec.as_str() != envelope.spec {
        return Err(DaemonError::Config(format!(
            "export header says {} but the material is {}",
            envelope.spec,
            key.spec.as_str()
        )));
    }
    key.validate()?;
    Ok(key)
}

/// The driver's routing tag for cluster-hosted keys (`FrostKeyIds.HostedTag`).
pub const HOSTED_ROUTING_TAG: &str = "rutli-";
/// The driver's routing tag for FROST threshold keys (`FrostKeyIds.FrostTag`).
pub const FROST_ROUTING_TAG: &str = "frost-";

/// Check an operator-chosen id for an imported hosted key against the driver's routing, and return
/// the `frost.key-prefix` a driver must run with to reach it.
///
/// The driver (`FrostKeyIds`) routes an id to the cluster's hosted keys iff it starts with
/// `<prefix>rutli-`, and to FROST iff it starts with `<prefix>frost-` — checked first. So an
/// importable id is `<prefix>rutli-<name>`, all in the keystore alphabet `[A-Za-z0-9_-]`, with a
/// non-empty name, and it never contains `frost-` (with some prefix, the driver would read it as a
/// FROST key; and `…frost-import-…` is reserved for the split ceremony).
///
/// With `key_prefix` given, the id must start with exactly `key_prefix + "rutli-"`. Without it, the
/// prefix is everything before the first `rutli-` — returned so the operator can check it is the
/// participant's `frost.key-prefix`.
pub fn hosted_import_key_id(key_id: &str, key_prefix: Option<&str>) -> Result<String> {
    let alphabet = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let refuse = |why: String| DaemonError::Config(format!("--key-id {key_id:?}: {why}"));
    if !alphabet(key_id) {
        return Err(refuse("only [A-Za-z0-9_-] is allowed (the cosigner keystore alphabet)".into()));
    }
    if key_id.contains(FROST_ROUTING_TAG) {
        return Err(refuse(format!(
            "contains `{FROST_ROUTING_TAG}`, the driver's FROST routing tag; a hosted key id must not"
        )));
    }
    let prefix = match key_prefix {
        Some(p) => {
            if !alphabet(p) {
                return Err(refuse(format!("--key-prefix {p:?} is outside [A-Za-z0-9_-]")));
            }
            if !key_id.starts_with(&format!("{p}{HOSTED_ROUTING_TAG}")) {
                return Err(refuse(format!(
                    "a driver with frost.key-prefix {p:?} routes only `{p}{HOSTED_ROUTING_TAG}…` \
                     to hosted keys"
                )));
            }
            p.to_string()
        }
        None => match key_id.find(HOSTED_ROUTING_TAG) {
            Some(at) => key_id[..at].to_string(),
            None => {
                return Err(refuse(format!(
                    "does not carry the driver's hosted routing tag `{HOSTED_ROUTING_TAG}` \
                     (ids are <frost.key-prefix>{HOSTED_ROUTING_TAG}<name>), so the driver could \
                     never route Canton to it"
                )))
            }
        },
    };
    if key_id.len() == prefix.len() + HOSTED_ROUTING_TAG.len() {
        return Err(refuse(format!("needs a name after `{prefix}{HOSTED_ROUTING_TAG}`")));
    }
    Ok(prefix)
}

/// A key read from a Canton export, ready to be created under an operator-chosen hosted key id.
#[derive(Debug)]
pub struct CantonImport {
    pub key: HostedKey,
    /// The Canton fingerprint (`1220…`), re-derived from the stored public key.
    pub fingerprint: String,
}

/// Import an **existing Canton encryption key** as a hosted key: `ExportKeyPair` output, plain or
/// password-protected, or a `common_crypto_private_keys.data` value — parsed by
/// `rutli-canton-key` (milestone B1).
///
/// This is how a node migrates into the cluster without touching its encryption key: the
/// participant re-registers the very same key by KMS id (`RegisterKmsEncryptionKey`), so its
/// fingerprint — and the topology mapping that publishes it — stay what they were. That only works
/// if the public key the cluster serves is **byte-identical** to the one Canton recorded, so this
/// checks exactly that, and refuses on any disagreement:
///
/// - only an EC P-256 key whose Canton purpose is *encryption* is accepted (`ec-p256-ecies`). A
///   P-256 *signing* key is refused (the cluster never turns a signing key into an ECDH oracle), as
///   is plain PKCS#8, which carries no purpose. Ed25519 keys go through the split ceremony, and
///   RSA-2048 import is milestone B3 — both refused here with a pointer;
/// - the key's Canton fingerprint must equal `expect_fingerprint`, which the operator copies from
///   the old node (`keys.secret.list`), not from the file;
/// - the SPKI DER this cluster will serve must equal the SPKI Canton derives for the key
///   (`rutli_canton_key::PublicKey::spki_der`), byte for byte, and fingerprint to the same value.
pub fn import_canton(
    input: &[u8],
    password: Option<&[u8]>,
    expect_fingerprint: &str,
    now_secs: u64,
) -> Result<CantonImport> {
    use rutli_canton_key::{KeyPurpose, KeySpec, PrivateKeyMaterial, Source};

    let refuse = |msg: String| DaemonError::Config(format!("Canton key import: {msg}"));
    let expect = expect_fingerprint.trim().to_ascii_lowercase();
    let parsed = rutli_canton_key::parse(input, password)
        .map_err(|e| refuse(format!("cannot read the key: {e}")))?;

    if let Source::Pkcs8 { .. } = parsed.source {
        return Err(refuse(
            "plain PKCS#8 carries no Canton purpose or fingerprint; import the node's \
             ExportKeyPair output (keys.secret.download) instead"
                .into(),
        ));
    }
    let fingerprint = parsed.fingerprint();
    if fingerprint != expect || parsed.canton_id.as_ref().is_some_and(|id| *id != expect) {
        return Err(refuse(format!(
            "this key's fingerprint is {fingerprint}, not the expected {expect} — wrong key file"
        )));
    }
    let key = match (parsed.spec(), parsed.purpose, &parsed.material) {
        (KeySpec::EcP256, Some(KeyPurpose::Encryption), PrivateKeyMaterial::EcP256 { scalar }) => {
            HostedKey::ec_p256_from_scalar(scalar.as_ref(), now_secs)?
        }
        (KeySpec::EcP256, _, _) => {
            return Err(refuse(
                "this is an EC P-256 signing key; only encryption keys are hosted (ec-p256-ecies), \
                 and a signing key is never used for ECDH"
                    .into(),
            ))
        }
        (KeySpec::Ed25519, _, _) => {
            return Err(refuse(
                "this is an Ed25519 signing key; namespace and signing keys move into the cluster \
                 through the split ceremony (docs/split-ceremony.md), not import-key"
                    .into(),
            ))
        }
        (KeySpec::Rsa2048, _, _) => {
            return Err(refuse(
                "RSA-2048 import is not supported yet (roadmap milestone B3); only EC P-256 \
                 encryption keys are"
                    .into(),
            ))
        }
    };
    key.validate()?;

    // The load-bearing check: Canton re-registers the key by the fingerprint of the SPKI the
    // driver returns, so the cluster must serve exactly the bytes Canton derives.
    let served = key.public_key_der()?;
    if served != parsed.public.spki_der() {
        return Err(refuse(
            "the public key this cluster would serve is not byte-identical to Canton's encoding — \
             refusing, Canton would see a different key"
                .into(),
        ));
    }
    let served_fp = rutli_canton_key::PublicKey::from_spki_der(&served)
        .map_err(|e| refuse(format!("cannot re-read the served public key: {e}")))?
        .fingerprint();
    if served_fp != expect {
        return Err(refuse(format!(
            "the served public key fingerprints to {served_fp}, not {expect}"
        )));
    }
    Ok(CantonImport { key, fingerprint })
}

fn aad(key_id: &str, spec: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rutli-export-v1");
    for field in [key_id, spec] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

fn derive_dek(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_dek_with(passphrase, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

fn derive_dek_with(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| DaemonError::Config(format!("bad Argon2 parameters: {e}")))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut dek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, dek.as_mut())
        .map_err(|e| DaemonError::Config(format!("key derivation failed: {e}")))?;
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted::HostedSpec;

    const PASS: &str = "correct horse battery staple";

    #[test]
    fn an_encrypted_export_round_trips() {
        let key = HostedKey::generate(HostedSpec::Rsa2048, 99).unwrap();
        let ct = key.encrypt_oaep(b"before export").unwrap();

        let env = export_encrypted("rutli-enc-1", &key, PASS).unwrap();
        // The artifact must not contain the key material in the clear.
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains(&key.private_der));
        assert_eq!(env.created_at, 99, "provenance is carried through");

        // Round-trip through JSON, as a real file would.
        let reloaded: ExportEnvelope = serde_json::from_str(&json).unwrap();
        let back = import(&reloaded, Some(PASS)).unwrap();
        assert_eq!(back.decrypt_oaep(&ct).unwrap().as_slice(), b"before export");
    }

    #[test]
    fn a_wrong_passphrase_is_refused() {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let env = export_encrypted("rutli-sym-1", &key, PASS).unwrap();
        assert!(import(&env, Some("not the passphrase")).is_err());
        assert!(import(&env, None).is_err(), "an encrypted export needs a passphrase");
    }

    #[test]
    fn a_weak_passphrase_is_refused_up_front() {
        // The passphrase is the only protection on a portable private key.
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        assert!(export_encrypted("rutli-sym-1", &key, "short").is_err());
    }

    #[test]
    fn tampering_with_the_artifact_is_detected() {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let mut env = export_encrypted("rutli-sym-1", &key, PASS).unwrap();

        // Flip a byte of ciphertext.
        let mut raw = hex::decode(&env.payload).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        env.payload = hex::encode(&raw);
        assert!(import(&env, Some(PASS)).is_err());
    }

    #[test]
    fn an_artifact_cannot_be_relabelled_to_another_key_id() {
        // The AAD binds the ciphertext to the header, so editing the header to import a key under a
        // different id (or a different spec) fails instead of silently succeeding.
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let mut env = export_encrypted("rutli-sym-original", &key, PASS).unwrap();
        env.key_id = "rutli-sym-impostor".into();
        assert!(import(&env, Some(PASS)).is_err());
    }

    #[test]
    fn a_plaintext_export_round_trips_and_is_marked_unencrypted() {
        let key = HostedKey::generate(HostedSpec::Rsa2048, 5).unwrap();
        let ct = key.encrypt_oaep(b"plaintext path").unwrap();
        let env = export_plaintext("rutli-enc-2", &key).unwrap();
        assert!(env.kdf.is_none(), "a plaintext export must be identifiable as such");

        let back = import(&env, None).unwrap();
        assert_eq!(back.decrypt_oaep(&ct).unwrap().as_slice(), b"plaintext path");
    }

    /// Mirrors the driver's `FrostKeyIds(prefix)`: hosted iff `id.startsWith(prefix + "rutli-")`,
    /// FROST iff `id.startsWith(prefix + "frost-")` (checked first).
    fn driver_routes_to_hosted(id: &str, prefix: &str) -> bool {
        !id.starts_with(&format!("{prefix}frost-")) && id.starts_with(&format!("{prefix}rutli-"))
    }

    #[test]
    fn an_import_key_id_is_one_the_driver_routes_to_hosted_keys() {
        // Accepted, with the prefix a driver must run with.
        for (id, prefix) in [
            ("rutli-enc-imported-1", ""),
            ("soak1-rutli-enc-imported-1", "soak1-"),
            ("e2e1-rutli-x", "e2e1-"),
            ("rutli-a-rutli-b", ""), // the first `rutli-` is the tag
        ] {
            assert_eq!(hosted_import_key_id(id, None).unwrap(), prefix, "{id}");
            assert_eq!(hosted_import_key_id(id, Some(prefix)).unwrap(), prefix, "{id}");
            assert!(driver_routes_to_hosted(id, prefix), "{id}");
        }
        // Refused: no tag, no name after it, outside the alphabet, any `frost-` (a FROST id under
        // some prefix, or the split ceremony's reserved `frost-import-`).
        for id in [
            "enc-1",
            "rutli-",
            "soak1-rutli-",
            "rutli-enc/1",
            "rutli-enc 1",
            "rutli-é",
            "",
            "frost-rutli-x",
            "rutli-frost-import-x",
            "frost-import-1220cb0e",
            "a-frost-b-rutli-c",
        ] {
            assert!(hosted_import_key_id(id, None).is_err(), "{id:?} must be refused");
        }
        // With --key-prefix the id must carry exactly that prefix.
        assert!(hosted_import_key_id("soak1-rutli-x", Some("soak2-")).is_err());
        assert!(hosted_import_key_id("rutli-x", Some("soak1-")).is_err());
        assert!(hosted_import_key_id("soak1-rutli-x", Some("")).is_err(), "prefix \"\" means no prefix");
        assert!(hosted_import_key_id("soak1-rutli-x", Some("so ak1-")).is_err());
    }

    #[test]
    fn a_foreign_or_future_artifact_is_refused_clearly() {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let mut env = export_plaintext("rutli-sym-1", &key).unwrap();

        let mut wrong_kind = export_plaintext("rutli-sym-1", &key).unwrap();
        wrong_kind.kind = "something-else".into();
        assert!(import(&wrong_kind, None).is_err(), "a mis-pointed --in must say so");

        // A file written by a future build must be refused, not guessed at.
        env.v = ENVELOPE_VERSION + 1;
        assert!(import(&env, None).is_err());
    }
}

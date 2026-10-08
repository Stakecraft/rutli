// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Wrapping hosted key material for transport between cosigners.
//!
//! Hosted keys are whole keys, so replicating one means moving private material across the mesh.
//! mTLS alone is not enough protection for that:
//!
//! - In Kubernetes a service-mesh sidecar (Istio/Linkerd) terminating TLS would see the plaintext
//!   private key.
//! - The cluster CA also signs the *driver's* certificate, and every cosigner cert carries the same
//!   shared `rutli-cosigner` SAN, so TLS alone does not tell peer 2 from peer 3.
//!
//! So key material is additionally sealed to **one specific recipient node** with an
//! HPKE-style construction: ephemeral X25519 → HKDF-SHA256 → AES-256-GCM, with an AAD binding the
//! cluster, key id, spec and recipient. An envelope minted for node 2 is undecryptable by node 3
//! and unusable under a different key id.
//!
//! The recipient's static X25519 key is **derived from that node's seal secret** rather than
//! generated and stored:
//!
//! ```text
//! dist_sk_j = HKDF-SHA256(ikm = master secret, salt = "rutli-dist/node-{j}", info = "x25519-v1")
//! ```
//!
//! Deriving rather than generating avoids a first-boot ordering problem: there is no key to
//! distribute before the cluster can talk.
//!
//! Two honest limits on what this buys today. Under the current *shared* master secret any node can
//! derive any peer's key, so this binds material to a node identity only as strongly as the shared
//! secret is held — no worse than share sealing already is, and it becomes a real binding with no
//! code change once operators move to per-node seal secrets. And `PeerConfig` does **not** yet pin
//! each peer's expected `dist_pubkey`, so a wrong secret or a wrong mount is caught when an
//! envelope fails to open, not at startup before any key exists. Pinning it is the follow-up that
//! would make the failure loud and early.

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{DaemonError, Result};

/// Envelope format version, carried on the wire so the construction can evolve.
pub const WRAP_VERSION: u32 = 1;

/// A hosted key sealed to one recipient node.
pub struct Wrapped {
    pub recipient: u16,
    /// Ephemeral X25519 public key (the HPKE "enc").
    pub encapsulated_key: Vec<u8>,
    /// AES-256-GCM `nonce ‖ ciphertext‖tag`.
    pub ciphertext: Vec<u8>,
    pub version: u32,
}

/// This node's static distribution keypair, derived from the share-seal master secret.
pub struct DistKey {
    secret: StaticSecret,
    public: PublicKey,
    identifier: u16,
}

impl DistKey {
    /// Derive the distribution key for `node_identifier` from the cluster master secret.
    pub fn derive(master: &[u8], node_identifier: u16) -> Self {
        let salt = format!("rutli-dist/node-{node_identifier}");
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master);
        let mut seed = Zeroizing::new([0u8; 32]);
        hk.expand(b"x25519-v1", seed.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        // StaticSecret::from clamps the scalar, so any 32 bytes are a valid secret key.
        let secret = StaticSecret::from(*seed);
        let public = PublicKey::from(&secret);
        Self { secret, public, identifier: node_identifier }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Unwrap an envelope addressed to this node.
    pub fn unwrap_key(&self, w: &Wrapped, cluster_id: &str, key_id: &str, spec: &str) -> Result<Zeroizing<Vec<u8>>> {
        if w.version != WRAP_VERSION {
            return Err(DaemonError::Config(format!(
                "unsupported key-wrap version {} (this node speaks {WRAP_VERSION})",
                w.version
            )));
        }
        if w.recipient != self.identifier {
            return Err(DaemonError::Config(format!(
                "key envelope is addressed to node {}, not this node ({})",
                w.recipient, self.identifier
            )));
        }
        let aad = aad(cluster_id, key_id, spec, w.recipient, &[]);
        open_with(&self.secret, self.public.as_bytes(), w, &aad)
    }
}

/// Seal `material` to `recipient_pub` (the recipient node's derived distribution key).
///
/// The AAD binds the envelope to a cluster, key id, spec and recipient, so it cannot be replayed
/// to another node or presented as a different key.
pub fn wrap_for(
    recipient: u16,
    recipient_pub: &[u8; 32],
    material: &[u8],
    cluster_id: &str,
    key_id: &str,
    spec: &str,
) -> Result<Wrapped> {
    let aad = aad(cluster_id, key_id, spec, recipient, &[]);
    let (encapsulated_key, ciphertext) = seal_to(recipient_pub, material, &aad)?;
    Ok(Wrapped { recipient, encapsulated_key, ciphertext, version: WRAP_VERSION })
}

/// The construction under [`wrap_for`], for any X25519 recipient key: ephemeral X25519 →
/// HKDF-SHA256 (bound to both public keys) → AES-256-GCM over `material` with `aad`. Returns the
/// ephemeral public key and `nonce ‖ ciphertext‖tag`.
///
/// Also used by the split ceremony (`share_delivery.rs`) to seal a dealer share to a
/// per-ceremony recipient key; the caller owns the AAD, so each use binds its own context.
///
/// This is confidentiality to the holder of the recipient key, **not** sender authentication:
/// anyone who knows `recipient_pub` can produce an envelope that opens. Callers that need to know
/// where the material came from must check it against something they already trust.
pub fn seal_to(recipient_pub: &[u8; 32], material: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_pub));
    // A small-order recipient key gives an all-zero shared secret: refuse rather than encrypt under
    // a key anyone can compute.
    if !shared.was_contributory() {
        return Err(DaemonError::Config("recipient public key is not a usable X25519 key".into()));
    }
    let cek = derive_cek(shared.as_bytes(), epk.as_bytes(), recipient_pub);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek.as_ref()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: material, aad })
        .map_err(|_| DaemonError::Config("key wrapping failed".into()))?;

    let mut ciphertext = Vec::with_capacity(NONCE_LEN + ct.len());
    ciphertext.extend_from_slice(nonce.as_slice());
    ciphertext.extend_from_slice(&ct);
    Ok((epk.to_bytes().to_vec(), ciphertext))
}

/// Open an envelope made by [`seal_to`] with the recipient's `secret` (whose public key is
/// `recipient_pub`) and the same `aad`. Only `w.encapsulated_key` and `w.ciphertext` are read:
/// checking `w.version` and `w.recipient` is the caller's job, because what they must equal
/// depends on the use.
pub fn open_with(
    secret: &StaticSecret,
    recipient_pub: &[u8; 32],
    w: &Wrapped,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let epk: [u8; 32] = w
        .encapsulated_key
        .as_slice()
        .try_into()
        .map_err(|_| DaemonError::Config("malformed encapsulated key".into()))?;
    let shared = secret.diffie_hellman(&PublicKey::from(epk));
    if !shared.was_contributory() {
        // A small-order ephemeral key: the CEK would be public. Same opaque error as a bad tag.
        return Err(DaemonError::Config("key envelope failed authentication".into()));
    }
    let cek = derive_cek(shared.as_bytes(), &epk, recipient_pub);

    if w.ciphertext.len() < NONCE_LEN {
        return Err(DaemonError::Config("malformed key envelope".into()));
    }
    let (nonce, ct) = w.ciphertext.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek.as_ref()));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        // Opaque on purpose: wrong recipient, tampered AAD and corrupt ciphertext are all just
        // "this envelope is not for you / not intact".
        .map_err(|_| DaemonError::Config("key envelope failed authentication".into()))?;
    Ok(Zeroizing::new(plain))
}

/// A stable cluster identifier derived from the CA certificate — no new config field, and it
/// changes if the trust domain changes (so envelopes never cross clusters).
pub fn cluster_id_from_ca(ca_pem: &[u8]) -> String {
    hex::encode(&Sha256::digest(ca_pem)[..8])
}

const NONCE_LEN: usize = 12;

/// Bind the content-encryption key to both public keys, so a shared secret cannot be reused under
/// a different pairing.
fn derive_cek(shared: &[u8; 32], epk: &[u8; 32], recipient_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(64 + 16);
    info.extend_from_slice(b"rutli-keywrap-v1");
    info.extend_from_slice(epk);
    info.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut cek = Zeroizing::new([0u8; 32]);
    hk.expand(&info, cek.as_mut()).expect("32 bytes is a valid HKDF-SHA256 output length");
    cek
}

/// The envelope AAD: `"rutli-kw-v1" ‖ be16(recipient) ‖ lp(cluster_id) ‖ lp(key_id) ‖ lp(spec)`,
/// then `lp(field)` for each of `extra`, where `lp(x) = be32(len(x)) ‖ x`. Length-prefixed so
/// distinct field values can never produce the same AAD.
///
/// Hosted-key envelopes pass no `extra` fields, so their AAD is byte-for-byte what it was before
/// `extra` existed (pinned by a golden test), and envelopes minted by an older node still open.
/// The split ceremony appends its own context (ceremony id, group key, fingerprint, package digest).
pub fn aad(cluster_id: &str, key_id: &str, spec: &str, recipient: u16, extra: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rutli-kw-v1");
    out.extend_from_slice(&recipient.to_be_bytes());
    let fixed = [cluster_id.as_bytes(), key_id.as_bytes(), spec.as_bytes()];
    for field in fixed.into_iter().chain(extra.iter().copied()) {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"cluster master secret for wrap tests";
    const CLUSTER: &str = "abcdef0123456789";

    #[test]
    fn wrap_round_trips_to_the_intended_node() {
        let node2 = DistKey::derive(MASTER, 2);
        let material = b"PKCS#8 private key bytes";
        let w = wrap_for(2, &node2.public_bytes(), material, CLUSTER, "rutli-enc-1", "rsa-2048-oaep-sha256")
            .unwrap();
        assert_eq!(w.version, WRAP_VERSION);
        assert_eq!(w.encapsulated_key.len(), 32);
        // The material must not appear in the envelope.
        assert!(!w.ciphertext.windows(material.len()).any(|c| c == material));

        let out = node2.unwrap_key(&w, CLUSTER, "rutli-enc-1", "rsa-2048-oaep-sha256").unwrap();
        assert_eq!(out.as_slice(), material);
    }

    #[test]
    fn another_node_cannot_open_it() {
        let node2 = DistKey::derive(MASTER, 2);
        let node3 = DistKey::derive(MASTER, 3);
        let w = wrap_for(2, &node2.public_bytes(), b"secret", CLUSTER, "k", "aes-256-gcm").unwrap();

        // Wrong recipient is refused up front...
        assert!(node3.unwrap_key(&w, CLUSTER, "k", "aes-256-gcm").is_err());
        // ...and even relabelled to node 3, the ciphertext will not open (different DH secret).
        let forged = Wrapped { recipient: 3, ..clone_wrapped(&w) };
        assert!(node3.unwrap_key(&forged, CLUSTER, "k", "aes-256-gcm").is_err());
    }

    #[test]
    fn the_envelope_is_bound_to_cluster_key_and_spec() {
        let node2 = DistKey::derive(MASTER, 2);
        let w = wrap_for(2, &node2.public_bytes(), b"secret", CLUSTER, "k1", "aes-256-gcm").unwrap();

        assert!(node2.unwrap_key(&w, "other-cluster", "k1", "aes-256-gcm").is_err());
        assert!(node2.unwrap_key(&w, CLUSTER, "k2", "aes-256-gcm").is_err(), "replay under another key id");
        assert!(node2.unwrap_key(&w, CLUSTER, "k1", "rsa-2048-oaep-sha256").is_err(), "spec confusion");
        assert!(node2.unwrap_key(&w, CLUSTER, "k1", "aes-256-gcm").is_ok());
    }

    #[test]
    fn tampering_is_detected() {
        let node2 = DistKey::derive(MASTER, 2);
        let mut w = wrap_for(2, &node2.public_bytes(), b"secret", CLUSTER, "k", "aes-256-gcm").unwrap();
        let last = w.ciphertext.len() - 1;
        w.ciphertext[last] ^= 1;
        assert!(node2.unwrap_key(&w, CLUSTER, "k", "aes-256-gcm").is_err());
    }

    #[test]
    fn a_future_wrap_version_is_refused_not_misparsed() {
        let node2 = DistKey::derive(MASTER, 2);
        let mut w = wrap_for(2, &node2.public_bytes(), b"secret", CLUSTER, "k", "aes-256-gcm").unwrap();
        w.version = WRAP_VERSION + 1;
        assert!(node2.unwrap_key(&w, CLUSTER, "k", "aes-256-gcm").is_err());
    }

    #[test]
    fn derivation_is_deterministic_and_node_specific() {
        // Deterministic: every node computes the same public key for a peer from the same master,
        // which is what lets the pinned config value be checked at startup.
        assert_eq!(DistKey::derive(MASTER, 2).public_bytes(), DistKey::derive(MASTER, 2).public_bytes());
        assert_ne!(DistKey::derive(MASTER, 2).public_bytes(), DistKey::derive(MASTER, 3).public_bytes());
        assert_ne!(
            DistKey::derive(MASTER, 2).public_bytes(),
            DistKey::derive(b"a different master", 2).public_bytes()
        );
    }

    #[test]
    fn cluster_id_tracks_the_trust_domain() {
        assert_eq!(cluster_id_from_ca(b"ca-pem").len(), 16);
        assert_ne!(cluster_id_from_ca(b"ca-pem"), cluster_id_from_ca(b"other-ca-pem"));
    }

    #[test]
    fn the_hosted_key_aad_is_unchanged_golden() {
        // Pinned bytes, written out by hand: the refactor that added `extra` must not change what
        // a hosted-key envelope authenticates, or envelopes minted by an older node stop opening.
        assert_eq!(
            hex::encode(aad(CLUSTER, "rutli-enc-1", "rsa-2048-oaep-sha256", 2, &[])),
            "7275746c692d6b772d7631000200000010616263646566303132333435363738390000000b7275746c\
             692d656e632d31000000147273612d323034382d6f6165702d736861323536"
        );
        // Extra fields are appended length-prefixed, an empty one included.
        assert_eq!(
            hex::encode(aad("c", "k", "frost-ed25519-share", 3, &[b"x", b""])),
            "7275746c692d6b772d763100030000000163000000016b0000001366726f73742d656432353531392d\
             7368617265000000017800000000"
        );
        // No field boundary can be shifted: ("ab","c") and ("a","bc") differ.
        assert_ne!(aad("c", "k", "s", 1, &[b"ab", b"c"]), aad("c", "k", "s", 1, &[b"a", b"bc"]));
    }

    #[test]
    fn seal_to_and_open_with_round_trip_under_the_same_aad_only() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        let (epk, ct) = seal_to(&public, b"share", b"context-a").unwrap();
        let w = Wrapped { recipient: 0, encapsulated_key: epk, ciphertext: ct, version: 0 };
        assert_eq!(open_with(&secret, &public, &w, b"context-a").unwrap().as_slice(), b"share");
        assert!(open_with(&secret, &public, &w, b"context-b").is_err());
        let other = StaticSecret::random_from_rng(OsRng);
        assert!(open_with(&other, &PublicKey::from(&other).to_bytes(), &w, b"context-a").is_err());
    }

    #[test]
    fn small_order_keys_are_refused_both_ways() {
        // u = 0 is a small-order point: the shared secret would be all zeros, the CEK public.
        assert!(seal_to(&[0u8; 32], b"share", b"aad").is_err());
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        let (_, ct) = seal_to(&public, b"share", b"aad").unwrap();
        let w = Wrapped { recipient: 0, encapsulated_key: vec![0u8; 32], ciphertext: ct, version: 0 };
        assert!(open_with(&secret, &public, &w, b"aad").is_err());
    }

    fn clone_wrapped(w: &Wrapped) -> Wrapped {
        Wrapped {
            recipient: w.recipient,
            encapsulated_key: w.encapsulated_key.clone(),
            ciphertext: w.ciphertext.clone(),
            version: w.version,
        }
    }
}

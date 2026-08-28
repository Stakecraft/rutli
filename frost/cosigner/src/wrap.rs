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
        let epk: [u8; 32] = w
            .encapsulated_key
            .as_slice()
            .try_into()
            .map_err(|_| DaemonError::Config("malformed encapsulated key".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(epk));
        let cek = derive_cek(shared.as_bytes(), &epk, self.public.as_bytes());

        if w.ciphertext.len() < NONCE_LEN {
            return Err(DaemonError::Config("malformed key envelope".into()));
        }
        let (nonce, ct) = w.ciphertext.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek.as_ref()));
        let aad = aad(cluster_id, key_id, spec, w.recipient);
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            // Opaque on purpose: wrong recipient, tampered AAD and corrupt ciphertext are all just
            // "this envelope is not for you / not intact".
            .map_err(|_| DaemonError::Config("key envelope failed authentication".into()))?;
        Ok(Zeroizing::new(plain))
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
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_pub));
    let cek = derive_cek(shared.as_bytes(), epk.as_bytes(), recipient_pub);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek.as_ref()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let aad = aad(cluster_id, key_id, spec, recipient);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: material, aad: &aad })
        .map_err(|_| DaemonError::Config("key wrapping failed".into()))?;

    let mut ciphertext = Vec::with_capacity(NONCE_LEN + ct.len());
    ciphertext.extend_from_slice(nonce.as_slice());
    ciphertext.extend_from_slice(&ct);
    Ok(Wrapped {
        recipient,
        encapsulated_key: epk.to_bytes().to_vec(),
        ciphertext,
        version: WRAP_VERSION,
    })
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

/// Length-prefixed so distinct field values can never produce the same AAD.
fn aad(cluster_id: &str, key_id: &str, spec: &str, recipient: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"rutli-kw-v1");
    out.extend_from_slice(&recipient.to_be_bytes());
    for field in [cluster_id, key_id, spec] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
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

    fn clone_wrapped(w: &Wrapped) -> Wrapped {
        Wrapped {
            recipient: w.recipient,
            encapsulated_key: w.encapsulated_key.clone(),
            ciphertext: w.ciphertext.clone(),
            version: w.version,
        }
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Authenticating split-ceremony recipient requests.
//!
//! A recipient request names the X25519 key the dealer seals a node's share to. If an attacker can
//! swap `t` request files on their way from the pods to the dealer (operator laptop, removable
//! media), the dealer seals `t` real shares to keys the attacker holds, and the attacker
//! reconstructs the key. So a request must prove it was minted by the node it names:
//!
//! - `share-recipient` signs the request's canonical bytes ([`canonical_bytes`]) with the node's
//!   **mTLS leaf private key** and embeds the leaf certificate chain ([`NodeSigner`]);
//! - `rutli-dealer` verifies ([`verify_request`]) the chain up to the cluster CA it was given
//!   (`--ca-cert`), the signature, that `cluster_id` is that CA's (`wrap::cluster_id_from_ca`), and
//!   that the leaf's identity is the request's `identifier`.
//!
//! **Identity rule.** A leaf certificate names cosigner `N` iff its subject Common Name is exactly
//! `cosigner<N>` (decimal, no leading zeros) — the CN `scripts/gen-frost-certs.sh` issues, the one
//! `peer_allowlist` lists, and the number the Peer API's `FetchKey` already takes from the caller's
//! CN. The driver's and the operator's certificates (CN `driver`, `operator`) never qualify.
//!
//! A second, human channel backs this up: the **SAS** ([`sas`]), 16 hex characters of the request's
//! digest, which `share-recipient` prints in the pod and the dealer requires the operator to
//! confirm (Gate 0 of docs/split-ceremony.md). A forged request then needs both a CA-signed
//! cosigner key *and* a witness who reads the wrong SAS.
//!
//! Supported keys (leaf and issuer): ECDSA P-256 (what `gen-frost-certs.sh` issues), ECDSA P-384,
//! Ed25519, RSA ≥ 2048 (PKCS#1 v1.5, SHA-256/384). Verification is aws-lc-rs over x509-parser's
//! parse — both already the cosigner's dependencies.

use aws_lc_rs::signature::{self, KeyPair, UnparsedPublicKey};
use base64::Engine;
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION,
    OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ED25519,
};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use crate::share_delivery::RecipientRequest;
use crate::{DaemonError, Result};

/// Domain separation for the request signature: these bytes can never be a TLS handshake
/// transcript or any other message the leaf key signs.
const REQUEST_CONTEXT: &[u8] = b"rutli-share-recipient-request-v1\n";

/// The bytes a request signature covers: [`REQUEST_CONTEXT`] ‖ the JSON of every request field
/// except the three authentication fields, in declaration order (deterministic: a struct, no maps).
pub fn canonical_bytes(r: &RecipientRequest) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        v: u8,
        kind: &'a str,
        ceremony_id: &'a str,
        key_id: &'a str,
        cluster_id: &'a str,
        identifier: u16,
        threshold: u16,
        max_signers: u16,
        roster: &'a [u16],
        recipient_pub: &'a str,
    }
    let body = Body {
        v: r.v,
        kind: &r.kind,
        ceremony_id: &r.ceremony_id,
        key_id: &r.key_id,
        cluster_id: &r.cluster_id,
        identifier: r.identifier,
        threshold: r.threshold,
        max_signers: r.max_signers,
        roster: &r.roster,
        recipient_pub: &r.recipient_pub,
    };
    let mut out = REQUEST_CONTEXT.to_vec();
    out.extend_from_slice(&serde_json::to_vec(&body).expect("a plain struct serializes"));
    out
}

/// Short authentication string: the first 16 hex characters of SHA-256 of [`canonical_bytes`].
/// Read aloud / compared by witnesses between the pod and the dealer (64 bits: a substitution
/// that matches a SAS chosen by the honest node is a 2^64 second-preimage search).
pub fn sas(r: &RecipientRequest) -> String {
    hex::encode(Sha256::digest(canonical_bytes(r)))[..16].to_string()
}

/// The node identifier a certificate subject CN names: `cosigner<N>` → `N`, nothing else.
pub fn identifier_from_cn(cn: &str) -> Option<u16> {
    let digits = cn.strip_prefix("cosigner")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

/// The key algorithm of a certificate's SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    Rsa,
}

impl KeyKind {
    fn of(cert: &X509Certificate<'_>) -> Result<Self> {
        let spki = cert.public_key();
        let alg = &spki.algorithm.algorithm;
        if *alg == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok());
            return match curve {
                Some(c) if c == OID_EC_P256 => Ok(Self::EcdsaP256),
                Some(c) if c == OID_NIST_EC_P384 => Ok(Self::EcdsaP384),
                _ => Err(auth("certificate uses an unsupported EC curve".into())),
            };
        }
        if *alg == OID_SIG_ED25519 {
            return Ok(Self::Ed25519);
        }
        if *alg == OID_PKCS1_RSAENCRYPTION {
            return Ok(Self::Rsa);
        }
        Err(auth(format!("certificate key algorithm {alg} is not supported")))
    }

    /// The request-signature algorithm name a key of this kind produces.
    fn request_alg(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256-sha256",
            Self::EcdsaP384 => "ecdsa-p384-sha384",
            Self::Ed25519 => "ed25519",
            Self::Rsa => "rsa-pkcs1-sha256",
        }
    }

    fn request_verifier(self) -> &'static dyn signature::VerificationAlgorithm {
        match self {
            Self::EcdsaP256 => &signature::ECDSA_P256_SHA256_ASN1,
            Self::EcdsaP384 => &signature::ECDSA_P384_SHA384_ASN1,
            Self::Ed25519 => &signature::ED25519,
            Self::Rsa => &signature::RSA_PKCS1_2048_8192_SHA256,
        }
    }
}

enum SigningKey {
    Ecdsa(signature::EcdsaKeyPair),
    Ed25519(signature::Ed25519KeyPair),
    Rsa(signature::RsaKeyPair),
}

/// A node's mTLS identity, able to sign its recipient requests.
pub struct NodeSigner {
    /// DER certificates, leaf first, as in the node's `tls.cert` file.
    chain: Vec<Vec<u8>>,
    kind: KeyKind,
    key: SigningKey,
}

impl NodeSigner {
    /// From the node's `tls.cert` (leaf first, then any intermediates) and `tls.key` files.
    pub fn from_files(cert: &std::path::Path, key: &std::path::Path) -> Result<Self> {
        let cert_pem = std::fs::read(cert)
            .map_err(|e| auth(format!("cannot read {}: {e}", cert.display())))?;
        let key_pem = Zeroizing::new(
            std::fs::read(key).map_err(|e| auth(format!("cannot read {}: {e}", key.display())))?,
        );
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// From PEM text: certificates (leaf first) and the leaf's private key — PKCS#8
    /// (`PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let chain: Vec<Vec<u8>> = pem_blocks(cert_pem)?
            .into_iter()
            .filter(|(label, _)| label == "CERTIFICATE")
            .map(|(_, der)| der.to_vec())
            .collect();
        let leaf_der = chain.first().ok_or_else(|| auth("no certificate in the cert file".into()))?;
        let leaf = parse(leaf_der)?;
        let kind = KeyKind::of(&leaf)?;
        let (_, key_der) = pem_blocks(key_pem)?
            .into_iter()
            .find(|(label, _)| label.ends_with("PRIVATE KEY"))
            .ok_or_else(|| auth("no private key in the key file".into()))?;
        let rejected = |e: aws_lc_rs::error::KeyRejected| auth(format!("private key rejected: {e}"));
        let (key, public) = match kind {
            KeyKind::EcdsaP256 | KeyKind::EcdsaP384 => {
                let alg = if kind == KeyKind::EcdsaP256 {
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING
                } else {
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING
                };
                let k = signature::EcdsaKeyPair::from_private_key_der(alg, &key_der).map_err(rejected)?;
                let public = k.public_key().as_ref().to_vec();
                (SigningKey::Ecdsa(k), public)
            }
            KeyKind::Ed25519 => {
                let k = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&key_der).map_err(rejected)?;
                let public = k.public_key().as_ref().to_vec();
                (SigningKey::Ed25519(k), public)
            }
            KeyKind::Rsa => {
                let k = signature::RsaKeyPair::from_pkcs8(&key_der)
                    .or_else(|_| signature::RsaKeyPair::from_der(&key_der))
                    .map_err(rejected)?;
                let public = k.public_key().as_ref().to_vec();
                (SigningKey::Rsa(k), public)
            }
        };
        if public.as_slice() != leaf.public_key().subject_public_key.data.as_ref() {
            return Err(auth("the private key does not belong to the leaf certificate".into()));
        }
        Ok(Self { chain, kind, key })
    }

    /// Fill in `signature_alg`, `signer_chain` and `signature` on `r`.
    pub fn sign(&self, r: &mut RecipientRequest) -> Result<()> {
        let msg = canonical_bytes(r);
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let fail = |_| auth("signing the request failed".into());
        let sig = match &self.key {
            SigningKey::Ecdsa(k) => k.sign(&rng, &msg).map_err(fail)?.as_ref().to_vec(),
            SigningKey::Ed25519(k) => k.sign(&msg).as_ref().to_vec(),
            SigningKey::Rsa(k) => {
                let mut out = vec![0u8; k.public_modulus_len()];
                k.sign(&signature::RSA_PKCS1_SHA256, &rng, &msg, &mut out).map_err(fail)?;
                out
            }
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        r.signature_alg = self.kind.request_alg().to_string();
        r.signer_chain = self.chain.iter().map(|c| b64.encode(c)).collect();
        r.signature = b64.encode(sig);
        Ok(())
    }
}

/// Verify that `r` was signed by the cosigner it names, under the cluster CA `ca_pem` (the exact
/// CA file the cosigners use — `cluster_id` is a hash of those bytes). The returned
/// [`VerifiedRequest`] is the only thing [`crate::share_delivery::seal_share`] accepts.
pub fn verify_request(r: &RecipientRequest, ca_pem: &[u8]) -> Result<VerifiedRequest> {
    check_request(r, ca_pem)?;
    Ok(VerifiedRequest(r.clone()))
}

/// A recipient request that passed [`verify_request`]. It cannot be built any other way (the
/// field is private to this module), so no caller can seal a share to an unverified request.
#[derive(Debug, Clone)]
pub struct VerifiedRequest(RecipientRequest);

impl std::ops::Deref for VerifiedRequest {
    type Target = RecipientRequest;
    fn deref(&self) -> &RecipientRequest {
        &self.0
    }
}

fn check_request(r: &RecipientRequest, ca_pem: &[u8]) -> Result<()> {
    let expected_cluster = crate::wrap::cluster_id_from_ca(ca_pem);
    if r.cluster_id != expected_cluster {
        return Err(auth(format!(
            "request is for cluster {}, the CA given is cluster {expected_cluster}",
            r.cluster_id
        )));
    }
    let ca_der = pem_blocks(ca_pem)?
        .into_iter()
        .find(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| der.to_vec())
        .ok_or_else(|| auth("no certificate in the CA file".into()))?;
    let ca = parse(&ca_der)?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let chain_der: Vec<Vec<u8>> = r
        .signer_chain
        .iter()
        .map(|c| b64.decode(c).map_err(|_| auth("signer_chain is not base64".into())))
        .collect::<Result<_>>()?;
    if chain_der.is_empty() {
        return Err(auth("the request is not signed (no signer_chain)".into()));
    }
    if chain_der.len() > 4 {
        return Err(auth("signer_chain is too long".into()));
    }
    let chain: Vec<X509Certificate<'_>> = chain_der.iter().map(|d| parse(d)).collect::<Result<_>>()?;

    // Trust anchor: itself valid now, and a CA allowed to sign certificates.
    let now = x509_parser::time::ASN1Time::now();
    if !ca.validity().is_valid_at(now) {
        return Err(auth("the CA certificate is expired or not yet valid".into()));
    }
    require_issuer(&ca, "the CA certificate")?;

    // Chain: each certificate signed by the next, the last by the CA. Intermediates must be CAs.
    for (i, cert) in chain.iter().enumerate() {
        if !cert.validity().is_valid_at(now) {
            return Err(auth(format!("certificate {i} of signer_chain is expired or not yet valid")));
        }
        let issuer = chain.get(i + 1).unwrap_or(&ca);
        if i + 1 < chain.len() {
            require_issuer(issuer, "an intermediate in signer_chain")?;
        }
        verify_cert_signature(cert, issuer)?;
    }

    // The leaf: an end-entity TLS certificate, not a CA, usable for signatures.
    let leaf = &chain[0];
    if ca_flag(leaf)? {
        return Err(auth("the signing certificate is a CA certificate, not a cosigner's".into()));
    }
    match leaf.key_usage() {
        Ok(Some(ku)) if !ku.value.digital_signature() => {
            return Err(auth("the signing certificate's keyUsage lacks digitalSignature".into()))
        }
        Ok(_) => {}
        Err(_) => return Err(auth("the signing certificate's keyUsage is malformed".into())),
    }
    match leaf.extended_key_usage() {
        Ok(Some(eku)) if !(eku.value.client_auth || eku.value.server_auth) => {
            return Err(auth(
                "the signing certificate's extendedKeyUsage has neither clientAuth nor serverAuth"
                    .into(),
            ))
        }
        Ok(_) => {}
        Err(_) => return Err(auth("the signing certificate's extendedKeyUsage is malformed".into())),
    }

    // Identity: the leaf is the cosigner the request names — by the same CN rule as mTLS.
    let cn = crate::tls::subject_cn(leaf);
    if cn.as_deref().and_then(identifier_from_cn) != Some(r.identifier) {
        return Err(auth(format!(
            "the request is for node {}, but it is signed by certificate CN {:?} (expected exactly \
             one CN \"cosigner{}\")",
            r.identifier, cn, r.identifier
        )));
    }

    // Signature over the canonical request.
    let kind = KeyKind::of(leaf)?;
    if r.signature_alg != kind.request_alg() {
        return Err(auth(format!(
            "signature_alg {:?} does not match the leaf key ({})",
            r.signature_alg,
            kind.request_alg()
        )));
    }
    let sig = b64.decode(&r.signature).map_err(|_| auth("signature is not base64".into()))?;
    UnparsedPublicKey::new(kind.request_verifier(), leaf.public_key().subject_public_key.data.as_ref())
        .verify(&canonical_bytes(r), &sig)
        .map_err(|_| auth(format!("bad request signature for node {}", r.identifier)))
}

/// The basicConstraints CA flag; a malformed or duplicated extension is an error, not "no".
fn ca_flag(cert: &X509Certificate<'_>) -> Result<bool> {
    cert.basic_constraints()
        .map(|bc| bc.is_some_and(|bc| bc.value.ca))
        .map_err(|_| auth("a certificate's basicConstraints is malformed".into()))
}

/// `cert` may issue certificates: CA flag set, and keyCertSign if it has a keyUsage at all.
fn require_issuer(cert: &X509Certificate<'_>, what: &str) -> Result<()> {
    if !ca_flag(cert)? {
        return Err(auth(format!("{what} is not a CA certificate (basicConstraints CA)")));
    }
    match cert.key_usage() {
        Ok(Some(ku)) if !ku.value.key_cert_sign() => {
            Err(auth(format!("{what} may not sign certificates (keyUsage lacks keyCertSign)")))
        }
        Ok(_) => Ok(()),
        Err(_) => Err(auth(format!("{what} has a malformed keyUsage"))),
    }
}

/// Check `cert`'s signature with `issuer`'s key, and that the names chain.
fn verify_cert_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<()> {
    if cert.issuer().as_raw() != issuer.subject().as_raw() {
        return Err(auth("certificate issuer does not match the CA's subject".into()));
    }
    let sig_alg = &cert.signature_algorithm.algorithm;
    let issuer_kind = KeyKind::of(issuer)?;
    let verifier: &dyn signature::VerificationAlgorithm = match issuer_kind {
        KeyKind::EcdsaP256 if *sig_alg == OID_SIG_ECDSA_WITH_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
        KeyKind::EcdsaP256 if *sig_alg == OID_SIG_ECDSA_WITH_SHA384 => &signature::ECDSA_P256_SHA384_ASN1,
        KeyKind::EcdsaP384 if *sig_alg == OID_SIG_ECDSA_WITH_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
        KeyKind::EcdsaP384 if *sig_alg == OID_SIG_ECDSA_WITH_SHA256 => &signature::ECDSA_P384_SHA256_ASN1,
        KeyKind::Ed25519 if *sig_alg == OID_SIG_ED25519 => &signature::ED25519,
        KeyKind::Rsa if *sig_alg == OID_PKCS1_SHA256WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA256,
        KeyKind::Rsa if *sig_alg == OID_PKCS1_SHA384WITHRSA => &signature::RSA_PKCS1_2048_8192_SHA384,
        _ => {
            return Err(auth(format!(
                "certificate signature algorithm {sig_alg} with a {issuer_kind:?} issuer is not supported"
            )))
        }
    };
    UnparsedPublicKey::new(verifier, issuer.public_key().subject_public_key.data.as_ref())
        .verify(cert.tbs_certificate.as_ref(), cert.signature_value.data.as_ref())
        .map_err(|_| auth("a certificate in signer_chain is not signed by the cluster CA".into()))
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>> {
    match X509Certificate::from_der(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(auth("malformed certificate".into())),
    }
}

/// `(label, DER)` for every PEM block in `text`. The DER is zeroized on drop (key files).
fn pem_blocks(text: &[u8]) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let text = std::str::from_utf8(text).map_err(|_| auth("PEM file is not UTF-8".into()))?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let label_end = after.find("-----").ok_or_else(|| auth("malformed PEM header".into()))?;
        let label = after[..label_end].to_string();
        let body_start = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let body_end = body_start.find(&end_marker).ok_or_else(|| auth("unterminated PEM block".into()))?;
        let body: Zeroizing<String> =
            Zeroizing::new(body_start[..body_end].chars().filter(|c| !c.is_whitespace()).collect());
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| auth("PEM body is not base64".into()))?;
        out.push((label, Zeroizing::new(der)));
        rest = &body_start[body_end + end_marker.len()..];
    }
    Ok(out)
}

fn auth(msg: String) -> DaemonError {
    DaemonError::Ceremony(format!("recipient request authentication: {msg}"))
}

#[cfg(test)]
mod tests {
    use crate::test_pki::TestPki;
    use super::*;
    use crate::share_delivery::{RECIPIENT_KIND, RECIPIENT_VERSION};

    fn request(pki: &TestPki, identifier: u16) -> RecipientRequest {
        RecipientRequest {
            v: RECIPIENT_VERSION,
            kind: RECIPIENT_KIND.into(),
            ceremony_id: "c".into(),
            key_id: "frost-import-x".into(),
            cluster_id: pki.cluster_id(),
            identifier,
            threshold: 2,
            max_signers: 3,
            roster: vec![1, 2, 3],
            recipient_pub: hex::encode([7u8; 32]),
            signature_alg: String::new(),
            signer_chain: Vec::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_request_signed_by_its_node_verifies_for_every_supported_key_type() {
        for alg in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ECDSA_P384_SHA384, &rcgen::PKCS_ED25519] {
            let pki = TestPki::with_alg(alg);
            let mut r = request(&pki, 2);
            pki.signer_with("cosigner2", alg, false).sign(&mut r).unwrap();
            verify_request(&r, pki.ca_pem.as_bytes()).unwrap();
        }
    }

    #[test]
    fn every_field_is_covered_and_every_identity_mismatch_is_refused() {
        let pki = TestPki::new();
        let mut good = request(&pki, 1);
        pki.signer("cosigner1").sign(&mut good).unwrap();
        verify_request(&good, pki.ca_pem.as_bytes()).unwrap();

        // Any field changed after signing: the recipient key above all (the PoC).
        for mutate in [
            (|r: &mut RecipientRequest| r.recipient_pub = hex::encode([8u8; 32])) as fn(&mut RecipientRequest),
            |r| r.ceremony_id = "d".into(),
            |r| r.key_id = "frost-import-y".into(),
            |r| r.threshold = 3,
            |r| r.roster = vec![1, 2, 4],
        ] {
            let mut r = good.clone();
            mutate(&mut r);
            assert!(verify_request(&r, pki.ca_pem.as_bytes()).is_err());
        }

        // Signed by node 2's certificate but claiming to be node 1.
        let mut r = request(&pki, 1);
        pki.signer("cosigner2").sign(&mut r).unwrap();
        assert!(verify_request(&r, pki.ca_pem.as_bytes()).is_err());
        // Signed by a CA-issued certificate that is not a cosigner's.
        for cn in ["driver", "operator", "cosigner01", "xcosigner1"] {
            let mut r = request(&pki, 1);
            pki.signer(cn).sign(&mut r).unwrap();
            assert!(verify_request(&r, pki.ca_pem.as_bytes()).is_err(), "{cn}");
        }
        // A perfectly self-consistent request from another CA (the attacker's own PKI).
        let rogue = TestPki::new();
        let mut r = request(&pki, 1); // claims our cluster id
        rogue.signer("cosigner1").sign(&mut r).unwrap();
        assert!(verify_request(&r, pki.ca_pem.as_bytes()).is_err());
        // Ours, verified against the rogue CA: wrong cluster.
        assert!(verify_request(&good, rogue.ca_pem.as_bytes()).is_err());
        // Unsigned, and expired.
        assert!(verify_request(&request(&pki, 1), pki.ca_pem.as_bytes()).is_err());
        let mut r = request(&pki, 1);
        pki.signer_with("cosigner1", &rcgen::PKCS_ECDSA_P256_SHA256, true).sign(&mut r).unwrap();
        assert!(verify_request(&r, pki.ca_pem.as_bytes()).is_err());
    }

    #[test]
    fn the_sas_tracks_the_request_content_not_the_signature() {
        let pki = TestPki::new();
        let mut r = request(&pki, 1);
        let before = sas(&r);
        pki.signer("cosigner1").sign(&mut r).unwrap();
        assert_eq!(sas(&r), before);
        assert_eq!(before.len(), 16);
        r.recipient_pub = hex::encode([9u8; 32]);
        assert_ne!(sas(&r), before);
    }

    /// Review NEW-4 (PoC `poc2_request_auth_edge_cases`): leaves and anchors the chain check
    /// accepted.
    #[test]
    fn leaf_and_anchor_edge_cases_are_refused() {
        let pki = TestPki::new();
        let signed_by = |(cert, key): (String, String)| {
            let mut r = request(&pki, 1);
            NodeSigner::from_pem(cert.as_bytes(), key.as_bytes()).unwrap().sign(&mut r).unwrap();
            verify_request(&r, pki.ca_pem.as_bytes())
        };
        let cn1 = |p: &mut rcgen::CertificateParams| {
            p.distinguished_name.push(rcgen::DnType::CommonName, "cosigner1");
        };
        // (a) a CA certificate as the leaf.
        assert!(signed_by(pki.leaf_custom(|p| {
            cn1(p);
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        }))
        .is_err());
        // (b) two CN attributes (a BMPString naming cosigner2, then UTF8 cosigner1).
        assert!(signed_by(pki.leaf_custom(|p| {
            p.distinguished_name.push(
                rcgen::DnType::CommonName,
                rcgen::DnValue::BmpString("cosigner2".try_into().unwrap()),
            );
            p.distinguished_name.push(rcgen::DnType::CustomDnType(vec![2, 5, 4, 3]), "cosigner1");
        }))
        .is_err());
        // (b') a single CN that does not decode as a string.
        assert!(signed_by(pki.leaf_custom(|p| {
            p.distinguished_name.push(
                rcgen::DnType::CommonName,
                rcgen::DnValue::BmpString("cosigner1".try_into().unwrap()),
            );
        }))
        .is_err());
        // (c) an EKU without clientAuth/serverAuth.
        assert!(signed_by(pki.leaf_custom(|p| {
            cn1(p);
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
        }))
        .is_err());
        // (d) a keyUsage without digitalSignature.
        assert!(signed_by(pki.leaf_custom(|p| {
            cn1(p);
            p.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment];
        }))
        .is_err());
        // What gen-frost-certs.sh issues passes: KU digitalSignature, EKU serverAuth + clientAuth.
        signed_by(pki.leaf_custom(|p| {
            cn1(p);
            p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            p.extended_key_usages = vec![
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ];
        }))
        .unwrap();
        // (e) a trust anchor that is not a CA, or is expired.
        for bad_ca in [
            TestPki::with_ca(&rcgen::PKCS_ECDSA_P256_SHA256, |p| p.is_ca = rcgen::IsCa::NoCa),
            TestPki::with_ca(&rcgen::PKCS_ECDSA_P256_SHA256, |p| {
                p.not_before = rcgen::date_time_ymd(2001, 1, 1);
                p.not_after = rcgen::date_time_ymd(2002, 1, 1);
            }),
        ] {
            let mut r = request(&bad_ca, 1);
            bad_ca.signer("cosigner1").sign(&mut r).unwrap();
            assert!(verify_request(&r, bad_ca.ca_pem.as_bytes()).is_err());
        }
    }

    #[test]
    fn cn_mapping_is_strict() {
        assert_eq!(identifier_from_cn("cosigner3"), Some(3));
        for bad in ["cosigner", "cosigner03", "cosigner-1", "Cosigner1", "cosigner1 ", "driver"] {
            assert_eq!(identifier_from_cn(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let pki = TestPki::new();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "cosigner1");
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&ca_key).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        assert!(NodeSigner::from_pem(cert.pem().as_bytes(), other.serialize_pem().as_bytes()).is_err());
        let _ = pki;
    }
}

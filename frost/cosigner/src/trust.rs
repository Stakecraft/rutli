// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Trust files: the **one** validation of a cluster CA file, for every reader of one.
//!
//! rustls (through tonic) makes **every** certificate of a PEM trust file a full trust anchor, and
//! never checks an anchor's own validity, CA flag or key usage: an anchor is only a name and a key.
//! So `cat ca.crt cosigner1.crt > ca.crt` would let whoever holds `cosigner1.key` mint a
//! `cosigner2` or `driver` certificate that passes the handshake and every CN allowlist, and an
//! expired CA left in the file would keep certifying its leaves (review M1). Netty's
//! `trustManager(File)` in the driver behaves the same way.
//!
//! [`load_trust_anchors`] therefore refuses a trust file unless **every** PEM block in it is a
//! `CERTIFICATE` that is a CA allowed to sign certificates (basicConstraints CA, keyCertSign when a
//! keyUsage is present — [`check_issuer`]) and valid now ([`check_anchor`]). Readers:
//!
//! - the cosigner (`tls::load`, so the daemon, `refresh` and `verify-key`): it then hands rustls a
//!   PEM re-encoded from exactly the certificates it validated, so no second parser decides what
//!   is trusted;
//! - `rutli-dealer split-key --ca-cert`, before it verifies any recipient request
//!   (`request_auth` additionally applies [`check_anchor`] per anchor);
//! - the driver (`FrostTrustFile.scala`), with the same rules.
//!
//! An expired or not-yet-valid anchor is refused unless the caller passes `allow_expired`
//! (`tls.allow_expired_ca`): the one case that needs it is an emergency rotation away from a CA
//! that has already expired, where the old CA must stay in the bundle until the leaves are swapped.
//! A file that is not a CA is never accepted.

use base64::Engine;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;
use zeroize::Zeroizing;

/// One validated trust anchor, and what to log about it.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// RFC 4514 subject.
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    /// Lowercase hex SHA-256 of the DER (`openssl x509 -noout -fingerprint -sha256`, without colons).
    pub sha256: String,
    /// Valid now. Always true unless the file was loaded with `allow_expired`.
    pub valid_now: bool,
    /// Whole days until `not_after` (negative once expired).
    pub days_left: i64,
}

impl TrustAnchor {
    /// One log/print line: `subject=… notAfter=… sha256=…`.
    pub fn describe(&self) -> String {
        format!("subject={:?} notAfter={} sha256={}", self.subject, self.not_after, self.sha256)
    }
}

/// Validate a trust file (PEM) and return its anchors, in file order. See the module docs for the
/// rules. The error names the offending block by its index and never echoes its content.
pub fn load_trust_anchors(pem: &[u8], allow_expired: bool) -> Result<Vec<TrustAnchor>, String> {
    let blocks = pem_blocks(pem)?;
    if blocks.is_empty() {
        return Err("no CERTIFICATE in the trust file".into());
    }
    let now = ASN1Time::now();
    let mut out = Vec::with_capacity(blocks.len());
    for (i, (label, der)) in blocks.iter().enumerate() {
        if label != "CERTIFICATE" {
            return Err(format!(
                "PEM block {i} is a {label:?}, not a CERTIFICATE — a trust file holds only CA \
                 certificates (if this is a private key, treat it as exposed)"
            ));
        }
        let cert = parse(der).map_err(|e| format!("certificate {i}: {e}"))?;
        let subject = cert.subject().to_string();
        let valid_now = cert.validity().is_valid_at(now);
        check_issuer(&cert).map_err(|e| {
            format!(
                "certificate {i} ({subject}) {e} — every certificate in a trust file is a trust \
                 anchor, so a leaf here would let its key holder issue any identity"
            )
        })?;
        if !valid_now && !allow_expired {
            return Err(format!(
                "certificate {i} ({subject}) is expired or not yet valid (notBefore {}, notAfter \
                 {}, now {now}) — remove it, or set tls.allow_expired_ca for an emergency rotation \
                 away from an expired CA",
                cert.validity().not_before,
                cert.validity().not_after
            ));
        }
        let days_left = (cert.validity().not_after.timestamp() - now.timestamp()).div_euclid(86_400);
        out.push(TrustAnchor {
            der: der.to_vec(),
            subject,
            not_before: cert.validity().not_before.to_string(),
            not_after: cert.validity().not_after.to_string(),
            sha256: hex::encode(Sha256::digest(der.as_slice())),
            valid_now,
            days_left,
        });
    }
    Ok(out)
}

/// The anchors as one PEM text — what the TLS stack is given, so it trusts exactly what
/// [`load_trust_anchors`] validated.
pub fn to_pem(anchors: &[TrustAnchor]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = String::new();
    for a in anchors {
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let body = b64.encode(&a.der);
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    out
}

/// The per-anchor rule: a CA allowed to sign certificates ([`check_issuer`]) and valid at `now`.
pub fn check_anchor(cert: &X509Certificate<'_>, now: ASN1Time) -> Result<(), String> {
    check_issuer(cert)?;
    if !cert.validity().is_valid_at(now) {
        return Err("is expired or not yet valid".into());
    }
    Ok(())
}

/// `cert` may issue certificates: basicConstraints CA, and keyCertSign if it has a keyUsage at
/// all. The error reads after the certificate's name ("… is not a CA certificate …").
pub fn check_issuer(cert: &X509Certificate<'_>) -> Result<(), String> {
    if !ca_flag(cert)? {
        return Err("is not a CA certificate (basicConstraints CA)".into());
    }
    match cert.key_usage() {
        Ok(Some(ku)) if !ku.value.key_cert_sign() => {
            Err("may not sign certificates (keyUsage lacks keyCertSign)".into())
        }
        Ok(_) => Ok(()),
        Err(_) => Err("has a malformed keyUsage".into()),
    }
}

/// The basicConstraints CA flag; a malformed or duplicated extension is an error, not "no".
pub fn ca_flag(cert: &X509Certificate<'_>) -> Result<bool, String> {
    cert.basic_constraints()
        .map(|bc| bc.is_some_and(|bc| bc.value.ca))
        .map_err(|_| "has a malformed basicConstraints".into())
}

/// A DER certificate, with nothing after it.
pub fn parse(der: &[u8]) -> Result<X509Certificate<'_>, String> {
    match X509Certificate::from_der(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err("malformed certificate".into()),
    }
}

/// One PEM block: its label and its DER, zeroized on drop (key files).
pub type PemBlock = (String, Zeroizing<Vec<u8>>);

/// `(label, DER)` for every PEM block in `text`. Text outside the blocks (comments, OpenSSL
/// "Bag Attributes") is ignored.
pub fn pem_blocks(text: &[u8]) -> Result<Vec<PemBlock>, String> {
    let text = std::str::from_utf8(text).map_err(|_| "PEM file is not UTF-8".to_string())?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let label_end = after.find("-----").ok_or("malformed PEM header")?;
        let label = after[..label_end].to_string();
        let body_start = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let body_end = body_start.find(&end_marker).ok_or("unterminated PEM block")?;
        let body: Zeroizing<String> =
            Zeroizing::new(body_start[..body_end].chars().filter(|c| !c.is_whitespace()).collect());
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| "PEM body is not base64".to_string())?;
        out.push((label, Zeroizing::new(der)));
        rest = &body_start[body_end + end_marker.len()..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca(f: impl FnOnce(&mut rcgen::CertificateParams)) -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, "test-ca");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        f(&mut p);
        (p.self_signed(&key).unwrap(), key)
    }

    #[test]
    fn a_ca_bundle_loads_in_order_and_round_trips_to_pem() {
        let (a, _) = ca(|_| {});
        let (b, _) = ca(|p| {
            p.distinguished_name = rcgen::DistinguishedName::new();
            p.distinguished_name.push(rcgen::DnType::CommonName, "other-ca");
        });
        // Text around the blocks, as `openssl pkcs12` writes it, is ignored.
        let pem = format!("Bag Attributes\n{}\n# comment\n{}", a.pem(), b.pem());
        let anchors = load_trust_anchors(pem.as_bytes(), false).unwrap();
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].subject, "CN=test-ca");
        assert_eq!(anchors[1].subject, "CN=other-ca");
        assert_eq!(anchors[0].sha256, hex::encode(Sha256::digest(a.der())));
        assert!(anchors.iter().all(|a| a.valid_now && a.days_left > 365));
        let again = load_trust_anchors(to_pem(&anchors).as_bytes(), false).unwrap();
        assert_eq!(again.iter().map(|a| &a.der).collect::<Vec<_>>(), anchors.iter().map(|a| &a.der).collect::<Vec<_>>());
        assert!(anchors[0].describe().contains("notAfter="));
    }

    #[test]
    fn every_non_anchor_is_refused() {
        let (good, good_key) = ca(|_| {});
        let leaf = {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(vec!["x".into()]).unwrap();
            p.distinguished_name.push(rcgen::DnType::CommonName, "cosigner1");
            p.signed_by(&key, &good, &good_key).unwrap()
        };
        let (no_cert_sign, _) = ca(|p| p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature]);
        let (explicit_not_ca, _) = ca(|p| p.is_ca = rcgen::IsCa::ExplicitNoCa);
        let (no_bc, _) = ca(|p| p.is_ca = rcgen::IsCa::NoCa);
        for (what, bad, needle) in [
            ("leaf", leaf.pem(), "not a CA"),
            ("no keyCertSign", no_cert_sign.pem(), "keyCertSign"),
            ("CA=false", explicit_not_ca.pem(), "not a CA"),
            ("no basicConstraints", no_bc.pem(), "not a CA"),
        ] {
            for (pem, index) in [(format!("{}{bad}", good.pem()), 1), (format!("{bad}{}", good.pem()), 0)] {
                let e = load_trust_anchors(pem.as_bytes(), true).unwrap_err();
                assert!(e.contains(needle) && e.contains(&format!("certificate {index}")), "{what}: {e}");
            }
        }
        // Not PEM certificates at all.
        let key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let e = load_trust_anchors(format!("{}{key}", good.pem()).as_bytes(), false).unwrap_err();
        assert!(e.contains("PEM block 1") && e.contains("PRIVATE KEY"), "{e}");
        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(load_trust_anchors(garbage.as_bytes(), false).unwrap_err().contains("malformed"));
        let open = "-----BEGIN CERTIFICATE-----\nAAAA\n";
        assert!(load_trust_anchors(open.as_bytes(), false).unwrap_err().contains("unterminated"));
        assert!(load_trust_anchors(b"", false).unwrap_err().contains("no CERTIFICATE"));
    }

    #[test]
    fn an_expired_anchor_is_refused_unless_explicitly_allowed() {
        let (expired, _) = ca(|p| {
            p.not_before = rcgen::date_time_ymd(2001, 1, 1);
            p.not_after = rcgen::date_time_ymd(2002, 1, 1);
        });
        let (good, _) = ca(|_| {});
        let pem = format!("{}{}", expired.pem(), good.pem());
        let e = load_trust_anchors(pem.as_bytes(), false).unwrap_err();
        assert!(e.contains("certificate 0") && e.contains("expired") && e.contains("allow_expired_ca"), "{e}");
        let anchors = load_trust_anchors(pem.as_bytes(), true).unwrap();
        assert!(!anchors[0].valid_now && anchors[0].days_left < 0);
        assert!(anchors[1].valid_now);
    }
}

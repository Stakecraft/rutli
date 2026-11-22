// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner key`: the read-only key commands (docs/admin-cli.md).
//!
//! - `key show` prints what the cluster holds under a key id. It only decides here which of the two
//!   existing checks to run ([`KeyKind::of`]); the checks are [`crate::verify_key`] (FROST) and
//!   [`crate::verify_hosted`] (cluster-hosted), over the same read-only RPCs and with the same
//!   certificate as `verify-key` and `verify-hosted`.
//! - `key fingerprint` computes the Canton fingerprint of a public key file
//!   ([`parse_public_input`]). Offline: no config, no certificate, no network.
//!
//! Neither command reads or writes key material, starts a ceremony, or adds an RPC.

use base64::Engine;
use rutli_canton_key::{KeySpec, PublicKey};

use crate::{DaemonError, Result};

/// Which kind of cluster key an id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// A FROST threshold key: one share per cosigner (`Signer.KeyStatus`).
    Frost,
    /// A cluster-hosted key: the same key on every cosigner (`Signer.HostedKeyStatus`).
    Hosted,
}

impl KeyKind {
    /// The kind `key_id` can name, by the rule the cosigners enforce on every hosted-key write
    /// ([`crate::node::refuse_unless_hosted_id`]): a hosted key exists only under an id whose
    /// routing tag is `rutli-`. Any other id — `<prefix>frost-…`, or one with no tag at all — can
    /// only hold a FROST share.
    pub fn of(key_id: &str) -> Self {
        if crate::node::routing_tag(key_id) == Some(crate::export::HOSTED_ROUTING_TAG) {
            KeyKind::Hosted
        } else {
            KeyKind::Frost
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KeyKind::Frost => "frost",
            KeyKind::Hosted => "hosted",
        }
    }
}

/// More than any public key file holds: an RSA-2048 SPKI is 294 bytes, and PEM, hex or Canton's
/// wrapper at most triple that.
pub const MAX_PUBLIC_KEY_INPUT: usize = 16 * 1024;

/// A public key read by [`parse_public_input`], and what the input was read as.
#[derive(Debug)]
pub struct PublicInput {
    pub public: PublicKey,
    pub format: &'static str,
}

impl PublicInput {
    pub fn spec_name(&self) -> &'static str {
        match self.public.spec() {
            KeySpec::Ed25519 => "Ed25519",
            KeySpec::EcP256 => "EC P-256",
            KeySpec::Rsa2048 => "RSA-2048",
        }
    }
}

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_PUBLIC_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_PUBLIC_END: &str = "-----END PUBLIC KEY-----";
/// The fixed head of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the 32-byte key follows.
const ED25519_SPKI_HEAD: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Read a public key for `key fingerprint`. Accepted, and told apart by the input alone:
///
/// - X.509 SubjectPublicKeyInfo, as DER, as one `PUBLIC KEY` PEM block, or as hex (what `key show`
///   and `verify-hosted` print for a hosted key);
/// - a raw Ed25519 public key as 64 hex digits (what `key show` and `verify-key` print as the
///   group key);
/// - a Canton public key file (console `keys.public.download`).
///
/// Every route ends in `rutli-canton-key`'s validation: a point on the curve or a well-formed
/// RSA-2048 key, in canonical encoding. A PEM private key is refused by its label, before
/// anything is decoded, and PKCS#8 or a Canton key export is not a public key in any of these
/// forms. 64 hex digits, however, are always read as a public key: a raw Ed25519 seed looks the
/// same, so this command must only ever be given public values.
pub fn parse_public_input(input: &[u8]) -> Result<PublicInput> {
    let refuse =
        |why: String| DaemonError::Config(format!("not a public key this command reads: {why}"));
    if input.len() > MAX_PUBLIC_KEY_INPUT {
        return Err(refuse(format!("more than {MAX_PUBLIC_KEY_INPUT} bytes")));
    }
    if let Ok(text) = std::str::from_utf8(input) {
        let text = text.trim();
        if text.starts_with(PEM_BEGIN) {
            let der = public_pem_to_der(text).map_err(refuse)?;
            let public = PublicKey::from_spki_der(&der).map_err(|e| refuse(e.to_string()))?;
            return Ok(PublicInput {
                public,
                format: "SubjectPublicKeyInfo (PEM)",
            });
        }
        if !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            let bytes = hex::decode(text).map_err(|e| refuse(format!("hex: {e}")))?;
            let (der, format) = match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(raw) => (
                    [ED25519_SPKI_HEAD.as_slice(), &raw].concat(),
                    "raw Ed25519 public key (hex)",
                ),
                Err(_) => (bytes, "SubjectPublicKeyInfo (hex)"),
            };
            let public = PublicKey::from_spki_der(&der).map_err(|e| refuse(e.to_string()))?;
            return Ok(PublicInput { public, format });
        }
    }
    let as_spki = match PublicKey::from_spki_der(input) {
        Ok(public) => {
            return Ok(PublicInput {
                public,
                format: "SubjectPublicKeyInfo (DER)",
            })
        }
        Err(e) => e,
    };
    match rutli_canton_key::parse_public_key(input) {
        Ok(canton) => Ok(PublicInput { public: canton.public, format: "Canton public key (keys.public.download)" }),
        Err(as_canton) => Err(refuse(format!(
            "as SubjectPublicKeyInfo DER: {as_spki}; as a Canton public key file: {as_canton}. Give \
             SubjectPublicKeyInfo (DER, PEM or hex), a Canton `keys.public.download` file, or the 64 \
             hex digits of a raw Ed25519 public key"
        ))),
    }
}

/// The DER inside exactly one `PUBLIC KEY` PEM block; nothing before, between or after it. Any
/// other label is refused by name, before anything is decoded — a private key is not read.
fn public_pem_to_der(text: &str) -> std::result::Result<Vec<u8>, String> {
    let mut lines = text.lines().map(str::trim);
    let first = lines.next().unwrap_or_default();
    if first != PEM_PUBLIC_BEGIN {
        // The line itself is not repeated: nothing of the input goes into an error.
        return Err(if first.contains("PRIVATE KEY") {
            "the file is a PRIVATE key; `key fingerprint` reads public keys only".to_string()
        } else {
            "PEM must be one `PUBLIC KEY` block, and this is another kind".to_string()
        });
    }
    let mut body = String::new();
    let mut closed = false;
    for line in lines {
        if closed {
            return Err("data after the PEM END line".into());
        }
        if line == PEM_PUBLIC_END {
            closed = true;
        } else {
            body.push_str(line);
        }
    }
    if !closed {
        return Err("PEM END line missing".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| "PEM body is not valid base64".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 TEST 1.
    const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn pem(der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let body: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "{PEM_PUBLIC_BEGIN}\n{}\n{PEM_PUBLIC_END}\n",
            body.join("\n")
        )
    }

    fn refusal(input: &[u8]) -> String {
        parse_public_input(input).unwrap_err().to_string()
    }

    #[test]
    fn show_routes_an_id_as_the_cosigners_do() {
        // The driver's two id shapes, with and without a `frost.key-prefix`.
        for id in [
            "frost-namespace",
            "p1-frost-signing",
            "frost-import-1220cb0e",
            "frost-participant1-rutli-x",
        ] {
            assert_eq!(KeyKind::of(id), KeyKind::Frost, "{id}");
        }
        for id in [
            "rutli-enc-1",
            "p2-rutli-enc-ecies-1",
            "p1-rutli-enc-frost-named-key-1",
            "rutli-sym-p1",
        ] {
            assert_eq!(KeyKind::of(id), KeyKind::Hosted, "{id}");
        }
        // No tag: never a hosted key (every hosted write refuses such an id), so a FROST lookup.
        for id in ["namespace-participant1", "k", "rutli", "frost", ""] {
            assert_eq!(KeyKind::of(id), KeyKind::Frost, "{id}");
        }
        // Exactly the cosigners' own rule, for every id above and a few more.
        for id in [
            "frost-a",
            "rutli-a",
            "x-rutli-frost-a",
            "x-frost-rutli-a",
            "plain",
            "RUTLI-a",
        ] {
            let hosted = crate::node::refuse_unless_hosted_id(id).is_ok();
            assert_eq!(KeyKind::of(id) == KeyKind::Hosted, hosted, "{id}");
        }
        assert_eq!(
            (KeyKind::Frost.as_str(), KeyKind::Hosted.as_str()),
            ("frost", "hosted")
        );
    }

    #[test]
    fn one_ed25519_key_has_one_fingerprint_in_every_encoding() {
        let raw: [u8; 32] = hex::decode(RFC8032_PUBLIC).unwrap().try_into().unwrap();
        let public = PublicKey::Ed25519(raw);
        let der = public.spki_der();
        let expected = crate::share_delivery::ed25519_fingerprint(&raw);
        assert!(expected.starts_with("1220") && expected.len() == 68);
        for (input, format) in [
            (
                RFC8032_PUBLIC.as_bytes().to_vec(),
                "raw Ed25519 public key (hex)",
            ),
            (
                format!("  {}\n", RFC8032_PUBLIC.to_uppercase()).into_bytes(),
                "raw Ed25519 public key (hex)",
            ),
            (der.clone(), "SubjectPublicKeyInfo (DER)"),
            (hex::encode(&der).into_bytes(), "SubjectPublicKeyInfo (hex)"),
            (pem(&der).into_bytes(), "SubjectPublicKeyInfo (PEM)"),
        ] {
            let parsed = parse_public_input(&input).unwrap();
            assert_eq!((parsed.format, parsed.spec_name()), (format, "Ed25519"));
            assert_eq!(parsed.public, public, "{format}");
            assert_eq!(parsed.public.fingerprint(), expected, "{format}");
        }
    }

    #[test]
    fn hosted_public_keys_are_read_as_the_cluster_prints_them() {
        use crate::hosted::{HostedKey, HostedSpec};
        for (spec, name) in [
            (HostedSpec::EcP256, "EC P-256"),
            (HostedSpec::Rsa2048, "RSA-2048"),
        ] {
            let der = HostedKey::generate(spec, 1)
                .unwrap()
                .public_key_der()
                .unwrap();
            let expected = PublicKey::from_spki_der(&der).unwrap().fingerprint();
            for input in [
                der.clone(),
                hex::encode(&der).into_bytes(),
                pem(&der).into_bytes(),
            ] {
                let parsed = parse_public_input(&input).unwrap();
                assert_eq!(
                    (parsed.spec_name(), parsed.public.fingerprint()),
                    (name, expected.clone())
                );
            }
        }
    }

    /// Canton 3.6.1's own `keys.public.download` files and the fingerprints Canton printed for
    /// them (`frost/canton-key/testdata`, throwaway keys).
    #[test]
    fn cantons_public_key_files_give_cantons_fingerprints() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../canton-key/testdata/vectors");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        let keys = manifest["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 6);
        for key in keys {
            let name = key["name"].as_str().unwrap();
            let file = std::fs::read(dir.join(format!("{name}.pub.bin"))).unwrap();
            let parsed = parse_public_input(&file).unwrap();
            assert_eq!(
                parsed.format, "Canton public key (keys.public.download)",
                "{name}"
            );
            assert_eq!(
                parsed.public.fingerprint(),
                key["fingerprint"].as_str().unwrap(),
                "{name}"
            );
            // The same key as bare SPKI: the same fingerprint.
            let spki = parse_public_input(&parsed.public.spki_der()).unwrap();
            assert_eq!(
                spki.public.fingerprint(),
                parsed.public.fingerprint(),
                "{name}"
            );
            // The private halves of the same keys are not public keys.
            for private in ["export", "export-pw", "stored"] {
                let file = std::fs::read(dir.join(format!("{name}.{private}.bin"))).unwrap();
                assert!(parse_public_input(&file).is_err(), "{name}.{private}.bin");
            }
        }
    }

    #[test]
    fn anything_else_is_refused_and_a_private_key_is_never_decoded() {
        let raw: [u8; 32] = hex::decode(RFC8032_PUBLIC).unwrap().try_into().unwrap();
        let der = PublicKey::Ed25519(raw).spki_der();
        // Private keys, by label: the body here is not even base64.
        for label in [
            "PRIVATE KEY",
            "EC PRIVATE KEY",
            "RSA PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
        ] {
            let r = refusal(
                format!("-----BEGIN {label}-----\n!!!\n-----END {label}-----\n").as_bytes(),
            );
            assert!(r.contains("PRIVATE key") && !r.contains("base64"), "{r}");
        }
        let r = refusal(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        assert!(
            r.contains("one `PUBLIC KEY` block") && !r.contains("CERTIFICATE"),
            "{r}"
        );
        // One block, whole, and nothing around it.
        let one = pem(&der);
        assert!(refusal(format!("{one}{one}").as_bytes()).contains("after the PEM END line"));
        assert!(refusal(one.replace(PEM_PUBLIC_END, "").as_bytes()).contains("END line missing"));
        assert!(
            refusal(format!("{PEM_PUBLIC_BEGIN}\n!!!\n{PEM_PUBLIC_END}\n").as_bytes())
                .contains("base64")
        );
        // Hex of the wrong length, a point not on the curve, a truncated or padded SPKI. 31 or 33
        // bytes of hex are never padded or cut to a key: they are read as (bad) SPKI.
        for digits in [62, 66] {
            let hex = format!("{RFC8032_PUBLIC}00");
            assert!(
                refusal(&hex.as_bytes()[..digits]).contains("SubjectPublicKeyInfo: "),
                "{digits}"
            );
        }
        // 31 zero bytes: padded to 32 they would be a valid point (y = 0).
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).is_ok());
        assert!(refusal("00".repeat(31).as_bytes()).contains("SubjectPublicKeyInfo: "));
        assert!(refusal(&RFC8032_PUBLIC.as_bytes()[..63]).contains("hex"));
        // A y with no x on edwards25519 (about every second one).
        let off_curve = (2u8..)
            .map(|y| [&[y][..], &[0u8; 31]].concat())
            .find(|y| {
                ed25519_dalek::VerifyingKey::from_bytes(y.as_slice().try_into().unwrap()).is_err()
            })
            .unwrap();
        assert!(refusal(hex::encode(off_curve).as_bytes()).contains("not a valid curve point"));
        assert!(refusal(&der[..der.len() - 1]).contains("as SubjectPublicKeyInfo DER"));
        assert!(refusal(&[der.as_slice(), &[0]].concat()).contains("as a Canton public key file"));
        assert!(refusal(b"").contains("not a public key"));
        assert!(refusal(&vec![0x30; MAX_PUBLIC_KEY_INPUT + 1]).contains("more than"));
    }
}

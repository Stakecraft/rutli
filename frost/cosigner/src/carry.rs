// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! What a key brought in by the split ceremony is carried *for* (milestone B6,
//! docs/migration.md "Carrying the signing and encryption keys").
//!
//! The split ceremony was built for the namespace key. B6 lets it carry a participant's protocol
//! signing and sequencer-authentication keys as well — discouraged, but possible. Two things must
//! then never be confused:
//!
//! - **Which key it is.** Canton records each signing key's usage, but the usage alone does not
//!   identify the namespace key: Splice generates its `signing` key with `SigningKeyUsage.All`,
//!   which *includes* `namespace` (`NodeInitializer.scala:69-73`), and a Canton key whose usage
//!   list is empty is read as `All` (`Signing.scala:874-888`). Only the node's namespace — the
//!   fingerprint after `::` in its UID — says which key is the root.
//! - **Which id it lives under.** The driver's approval policy matches key-id *prefixes*, first
//!   match wins (`ApprovalPolicy.scala:38-42`). Protocol keys therefore get their own sub-prefixes,
//!   `<prefix>frost-import-sig-<name>` and `<prefix>frost-import-seqauth-<name>`, and the namespace
//!   key keeps `<prefix>frost-import-<name>`. A protocol key under a namespace-style id (or the
//!   other way round) would be held by — or escape — the wrong rule.
//!
//! [`check_carried_id`] is the one rule set: the dealer applies it ([`check_dealer_usage`]) and every
//! cosigner applies it again at `import-share`, from the bundle's authenticated [`CarriedUsage`]
//! and Canton fingerprint.

use std::collections::BTreeSet;

use rutli_canton_key::SigningKeyUsage;
use serde::{Deserialize, Serialize};

use crate::share_delivery::{is_import_key_id, IMPORT_MARKER};
use crate::{DaemonError, Result};

/// The sub-prefix of a carried protocol signing key: `<prefix>frost-import-sig-<name>`.
pub const PROTOCOL_LABEL: &str = "sig-";
/// The sub-prefix of a carried sequencer-authentication key: `<prefix>frost-import-seqauth-<name>`.
pub const SEQAUTH_LABEL: &str = "seqauth-";

/// `rutli-dealer split-key --expect-usage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarriedFor {
    /// The namespace (root) key. B2's only case, and the default.
    Namespace,
    /// A protocol signing or sequencer-authentication key (B6, discouraged).
    Protocol,
}

impl CarriedFor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Protocol => "protocol",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "namespace" => Ok(Self::Namespace),
            "protocol" => Ok(Self::Protocol),
            other => Err(refuse(format!("expected usage {other:?} is neither namespace nor protocol"))),
        }
    }
}

/// What an import id says about its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportIdClass {
    /// `<prefix>frost-import-<name>`, `<name>` not starting with a protocol label.
    Namespace,
    /// `<prefix>frost-import-sig-<name>`.
    ProtocolSigning,
    /// `<prefix>frost-import-seqauth-<name>`.
    SequencerAuth,
}

/// The class of an import id, or `None` when it is not one — including an id with the marker more
/// than once, whose class would depend on which occurrence a reader picks.
pub fn import_id_class(key_id: &str) -> Option<ImportIdClass> {
    if !is_import_key_id(key_id) || key_id.matches(IMPORT_MARKER).count() != 1 {
        return None;
    }
    let at = key_id.find(IMPORT_MARKER)? + IMPORT_MARKER.len();
    let name = &key_id[at..];
    let labelled = |label: &str| name.strip_prefix(label).map(|rest| !rest.is_empty());
    Some(match (labelled(PROTOCOL_LABEL), labelled(SEQAUTH_LABEL)) {
        (Some(true), _) => ImportIdClass::ProtocolSigning,
        (_, Some(true)) => ImportIdClass::SequencerAuth,
        // `frost-import-sig-` with nothing after: neither a protocol id nor a namespace id.
        (Some(false), _) | (_, Some(false)) => return None,
        _ => ImportIdClass::Namespace,
    })
}

/// What the dealer was told a key is for, what Canton recorded about it, and the operator's
/// acknowledgement of the namespace. Travels inside the share bundle, bound into the envelope's AAD,
/// and lands in the installed share's provenance. Every rule the dealer applies to it is
/// re-applied by each cosigner at install ([`check_carried_id`]), against the bundle's own Canton
/// fingerprint: a modified dealer cannot produce an installable bundle the real one would refuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedUsage {
    /// [`CarriedFor::as_str`]: `namespace` or `protocol`.
    pub expected: String,
    /// The key's recorded Canton usage, as Canton names it ([`SigningKeyUsage::identifier`]),
    /// sorted. Empty: a legacy key with no usage list, which Canton reads as `All`. `None`: the
    /// input carried no Canton metadata (plain PKCS#8).
    pub recorded: Option<Vec<String>>,
    /// `--namespace-fingerprint` as given (trimmed, lower case): the old node's namespace as the
    /// operator read it from its UID. `None` when not given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_fingerprint: Option<String>,
}

impl CarriedUsage {
    /// The three AAD fields this adds to a share envelope (each length-prefixed by the caller).
    pub fn aad_fields(&self) -> [Vec<u8>; 3] {
        let recorded = match &self.recorded {
            Some(list) => format!("recorded:{}", list.join(",")),
            None => "unknown".to_string(),
        };
        let namespace = match &self.namespace_fingerprint {
            Some(fp) => format!("namespace:{fp}"),
            None => "none".to_string(),
        };
        [self.expected.as_bytes().to_vec(), recorded.into_bytes(), namespace.into_bytes()]
    }

    /// The usage Canton acts on: the recorded list without the retired `identity-delegation`
    /// (`fromProtoEnumV30` drops it), and `All` for an empty list. `None` when unknown.
    pub fn effective(&self) -> Result<Option<BTreeSet<SigningKeyUsage>>> {
        let Some(recorded) = &self.recorded else { return Ok(None) };
        let parsed = recorded
            .iter()
            .map(|s| {
                SigningKeyUsage::from_identifier(s)
                    .ok_or_else(|| refuse(format!("unknown Canton key usage {s:?}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(effective_usage(&parsed)))
    }
}

/// See [`CarriedUsage::effective`].
pub fn effective_usage(recorded: &[SigningKeyUsage]) -> BTreeSet<SigningKeyUsage> {
    let set: BTreeSet<_> =
        recorded.iter().copied().filter(|u| *u != SigningKeyUsage::IdentityDelegation).collect();
    if set.is_empty() {
        SigningKeyUsage::ALL.into_iter().collect()
    } else {
        set
    }
}

fn names(set: &BTreeSet<SigningKeyUsage>) -> String {
    set.iter().map(|u| u.identifier()).collect::<Vec<_>>().join(",")
}

fn is_fingerprint(s: &str) -> bool {
    s.len() == 68 && s.starts_with("1220") && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The dealer's usage rules (`split-key --expect-usage`): builds the [`CarriedUsage`] from the
/// key's usage list (`recorded`, `None` for plain PKCS#8) and `--namespace-fingerprint`, then
/// applies [`check_carried_id`] — the very rules every cosigner re-applies at install.
pub fn check_dealer_usage(
    expect: CarriedFor,
    key_id: &str,
    key_fingerprint: &str,
    recorded: Option<&[SigningKeyUsage]>,
    namespace_fingerprint: Option<&str>,
) -> Result<CarriedUsage> {
    let carried = CarriedUsage {
        expected: expect.as_str().to_string(),
        recorded: recorded.map(|r| {
            let mut v: Vec<String> = r.iter().map(|u| u.identifier().to_string()).collect();
            v.sort();
            v.dedup();
            v
        }),
        // Normalised so that an upper-cased copy of the key's own fingerprint cannot pass protocol
        // mode's "differs" check, and so that the AAD binds one spelling.
        namespace_fingerprint: namespace_fingerprint
            .map(|s| {
                crate::share_delivery::canonical_fingerprint(s)
                    .map_err(|e| refuse(format!("--namespace-fingerprint: {e}")))
            })
            .transpose()?,
    };
    check_carried_id(key_id, key_fingerprint, &carried)?;
    Ok(carried)
}

/// The id class `expect` requires, checked from the id alone — before the dealer reads any secret.
pub fn check_id_class(key_id: &str, expect: CarriedFor) -> Result<ImportIdClass> {
    let class = import_id_class(key_id).ok_or_else(|| {
        refuse(format!(
            "{key_id:?} is not an import id with one `{IMPORT_MARKER}` and a name after it \
             (<prefix>{IMPORT_MARKER}<name>, <prefix>{IMPORT_MARKER}{PROTOCOL_LABEL}<name>, \
             <prefix>{IMPORT_MARKER}{SEQAUTH_LABEL}<name>)"
        ))
    })?;
    match (expect, class) {
        (CarriedFor::Namespace, ImportIdClass::Namespace) => Ok(class),
        (CarriedFor::Namespace, _) => Err(refuse(format!(
            "{key_id} is a protocol key id (`{IMPORT_MARKER}{PROTOCOL_LABEL}` / \
             `{IMPORT_MARKER}{SEQAUTH_LABEL}`); a namespace key keeps <prefix>{IMPORT_MARKER}<name>"
        ))),
        (CarriedFor::Protocol, ImportIdClass::Namespace) => Err(refuse(format!(
            "{key_id} is a namespace-style id; a protocol key is carried as \
             <prefix>{IMPORT_MARKER}{PROTOCOL_LABEL}<name> (protocol signing) or \
             <prefix>{IMPORT_MARKER}{SEQAUTH_LABEL}<name> (sequencer authentication), so that an \
             approval rule naming the namespace id never holds — or releases — the wrong key"
        ))),
        (CarriedFor::Protocol, _) => Ok(class),
    }
}

/// The carry rules, applied by the dealer and again by every cosigner at install, against the key's
/// Canton fingerprint (`key_fingerprint`; at install, the bundle's, which `import-share` checks is
/// its group key's and the operator's `--expect-fingerprint`). The namespace acknowledgement is
/// `carried.namespace_fingerprint`, the old node's namespace read from its UID.
///
/// - **namespace**: the key's effective usage must include `namespace`. Exactly `{namespace}`
///   (recorded, not an empty list) is the plain case. Anything else — extra usages (Splice's
///   `signing` key, a hand-initialised node), a legacy empty list, or no Canton metadata — needs
///   the namespace fingerprint, equal to the key's own: this key *is* the root.
/// - **protocol**: the usage must be known (no plain PKCS#8) and include `signing` (protocol) or
///   `sequencer-auth`, and the namespace fingerprint is **always** required and must *differ* from
///   the key's. The recorded usage is advisory: it is unsigned metadata in the export (or the
///   database row), so a namespace key whose container was altered or mislabelled to say
///   `[signing]` would otherwise pass. The namespace read from the node's UID is the discriminator;
///   the usage only picks the mode, the label and the operator's prompts.
/// - A given namespace fingerprint is always checked; the id must be of the mode's class
///   ([`check_id_class`]); a protocol id's label must match the usage: `sig-` when it includes
///   `signing`, `seqauth-` for `sequencer-auth` without `signing`.
///
/// **What this does not exclude.** The namespace fingerprint rules out the *root* namespace key
/// only. A key that is the target of a namespace delegation also signs for the namespace; whether
/// the carried key is one is a topology question the runbook answers before the split
/// (docs/migration.md §8, "Before the split").
pub fn check_carried_id(key_id: &str, key_fingerprint: &str, carried: &CarriedUsage) -> Result<()> {
    let expect = CarriedFor::parse(&carried.expected)?;
    let effective = carried.effective()?;
    let shown = match (&effective, carried.recorded.as_deref()) {
        (None, _) => "unknown (plain PKCS#8 carries no Canton usage)".to_string(),
        (Some(e), Some([])) => format!("none recorded, which Canton reads as all ({})", names(e)),
        (Some(e), _) => names(e),
    };
    let key_fingerprint = key_fingerprint.trim().to_ascii_lowercase();
    let ns = carried.namespace_fingerprint.as_deref();
    if let Some(ns) = ns {
        if !is_fingerprint(ns) || ns != ns.to_ascii_lowercase() {
            return Err(refuse(format!(
                "--namespace-fingerprint {ns:?} is not a 1220… Canton fingerprint (lower case)"
            )));
        }
    }
    let has = |u: SigningKeyUsage| effective.as_ref().is_some_and(|e| e.contains(&u));
    match expect {
        CarriedFor::Namespace => {
            if effective.is_some() && !has(SigningKeyUsage::Namespace) {
                return Err(refuse(format!(
                    "the key's usage is {shown}, which does not include namespace — this is not a \
                     namespace key (for a protocol key, see --expect-usage protocol)"
                )));
            }
            let plain = effective.as_ref().is_some_and(|e| e.len() == 1)
                && carried.recorded.as_ref().is_some_and(|r| !r.is_empty());
            match ns {
                Some(ns) if ns != key_fingerprint => {
                    return Err(refuse(format!(
                        "this key ({key_fingerprint}) is not the namespace {ns} — wrong key file. \
                         (A Splice validator's `signing` key has usage {}, namespace included, but \
                         its namespace key is the one named `namespace`.)",
                        names(&SigningKeyUsage::ALL.into_iter().collect())
                    )))
                }
                None if !plain => {
                    return Err(refuse(format!(
                        "the key's usage is {shown}, not namespace alone, so the usage does not \
                         show it is the namespace key (a Splice validator's `signing` key also \
                         includes namespace). Read the old node's UID (`<name>::<namespace>`) and \
                         pass --namespace-fingerprint <namespace>; it must equal this key's \
                         fingerprint"
                    )))
                }
                _ => {}
            }
        }
        CarriedFor::Protocol => {
            let Some(effective) = &effective else {
                return Err(refuse(
                    "plain PKCS#8 carries no Canton usage; a protocol key must come from the \
                     node's ExportKeyPair output (keys.secret.download), which records it"
                        .into(),
                ));
            };
            if !has(SigningKeyUsage::Protocol) && !has(SigningKeyUsage::SequencerAuthentication) {
                return Err(refuse(format!(
                    "the key's usage is {shown}, which includes neither signing (protocol) nor \
                     sequencer-auth — not a protocol key"
                )));
            }
            match ns {
                Some(ns) if ns == key_fingerprint => {
                    return Err(refuse(format!(
                        "this key IS the namespace {ns} — the namespace key is carried with \
                         --expect-usage namespace under a namespace id, never as a protocol key"
                    )))
                }
                None => {
                    let why = if effective.contains(&SigningKeyUsage::Namespace) {
                        "includes namespace"
                    } else {
                        "is unsigned metadata in the key file"
                    };
                    return Err(refuse(format!(
                        "protocol mode needs --namespace-fingerprint: the key's recorded usage \
                         ({shown}) {why}, so it cannot rule out that this is the namespace key. \
                         Read the old node's UID (`<name>::<namespace>`) and pass \
                         --namespace-fingerprint <namespace>; it must differ from this key's \
                         fingerprint"
                    )))
                }
                _ => {}
            }
        }
    }
    match check_id_class(key_id, expect)? {
        ImportIdClass::ProtocolSigning if !has(SigningKeyUsage::Protocol) => Err(refuse(format!(
            "{key_id} names a protocol signing key, but the key's usage does not include signing — \
             use <prefix>{IMPORT_MARKER}{SEQAUTH_LABEL}<name>"
        ))),
        ImportIdClass::SequencerAuth
            if has(SigningKeyUsage::Protocol) || !has(SigningKeyUsage::SequencerAuthentication) =>
        {
            Err(refuse(format!(
                "{key_id} names a sequencer-authentication key, but the key's usage is not \
                 sequencer-auth without signing — a key that signs protocol messages uses \
                 <prefix>{IMPORT_MARKER}{PROTOCOL_LABEL}<name>"
            )))
        }
        _ => Ok(()),
    }
}

fn refuse(msg: String) -> DaemonError {
    DaemonError::Ceremony(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SigningKeyUsage::*;

    const FP: &str = "1220f2bd11097f78ff4eb2354a43a62fd5b90271889914dece696d356f24beb3c9b4";
    const NS: &str = "1220cb0e86a9696add3a5e1daca40daee41bcd709d325c77cda974a63bccc6a0d6a5";

    fn check(expect: CarriedFor, id: &str, usage: Option<&[SigningKeyUsage]>, ns: Option<&str>) -> Result<CarriedUsage> {
        check_dealer_usage(expect, id, FP, usage, ns)
    }

    #[test]
    fn import_ids_are_classified_by_their_label() {
        assert_eq!(import_id_class("frost-import-1220cb0e"), Some(ImportIdClass::Namespace));
        assert_eq!(import_id_class("p1-frost-import-sig-1220f2bd"), Some(ImportIdClass::ProtocolSigning));
        assert_eq!(import_id_class("p1-frost-import-seqauth-1220e158"), Some(ImportIdClass::SequencerAuth));
        // A name merely starting with the letters is a namespace id; the labels need their dash.
        assert_eq!(import_id_class("frost-import-sigma"), Some(ImportIdClass::Namespace));
        for bad in [
            "frost-import-sig-",
            "frost-import-seqauth-",
            "frost-import-frost-import-sig-x",
            "frost-namespace",
            "frost-import-",
        ] {
            assert_eq!(import_id_class(bad), None, "{bad}");
        }
    }

    #[test]
    fn namespace_mode_takes_a_namespace_only_key_and_needs_the_namespace_for_anything_else() {
        let ns_id = "frost-import-1220f2bd";
        let carried = check(CarriedFor::Namespace, ns_id, Some(&[Namespace]), None).unwrap();
        assert_eq!(carried.expected, "namespace");
        assert_eq!(carried.recorded, Some(vec!["namespace".to_string()]));
        // The retired identity-delegation is ignored, as Canton does.
        check(CarriedFor::Namespace, ns_id, Some(&[Namespace, IdentityDelegation]), None).unwrap();

        // A protocol key is not a namespace key.
        let e = check(CarriedFor::Namespace, ns_id, Some(&[Protocol, ProofOfOwnership]), None).unwrap_err();
        assert!(e.to_string().contains("does not include namespace"), "{e}");

        // All usage (Splice's `signing` key), a legacy empty list, plain PKCS#8: ambiguous.
        let all = [Namespace, SequencerAuthentication, Protocol, ProofOfOwnership];
        for usage in [Some(&all[..]), Some(&[][..]), None] {
            let e = check(CarriedFor::Namespace, ns_id, usage, None).unwrap_err();
            assert!(e.to_string().contains("--namespace-fingerprint"), "{usage:?}: {e}");
            // The operator read the UID: this key is not its namespace (the Splice mistake).
            let e = check(CarriedFor::Namespace, ns_id, usage, Some(NS)).unwrap_err();
            assert!(e.to_string().contains("is not the namespace"), "{usage:?}: {e}");
            // ... or it is (a hand-initialised node whose root signs everything).
            check(CarriedFor::Namespace, ns_id, usage, Some(FP)).unwrap();
        }
        // A given --namespace-fingerprint is checked even where it is not needed.
        assert!(check(CarriedFor::Namespace, ns_id, Some(&[Namespace]), Some(NS)).is_err());
        assert!(check(CarriedFor::Namespace, ns_id, Some(&[Namespace]), Some("1220ab")).is_err());
        // Never under a protocol id.
        for id in ["frost-import-sig-1220f2bd", "frost-import-seqauth-1220f2bd"] {
            let e = check(CarriedFor::Namespace, id, Some(&[Namespace]), None).unwrap_err();
            assert!(e.to_string().contains("protocol key id"), "{e}");
        }
    }

    #[test]
    fn protocol_mode_needs_a_protocol_usage_the_right_label_and_never_takes_the_namespace() {
        let sig = "frost-import-sig-1220f2bd";
        let seq = "frost-import-seqauth-1220e158";
        // Canton auto-init's two keys.
        check(CarriedFor::Protocol, sig, Some(&[Protocol, ProofOfOwnership]), Some(NS)).unwrap();
        let c = check(CarriedFor::Protocol, seq, Some(&[SequencerAuthentication, ProofOfOwnership]), Some(NS)).unwrap();
        // The recorded usage is unsigned metadata: protocol mode always needs the namespace, even
        // for a key whose usage says nothing about namespace (it could be a relabelled root).
        let e = check(CarriedFor::Protocol, sig, Some(&[Protocol, ProofOfOwnership]), None).unwrap_err();
        assert!(e.to_string().contains("unsigned metadata"), "{e}");
        for own in [FP.to_string(), FP.to_uppercase()] {
            let e = check(CarriedFor::Protocol, sig, Some(&[Protocol]), Some(&own)).unwrap_err();
            assert!(e.to_string().contains("IS the namespace"), "{e}");
        }
        assert_eq!(c.recorded, Some(vec!["proof-of-ownership".into(), "sequencer-auth".into()]));
        // Swapped labels.
        assert!(check(CarriedFor::Protocol, seq, Some(&[Protocol, ProofOfOwnership]), Some(NS)).is_err());
        assert!(check(CarriedFor::Protocol, sig, Some(&[SequencerAuthentication, ProofOfOwnership]), Some(NS)).is_err());
        // Never under a namespace-style id.
        let e = check(CarriedFor::Protocol, "frost-import-1220f2bd", Some(&[Protocol]), Some(NS)).unwrap_err();
        assert!(e.to_string().contains("namespace-style id"), "{e}");
        // Not a protocol key, or usage unknown.
        assert!(check(CarriedFor::Protocol, sig, Some(&[Namespace]), None).is_err());
        assert!(check(CarriedFor::Protocol, sig, Some(&[ProofOfOwnership]), None).is_err());
        assert!(check(CarriedFor::Protocol, sig, None, Some(NS)).is_err());

        // Splice's All key (and a legacy empty list): needs the namespace, which must differ.
        let all = [Namespace, SequencerAuthentication, Protocol, ProofOfOwnership];
        for usage in [&all[..], &[][..]] {
            let e = check(CarriedFor::Protocol, sig, Some(usage), None).unwrap_err();
            assert!(e.to_string().contains("includes namespace"), "{e}");
            for own in [FP.to_string(), FP.to_uppercase()] {
                let e = check(CarriedFor::Protocol, sig, Some(usage), Some(&own)).unwrap_err();
                assert!(e.to_string().contains("IS the namespace"), "{e}");
            }
            check(CarriedFor::Protocol, sig, Some(usage), Some(NS)).unwrap();
            // It signs protocol messages: never a seqauth id.
            assert!(check(CarriedFor::Protocol, seq, Some(usage), Some(NS)).is_err());
        }
    }

    #[test]
    fn the_cosigner_side_check_is_the_dealers_and_aad_fields_differ() {
        let c = |expected: &str, recorded: Option<&[&str]>, ns: Option<&str>| CarriedUsage {
            expected: expected.into(),
            recorded: recorded.map(|r| r.iter().map(|s| s.to_string()).collect()),
            namespace_fingerprint: ns.map(String::from),
        };
        let all: &[&str] = &["namespace", "proof-of-ownership", "sequencer-auth", "signing"];
        check_carried_id("frost-import-x", FP, &c("namespace", Some(&["namespace"]), None)).unwrap();
        check_carried_id("frost-import-sig-x", FP, &c("protocol", Some(&["proof-of-ownership", "signing"]), Some(NS))).unwrap();
        check_carried_id("frost-import-sig-x", FP, &c("protocol", Some(all), Some(NS))).unwrap();
        check_carried_id("frost-import-x", FP, &c("namespace", Some(all), Some(FP))).unwrap();
        check_carried_id("frost-import-x", FP, &c("namespace", None, Some(FP))).unwrap();

        // What a modified dealer could write, and the real one would refuse: refused here too.
        for (id, carried, needle) in [
            ("frost-import-seqauth-x", c("protocol", None, Some(NS)), "PKCS#8"),
            ("frost-import-x", c("namespace", Some(all), None), "--namespace-fingerprint"),
            ("frost-import-x", c("namespace", Some(&[]), None), "--namespace-fingerprint"),
            ("frost-import-x", c("namespace", None, None), "--namespace-fingerprint"),
            ("frost-import-x", c("namespace", Some(all), Some(NS)), "is not the namespace"),
            ("frost-import-x", c("namespace", Some(&["signing"]), Some(FP)), "does not include namespace"),
            ("frost-import-sig-x", c("protocol", Some(all), None), "includes namespace"),
            ("frost-import-sig-x", c("protocol", Some(&["signing"]), None), "unsigned metadata"),
            ("frost-import-sig-x", c("protocol", Some(all), Some(FP)), "IS the namespace"),
            ("frost-import-sig-x", c("protocol", Some(&["proof-of-ownership"]), Some(NS)), "neither signing"),
            ("frost-import-x", c("protocol", Some(&["signing"]), Some(NS)), "namespace-style id"),
            ("frost-import-sig-x", c("namespace", Some(&["namespace"]), None), "protocol key id"),
            ("frost-import-x", c("namespace", Some(&["namespace"]), Some("1220AB")), "not a 1220"),
            ("frost-import-x", c("namespace", Some(&["namespace"]), Some(&FP.to_uppercase())), "lower case"),
            ("frost-import-x", c("root", None, None), "neither namespace nor protocol"),
            ("frost-import-sig-x", c("protocol", Some(&["bogus"]), Some(NS)), "unknown Canton key usage"),
        ] {
            let e = check_carried_id(id, FP, &carried).unwrap_err().to_string();
            assert!(e.contains(needle), "{id} {carried:?}: expected {needle:?} in {e}");
        }
        // The key's fingerprint is compared case-insensitively.
        check_carried_id("frost-import-x", &FP.to_uppercase(), &c("namespace", Some(all), Some(FP))).unwrap();

        let fields = |u: &CarriedUsage| u.aad_fields();
        let known_empty = c("namespace", Some(&[]), None);
        let unknown = c("namespace", None, None);
        assert_ne!(fields(&known_empty), fields(&unknown), "empty (= all) and unknown must not collide");
        let ns_only = c("namespace", Some(&["namespace"]), None);
        assert_ne!(fields(&ns_only), fields(&c("protocol", Some(&["namespace"]), None)));
        assert_ne!(fields(&ns_only), fields(&c("namespace", Some(&["namespace"]), Some(FP))), "the acknowledgement is bound");
        assert_ne!(fields(&c("namespace", None, Some(FP))), fields(&c("namespace", None, Some(NS))));
    }
}

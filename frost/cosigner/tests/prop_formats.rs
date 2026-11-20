// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Property tests for the on-disk and portable formats (issue #121): sealed key files (v1 and v2),
//! the v2 header's associated data, node seal bundles, the export-key envelope, and the canonical
//! form of a Canton fingerprint.

use proptest::prelude::*;
use zeroize::Zeroizing;

use rutli_cosigner::export;
use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::seal::{self, header_aad, KeyFileBinding, KeyFileHeader, NodeSealBundle, RecordKind, RecordMeta, Sealer};
use rutli_cosigner::share_delivery::{canonical_fingerprint, ed25519_fingerprint};

/// `cases` per test, unless `PROPTEST_CASES` is set (a longer local run).
fn config(cases: u32) -> ProptestConfig {
    let mut c = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        c.cases = cases;
    }
    c.failure_persistence = None;
    c
}

const KINDS: [RecordKind; 4] = [RecordKind::FrostShare, RecordKind::HostedKey, RecordKind::Tombstone, RecordKind::Recipient];

fn kind() -> impl Strategy<Value = RecordKind> {
    prop::sample::select(KINDS.to_vec())
}

fn key_id() -> impl Strategy<Value = String> {
    "[a-z0-9][a-z0-9_-]{0,30}"
}

const CLUSTER: &str = "0f6c3c2e-4a8b-4d5e-9f10-111213141516";

fn sealer(dek: [u8; 32], node: u16, write_version: u8) -> Sealer {
    Sealer::from_dek(Zeroizing::new(dek), node).with_binding(KeyFileBinding {
        node,
        cluster_uuid: Some(CLUSTER.into()),
        write_version,
        accept_v1: true,
    })
}

fn header() -> impl Strategy<Value = KeyFileHeader> {
    (".{0,12}", ".{0,12}", any::<u16>(), ".{0,12}", ".{0,12}", any::<u64>(), "[0-9a-f]{0,16}", "[0-9a-f]{0,8}").prop_map(
        |(fmt, cluster, node, key_id, kind, epoch, digest, dek_id)| KeyFileHeader {
            fmt,
            cluster,
            node,
            key_id,
            kind,
            epoch,
            digest,
            dek_id,
        },
    )
}

proptest! {
    #![proptest_config(config(64))]

    /// v1 seal/unseal round-trips any plaintext, and `file_version` recognises the result.
    #[test]
    fn v1_seal_round_trips(dek in any::<[u8; 32]>(), node in any::<u16>(), plain in prop::collection::vec(any::<u8>(), 0..512)) {
        let s = sealer(dek, node, 1);
        let file = s.seal(&plain).unwrap();
        prop_assert_eq!(seal::file_version(&file), Some(1));
        prop_assert_eq!(s.unseal(&file).unwrap(), plain.clone());
        let meta = RecordMeta { kind: RecordKind::FrostShare, key_id: "k", epoch: 0, digest: &[] };
        let (opened, hdr) = s.unseal_record(&s.seal_record(&meta, &plain).unwrap(), "k", &KINDS).unwrap();
        prop_assert_eq!(opened, plain);
        prop_assert!(hdr.is_none());
    }

    /// v2 seal/unseal round-trips any record, and the header it returns is exactly what was
    /// sealed (`header_of` reads the same header without the key).
    #[test]
    fn v2_seal_round_trips_with_its_header(
        dek in any::<[u8; 32]>(),
        node in any::<u16>(),
        kind in kind(),
        key_id in key_id(),
        epoch in any::<u64>(),
        digest in prop::collection::vec(any::<u8>(), 0..40),
        plain in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let s = sealer(dek, node, 2);
        let meta = RecordMeta { kind, key_id: &key_id, epoch, digest: &digest };
        let file = s.seal_record(&meta, &plain).unwrap();
        prop_assert_eq!(seal::file_version(&file), Some(2));
        let (opened, hdr) = s.unseal_record(&file, &key_id, &[kind]).unwrap();
        prop_assert_eq!(opened, plain);
        let hdr = hdr.unwrap();
        prop_assert_eq!(seal::header_of(&file), Some(hdr.clone()));
        prop_assert_eq!(hdr.cluster, CLUSTER);
        prop_assert_eq!(hdr.node, node);
        prop_assert_eq!(&hdr.key_id, &key_id);
        prop_assert_eq!(hdr.kind, kind.as_str());
        prop_assert_eq!(hdr.epoch, epoch);
        prop_assert_eq!(hdr.digest, hex::encode(&digest));
        prop_assert_eq!(hdr.dek_id, s.current_dek_id());
    }

    /// A v2 file opens only for the key id, kind, node and cluster in its header, and only under
    /// the DEK that sealed it.
    #[test]
    fn v2_files_open_only_where_they_belong(
        dek in any::<[u8; 32]>(),
        other_dek in any::<[u8; 32]>(),
        node in 1u16..100,
        kind in kind(),
        other_kind in kind(),
        key_id in key_id(),
        other_key in key_id(),
    ) {
        let s = sealer(dek, node, 2);
        let meta = RecordMeta { kind, key_id: &key_id, epoch: 1, digest: b"d" };
        let file = s.seal_record(&meta, b"secret").unwrap();
        if other_key != key_id {
            prop_assert!(s.unseal_record(&file, &other_key, &KINDS).is_err());
        }
        if other_kind != kind {
            prop_assert!(s.unseal_record(&file, &key_id, &[other_kind]).is_err());
        }
        prop_assert!(sealer(dek, node + 1, 2).unseal_record(&file, &key_id, &KINDS).is_err());
        let foreign_cluster = Sealer::from_dek(Zeroizing::new(dek), node).with_binding(KeyFileBinding {
            node,
            cluster_uuid: Some("another-cluster".into()),
            write_version: 2,
            accept_v1: true,
        });
        prop_assert!(foreign_cluster.unseal_record(&file, &key_id, &KINDS).is_err());
        if other_dek != dek {
            prop_assert!(sealer(other_dek, node, 2).unseal_record(&file, &key_id, &KINDS).is_err());
        }
    }

    /// Changing any single byte of a sealed file (v1 or v2) never yields a different plaintext:
    /// it either fails to open or — when the byte is JSON whitespace or a hex digit's case — opens
    /// to the original.
    #[test]
    fn a_tampered_key_file_never_opens_to_something_else(
        dek in any::<[u8; 32]>(),
        v2 in any::<bool>(),
        plain in prop::collection::vec(any::<u8>(), 1..64),
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let s = sealer(dek, 7, if v2 { 2 } else { 1 });
        let meta = RecordMeta { kind: RecordKind::HostedKey, key_id: "k", epoch: 3, digest: b"dd" };
        let mut file = s.seal_record(&meta, &plain).unwrap();
        let i = at.index(file.len());
        file[i] ^= xor;
        if let Ok((opened, _)) = s.unseal_record(&file, "k", &KINDS) {
            prop_assert_eq!(opened, plain);
        }
    }

    /// The associated data of a v2 header is injective: two different headers never share it, so
    /// no header field can be moved into another without breaking the seal.
    #[test]
    fn header_aad_is_injective(a in header(), b in header()) {
        prop_assert_eq!(a == b, header_aad(&a) == header_aad(&b));
    }

    /// Every header field is bound: changing any one of them changes the associated data.
    #[test]
    fn every_header_field_is_in_the_aad(h in header(), field in 0usize..8, bump in 1u16..) {
        let mut m = h.clone();
        match field {
            0 => m.fmt.push('x'),
            1 => m.cluster.push('x'),
            2 => m.node = h.node.wrapping_add(bump),
            3 => m.key_id.push('x'),
            4 => m.kind.push('x'),
            5 => m.epoch = h.epoch.wrapping_add(u64::from(bump)),
            6 => m.digest.push('0'),
            _ => m.dek_id.push('0'),
        }
        prop_assert_ne!(header_aad(&h), header_aad(&m));
    }

    /// A node seal bundle survives `to_json` → `parse` unchanged (byte-identical re-serialization),
    /// and a rotation keeps every file sealed under the old DEK openable.
    #[test]
    fn seal_bundles_round_trip_and_rotation_keeps_old_files(
        node in any::<u16>(),
        share_dek in any::<[u8; 32]>(),
        dist_seed in any::<[u8; 32]>(),
        previous in prop::collection::vec(any::<[u8; 32]>(), 0..3),
        plain in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let json = serde_json::json!({
            "v": 1,
            "kind": seal::BUNDLE_KIND,
            "node": node,
            "share_dek": hex::encode(share_dek),
            "dist_seed": hex::encode(dist_seed),
            "previous_share_deks": previous.iter().map(hex::encode).collect::<Vec<_>>(),
        });
        let bundle = NodeSealBundle::parse(json.to_string().as_bytes()).unwrap();
        let bytes = bundle.to_json().unwrap();
        let again = NodeSealBundle::parse(&bytes).unwrap();
        prop_assert_eq!(&*again.to_json().unwrap(), &*bytes);
        prop_assert_eq!(again.node, node);
        prop_assert_eq!(again.previous_count(), previous.len());
        prop_assert_eq!(again.dist_public_key(), bundle.dist_public_key());

        let old_file = bundle.sealer().seal(&plain).unwrap();
        let rotated = bundle.rotated();
        prop_assert_eq!(rotated.previous_count(), previous.len() + 1);
        prop_assert_eq!(rotated.dist_public_key(), bundle.dist_public_key());
        prop_assert_eq!(rotated.sealer().unseal(&old_file).unwrap(), plain.clone());
        prop_assert!(rotated.without_previous().sealer().unseal(&old_file).is_err());
    }

    /// A Canton fingerprint has one canonical spelling: whitespace around it and the case of its
    /// hex digits do not matter, the canonical form is a fixed point, and anything that is not 68
    /// hex digits starting `1220` is refused.
    #[test]
    fn fingerprints_canonicalise(
        digest in any::<[u8; 32]>(),
        upper in prop::collection::vec(any::<bool>(), 68),
        pad_left in "[ \t\n]{0,3}",
        pad_right in "[ \t\n]{0,3}",
    ) {
        let canonical = format!("1220{}", hex::encode(digest));
        let mixed: String = canonical
            .chars()
            .zip(&upper)
            .map(|(c, &u)| if u { c.to_ascii_uppercase() } else { c })
            .collect();
        let spelled = format!("{pad_left}{mixed}{pad_right}");
        prop_assert_eq!(canonical_fingerprint(&spelled).unwrap(), canonical.clone());
        prop_assert_eq!(canonical_fingerprint(&canonical).unwrap(), canonical.clone());
        // One digit too few or too many, or another multihash prefix.
        let too_long = format!("{canonical}0");
        let other_prefix = format!("1221{}", &canonical[4..]);
        prop_assert!(canonical_fingerprint(&canonical[..67]).is_err());
        prop_assert!(canonical_fingerprint(&too_long).is_err());
        prop_assert!(canonical_fingerprint(&other_prefix).is_err());
    }

    /// Whatever string comes in, an accepted fingerprint is canonical: lower-case, 68 hex digits,
    /// prefix `1220`.
    #[test]
    fn an_accepted_fingerprint_is_always_canonical(input in prop_oneof![".{0,80}", "[ ]?1220[0-9a-fA-FgG]{60,68}[ ]?"]) {
        if let Ok(fp) = canonical_fingerprint(&input) {
            prop_assert_eq!(fp.len(), 68);
            prop_assert!(fp.starts_with("1220"));
            prop_assert!(fp.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
            prop_assert_eq!(canonical_fingerprint(&fp).unwrap(), fp.clone());
        }
    }

    /// The fingerprint of a group key is already canonical.
    #[test]
    fn group_key_fingerprints_are_canonical(seed in any::<[u8; 32]>()) {
        let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let fp = ed25519_fingerprint(&vk);
        prop_assert_eq!(canonical_fingerprint(&fp).unwrap(), fp);
    }
}

fn hosted_spec() -> impl Strategy<Value = HostedSpec> {
    // RSA keys take long to generate; the envelope does not depend on the spec beyond its name.
    prop_oneof![Just(HostedSpec::Aes256Gcm), Just(HostedSpec::EcP256)]
}

proptest! {
    #![proptest_config(config(32))]

    /// A plaintext export imports back to the same key, and its JSON survives a re-parse.
    #[test]
    fn plaintext_exports_round_trip(spec in hosted_spec(), created in 0u64..4_000_000_000, key_id in key_id()) {
        let key = HostedKey::generate(spec, created).unwrap();
        let envelope = export::export_plaintext(&key_id, &key).unwrap();
        let json = serde_json::to_vec(&envelope).unwrap();
        let parsed: export::ExportEnvelope = serde_json::from_slice(&json).unwrap();
        prop_assert_eq!(&parsed.key_id, &key_id);
        prop_assert_eq!(parsed.created_at, created);
        let back = export::import(&parsed, None).unwrap();
        prop_assert_eq!(serde_json::to_value(&back).unwrap(), serde_json::to_value(&key).unwrap());
    }

    /// An export whose header names another spec than its material is refused.
    #[test]
    fn an_export_header_must_match_its_material(spec in hosted_spec()) {
        let key = HostedKey::generate(spec, 1).unwrap();
        let mut envelope = export::export_plaintext("k", &key).unwrap();
        envelope.spec = match spec {
            HostedSpec::Aes256Gcm => HostedSpec::EcP256.as_str().into(),
            _ => HostedSpec::Aes256Gcm.as_str().into(),
        };
        prop_assert!(export::import(&envelope, None).is_err());
    }
}

proptest! {
    // Each case runs Argon2id (64 MiB) a few times: two cases, whatever PROPTEST_CASES says.
    #![proptest_config(ProptestConfig { cases: 2, failure_persistence: None, ..ProptestConfig::default() })]

    /// An encrypted export opens with its passphrase and nothing else, and relabelling it (key id,
    /// spec) or flipping a byte of its ciphertext makes it unopenable.
    #[test]
    fn encrypted_exports_open_only_unaltered_with_their_passphrase(
        pass in "[ -~]{12,24}",
        wrong in "[ -~]{12,24}",
        at in any::<prop::sample::Index>(),
    ) {
        let key = HostedKey::generate(HostedSpec::Aes256Gcm, 1).unwrap();
        let envelope = export::export_encrypted("rutli-k", &key, &pass).unwrap();
        let back = export::import(&envelope, Some(&pass)).unwrap();
        prop_assert_eq!(serde_json::to_value(&back).unwrap(), serde_json::to_value(&key).unwrap());
        prop_assert!(export::import(&envelope, None).is_err());
        if wrong != pass {
            prop_assert!(export::import(&envelope, Some(&wrong)).is_err());
        }
        let reparse = |e: &export::ExportEnvelope| -> export::ExportEnvelope {
            serde_json::from_slice(&serde_json::to_vec(e).unwrap()).unwrap()
        };
        let mut relabelled = reparse(&envelope);
        relabelled.key_id = "rutli-other".into();
        prop_assert!(export::import(&relabelled, Some(&pass)).is_err());
        let mut respecced = reparse(&envelope);
        respecced.spec = HostedSpec::EcP256.as_str().into();
        prop_assert!(export::import(&respecced, Some(&pass)).is_err());
        let mut flipped = reparse(&envelope);
        let mut ct = hex::decode(&flipped.payload).unwrap();
        let i = at.index(ct.len());
        ct[i] ^= 0x01;
        flipped.payload = hex::encode(ct);
        prop_assert!(export::import(&flipped, Some(&pass)).is_err());
    }
}

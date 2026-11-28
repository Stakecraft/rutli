// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Fuzz harness bodies, one public function per target in `fuzz_targets/`.
//!
//! Each function takes the raw fuzzer input, feeds it to the cosigner's parsers and checks, and
//! returns whether the input was accepted. Rejection is the normal outcome; a panic, an abort or a
//! broken invariant (an `assert!` here) is a finding.
//!
//! Seed inputs are generated at run time ([`generated_seeds`]) rather than committed: most of them
//! hold key material (key files, seal bundles, exports), and the repository carries none, not even
//! test keys. The fuzz targets write them into the corpus directory at start-up when
//! `RUTLI_FUZZ_SEED_DIR` is set ([`init`]).
//!
//! The same file is compiled into the normal test suite (`frost/cosigner/tests/fuzz_regressions.rs`,
//! by `#[path]`), which runs the generated seeds and every file under
//! `frost/fuzz/regressions/<target>/` through these functions on stable Rust. So it uses only
//! crates the cosigner's tests already have, and no libFuzzer API.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prost::Message;
use rutli_cosigner::pb;
use zeroize::Zeroizing;

/// The key id every target uses for "this node's key".
pub const KEY_ID: &str = "frost-fuzz";
/// Hosted keys the `grpc` mesh holds.
pub const HOSTED_AES: &str = "rutli-fuzz-aes";
pub const HOSTED_EC: &str = "rutli-fuzz-ec";
/// The cluster id of the test verifier, key files and mesh.
pub const CLUSTER: &str = "fuzzcluster00000";
/// A fixed clock for intent checks (2027-01-15), so a replayed input gets the same verdict.
pub const NOW_MS: u64 = 1_800_000_000_000;
/// The longest input any target looks at. Every format here is a few KiB at most; without a cap a
/// mutated multi-MB input only measures AES and the file system.
pub const MAX_INPUT: usize = 64 * 1024;
/// This node's identifier.
const NODE: u16 = 1;
const DEK: [u8; 32] = [7u8; 32];
const MASTER: &[u8] = b"rutli fuzz harness hosted-key master secret";

/// A harness body: the input in, whether it was accepted out.
pub type Target = fn(&[u8]) -> bool;

/// The targets, by name: what the regression test and the corpus layout use.
pub const TARGETS: &[(&str, Target)] = &[
    ("key_file", key_file),
    ("seal_bundle", seal_bundle),
    ("share_bundle", share_bundle),
    ("canton_key", canton_key),
    ("export_file", export_file),
    ("intent", intent),
    ("grpc", grpc),
];

/// The entry point of every fuzz target: on the first input, with `RUTLI_FUZZ_SEED_DIR` set, write
/// `target`'s generated seeds there ([`init`]); then run the target. libFuzzer always runs the empty
/// input first, so `cargo fuzz run <target> <empty dir> -- -runs=0` only writes the seeds.
pub fn fuzz(target: &str, data: &[u8]) {
    static SEEDED: std::sync::Once = std::sync::Once::new();
    SEEDED.call_once(|| init(target));
    let (_, body) = TARGETS
        .iter()
        .find(|(n, _)| *n == target)
        .expect("known target");
    let _ = body(data);
}

/// With `RUTLI_FUZZ_SEED_DIR` set, write `target`'s generated seeds there.
pub fn init(target: &str) {
    let Some(dir) = std::env::var_os("RUTLI_FUZZ_SEED_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("seed dir");
    for (name, bytes) in generated_seeds(target) {
        std::fs::write(dir.join(format!("seed-{name}")), bytes).expect("write seed");
    }
}

/// A scratch directory for the whole process, and unique file names in it (the regression test
/// may run targets on several threads).
fn scratch() -> &'static Path {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().expect("scratch dir"))
        .path()
}

fn scratch_path(stem: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    scratch().join(format!("{stem}-{}", N.fetch_add(1, Ordering::Relaxed)))
}

/// `std::fs::copy`, started again when a signal interrupts it. libFuzzer runs a timer in the
/// process (`-timeout`), and `std::fs::copy` hands an interrupted system call back as an error:
/// a nightly run ended on `Interrupted system call` here, with an input that never reached a
/// handler (#360). A copy that starts again truncates what the interrupted one wrote.
fn copy_file(from: &Path, to: &Path) -> std::io::Result<u64> {
    loop {
        match std::fs::copy(from, to) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            done => return done,
        }
    }
}

fn binding_v2() -> rutli_cosigner::seal::KeyFileBinding {
    rutli_cosigner::seal::KeyFileBinding {
        node: NODE,
        cluster_uuid: Some(CLUSTER.to_string()),
        write_version: 2,
        accept_v1: true,
    }
}

fn sealer() -> rutli_cosigner::seal::Sealer {
    rutli_cosigner::seal::Sealer::from_dek(Zeroizing::new(DEK), NODE).with_binding(binding_v2())
}

const ALL_KINDS: &[rutli_cosigner::seal::RecordKind] = &[
    rutli_cosigner::seal::RecordKind::FrostShare,
    rutli_cosigner::seal::RecordKind::HostedKey,
    rutli_cosigner::seal::RecordKind::Tombstone,
    rutli_cosigner::seal::RecordKind::Recipient,
];

// ---------------------------------------------------------------------------------------------
// key_file: key-file envelopes (v1, v2), their headers, and the record inside.

/// The key-file readers: format probe, clear header, unseal with this node's binding, and the
/// key store's record parser behind both a sealed and a plaintext (dev) store. Then a round trip:
/// the input sealed as a record of each kind must unseal to itself.
pub fn key_file(data: &[u8]) -> bool {
    use rutli_cosigner::keystore::KeyStore;
    use rutli_cosigner::seal::{self, RecordMeta, Sealer};
    if data.len() > MAX_INPUT {
        return false;
    }

    let version = seal::file_version(data);
    let header = seal::header_of(data);
    if let Some(h) = &header {
        assert_eq!(version, Some(2), "a file with a v2 header probes as v2");
        let _ = seal::header_aad(h);
    }
    let sealer = sealer();
    let _ = sealer.dek_use(data);
    let _ = Sealer::is_sealed(data);
    let mut accepted = sealer.unseal_record(data, KEY_ID, ALL_KINDS).is_ok();

    // The record parser, as restore reads a backup file: sealed store and plaintext store.
    static SEALED: OnceLock<KeyStore> = OnceLock::new();
    static PLAIN: OnceLock<KeyStore> = OnceLock::new();
    let sealed_store = SEALED.get_or_init(|| {
        KeyStore::open_with_sealer(
            scratch().join("sealed-store"),
            Some(Arc::new(self::sealer())),
        )
        .expect("sealed store")
    });
    let plain_store =
        PLAIN.get_or_init(|| KeyStore::open(scratch().join("plain-store")).expect("plain store"));
    let path = scratch_path("keyfile");
    std::fs::write(&path, data).expect("write scratch file");
    accepted |= sealed_store.load_foreign(&path, KEY_ID).is_ok();
    accepted |= plain_store.load_foreign(&path, KEY_ID).is_ok();

    // The record parser behind a valid v2 envelope: the input is the sealed plaintext.
    for kind in ALL_KINDS {
        let meta = RecordMeta {
            kind: *kind,
            key_id: KEY_ID,
            epoch: 0,
            digest: &[],
        };
        let sealed = sealer.seal_record(&meta, data).expect("seal");
        let (plain, hdr) = sealer
            .unseal_record(&sealed, KEY_ID, &[*kind])
            .expect("own seal must open");
        assert_eq!(plain, data, "seal/unseal round trip");
        assert_eq!(hdr.map(|h| h.kind), Some(kind.as_str().to_string()));
        if *kind != rutli_cosigner::seal::RecordKind::Recipient {
            std::fs::write(&path, &sealed).expect("write scratch file");
            accepted |= sealed_store.load_foreign(&path, KEY_ID).is_ok();
        }
    }
    let _ = std::fs::remove_file(&path);
    accepted
}

// ---------------------------------------------------------------------------------------------
// seal_bundle: the per-node seal bundle (`share_seal.secret_file`).

pub fn seal_bundle(data: &[u8]) -> bool {
    use rutli_cosigner::seal::NodeSealBundle;
    if data.len() > MAX_INPUT {
        return false;
    }
    let Ok(bundle) = NodeSealBundle::parse(data) else {
        return false;
    };
    // Round trip: what it writes, it reads back as the same keys.
    let json = bundle.to_json().expect("to_json");
    let again = NodeSealBundle::parse(&json).expect("a bundle's own JSON parses");
    assert_eq!(again.node, bundle.node);
    assert_eq!(again.dek_id(), bundle.dek_id());
    assert_eq!(again.dist_public_key(), bundle.dist_public_key());
    assert_eq!(again.previous_count(), bundle.previous_count());
    let _ = bundle.sealer();
    true
}

// ---------------------------------------------------------------------------------------------
// share_bundle: the split ceremony's share bundle and recipient request.

/// A node waiting for its share: node 1 of a 2-of-3 cluster with a pending recipient for an import
/// key, made with this process's test PKI. Its recipient secret is random, so the bundle a seed
/// seals to it opens only in the process that generated it.
struct ShareNode {
    ctx: rutli_cosigner::share_import::NodeContext,
    keystore: rutli_cosigner::keystore::KeyStore,
    request: rutli_cosigner::share_delivery::RecipientRequest,
}

fn share_node() -> &'static ShareNode {
    static NODE_: OnceLock<ShareNode> = OnceLock::new();
    NODE_.get_or_init(|| {
        let ctx = rutli_cosigner::share_import::NodeContext {
            data_dir: scratch().join("share-node"),
            identifier: NODE,
            threshold: 2,
            max_signers: 3,
            roster: vec![1, 2, 3],
            cluster_id: rutli_cosigner::wrap::cluster_id_from_ca(pki().ca_pem.as_bytes()),
        };
        let keystore = rutli_cosigner::keystore::KeyStore::open_with_sealer(
            ctx.keys_dir(),
            Some(Arc::new(sealer())),
        )
        .expect("share node key store");
        let request = rutli_cosigner::share_import::share_recipient(
            &ctx,
            &keystore,
            &sealer(),
            &pki().cosigner1,
            &dealt_key().key_id,
            "fuzz-ceremony",
            false,
        )
        .expect("recipient");
        ShareNode {
            ctx,
            keystore,
            request,
        }
    })
}

/// The dealer's split of a fixed test seed for the share node's cluster.
struct Dealt {
    shares: Vec<frost_ed25519::keys::SecretShare>,
    pkp: frost_ed25519::keys::PublicKeyPackage,
    fingerprint: String,
    key_id: String,
}

fn dealt_key() -> &'static Dealt {
    static DEALT: OnceLock<Dealt> = OnceLock::new();
    DEALT.get_or_init(|| {
        let (shares, pkp) =
            rutli_frost_core::dealer::split_ed25519_seed(&[9u8; 32], &[1, 2, 3], 2).expect("split");
        let group = rutli_frost_core::dkg::group_verifying_key_bytes(&pkp).expect("group key");
        let fingerprint = rutli_cosigner::share_delivery::ed25519_fingerprint(&group);
        let key_id = format!("frost-import-{}", &fingerprint[..8]);
        Dealt {
            shares,
            pkp,
            fingerprint,
            key_id,
        }
    })
}

pub fn share_bundle(data: &[u8]) -> bool {
    use rutli_cosigner::share_delivery::{self, RecipientRequest, ShareBundle};
    if data.len() > MAX_INPUT {
        return false;
    }
    let mut accepted = false;

    if let Ok(request) = serde_json::from_slice::<RecipientRequest>(data) {
        let _ = request.public_key();
        let _ = rutli_cosigner::request_auth::canonical_bytes(&request);
        if request.validate().is_ok() {
            accepted |=
                rutli_cosigner::request_auth::verify_request(&request, pki().ca_pem.as_bytes())
                    .is_ok();
        }
    }

    if let Ok(bundle) = serde_json::from_slice::<ShareBundle>(data) {
        let _ = bundle.group_key();
        let _ = share_delivery::canonical_fingerprint(&bundle.canton_fingerprint);
        if let Ok(usage) = bundle.carried_usage() {
            let _ = rutli_cosigner::carry::check_carried_id(
                &bundle.key_id,
                &bundle.canton_fingerprint,
                usage,
            );
        }
        // Against the request it claims to answer, so the package checks run whatever the ids.
        let claimed = RecipientRequest {
            v: share_delivery::RECIPIENT_VERSION,
            kind: share_delivery::RECIPIENT_KIND.into(),
            ceremony_id: bundle.ceremony_id.clone(),
            key_id: bundle.key_id.clone(),
            cluster_id: bundle.cluster_id.clone(),
            identifier: bundle.recipient,
            threshold: bundle.threshold,
            max_signers: bundle.max_signers,
            roster: (1..=bundle.max_signers.min(64)).collect(),
            recipient_pub: bundle.recipient_pub.clone(),
            signature_alg: String::new(),
            signer_chain: Vec::new(),
            signature: String::new(),
        };
        let _ = bundle.check_against(&claimed);
        // import-share as a dry run on the node waiting for it: every check, nothing written.
        let node = share_node();
        let _ = bundle.check_against(&node.request);
        let fp = bundle.canton_fingerprint.clone();
        accepted |= rutli_cosigner::share_import::import_share(
            &node.ctx,
            &node.keystore,
            &sealer(),
            &bundle,
            &fp,
            true,
        )
        .is_ok();
    }
    accepted
}

// ---------------------------------------------------------------------------------------------
// canton_key: every form a Canton private key reaches Rütli in (import-key, the split ceremony's
// dealer), and the hosted-key import on top. Seeds: frost/canton-key/testdata/vectors.

/// The fingerprint `import_canton` is told to expect: well formed, matching no key.
const EXPECT_FP: &str = "12200000000000000000000000000000000000000000000000000000000000000000";

pub fn canton_key(data: &[u8]) -> bool {
    use rutli_canton_key::{self as ck, KeyPurpose};
    if data.len() > MAX_INPUT {
        return false;
    }
    let mut accepted = false;
    // The public password of canton-key/testdata, so the password-protected vectors decrypt and the
    // fuzzer mutates what is behind the PBE layer too.
    for password in [None, Some(&b"rutli-test-vector-password"[..])] {
        if let Ok(k) = ck::parse(data, password) {
            accepted = true;
            // A Canton container's id is checked against the key it holds: never a mismatch.
            if let Some(id) = &k.canton_id {
                assert_eq!(
                    id,
                    &k.fingerprint(),
                    "parsed key's container id differs from its fingerprint"
                );
            }
            let _ = k.spec();
        }
        accepted |= ck::parse_export(data, password).is_ok();
        let _ = rutli_cosigner::export::import_canton(data, password, EXPECT_FP, 0);
    }
    for purpose in [
        None,
        Some(KeyPurpose::Signing),
        Some(KeyPurpose::Encryption),
    ] {
        accepted |= ck::parse_stored(data, purpose).is_ok();
    }
    accepted |= ck::parse_pkcs8(data).is_ok();
    if let Ok(public) = ck::parse_public_key(data) {
        accepted = true;
        // SPKI round trip.
        let der = public.public.spki_der();
        let again = ck::PublicKey::from_spki_der(&der).expect("own SPKI parses");
        assert_eq!(again.spki_der(), der, "SPKI round trip");
        assert_eq!(again.fingerprint(), public.fingerprint());
    }
    accepted |= ck::PublicKey::from_spki_der(data).is_ok();
    accepted
}

// ---------------------------------------------------------------------------------------------
// export_file: the `export-key` / `import-key` envelope.

/// Argon2 parameters this harness lets an encrypted envelope run with: the file chooses them, and
/// the shipped ones (64 MiB, 3 passes) would make every input take a second.
const MAX_FUZZ_M_COST: u32 = 64;
const MAX_FUZZ_T_COST: u32 = 2;

pub fn export_file(data: &[u8]) -> bool {
    use rutli_cosigner::export::{self, ExportEnvelope};
    if data.len() > MAX_INPUT {
        return false;
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = export::hosted_import_key_id(s.trim(), None);
    }
    let Ok(envelope) = serde_json::from_slice::<ExportEnvelope>(data) else {
        return false;
    };
    let _ = export::hosted_import_key_id(&envelope.key_id, None);
    let _ = export::hosted_import_key_id(&envelope.key_id, Some("tenant-"));
    let cheap_kdf = envelope.kdf.as_ref().is_some_and(|k| {
        k.m_cost <= MAX_FUZZ_M_COST && k.t_cost <= MAX_FUZZ_T_COST && k.p_cost <= 1
    });
    if cheap_kdf {
        let _ = export::import(&envelope, Some("fuzz passphrase 0"));
    }
    let Ok(key) = export::import(&envelope, None) else {
        return false;
    };
    // Accepted: the header agrees with the material, and a re-export reads back as the same key.
    assert_eq!(key.spec.as_str(), envelope.spec);
    let again = export::export_plaintext(&envelope.key_id, &key).expect("re-export");
    let back = export::import(&again, None).expect("own export imports");
    assert_eq!(
        serde_json::to_vec(&back).expect("serialize"),
        serde_json::to_vec(&key).expect("serialize"),
        "export/import round trip"
    );
    true
}

// ---------------------------------------------------------------------------------------------
// intent: signing, delete and ceremony intents.

/// The harness's cluster CA and the client identities it signs with.
pub struct Pki {
    pub ca_pem: String,
    pub driver: rutli_cosigner::request_auth::NodeSigner,
    pub refresher: rutli_cosigner::request_auth::NodeSigner,
    pub cosigner1: rutli_cosigner::request_auth::NodeSigner,
}

pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rutli-frost-cluster-ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).expect("CA");
        let leaf = |cn: &str| {
            let key =
                rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
            let mut p = rcgen::CertificateParams::new(vec!["rutli-cosigner".to_string()])
                .expect("leaf params");
            p.distinguished_name.push(rcgen::DnType::CommonName, cn);
            let cert = p.signed_by(&key, &ca, &ca_key).expect("leaf");
            rutli_cosigner::request_auth::NodeSigner::from_pem(
                cert.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
            )
            .expect("signer")
        };
        Pki {
            ca_pem: ca.pem(),
            driver: leaf("driver"),
            refresher: leaf("refresher"),
            cosigner1: leaf("cosigner1"),
        }
    })
}

fn verifier() -> &'static rutli_cosigner::intent::IntentVerifier {
    static V: OnceLock<rutli_cosigner::intent::IntentVerifier> = OnceLock::new();
    V.get_or_init(|| {
        let policy = rutli_cosigner::config::SigningPolicyConfig {
            // A gated prefix, so the approval counting runs. No input can carry an approver's
            // signature, so a gated key never verifies.
            rules: vec![rutli_cosigner::config::ApprovalRuleConfig {
                key_id_prefix: "gated-".into(),
                mode: "quorum".into(),
                threshold: 1,
            }],
            approvers: vec![rutli_cosigner::config::ApproverConfig {
                id: "approver-1".into(),
                // RFC 8032 test 1's public key: any valid Ed25519 SPKI will do.
                public_key_spki_b64: "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
                    .into(),
            }],
            ..Default::default()
        };
        rutli_cosigner::intent::IntentVerifier::new(
            pki().ca_pem.as_bytes().to_vec(),
            false,
            CLUSTER.into(),
            ["driver".to_string()],
            &policy,
        )
        .expect("verifier")
        .with_refreshers(["refresher".to_string()])
    })
}

/// Input: one mode byte, then
/// * mode even — a serialized `SignedIntent`, verified as it is (decoding, chain, signature);
/// * mode odd — a serialized `SignIntent`, which the harness signs with an allowlisted client
///   identity first (bit 1 picks the driver or the refresher), so the checks behind the signature
///   (purpose, key, digest, request id, validity, ACL, approvals, ceremony binding) see
///   fuzzer-chosen fields.
pub fn intent(data: &[u8]) -> bool {
    use rutli_cosigner::intent::{self, Expiry};
    use rutli_cosigner::node::CeremonyKind;
    if data.len() > MAX_INPUT {
        return false;
    }
    let Some((&mode, rest)) = data.split_first() else {
        return false;
    };
    let signed = if mode % 2 == 0 {
        match pb::SignedIntent::decode(rest) {
            Ok(s) => s,
            Err(_) => return false,
        }
    } else {
        let Ok(body) = pb::SignIntent::decode(rest) else {
            return false;
        };
        let signer = if mode & 2 == 0 {
            &pki().driver
        } else {
            &pki().refresher
        };
        intent::sign_intent(signer, &body).expect("sign intent")
    };
    let v = verifier();
    let mut accepted = false;

    let key_ids: Vec<String> = match pb::SignIntent::decode(signed.intent.as_slice()) {
        Ok(body) if !body.key_id.is_empty() && body.key_id != KEY_ID => {
            vec![KEY_ID.to_string(), body.key_id]
        }
        _ => vec![KEY_ID.to_string()],
    };
    for key_id in &key_ids {
        if let Ok(ok) = v.verify(&signed, key_id, NOW_MS) {
            accepted = true;
            assert_eq!(&ok.key_id, key_id);
            assert_eq!(ok.digest, intent::intent_digest(&signed));
            assert_eq!(
                ok.message.len(),
                rutli_cosigner::orchestrator::CANTON_DIGEST_LEN
            );
            assert!(
                v.check_live(&ok, NOW_MS).is_ok(),
                "an intent verified now is live now"
            );
            assert!(
                !key_id.starts_with("gated-"),
                "a gated key verified without an approver's signature"
            );
        }
        for expiry in [
            Expiry::Enforce,
            Expiry::Propagated {
                deleted_at_ms: NOW_MS,
            },
        ] {
            accepted |= v.verify_delete(&signed, key_id, NOW_MS, expiry).is_ok();
        }
        for kind in [CeremonyKind::Dkg, CeremonyKind::Refresh] {
            let named = intent::ceremony_id_of(&signed, kind);
            let ceremony_id = named
                .as_deref()
                .unwrap_or("dkg-00000000000000000000000000000000");
            if let Ok(c) = v.verify_ceremony(&signed, kind, key_id, ceremony_id, NOW_MS) {
                accepted = true;
                assert_eq!(c.kind, kind);
                assert_eq!(&c.key_id, key_id);
                assert_eq!(Some(c.ceremony_id.as_str()), named.as_deref().ok());
            }
        }
    }
    accepted
}

// ---------------------------------------------------------------------------------------------
// grpc: protobuf requests into the Signer and Peer handlers of an in-process node.

const MESH_N: u16 = 3;
const MESH_T: u16 = 2;

/// The tokio runtime the handlers run on, and a template of a three-node cluster's key stores:
/// a FROST key `KEY_ID` (DKG) and hosted keys `HOSTED_AES` and `HOSTED_EC`, made once per process.
struct Template {
    rt: tokio::runtime::Runtime,
    dir: tempfile::TempDir,
    /// The nodes that made the key stores, kept for the life of the process: their mesh
    /// (`wire_local_mesh`) is a reference cycle, which dropping them would leak (LeakSanitizer).
    _nodes: Vec<Arc<rutli_cosigner::node::Node>>,
}

fn template() -> &'static Template {
    static T: OnceLock<Template> = OnceLock::new();
    T.get_or_init(|| {
        use rutli_cosigner::pb::signer_server::Signer;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let dir = tempfile::tempdir().expect("template dir");
        let (nodes, signer, _) = mesh_in(dir.path());
        rt.block_on(async {
            rutli_cosigner::orchestrator::run_dkg(&signer.peers, KEY_ID)
                .await
                .expect("dkg");
            for (key_id, spec) in [(HOSTED_AES, "aes-256-gcm"), (HOSTED_EC, "ec-p256-ecies")] {
                let req = pb::GenerateKeyRequest {
                    key_id: key_id.into(),
                    spec: spec.into(),
                    intent: None,
                };
                signer
                    .generate_key(tonic::Request::new(req))
                    .await
                    .expect("generate hosted key");
            }
        });
        Template {
            rt,
            dir,
            _nodes: nodes,
        }
    })
}

/// Three plaintext (dev-mode) nodes over the key stores under `root`, wired in process, and node
/// 1's Signer and Peer services. No TLS, so no caller identity: the input meets the handlers' own
/// request validation and the node behind them.
fn mesh_in(
    root: &Path,
) -> (
    Vec<Arc<rutli_cosigner::node::Node>>,
    rutli_cosigner::service::SignerSvc,
    rutli_cosigner::service::PeerSvc,
) {
    use rutli_cosigner::keystore::KeyStore;
    use rutli_cosigner::node::Node;
    use rutli_cosigner::orchestrator::Peers;
    use rutli_cosigner::peer::{LocalPeer, PeerApi};
    let nodes: Vec<Arc<Node>> = (1..=MESH_N)
        .map(|i| {
            let ks = KeyStore::open(root.join(format!("node-{i}"))).expect("key store");
            let id = frost_ed25519::Identifier::try_from(i).expect("identifier");
            Arc::new(
                Node::new_with_ceremony_timeout(id, MESH_N, MESH_T, ks, Duration::from_secs(2))
                    .with_ceremony_fence_timeout(Duration::from_millis(500))
                    .with_regather_delay(Duration::from_millis(10))
                    .with_hosted_keys(MASTER, CLUSTER.to_string())
                    .expect("hosted keys"),
            )
        })
        .collect();
    rutli_cosigner::peer::wire_local_mesh(&nodes).expect("mesh");
    let peers: Peers = nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>)
        .collect();
    let signer = rutli_cosigner::service::SignerSvc {
        node: nodes[0].clone(),
        peers,
        allowed_cns: None,
        operator_cns: None,
        hosted_write_quorum: 2,
        decrypt_limiter: Arc::new(rutli_cosigner::ratelimit::DecryptRateLimiter::new(0)),
        ceremony_test_limiter: Arc::new(rutli_cosigner::service::ceremony_sign_test_limiter(0)),
        sign_guard: None,
        refresh_cns: None,
    };
    let peer = rutli_cosigner::service::PeerSvc {
        node: nodes[0].clone(),
        allowed_cns: None,
        peer_ids: None,
        peer_pins: None,
    };
    (nodes, signer, peer)
}

/// Decode `$bytes` as `$msg` and call `$svc.$method`; the reply or status is discarded.
macro_rules! call {
    ($rt:expr, $svc:expr, $method:ident, $msg:ty, $bytes:expr) => {{
        match <$msg>::decode($bytes) {
            Ok(req) => {
                let _ = $rt.block_on($svc.$method(tonic::Request::new(req)));
                true
            }
            Err(_) => false,
        }
    }};
}

/// Input: one selector byte (which RPC), then the protobuf request. Each input gets a fresh
/// cluster copied from [`template`], so it sees the same state whatever ran before it and a crash
/// reproduces on its own. `GenerateKey` for RSA is skipped: key generation, not parsing, would
/// dominate the run.
pub fn grpc(data: &[u8]) -> bool {
    use rutli_cosigner::pb::peer_server::Peer;
    use rutli_cosigner::pb::signer_server::Signer;
    if data.len() > MAX_INPUT {
        return false;
    }
    let Some((&sel, b)) = data.split_first() else {
        return false;
    };
    let t = template();
    let root = scratch_path("mesh");
    for i in 1..=MESH_N {
        let (from, to) = (
            t.dir.path().join(format!("node-{i}")),
            root.join(format!("node-{i}")),
        );
        std::fs::create_dir_all(&to).expect("node dir");
        for entry in std::fs::read_dir(&from).expect("template node dir") {
            let path = entry.expect("template entry").path();
            if path.is_file() {
                copy_file(&path, &to.join(path.file_name().expect("file name")))
                    .expect("copy key file");
            }
        }
    }
    let (nodes, signer, peer) = mesh_in(&root);
    let rt = &t.rt;
    let decoded = match sel % 40 {
        0 => call!(rt, signer, health, pb::HealthRequest, b),
        1 => call!(rt, signer, group_key, pb::GroupKeyRequest, b),
        2 => call!(rt, signer, dkg, pb::DkgRequest, b),
        3 => call!(rt, signer, sign, pb::SignRequest, b),
        4 => call!(rt, signer, refresh, pb::RefreshRequest, b),
        5 => call!(rt, signer, key_status, pb::KeyStatusRequest, b),
        6 => call!(
            rt,
            signer,
            ceremony_sign_test,
            pb::CeremonySignTestRequest,
            b
        ),
        7 => call!(rt, signer, capabilities, pb::CapabilitiesRequest, b),
        8 => call!(rt, signer, public_key, pb::PublicKeyRequest, b),
        9 => call!(rt, signer, key_info, pb::KeyInfoRequest, b),
        10 => call!(rt, signer, delete_key, pb::DeleteKeyRequest, b),
        11 => call!(rt, signer, decrypt, pb::DecryptRequest, b),
        12 => call!(rt, signer, ecdh_derive, pb::EcdhDeriveRequest, b),
        13 => call!(rt, signer, symmetric_encrypt, pb::SymmetricRequest, b),
        14 => call!(rt, signer, symmetric_decrypt, pb::SymmetricRequest, b),
        15 => call!(rt, signer, hosted_key_status, pb::HostedKeyStatusRequest, b),
        16 => match pb::GenerateKeyRequest::decode(b) {
            Ok(req) => {
                let rsa = rutli_cosigner::hosted::HostedSpec::parse(&req.spec)
                    .is_ok_and(|s| s == rutli_cosigner::hosted::HostedSpec::Rsa2048);
                if !rsa {
                    let _ = rt.block_on(signer.generate_key(tonic::Request::new(req)));
                }
                true
            }
            Err(_) => false,
        },
        17 => call!(rt, peer, sign_round1, pb::SignRound1Request, b),
        18 => call!(rt, peer, sign_round2, pb::SignRound2Request, b),
        19 => call!(rt, peer, abort_sign, pb::AbortSignRequest, b),
        20 => call!(rt, peer, ceremony_fence, pb::CeremonyFenceRequest, b),
        21 => call!(rt, peer, ceremony_release, pb::CeremonyReleaseRequest, b),
        22 => call!(rt, peer, dkg_part1, pb::DkgPart1Request, b),
        23 => call!(rt, peer, dkg_part2, pb::DkgPart2Request, b),
        24 => call!(rt, peer, dkg_part3, pb::DkgPart3Request, b),
        25 => call!(rt, peer, refresh_part1, pb::RefreshPart1Request, b),
        26 => call!(rt, peer, refresh_part2, pb::DkgPart2Request, b),
        27 => call!(rt, peer, refresh_part3, pb::DkgPart3Request, b),
        28 => call!(rt, peer, ceremony_part1, pb::CeremonyPart1Request, b),
        29 => call!(rt, peer, ceremony_part2, pb::CeremonyPart2Request, b),
        30 => call!(rt, peer, ceremony_deliver, pb::CeremonyDeliverRequest, b),
        31 => call!(rt, peer, ceremony_part3, pb::CeremonyPart3Request, b),
        32 => call!(rt, peer, replicate_key, pb::ReplicateKeyRequest, b),
        33 => call!(rt, peer, fetch_key, pb::FetchKeyRequest, b),
        34 => call!(rt, peer, list_keys, pb::ListKeysRequest, b),
        35 => call!(rt, peer, purge_key, pb::PurgeKeyRequest, b),
        36 => call!(rt, peer, node_info, pb::NodeInfoRequest, b),
        37 => call!(rt, peer, key_epoch, pb::KeyEpochRequest, b),
        38 => call!(rt, peer, ceremony_commit, pb::CeremonyCommitRequest, b),
        _ => match (sel / 40) % 2 {
            0 => call!(rt, peer, ceremony_status, pb::CeremonyStatusRequest, b),
            _ => call!(rt, peer, ceremony_abort, pb::CeremonyAbortRequest, b),
        },
    };
    drop((nodes, signer, peer));
    let _ = std::fs::remove_dir_all(&root);
    decoded
}

// ---------------------------------------------------------------------------------------------
// Seeds.

/// Valid (and a few near-valid) inputs for `target`, made now: `(name, bytes)`. Names starting
/// with `ok-` must be accepted by the target, which the regression test checks. `canton_key` has
/// none: its seeds are the Canton test vectors in `frost/canton-key/testdata/vectors`.
pub fn generated_seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut put = |name: &str, bytes: Vec<u8>| out.push((name.to_string(), bytes));
    match target {
        "key_file" => {
            use rutli_cosigner::keystore::KeyStore;
            use rutli_cosigner::seal::{KeyFileBinding, Sealer};
            let t = template();
            let plain = std::fs::read(t.dir.path().join("node-1").join(format!("{KEY_ID}.json")))
                .expect("share file");
            put("ok-plaintext-share.json", plain);
            let share = KeyStore::open(t.dir.path().join("node-1"))
                .expect("store")
                .load(KEY_ID)
                .expect("share");
            let hosted = rutli_cosigner::hosted::HostedKey::generate(
                rutli_cosigner::hosted::HostedSpec::Aes256Gcm,
                1,
            )
            .expect("aes");
            for (v, binding) in [(1u8, KeyFileBinding::v1(NODE)), (2u8, binding_v2())] {
                let dir = scratch_path("seed-store");
                let s = Arc::new(Sealer::from_dek(Zeroizing::new(DEK), NODE).with_binding(binding));
                let ks = KeyStore::open_with_sealer(&dir, Some(s)).expect("sealed store");
                ks.save(KEY_ID, &share).expect("save share");
                put(
                    &format!("ok-sealed-v{v}-share.json"),
                    std::fs::read(dir.join(format!("{KEY_ID}.json"))).expect("read"),
                );
                ks.save_hosted(KEY_ID, &hosted).expect("save hosted");
                put(
                    &format!("ok-sealed-v{v}-hosted.json"),
                    std::fs::read(dir.join(format!("{KEY_ID}.json"))).expect("read"),
                );
            }
        }
        "seal_bundle" => {
            let b = rutli_cosigner::seal::NodeSealBundle::from_legacy_master(b"fuzz master", NODE);
            put("ok-bundle.json", b.to_json().expect("json").to_vec());
            put(
                "ok-bundle-rotated.json",
                b.rotated().to_json().expect("json").to_vec(),
            );
        }
        "share_bundle" => {
            let node = share_node();
            put(
                "ok-recipient-request.json",
                serde_json::to_vec_pretty(&node.request).expect("json"),
            );
            let dealt = dealt_key();
            let verified = rutli_cosigner::request_auth::verify_request(
                &node.request,
                pki().ca_pem.as_bytes(),
            )
            .expect("verify own request");
            let usage = rutli_cosigner::carry::CarriedUsage {
                expected: "namespace".into(),
                recorded: Some(vec!["namespace".into()]),
                namespace_fingerprint: None,
            };
            let me = frost_ed25519::Identifier::try_from(NODE).expect("identifier");
            let share = dealt
                .shares
                .iter()
                .find(|s| *s.identifier() == me)
                .expect("node 1's share");
            let bundle = rutli_cosigner::share_delivery::seal_share(
                &verified,
                share,
                &dealt.pkp,
                &dealt.fingerprint,
                &usage,
            )
            .expect("seal share");
            put(
                "ok-share-bundle.json",
                serde_json::to_vec_pretty(&bundle).expect("json"),
            );
        }
        "export_file" => {
            use rutli_cosigner::export;
            use rutli_cosigner::hosted::{HostedKey, HostedSpec};
            let aes = HostedKey::generate(HostedSpec::Aes256Gcm, 1).expect("aes");
            let ec = HostedKey::generate(HostedSpec::EcP256, 1).expect("ec");
            let json = |e: &export::ExportEnvelope| serde_json::to_vec_pretty(e).expect("json");
            put(
                "ok-plaintext-aes.json",
                json(&export::export_plaintext("rutli-fuzz-aes", &aes).expect("export")),
            );
            put(
                "ok-plaintext-ec.json",
                json(&export::export_plaintext("rutli-fuzz-ec", &ec).expect("export")),
            );
            put(
                "encrypted-aes.json",
                json(
                    &export::export_encrypted("rutli-fuzz-aes", &aes, "fuzz passphrase 0")
                        .expect("export"),
                ),
            );
        }
        "intent" => {
            let base = pb::SignIntent {
                version: 1,
                cluster_id: CLUSTER.into(),
                purpose: "sign".into(),
                key_id: KEY_ID.into(),
                digest: [&[0x12u8, 0x20][..], &[0xab; 32]].concat(),
                request_id: vec![0x42; 16],
                issued_at_ms: NOW_MS,
                not_after_ms: NOW_MS + 60_000,
                approval_nonce: Vec::new(),
                approvals: Vec::new(),
                ..Default::default()
            };
            let with = |mode: u8, i: &pb::SignIntent| [vec![mode], i.encode_to_vec()].concat();
            let ceremony = |purpose: &str| pb::SignIntent {
                purpose: purpose.into(),
                digest: vec![],
                ..base.clone()
            };
            put("ok-sign.bin", with(1, &base));
            put("ok-dkg.bin", with(1, &ceremony("dkg")));
            put("ok-refresh-by-refresher.bin", with(3, &ceremony("refresh")));
            put("ok-signed-sign.bin", {
                let signed =
                    rutli_cosigner::intent::sign_intent(&pki().driver, &base).expect("sign");
                [vec![0u8], signed.encode_to_vec()].concat()
            });
            put(
                "delete.bin",
                with(
                    1,
                    &pb::SignIntent {
                        purpose: "delete-key".into(),
                        key_id: HOSTED_AES.into(),
                        digest: rutli_cosigner::intent::delete_digest(HOSTED_AES).to_vec(),
                        ..base.clone()
                    },
                ),
            );
            put(
                "gated-sign.bin",
                with(
                    1,
                    &pb::SignIntent {
                        key_id: "gated-key".into(),
                        approval_nonce: vec![1; 16],
                        approvals: vec![pb::IntentApproval {
                            approver_id: "approver-1".into(),
                            signature: vec![0; 64],
                        }],
                        ..base.clone()
                    },
                ),
            );
        }
        "grpc" => {
            let g = |sel: u8, m: Vec<u8>| [vec![sel], m].concat();
            let msg = [&[0x12u8, 0x20][..], &[0x5a; 32]].concat();
            put(
                "health.bin",
                g(0, pb::HealthRequest::default().encode_to_vec()),
            );
            put(
                "group-key.bin",
                g(
                    1,
                    pb::GroupKeyRequest {
                        key_id: KEY_ID.into(),
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "sign.bin",
                g(
                    3,
                    pb::SignRequest {
                        key_id: KEY_ID.into(),
                        message: msg.clone(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "key-status.bin",
                g(
                    5,
                    pb::KeyStatusRequest {
                        key_id: KEY_ID.into(),
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "capabilities.bin",
                g(7, pb::CapabilitiesRequest::default().encode_to_vec()),
            );
            put(
                "public-key.bin",
                g(
                    8,
                    pb::PublicKeyRequest {
                        key_id: HOSTED_EC.into(),
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "ecdh.bin",
                g(
                    12,
                    pb::EcdhDeriveRequest {
                        key_id: HOSTED_EC.into(),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "symmetric-encrypt.bin",
                g(
                    13,
                    pb::SymmetricRequest {
                        key_id: HOSTED_AES.into(),
                        data: b"x".to_vec(),
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "symmetric-decrypt.bin",
                g(
                    14,
                    pb::SymmetricRequest {
                        key_id: HOSTED_AES.into(),
                        data: vec![0; 40],
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "generate-aes.bin",
                g(
                    16,
                    pb::GenerateKeyRequest {
                        key_id: "rutli-fuzz-new".into(),
                        spec: "aes-256-gcm".into(),
                        intent: None,
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "round1.bin",
                g(
                    17,
                    pb::SignRound1Request {
                        key_id: KEY_ID.into(),
                        session_id: "fuzz-session-1".into(),
                        message: msg.clone(),
                        signers: vec![1, 2],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "fence-dkg.bin",
                g(
                    20,
                    pb::CeremonyFenceRequest {
                        ceremony_id: "dkg-fuzz".into(),
                        key_id: "frost-fuzz-2".into(),
                        kind: "dkg".into(),
                        protocol: 2,
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "node-info.bin",
                g(36, pb::NodeInfoRequest::default().encode_to_vec()),
            );
            put(
                "key-epoch.bin",
                g(
                    37,
                    pb::KeyEpochRequest {
                        key_id: KEY_ID.into(),
                    }
                    .encode_to_vec(),
                ),
            );
            put(
                "ceremony-status.bin",
                g(
                    39,
                    pb::CeremonyStatusRequest {
                        ceremony_id: "dkg-fuzz".into(),
                    }
                    .encode_to_vec(),
                ),
            );
        }
        _ => {}
    }
    out
}

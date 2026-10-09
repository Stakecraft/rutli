// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! EC P-256 (ECIES) hosted keys — milestone C1 (docs/roadmap-migration.md, Track C):
//!
//! - replication, anti-entropy and read-repair carry an `ec-p256-ecies` key like any hosted key,
//!   and every replica answers `EcdhDerive` with the same Z;
//! - the `EcdhDerive` RPC's guards, called on the service itself: reserved ids, malformed and
//!   off-curve points, non-EC keys, the per-key decryption budget, read-repair;
//! - the portable export round trip, and `import-key` of B1's real Canton 3.6.1 ECIES encryption
//!   key — library and CLI — including every refusal the migration runbook relies on.

// tonic::Status is large by value (see the crate root); the RPC helper returns it as the service does.
#![allow(clippy::result_large_err)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use frost_ed25519::Identifier;
use rutli_cosigner::hosted::{HostedKey, HostedSpec};
use rutli_cosigner::keystore::KeyStore;
use rutli_cosigner::node::Node;
use rutli_cosigner::orchestrator::{
    anti_entropy_sweep, generate_hosted_key, repair_hosted_key, Peers, DEFAULT_WRITE_QUORUM,
};
use rutli_cosigner::pb;
use rutli_cosigner::pb::signer_server::Signer;
use rutli_cosigner::peer::{LocalPeer, PeerApi};
use rutli_cosigner::ratelimit::DecryptRateLimiter;
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::service::SignerSvc;
use tonic::{Code, Request};

const N: u16 = 3;
const T: u16 = 2;
const MASTER: &[u8] = b"hosted key cluster master secret for tests";
const CLUSTER: &str = "testcluster00000";

/// The known-answer vector of `hosted.rs` (independent Python P-256): V = e·G, Z = x(d·V).
const KAT_D: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const KAT_V: &str = "041f5efe3b2928f7db57c6befca0428a5833ea10b2e70fada8ccf40478c29bbcdb\
                     3a143c9e3f9982325a7750a8b095d0b3feaf12fd01ef6172739b82e9ec62c421";
const KAT_Z: &str = "605c4045e713174af954ea4740a93c48b42298ab59425be60430752ace33dc1e";

fn hosted_cluster(tmp: &tempfile::TempDir) -> (Vec<Arc<Node>>, Peers) {
    let mut nodes = Vec::new();
    for i in 1..=N {
        let sealer = Arc::new(Sealer::from_master_secret(MASTER, i));
        let ks =
            KeyStore::open_with_sealer(tmp.path().join(format!("node-{i}")), Some(sealer)).unwrap();
        let node = Node::new(Identifier::try_from(i).unwrap(), N, T, ks)
            .with_hosted_keys(MASTER, CLUSTER.to_string())
            .unwrap();
        nodes.push(Arc::new(node));
    }
    let peers: Peers =
        nodes.iter().map(|n| Arc::new(LocalPeer::new(n.clone())) as Arc<dyn PeerApi>).collect();
    (nodes, peers)
}

/// Node `me`'s view of the cluster for pulls: every other node answers `FetchKey` wrapped to `me`,
/// as the gRPC path does for the certificate-identified caller.
fn view_of(nodes: &[Arc<Node>], me: usize) -> Peers {
    nodes
        .iter()
        .map(|n| Arc::new(LocalPeer::new(n.clone()).on_behalf_of(nodes[me].clone())) as Arc<dyn PeerApi>)
        .collect()
}

fn signer(node: &Arc<Node>, peers: &Peers, decrypt_per_min: u32) -> SignerSvc {
    SignerSvc {
        node: node.clone(),
        peers: peers.clone(),
        allowed_cns: None,
        operator_cns: None,
        hosted_write_quorum: DEFAULT_WRITE_QUORUM,
        decrypt_limiter: Arc::new(DecryptRateLimiter::new(decrypt_per_min)),
        ceremony_test_limiter: Arc::new(DecryptRateLimiter::new(0)),
    }
}

async fn ecdh(svc: &SignerSvc, key_id: &str, point: &[u8]) -> Result<Vec<u8>, tonic::Status> {
    svc.ecdh_derive(Request::new(pb::EcdhDeriveRequest {
        key_id: key_id.into(),
        peer_point: point.to_vec(),
    }))
    .await
    .map(|r| r.into_inner().shared_secret)
}

fn v() -> Vec<u8> {
    hex::decode(KAT_V).unwrap()
}

// ── replication ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_ec_key_replicates_and_every_replica_derives_the_same_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);

    let (key, created, replicas) =
        generate_hosted_key(&nodes[0], &peers, "rutli-enc-ec-1", HostedSpec::EcP256, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();
    assert!(created);
    assert_eq!(replicas, N as usize);

    let spki = key.public_key_der().unwrap();
    let z = key.ecdh_p256(&v()).unwrap();
    for n in &nodes {
        let replica = n.hosted_load("rutli-enc-ec-1").unwrap();
        assert_eq!(replica.spec, HostedSpec::EcP256);
        assert_eq!(replica.public_key_der().unwrap(), spki, "every node serves one public key");
        assert_eq!(n.hosted_ecdh("rutli-enc-ec-1", &v()).unwrap().as_ref(), z.as_ref());
    }

    // Sealed at rest like every hosted key.
    let raw = std::fs::read(tmp.path().join("node-3").join("rutli-enc-ec-1.json")).unwrap();
    assert!(Sealer::is_sealed(&raw));
    assert!(!String::from_utf8_lossy(&raw).contains("private_der"));

    // Idempotent: a retry returns the same key, and a retry under another spec is refused.
    let (again, created, _) =
        generate_hosted_key(&nodes[1], &peers, "rutli-enc-ec-1", HostedSpec::EcP256, DEFAULT_WRITE_QUORUM)
            .await
            .unwrap();
    assert!(!created);
    assert_eq!(again.public_key_der().unwrap(), spki);
    assert!(generate_hosted_key(&nodes[1], &peers, "rutli-enc-ec-1", HostedSpec::Rsa2048, 2)
        .await
        .is_err());
}

#[tokio::test]
async fn anti_entropy_and_read_repair_carry_ec_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = hosted_cluster(&tmp);

    // Only node 3 has it (the others were down for the write).
    let (key, _) = nodes[2].hosted_generate("rutli-enc-ec-2", HostedSpec::EcP256).unwrap();
    let (pulled, _) = anti_entropy_sweep(&nodes[1], &view_of(&nodes, 1)).await.unwrap();
    assert!(pulled >= 1);
    assert!(repair_hosted_key(&nodes[0], &view_of(&nodes, 0), "rutli-enc-ec-2").await.unwrap());
    let z = key.ecdh_p256(&v()).unwrap();
    for n in &nodes {
        assert_eq!(n.hosted_ecdh("rutli-enc-ec-2", &v()).unwrap().as_ref(), z.as_ref());
    }
}

#[tokio::test]
async fn a_replica_whose_public_key_is_not_its_own_is_refused() {
    // A hostile or buggy peer pushes an EC key whose public half belongs to another key: the
    // recipient would serve Canton a public key it cannot decrypt for. Refused at unwrap.
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = hosted_cluster(&tmp);
    let mut forged = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
    forged.public_der = HostedKey::generate(HostedSpec::EcP256, 1).unwrap().public_der.clone();
    let to = nodes[1].dist_public_key().unwrap();
    let wrapped = nodes[0].hosted_wrap_for("rutli-enc-forged", &forged, 2, &to).unwrap();
    assert!(nodes[1].hosted_unwrap("rutli-enc-forged", HostedSpec::EcP256, &wrapped).is_err());
}

// ── mixed-version clusters (review M1) ─────────────────────────────────────────────────────────

/// A cosigner whose NodeInfo reports no `ec-p256-ecies` — as one built before Track C does (its
/// reply has no specs field at all, which decodes as an empty list). Modelled by a node with hosted
/// keys off, which reports exactly that.
fn node_without_ec(tmp: &tempfile::TempDir, i: u16) -> Arc<Node> {
    let ks = KeyStore::open(tmp.path().join(format!("old-{i}"))).unwrap();
    Arc::new(Node::new(Identifier::try_from(i).unwrap(), N, T, ks))
}

#[tokio::test]
async fn an_ec_key_is_not_created_while_a_peer_does_not_report_the_spec() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = hosted_cluster(&tmp);
    let old = node_without_ec(&tmp, 3);
    assert!(old.hosted_specs().is_empty());
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
        Arc::new(LocalPeer::new(nodes[1].clone())),
        Arc::new(LocalPeer::new(old)),
    ];

    let err = generate_hosted_key(&nodes[0], &peers, "rutli-enc-ec-mixed", HostedSpec::EcP256, 2)
        .await
        .unwrap_err();
    let status = tonic::Status::from(err);
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    assert!(status.message().contains("cosigner 3 does not support it"), "{status:?}");
    assert!(status.message().contains("upgrade") || status.message().contains("release"), "{status:?}");
    // Nothing was written anywhere, and no fence is left behind.
    assert!(!nodes[0].hosted_exists("rutli-enc-ec-mixed"));
    assert!(!nodes[1].hosted_exists("rutli-enc-ec-mixed"));

    // v1 specs are unaffected: an RSA key still commits at the write quorum.
    let (_, created, replicas) =
        generate_hosted_key(&nodes[0], &peers, "rutli-enc-rsa-mixed", HostedSpec::Rsa2048, 2).await.unwrap();
    assert!(created);
    assert_eq!(replicas, 2);
}

#[tokio::test]
async fn an_ec_key_is_not_created_while_a_peer_cannot_be_asked() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = hosted_cluster(&tmp);
    // Node 3 is down: nothing listens on its endpoint.
    let down = rutli_cosigner::peer::GrpcPeer::connect_lazy(
        Identifier::try_from(3u16).unwrap(),
        "http://127.0.0.1:1",
        None,
    )
    .unwrap();
    let peers: Peers = vec![
        Arc::new(LocalPeer::new(nodes[0].clone())) as Arc<dyn PeerApi>,
        Arc::new(LocalPeer::new(nodes[1].clone())),
        Arc::new(down),
    ];
    let err = generate_hosted_key(&nodes[0], &peers, "rutli-enc-ec-down", HostedSpec::EcP256, 2)
        .await
        .unwrap_err();
    let status = tonic::Status::from(err);
    assert_eq!(status.code(), Code::FailedPrecondition, "{status:?}");
    assert!(status.message().contains("cosigner 3 could not be asked"), "{status:?}");
    // An RSA write still goes through with the node down (2-of-3 write quorum).
    generate_hosted_key(&nodes[0], &peers, "rutli-enc-rsa-down", HostedSpec::Rsa2048, 2).await.unwrap();
}

#[test]
fn only_specs_newer_than_v1_need_every_node() {
    assert!(HostedSpec::EcP256.needs_every_node());
    assert!(!HostedSpec::Rsa2048.needs_every_node());
    assert!(!HostedSpec::Aes256Gcm.needs_every_node());
}

// ── the EcdhDerive RPC ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ecdh_derive_answers_the_known_vector_and_any_node_serves_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, _) = hosted_cluster(&tmp);
    let kat = HostedKey::ec_p256_from_scalar(&hex::decode(KAT_D).unwrap(), 1).unwrap();
    nodes[0].hosted_store("rutli-enc-kat", &kat).unwrap();

    // Node 2 lacks the key: the RPC read-repairs from a peer before answering.
    let svc = signer(&nodes[1], &view_of(&nodes, 1), 0);
    assert_eq!(hex::encode(ecdh(&svc, "rutli-enc-kat", &v()).await.unwrap()), KAT_Z);
    assert!(nodes[1].hosted_exists("rutli-enc-kat"), "read-repair stored the key");

    // Capabilities advertises the spec, so the driver can offer EcP256 to Canton.
    let caps = svc.capabilities(Request::new(pb::CapabilitiesRequest {})).await.unwrap().into_inner();
    assert!(caps.hosted_key_specs.contains(&"ec-p256-ecies".to_string()), "{caps:?}");

    // An unknown key is NOT_FOUND (authoritative after read-repair), never a guess.
    let err = ecdh(&svc, "rutli-enc-nobody", &v()).await.unwrap_err();
    assert_eq!(err.code(), Code::NotFound, "{err:?}");
}

#[tokio::test]
async fn ecdh_derive_refuses_bad_points_reserved_ids_and_non_ec_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);
    let svc = signer(&nodes[0], &peers, 0);
    generate_hosted_key(&nodes[0], &peers, "rutli-enc-ec", HostedSpec::EcP256, 2).await.unwrap();
    generate_hosted_key(&nodes[0], &peers, "rutli-enc-rsa", HostedSpec::Rsa2048, 2).await.unwrap();
    generate_hosted_key(&nodes[0], &peers, "rutli-sym-aes", HostedSpec::Aes256Gcm, 2).await.unwrap();

    let mut compressed = vec![0x03];
    compressed.extend_from_slice(&v()[1..33]);
    let mut off_curve = v();
    off_curve[64] ^= 1;
    for (what, point) in [
        ("empty", vec![]),
        ("infinity", vec![0x00]),
        ("compressed", compressed),
        ("truncated", v()[..64].to_vec()),
        ("off-curve", off_curve),
    ] {
        let err = ecdh(&svc, "rutli-enc-ec", &point).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{what}: {err:?}");
    }

    // A non-EC hosted key is never an ECDH oracle.
    for id in ["rutli-enc-rsa", "rutli-sym-aes"] {
        let err = ecdh(&svc, id, &v()).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition, "{id}: {err:?}");
    }

    // Ids reserved for the split ceremony are refused outright, whatever the point.
    for id in ["frost-import-1220cb0e", "soak1-frost-import-x"] {
        let err = ecdh(&svc, id, &v()).await.unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists, "{id}: {err:?}");
    }
}

#[tokio::test]
async fn ecdh_derive_spends_the_decryption_budget_but_malformed_requests_do_not() {
    let tmp = tempfile::tempdir().unwrap();
    let (nodes, peers) = hosted_cluster(&tmp);
    generate_hosted_key(&nodes[0], &peers, "rutli-enc-ec", HostedSpec::EcP256, 2).await.unwrap();
    // A budget of two per minute (the bucket starts full).
    let svc = signer(&nodes[0], &peers, 2);

    // Refused from the request alone: no budget spent.
    for _ in 0..5 {
        assert_eq!(ecdh(&svc, "rutli-enc-ec", &[0x04; 64]).await.unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(ecdh(&svc, "frost-import-x", &v()).await.unwrap_err().code(), Code::AlreadyExists);
    }
    ecdh(&svc, "rutli-enc-ec", &v()).await.unwrap();
    ecdh(&svc, "rutli-enc-ec", &v()).await.unwrap();
    let err = ecdh(&svc, "rutli-enc-ec", &v()).await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted, "{err:?}");

    // The budget is the same one Decrypt draws on: per key, shared across both RPCs.
    let err = svc
        .decrypt(Request::new(pb::DecryptRequest { key_id: "rutli-enc-ec".into(), ciphertext: vec![0; 256] }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted, "{err:?}");
}

// ── export / import ────────────────────────────────────────────────────────────────────────────

const PASS: &str = "a sufficiently long export passphrase";

#[test]
fn an_ec_key_survives_a_portable_export_into_another_cluster() {
    let key = HostedKey::generate(HostedSpec::EcP256, 42).unwrap();
    let z = key.ecdh_p256(&v()).unwrap();
    let env = rutli_cosigner::export::export_encrypted("rutli-enc-ec-portable", &key, PASS).unwrap();
    let back = rutli_cosigner::export::import(&env, Some(PASS)).unwrap();
    assert_eq!(back.spec, HostedSpec::EcP256);
    assert_eq!(back.ecdh_p256(&v()).unwrap().as_ref(), z.as_ref());
    assert_eq!(back.created_at, 42);

    // An artifact whose EC public key was swapped is refused on import.
    let mut forged = key.clone();
    forged.public_der = HostedKey::generate(HostedSpec::EcP256, 1).unwrap().public_der.clone();
    let env = rutli_cosigner::export::export_plaintext("rutli-enc-ec-forged", &forged).unwrap();
    assert!(rutli_cosigner::export::import(&env, None).is_err());
}

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../canton-key/testdata/vectors")
}

fn manifest() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(vectors().join("manifest.json")).unwrap()).unwrap()
}

fn fingerprint_of(name: &str) -> String {
    manifest()["keys"].as_array().unwrap().iter().find(|k| k["name"] == name).unwrap()["fingerprint"]
        .as_str()
        .unwrap()
        .to_string()
}

fn password() -> String {
    manifest()["password"].as_str().unwrap().to_string()
}

fn read(file: &str) -> Vec<u8> {
    std::fs::read(vectors().join(file)).unwrap()
}

#[test]
fn a_canton_ecies_key_imports_with_the_exact_public_key_canton_recorded() {
    use rutli_cosigner::export::import_canton;
    let fp = fingerprint_of("encryption");
    // What Canton itself publishes for this key (`keys.public.download`).
    let canton_pub = rutli_canton_key::parse_public_key(&read("encryption.pub.bin")).unwrap();
    assert_eq!(canton_pub.fingerprint(), fp);

    let plain = import_canton(&read("encryption.export.bin"), None, &fp, 1).unwrap();
    let pw = import_canton(&read("encryption.export-pw.bin"), Some(password().as_bytes()), &fp, 1).unwrap();
    let stored = import_canton(&read("encryption.stored.bin"), None, &fp, 1).unwrap();
    for imported in [&plain, &pw, &stored] {
        assert_eq!(imported.fingerprint, fp);
        assert_eq!(imported.key.spec, HostedSpec::EcP256);
        // Byte-identical SPKI: Canton re-registers the key by the fingerprint of these bytes.
        assert_eq!(imported.key.public_key_der().unwrap(), canton_pub.public.spki_der());
        imported.key.validate().unwrap();
    }
    // All three forms are the same key (same deterministic encoding, same ECDH).
    assert_eq!(plain.key.private_der, pw.key.private_der);
    assert_eq!(plain.key.private_der, stored.key.private_der);

    // And it is the key B1's parser reads: ECDH with the parsed scalar agrees.
    let parsed = rutli_canton_key::parse(&read("encryption.export.bin"), None).unwrap();
    let rutli_canton_key::PrivateKeyMaterial::EcP256 { scalar } = &parsed.material else { panic!() };
    let reference = HostedKey::ec_p256_from_scalar(scalar.as_ref(), 1).unwrap();
    assert_eq!(
        plain.key.ecdh_p256(&v()).unwrap().as_ref(),
        reference.ecdh_p256(&v()).unwrap().as_ref()
    );
    // The fingerprint argument is normalised (an operator pasting upper case is not a mismatch).
    assert!(import_canton(&read("encryption.export.bin"), None, &fp.to_uppercase(), 1).is_ok());
}

#[test]
fn canton_import_refuses_every_key_that_is_not_the_expected_ecies_key() {
    use rutli_cosigner::export::import_canton;
    let fp = fingerprint_of("encryption");
    let refused = |input: &[u8], pw: Option<&[u8]>, expect: &str| {
        import_canton(input, pw, expect, 1).expect_err("must be refused").to_string()
    };

    // The right file, the wrong expected key.
    let e = refused(&read("encryption.export.bin"), None, &fingerprint_of("extra-ecp256-signing"));
    assert!(e.contains("not the expected"), "{e}");
    // A P-256 signing key is never turned into an ECDH oracle, even when it is the expected key.
    let e = refused(
        &read("extra-ecp256-signing.export.bin"),
        None,
        &fingerprint_of("extra-ecp256-signing"),
    );
    assert!(e.contains("signing key"), "{e}");
    // Ed25519 goes through the split ceremony; RSA is milestone B3.
    let e = refused(&read("namespace.export.bin"), None, &fingerprint_of("namespace"));
    assert!(e.contains("split ceremony"), "{e}");
    let e = refused(
        &read("extra-rsa2048-encryption.export.bin"),
        None,
        &fingerprint_of("extra-rsa2048-encryption"),
    );
    assert!(e.contains("B3"), "{e}");
    // Password handling is the parser's: required when protected, refused when not, checked.
    assert!(refused(&read("encryption.export-pw.bin"), None, &fp).contains("password"));
    assert!(refused(&read("encryption.export-pw.bin"), Some(b"wrong password"), &fp).contains("password"));
    assert!(refused(&read("encryption.export.bin"), Some(b"x"), &fp).contains("password"));
    // Plain PKCS#8 carries no purpose, so it cannot be told from a signing key.
    let parsed = rutli_canton_key::parse(&read("encryption.export.bin"), None).unwrap();
    let rutli_canton_key::PrivateKeyMaterial::EcP256 { scalar } = &parsed.material else { panic!() };
    let pkcs8 = HostedKey::ec_p256_from_scalar(scalar.as_ref(), 1).unwrap().private_der.clone();
    let e = refused(&hex::decode(pkcs8).unwrap(), None, &fp);
    assert!(e.contains("PKCS#8"), "{e}");
    // Garbage.
    assert!(refused(b"\x0a\x03abc", None, &fp).contains("cannot read"));
}

// ── the import-key CLI ─────────────────────────────────────────────────────────────────────────

const SEAL_ENV: &str = "RUTLI_TEST_SEAL_SECRET";
const SEAL: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
const PW_ENV: &str = "RUTLI_TEST_CANTON_PASSWORD";

fn cli_config(dir: &Path) -> PathBuf {
    let cfg = dir.join("cosigner1.json");
    std::fs::write(
        &cfg,
        serde_json::json!({
            "identifier": 1,
            "listen": "127.0.0.1:1",
            "threshold": 2,
            "data_dir": dir,
            "peers": [
                { "identifier": 1, "endpoint": "http://127.0.0.1:1" },
                { "identifier": 2, "endpoint": "http://127.0.0.1:2" },
                { "identifier": 3, "endpoint": "http://127.0.0.1:3" }
            ],
            "share_seal": { "secret_env": SEAL_ENV },
        })
        .to_string(),
    )
    .unwrap();
    cfg
}

fn import_key(cfg: &Path, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .args(["--config", cfg.to_str().unwrap(), "import-key"])
        .args(args)
        .env_remove("RUTLI_COSIGNER_CONFIG")
        .env(SEAL_ENV, SEAL)
        .env(PW_ENV, password())
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

#[test]
fn import_key_cli_installs_a_canton_ecies_key_once() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = cli_config(tmp.path());
    let fp = fingerprint_of("encryption");
    let input = vectors().join("encryption.export-pw.bin");
    let input = input.to_str().unwrap();
    let id = "soak1-rutli-enc-imported-1";

    // Canton input needs both --key-id and --expect-fingerprint.
    let (ok, out) = import_key(&cfg, &["--in", input, "--passphrase-env", PW_ENV]);
    assert!(!ok && out.contains("--key-id"), "{out}");
    // An id the driver could never route to the cluster.
    let (ok, out) = import_key(
        &cfg,
        &["--in", input, "--passphrase-env", PW_ENV, "--key-id", "enc-1", "--expect-fingerprint", &fp],
    );
    assert!(!ok && out.contains("routing tag"), "{out}");
    // An id reserved for the split ceremony.
    let (ok, out) = import_key(
        &cfg,
        &["--in", input, "--passphrase-env", PW_ENV, "--key-id", "rutli-frost-import-x", "--expect-fingerprint", &fp],
    );
    assert!(!ok && out.contains("FROST routing tag"), "{out}");
    // --key-prefix must match the id.
    let (ok, out) = import_key(
        &cfg,
        &["--in", input, "--passphrase-env", PW_ENV, "--key-id", id, "--expect-fingerprint", &fp, "--key-prefix", "soak2-"],
    );
    assert!(!ok && out.contains("soak2-rutli-"), "{out}");

    let args = [
        "--in", input, "--passphrase-env", PW_ENV, "--key-id", id, "--expect-fingerprint", &fp, "--key-prefix", "soak1-",
    ];
    let (ok, out) = import_key(&cfg, &args);
    assert!(ok, "{out}");
    assert!(out.contains("ec-p256-ecies") && out.contains(&fp), "{out}");
    assert!(out.contains("frost.key-prefix is \"soak1-\""), "{out}");

    // Installed, sealed, and serving the key Canton recorded.
    let ks = KeyStore::open_with_sealer(
        tmp.path().join("keys"),
        Some(Arc::new(Sealer::from_master_secret(SEAL.as_bytes(), 1))),
    )
    .unwrap();
    let key = ks.load_hosted(id).unwrap();
    let canton_pub = rutli_canton_key::parse_public_key(&read("encryption.pub.bin")).unwrap();
    assert_eq!(key.public_key_der().unwrap(), canton_pub.public.spki_der());
    assert!(Sealer::is_sealed(&std::fs::read(tmp.path().join("keys").join(format!("{id}.json"))).unwrap()));

    // A second, identical import is a no-op; the same id with another key is refused.
    let (ok, out) = import_key(&cfg, &args);
    assert!(ok && out.contains("identical"), "{out}");
    let other = HostedKey::generate(HostedSpec::EcP256, 1).unwrap();
    let env = rutli_cosigner::export::export_plaintext(id, &other).unwrap();
    let artifact = tmp.path().join("other.json");
    std::fs::write(&artifact, serde_json::to_vec(&env).unwrap()).unwrap();
    let (ok, out) = import_key(&cfg, &["--in", artifact.to_str().unwrap()]);
    assert!(!ok && out.contains("different material"), "{out}");
    // A Rütli artifact carries its own id: the Canton-only flags are refused for it.
    let (ok, out) = import_key(&cfg, &["--in", artifact.to_str().unwrap(), "--key-id", "rutli-x"]);
    assert!(!ok && out.contains("carries its own key id"), "{out}");
}

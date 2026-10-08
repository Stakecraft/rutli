// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The `rutli-dealer` binary end to end, on B1's real Canton 3.6.1 key vectors: what it writes,
//! that every bundle opens on its node only, and every refusal the runbook relies on.

use std::path::{Path, PathBuf};
use std::process::Command;

use rutli_cosigner::seal::Sealer;
use rutli_cosigner::share_delivery::{
    self, RecipientRequest, ShareBundle, RECIPIENT_KIND, RECIPIENT_VERSION,
};

const KEY: &str = "frost-import-1220cb0e";
const CEREMONY: &str = "b2-test";
const CLUSTER: &str = "0011223344556677";
const PASSWORD_ENV: &str = "RUTLI_TEST_EXPORT_PASSWORD";

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../canton-key/testdata/vectors")
}

fn manifest() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(vectors().join("manifest.json")).unwrap()).unwrap()
}

fn fingerprint_of(name: &str) -> String {
    manifest()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == name)
        .unwrap()["fingerprint"]
        .as_str()
        .unwrap()
        .to_string()
}

fn password() -> String {
    manifest()["password"].as_str().unwrap().to_string()
}

fn sealer(node: u16) -> Sealer {
    Sealer::from_master_secret(b"dealer cli test master secret", node)
}

struct Ceremony {
    tmp: tempfile::TempDir,
    requests: Vec<PathBuf>,
}

impl Ceremony {
    /// Three nodes run share-recipient (via the library) and drop their requests in `requests/`.
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("requests")).unwrap();
        let mut requests = Vec::new();
        for id in 1..=3u16 {
            let r = share_delivery::create_recipient(&tmp.path().join(format!("node{id}")), &sealer(id), template(id), false)
                .unwrap();
            let path = tmp.path().join("requests").join(format!("r{id}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&r).unwrap()).unwrap();
            requests.push(path);
        }
        Self { tmp, requests }
    }

    fn out(&self) -> PathBuf {
        self.tmp.path().join("out")
    }

    fn dealer(&self, input: &str, fingerprint: &str, extra: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rutli-dealer"));
        cmd.arg("split-key")
            .arg("--in")
            .arg(vectors().join(input))
            .args(["--expect-fingerprint", fingerprint, "--key-id", KEY, "--threshold", "2"])
            .arg("--out-dir")
            .arg(self.out())
            .env(PASSWORD_ENV, password());
        for r in &self.requests {
            cmd.arg("--recipient").arg(r);
        }
        cmd.args(extra);
        cmd.output().unwrap()
    }

    fn bundle(&self, node: u16) -> ShareBundle {
        let path = self.out().join(format!("share-{KEY}-node{node}.json"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn state(&self, node: u16) -> share_delivery::RecipientState {
        share_delivery::load_recipient(&self.tmp.path().join(format!("node{node}")), &sealer(node), KEY)
            .unwrap()
    }
}

fn template(identifier: u16) -> RecipientRequest {
    RecipientRequest {
        v: RECIPIENT_VERSION,
        kind: RECIPIENT_KIND.into(),
        ceremony_id: CEREMONY.into(),
        key_id: KEY.into(),
        cluster_id: CLUSTER.into(),
        identifier,
        threshold: 2,
        max_signers: 3,
        roster: vec![1, 2, 3],
        recipient_pub: String::new(),
    }
}

/// `--allow-swap` where swap cannot be ruled out (every non-Linux host, a Linux host with swap).
const SWAP: &str = "--allow-swap";

fn ok(out: &std::process::Output) {
    assert!(
        out.status.success(),
        "dealer failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn refused(out: &std::process::Output, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "expected a refusal containing {needle:?}");
    assert!(stderr.contains(needle), "expected {needle:?} in: {stderr}");
}

/// The seed of a vector, to prove it never appears in any output.
fn seed_hex(input: &str) -> String {
    let bytes = std::fs::read(vectors().join(input)).unwrap();
    let pw = password();
    let key = rutli_canton_key::parse(&bytes, input.contains("-pw").then_some(pw.as_bytes())).unwrap();
    let rutli_canton_key::PrivateKeyMaterial::Ed25519 { seed } = &key.material else { panic!() };
    hex::encode(seed.as_slice())
}

#[test]
fn split_key_writes_one_sealed_bundle_per_node_and_a_public_record() {
    let c = Ceremony::new();
    let fp = fingerprint_of("namespace");
    let out = c.dealer("namespace.export-pw.bin", &fp, &["--password-env", PASSWORD_ENV, SWAP]);
    ok(&out);

    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(c.out().join("dealer-record.json")).unwrap()).unwrap();
    assert_eq!(record["canton_fingerprint"], fp.as_str());
    assert_eq!(record["key_id"], KEY);
    assert_eq!(record["roster"], serde_json::json!([1, 2, 3]));
    assert_eq!(record["dealer_binary_sha256"].as_str().unwrap().len(), 64);

    let mut shares = Vec::new();
    for node in 1..=3u16 {
        let b = c.bundle(node);
        assert_eq!(b.pkp_digest, record["pkp_digest"].as_str().unwrap());
        assert_eq!(b.canton_fingerprint, fp);
        shares.push(b.open(&c.state(node)).unwrap());
        // Each bundle opens on its own node only.
        let other = if node == 1 { 2 } else { 1 };
        assert!(b.open(&c.state(other)).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = c.out().join(format!("share-{KEY}-node{node}.json"));
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    // Two shares reconstruct the Canton key: the split is of the right key.
    let kps: Vec<_> = shares[..2]
        .iter()
        .map(|s| frost_ed25519::keys::KeyPackage::try_from(s.clone()).unwrap())
        .collect();
    let key = frost_ed25519::keys::reconstruct(&kps).unwrap();
    let group = frost_ed25519::VerifyingKey::from(&key).serialize().unwrap();
    assert_eq!(share_delivery::ed25519_fingerprint(&group.try_into().unwrap()), fp);

    // Nothing secret on stdout/stderr.
    let seed = seed_hex("namespace.export-pw.bin");
    for stream in [&out.stdout, &out.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains(&seed));
    }

    // Never overwrites: a second run refuses before reading the key.
    refused(&c.dealer("namespace.export-pw.bin", &fp, &["--password-env", PASSWORD_ENV, SWAP]), "exists");
}

#[test]
fn stored_rows_work_in_binary_and_as_psql_hex() {
    let fp = fingerprint_of("namespace");
    let c = Ceremony::new();
    ok(&c.dealer("namespace.stored.bin", &fp, &[SWAP]));

    let c = Ceremony::new();
    let hex_path = c.tmp.path().join("row.hex");
    let row = std::fs::read(vectors().join("namespace.stored.bin")).unwrap();
    std::fs::write(&hex_path, format!("\\x{}\n", hex::encode(row))).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rutli-dealer"))
        .arg("split-key")
        .arg("--in")
        .arg(&hex_path)
        .args(["--stored-hex", "--expect-fingerprint", &fp, "--key-id", KEY, "--threshold", "2", SWAP])
        .arg("--out-dir")
        .arg(c.out())
        .args(c.requests.iter().flat_map(|r| [std::ffi::OsStr::new("--recipient"), r.as_os_str()]))
        .output()
        .unwrap();
    ok(&out);
    c.bundle(3).open(&c.state(3)).unwrap();
}

#[test]
fn the_wrong_key_a_non_namespace_key_and_a_missing_password_are_refused() {
    let c = Ceremony::new();
    let ns = fingerprint_of("namespace");

    // The operator expects a different key than the file holds.
    let other = fingerprint_of("signing");
    refused(&c.dealer("namespace.export-pw.bin", &other, &["--password-env", PASSWORD_ENV, SWAP]), "not the expected");

    // A protocol signing key: refused without --any-usage, accepted with it.
    let signing = fingerprint_of("signing");
    refused(&c.dealer("signing.export.bin", &signing, &[SWAP]), "namespace");
    // Not Ed25519 at all.
    refused(&c.dealer("encryption.export.bin", &fingerprint_of("encryption"), &[SWAP, "--any-usage"]), "Ed25519");

    // Password-protected without a password, and a password env that is not set.
    refused(&c.dealer("namespace.export-pw.bin", &ns, &[SWAP]), "password");
    refused(&c.dealer("namespace.export-pw.bin", &ns, &["--password-env", "RUTLI_TEST_UNSET_VAR", SWAP]), "not set");

    // Malformed expectations and ids, before anything is read.
    refused(&c.dealer("namespace.export.bin", "1220abc", &[SWAP]), "fingerprint");
    assert!(!c.out().exists(), "no refusal may leave output behind");

    ok(&c.dealer("signing.export.bin", &signing, &[SWAP, "--any-usage"]));
}

#[test]
fn recipients_must_describe_one_ceremony_with_every_node_exactly_once() {
    let fp = fingerprint_of("namespace");

    // Only two of three.
    let mut c = Ceremony::new();
    c.requests.pop();
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "exactly one request per roster member");

    // The same node twice.
    let mut c = Ceremony::new();
    c.requests[2] = c.requests[1].clone();
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "same node");

    // A node from another ceremony.
    let c = Ceremony::new();
    let mut r: RecipientRequest = serde_json::from_slice(&std::fs::read(&c.requests[1]).unwrap()).unwrap();
    r.ceremony_id = "other-ceremony".into();
    std::fs::write(&c.requests[1], serde_json::to_vec(&r).unwrap()).unwrap();
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "disagree");

    // A node configured with a different threshold.
    let c = Ceremony::new();
    let mut r: RecipientRequest = serde_json::from_slice(&std::fs::read(&c.requests[0]).unwrap()).unwrap();
    r.threshold = 3;
    std::fs::write(&c.requests[0], serde_json::to_vec(&r).unwrap()).unwrap();
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "disagree");

    // --threshold / --key-id that the recipients did not ask for.
    let c = Ceremony::new();
    let out = Command::new(env!("CARGO_BIN_EXE_rutli-dealer"))
        .arg("split-key")
        .arg("--in")
        .arg(vectors().join("namespace.export.bin"))
        .args(["--expect-fingerprint", &fp, "--key-id", "frost-import-other", "--threshold", "2", SWAP])
        .arg("--out-dir")
        .arg(c.out())
        .args(c.requests.iter().flat_map(|r| [std::ffi::OsStr::new("--recipient"), r.as_os_str()]))
        .output()
        .unwrap();
    refused(&out, "key id");
    let out = Command::new(env!("CARGO_BIN_EXE_rutli-dealer"))
        .arg("split-key")
        .arg("--in")
        .arg(vectors().join("namespace.export.bin"))
        .args(["--expect-fingerprint", &fp, "--key-id", "frost-namespace", "--threshold", "2", SWAP])
        .arg("--out-dir")
        .arg(c.out())
        .args(c.requests.iter().flat_map(|r| [std::ffi::OsStr::new("--recipient"), r.as_os_str()]))
        .output()
        .unwrap();
    refused(&out, "frost-import-");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn without_a_swap_check_the_dealer_refuses_unless_told() {
    let c = Ceremony::new();
    refused(&c.dealer("namespace.export.bin", &fingerprint_of("namespace"), &[]), "swap");
}

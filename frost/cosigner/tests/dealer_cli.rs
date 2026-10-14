// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The `rutli-dealer` binary end to end, on B1's real Canton 3.6.1 key vectors: what it writes,
//! that every bundle opens on its node only, and every refusal the runbook relies on — including
//! requests that were not minted by the node they name (review HIGH-1), and B6's usage rules
//! (`--expect-usage`, `--namespace-fingerprint`, protocol key ids).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::Digest;

use rutli_cosigner::request_auth::{self, NodeSigner};
use rutli_cosigner::seal::Sealer;
use rutli_cosigner::share_delivery::{
    self, RecipientRequest, ShareBundle, RECIPIENT_KIND, RECIPIENT_VERSION,
};

#[path = "common/pki.rs"]
mod pki;
use pki::TestPki;

const KEY: &str = "frost-import-1220cb0e";
const CEREMONY: &str = "b2-test";
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
    /// The key id every request was made for.
    key: String,
    pki: TestPki,
    signers: Vec<NodeSigner>,
    requests: Vec<PathBuf>,
    /// The SAS each node printed in its pod (what the witnesses read), in identifier order.
    sas: Vec<String>,
}

impl Ceremony {
    /// Three nodes of one TLS cluster run share-recipient (via the library) and drop their signed
    /// requests in `requests/`.
    fn new() -> Self {
        Self::for_key(KEY)
    }

    /// As [`Ceremony::new`], for another import id.
    fn for_key(key: &str) -> Self {
        let pki = TestPki::new();
        let signers: Vec<NodeSigner> = (1..=3u16).map(|i| pki.signer(&format!("cosigner{i}"))).collect();
        let (ca_pem, cluster) = (pki.ca_pem.clone(), pki.cluster_id());
        Self::build(pki, signers, &ca_pem, &cluster, key)
    }

    /// Mid CA rotation (docs/ca-rotation.md): the cosigners are pinned to the old CA's derived
    /// cluster id, their CA file is the bundle old+new, node 1 still has its old-CA leaf and nodes 2
    /// and 3 already have new-CA leaves. `pki` is the new CA.
    fn rotated() -> Self {
        let old = TestPki::new();
        let new = TestPki::new();
        let signers = vec![old.signer("cosigner1"), new.signer("cosigner2"), new.signer("cosigner3")];
        let bundle = pki::bundle(&[&old, &new]);
        Self::build(new, signers, &bundle, &old.cluster_id(), KEY)
    }

    fn build(pki: TestPki, signers: Vec<NodeSigner>, ca_pem: &str, cluster: &str, key: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("requests")).unwrap();
        std::fs::write(tmp.path().join("ca.crt"), ca_pem).unwrap();
        let mut requests = Vec::new();
        let mut sas = Vec::new();
        for id in 1..=3u16 {
            let r = share_delivery::create_recipient(
                &tmp.path().join(format!("node{id}")),
                &sealer(id),
                &signers[usize::from(id) - 1],
                template(id, cluster, key),
                false,
            )
            .unwrap();
            sas.push(request_auth::sas(&r));
            let path = tmp.path().join("requests").join(format!("r{id}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&r).unwrap()).unwrap();
            requests.push(path);
        }
        Self { tmp, key: key.to_string(), pki, signers, requests, sas }
    }

    fn out(&self) -> PathBuf {
        self.tmp.path().join("out")
    }

    fn read(&self, i: usize) -> RecipientRequest {
        serde_json::from_slice(&std::fs::read(&self.requests[i]).unwrap()).unwrap()
    }

    fn write(&self, i: usize, r: &RecipientRequest) {
        std::fs::write(&self.requests[i], serde_json::to_vec(r).unwrap()).unwrap();
    }

    /// The SAS of the request files as they are now (what a fooled witness would confirm).
    fn sas_of_files(&self) -> String {
        (0..self.requests.len()).map(|i| request_auth::sas(&self.read(i))).collect::<Vec<_>>().join(",")
    }

    /// `rutli-dealer split-key` with everything but the key input; `sas` is `--confirm-sas`
    /// (`None`: omit the flag).
    fn cmd(&self, input: &Path, fingerprint: &str, key_id: &str, sas: Option<&str>) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rutli-dealer"));
        cmd.arg("split-key")
            .arg("--in")
            .arg(input)
            .args(["--expect-fingerprint", fingerprint, "--key-id", key_id, "--threshold", "2"])
            .arg("--out-dir")
            .arg(self.out())
            .arg("--ca-cert")
            .arg(self.tmp.path().join("ca.crt"))
            // CI runners (and most dev Linux hosts) pipe core dumps to systemd-coredump; the
            // refusal is the runbook host's concern, not what these tests exercise.
            .arg("--allow-core-handler")
            .env(PASSWORD_ENV, password())
            .stdin(std::process::Stdio::null());
        for r in &self.requests {
            cmd.arg("--recipient").arg(r);
        }
        if let Some(sas) = sas {
            cmd.args(["--confirm-sas", sas]);
        }
        cmd
    }

    /// The dealer on a vector, with the SAS the witnesses read in the pods.
    fn dealer(&self, input: &str, fingerprint: &str, extra: &[&str]) -> std::process::Output {
        self.dealer_on(&vectors().join(input), fingerprint, extra)
    }

    /// The dealer on any key file, for this ceremony's key id.
    fn dealer_on(&self, input: &Path, fingerprint: &str, extra: &[&str]) -> std::process::Output {
        let sas = self.sas.join(",");
        self.cmd(input, fingerprint, &self.key, Some(&sas)).args(extra).output().unwrap()
    }

    fn bundle(&self, node: u16) -> ShareBundle {
        let path = self.out().join(format!("share-{}-node{node}.json", self.key));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn state(&self, node: u16) -> share_delivery::RecipientState {
        share_delivery::load_recipient(&self.tmp.path().join(format!("node{node}")), &sealer(node), &self.key)
            .unwrap()
    }

    fn record(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.out().join("dealer-record.json")).unwrap()).unwrap()
    }

    /// Two opened shares reconstruct the key with Canton fingerprint `fp`.
    fn assert_reconstructs(&self, fp: &str) {
        let kps: Vec<_> = [1u16, 2]
            .iter()
            .map(|&n| {
                frost_ed25519::keys::KeyPackage::try_from(self.bundle(n).open(&self.state(n)).unwrap()).unwrap()
            })
            .collect();
        let key = frost_ed25519::keys::reconstruct(&kps).unwrap();
        let group = frost_ed25519::VerifyingKey::from(&key).serialize().unwrap();
        assert_eq!(share_delivery::ed25519_fingerprint(&group.try_into().unwrap()), fp);
    }
}

fn template(identifier: u16, cluster: &str, key: &str) -> RecipientRequest {
    RecipientRequest {
        v: RECIPIENT_VERSION,
        kind: RECIPIENT_KIND.into(),
        ceremony_id: CEREMONY.into(),
        key_id: key.into(),
        cluster_id: cluster.into(),
        identifier,
        threshold: 2,
        max_signers: 3,
        roster: vec![1, 2, 3],
        recipient_pub: String::new(),
        signature_alg: String::new(),
        signer_chain: Vec::new(),
        signature: String::new(),
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
    assert_eq!(record["expected_usage"], "namespace");
    assert_eq!(record["recorded_usage"], serde_json::json!(["namespace"]));
    assert!(record["namespace_fingerprint"].is_null());
    assert_eq!(record["roster"], serde_json::json!([1, 2, 3]));
    assert_eq!(record["dealer_binary_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(record["recipients"][1]["sas"], c.sas[1].as_str());

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
    let sas = c.sas.join(",");
    ok(&c.cmd(&hex_path, &fp, KEY, Some(&sas)).args(["--stored-hex", SWAP]).output().unwrap());
    c.bundle(3).open(&c.state(3)).unwrap();
}

#[test]
fn the_wrong_key_a_non_namespace_key_and_a_missing_password_are_refused() {
    let c = Ceremony::new();
    let ns = fingerprint_of("namespace");

    // The operator expects a different key than the file holds.
    let other = fingerprint_of("signing");
    refused(&c.dealer("namespace.export-pw.bin", &other, &["--password-env", PASSWORD_ENV, SWAP]), "not the expected");

    // A protocol signing key is not a namespace key (B6: --expect-usage protocol, its own ids).
    let signing = fingerprint_of("signing");
    refused(&c.dealer("signing.export.bin", &signing, &[SWAP]), "does not include namespace");
    // Not Ed25519 at all.
    refused(&c.dealer("encryption.export.bin", &fingerprint_of("encryption"), &[SWAP]), "Ed25519");

    // Password-protected without a password, and a password env that is not set.
    refused(&c.dealer("namespace.export-pw.bin", &ns, &[SWAP]), "password");
    refused(&c.dealer("namespace.export-pw.bin", &ns, &["--password-env", "RUTLI_TEST_UNSET_VAR", SWAP]), "not set");

    // Malformed expectations and ids, before anything is read.
    refused(&c.dealer("namespace.export.bin", "1220abc", &[SWAP]), "fingerprint");
    assert!(!c.out().exists(), "no refusal may leave output behind");

    // The retired --any-usage is gone: an unknown flag, not a silent pass.
    refused(&c.dealer("signing.export.bin", &signing, &[SWAP, "--any-usage"]), "--any-usage");
    ok(&c.dealer("namespace.export.bin", &ns, &[SWAP]));
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

    // A node from another ceremony (genuinely signed by that node).
    let c = Ceremony::new();
    let mut r = c.read(1);
    r.ceremony_id = "other-ceremony".into();
    c.signers[1].sign(&mut r).unwrap();
    c.write(1, &r);
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "disagree");

    // A node configured with a different threshold.
    let c = Ceremony::new();
    let mut r = c.read(0);
    r.threshold = 3;
    c.signers[0].sign(&mut r).unwrap();
    c.write(0, &r);
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "disagree");

    // --threshold / --key-id that the recipients did not ask for.
    let c = Ceremony::new();
    let input = vectors().join("namespace.export.bin");
    let sas = c.sas.join(",");
    refused(&c.cmd(&input, &fp, "frost-import-other", Some(&sas)).arg(SWAP).output().unwrap(), "key id");
    refused(&c.cmd(&input, &fp, "frost-namespace", Some(&sas)).arg(SWAP).output().unwrap(), "frost-import-");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn without_a_swap_check_the_dealer_refuses_unless_told() {
    let c = Ceremony::new();
    refused(&c.dealer("namespace.export.bin", &fingerprint_of("namespace"), &[]), "swap");
}

/// Review HIGH-1 (PoC `poc_substituted_recipient_requests_leak_the_key`): whoever swaps `t` request
/// files between the pods and the dealer gets real shares sealed to their own keys. The dealer
/// must refuse a request whose recipient key was not minted by the node it names — even when the
/// witnesses were fooled into confirming the substituted requests' SAS.
#[test]
fn substituted_recipient_requests_are_refused() {
    use x25519_dalek::{PublicKey, StaticSecret};
    let fp = fingerprint_of("namespace");
    let input = vectors().join("namespace.export.bin");
    let attacker_pub = |seed: u8| hex::encode(PublicKey::from(&StaticSecret::from([seed; 32])).as_bytes());

    // 1. The PoC: recipient keys swapped in two files, signatures left as they were.
    let c = Ceremony::new();
    for (i, seed) in [(0usize, 9u8), (1, 10)] {
        let mut r = c.read(i);
        r.recipient_pub = attacker_pub(seed);
        c.write(i, &r);
    }
    let fooled = c.sas_of_files();
    let out = c.cmd(&input, &fp, KEY, Some(&fooled)).arg(SWAP).output().unwrap();
    assert!(!out.status.success(), "the dealer sealed real shares to substituted recipient keys");
    refused(&out, "bad request signature");
    assert!(!c.out().join(format!("share-{KEY}-node1.json")).exists());

    // 2. Re-signed by the attacker's own PKI (a cert that says cosigner1, from another CA).
    let c = Ceremony::new();
    let rogue = TestPki::new();
    let mut r = c.read(0);
    r.recipient_pub = attacker_pub(9);
    rogue.signer("cosigner1").sign(&mut r).unwrap();
    c.write(0, &r);
    let out = c.cmd(&input, &fp, KEY, Some(&c.sas_of_files())).arg(SWAP).output().unwrap();
    refused(&out, "not signed by the cluster CA");

    // 3. Re-signed with another real cosigner's key (node 2 compromised, impersonating node 1).
    let c = Ceremony::new();
    let mut r = c.read(0);
    r.recipient_pub = attacker_pub(9);
    c.signers[1].sign(&mut r).unwrap();
    c.write(0, &r);
    let out = c.cmd(&input, &fp, KEY, Some(&c.sas_of_files())).arg(SWAP).output().unwrap();
    refused(&out, "one CN \"cosigner1\"");

    // 4. Signed by a CA-issued certificate that is not a cosigner's (the driver's).
    let c = Ceremony::new();
    let mut r = c.read(0);
    r.recipient_pub = attacker_pub(9);
    c.pki.signer("driver").sign(&mut r).unwrap();
    c.write(0, &r);
    refused(&c.cmd(&input, &fp, KEY, Some(&c.sas_of_files())).arg(SWAP).output().unwrap(), "driver");

    // 5. Verified against the wrong CA file: the cluster id does not match either.
    let c = Ceremony::new();
    std::fs::write(c.tmp.path().join("ca.crt"), TestPki::new().ca_pem).unwrap();
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "cluster");
}

/// Review HIGH-1 (b): the SAS read in the pods must match, and must be confirmed at all.
#[test]
fn the_dealer_requires_the_sas_the_witnesses_read() {
    let fp = fingerprint_of("namespace");
    let input = vectors().join("namespace.export.bin");
    let c = Ceremony::new();
    let mut wrong = c.sas.clone();
    wrong[2] = "0000000000000000".into();
    refused(&c.cmd(&input, &fp, KEY, Some(&wrong.join(","))).arg(SWAP).output().unwrap(), "SAS mismatch for node 3");
    refused(&c.cmd(&input, &fp, KEY, Some(&c.sas[..2].join(","))).arg(SWAP).output().unwrap(), "one per node");
    // No --confirm-sas and no terminal to ask on.
    refused(&c.cmd(&input, &fp, KEY, None).arg(SWAP).output().unwrap(), "--confirm-sas");
    assert!(!c.out().exists());
    // Case and spacing are forgiven, content is not.
    let loose = c.sas.iter().map(|s| format!(" {} ", s.to_uppercase())).collect::<Vec<_>>().join(",");
    ok(&c.cmd(&input, &fp, KEY, Some(&loose)).arg(SWAP).output().unwrap());
}

/// CA rotation: the CA file is a two-CA bundle, so its derived id is not the cluster's; the dealer
/// needs `--cluster-id` (the cosigners' pin), and then accepts leaves from either CA.
#[test]
fn a_rotation_bundle_needs_the_pinned_cluster_id_and_then_accepts_leaves_of_either_ca() {
    let fp = fingerprint_of("namespace");
    let c = Ceremony::rotated();
    let pinned = c.read(0).cluster_id;

    // Without --cluster-id the dealer derives the id from the bundle's bytes: not the cluster's.
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP]), "cluster");
    assert!(!c.out().exists());
    // A malformed id is refused before anything is read.
    for bad in ["453BB4AEA2088BB5", "453bb4aea2088bb", "not-hex-at-all!!"] {
        refused(&c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", bad]), "--cluster-id");
    }
    // A well-formed id that is not the cosigners' pin.
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", "0000000000000000"]), "cluster");
    assert!(!c.out().exists());

    // The pin: old- and new-CA leaves both verify, and every bundle opens on its node.
    ok(&c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", &pinned]));
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(c.out().join("dealer-record.json")).unwrap()).unwrap();
    assert_eq!(record["cluster_id"], pinned.as_str());
    for node in 1..=3u16 {
        let b = c.bundle(node);
        assert_eq!(b.cluster_id, pinned);
        b.open(&c.state(node)).unwrap();
    }

    // A request certified by neither CA of the bundle is still refused under the pin.
    let c = Ceremony::rotated();
    let pinned = c.read(0).cluster_id;
    let mut r = c.read(1);
    TestPki::new().signer("cosigner2").sign(&mut r).unwrap();
    c.write(1, &r);
    let input = vectors().join("namespace.export.bin");
    let out = c
        .cmd(&input, &fp, KEY, Some(&c.sas_of_files()))
        .args([SWAP, "--cluster-id", &pinned])
        .output()
        .unwrap();
    refused(&out, "not certified by any");
}

/// Review M1 / L8: the dealer validates `--ca-cert` with the cosigners' rule before it reads any
/// request: only valid CA certificates. A cosigner leaf in the file (whose key holder could then
/// certify a request for any node), a private key pasted into it, or an expired CA is refused; the
/// anchors are printed and recorded, and a bundle of more than one CA is warned about.
#[test]
fn the_dealer_refuses_a_ca_file_that_is_not_only_valid_cas_and_records_the_anchors() {
    let fp = fingerprint_of("namespace");
    let ca_file = |c: &Ceremony, pem: &str| std::fs::write(c.tmp.path().join("ca.crt"), pem).unwrap();

    // Node 1's own leaf appended to the CA file: refused before any request is looked at.
    let c = Ceremony::new();
    let (leaf, key) = c.pki.leaf_pem("cosigner1", &rcgen::PKCS_ECDSA_P256_SHA256, false);
    ca_file(&c, &format!("{}{leaf}", c.pki.ca_pem));
    let cluster = c.read(0).cluster_id;
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", &cluster]), "not a CA");
    assert!(!c.out().exists());
    // A private key in it: refused, and never echoed.
    ca_file(&c, &format!("{}{key}", c.pki.ca_pem));
    let out = c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", &cluster]);
    refused(&out, "PRIVATE KEY");
    let body = key.lines().nth(1).unwrap();
    assert!(!String::from_utf8_lossy(&out.stderr).contains(body) && !String::from_utf8_lossy(&out.stdout).contains(body));
    // An expired CA next to the valid one.
    let expired = TestPki::with_ca(&rcgen::PKCS_ECDSA_P256_SHA256, |p| {
        p.not_before = rcgen::date_time_ymd(2001, 1, 1);
        p.not_after = rcgen::date_time_ymd(2002, 1, 1);
    });
    ca_file(&c, &pki::bundle(&[&expired, &c.pki]));
    refused(&c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", &cluster]), "expired");

    // A single CA: one anchor, printed and recorded, no warning.
    let c = Ceremony::new();
    let out = c.dealer("namespace.export.bin", &fp, &[SWAP]);
    ok(&out);
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let sha = hex::encode(sha2::Sha256::digest(
        rutli_cosigner::trust::load_trust_anchors(c.pki.ca_pem.as_bytes(), false).unwrap()[0].der.as_slice(),
    ));
    assert!(stdout.contains("trust anchor 0") && stdout.contains(&sha), "{stdout}");
    assert!(!stderr.contains("CA certificates"), "{stderr}");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(c.out().join("dealer-record.json")).unwrap()).unwrap();
    assert_eq!(record["ca_anchors"].as_array().unwrap().len(), 1);
    assert_eq!(record["ca_anchors"][0]["sha256"], sha.as_str());
    assert_eq!(record["ca_anchors"][0]["subject"], "CN=rutli-frost-cluster-ca");
    assert!(record["ca_anchors"][0]["not_after"].as_str().is_some());
    assert_eq!(
        record["ca_file_sha256"],
        hex::encode(sha2::Sha256::digest(c.pki.ca_pem.as_bytes())).as_str()
    );

    // A rotation bundle: accepted (with the pin), but warned about, and both anchors recorded.
    let c = Ceremony::rotated();
    let pinned = c.read(0).cluster_id;
    let out = c.dealer("namespace.export.bin", &fp, &[SWAP, "--cluster-id", &pinned]);
    ok(&out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("warning") && stderr.contains("2 CA certificates"), "{stderr}");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(c.out().join("dealer-record.json")).unwrap()).unwrap();
    assert_eq!(record["ca_anchors"].as_array().unwrap().len(), 2);
}

// ── B6: carrying protocol keys ─────────────────────────────────────────────────────────────────

/// `<marker><label><first 8 hex of the fingerprint>`, as the runbook names them.
fn import_id(label: &str, fp: &str) -> String {
    format!("frost-import-{label}{}", &fp[..8])
}

#[test]
fn protocol_keys_split_under_protocol_ids_and_the_record_says_what_they_are() {
    for (name, label, recorded) in [
        ("signing", "sig-", ["proof-of-ownership", "signing"]),
        ("sequencer-auth", "seqauth-", ["proof-of-ownership", "sequencer-auth"]),
    ] {
        let fp = fingerprint_of(name);
        let c = Ceremony::for_key(&import_id(label, &fp));
        let args = ["--password-env", PASSWORD_ENV, "--expect-usage", "protocol", SWAP];
        let out = c.dealer(&format!("{name}.export-pw.bin"), &fp, &args);
        ok(&out);
        assert!(String::from_utf8_lossy(&out.stdout).contains("carried for:   protocol"), "{name}");
        let record = c.record();
        assert_eq!(record["key_id"], c.key.as_str());
        assert_eq!(record["expected_usage"], "protocol");
        assert_eq!(record["recorded_usage"], serde_json::json!(recorded));
        // The bundles say so too, under the envelope's AAD; the node records it at install.
        let usage = c.bundle(1).usage.expect("a B6 bundle carries its usage");
        assert_eq!((usage.expected.as_str(), usage.recorded), ("protocol", Some(recorded.map(String::from).to_vec())));
        c.assert_reconstructs(&fp);
    }
}

#[test]
fn every_usage_and_id_mismatch_is_refused() {
    let (ns, sig, seq) = (fingerprint_of("namespace"), fingerprint_of("signing"), fingerprint_of("sequencer-auth"));
    let protocol = ["--expect-usage", "protocol", SWAP];

    // A namespace key carried as a protocol key, under a protocol id.
    let c = Ceremony::for_key(&import_id("sig-", &ns));
    refused(&c.dealer("namespace.export.bin", &ns, &protocol), "neither signing (protocol) nor sequencer-auth");
    // Namespace mode refuses a protocol id before reading any key (no password is asked for).
    refused(&c.dealer("namespace.export-pw.bin", &ns, &[SWAP]), "protocol key id");
    // A protocol key under a namespace-style id: refused before reading the key, too.
    let c = Ceremony::for_key(&import_id("", &sig));
    refused(&c.dealer("signing.export-pw.bin", &sig, &protocol), "namespace-style id");
    // ... and as a namespace key.
    refused(&c.dealer("signing.export.bin", &sig, &[SWAP]), "does not include namespace");
    // The protocol signing key under the sequencer-auth label, and the other way round.
    let c = Ceremony::for_key(&import_id("seqauth-", &sig));
    refused(&c.dealer("signing.export.bin", &sig, &protocol), "names a sequencer-authentication key");
    let c = Ceremony::for_key(&import_id("sig-", &seq));
    refused(&c.dealer("sequencer-auth.export.bin", &seq, &protocol), "names a protocol signing key");
    // A label with no name after it, and an unknown mode.
    let c = Ceremony::for_key("frost-import-sig-");
    refused(&c.dealer("signing.export.bin", &sig, &protocol), "not an import id");
    let c = Ceremony::for_key(&import_id("sig-", &sig));
    refused(&c.dealer("signing.export.bin", &sig, &["--expect-usage", "root", SWAP]), "root");
    // The right key, but the operator's namespace says it is the root: never under a protocol id.
    let with_ns = |ns: &str| ["--expect-usage", "protocol", "--namespace-fingerprint", ns, SWAP].map(String::from);
    let run = |args: [String; 5]| c.dealer("signing.export.bin", &sig, &args.each_ref().map(String::as_str));
    refused(&run(with_ns(&sig)), "IS the namespace");
    refused(&run(with_ns("1220ab")), "not a 1220");
    assert!(!c.out().exists(), "no refusal may leave output behind");
    // And the same ceremony, done right.
    ok(&run(with_ns(&ns)));
    assert_eq!(c.record()["namespace_fingerprint"], ns.as_str());
}

/// `common_crypto_private_keys.data` of a vector's Ed25519 key with the given usage list (protobuf
/// enum values), for keys Canton 3.6.1 does not generate by default: Splice's `All`, a legacy
/// empty list.
fn stored_with_usage(name: &str, usage: &[u8]) -> Vec<u8> {
    fn len(field: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 1 << 14);
        let n = data.len();
        let varint = if n < 128 { vec![n as u8] } else { vec![(n & 0x7f) as u8 | 0x80, (n >> 7) as u8] };
        [&[field << 3 | 2][..], &varint, data].concat()
    }
    let fp = fingerprint_of(name);
    let seed = hex::decode(seed_hex(&format!("{name}.export.bin"))).unwrap();
    // RFC 8410 PKCS#8 for Ed25519 (CryptoKeyFormat 5).
    let pkcs8 = [hex::decode("302e020100300506032b657004220420").unwrap(), seed].concat();
    let mut msg = [len(1, fp.as_bytes()), vec![2 << 3, 5], len(3, &pkcs8)].concat();
    if !usage.is_empty() {
        msg.extend(len(5, usage));
    }
    msg.extend([6 << 3, 1]); // key_spec EC-Curve25519
    [len(1, &msg), vec![2 << 3, 30]].concat() // UntypedVersionedMessage, version 30
}

#[test]
fn an_all_usage_key_is_only_carried_with_the_namespace_the_operator_read() {
    let (ns, sig) = (fingerprint_of("namespace"), fingerprint_of("signing"));
    let tmp = tempfile::tempdir().unwrap();
    let file = |name: &str, usage: &[u8]| {
        let path = tmp.path().join(format!("{name}-{}.stored.bin", usage.len()));
        std::fs::write(&path, stored_with_usage(name, usage)).unwrap();
        path
    };
    let all: &[u8] = &[1, 3, 4, 5];
    let all_names = ["namespace", "proof-of-ownership", "sequencer-auth", "signing"];

    // Splice's `signing` key: usage All, namespace included, but not the namespace key.
    let splice_signing = file("signing", all);
    let c = Ceremony::for_key(&import_id("", &sig));
    refused(&c.dealer_on(&splice_signing, &sig, &[SWAP]), "--namespace-fingerprint");
    refused(&c.dealer_on(&splice_signing, &sig, &["--namespace-fingerprint", &ns, SWAP]), "is not the namespace");
    let c = Ceremony::for_key(&import_id("sig-", &sig));
    refused(&c.dealer_on(&splice_signing, &sig, &["--expect-usage", "protocol", SWAP]), "namespace included");
    let protocol_ns = |ns: &str| ["--expect-usage", "protocol", "--namespace-fingerprint", ns, SWAP].map(String::from);
    let run = |args: [String; 5]| c.dealer_on(&splice_signing, &sig, &args.each_ref().map(String::as_str));
    refused(&run(protocol_ns(&sig)), "IS the namespace");
    assert!(!c.out().exists());
    // Carried as what it is used for, its namespace confirmed to be another key.
    ok(&run(protocol_ns(&ns)));
    let record = c.record();
    assert_eq!(record["recorded_usage"], serde_json::json!(all_names));
    assert_eq!(record["namespace_fingerprint"], ns.as_str());
    c.assert_reconstructs(&sig);

    // A root key that signs everything (a hand-initialised node), and a legacy key with no usage
    // list (Canton reads it as All): namespace mode needs the namespace to be this very key.
    for usage in [all, &[][..]] {
        let root = file("namespace", usage);
        let c = Ceremony::new();
        refused(&c.dealer_on(&root, &ns, &[SWAP]), "--namespace-fingerprint");
        ok(&c.dealer_on(&root, &ns, &["--namespace-fingerprint", &ns, SWAP]));
        let expected: &[&str] = if usage.is_empty() { &[] } else { &all_names };
        assert_eq!(c.record()["recorded_usage"], serde_json::json!(expected));
    }

    // Plain PKCS#8 has no Canton usage: namespace mode only with the namespace confirmed, never
    // protocol mode.
    let pkcs8 = tmp.path().join("namespace.pk8");
    let seed = hex::decode(seed_hex("namespace.export.bin")).unwrap();
    std::fs::write(&pkcs8, [hex::decode("302e020100300506032b657004220420").unwrap(), seed].concat()).unwrap();
    let c = Ceremony::new();
    refused(&c.dealer_on(&pkcs8, &ns, &[SWAP]), "--namespace-fingerprint");
    ok(&c.dealer_on(&pkcs8, &ns, &["--namespace-fingerprint", &ns, SWAP]));
    assert!(c.record()["recorded_usage"].is_null());
    let c = Ceremony::for_key(&import_id("sig-", &ns));
    refused(&c.dealer_on(&pkcs8, &ns, &["--expect-usage", "protocol", SWAP]), "PKCS#8");
}

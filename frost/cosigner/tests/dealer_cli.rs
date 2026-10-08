// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The `rutli-dealer` binary end to end, on B1's real Canton 3.6.1 key vectors: what it writes,
//! that every bundle opens on its node only, and every refusal the runbook relies on — including
//! requests that were not minted by the node they name (review HIGH-1).

use std::path::{Path, PathBuf};
use std::process::Command;

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
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("requests")).unwrap();
        let pki = TestPki::new();
        std::fs::write(tmp.path().join("ca.crt"), &pki.ca_pem).unwrap();
        let signers: Vec<NodeSigner> = (1..=3u16).map(|i| pki.signer(&format!("cosigner{i}"))).collect();
        let mut requests = Vec::new();
        let mut sas = Vec::new();
        for id in 1..=3u16 {
            let r = share_delivery::create_recipient(
                &tmp.path().join(format!("node{id}")),
                &sealer(id),
                &signers[usize::from(id) - 1],
                template(id, &pki.cluster_id()),
                false,
            )
            .unwrap();
            sas.push(request_auth::sas(&r));
            let path = tmp.path().join("requests").join(format!("r{id}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&r).unwrap()).unwrap();
            requests.push(path);
        }
        Self { tmp, pki, signers, requests, sas }
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
        let sas = self.sas.join(",");
        self.cmd(&vectors().join(input), fingerprint, KEY, Some(&sas)).args(extra).output().unwrap()
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

fn template(identifier: u16, cluster: &str) -> RecipientRequest {
    RecipientRequest {
        v: RECIPIENT_VERSION,
        kind: RECIPIENT_KIND.into(),
        ceremony_id: CEREMONY.into(),
        key_id: KEY.into(),
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
    refused(&out, "expected \"cosigner1\"");

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

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `verify-key` must say *why* a node is unreachable. The CA rotation's Phase D negative control
//! (docs/ca-rotation.md, review L2) greps its output for the TLS alert (`UnknownCA`) to tell a
//! refused old-CA certificate from a config error; a bare "transport error" made that impossible.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    fn new(cn: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name.push(DnType::CommonName, cn);
        Self { cert: p.self_signed(&key).unwrap(), key }
    }

    /// Writes `<name>.crt` / `<name>.key` under `dir` for a leaf with CN `cn`.
    fn leaf(&self, dir: &std::path::Path, name: &str, cn: &str) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["rutli-cosigner".to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        std::fs::write(dir.join(format!("{name}.crt")), cert.pem()).unwrap();
        std::fs::write(dir.join(format!("{name}.key")), key.serialize_pem()).unwrap();
    }
}

fn config(dir: &std::path::Path, port: u16, data: &str, trust: &str, leaf: &str) -> std::path::PathBuf {
    let cfg = serde_json::json!({
        "identifier": 1, "listen": format!("127.0.0.1:{port}"), "threshold": 1,
        "data_dir": dir.join(data),
        "peers": [{ "identifier": 1, "endpoint": format!("https://127.0.0.1:{port}") }],
        "tls": {
            "ca_cert": dir.join(trust), "cert": dir.join(format!("{leaf}.crt")),
            "key": dir.join(format!("{leaf}.key")), "domain": "rutli-cosigner"
        },
        "signer_allowlist": ["driver"], "peer_allowlist": ["cosigner1"],
        "operator_allowlist": ["operator"]
    });
    let path = dir.join(format!("{data}.json"));
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    path
}

#[test]
fn verify_key_reports_the_tls_alert_when_a_node_refuses_an_old_ca_certificate() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let (old, new) = (Ca::new("old-ca"), Ca::new("new-ca"));
    std::fs::write(dir.join("new.crt"), new.cert.pem()).unwrap();
    std::fs::write(dir.join("bundle.crt"), format!("{}{}", old.cert.pem(), new.cert.pem())).unwrap();
    new.leaf(dir, "cosigner1", "cosigner1");
    old.leaf(dir, "old-operator", "operator");
    new.leaf(dir, "new-operator", "operator");

    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    // Phase D: the node trusts only the new CA.
    let mut node = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .arg("--config")
        .arg(config(dir, port, "server", "new.crt", "cosigner1"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = node.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(|l| l.ok()) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    while !rx.recv_timeout(Duration::from_millis(200)).is_ok_and(|l| l.contains("gRPC serving")) {
        assert!(Instant::now() < deadline && node.try_wait().unwrap().is_none(), "the node did not start");
    }

    let verify = |client: &std::path::Path| {
        let out = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
            .arg("--config")
            .arg(client)
            .args(["verify-key", "--key-id", "frost-namespace", "--expect-fingerprint"])
            .arg(format!("1220{}", "0".repeat(64)))
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    // The old-CA operator leaf, trusting the bundle (so the client side accepts the server).
    let (ok, refused) = verify(&config(dir, port, "client-old", "bundle.crt", "old-operator"));
    // The new-CA operator leaf gets through TLS (the key is simply absent).
    let (_, through) = verify(&config(dir, port, "client-new", "bundle.crt", "new-operator"));
    let _ = node.kill();
    let _ = node.wait();

    assert!(!ok);
    let line = refused.lines().find(|l| l.starts_with("  node 1 ")).unwrap_or_default();
    assert!(line.contains("UnknownCA"), "the TLS alert must be in the output: {refused}");
    assert!(through.contains("unknown key id") && !through.contains("UnknownCA"), "{through}");
}

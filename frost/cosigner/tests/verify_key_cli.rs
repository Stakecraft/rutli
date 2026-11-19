// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `verify-key` must say *why* a node is unreachable. The CA rotation's Phase D negative control
//! (docs/ca-rotation.md, review L2) greps its output for the TLS alert (`UnknownCA`) to tell a
//! refused old-CA certificate from a config error; a bare "transport error" made that impossible.
//!
//! `key show` and `key fingerprint` (docs/admin-cli.md), through the real binary: an operator
//! certificate reads a FROST key and a hosted key off a cluster of three real daemons, and the
//! offline fingerprint of what `key show` printed is the fingerprint `key show` reported.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::Receiver;
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

    /// Writes `<name>.crt` / `<name>.key` under `dir` for a leaf with CN `cn` and that same name as
    /// its SAN — a node is dialled under its own name (`cosigner<id>`, audit M3), never a shared one.
    fn leaf(&self, dir: &std::path::Path, name: &str, cn: &str) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
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

/// A running `rutli-cosigner --config <config>` daemon, killed when the test ends (on a failed
/// assertion too, so no daemon outlives its test).
struct Daemon {
    child: std::process::Child,
    lines: Receiver<String>,
}

impl Daemon {
    fn spawn(config: &Path, env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .envs(env.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(|l| l.ok()) {
                let _ = tx.send(line);
            }
        });
        Self { child, lines }
    }

    fn wait_serving(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.lines.recv_timeout(Duration::from_millis(200)).is_ok_and(|l| l.contains("gRPC serving")) {
            assert!(Instant::now() < deadline && self.child.try_wait().unwrap().is_none(), "the node did not start");
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    let mut node = Daemon::spawn(&config(dir, port, "server", "new.crt", "cosigner1"), &[]);
    node.wait_serving();

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
    let node_line = |out: &str| out.lines().find(|l| l.starts_with("  node 1 ")).unwrap_or_default().to_string();
    // The old-CA operator leaf, trusting the bundle (so the client side accepts the server). In
    // TLS 1.3 the node's alert races the client's first request, and the RPC error alone said
    // "connection closed" / "broken pipe" in about half the runs; the TLS probe must make the alert
    // show every time, so ask several times.
    let old = config(dir, port, "client-old", "bundle.crt", "old-operator");
    for _ in 0..5 {
        let (ok, refused) = verify(&old);
        assert!(!ok);
        let line = node_line(&refused);
        eprintln!("refused: {line}");
        assert!(line.contains("UnknownCA"), "the TLS alert must be in the output: {refused}");
    }
    // The new-CA operator leaf gets through TLS (the key is simply absent): no probe detail.
    let (_, through) = verify(&config(dir, port, "client-new", "bundle.crt", "new-operator"));
    drop(node);
    assert!(through.contains("unknown key id") && !through.contains("UnknownCA"), "{through}");
    assert!(!through.contains("TLS probe"), "{through}");

    // A node that is down is reported as unreachable, with no TLS detail made up for it.
    let (ok, down) = verify(&old);
    let line = node_line(&down);
    eprintln!("down: {line}");
    assert!(!ok);
    assert!(line.contains("unreachable") && !line.contains("TLS probe") && !line.contains("UnknownCA"), "{down}");
}

// ── key show / key fingerprint ─────────────────────────────────────────────────────────────────

/// The legacy shared seal master of the test daemons (hosted keys need sealing).
const SEAL_ENV: &str = "RUTLI_TEST_SEAL";
const SEAL: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A config on the 2-of-3 roster at `ports` for node `identifier`, listening on `listen` and
/// presenting `<leaf>.crt`, with `extra` merged in.
fn roster_config(dir: &Path, name: &str, identifier: u16, listen: u16, ports: &[u16], leaf: &str, extra: serde_json::Value) -> PathBuf {
    let peers: Vec<_> = (1u16..)
        .zip(ports)
        .map(|(i, p)| serde_json::json!({ "identifier": i, "endpoint": format!("https://127.0.0.1:{p}") }))
        .collect();
    let mut cfg = serde_json::json!({
        "identifier": identifier, "listen": format!("127.0.0.1:{listen}"), "threshold": 2,
        "data_dir": dir.join(name), "peers": peers,
        "tls": { "ca_cert": dir.join("ca.crt"), "cert": dir.join(format!("{leaf}.crt")), "key": dir.join(format!("{leaf}.key")) },
        "signer_allowlist": ["driver"], "peer_allowlist": ["cosigner1", "cosigner2", "cosigner3"],
        "operator_allowlist": ["operator"]
    });
    cfg.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    path
}

/// Run the CLI to its end: (exit 0, stdout, stderr). A command that fell through the dispatch and
/// started serving would never exit, so it gets 30 s and then fails the test.
fn cli(config: Option<&Path>, args: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"));
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }
    let mut child = cmd
        .args(args)
        .env_remove("RUTLI_COSIGNER_CONFIG")
        // Logs go to stdout too; a report on stdout is read whole below.
        .env("RUST_LOG", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("{args:?} did not exit (serving?): {}", String::from_utf8_lossy(&out.stdout));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.success(), text(&out.stdout), text(&out.stderr))
}

/// The value after `prefix` on the first stdout line that starts with it.
fn field(out: &str, prefix: &str) -> String {
    out.lines().find_map(|l| l.strip_prefix(prefix)).unwrap_or_else(|| panic!("no {prefix:?} in {out}")).to_string()
}

/// Three real daemons over mTLS hold a DKG key and a hosted EC P-256 key, both made over gRPC with
/// the driver certificate. With the operator certificate (operator_allowlist only), `key show`
/// routes each id to its kind and prints the Canton fingerprint computed here from what the DKG and
/// the generation returned; `--json` is one JSON report with no expectation in it; the right
/// `--expect-fingerprint` passes and a wrong one fails; an absent id of either kind fails and the
/// process exits (no fall-through to serving). `key fingerprint`, with no config, gives the same
/// fingerprint for the group key and the SPKI `key show` printed.
#[test]
fn key_show_reads_both_kinds_with_an_operator_certificate_and_key_fingerprint_agrees_offline() {
    use rutli_cosigner::pb;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let ca = Ca::new("rutli test CA");
    std::fs::write(dir.join("ca.crt"), ca.cert.pem()).unwrap();
    for name in ["cosigner1", "cosigner2", "cosigner3", "driver", "operator"] {
        ca.leaf(dir, name, name);
    }
    let listeners: Vec<_> = (0..4).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let ports: Vec<u16> = listeners.iter().map(|l| l.local_addr().unwrap().port()).collect();
    drop(listeners);
    let (nodes, operator_port) = (&ports[..3], ports[3]);
    let daemon_extra = serde_json::json!({
        "share_seal": { "secret_env": SEAL_ENV }, "hosted_keys": { "enabled": true },
        // DKG without a ceremony intent: the roles are under test here, not the intents.
        "signing_policy": { "require_ceremony_intent": false }
    });
    let mut daemons: Vec<Daemon> = (1u16..=3)
        .map(|i| {
            let name = format!("cosigner{i}");
            let config = roster_config(dir, &name, i, nodes[usize::from(i) - 1], nodes, &name, daemon_extra.clone());
            Daemon::spawn(&config, &[(SEAL_ENV, SEAL)])
        })
        .collect();
    daemons.iter_mut().for_each(Daemon::wait_serving);
    // The operator's own `listen` is free: a `key show` that fell through to the daemon would serve
    // there and never exit, rather than fail on a taken port.
    let op = roster_config(dir, "operator", 1, operator_port, nodes, "operator", serde_json::json!({}));

    let (frost_id, hosted_id) = ("frost-participant1-namespace", "rutli-enc-ecies-1");
    let (group_key, spki) = tokio::runtime::Runtime::new().unwrap().block_on(async {
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap();
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(read("ca.crt")))
            .domain_name("cosigner1")
            .identity(Identity::from_pem(read("driver.crt"), read("driver.key")));
        let channel = Endpoint::from_shared(format!("https://127.0.0.1:{}", nodes[0])).unwrap();
        let mut driver = pb::signer_client::SignerClient::new(channel.tls_config(tls).unwrap().connect().await.unwrap());
        let dkg = pb::DkgRequest { key_id: frost_id.into(), ..Default::default() };
        let group_key = driver.dkg(dkg).await.unwrap().into_inner().group_verifying_key;
        let request = pb::GenerateKeyRequest { key_id: hosted_id.into(), spec: "ec-p256-ecies".into() };
        let generated = driver.generate_key(request).await.unwrap().into_inner();
        assert_eq!(generated.replicas, 3, "`key show` reads each node's own copy: it must be on all three");
        (group_key, generated.public_key_der)
    });
    let frost_fp = rutli_cosigner::share_delivery::ed25519_fingerprint(&group_key.clone().try_into().unwrap());
    let hosted_fp = rutli_canton_key::PublicKey::from_spki_der(&spki).unwrap().fingerprint();
    let wrong = format!("1220{}", "ab".repeat(32));

    for (id, kind, fp, printed) in [
        (frost_id, "frost", &frost_fp, ("  group key ", hex::encode(&group_key))),
        (hosted_id, "hosted", &hosted_fp, ("  public key (SPKI) ", hex::encode(&spki))),
    ] {
        let (ok, out, err) = cli(Some(&op), &["key", "show", "--key-id", id]);
        assert!(ok, "{out}{err}");
        assert!(out.starts_with(&format!("key show {id} (")) && out.contains("compared with nothing"), "{out}");
        assert_eq!((field(&out, "  fingerprint "), field(&out, printed.0)), (fp.clone(), printed.1.clone()));
        assert!(!out.contains("PROBLEM"), "{out}");

        let (ok, out, err) = cli(Some(&op), &["key", "show", "--key-id", id, "--json"]);
        assert!(ok, "{out}{err}");
        let report: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        assert_eq!((report["kind"].as_str(), report["fingerprint"].as_str()), (Some(kind), Some(fp.as_str())));
        assert_eq!((report["ok"].as_bool(), report["key_id"].as_str()), (Some(true), Some(id)));
        assert!(report.get("expected_fingerprint").is_none(), "{out}");

        let (ok, out, err) = cli(Some(&op), &["key", "show", "--key-id", id, "--expect-fingerprint", fp]);
        assert!(ok && out.contains(&format!("expected {fp}")), "{out}{err}");
        let (ok, out, err) = cli(Some(&op), &["key", "show", "--key-id", id, "--expect-fingerprint", &wrong]);
        assert!(!ok && out.contains("not the expected") && err.contains("key show: 3 problem(s)"), "{out}{err}");

        // Offline, from what `key show` printed: the same fingerprint, alone on stdout.
        let file = dir.join(format!("{kind}.pub"));
        std::fs::write(&file, format!("{}\n", printed.1)).unwrap();
        let (ok, out, err) = cli(None, &["key", "fingerprint", "--in", file.to_str().unwrap()]);
        assert!(ok, "{err}");
        assert_eq!(out, format!("{fp}\n"), "{err}");
        assert!(err.contains("read as"), "{err}");
    }

    // Absent ids of either kind: refused, and the process returns rather than serving.
    for (id, why) in [("frost-participant1-absent", "NotFound"), ("rutli-enc-absent", "does not hold the key")] {
        let started = Instant::now();
        let (ok, out, err) = cli(Some(&op), &["key", "show", "--key-id", id]);
        assert!(!ok && out.contains(why) && err.contains("key show: 3 problem(s)"), "{out}{err}");
        assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    }
}

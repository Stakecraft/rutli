// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Review M2, through the real `rutli-cosigner` binary: a `helm upgrade` without `--reuse-values`
//! drops the `cluster_id` pin, and after a CA rotation the id derived from the trust bundle is a
//! different one. The node must refuse to start under it rather than silently leave its cluster.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

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
}

struct Node {
    dir: tempfile::TempDir,
}

impl Node {
    /// One cosigner of a 1-node cluster, its leaf from `issuer`.
    fn new(issuer: &Ca) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec!["rutli-cosigner".to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, "cosigner1");
        let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
        std::fs::write(dir.path().join("cosigner1.crt"), cert.pem()).unwrap();
        std::fs::write(dir.path().join("cosigner1.key"), key.serialize_pem()).unwrap();
        Self { dir }
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn set_trust(&self, cas: &[&Ca]) -> String {
        let pem: String = cas.iter().map(|c| c.cert.pem()).collect();
        std::fs::write(self.dir.path().join("ca.crt"), &pem).unwrap();
        rutli_cosigner::wrap::cluster_id_from_ca(pem.as_bytes())
    }

    /// Write the config (`pin`: the `cluster_id` value, `None` = dropped) and return its path.
    fn config(&self, pin: Option<&str>, change_allowed: bool) -> PathBuf {
        let d = self.dir.path();
        let mut cfg = serde_json::json!({
            "identifier": 1, "listen": "127.0.0.1:0", "threshold": 1,
            "data_dir": self.data_dir(),
            "peers": [{ "identifier": 1, "endpoint": "https://127.0.0.1:1" }],
            "tls": {
                "ca_cert": d.join("ca.crt"), "cert": d.join("cosigner1.crt"),
                "key": d.join("cosigner1.key"), "domain": "rutli-cosigner"
            },
            "signer_allowlist": ["driver"], "peer_allowlist": ["cosigner1"]
        });
        if let Some(pin) = pin {
            cfg["cluster_id"] = pin.into();
        }
        if change_allowed {
            cfg["cluster_id_change_allowed"] = true.into();
        }
        let path = d.join("cosigner.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        path
    }

    fn recorded(&self) -> Option<String> {
        std::fs::read_to_string(self.data_dir().join("cluster-id")).ok().map(|s| s.trim().to_string())
    }
}

/// Start `rutli-cosigner serve`; every output line (stdout and stderr) arrives on the receiver.
fn serve(config: &Path) -> (Child, Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .arg("--config")
        .arg(config)
        .arg("serve")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = channel();
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(|l| l.ok()) {
                let _ = tx.send(line);
            }
        });
    }
    (child, rx)
}

/// Lines until one contains `needle`, or the process exits / 30 s pass (then the lines so far).
fn wait_for(child: &mut Child, rx: &Receiver<String>, needle: &str) -> (bool, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                let hit = line.contains(needle);
                seen.push(line);
                if hit {
                    return (true, seen);
                }
            }
            Err(_) => {
                if child.try_wait().unwrap().is_some() {
                    // Drain what is left.
                    while let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
                        let hit = line.contains(needle);
                        seen.push(line);
                        if hit {
                            return (true, seen);
                        }
                    }
                    return (false, seen);
                }
            }
        }
    }
    (false, seen)
}

/// Run until it serves (then stop it): the node started.
fn starts(config: &Path) -> Vec<String> {
    let (mut child, rx) = serve(config);
    let (served, lines) = wait_for(&mut child, &rx, "gRPC serving");
    let _ = child.kill();
    let _ = child.wait();
    assert!(served, "the node did not start:\n{}", lines.join("\n"));
    lines
}

/// Must exit non-zero, with `needle` in its output.
fn refuses(config: &Path, needle: &str) {
    let (mut child, rx) = serve(config);
    let (hit, lines) = wait_for(&mut child, &rx, needle);
    let status = child.wait_timeout_or_kill();
    assert!(hit && status.is_some_and(|s| !s.success()), "expected a refusal with {needle:?}:\n{}", lines.join("\n"));
}

trait WaitTimeout {
    fn wait_timeout_or_kill(&mut self) -> Option<std::process::ExitStatus>;
}

impl WaitTimeout for Child {
    fn wait_timeout_or_kill(&mut self) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(s) = self.try_wait().unwrap() {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.kill();
        let _ = self.wait();
        None
    }
}

#[test]
fn a_dropped_pin_after_a_ca_rotation_stops_the_node_instead_of_moving_it_to_another_cluster_id() {
    let old = Ca::new("rutli-frost-cluster-ca");
    let new = Ca::new("rutli-frost-cluster-ca-2026-10");
    let node = Node::new(&old);

    // An existing, unpinned install: its first start records the id it runs under.
    let derived = node.set_trust(&[&old]);
    let lines = starts(&node.config(None, false));
    assert!(lines.iter().any(|l| l.contains(&format!("cluster id {derived} (derived from tls.ca_cert)"))));
    assert_eq!(node.recorded().as_deref(), Some(derived.as_str()));

    // Phase 0: pinned to the derived value — nothing changes.
    let pin = derived;
    starts(&node.config(Some(&pin), false));
    // Phase A: the trust file becomes the bundle; the pin holds the id.
    let bundle_id = node.set_trust(&[&old, &new]);
    assert_ne!(bundle_id, pin);
    starts(&node.config(Some(&pin), false));
    assert_eq!(node.recorded().as_deref(), Some(pin.as_str()));

    // A later `helm upgrade` without --reuse-values drops clusterId: the node would derive the
    // bundle's id. It refuses, and the record is untouched.
    refuses(&node.config(None, false), "cluster id mismatch");
    assert_eq!(node.recorded().as_deref(), Some(pin.as_str()));
    // The ceremony commands refuse too, before they touch anything.
    let out = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"))
        .arg("--config")
        .arg(node.config(None, false))
        .args(["share-recipient", "--key-id", "frost-import-x", "--ceremony-id", "c", "--out"])
        .arg(node.dir.path().join("r1.json"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cluster id mismatch"), "{out:?}");

    // Putting the pin back is the fix.
    starts(&node.config(Some(&pin), false));

    // A deliberate change: allowed for one start, recorded, then enforced again.
    let lines = starts(&node.config(None, true));
    assert!(lines.iter().any(|l| l.contains("cluster id CHANGED")), "{}", lines.join("\n"));
    assert_eq!(node.recorded().as_deref(), Some(bundle_id.as_str()));
    starts(&node.config(None, false));
    refuses(&node.config(Some(&pin), false), "cluster id mismatch");
}

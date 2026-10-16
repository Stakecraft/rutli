// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! `rutli-cosigner audit-cross-check` (audit C2 / L1): the driver's audit log against the
//! cosigners' sign journals, through the real binary. The driver log is written here exactly as
//! `HashChainedAuditLog` writes it; the journals by the cosigner's own `SignJournal`.

use std::path::Path;
use std::process::Command;

use rutli_cosigner::journal::{JournalEntry, Limits, Retention, SignJournal, PURPOSE_NO_INTENT, PURPOSE_SIGN};
use sha2::{Digest, Sha256};

const T0: u64 = 1_792_159_730_000; // 2026-10-16T14:08:50Z
const UNLIMITED: Limits = Limits { per_min: 0, per_day: 0, max_shares_per_charge: u32::MAX };
const KEEP: Retention = Retention { days: 90, max_bytes: 64 << 20 };

/// A driver audit log of these (op, detail) entries, one second apart from T0.
fn driver_log(path: &Path, entries: &[(&str, String)]) {
    let mut prev = "0".repeat(64);
    let mut out = String::new();
    for (i, (op, detail)) in entries.iter().enumerate() {
        let seq = i as u64 + 1;
        let ts = rutli_cosigner::audit_check::fmt_ms(T0 + seq * 1000);
        let mut h = Sha256::new();
        for part in [prev.as_str(), &seq.to_string(), &ts, op, detail] {
            h.update(part.as_bytes());
        }
        let hash = hex::encode(h.finalize());
        out.push_str(&format!(
            "{{\"seq\":{seq},\"ts\":\"{ts}\",\"op\":\"{op}\",\"detail\":\"{detail}\",\"prev\":\"{prev}\",\"hash\":\"{hash}\"}}\n"
        ));
        prev = hash;
    }
    std::fs::write(path, out).unwrap();
}

fn sign_detail(key: &str, request: &str, ok: bool) -> String {
    format!(
        "keyId={key} algo=Ed25519 inBytes=34 intent={request} {}",
        if ok { "sigBytes=64 outcome=ok" } else { "outcome=failed error=boom" }
    )
}

/// A sign line as the driver writes it since `msg=`: the SHA-256 of the signed bytes.
fn sign_detail_msg(key: &str, request: &str, message_hex: &str) -> String {
    let msg = hex::encode(Sha256::digest(hex::decode(message_hex).unwrap()));
    format!("keyId={key} algo=Ed25519 inBytes=34 msg={msg} intent={request} sigBytes=64 outcome=ok")
}

fn journal(dir: &Path, node: u16, entries: &[(&str, &str, &str, u64)]) {
    journal_messages(dir, node, &entries.iter().map(|&(k, p, r, at)| (k, p, r, "12".repeat(34), at)).collect::<Vec<_>>());
}

fn journal_messages(dir: &Path, node: u16, entries: &[(&str, &str, &str, String, u64)]) {
    let j = SignJournal::open(dir, node, KEEP).unwrap();
    for (key, purpose, request, digest, at) in entries {
        let e = JournalEntry {
            key_id: key.to_string(),
            purpose: purpose.to_string(),
            request_id: request.to_string(),
            // Each intent names its own digest, so its hash (the charge) differs too.
            intent_sha256: hex::encode(Sha256::digest(format!("{request}/{digest}"))),
            digest: digest.clone(),
            session_id: format!("sign-{request}-{node}"),
            ..Default::default()
        };
        j.append_charged(e, UNLIMITED, *at).unwrap();
    }
}

fn run(audit: &Path, journals: &[&Path], extra: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rutli-cosigner"));
    cmd.arg("audit-cross-check").arg("--driver-audit").arg(audit);
    for j in journals {
        cmd.arg("--journal").arg(j);
    }
    cmd.args(extra);
    let out = cmd.output().unwrap();
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
}

#[test]
fn consistent_logs_pass_and_every_kind_of_discrepancy_is_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let (audit, j1, j2) = (tmp.path().join("audit.jsonl"), tmp.path().join("j1"), tmp.path().join("j2"));
    let (a, b, c) = ("a".repeat(32), "b".repeat(32), "c".repeat(32));

    // Two signs, each journaled by both participants; a failed attempt journaled on one node.
    driver_log(
        &audit,
        &[
            ("getPublicKey", "keyId=frost-ns spec=EcCurve25519 spkiBytes=44 outcome=ok".into()),
            ("sign", sign_detail("frost-ns", &a, true)),
            ("sign", sign_detail("frost-ns", &b, false)),
            ("sign", sign_detail("frost-ns", &c, true)),
        ],
    );
    journal(&j1, 1, &[("frost-ns", PURPOSE_SIGN, &a, T0 + 1500), ("frost-ns", PURPOSE_SIGN, &b, T0 + 2500), ("frost-ns", PURPOSE_SIGN, &c, T0 + 3500)]);
    journal(&j2, 2, &[("frost-ns", PURPOSE_SIGN, &a, T0 + 1500), ("frost-ns", PURPOSE_SIGN, &c, T0 + 3500)]);
    let (code, out) = run(&audit, &[&j1, &j2], &["--min-journals", "2"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("consistent"), "{out}");

    // The driver audit tail truncated: its last sign is gone, both journals still hold it.
    driver_log(
        &audit,
        &[
            ("getPublicKey", "keyId=frost-ns spec=EcCurve25519 spkiBytes=44 outcome=ok".into()),
            ("sign", sign_detail("frost-ns", &a, true)),
            ("sign", sign_detail("frost-ns", &b, false)),
        ],
    );
    let (code, out) = run(&audit, &[&j1, &j2], &[]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains(&format!("request {c} was signed (message")) && out.contains("not in the driver audit log"), "{out}");

    // A signature outside the driver (stolen certificate): journaled, never audited.
    let d = "d".repeat(32);
    journal(&j2, 2, &[("frost-ns", PURPOSE_SIGN, &d, T0 + 9000)]);
    let (code, out) = run(&audit, &[&j1, &j2], &[]);
    assert_eq!(code, 1);
    assert!(out.contains(&format!("request {d}")), "{out}");
}

#[test]
fn an_audited_signature_no_journal_holds_and_unattributed_signatures_are_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let (audit, j1, j2) = (tmp.path().join("audit.jsonl"), tmp.path().join("j1"), tmp.path().join("j2"));
    let (a, b) = ("a".repeat(32), "b".repeat(32));
    driver_log(&audit, &[("sign", sign_detail("frost-ns", &a, true)), ("sign", sign_detail("frost-ns", &b, true))]);
    journal(&j1, 1, &[("frost-ns", PURPOSE_SIGN, &a, T0 + 1500)]);
    journal(&j2, 2, &[("frost-ns", PURPOSE_SIGN, &a, T0 + 1500)]);
    let (code, out) = run(&audit, &[&j1, &j2], &[]);
    assert_eq!(code, 1);
    assert!(out.contains(&format!("request {b}")) && out.contains("in 0 of the supplied journals"), "{out}");

    // Only one node's journal holds a sign the threshold says two must.
    driver_log(&audit, &[("sign", sign_detail("frost-ns", &a, true))]);
    let (code, _) = run(&audit, &[&j1], &["--min-journals", "2"]);
    assert_eq!(code, 1);

    // Signatures without an intent: flagged, unless the rollout allows them.
    journal(&j1, 1, &[("frost-ns", PURPOSE_NO_INTENT, "", T0 + 2000)]);
    let (code, out) = run(&audit, &[&j1, &j2], &[]);
    assert_eq!(code, 1);
    assert!(out.contains("without a signing intent"), "{out}");
    let (code, out) = run(&audit, &[&j1, &j2], &["--allow-no-intent"]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn a_tampered_driver_audit_log_or_journal_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let (audit, j1) = (tmp.path().join("audit.jsonl"), tmp.path().join("j1"));
    let a = "a".repeat(32);
    driver_log(&audit, &[("sign", sign_detail("frost-ns", &a, true)), ("sign", sign_detail("frost-ns", &a, true))]);
    journal(&j1, 1, &[("frost-ns", PURPOSE_SIGN, &a, T0 + 1500)]);
    let text = std::fs::read_to_string(&audit).unwrap();
    std::fs::write(&audit, text.replacen("outcome=ok", "outcome=ko", 1)).unwrap();
    let (code, out) = run(&audit, &[&j1], &[]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("hash chain breaks at entry 1"), "{out}");

    driver_log(&audit, &[("sign", sign_detail("frost-ns", &a, true))]);
    let seg = rutli_cosigner::journal::segments(&j1.join("frost-ns")).unwrap().pop().unwrap();
    let t = std::fs::read_to_string(&seg).unwrap();
    std::fs::write(&seg, t.replacen("\"node\":1", "\"node\":3", 1)).unwrap();
    let (code, out) = run(&audit, &[&j1], &[]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("corrupt"), "{out}");
}

#[test]
fn msg_names_which_message_the_driver_signed_and_which_were_signed_out_of_band() {
    let tmp = tempfile::tempdir().unwrap();
    let (audit, j1, j2) = (tmp.path().join("audit.jsonl"), tmp.path().join("j1"), tmp.path().join("j2"));
    let (a, b) = ("a".repeat(32), "b".repeat(32));
    let (m1, m2, m3) = ("1220".to_string() + &"11".repeat(32), "1220".to_string() + &"22".repeat(32), "1220".to_string() + &"33".repeat(32));
    // A current driver (msg=) and an older one (no msg=) in one log: both still match.
    driver_log(&audit, &[("sign", sign_detail_msg("frost-ns", &a, &m1)), ("sign", sign_detail("frost-ns", &b, true))]);
    let sign = |r: &str, m: &str, at: u64| ("frost-ns", PURPOSE_SIGN, r.to_string(), m.to_string(), at);
    let both = |dir: &Path, node: u16, extra: Vec<(&str, &str, String, String, u64)>| {
        let mut e = vec![sign(&a, &m1, T0 + 1500), sign(&b, &m2, T0 + 2500)];
        e.extend(extra);
        let e: Vec<_> = e.iter().map(|(k, p, r, m, at)| (*k, *p, r.as_str(), m.clone(), *at)).collect();
        journal_messages(dir, node, &e);
    };
    both(&j1, 1, vec![]);
    both(&j2, 2, vec![]);
    let (code, out) = run(&audit, &[&j1, &j2], &["--min-journals", "2"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("1 with a message digest") && out.contains("1 driver sign(s) without msg="), "{out}");

    // Node 2 also signed m3 under the audited request id `a` — outside the driver.
    let j3 = tmp.path().join("j3");
    both(&j3, 2, vec![sign(&a, &m3, T0 + 5000)]);
    let (code, out) = run(&audit, &[&j1, &j3], &["--min-journals", "2"]);
    assert_eq!(code, 1, "{out}");
    let flagged: Vec<_> = out.lines().filter(|l| l.starts_with("DISCREPANCY")).collect();
    assert_eq!(flagged.len(), 1, "{out}");
    let m1_sha = hex::encode(Sha256::digest(hex::decode(&m1).unwrap()));
    assert!(
        flagged[0].contains(&format!("message {m3}"))
            && flagged[0].contains("OUT OF BAND")
            && flagged[0].contains(&format!("signed only msg={m1_sha} (seq 1)")),
        "{out}"
    );
}

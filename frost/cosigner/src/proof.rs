// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! "Epoch E is proven": the operator's statement that a sharing works, recorded next to the key
//! files as a clear marker (`keys/.proven/<key id>.<epoch>.json`).
//!
//! A refresh commits when every node staged and voted for the same outcome, and each node checks
//! that the new verifying shares interpolate to the group key. That shows the commit happened. It
//! does not show that the shares sign together; `verify-key --sign-test` does (every `t`-subset of
//! the roster signs, every signature verifies under the group key, every node reports the same
//! epoch and sharing). It runs from a workstation over gRPC, so no node can know its result.
//! `rutli-cosigner keyfile prove` takes the report of that run, checks it against this node's own
//! live key, and writes the marker. Anything that deletes an older epoch (the backup retention,
//! `backup-retain`) needs this marker for the newer one first.
//!
//! What a marker is: the **operator's statement**. The node checks the report's own consistency and
//! that it agrees with this node's live key (epoch, sharing digest, group key), but cannot check who
//! produced it. The marker records the report's SHA-256, so the statement can be matched with the
//! report later. A marker holds no secret and is not sealed. The marker's time is this node's clock
//! at stamping; a marker dated in the future is ignored.
//!
//! Writing a marker takes no lock and touches nothing on the signing path: the key files are only
//! read, the marker is one new file.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::DaemonError;
use crate::Result;

/// Milliseconds in a second.
const MILLIS_PER_SECOND: u64 = 1000;

/// The directory of markers, inside the key directory (a dot-dir: key listings skip it).
pub const DIR: &str = ".proven";

/// The version of the marker format.
pub const MARKER_VERSION: u8 = 1;

/// One marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    pub v: u8,
    pub key_id: String,
    pub epoch: u64,
    /// Hex: the group verifying key the report agreed on.
    pub group_key: String,
    /// Hex: the sharing's PKP digest, as in the key-file header.
    pub pkp_digest: String,
    /// This node's clock at stamping, milliseconds since the Unix epoch.
    pub proven_ms: u64,
    /// Hex SHA-256 of the report file the operator supplied.
    pub report_sha256: String,
    /// Always [`STATEMENT`]: what the marker is and is not.
    pub statement: String,
}

/// What the marker says about itself.
pub const STATEMENT: &str =
    "recorded from an operator-supplied `verify-key --sign-test --json` report, checked for \
consistency and against this node's live key; the node cannot check who produced it";

/// This node's live sharing of a key: what a report must agree with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    pub key_id: String,
    pub epoch: u64,
    pub group_key: [u8; 32],
    pub pkp_digest: [u8; 32],
    /// The key's own threshold (`min_signers` of this node's key package).
    pub threshold: u16,
    /// The identifiers the key's public package lists (its verifying shares).
    pub roster: Vec<u16>,
}

/// The part of `verify-key --json` that is read here. Unknown fields are fine (the report grows).
#[derive(Debug, Deserialize)]
struct Report {
    key_id: String,
    ok: bool,
    #[serde(default)]
    problems: Vec<String>,
    group_verifying_key: Option<String>,
    pkp_digest: Option<String>,
    epoch: Option<u64>,
    #[serde(default)]
    nodes: Vec<ReportNode>,
    #[serde(default)]
    sign_test: Vec<ReportSign>,
}

#[derive(Debug, Deserialize)]
struct ReportNode {
    identifier: u16,
    present: bool,
    error: Option<String>,
    pkp_digest: String,
    own_share_in_package: bool,
    epoch: u64,
    stale: bool,
}

#[derive(Debug, Deserialize)]
struct ReportSign {
    signers: Vec<u16>,
    ok: bool,
}

fn refuse(msg: impl Into<String>) -> DaemonError {
    DaemonError::Config(format!("keyfile prove: {}", msg.into()))
}

/// Where the marker of `key_id` at `epoch` lives.
pub fn marker_path(keys_dir: &Path, key_id: &str, epoch: u64) -> PathBuf {
    keys_dir.join(DIR).join(format!("{key_id}.{epoch}.json"))
}

/// Check `report` and, if it holds up against this node's `live` sharing, write the marker.
///
/// `roster` and `threshold` are this node's own configuration (every node of the cluster, and `t`):
/// the report must cover exactly that roster and every `t`-subset of it. `now_ms` is this node's
/// clock. Returns the marker and whether this call wrote it (`false`: an equal marker, with its
/// original time, was already there).
pub fn prove(
    keys_dir: &Path,
    live: &Live,
    roster: &[u16],
    threshold: u16,
    report_bytes: &[u8],
    now_ms: u64,
) -> Result<(Marker, bool)> {
    crate::keystore::validate_key_id(&live.key_id)?;
    let report: Report = serde_json::from_slice(report_bytes)
        .map_err(|e| refuse(format!("the report is not `verify-key --json` output: {e}")))?;
    let live_group = hex::encode(live.group_key);
    let live_digest = hex::encode(live.pkp_digest);

    if report.key_id != live.key_id {
        return Err(refuse(format!(
            "the report is for key {}, not {}",
            report.key_id, live.key_id
        )));
    }
    if !report.ok || !report.problems.is_empty() {
        return Err(refuse(format!(
            "the report is not clean ({} problem(s)): {}",
            report.problems.len(),
            report.problems.join("; ")
        )));
    }
    if report.epoch != Some(live.epoch) {
        return Err(refuse(format!(
            "the report is for epoch {}, this node's live share of {} is at epoch {}",
            report
                .epoch
                .map_or_else(|| "?".to_string(), |e| e.to_string()),
            live.key_id,
            live.epoch
        )));
    }
    if report.group_verifying_key.as_deref() != Some(live_group.as_str()) {
        return Err(refuse(
            "the report's group key is not this node's group key",
        ));
    }
    if report.pkp_digest.as_deref() != Some(live_digest.as_str()) {
        return Err(refuse("the report's sharing digest is not this node's"));
    }

    // The configured roster and threshold must be the key's own: a config that says another `t`
    // would ask for the wrong set of quorums.
    let want: BTreeSet<u16> = roster.iter().copied().collect();
    let key_roster: BTreeSet<u16> = live.roster.iter().copied().collect();
    if want != key_roster || threshold != live.threshold {
        return Err(refuse(format!(
            "this node's config (roster {want:?}, threshold {threshold}) is not the key's (roster {key_roster:?}, threshold {})",
            live.threshold
        )));
    }
    // Every node of the roster, nothing else, all on this epoch and this sharing, none stale.
    let got: BTreeSet<u16> = report.nodes.iter().map(|n| n.identifier).collect();
    if want.len() != roster.len() || got.len() != report.nodes.len() || want != got {
        return Err(refuse(format!(
            "the report covers nodes {got:?}, this node's roster is {want:?}"
        )));
    }
    for n in &report.nodes {
        if !n.present
            || n.error.is_some()
            || n.stale
            || !n.own_share_in_package
            || n.epoch != live.epoch
            || n.pkp_digest != live_digest
        {
            return Err(refuse(format!(
                "node {} is not on epoch {} of this sharing in the report (present {}, stale {}, epoch {})",
                n.identifier, live.epoch, n.present, n.stale, n.epoch
            )));
        }
    }

    // Every t-subset signed, and every signature was accepted by the verifier that wrote the report.
    if threshold < 2 || usize::from(threshold) > roster.len() {
        return Err(refuse(format!(
            "threshold {threshold} does not fit a roster of {}",
            roster.len()
        )));
    }
    if let Some(bad) = report.sign_test.iter().find(|s| !s.ok) {
        return Err(refuse(format!(
            "the sign test of quorum {:?} failed in the report",
            bad.signers
        )));
    }
    let signed: BTreeSet<Vec<u16>> = report
        .sign_test
        .iter()
        .map(|s| {
            let mut q = s.signers.clone();
            q.sort_unstable();
            q
        })
        .collect();
    for (_, quorum) in
        crate::verify_key::sign_test_plan(&want.iter().copied().collect::<Vec<_>>(), threshold)
    {
        let mut q = quorum;
        q.sort_unstable();
        if !signed.contains(&q) {
            return Err(refuse(format!("the report has no sign test for the quorum {q:?} (run verify-key with --sign-test)")));
        }
    }

    let marker = Marker {
        v: MARKER_VERSION,
        key_id: live.key_id.clone(),
        epoch: live.epoch,
        group_key: live_group,
        pkp_digest: live_digest,
        proven_ms: now_ms,
        report_sha256: hex::encode(Sha256::digest(report_bytes)),
        statement: STATEMENT.to_string(),
    };
    // An equal marker already there keeps its time: stamping again must not restart the clock that
    // retention measures the epoch's age by.
    // A marker dated in the future proves nothing (see `proves`), so it is replaced, not kept.
    if let Some(existing) = read_marker(keys_dir, &live.key_id, live.epoch) {
        if existing.group_key == marker.group_key
            && existing.pkp_digest == marker.pkp_digest
            && existing.proven_ms <= now_ms
        {
            return Ok((existing, false));
        }
    }
    write_marker(keys_dir, &marker)?;
    Ok((marker, true))
}

/// Write the marker: a temp file in the same directory, fsynced, renamed into place.
fn write_marker(keys_dir: &Path, marker: &Marker) -> Result<()> {
    use std::io::Write;
    let dir = keys_dir.join(DIR);
    std::fs::create_dir_all(&dir)?;
    let path = marker_path(keys_dir, &marker.key_id, marker.epoch);
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        marker.key_id,
        marker.epoch,
        std::process::id()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(marker)?)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The marker of `key_id` at `epoch`, if there is a well-formed one for exactly that key and epoch.
/// Anything else (absent, unreadable, malformed, another key or epoch inside) is `None`.
pub fn read_marker(keys_dir: &Path, key_id: &str, epoch: u64) -> Option<Marker> {
    let bytes = std::fs::read(marker_path(keys_dir, key_id, epoch)).ok()?;
    let m: Marker = serde_json::from_slice(&bytes).ok()?;
    (m.v == MARKER_VERSION && m.key_id == key_id && m.epoch == epoch).then_some(m)
}

/// Whether `marker` proves the sharing with this PKP digest (hex) at `now_ms`: same sharing, and
/// not dated in the future (a clock set ahead, or a forged file).
pub fn proves(marker: &Marker, pkp_digest_hex: &str, now_ms: u64) -> bool {
    marker.pkp_digest == pkp_digest_hex && marker.proven_ms <= now_ms
}

/// How long ago `marker` was stamped, if it proves `pkp_digest_hex` at all.
pub fn proof_age_ms(marker: &Marker, pkp_digest_hex: &str, now_ms: u64) -> Option<u64> {
    proves(marker, pkp_digest_hex, now_ms).then(|| now_ms - marker.proven_ms)
}

/// Set `rutli_key_epoch_proven{key}` (1 when the live epoch has a marker for the live sharing) and
/// `rutli_key_epoch_age_seconds{key}` (seconds since the live key file was written, that is since
/// the epoch was installed or the file was last re-sealed) for every FROST key file with a v2
/// header. v1 files carry no clear epoch and are skipped. Reads only; never fails the caller.
pub fn refresh_gauges(keys_dir: &Path, now_ms: u64) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(keys_dir) else {
        return seen;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Some(header) = crate::seal::header_of(&bytes) else {
            continue;
        };
        if header.kind != crate::seal::RecordKind::FrostShare.as_str() {
            continue;
        }
        let proven = read_marker(keys_dir, &header.key_id, header.epoch)
            .is_some_and(|m| proves(&m, &header.digest, now_ms));
        let age_s = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |t| {
                now_ms.saturating_sub(t.as_millis() as u64) / MILLIS_PER_SECOND
            });
        metrics::gauge!(crate::metrics::KEY_EPOCH_PROVEN, "key" => header.key_id.clone())
            .set(if proven { 1.0 } else { 0.0 });
        metrics::gauge!(crate::metrics::KEY_EPOCH_AGE_SECONDS, "key" => header.key_id.clone())
            .set(age_s as f64);
        seen.insert(header.key_id);
    }
    seen
}

/// A thread that refreshes the two gauges every `interval`. A hung volume stalls only this thread.
/// A key that is no longer listed (deleted, replaced by a tombstone) gets age 0, so a frozen old
/// value cannot keep the alert firing.
pub fn spawn_gauge_updater(
    keys_dir: PathBuf,
    interval: std::time::Duration,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("rutli-epoch-proof-gauges".into())
        .spawn(move || {
            let mut before = BTreeSet::new();
            loop {
                let seen = refresh_gauges(&keys_dir, crate::intent::now_ms());
                for gone in before.difference(&seen) {
                    metrics::gauge!(crate::metrics::KEY_EPOCH_PROVEN, "key" => gone.clone())
                        .set(0.0);
                    metrics::gauge!(crate::metrics::KEY_EPOCH_AGE_SECONDS, "key" => gone.clone())
                        .set(0.0);
                }
                before = seen;
                std::thread::sleep(interval);
            }
        })
        .expect("spawn the epoch-proof gauge thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "frost-test";

    fn live() -> Live {
        Live {
            key_id: KEY.into(),
            epoch: 3,
            group_key: [7; 32],
            pkp_digest: [9; 32],
            threshold: 2,
            roster: vec![1, 2, 3],
        }
    }

    /// A clean report for `live()` over roster 1..=3, threshold 2.
    fn report() -> serde_json::Value {
        let digest = hex::encode([9u8; 32]);
        serde_json::json!({
            "key_id": KEY, "ok": true, "problems": [],
            "group_verifying_key": hex::encode([7u8; 32]), "pkp_digest": digest, "epoch": 3,
            "nodes": (1..=3).map(|i| serde_json::json!({
                "identifier": i, "endpoint": "x", "present": true, "pkp_digest": digest,
                "own_share_in_package": true, "epoch": 3, "stale": false, "unknown_field": 1,
            })).collect::<Vec<_>>(),
            "sign_test": [
                {"leader": 1, "signers": [1, 2], "ok": true},
                {"leader": 2, "signers": [3, 1], "ok": true},
                {"leader": 3, "signers": [2, 3], "ok": true},
            ],
        })
    }

    fn run(dir: &Path, r: &serde_json::Value, l: &Live, now: u64) -> Result<(Marker, bool)> {
        prove(dir, l, &[1, 2, 3], 2, r.to_string().as_bytes(), now)
    }

    #[test]
    fn a_clean_report_for_the_live_sharing_writes_a_marker_once() {
        let d = tempfile::tempdir().unwrap();
        let (m, wrote) = run(d.path(), &report(), &live(), 1_000).unwrap();
        assert!(wrote);
        assert_eq!((m.epoch, m.proven_ms), (3, 1_000));
        assert_eq!(
            m.report_sha256,
            hex::encode(Sha256::digest(report().to_string().as_bytes()))
        );
        assert_eq!(read_marker(d.path(), KEY, 3).unwrap(), m);
        // Again, later: the original time stays (the age clock does not restart).
        let (again, wrote) = run(d.path(), &report(), &live(), 9_000_000).unwrap();
        assert!(!wrote);
        assert_eq!(again.proven_ms, 1_000);
    }

    #[test]
    fn no_marker_when_this_nodes_epoch_sharing_or_group_key_differs() {
        let d = tempfile::tempdir().unwrap();
        let mut other_epoch = live();
        other_epoch.epoch = 2;
        let mut other_group = live();
        other_group.group_key = [8; 32];
        let mut other_digest = live();
        other_digest.pkp_digest = [1; 32];
        for l in [other_epoch, other_group, other_digest] {
            assert!(run(d.path(), &report(), &l, 1).is_err(), "{l:?}");
        }
        let mut other_key = live();
        other_key.key_id = "frost-other".into();
        assert!(run(d.path(), &report(), &other_key, 1).is_err());
        assert!(!d.path().join(DIR).exists(), "nothing was written");
    }

    #[test]
    fn an_unclean_or_incomplete_report_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
        let mut r = report();
        r["ok"] = false.into();
        cases.push(("not ok", r));
        let mut r = report();
        r["problems"] = serde_json::json!(["x"]);
        cases.push(("problems", r));
        let mut r = report();
        r["nodes"][1]["stale"] = true.into();
        cases.push(("stale node", r));
        let mut r = report();
        r["nodes"][2]["epoch"] = 2.into();
        cases.push(("node on another epoch", r));
        let mut r = report();
        r["nodes"][0]["pkp_digest"] = hex::encode([5u8; 32]).into();
        cases.push(("node on another sharing", r));
        let mut r = report();
        r["nodes"][0]["error"] = "unreachable".into();
        cases.push(("node error", r));
        let mut r = report();
        r["nodes"].as_array_mut().unwrap().pop();
        cases.push(("a roster node missing", r));
        let mut r = report();
        r["nodes"][2]["identifier"] = 9.into();
        cases.push(("a node outside the roster", r));
        let mut r = report();
        r["sign_test"].as_array_mut().unwrap().pop();
        cases.push(("a quorum was not tested", r));
        let mut r = report();
        r["sign_test"][0]["ok"] = false.into();
        cases.push(("a quorum failed", r));
        let mut r = report();
        r["sign_test"] = serde_json::json!([]);
        cases.push(("no sign test at all", r));
        let mut r = report();
        r["epoch"] = serde_json::Value::Null;
        cases.push(("no epoch", r));
        for (why, r) in cases {
            assert!(run(d.path(), &r, &live(), 1).is_err(), "{why}");
        }
        assert!(prove(d.path(), &live(), &[1, 2, 3], 2, b"not json", 1).is_err());
        assert!(!d.path().join(DIR).exists(), "nothing was written");
    }

    #[test]
    fn a_config_that_is_not_the_keys_own_roster_and_threshold_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let r = report().to_string();
        // Config says t = 3 for a 2-of-3 key: it would ask for the single quorum [1,2,3].
        assert!(prove(d.path(), &live(), &[1, 2, 3], 3, r.as_bytes(), 1).is_err());
        // Config roster differs from the key's.
        assert!(prove(d.path(), &live(), &[1, 2], 2, r.as_bytes(), 1).is_err());
        assert!(prove(d.path(), &live(), &[1, 2, 3, 4], 2, r.as_bytes(), 1).is_err());
        assert!(!d.path().join(DIR).exists());
    }

    #[test]
    fn a_marker_dated_in_the_future_is_replaced_not_kept() {
        let d = tempfile::tempdir().unwrap();
        run(d.path(), &report(), &live(), 9_000).unwrap();
        // The clock was ahead at the first stamp: now is earlier than the marker's time.
        let (m, wrote) = run(d.path(), &report(), &live(), 4_000).unwrap();
        assert!(wrote);
        assert_eq!(m.proven_ms, 4_000);
    }

    #[test]
    fn a_marker_proves_only_its_sharing_and_never_from_the_future() {
        let d = tempfile::tempdir().unwrap();
        let (m, _) = run(d.path(), &report(), &live(), 5_000).unwrap();
        let digest = hex::encode([9u8; 32]);
        assert!(proves(&m, &digest, 5_000));
        assert!(!proves(&m, &digest, 4_999), "dated after now: ignored");
        assert!(
            !proves(&m, &hex::encode([1u8; 32]), 9_000),
            "another sharing"
        );
        assert_eq!(proof_age_ms(&m, &digest, 8_000), Some(3_000));
        assert_eq!(proof_age_ms(&m, &digest, 1_000), None);
    }

    #[test]
    fn a_damaged_or_misnamed_marker_reads_as_none() {
        let d = tempfile::tempdir().unwrap();
        run(d.path(), &report(), &live(), 1).unwrap();
        let p = marker_path(d.path(), KEY, 3);
        // Copied under another epoch's name: its own epoch no longer matches the name.
        std::fs::copy(&p, marker_path(d.path(), KEY, 4)).unwrap();
        assert!(read_marker(d.path(), KEY, 4).is_none());
        std::fs::write(&p, b"{").unwrap();
        assert!(read_marker(d.path(), KEY, 3).is_none());
        assert!(read_marker(d.path(), KEY, 99).is_none());
    }

    #[test]
    fn the_gauges_follow_the_live_header_and_the_marker() {
        use crate::keystore::{KeyStore, Share};
        use crate::seal::{KeyFileBinding, Sealer};
        let d = tempfile::tempdir().unwrap();
        let keys = d.path().join("keys");
        let sealer = Sealer::from_master_secret(b"proof gauge test master secret", 1).with_binding(
            KeyFileBinding {
                node: 1,
                cluster_uuid: Some("2b0c6a52-4c1e-4b7a-9d1e-3f1a7c2e9b10".into()),
                write_version: 2,
                accept_v1: true,
            },
        );
        let ks = KeyStore::open_with_sealer(&keys, Some(std::sync::Arc::new(sealer))).unwrap();
        let (shares, pkp) =
            rutli_frost_core::dealer::split_ed25519_seed(&[3u8; 32], &[1, 2, 3], 2).unwrap();
        let share = Share {
            key_package: frost_ed25519::keys::KeyPackage::try_from(shares[0].clone()).unwrap(),
            public_key_package: pkp,
            origin: None,
            epoch: 2,
            key_id: KEY.into(),
        };
        ks.create(KEY, &share).unwrap();
        let live = Live {
            key_id: KEY.into(),
            epoch: 2,
            group_key: rutli_frost_core::dkg::group_verifying_key_bytes(&share.public_key_package)
                .unwrap(),
            pkp_digest: share.pkp_digest().unwrap(),
            threshold: 2,
            roster: vec![1, 2, 3],
        };
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let now = crate::intent::now_ms();
        metrics::with_local_recorder(&recorder, || refresh_gauges(&keys, now));
        let out = handle.render();
        assert!(
            out.contains(&format!(
                "{}{{key=\"{KEY}\"}} 0",
                crate::metrics::KEY_EPOCH_PROVEN
            )),
            "{out}"
        );
        assert!(out.contains(crate::metrics::KEY_EPOCH_AGE_SECONDS), "{out}");

        let mut r = report();
        r["epoch"] = 2.into();
        r["group_verifying_key"] = hex::encode(live.group_key).into();
        r["pkp_digest"] = hex::encode(live.pkp_digest).into();
        for n in r["nodes"].as_array_mut().unwrap() {
            n["epoch"] = 2.into();
            n["pkp_digest"] = hex::encode(live.pkp_digest).into();
        }
        prove(&keys, &live, &[1, 2, 3], 2, r.to_string().as_bytes(), now).unwrap();
        metrics::with_local_recorder(&recorder, || refresh_gauges(&keys, now));
        assert!(handle.render().contains(&format!(
            "{}{{key=\"{KEY}\"}} 1",
            crate::metrics::KEY_EPOCH_PROVEN
        )));
        // A marker dated after now does not count.
        metrics::with_local_recorder(&recorder, || refresh_gauges(&keys, now - 10_000));
        assert!(handle.render().contains(&format!(
            "{}{{key=\"{KEY}\"}} 0",
            crate::metrics::KEY_EPOCH_PROVEN
        )));
    }

    #[test]
    fn a_rewritten_sharing_at_the_same_epoch_replaces_the_marker() {
        let d = tempfile::tempdir().unwrap();
        run(d.path(), &report(), &live(), 1).unwrap();
        // The same epoch number, another sharing (an aborted vs a committed ceremony).
        let mut l = live();
        l.pkp_digest = [4; 32];
        let mut r = report();
        r["pkp_digest"] = hex::encode([4u8; 32]).into();
        for n in r["nodes"].as_array_mut().unwrap() {
            n["pkp_digest"] = hex::encode([4u8; 32]).into();
        }
        let (m, wrote) = run(d.path(), &r, &l, 2).unwrap();
        assert!(wrote);
        assert_eq!(m.pkp_digest, hex::encode([4u8; 32]));
    }
}

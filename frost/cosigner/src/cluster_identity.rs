// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The cluster id this node runs under, recorded in `data_dir/cluster-id` (review M2).
//!
//! The effective cluster id ([`crate::config::Config::cluster_id`]) is the `cluster_id` pin when
//! set, else a hash of the `tls.ca_cert` bytes. During and after a CA rotation the file no longer
//! hashes to the cluster's id, so the pin is all that keeps the node in its cluster — and a pin is
//! one Helm value that a `helm upgrade` without `--reuse-values` / `-f <saved values>` silently
//! drops. The node would then start under a different id: hosted-key replication with its peers
//! fails (`key envelope failed authentication`) and split-ceremony files in flight stop opening.
//!
//! So the daemon records the id it runs under on its first start ([`reconcile`]) and refuses to
//! start under a different one unless `cluster_id_change_allowed` is set for a deliberate change.
//! The offline ceremony commands that bind files to the id (`share-recipient`, `import-share`)
//! check it too ([`check`]), without writing.
//!
//! - **Existing installs:** the first start of an image with this check writes the id it computes,
//!   which is the id it already ran under.
//! - **CA rotation, Phase 0** (docs/ca-rotation.md): the pin is set to the current derived value,
//!   so the effective id does not change and the check passes; from Phase A on the pin keeps it.
//! - **A deliberate change** (moving a node to another cluster, a fresh start of a dev cluster):
//!   set `cluster_id_change_allowed: true` for one start; the file is rewritten and a WARN logged.
//!
//! The file lives in `data_dir`, beside `keys/` and `ceremony/`, not in them: the key store, its
//! readiness probe and `backup`/`restore` only look inside `data_dir/keys`. A node restored onto a
//! fresh volume records its id again at its first start.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{DaemonError, Result};

/// `data_dir/<FILE_NAME>`.
pub const FILE_NAME: &str = "cluster-id";

/// Where the id is recorded.
pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// What [`reconcile`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// No record yet: `effective` was recorded now.
    First,
    /// The record is `effective`.
    Unchanged,
    /// The record was `previous` (or unreadable, `None`); `effective` replaced it because the
    /// change is allowed.
    Changed { previous: Option<String> },
}

/// The daemon at startup: compare the effective id (`source` says where it came from, for the
/// message) with the record, record it if there is none, and refuse a different one unless
/// `change_allowed`, in which case the record is replaced.
pub fn reconcile(data_dir: &Path, effective: &str, source: &str, change_allowed: bool) -> Result<Recorded> {
    match read(data_dir)? {
        None => {
            write(data_dir, effective)?;
            Ok(Recorded::First)
        }
        Some(Ok(recorded)) if recorded == effective => Ok(Recorded::Unchanged),
        Some(previous) if change_allowed => {
            write(data_dir, effective)?;
            Ok(Recorded::Changed { previous: previous.ok() })
        }
        Some(Ok(recorded)) => Err(mismatch(data_dir, &recorded, effective, source)),
        Some(Err(bad)) => Err(malformed(data_dir, &bad)),
    }
}

/// An offline command that binds files to the cluster id: refuse if the record exists and differs
/// (unless `change_allowed`). Never writes.
pub fn check(data_dir: &Path, effective: &str, source: &str, change_allowed: bool) -> Result<()> {
    match read(data_dir)? {
        None => Ok(()),
        Some(Ok(recorded)) if recorded == effective => Ok(()),
        Some(_) if change_allowed => Ok(()),
        Some(Ok(recorded)) => Err(mismatch(data_dir, &recorded, effective, source)),
        Some(Err(bad)) => Err(malformed(data_dir, &bad)),
    }
}

/// `None`: no record. `Some(Err(content))`: a record that is not a cluster id.
fn read(data_dir: &Path) -> Result<Option<std::result::Result<String, String>>> {
    let p = path(data_dir);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(DaemonError::Config(format!("cannot read {}: {e}", p.display())));
        }
    };
    let id = text.trim_end_matches('\n').to_string();
    let well_formed = id == "plaintext-dev" || crate::wrap::check_cluster_id(&id).is_ok();
    Ok(Some(if well_formed { Ok(id) } else { Err(id) }))
}

/// Atomically: a temp file, fsync, rename, fsync of the directory.
fn write(data_dir: &Path, id: &str) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let p = path(data_dir);
    let tmp = data_dir.join(format!(".{FILE_NAME}.tmp"));
    let io = |e: std::io::Error| DaemonError::Config(format!("cannot record the cluster id in {}: {e}", p.display()));
    let mut f = std::fs::File::create(&tmp).map_err(io)?;
    f.write_all(format!("{id}\n").as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    drop(f);
    std::fs::rename(&tmp, &p).map_err(io)?;
    std::fs::File::open(data_dir).and_then(|d| d.sync_all()).map_err(io)?;
    Ok(())
}

fn mismatch(data_dir: &Path, recorded: &str, effective: &str, source: &str) -> DaemonError {
    DaemonError::Config(format!(
        "cluster id mismatch: this node runs under cluster id {recorded} (recorded in {} at an \
         earlier start), but its config now gives {effective} ({source}). Starting would cut it off \
         from its peers' hosted-key replication and orphan split-ceremony files in flight. Most \
         likely a `helm upgrade` without --reuse-values / -f <saved values> dropped clusterId, or \
         ca.crt changed while the id was not pinned: set cluster_id (chart clusterId) back to \
         {recorded}. If the change is deliberate, set cluster_id_change_allowed: true (chart \
         clusterIdChangeAllowed) for one start, then remove it (docs/ca-rotation.md)",
        path(data_dir).display()
    ))
}

fn malformed(data_dir: &Path, content: &str) -> DaemonError {
    DaemonError::Config(format!(
        "{} holds {:?}, not a cluster id — restore it, or set cluster_id_change_allowed: true for \
         one start to record the current id",
        path(data_dir).display(),
        content.chars().take(40).collect::<String>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "453bb4aea2088bb5";
    const B: &str = "0123456789abcdef";

    #[test]
    fn the_first_start_records_and_later_starts_must_match() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        check(d, A, "pinned in config", false).unwrap(); // nothing recorded: offline commands pass
        assert!(!path(d).exists(), "check never writes");
        assert_eq!(reconcile(d, A, "derived from tls.ca_cert", false).unwrap(), Recorded::First);
        assert_eq!(std::fs::read_to_string(path(d)).unwrap(), format!("{A}\n"));
        // CA rotation Phase 0: the pin equals the derived value, nothing changes.
        assert_eq!(reconcile(d, A, "pinned in config", false).unwrap(), Recorded::Unchanged);
        check(d, A, "pinned in config", false).unwrap();

        // The pin dropped by a helm upgrade: the id derived from the rotation bundle differs.
        let e = reconcile(d, B, "derived from tls.ca_cert", false).unwrap_err().to_string();
        assert!(e.contains(A) && e.contains(B) && e.contains("derived from tls.ca_cert"), "{e}");
        assert!(e.contains("--reuse-values") && e.contains("cluster_id_change_allowed"), "{e}");
        assert!(check(d, B, "derived from tls.ca_cert", false).is_err());
        assert_eq!(std::fs::read_to_string(path(d)).unwrap(), format!("{A}\n"), "a refusal changes nothing");

        // A deliberate change.
        check(d, B, "pinned in config", true).unwrap();
        assert_eq!(
            reconcile(d, B, "pinned in config", true).unwrap(),
            Recorded::Changed { previous: Some(A.into()) }
        );
        assert_eq!(reconcile(d, B, "pinned in config", false).unwrap(), Recorded::Unchanged);
        assert!(!d.join(format!(".{FILE_NAME}.tmp")).exists());
    }

    #[test]
    fn plaintext_dev_is_recorded_and_a_malformed_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(reconcile(d, "plaintext-dev", "plaintext-dev, no TLS", false).unwrap(), Recorded::First);
        assert_eq!(reconcile(d, "plaintext-dev", "plaintext-dev, no TLS", false).unwrap(), Recorded::Unchanged);
        assert!(reconcile(d, A, "derived from tls.ca_cert", false).is_err());

        std::fs::write(path(d), "garbage").unwrap();
        let e = reconcile(d, A, "pinned in config", false).unwrap_err().to_string();
        assert!(e.contains("not a cluster id"), "{e}");
        assert!(check(d, A, "pinned in config", false).is_err());
        assert_eq!(
            reconcile(d, A, "pinned in config", true).unwrap(),
            Recorded::Changed { previous: None }
        );
        assert_eq!(reconcile(d, A, "pinned in config", false).unwrap(), Recorded::Unchanged);
        // No trailing newline is fine too (a hand-written file).
        std::fs::write(path(d), A).unwrap();
        assert_eq!(reconcile(d, A, "pinned in config", false).unwrap(), Recorded::Unchanged);
    }
}

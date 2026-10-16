// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! One cosigner process per data directory.
//!
//! Two live processes on one share directory are never intended: after a proactive refresh the
//! process that did not take part keeps the OLD share cached (its signatures then fail), and a
//! second process would also race the first on the key store and the nonce markers. The cluster
//! prevents it with `ReadWriteOncePod` volumes; this is the same guarantee for everything the
//! volume layer cannot see — two containers on one host, a compose file started twice, an old
//! process that outlived a restart on the same node.
//!
//! It is an advisory `flock(2)` on a file in `data_dir`, held for the life of the process and
//! released by the kernel when the process exits, however it exits. It does not help across nodes
//! (separate filesystems); that is what `ReadWriteOncePod` is for.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::{DaemonError, Result};

/// Lock file name inside `data_dir`. Outside `data_dir/keys`, so `backup` (a flat copy of that
/// directory) and the key store's readiness probe never see it.
pub const LOCK_FILE: &str = ".rutli-cosigner.lock";

/// Holds the lock; drop it (or exit) to release. Keep it alive for the whole serve loop.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Take the exclusive lock on `data_dir` without blocking, creating the directory and the lock
    /// file if needed. Fails with a clear error if another process holds it.
    pub fn acquire(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(LOCK_FILE);
        let mut file = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&path)?;

        // SAFETY: `flock` on a valid, owned file descriptor; no memory is touched.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EWOULDBLOCK) => {
                    let holder = std::fs::read_to_string(&path).unwrap_or_default();
                    let holder = holder.trim();
                    DaemonError::Config(format!(
                        "data directory {} is already in use by another rutli-cosigner process{} — \
                         refusing to start a second instance on the same shares (stop the other \
                         one first)",
                        data_dir.display(),
                        if holder.is_empty() { String::new() } else { format!(" (pid {holder})") }
                    ))
                }
                _ => DaemonError::Io(err),
            });
        }

        // Diagnostic only: who holds it. A failure to write it must not stop the node.
        let _ = file.set_len(0);
        let _ = writeln!(file, "{}", std::process::id());
        Ok(Self { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_open_of_the_same_data_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let first = InstanceLock::acquire(dir.path()).unwrap();
        let err = InstanceLock::acquire(dir.path()).unwrap_err().to_string();
        assert!(err.contains("already in use") && err.contains(&std::process::id().to_string()), "{err}");
        assert_eq!(first.path(), dir.path().join(LOCK_FILE));
    }

    #[test]
    fn the_lock_is_released_on_drop_and_dirs_are_independent() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let held = InstanceLock::acquire(a.path()).unwrap();
        // A different data dir is unaffected.
        let _other = InstanceLock::acquire(b.path()).unwrap();
        drop(held);
        InstanceLock::acquire(a.path()).expect("released with the holder");
    }

    #[test]
    fn it_creates_a_missing_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("not/yet/there");
        let _l = InstanceLock::acquire(&nested).unwrap();
        assert!(nested.join(LOCK_FILE).exists());
    }
}

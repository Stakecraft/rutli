// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Filesystem helpers shared by the stores that must survive a crash.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Canonical store directories that existed, and whose parent was synced, in this process.
static PARENT_SYNCED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Open (creating if needed) the store directory `dir` and make its name durable in its parent.
/// Returns the canonical path of `dir`.
///
/// - A directory that did not exist is created, and the parent of EVERY level this call created
///   (`create_dir_all` may make several) is fsynced, top-down, so each new name reaches disk. This
///   always happens, whatever was synced before: a directory deleted and created again at the same
///   path is a new entry.
/// - A directory that already existed has its parent synced on the first successful open in this
///   process: an earlier process may have died, or its sync failed, before the entry reached disk.
///   Later opens of it skip the sync. The set is keyed by the canonical path, so `.`, `..`,
///   symlinks and a changed working directory do not make one directory look like two.
/// - A failed sync is returned and not recorded, so the next open tries again.
///
/// The process needs read permission on the parent (a directory is opened to be synced).
pub fn open_dir_durably(dir: &Path) -> io::Result<PathBuf> {
    let existed = dir.try_exists()?;
    // The levels `create_dir_all` is about to create, deepest first.
    let mut missing: Vec<&Path> = Vec::new();
    if !existed {
        for a in dir.ancestors() {
            if a.as_os_str().is_empty() || a.try_exists()? {
                break;
            }
            missing.push(a);
        }
    }
    fs::create_dir_all(dir)?;
    let canonical = fs::canonicalize(dir)?;
    let set = PARENT_SYNCED.get_or_init(Default::default);
    if existed
        && set
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&canonical)
    {
        return Ok(canonical);
    }
    // Top-down: the shallowest new name first.
    for level in missing.iter().rev() {
        let level = fs::canonicalize(level)?;
        sync_parent_of(&level)?;
    }
    if existed {
        sync_parent_of(&canonical)?;
    }
    set.lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(canonical.clone());
    Ok(canonical)
}

/// fsync the directory that holds `canonical`.
fn sync_parent_of(canonical: &Path) -> io::Result<()> {
    match canonical.parent() {
        Some(parent) => sync_dir(parent),
        None => Ok(()),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    let handle = fs::File::open(dir)?;
    #[cfg(test)]
    seam::before_sync(dir)?;
    handle.sync_all()
}

/// Test seam: records directory syncs and makes the next one fail after the directory was opened.
/// Thread-local, so parallel tests do not see each other.
#[cfg(test)]
mod seam {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::path::{Path, PathBuf};

    thread_local! {
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
        static SYNCED: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn before_sync(dir: &Path) -> io::Result<()> {
        if FAIL_NEXT.with(|f| f.replace(false)) {
            return Err(io::Error::other("injected sync_all failure"));
        }
        SYNCED.with(|s| s.borrow_mut().push(dir.to_path_buf()));
        Ok(())
    }

    pub(super) fn fail_next_sync() {
        FAIL_NEXT.with(|f| f.set(true));
    }

    /// The directories synced since the last call.
    pub(super) fn take_synced() -> Vec<PathBuf> {
        SYNCED.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        seam::take_synced();
        (tmp, base)
    }

    #[test]
    fn a_failed_sync_is_reported_and_retried() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        fs::create_dir_all(&dir).unwrap();
        seam::fail_next_sync();
        let err = open_dir_durably(&dir).expect_err("the sync error is returned");
        assert_eq!(err.to_string(), "injected sync_all failure");
        assert!(seam::take_synced().is_empty());
        // Not recorded: the next open syncs again, and succeeds.
        assert_eq!(open_dir_durably(&dir).unwrap(), dir);
        assert_eq!(seam::take_synced(), vec![base.join("keys")]);
    }

    #[test]
    fn a_failed_sync_of_a_new_directory_is_retried_too() {
        let (_tmp, base) = fresh();
        let dir = base.join("d");
        seam::fail_next_sync();
        assert!(open_dir_durably(&dir).is_err());
        // The directory exists now but its name may not be durable: it is synced on the next open.
        open_dir_durably(&dir).unwrap();
        assert_eq!(seam::take_synced(), vec![base.clone()]);
    }

    #[test]
    fn a_success_is_cached_for_an_existing_directory() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        fs::create_dir_all(&dir).unwrap();
        open_dir_durably(&dir).unwrap();
        assert_eq!(seam::take_synced(), vec![base.join("keys")]);
        open_dir_durably(&dir).unwrap();
        // The same directory spelled differently is the same directory.
        open_dir_durably(&dir.join("..").join("k.nonces")).unwrap();
        assert!(seam::take_synced().is_empty());
    }

    #[test]
    fn a_recreated_directory_is_synced_again_although_cached() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        open_dir_durably(&dir).unwrap();
        seam::take_synced();
        open_dir_durably(&dir).unwrap();
        assert!(seam::take_synced().is_empty(), "cached while it exists");
        fs::remove_dir(&dir).unwrap();
        open_dir_durably(&dir).unwrap();
        assert_eq!(seam::take_synced(), vec![base.join("keys")]);
    }

    #[test]
    fn creating_several_levels_syncs_the_parent_of_each_top_down() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        assert_eq!(open_dir_durably(&dir).unwrap(), dir);
        assert_eq!(
            seam::take_synced(),
            vec![base.clone(), base.join("keys")],
            "base holds keys/, keys/ holds k.nonces"
        );
        // Only the levels that were missing: keys/ exists now.
        let other = base.join("keys").join("j.nonces");
        open_dir_durably(&other).unwrap();
        assert_eq!(seam::take_synced(), vec![base.join("keys")]);
    }

    #[test]
    fn dot_dot_spellings_resolve_to_one_directory() {
        let (_tmp, base) = fresh();
        let dir = base.join("a").join("..").join("b");
        let canonical = open_dir_durably(&dir).unwrap();
        assert_eq!(canonical, base.join("b"));
        seam::take_synced();
        open_dir_durably(&base.join("b")).unwrap();
        assert!(seam::take_synced().is_empty());
    }
}

// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Filesystem helpers shared by the stores that must survive a crash.

use std::fs;
use std::io;
use std::path::{Component, Path};

/// Open (creating if needed) the store directory `dir`, and make the name of every level this call
/// creates durable in its parent before the directory is used.
///
/// - The missing levels are created one by one, top-down, and the parent of each is fsynced right
///   after. A level another thread or process created in the meantime is not ours, but its parent is
///   synced too: the creator's own sync may still be pending.
/// - If a create or a sync fails, the levels THIS call created are removed again, deepest first
///   (`remove_dir` only succeeds on an empty directory, and its errors are ignored), and the original
///   error is returned. The next open creates and syncs them again.
/// - A directory that already exists is left alone: no sync.
///
/// `dir` must not contain `..` components. The process needs read permission on the parent of every
/// directory it creates (a directory is opened to be synced).
pub fn open_dir_durably(dir: &Path) -> io::Result<()> {
    if dir.components().any(|c| c == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a store directory path must not contain `..`",
        ));
    }
    // The levels to create, deepest first.
    let mut missing: Vec<&Path> = Vec::new();
    for a in dir.ancestors() {
        if a.as_os_str().is_empty() || a.try_exists()? {
            break;
        }
        missing.push(a);
    }
    if missing.is_empty() && !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the store directory path exists and is not a directory",
        ));
    }
    let mut created: Vec<&Path> = Vec::new();
    for level in missing.iter().rev() {
        let step = match fs::create_dir(level) {
            Ok(()) => {
                created.push(level);
                sync_parent_of(level)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && level.is_dir() => {
                sync_parent_of(level)
            }
            Err(e) => Err(e),
        };
        if let Err(e) = step {
            for l in created.iter().rev() {
                let _ = fs::remove_dir(l);
            }
            return Err(e);
        }
    }
    Ok(())
}

/// fsync the directory that holds `path`.
fn sync_parent_of(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(p) if p.as_os_str().is_empty() => sync_dir(Path::new(".")),
        Some(p) => sync_dir(p),
        None => Ok(()),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    let handle = fs::File::open(dir)?;
    #[cfg(test)]
    seam::before_sync(dir)?;
    handle.sync_all()
}

/// Test seam: records directory syncs and can make one fail after the directory was opened.
/// Thread-local, so parallel tests do not see each other.
#[cfg(test)]
mod seam {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::path::{Path, PathBuf};

    thread_local! {
        static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
        static SYNCED: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn before_sync(dir: &Path) -> io::Result<()> {
        let fail = FAIL_AFTER.with(|f| match f.get() {
            Some(0) => {
                f.set(None);
                true
            }
            Some(n) => {
                f.set(Some(n - 1));
                false
            }
            None => false,
        });
        if fail {
            return Err(io::Error::other("injected sync_all failure"));
        }
        SYNCED.with(|s| s.borrow_mut().push(dir.to_path_buf()));
        Ok(())
    }

    /// Let `n` syncs succeed, then fail the next one.
    pub(super) fn fail_sync_after(n: usize) {
        FAIL_AFTER.with(|f| f.set(Some(n)));
    }

    /// The directories synced since the last call.
    pub(super) fn take_synced() -> Vec<PathBuf> {
        SYNCED.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fresh() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        seam::take_synced();
        (tmp, base)
    }

    #[test]
    fn creating_a_missing_directory_syncs_its_parent_once() {
        let (_tmp, base) = fresh();
        let dir = base.join("d");
        open_dir_durably(&dir).unwrap();
        assert!(dir.is_dir());
        assert_eq!(seam::take_synced(), vec![base]);
    }

    #[test]
    fn creating_several_levels_syncs_the_parent_of_each_top_down_and_only_those() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        open_dir_durably(&dir).unwrap();
        assert_eq!(
            seam::take_synced(),
            vec![base.clone(), base.join("keys")],
            "base holds keys/, keys/ holds k.nonces"
        );
        // keys/ exists now: only the new level is synced.
        open_dir_durably(&base.join("keys").join("j.nonces")).unwrap();
        assert_eq!(seam::take_synced(), vec![base.join("keys")]);
    }

    #[test]
    fn an_existing_directory_syncs_nothing() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        fs::create_dir_all(&dir).unwrap();
        open_dir_durably(&dir).unwrap();
        open_dir_durably(&dir).unwrap();
        assert!(seam::take_synced().is_empty());
    }

    #[test]
    fn a_failed_sync_removes_the_new_directory_and_the_retry_syncs_it_again() {
        let (_tmp, base) = fresh();
        let dir = base.join("d");
        seam::fail_sync_after(0);
        let err = open_dir_durably(&dir).expect_err("the sync error is returned");
        assert_eq!(err.to_string(), "injected sync_all failure");
        assert!(!dir.exists(), "the directory this call created is removed");
        assert!(seam::take_synced().is_empty());
        open_dir_durably(&dir).unwrap();
        assert!(dir.is_dir());
        assert_eq!(seam::take_synced(), vec![base]);
    }

    #[test]
    fn a_failure_in_a_multi_level_create_removes_every_level_and_the_retry_syncs_both() {
        let (_tmp, base) = fresh();
        let dir = base.join("keys").join("k.nonces");
        // The sync of base succeeds, the sync of keys/ fails.
        seam::fail_sync_after(1);
        assert!(open_dir_durably(&dir).is_err());
        assert!(!base.join("keys").exists(), "both levels are removed");
        assert_eq!(seam::take_synced(), vec![base.clone()]);
        // A failure on the very first sync leaves nothing either.
        seam::fail_sync_after(0);
        assert!(open_dir_durably(&dir).is_err());
        assert!(!base.join("keys").exists());
        seam::take_synced();
        open_dir_durably(&dir).unwrap();
        assert_eq!(seam::take_synced(), vec![base.clone(), base.join("keys")]);
    }

    #[test]
    fn a_failure_keeps_levels_that_existed_before_the_call() {
        let (_tmp, base) = fresh();
        fs::create_dir(base.join("keys")).unwrap();
        seam::fail_sync_after(0);
        assert!(open_dir_durably(&base.join("keys").join("k.nonces")).is_err());
        assert!(base.join("keys").is_dir());
        assert!(!base.join("keys").join("k.nonces").exists());
    }

    #[test]
    fn a_path_with_dot_dot_is_refused() {
        let (_tmp, base) = fresh();
        let err = open_dir_durably(&base.join("a").join("..").join("b")).expect_err("refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!base.join("a").exists() && !base.join("b").exists());
        assert!(seam::take_synced().is_empty());
    }
}

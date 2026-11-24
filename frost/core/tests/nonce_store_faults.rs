// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Marker pruning under file-system faults (issue #287): a marker that cannot be examined or
//! removed fails the pass instead of being skipped, a failed sentinel leaves every marker in place,
//! and concurrent passes do not fail on each other's removals.

#![cfg(unix)]

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use rutli_frost_core::nonce_store::{NonceStore, PruneReport, PRUNED_SENTINEL};
use rutli_frost_core::CoreError;

const HOUR: Duration = Duration::from_secs(3600);
const HORIZON: Duration = Duration::from_secs(900);

/// A store under `dir` with `sessions` consumed and their markers an hour old.
fn store_with_old_markers(dir: &Path, sessions: &[String]) -> NonceStore {
    let store = NonceStore::open(dir).unwrap();
    for s in sessions {
        store.consume(s).unwrap();
        let f = File::options()
            .write(true)
            .open(dir.join(format!("{s}.used")))
            .unwrap();
        f.set_modified(SystemTime::now() - HOUR).unwrap();
    }
    store
}

fn sessions(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("s-{i}")).collect()
}

fn set_mode(dir: &Path, mode: u32) {
    fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
}

/// Permission bits are not enforced for root: such a test proves nothing there.
fn permissions_enforced(dir: &Path) -> bool {
    set_mode(dir, 0o500);
    let enforced = File::create(dir.join("probe")).is_err();
    set_mode(dir, 0o700);
    let _ = fs::remove_file(dir.join("probe"));
    if !enforced {
        eprintln!("permission bits not enforced (running as root?) — skipping");
    }
    enforced
}

/// A marker whose age cannot be read (the directory can be listed but not searched) fails the
/// pass: it is never skipped as if it were gone.
#[test]
fn a_marker_that_cannot_be_examined_fails_the_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("k.nonces");
    let store = store_with_old_markers(&dir, &sessions(2));
    if !permissions_enforced(&dir) {
        return;
    }
    // Readable (the names list) but not searchable (no stat of an entry).
    set_mode(&dir, 0o600);
    let verdict = store.prune_older_than(HORIZON, 10);
    set_mode(&dir, 0o700); // restore before asserting, or a failure leaves an undeletable tempdir
    assert!(matches!(verdict, Err(CoreError::Io(_))), "got {verdict:?}");
    for s in sessions(2) {
        assert!(store.is_consumed(&s).unwrap(), "{s} must still be burned");
    }
}

/// A marker that cannot be removed (the directory is read-only, the sentinel already there) fails
/// the pass: it is never counted as gone, nor silently kept.
#[test]
fn a_marker_that_cannot_be_removed_fails_the_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("k.nonces");
    let store = store_with_old_markers(&dir, &sessions(2));
    fs::write(dir.join(PRUNED_SENTINEL), b"pruned before").unwrap();
    if !permissions_enforced(&dir) {
        return;
    }
    set_mode(&dir, 0o500);
    let verdict = store.prune_older_than(HORIZON, 10);
    set_mode(&dir, 0o700);
    assert!(matches!(verdict, Err(CoreError::Io(_))), "got {verdict:?}");
    for s in sessions(2) {
        assert!(store.is_consumed(&s).unwrap(), "{s} must still be burned");
    }
}

/// Passes over the same store at once: none fails on a marker another removed first (between its
/// listing and its look at the marker, or its removal), and together they remove every old marker.
#[test]
fn concurrent_passes_do_not_fail_on_each_others_removals() {
    const N: usize = 600;
    for _round in 0..3 {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("k.nonces");
        let all = sessions(N);
        drop(store_with_old_markers(&dir, &all));
        let reports: Vec<PruneReport> = std::thread::scope(|scope| {
            let passes: Vec<_> = (0..4)
                .map(|_| {
                    let dir = dir.clone();
                    scope
                        .spawn(move || NonceStore::open(&dir).unwrap().prune_older_than(HORIZON, N))
                })
                .collect();
            passes
                .into_iter()
                .map(|p| p.join().unwrap().expect("a concurrent pass fails"))
                .collect()
        });
        // At least every marker once. Not exactly: macOS (APFS) can report one unlink of a file as
        // successful to several racing callers, so the counts may overlap there.
        let removed: usize = reports.iter().map(|r| r.removed).sum();
        assert!(removed >= N, "{reports:?}");
        let store = NonceStore::open(&dir).unwrap();
        for s in &all {
            assert!(!store.is_consumed(s).unwrap());
        }
        assert!(dir.join(PRUNED_SENTINEL).exists());
    }
}

/// The environment variable that makes this test binary, re-run by [`run_child`], play the
/// child: `<test name>:<store directory>`.
const CHILD: &str = "RUTLI_NONCE_FD_CHILD";

/// Re-run this test binary for the test `name` alone, as a child with at most 64 file descriptors
/// (so using them all up is quick), on the store in `dir`.
fn run_child(name: &str, dir: &Path) {
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("ulimit -n 64 && exec \"$0\" --exact \"$1\" --test-threads=1 --nocapture")
        .arg(&exe)
        .arg(name)
        .env(CHILD, format!("{name}:{}", dir.display()))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// In the child for test `name`: the store directory to work on.
fn child_dir(name: &str) -> Option<std::path::PathBuf> {
    let v = std::env::var(CHILD).ok()?;
    let (test, dir) = v.split_once(':')?;
    (test == name).then(|| dir.into())
}

/// Use up every file descriptor but one, and check that a listing of `dir` takes exactly that one.
/// Drop the result to give them back.
fn all_descriptors_but_one(dir: &Path) -> Vec<File> {
    let mut held = Vec::new();
    while let Ok(f) = File::open("/dev/null") {
        held.push(f);
        assert!(held.len() < 1 << 20, "no descriptor limit");
    }
    held.pop();
    let listing = fs::read_dir(dir).expect("one descriptor is free");
    assert!(
        File::open("/dev/null").is_err(),
        "a listing must take the last descriptor"
    );
    drop(listing);
    held
}

/// If the sentinel cannot be written although markers could still be removed (here: no file
/// descriptor left once the pass has listed the directory — `unlink` needs none; as on a full
/// disk, where creating fails and removing works), the pass fails before it removes anything: a
/// store never loses its markers without saying "this key has signed here".
///
/// Runs in a child process: it uses up the process's file descriptors.
#[test]
fn a_sentinel_that_cannot_be_written_leaves_every_marker() {
    const NAME: &str = "a_sentinel_that_cannot_be_written_leaves_every_marker";
    if let Some(dir) = child_dir(NAME) {
        let store = NonceStore::open(&dir).unwrap();
        let held = all_descriptors_but_one(&dir);
        // The pass's own listing takes the last descriptor; the sentinel finds none.
        let verdict = store.prune_older_than(HORIZON, 10);
        drop(held);
        assert!(matches!(verdict, Err(CoreError::Io(_))), "got {verdict:?}");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("k.nonces");
    drop(store_with_old_markers(&dir, &sessions(3)));
    run_child(NAME, &dir);
    let store = NonceStore::open(&dir).unwrap();
    for s in sessions(3) {
        assert!(
            store.is_consumed(&s).unwrap(),
            "{s}: a marker went without the sentinel"
        );
    }
    assert!(!dir.join(PRUNED_SENTINEL).exists());
}

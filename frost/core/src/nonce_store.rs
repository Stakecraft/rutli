// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Crash-safe single-use guard for FROST signing nonces.
//!
//! THE failure mode of threshold Schnorr: releasing two round-2 signature shares computed from the
//! same round-1 nonce commitment (for different messages / commitment sets) leaks this
//! participant's key share. RFC 9591 mandates fresh random nonces per session; this store makes
//! that single-use property survive crashes and restarts.
//!
//! Protocol: before a cosigner's round-2 share leaves the process, [`NonceStore::consume`] must
//! succeed for the session id. `consume` creates a marker file with `O_EXCL` semantics and fsyncs
//! the directory, so:
//!   - a second `consume` for the same session (double-sign attempt, replayed request, retried
//!     round) fails with [`CoreError::NonceReuse`];
//!   - a crash after `consume` but before the share is sent errs on the safe side — the session is
//!     burned, never reusable.
//!
//! Marker files are tiny and per-session. [`NonceStore::prune_older_than`] removes ones past a safe
//! horizon (audit L4: unbounded markers could exhaust the volume's inodes); see its docs for why
//! that cannot enable reuse.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// What one [`NonceStore::prune_older_than`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneReport {
    /// Markers removed.
    pub removed: usize,
    /// Markers left (younger than the horizon, or beyond this pass's budget).
    pub kept: usize,
    /// The pass stopped at its removal budget; more old markers may remain.
    pub truncated: bool,
}

/// Left in a store the first time markers are pruned from it: "this key has signed here", which
/// the markers themselves said before (`discard-partial-key` refuses a key that ever signed). The
/// leading dot keeps it out of the session-id namespace ([`NonceStore::marker_path`]).
pub const PRUNED_SENTINEL: &str = ".signed";

/// What a complete [`PRUNED_SENTINEL`] holds.
const SENTINEL_TEXT: &[u8] = b"nonce markers were pruned; this key has signed on this node\n";
/// Prefix of the file a sentinel is rewritten into before it is renamed over [`PRUNED_SENTINEL`]:
/// `.signed.<pid>.<n>.tmp`, unique per rewrite and created exclusively, so two passes never write
/// into one file.
const SENTINEL_TEMP_PREFIX: &str = ".signed.";

/// Numbers the temporary files of sentinel rewrites within this process.
static SENTINEL_REWRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

use crate::{CoreError, Result};

/// Told how long each [`NonceStore::consume`] took and whether it succeeded. This crate exports no
/// metrics; the daemon passes one that records them.
pub type ConsumeObserver = fn(Duration, bool);

pub struct NonceStore {
    dir: PathBuf,
    observer: Option<ConsumeObserver>,
}

impl NonceStore {
    /// Open (creating if needed) a nonce store rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        crate::fsutil::open_dir_durably(&dir)?;
        Ok(Self {
            dir,
            observer: None,
        })
    }

    /// Call `observer` after every [`NonceStore::consume`] with its duration and outcome.
    #[must_use]
    pub fn with_observer(mut self, observer: ConsumeObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Burn `session_id`. Ok exactly once per session; every later call is [`CoreError::NonceReuse`].
    pub fn consume(&self, session_id: &str) -> Result<()> {
        let started = Instant::now();
        let result = self.burn(session_id);
        if let Some(observe) = self.observer {
            // A metric must never change a burn's outcome (the release profile unwinds).
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observe(started.elapsed(), result.is_ok())
            }));
        }
        result
    }

    /// [`NonceStore::consume`] without the observer.
    fn burn(&self, session_id: &str) -> Result<()> {
        let path = self.marker_path(session_id)?;
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                // Content is informational; the file's exclusive creation is the guarantee.
                let _ = f.write_all(b"burned");
                f.sync_all()?;
                // fsync the directory so the marker survives power loss.
                File::open(&self.dir)?.sync_all()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(CoreError::NonceReuse(session_id.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Whether a session has already been burned.
    ///
    /// Fails closed: an error looking up the marker (EACCES, a dead mount) is returned, never read
    /// as "not burned". `Path::exists` would swallow it — and did, letting a cosigner whose key store
    /// had become unreadable pass round 1 from its cached share, join a leader's quorum, then fail
    /// round 2 on the marker write, sinking that signature (2026-10-07 incident).
    pub fn is_consumed(&self, session_id: &str) -> Result<bool> {
        Ok(self.marker_path(session_id)?.try_exists()?)
    }

    /// Remove markers older than `horizon` (by modification time), at most `max_remove` per call.
    ///
    /// **Why this cannot enable nonce reuse** (audit L4). Nonces live only in RAM, in a
    /// [`crate::session::Cosigner`]'s in-flight map: round 1 creates an entry with fresh OS
    /// randomness, and the round 2 that uses it removes it under the lock first, so one entry's
    /// nonces sign at most once whatever the markers say. A marker for session `S` (written at
    /// time `c`, before the share is computed) adds two things: round 1 refuses to mint nonces for
    /// `S` again, and a second round 2 for `S` on this volume fails. The only nonces it can still
    /// guard are an entry for `S` created before `c` that has not been consumed — on another
    /// `Cosigner` instance of the key, e.g. one evicted from the cache while a call was in flight.
    /// Round 2 refuses entries older than [`crate::session::PENDING_TTL`] (monotonic clock), so from
    /// `c + PENDING_TTL` on no such entry can sign, and every entry for `S` created after `c` was
    /// refused at round 1. Past that point the marker guards nothing; callers prune at
    /// [`crate::session::MARKER_RETENTION`] (3 × the TTL), the margin covering the gap between the
    /// file's wall-clock mtime and the monotonic TTL. Even a wall clock that jumps forward and
    /// prunes a marker early cannot cause reuse: a later round 1 for `S` mints *fresh* nonces, never
    /// the ones already used. Session ids are random UUIDs, so a legitimate reuse of `S` is
    /// negligible and a replayed one only ever gets fresh nonces.
    ///
    /// A marker whose mtime is in the future (the clock went back) is kept. Before a pass removes
    /// anything, [`PRUNED_SENTINEL`] is on disk, complete and durable (file and directory fsynced),
    /// so the store still says the key has signed here; see [`NonceStore::write_sentinel`].
    /// After removing anything the directory is fsynced once — a removal lost to a crash only brings
    /// a marker back, which is harmless.
    pub fn prune_older_than(&self, horizon: Duration, max_remove: usize) -> Result<PruneReport> {
        let now = SystemTime::now();
        let mut report = PruneReport::default();
        let mut sentinel_written = false;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(session) = name.to_str().and_then(|n| n.strip_suffix(".used")) else {
                continue;
            };
            if self.marker_path(session).is_err() {
                continue; // not one of ours
            }
            let modified = match entry.metadata().and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let old = now.duration_since(modified).is_ok_and(|age| age >= horizon);
            if !old || report.removed >= max_remove {
                report.kept += 1;
                report.truncated |= old;
                continue;
            }
            if !sentinel_written {
                self.write_sentinel()?;
                sentinel_written = true;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => report.removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        if report.removed > 0 {
            File::open(&self.dir)?.sync_all()?;
        }
        Ok(report)
    }

    /// Make [`PRUNED_SENTINEL`] present, complete and durable, whether this pass creates it or an
    /// earlier one did. An earlier write may have stopped partway (a full disk) and left the file
    /// short, or not yet fsynced: an existing sentinel is checked against [`SENTINEL_TEXT`] and
    /// fsynced when complete. Otherwise, and when there is none yet, a complete one is written into
    /// a temporary file of its own, fsynced and renamed into place, so the name only ever points at
    /// a file whose fsync succeeded, and an existing one stays in place throughout. The directory is
    /// fsynced last. Anything that is not a regular file under the name is an error, and the pass
    /// removes nothing.
    fn write_sentinel(&self) -> Result<()> {
        let path = self.dir.join(PRUNED_SENTINEL);
        match complete_sentinel(&path)? {
            Some(f) => f.sync_all()?,
            None => self.rewrite_sentinel(&path)?,
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Write a complete sentinel into a temporary file of this call's own and rename it over `path`.
    /// The name is taken with an exclusive create; one already there (a leftover of a crash, after
    /// the counter restarted under the same pid) is skipped, never removed, and the next number is
    /// tried. Only a file this call created is removed on failure.
    fn rewrite_sentinel(&self, path: &Path) -> Result<()> {
        const ATTEMPTS: usize = 64;
        for _ in 0..ATTEMPTS {
            let n = SENTINEL_REWRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let temp = self.dir.join(format!(
                "{SENTINEL_TEMP_PREFIX}{}.{n}.tmp",
                std::process::id()
            ));
            let mut f = match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            };
            let written = f
                .write_all(SENTINEL_TEXT)
                .and_then(|()| f.sync_all())
                .and_then(|()| fs::rename(&temp, path));
            if let Err(e) = written {
                let _ = fs::remove_file(&temp);
                return Err(e.into());
            }
            return Ok(());
        }
        Err(CoreError::NonceStore(format!(
            "no free temporary name to rewrite {} after {ATTEMPTS} tries",
            path.display()
        )))
    }

    fn marker_path(&self, session_id: &str) -> Result<PathBuf> {
        // Session ids are cosigner-generated UUIDs; reject anything path-unsafe defensively.
        if session_id.is_empty()
            || !session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(CoreError::NonceStore(format!(
                "invalid session id: {session_id:?}"
            )));
        }
        Ok(self.dir.join(format!("{session_id}.used")))
    }
}

/// The sentinel at `path`, opened, when it holds exactly [`SENTINEL_TEXT`] (read at most one byte
/// past it); `None` when it holds anything else or is not there. Only a regular file is opened: a
/// symbolic link, a FIFO (which would block the open) or a directory under the name is an error.
fn complete_sentinel(path: &Path) -> Result<Option<File>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() {
        return Err(CoreError::NonceStore(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut f = File::open(path)?;
    let mut held = Vec::with_capacity(SENTINEL_TEXT.len() + 1);
    (&mut f)
        .take(SENTINEL_TEXT.len() as u64 + 1)
        .read_to_end(&mut held)?;
    Ok((held == SENTINEL_TEXT).then_some(f))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn age(store: &NonceStore, session: &str, by: Duration) {
        let f = File::options()
            .write(true)
            .open(store.dir.join(format!("{session}.used")))
            .unwrap();
        f.set_modified(SystemTime::now() - by).unwrap();
    }

    /// Restores a directory's permissions when dropped, so a failed assertion cannot leave a temp
    /// directory the cleanup cannot remove.
    struct RestoreMode(PathBuf);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
        }
    }

    #[test]
    fn a_failed_parent_sync_removes_the_new_directory_and_the_next_open_syncs_again() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("keys");
        let dir = parent.join("k.nonces");
        // The parent exists and can be written into but not opened to be synced.
        fs::create_dir_all(&parent).unwrap();
        let _restore = RestoreMode(parent.clone());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
        if File::open(&parent).is_ok() {
            assert!(
                std::env::var_os("CI").is_none(),
                "this test needs file permissions to be enforced, but the CI job runs as root"
            );
            eprintln!("skipped: permissions not enforced");
            return;
        }
        let err = NonceStore::open(&dir)
            .err()
            .expect("the sync error is returned");
        assert!(
            matches!(&err, CoreError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "{err}"
        );
        assert!(!dir.exists(), "the new directory is removed again");
        // The next open creates and syncs it again, and succeeds.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(NonceStore::open(&dir).is_ok());
        // An existing directory is not synced: the parent need not be readable.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
        assert!(NonceStore::open(&dir).is_ok());
    }

    #[test]
    fn pruning_removes_old_markers_keeps_young_ones_and_leaves_the_signed_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        for s in ["old-1", "old-2", "old-3", "young"] {
            store.consume(s).unwrap();
        }
        for s in ["old-1", "old-2", "old-3"] {
            age(&store, s, Duration::from_secs(3600));
        }
        // A marker from the future (clock went back) is never pruned.
        let f = File::options()
            .write(true)
            .open(store.dir.join("young.used"))
            .unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(3600))
            .unwrap();
        fs::write(store.dir.join("not-a-marker"), b"x").unwrap();
        let horizon = Duration::from_secs(900);

        // Bounded: two per pass.
        let r = store.prune_older_than(horizon, 2).unwrap();
        assert_eq!(
            r,
            PruneReport {
                removed: 2,
                kept: 2,
                truncated: true
            }
        );
        let r = store.prune_older_than(horizon, 2).unwrap();
        assert_eq!(
            r,
            PruneReport {
                removed: 1,
                kept: 1,
                truncated: false
            }
        );
        assert!(store.is_consumed("young").unwrap());
        assert!(!store.is_consumed("old-1").unwrap());
        assert!(
            store.dir.join(PRUNED_SENTINEL).exists() && store.dir.join("not-a-marker").exists()
        );
        // Nothing old left: a no-op that does not touch the sentinel.
        assert_eq!(
            store.prune_older_than(horizon, 2).unwrap(),
            PruneReport {
                removed: 0,
                kept: 1,
                truncated: false
            }
        );
    }

    /// The observer hears every consume with its outcome: a burn and a refused reuse.
    #[test]
    fn the_observer_hears_each_consume_and_its_outcome() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static OK: AtomicUsize = AtomicUsize::new(0);
        static ERR: AtomicUsize = AtomicUsize::new(0);
        fn count(_took: std::time::Duration, ok: bool) {
            let counter = if ok { &OK } else { &ERR };
            counter.fetch_add(1, Ordering::SeqCst);
        }
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path()).unwrap().with_observer(count);
        store.consume("s1").unwrap();
        assert_eq!(
            (OK.load(Ordering::SeqCst), ERR.load(Ordering::SeqCst)),
            (1, 0)
        );
        assert!(matches!(store.consume("s1"), Err(CoreError::NonceReuse(_))));
        assert_eq!(
            (OK.load(Ordering::SeqCst), ERR.load(Ordering::SeqCst)),
            (1, 1)
        );
    }

    /// A panicking observer changes nothing: the burn still succeeds and the marker stands.
    #[test]
    fn a_panicking_observer_does_not_change_a_burns_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path())
            .unwrap()
            .with_observer(|_, _| panic!("the observer failed"));
        store.consume("s2").unwrap();
        assert!(store.is_consumed("s2").unwrap());
        assert!(matches!(store.consume("s2"), Err(CoreError::NonceReuse(_))));
    }

    #[test]
    fn a_second_consume_is_nonce_reuse_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        store.consume("s1").unwrap();
        match store.consume("s1") {
            Err(CoreError::NonceReuse(s)) => assert_eq!(s, "s1"),
            other => panic!("expected NonceReuse, got {other:?}"),
        }
        // Reopening the store (a restart) does not forget it.
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        assert!(matches!(store.consume("s1"), Err(CoreError::NonceReuse(_))));
        assert!(store.is_consumed("s1").unwrap() && !store.is_consumed("s2").unwrap());
    }

    #[test]
    fn a_marker_that_cannot_be_written_is_an_io_error_not_reuse() {
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        let set = |mode| fs::set_permissions(&store.dir, fs::Permissions::from_mode(mode)).unwrap();
        set(0o500);
        if File::create(store.dir.join("probe")).is_ok() {
            set(0o700);
            eprintln!("permission bits not enforced (running as root?) — skipping");
            return;
        }
        let verdict = store.consume("s1");
        set(0o700);
        assert!(matches!(verdict, Err(CoreError::Io(_))), "got {verdict:?}");
    }

    #[test]
    fn invalid_session_ids_are_refused_before_touching_the_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        for bad in ["", "../x", "a/b", "a.b", "a b", "ü"] {
            assert!(
                matches!(store.consume(bad), Err(CoreError::NonceStore(_))),
                "{bad:?}"
            );
            assert!(
                matches!(store.is_consumed(bad), Err(CoreError::NonceStore(_))),
                "{bad:?}"
            );
        }
        for good in ["a", "A-9_z", "123e4567-e89b-12d3-a456-426614174000"] {
            store.consume(good).unwrap();
        }
        assert_eq!(fs::read_dir(&store.dir).unwrap().count(), 3);
    }

    #[test]
    fn is_consumed_fails_closed_when_the_store_cannot_be_read() {
        let tmp = tempfile::tempdir().unwrap();
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        assert!(!store.is_consumed("s1").unwrap());

        let set = |mode| fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode)).unwrap();
        set(0o000);
        if fs::read_dir(tmp.path()).is_ok() {
            set(0o700);
            eprintln!("permission bits not enforced (running as root?) — skipping");
            return;
        }
        let verdict = store.is_consumed("s1");
        set(0o700); // restore BEFORE asserting, or a failure leaves an undeletable tempdir
        assert!(
            verdict.is_err(),
            "an unreadable store must not report a session as unburned"
        );
    }

    /// Old markers in a fresh store, ready for a pass that removes them.
    fn with_old_markers(tmp: &tempfile::TempDir) -> NonceStore {
        let store = NonceStore::open(tmp.path().join("k.nonces")).unwrap();
        for s in ["old-1", "old-2"] {
            store.consume(s).unwrap();
            age(&store, s, Duration::from_secs(3600));
        }
        store
    }

    #[test]
    fn a_short_or_empty_sentinel_left_by_an_earlier_pass_is_completed_before_markers_go() {
        for left in [
            &b""[..],
            &b"nonce markers were pru"[..],
            &b"something else entirely\n"[..],
            &[SENTINEL_TEXT, &b"x"[..]].concat()[..],
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let store = with_old_markers(&tmp);
            fs::write(store.dir.join(PRUNED_SENTINEL), left).unwrap();
            let r = store
                .prune_older_than(Duration::from_secs(900), 10)
                .unwrap();
            assert_eq!(r.removed, 2);
            assert_eq!(
                fs::read(store.dir.join(PRUNED_SENTINEL)).unwrap(),
                SENTINEL_TEXT
            );
            let leftovers: Vec<_> = fs::read_dir(&store.dir)
                .unwrap()
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| n.starts_with(SENTINEL_TEMP_PREFIX) && n.ends_with(".tmp"))
                .collect();
            assert!(
                leftovers.is_empty(),
                "the rewrite is renamed into place: {leftovers:?}"
            );
        }
    }

    #[test]
    fn a_complete_sentinel_is_kept_as_it_is() {
        let tmp = tempfile::tempdir().unwrap();
        let store = with_old_markers(&tmp);
        fs::write(store.dir.join(PRUNED_SENTINEL), SENTINEL_TEXT).unwrap();
        let ino = |p: &Path| std::os::unix::fs::MetadataExt::ino(&fs::metadata(p).unwrap());
        let before = ino(&store.dir.join(PRUNED_SENTINEL));
        assert_eq!(
            store
                .prune_older_than(Duration::from_secs(900), 10)
                .unwrap()
                .removed,
            2
        );
        assert_eq!(
            ino(&store.dir.join(PRUNED_SENTINEL)),
            before,
            "not rewritten"
        );
        assert_eq!(
            fs::read(store.dir.join(PRUNED_SENTINEL)).unwrap(),
            SENTINEL_TEXT
        );
    }

    #[test]
    fn a_sentinel_name_that_is_not_a_readable_file_stops_the_pass_before_any_removal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = with_old_markers(&tmp);
        fs::create_dir(store.dir.join(PRUNED_SENTINEL)).unwrap();
        assert!(store
            .prune_older_than(Duration::from_secs(900), 10)
            .is_err());
        assert!(store.is_consumed("old-1").unwrap() && store.is_consumed("old-2").unwrap());
    }

    #[test]
    fn a_symlink_or_fifo_under_the_sentinel_name_stops_the_pass_before_any_removal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = with_old_markers(&tmp);
        let target = tmp.path().join("elsewhere");
        fs::write(&target, SENTINEL_TEXT).unwrap();
        std::os::unix::fs::symlink(&target, store.dir.join(PRUNED_SENTINEL)).unwrap();
        assert!(store
            .prune_older_than(Duration::from_secs(900), 10)
            .is_err());
        assert!(store.is_consumed("old-1").unwrap());

        let tmp = tempfile::tempdir().unwrap();
        let store = with_old_markers(&tmp);
        // A FIFO would block an open for reading: the pass must refuse it, not hang on it.
        let made = std::process::Command::new("mkfifo")
            .arg(store.dir.join(PRUNED_SENTINEL))
            .status()
            .unwrap();
        assert!(made.success());
        assert!(store
            .prune_older_than(Duration::from_secs(900), 10)
            .is_err());
        assert!(store.is_consumed("old-1").unwrap());
    }

    #[test]
    fn a_leftover_temporary_with_the_next_name_is_skipped_not_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = with_old_markers(&tmp);
        fs::write(store.dir.join(PRUNED_SENTINEL), b"short").unwrap();
        // What crashes mid-rewrite leave, under the names this process tries next (a run of them:
        // other tests share the counter and may take a few numbers first).
        let n = SENTINEL_REWRITES.load(std::sync::atomic::Ordering::Relaxed);
        let leftovers: Vec<_> = (n..n + 16)
            .map(|k| {
                let p = store.dir.join(format!(
                    "{SENTINEL_TEMP_PREFIX}{}.{k}.tmp",
                    std::process::id()
                ));
                fs::write(&p, b"from before").unwrap();
                p
            })
            .collect();
        assert_eq!(
            store
                .prune_older_than(Duration::from_secs(900), 10)
                .unwrap()
                .removed,
            2
        );
        assert_eq!(
            fs::read(store.dir.join(PRUNED_SENTINEL)).unwrap(),
            SENTINEL_TEXT
        );
        for p in &leftovers {
            assert_eq!(fs::read(p).unwrap(), b"from before", "not ours: left alone");
        }
    }

    #[test]
    fn a_new_sentinel_is_renamed_into_place_complete() {
        let tmp = tempfile::tempdir().unwrap();
        let store = with_old_markers(&tmp);
        assert!(!store.dir.join(PRUNED_SENTINEL).exists());
        assert_eq!(
            store
                .prune_older_than(Duration::from_secs(900), 10)
                .unwrap()
                .removed,
            2
        );
        assert_eq!(
            fs::read(store.dir.join(PRUNED_SENTINEL)).unwrap(),
            SENTINEL_TEXT
        );
        let names: Vec<_> = fs::read_dir(&store.dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        assert_eq!(
            names,
            vec![PRUNED_SENTINEL.to_string()],
            "no temporary left"
        );
    }
}

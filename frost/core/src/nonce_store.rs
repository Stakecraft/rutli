// Copyright 2026 StakeCraft
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
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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

use crate::{CoreError, Result};

pub struct NonceStore {
    dir: PathBuf,
}

impl NonceStore {
    /// Open (creating if needed) a nonce store rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Burn `session_id`. Ok exactly once per session; every later call is [`CoreError::NonceReuse`].
    pub fn consume(&self, session_id: &str) -> Result<()> {
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
    /// A marker whose mtime is in the future (the clock went back) is kept. The first removal from a
    /// store leaves [`PRUNED_SENTINEL`] (fsynced) so the store still says the key has signed here.
    /// After removing anything the directory is fsynced once — a removal lost to a crash only brings
    /// a marker back, which is harmless.
    pub fn prune_older_than(&self, horizon: Duration, max_remove: usize) -> Result<PruneReport> {
        let now = SystemTime::now();
        let mut report = PruneReport::default();
        let mut sentinel_written = false;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(session) = name.to_str().and_then(|n| n.strip_suffix(".used")) else { continue };
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

    fn write_sentinel(&self) -> Result<()> {
        let path = self.dir.join(PRUNED_SENTINEL);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                f.write_all(b"nonce markers were pruned; this key has signed on this node\n")?;
                f.sync_all()?;
                File::open(&self.dir)?.sync_all()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn marker_path(&self, session_id: &str) -> Result<PathBuf> {
        // Session ids are cosigner-generated UUIDs; reject anything path-unsafe defensively.
        if session_id.is_empty()
            || !session_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(CoreError::NonceStore(format!("invalid session id: {session_id:?}")));
        }
        Ok(self.dir.join(format!("{session_id}.used")))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn age(store: &NonceStore, session: &str, by: Duration) {
        let f = File::options().write(true).open(store.dir.join(format!("{session}.used"))).unwrap();
        f.set_modified(SystemTime::now() - by).unwrap();
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
        let f = File::options().write(true).open(store.dir.join("young.used")).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(3600)).unwrap();
        fs::write(store.dir.join("not-a-marker"), b"x").unwrap();
        let horizon = Duration::from_secs(900);

        // Bounded: two per pass.
        let r = store.prune_older_than(horizon, 2).unwrap();
        assert_eq!(r, PruneReport { removed: 2, kept: 2, truncated: true });
        let r = store.prune_older_than(horizon, 2).unwrap();
        assert_eq!(r, PruneReport { removed: 1, kept: 1, truncated: false });
        assert!(store.is_consumed("young").unwrap());
        assert!(!store.is_consumed("old-1").unwrap());
        assert!(store.dir.join(PRUNED_SENTINEL).exists() && store.dir.join("not-a-marker").exists());
        // Nothing old left: a no-op that does not touch the sentinel.
        assert_eq!(store.prune_older_than(horizon, 2).unwrap(), PruneReport { removed: 0, kept: 1, truncated: false });
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
        assert!(verdict.is_err(), "an unreadable store must not report a session as unburned");
    }
}

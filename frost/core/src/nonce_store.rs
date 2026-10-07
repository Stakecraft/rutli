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
//! Marker files are tiny and per-session; prune old ones operationally if ever needed (they are
//! keyed by session UUID, not by message, so retention has no correctness impact).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

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

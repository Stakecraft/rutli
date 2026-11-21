// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The open-file limit, raised at daemon start.
//!
//! Every gRPC connection, key file, journal segment and outbound peer channel holds a file
//! descriptor. Container runtimes often start a process with a soft `RLIMIT_NOFILE` of 1024 and a
//! much higher hard limit; the soft limit is what `accept(2)` and `open(2)` hit. The daemon raises
//! its soft limit to the hard limit at start-up and logs both, and the accept loop sizes its
//! connection cap from the result ([`crate::accept::connection_limit`]).

/// The soft and hard `RLIMIT_NOFILE` before and after [`raise_nofile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdLimit {
    /// The soft limit the process started with.
    pub soft_before: u64,
    /// The soft limit in force now: the hard limit, unless raising it failed.
    pub soft: u64,
    /// The hard limit (`u64::MAX` for unlimited).
    pub hard: u64,
    /// What the soft limit was raised towards: the hard limit, or 2^20 when that is unlimited.
    pub target: u64,
}

impl FdLimit {
    /// Raising fell short of the target (macOS caps a process at 10240; a sandbox may refuse).
    pub fn short_of_target(&self) -> bool {
        self.soft < self.target
    }
}

/// Where the soft limit goes when the hard limit is unlimited: high enough for any cosigner, and
/// a value every kernel accepts (`fs.nr_open` defaults to 2^20 on Linux).
const UNLIMITED_TARGET: u64 = 1 << 20;

/// Raise the soft `RLIMIT_NOFILE` to the hard limit. Never lowers it. Returns `None` where the
/// limit cannot be read (non-Unix).
#[cfg(unix)]
// `rlim_t` is `u64` on the 64-bit targets the casts are no-ops on, but not on every Unix.
#[allow(clippy::unnecessary_cast)]
pub fn raise_nofile() -> Option<FdLimit> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` writes one `rlimit` through a valid, exclusively borrowed pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    let as_u64 = |v: libc::rlim_t| {
        if v == libc::RLIM_INFINITY {
            u64::MAX
        } else {
            v as u64
        }
    };
    let (soft_before, hard) = (as_u64(lim.rlim_cur), as_u64(lim.rlim_max));
    let target = if hard == u64::MAX {
        UNLIMITED_TARGET
    } else {
        hard
    };
    if target <= soft_before {
        return Some(FdLimit {
            soft_before,
            soft: soft_before,
            hard,
            target: soft_before,
        });
    }
    let set = |soft: u64| {
        let want = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: lim.rlim_max,
        };
        // SAFETY: `setrlimit` reads one `rlimit` through a valid pointer; no memory is shared.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 }
    };
    // macOS refuses a soft limit above its per-process maximum (OPEN_MAX, 10240) even when the
    // hard limit is higher; fall back to that before giving up.
    let soft = [target, 10_240]
        .into_iter()
        .filter(|&s| s > soft_before && s <= target)
        .find(|&s| set(s))
        .unwrap_or(soft_before);
    Some(FdLimit {
        soft_before,
        soft,
        hard,
        target,
    })
}

#[cfg(not(unix))]
pub fn raise_nofile() -> Option<FdLimit> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_soft_limit_ends_at_or_below_the_hard_limit_and_never_drops() {
        let first = raise_nofile().expect("RLIMIT_NOFILE is readable on Unix");
        assert!(first.soft >= first.soft_before, "{first:?}");
        assert!(first.soft <= first.hard, "{first:?}");
        assert!(
            first.soft <= first.target && first.target <= first.hard,
            "{first:?}"
        );
        // A second call finds the limit already raised and changes nothing.
        let second = raise_nofile().expect("readable");
        assert_eq!(second.soft_before, first.soft, "{second:?}");
        assert_eq!(second.soft, first.soft, "{second:?}");
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Keep a crashing process's memory out of core dumps: `RLIMIT_CORE = 0` and, on Linux,
//! `PR_SET_DUMPABLE = 0` (which also stops same-user ptrace and makes `/proc/<pid>/mem` root-only).
//!
//! The cosigner daemon calls [`disable_core_dumps`] at start, before it opens a key store; the
//! dealer (`rutli-dealer`) calls it first thing. Neither setting holds against a kernel that hands
//! dumps to a user-space handler regardless (a piped `core_pattern` with a dumpable process) or
//! dumps non-dumpable processes (`suid_dumpable = 2`); [`CoreDumps::handler_risk`] says when the
//! host is configured that way.

/// What [`disable_core_dumps`] achieved. Every field is a plain fact, no key material.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CoreDumps {
    /// `RLIMIT_CORE` is now 0 (soft and hard).
    pub core_limit_zero: bool,
    /// `PR_SET_DUMPABLE` is now 0. Always false off Linux.
    pub not_dumpable: bool,
    /// `/proc/sys/kernel/core_pattern` (Linux).
    pub core_pattern: Option<String>,
    /// `/proc/sys/fs/suid_dumpable` (Linux).
    pub suid_dumpable: Option<u8>,
    /// A piped core_pattern or `suid_dumpable = 2`: a crash could still hand memory to a handler.
    pub handler_risk: bool,
}

/// Set `RLIMIT_CORE = 0` and, on Linux, `PR_SET_DUMPABLE = 0`, and read how the kernel handles
/// dumps. Best effort: every outcome is reported, nothing panics.
pub fn disable_core_dumps() -> CoreDumps {
    // SAFETY: plain libc call with a valid, initialised argument; no memory is shared with it.
    let core_limit_zero = unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0
    };
    #[cfg(target_os = "linux")]
    let not_dumpable = {
        // SAFETY: as above. Variadic: pass the unsigned longs the kernel reads, not ints.
        unsafe {
            let zero: libc::c_ulong = 0;
            libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) == 0
        }
    };
    #[cfg(not(target_os = "linux"))]
    let not_dumpable = false;
    #[cfg(target_os = "linux")]
    let (core_pattern, suid_dumpable) = (
        std::fs::read_to_string("/proc/sys/kernel/core_pattern").ok().map(|s| s.trim().to_string()),
        std::fs::read_to_string("/proc/sys/fs/suid_dumpable").ok().and_then(|s| s.trim().parse().ok()),
    );
    #[cfg(not(target_os = "linux"))]
    let (core_pattern, suid_dumpable): (Option<String>, Option<u8>) = (None, None);
    let handler_risk = core_handler_risk(core_pattern.as_deref(), suid_dumpable);
    CoreDumps { core_limit_zero, not_dumpable, core_pattern, suid_dumpable, handler_risk }
}

impl CoreDumps {
    /// Whether a crash of this process could still be dumped, as far as this process can tell. A
    /// process that cleared `PR_SET_DUMPABLE` itself is never dumped on Linux, whatever
    /// `core_pattern` or `suid_dumpable` say (`suid_dumpable` applies to processes made
    /// non-dumpable by a credential change, not by prctl). Without it (it failed, or not Linux), a
    /// piped `core_pattern` ignores `RLIMIT_CORE`.
    pub fn may_dump(&self) -> bool {
        let piped = self.core_pattern.as_deref().is_some_and(|p| p.starts_with('|'));
        !self.not_dumpable && (piped || !self.core_limit_zero)
    }

    /// Every requested setting took effect: `RLIMIT_CORE = 0`, and on Linux not dumpable.
    pub fn all_applied(&self) -> bool {
        self.core_limit_zero && (self.not_dumpable || !cfg!(target_os = "linux"))
    }
}

/// Would a crash reach a core handler despite `RLIMIT_CORE = 0` and `PR_SET_DUMPABLE = 0`?
pub fn core_handler_risk(core_pattern: Option<&str>, suid_dumpable: Option<u8>) -> bool {
    core_pattern.is_some_and(|p| p.starts_with('|')) || suid_dumpable == Some(2)
}

/// Whether the core-dump limit of this process is 0 (tests and the start-up log).
pub fn core_limit_is_zero() -> bool {
    let mut lim = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    // SAFETY: getrlimit writes into the struct we own.
    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) == 0 && lim.rlim_cur == 0 && lim.rlim_max == 0 }
}

/// Whether this process is dumpable (`PR_GET_DUMPABLE`); `None` off Linux.
pub fn is_dumpable() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_DUMPABLE takes no pointer arguments.
        let r = unsafe {
            libc::prctl(libc::PR_GET_DUMPABLE, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong)
        };
        // -1 is an error, not "dumpable".
        (r >= 0).then_some(r != 0)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_piped_core_pattern_or_suid_dumpable_2_is_a_core_handler_risk() {
        assert!(core_handler_risk(Some("|/usr/lib/systemd/systemd-coredump %P"), Some(0)));
        assert!(core_handler_risk(Some("core"), Some(2)));
        assert!(!core_handler_risk(Some("core"), Some(0)));
        assert!(!core_handler_risk(None, None), "not Linux: nothing known, nothing claimed");
    }

    #[test]
    fn not_dumpable_covers_a_piped_handler_and_suid_dumpable() {
        let d = |limit, nd, pat: &str, suid| CoreDumps {
            core_limit_zero: limit,
            not_dumpable: nd,
            core_pattern: Some(pat.into()),
            suid_dumpable: Some(suid),
            handler_risk: false,
        };
        assert!(!d(true, true, "|/usr/lib/systemd/systemd-coredump %P", 0).may_dump());
        assert!(!d(true, true, "core", 0).may_dump());
        assert!(!d(true, true, "core", 2).may_dump(), "suid_dumpable does not undo prctl(0)");
        assert!(d(true, false, "|/bin/handler", 0).may_dump());
        assert!(d(false, false, "core", 0).may_dump());
        assert!(!d(true, false, "core", 0).may_dump(), "off Linux: RLIMIT_CORE=0 and a file pattern");
    }

    #[test]
    fn disable_core_dumps_takes_effect_in_this_process() {
        let d = disable_core_dumps();
        assert!(d.core_limit_zero && core_limit_is_zero());
        if cfg!(target_os = "linux") {
            assert!(d.not_dumpable);
            assert_eq!(is_dumpable(), Some(false));
        }
    }
}

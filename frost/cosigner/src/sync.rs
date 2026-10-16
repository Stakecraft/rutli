// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Poison-tolerant locking (audit L3).
//!
//! RPC handlers unwind on a panic (no `panic = "abort"`): tokio contains the panic to that one
//! request. A `std::sync::Mutex` held at that moment is *poisoned*, though, and with
//! `.lock().expect(..)` every later caller panics too — one bad request would take a whole map, and
//! with it every key on the node, down until a restart. Each lock in the daemon therefore says how
//! it recovers, next to its use:
//!
//! * [`recover`] — the protected state stays consistent through a panic (every critical section is
//!   a single map insert/remove/lookup), so it is used as is;
//! * [`recover_reset`] — the state may be mid-update, so it is reset to something safe (a cache
//!   emptied, durable state reloaded) before use.
//!
//! Either way the recovery is logged and counted in `rutli_lock_poison_recoveries_total{lock}`.

use std::sync::{Mutex, MutexGuard};

/// Lock `lock`; if a holder panicked, take the state as it is (see the module docs) and clear the
/// poison.
pub fn recover<'a, T>(lock: &'a Mutex<T>, name: &'static str) -> MutexGuard<'a, T> {
    lock.lock().unwrap_or_else(|poisoned| {
        note(name, "kept");
        lock.clear_poison();
        poisoned.into_inner()
    })
}

/// Lock `lock`; if a holder panicked, run `reset` on the state first and clear the poison.
pub fn recover_reset<'a, T>(lock: &'a Mutex<T>, name: &'static str, reset: impl FnOnce(&mut T)) -> MutexGuard<'a, T> {
    lock.lock().unwrap_or_else(|poisoned| {
        note(name, "reset");
        let mut guard = poisoned.into_inner();
        reset(&mut guard);
        lock.clear_poison();
        guard
    })
}

/// Log and count one recovery of lock `name` (`state`: what happened to the protected state).
pub fn note(name: &'static str, state: &'static str) {
    metrics::counter!(crate::metrics::LOCK_POISON_RECOVERIES, "lock" => name).increment(1);
    tracing::error!(
        lock = name,
        state,
        "recovered a lock poisoned by a panicking request — the node keeps serving; the panic \
         itself is logged above and is a bug to report"
    );
}

#[cfg(test)]
pub(crate) fn poison<T: Send>(lock: &Mutex<T>) {
    let joined = std::thread::scope(|s| {
        s.spawn(|| {
            let _held = lock.lock();
            panic!("test: panic while holding a lock");
        })
        .join()
    });
    assert!(joined.is_err() && lock.is_poisoned());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_poisoned_lock_is_recovered_once_and_stays_usable() {
        let m = Mutex::new(vec![1, 2]);
        poison(&m);
        assert_eq!(*recover(&m, "test"), vec![1, 2]);
        assert!(!m.is_poisoned());
        poison(&m);
        assert!(recover_reset(&m, "test", |v| v.clear()).is_empty());
        assert!(!m.is_poisoned());
    }
}

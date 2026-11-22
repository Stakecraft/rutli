// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Background loops that outlive a panic in one of their passes.
//!
//! The cosigner's periodic work (the ceremony resolver, the epoch check, the nonce-marker pruner,
//! hosted-key anti-entropy) runs as long-lived tokio tasks whose handles nobody awaits. Their
//! store work goes through [`crate::node::Node::blocking`], which re-raises a panic from the
//! blocking pool, as a panic must stay a panic for a request. Inside a bare `tokio::spawn`ed loop
//! that panic ended the task for good: the loop stopped, and nothing showed it after the one panic
//! line in the log.
//!
//! [`spawn_supervised`] runs the loop as a child task and watches it. A panic is logged with the
//! loop's name and the panic message, counted in `rutli_background_loop_restarts_total{loop}`
//! (alert `RutliBackgroundLoopRestarted`), and the loop starts again from the beginning after
//! [`RESTART_DELAY`]. A loop that sleeps before its first pass (anti-entropy) then also waits its
//! own interval. The panic is still a bug to report; the restart only keeps the node's
//! housekeeping going until it is fixed.

use std::any::Any;
use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Pause before a panicked loop starts again, so a pass that panics every time costs one log line
/// and one counter increment per 30 s, not a hot loop.
pub const RESTART_DELAY: Duration = Duration::from_secs(30);

/// Spawn the background loop `name`, restarted after a panic.
///
/// `run(state.clone())` builds one run of the loop. It is called again for each restart, with a
/// fresh clone of `state`, so a loop needs no restart logic of its own. `name` must be one of
/// [`crate::metrics::BACKGROUND_LOOPS`] (a test checks the call sites).
///
/// The supervisor ends, without a restart, when a run returns (the loops here never do) or is
/// cancelled (runtime shutdown). Aborting the returned handle aborts the current run too, at its
/// next await; a `spawn_blocking` operation that run is waiting on still finishes, as tokio cannot
/// stop one. Dropping the handle leaves the loop running (the daemon only ever drops them).
pub fn spawn_supervised<S, F, Fut>(name: &'static str, state: S, run: F) -> JoinHandle<()>
where
    S: Clone + Send + 'static,
    F: Fn(S) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    spawn_supervised_after(name, RESTART_DELAY, state, run)
}

fn spawn_supervised_after<S, F, Fut>(
    name: &'static str,
    delay: Duration,
    state: S,
    run: F,
) -> JoinHandle<()>
where
    S: Clone + Send + 'static,
    F: Fn(S) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // Building the run's future can panic too (before any await); count that like a panic
            // inside the run rather than losing the supervisor.
            let outcome: Result<(), Box<dyn Any + Send>> = match std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| run(state.clone())),
            ) {
                Ok(fut) => {
                    let mut child = AbortOnDrop(tokio::spawn(fut));
                    match (&mut child.0).await {
                        Ok(()) => Ok(()),
                        Err(e) if e.is_panic() => Err(e.into_panic()),
                        Err(e) => {
                            tracing::debug!(background_loop = name, error = %e, "background loop cancelled");
                            return;
                        }
                    }
                }
                Err(payload) => Err(payload),
            };
            match outcome {
                Ok(()) => {
                    tracing::warn!(
                        background_loop = name,
                        "background loop returned; not restarting it"
                    );
                    return;
                }
                Err(payload) => {
                    let panic = panic_message(payload.as_ref());
                    metrics::counter!(crate::metrics::BACKGROUND_LOOP_RESTARTS, "loop" => name)
                        .increment(1);
                    tracing::error!(
                        background_loop = name,
                        %panic,
                        restart_in_secs = delay.as_secs(),
                        "background loop panicked; restarting it (the panic is a bug: report it)"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    })
}

/// The current run's handle, aborted when the supervisor goes away (aborted, or the runtime shuts
/// down), so an aborted supervisor never leaves its run going on beside a new one.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The text of a panic payload: what `panic!("..")` and `.expect("..")` carry.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "a panic without a message".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A loop that panics on its first two runs is started again each time, with fresh state, and
    /// the supervisor ends once a run returns.
    #[tokio::test]
    async fn a_panicked_loop_is_restarted_until_a_run_returns() {
        let runs = Arc::new(AtomicUsize::new(0));
        let handle = spawn_supervised_after(
            "test",
            Duration::from_millis(10),
            Arc::clone(&runs),
            |runs| async move {
                let n = runs.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    panic!("pass {n} panicked");
                }
            },
        );
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the supervisor must end once a run returns")
            .expect("the supervisor itself must not panic");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            3,
            "two panicked runs, then the one that returned"
        );
    }

    /// The restart waits the delay: a loop that panics every time is not restarted in a hot loop.
    #[tokio::test]
    async fn a_restart_waits_the_delay() {
        let runs = Arc::new(AtomicUsize::new(0));
        let handle = spawn_supervised_after(
            "test",
            Duration::from_secs(30),
            Arc::clone(&runs),
            |runs| async move {
                runs.fetch_add(1, Ordering::SeqCst);
                panic!("always");
            },
        );
        // Wait for the first run, however slow the scheduler, then give a hot loop time to show.
        tokio::time::timeout(Duration::from_secs(10), async {
            while runs.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first run starts");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "no second run before the delay has passed"
        );
        handle.abort();
    }

    /// A panic while the run's future is built (before any await) is counted and restarted like
    /// one inside the run, instead of killing the supervisor.
    #[tokio::test]
    async fn a_panic_building_the_run_is_restarted_too() {
        let builds = Arc::new(AtomicUsize::new(0));
        let handle = spawn_supervised_after(
            "test",
            Duration::from_millis(10),
            Arc::clone(&builds),
            |builds| {
                assert!(
                    builds.fetch_add(1, Ordering::SeqCst) > 0,
                    "the first build panics"
                );
                async {}
            },
        );
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the supervisor must end once a run returns")
            .expect("the supervisor itself must not panic");
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    /// Aborting the supervisor aborts its current run: no run is left going on behind it.
    #[tokio::test]
    async fn aborting_the_supervisor_aborts_the_run() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let handle = spawn_supervised_after(
            "test",
            Duration::from_millis(10),
            Arc::clone(&ticks),
            |ticks| async move {
                loop {
                    ticks.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            },
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while ticks.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the run starts");
        handle.abort();
        let _ = handle.await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = ticks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after,
            "the run must stop with its supervisor"
        );
    }

    #[test]
    fn panic_messages_are_read_from_both_payload_types() {
        assert_eq!(panic_message(&"static text"), "static text");
        assert_eq!(panic_message(&String::from("formatted 7")), "formatted 7");
        assert_eq!(panic_message(&7u8), "a panic without a message");
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The accept loop against a real `EMFILE`: connections wait in the listen backlog, the process's
//! soft open-file limit is lowered until `accept(2)` fails, and the loop must neither end nor yield
//! an error; once descriptors are free again, every waiting connection is served.
//!
//! Lowers the limit of the whole test process, so it is the only test in this binary.

#![cfg(unix)]
// `rlim_t` is `u64` on the 64-bit targets the casts are no-ops on, but not on every Unix.
#![allow(clippy::unnecessary_cast)]

use std::time::Duration;

use tokio_stream::StreamExt;

const WAITING: usize = 60;
const SPARE: u64 = 8;

fn nofile() -> libc::rlimit {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit through a valid pointer.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
    lim
}

fn set_soft(lim: libc::rlimit, soft: u64) {
    let want = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: setrlimit reads one rlimit through a valid pointer.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &want) }, 0);
}

/// Descriptors open now: (how many, the highest number).
fn open_fds() -> (usize, u64) {
    let fds: Vec<u64> = std::fs::read_dir("/dev/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u64>().ok())
        .collect();
    (fds.len(), fds.iter().copied().max().unwrap())
}

/// Fill every free descriptor number below the soft limit, then free `spare` of them: what the
/// process holds open (an inherited high-numbered descriptor leaves gaps below it) does not matter.
fn leave_free(spare: usize) -> Vec<std::fs::File> {
    let mut burned = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => burned.push(f),
            Err(e) if e.raw_os_error() == Some(libc::EMFILE) => break,
            Err(e) => panic!("opening /dev/null: {e}"),
        }
    }
    assert!(
        burned.len() >= spare,
        "only {} free descriptors under the lowered limit",
        burned.len()
    );
    burned.truncate(burned.len() - spare);
    burned
}

#[test]
fn descriptor_exhaustion_neither_ends_the_accept_loop_nor_loses_connections() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let scrape = recorder.handle();
    metrics::set_global_recorder(recorder).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // On a current-thread runtime the accept task runs only when this test awaits, so the
        // clients below all wait in the backlog first.
        let mut stream = rutli_cosigner::accept::incoming(
            listener,
            1000,
            rutli_cosigner::accept::Deadline::new(Duration::from_secs(60), false),
        );
        let clients: Vec<std::net::TcpStream> = (0..WAITING).map(|_| std::net::TcpStream::connect(addr).unwrap()).collect();

        let original = nofile();
        let (open, highest) = open_fds();
        // EMFILE comes from descriptor numbers, not counts: the kernel hands out the lowest free
        // number below the soft limit. Lower the limit near the highest open number, then fill the
        // gaps below it, so exactly SPARE accepts succeed.
        set_soft(original, highest + SPARE + 1);
        let burned = leave_free(SPARE as usize);
        let mut served = Vec::new();
        // Accept until the descriptors run out: the stream then stalls, it does not end or err.
        loop {
            match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
                Ok(Some(Ok(conn))) => served.push(conn),
                Ok(Some(Err(e))) => panic!("the accept stream yielded an error: {e}"),
                Ok(None) => panic!("the accept stream ended"),
                Err(_) => break, // stalled: out of descriptors, retrying with a backoff
            }
        }
        assert!(
            served.len() < WAITING,
            "the lowered limit must stop accepting early (served {}; {open} descriptors open, highest {highest})",
            served.len()
        );
        let errors = scrape.render();
        let failed: f64 = errors
            .lines()
            .find(|l| l.starts_with("rutli_grpc_accept_errors_total"))
            .and_then(|l| l.split_whitespace().last()?.parse().ok())
            .unwrap_or(0.0);
        assert!(failed >= 1.0, "accept must have failed with EMFILE at least once:\n{errors}");

        // Descriptors back: every connection still waiting is served.
        set_soft(original, original.rlim_cur as u64);
        drop(burned);
        while served.len() < WAITING {
            match tokio::time::timeout(Duration::from_secs(10), stream.next()).await {
                Ok(Some(Ok(conn))) => served.push(conn),
                Ok(Some(Err(e))) => panic!("the accept stream yielded an error: {e}"),
                Ok(None) => panic!("the accept stream ended with {} of {WAITING} served", served.len()),
                Err(_) => panic!("no connection within 10 s after the limit was restored ({} of {WAITING} served)", served.len()),
            }
        }
        drop(clients);
    });
}

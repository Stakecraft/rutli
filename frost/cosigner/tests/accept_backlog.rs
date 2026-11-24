// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! The gRPC listener's backlog (#181): a burst of new clients must be connected by the kernel
//! while the accept loop is busy, not have their SYNs dropped. Linux only: the accept-queue
//! behaviour is the kernel's.

#![cfg(target_os = "linux")]

use std::time::Duration;

use rutli_cosigner::accept::{bind, LISTEN_BACKLOG};

const BURST: usize = 400;

/// How many of `BURST` simultaneous connects to `addr` complete within `within`, while nothing
/// accepts.
async fn connected(addr: std::net::SocketAddr, within: Duration) -> usize {
    let tries = (0..BURST).map(|_| {
        tokio::spawn(async move {
            tokio::time::timeout(within, tokio::net::TcpStream::connect(addr))
                .await
                .ok()
                .and_then(Result::ok)
        })
    });
    let mut kept = Vec::new();
    for t in tries {
        if let Some(s) = t.await.unwrap() {
            kept.push(s); // held open until counted, as clients waiting for TLS would be
        }
    }
    kept.len()
}

fn somaxconn() -> usize {
    std::fs::read_to_string("/proc/sys/net/core/somaxconn")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn a_burst_of_connects_is_queued_by_the_kernel_not_dropped() {
    if somaxconn() < BURST + 1 {
        eprintln!(
            "skipped: net.core.somaxconn {} caps the backlog below {BURST}",
            somaxconn()
        );
        return;
    }
    let within = Duration::from_secs(2);

    let listener = bind("127.0.0.1:0".parse().unwrap(), LISTEN_BACKLOG).unwrap();
    let addr = listener.local_addr().unwrap();
    assert_eq!(
        connected(addr, within).await,
        BURST,
        "every connect completes without an accept"
    );
    drop(listener);

    // The control, informative only (the default backlog is mio's and the kernel's to decide):
    // `TcpListener::bind` asks for 128, which normally drops the rest of the burst.
    let old = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let n = connected(old.local_addr().unwrap(), within).await;
    if n == BURST {
        eprintln!(
            "note: the default listener also queued all {n}; this host cannot show the difference"
        );
    }
}

// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmarks of one cosigner's part in a 2-of-3 signature, as the daemon calls it:
//!
//! - `frost/round1`: [`Cosigner::round1`], which checks the session's marker (a `stat`) and
//!   generates the nonces and commitments. The session is aborted inside the measurement so the
//!   in-flight map stays empty, as it is on a node whose sessions complete; the abort is one map
//!   removal.
//! - `frost/round2`: [`Cosigner::round2`], which checks the round-1 binding, burns the session's
//!   marker (a file created and fsynced, then the directory fsynced) and computes the share.
//! - `frost/nonce_marker_burn`: the marker write alone ([`NonceStore::consume`]), to tell the disk
//!   part of round 2 from the arithmetic.
//! - `frost/aggregate`: the leader's aggregation of two shares, which verifies the signature.
//!
//! The marker directory is a temporary directory under `TMPDIR` (or `RUTLI_BENCH_DIR`), so the
//! fsync numbers are those of that filesystem. It gains one marker per signed session and is not
//! pruned during the run; a node keeps fifteen minutes of markers.
//! Run through `scripts/bench.sh`.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use frost_ed25519 as frost;
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;
use rutli_frost_core::nonce_store::NonceStore;
use rutli_frost_core::session::{aggregate, Cosigner, SessionBinding};

const KEY: &str = "bench-frost-namespace";

/// Canton's sign payload: `0x1220 ‖ sha256` (34 bytes, docs/wire-contract.md).
fn message() -> Vec<u8> {
    let mut m = vec![0x12, 0x20];
    m.extend_from_slice(&[0xab; 32]);
    m
}

/// Where the benchmark's files go: `RUTLI_BENCH_DIR` if set (to measure a specific volume), else
/// the system temporary directory.
fn bench_dir() -> tempfile::TempDir {
    match std::env::var_os("RUTLI_BENCH_DIR") {
        Some(dir) => tempfile::tempdir_in(PathBuf::from(dir)),
        None => tempfile::tempdir(),
    }
    .expect("a temporary directory for the benchmark")
}

/// A fresh session id per call (the nonce store refuses a second use of one).
fn session_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("bench-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Cosigners 1 and 2 of a 2-of-3 key, each with its own marker directory under `dir`.
fn cosigners(dir: &std::path::Path) -> (Cosigner, Cosigner) {
    let (shares, pkp) = rutli_frost_core::dealer::split_ed25519_seed(&[5; 32], &[1, 2, 3], 2).unwrap();
    let cosigner = |i: usize| {
        let kp = frost::keys::KeyPackage::try_from(shares[i].clone()).unwrap();
        Cosigner::new(kp, pkp.clone(), NonceStore::open(dir.join(format!("nonces-{}", i + 1))).unwrap())
    };
    (cosigner(0), cosigner(1))
}

fn binding(a: &Cosigner, b: &Cosigner, msg: &[u8]) -> SessionBinding {
    SessionBinding::new(KEY).with_message(msg).with_signers([a.identifier(), b.identifier()])
}

/// Round 1 on both cosigners for a new session: its id and the commitment map round 2 takes.
fn open_session(a: &Cosigner, b: &Cosigner, msg: &[u8]) -> (String, BTreeMap<Identifier, SigningCommitments>) {
    let session = session_id();
    let mut commitments = BTreeMap::new();
    for c in [a, b] {
        commitments.insert(c.identifier(), c.round1(&session, binding(a, b, msg)).unwrap());
    }
    (session, commitments)
}

fn sign_rounds(c: &mut Criterion) {
    let dir = bench_dir();
    let (a, b) = cosigners(dir.path());
    let msg = message();
    let mut group = c.benchmark_group("frost");

    group.bench_function("round1", |bench| {
        bench.iter_batched(
            || (session_id(), binding(&a, &b, &msg)),
            |(session, binding)| {
                let commitments = a.round1(&session, binding).unwrap();
                a.abort(&session);
                black_box(commitments)
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("round2", |bench| {
        bench.iter_batched(
            || {
                // Only cosigner 1 signs. Cosigner 2's commitment is all round 2 needs from it, so
                // its half of the session is dropped here and its in-flight map stays empty.
                let (session, commitments) = open_session(&a, &b, &msg);
                b.abort(&session);
                (session, commitments)
            },
            |(session, commitments)| black_box(a.round2(&session, KEY, &msg, &commitments, None).unwrap()),
            BatchSize::PerIteration,
        )
    });

    let markers = NonceStore::open(dir.path().join("markers")).unwrap();
    group.bench_function("nonce_marker_burn", |bench| {
        bench.iter_batched(session_id, |session| markers.consume(&session).unwrap(), BatchSize::PerIteration)
    });

    // Aggregation does not consume anything: one signed session serves every iteration.
    let (session, commitments) = open_session(&a, &b, &msg);
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    for c in [&a, &b] {
        shares.insert(c.identifier(), c.round2(&session, KEY, &msg, &commitments, None).unwrap());
    }
    let pkp = a.public_key_package().clone();
    group.bench_function("aggregate", |bench| {
        bench.iter(|| black_box(aggregate(&msg, &commitments, &shares, &pkp).unwrap()))
    });

    group.finish();
}

criterion_group!(benches, sign_rounds);
criterion_main!(benches);

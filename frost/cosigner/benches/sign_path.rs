// Copyright 2026 StakeCraft LLC
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmarks of what the cosigner daemon adds around the FROST rounds
//! (`frost/core/benches/sign_rounds.rs` measures those):
//!
//! - `intent/verify_p256`: [`IntentVerifier::verify`] of a signing intent signed with an ECDSA
//!   P-256 client certificate, as `scripts/gen-frost-certs.sh` issues them: the certificate chain
//!   to the cluster CA, the signature, and the intent's fields. Every cosigner in a signature does
//!   this once, at round 1.
//! - `journal/append_fsync`: [`SignJournal::append_charged`], one hash-chained line written and
//!   fsynced, with the rate-limit ledger's bookkeeping. Every released share costs one. No
//!   ceiling is set, but the ledger counts the last minute's charges on every append whatever the
//!   ceiling: the clock passed in advances 200 ms per append, so that window holds 300 charges,
//!   as on a key signing at the default per-minute ceiling. The journal and the ledger's 24-hour
//!   window grow during the run, as they do on a node.
//! - `seal/seal_v1`, `seal/unseal_v1`, `seal/seal_v2`, `seal/unseal_v2`: sealing and opening a
//!   FROST share record with [`Sealer`], in both key-file formats. Not on the path of a signature
//!   once the share is cached; this is what the first use of a key after a restart pays, and what
//!   a ceremony pays per write.
//!
//! The journal is written under `TMPDIR` (or `RUTLI_BENCH_DIR`), so the fsync number is that of
//! that filesystem. Run through `scripts/bench.sh`.

use std::hint::black_box;
use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};
use rutli_cosigner::config::SigningPolicyConfig;
use rutli_cosigner::intent::{self, IntentVerifier};
use rutli_cosigner::journal::{JournalEntry, Limits, Retention, SignJournal, PURPOSE_SIGN};
use rutli_cosigner::keystore::Share;
use rutli_cosigner::pb;
use rutli_cosigner::seal::{KeyFileBinding, RecordKind, RecordMeta, Sealer};

#[path = "../tests/common/pki.rs"]
mod pki;

const KEY: &str = "bench-frost-namespace";
/// How long the benchmark's signing intent is valid, in milliseconds.
const INTENT_LIFETIME_MS: u64 = 60_000;
/// The journal's retention in days.
const JOURNAL_RETENTION_DAYS: u32 = 90;
/// The journal's size ceiling per key, in MiB.
const JOURNAL_MAX_MIB: u64 = 64;
/// The shift that turns MiB into bytes.
const MIB_SHIFT: u32 = 20;
/// The most shares one charge to the rate-limit ledger may cover.
const MAX_SHARES_PER_CHARGE: u32 = 8;
/// How far the clock passed to the journal advances per append, in milliseconds.
const CLOCK_STEP_MS: u64 = 200;
/// The identifier of the third cosigner of the 2-of-3 key.
const THIRD_COSIGNER_ID: u16 = 3;

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

/// A throwaway secret, new on every run.
fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

fn intent_verify(c: &mut Criterion) {
    let pki = pki::TestPki::new();
    let cluster = pki.cluster_id();
    let verifier = IntentVerifier::new(
        pki.ca_pem.as_bytes().to_vec(),
        false,
        cluster.clone(),
        ["driver".to_string()],
        &SigningPolicyConfig::default(),
    )
    .unwrap();
    // One clock reading for the intent and for every verification, so the intent does not expire
    // however long the benchmark runs.
    let now = intent::now_ms();
    let unsigned = pb::SignIntent {
        version: intent::INTENT_VERSION,
        cluster_id: cluster,
        purpose: intent::PURPOSE_SIGN.into(),
        key_id: KEY.into(),
        digest: message(),
        request_id: intent::new_request_id().to_vec(),
        issued_at_ms: now,
        not_after_ms: now + INTENT_LIFETIME_MS,
        ..Default::default()
    };
    let signed = intent::sign_intent(&pki.signer("driver"), &unsigned).unwrap();
    verifier
        .verify(&signed, KEY, now)
        .expect("the benchmark's intent verifies");

    let mut group = c.benchmark_group("intent");
    group.bench_function("verify_p256", |bench| {
        bench.iter(|| black_box(verifier.verify(black_box(&signed), KEY, now).unwrap()))
    });
    group.finish();
}

fn journal_append(c: &mut Criterion) {
    let dir = bench_dir();
    let journal = SignJournal::open(
        dir.path().join("journal"),
        1,
        Retention {
            days: JOURNAL_RETENTION_DAYS,
            max_bytes: JOURNAL_MAX_MIB << MIB_SHIFT,
        },
    )
    .unwrap();
    // No ceiling: the benchmark appends more than a day's default quota. The ledger still counts
    // the last minute's charges and records each new one.
    let limits = Limits {
        per_min: 0,
        per_day: 0,
        max_shares_per_charge: MAX_SHARES_PER_CHARGE,
    };
    let digest = hex::encode(message());
    let mut now = intent::now_ms();
    let mut n: u64 = 0;

    let mut group = c.benchmark_group("journal");
    group.bench_function("append_fsync", |bench| {
        bench.iter(|| {
            n += 1;
            now += CLOCK_STEP_MS;
            // A new request id per append, as every driver call has: each one is a new charge.
            let entry = JournalEntry {
                key_id: KEY.into(),
                purpose: PURPOSE_SIGN.into(),
                request_id: format!("{n:032x}"),
                intent_sha256: format!("{n:064x}"),
                digest: digest.clone(),
                session_id: format!("bench-{n}"),
                signer_cn: "driver".into(),
                ..Default::default()
            };
            black_box(journal.append_charged(entry, limits, now).unwrap())
        })
    });
    group.finish();
}

fn seal_unseal(c: &mut Criterion) {
    // A real share record: what the key store seals for a FROST key.
    let (shares, pkp) =
        rutli_frost_core::dealer::split_ed25519_seed(&random_32(), &[1, 2, THIRD_COSIGNER_ID], 2)
            .unwrap();
    let share = Share {
        key_package: frost_ed25519::keys::KeyPackage::try_from(shares[0].clone()).unwrap(),
        public_key_package: pkp,
        origin: None,
        epoch: 1,
        key_id: KEY.into(),
    };
    let plain = serde_json::to_vec(&share).unwrap();
    let digest = share.pkp_digest().unwrap();
    let meta = RecordMeta {
        kind: RecordKind::FrostShare,
        key_id: KEY,
        epoch: share.epoch,
        digest: &digest,
    };
    let sealer = Sealer::from_master_secret(&random_32(), 1).with_binding(KeyFileBinding {
        node: 1,
        cluster_uuid: Some("0b0e6a52-8f0c-4a3e-9d57-5c1f2f3a4b5c".into()),
        write_version: 2,
        accept_v1: true,
    });

    let mut group = c.benchmark_group("seal");
    for version in [1u8, 2] {
        let sealed = sealer.seal_record_as(version, &meta, &plain).unwrap();
        let (opened, _) = sealer
            .unseal_record(&sealed, KEY, &[RecordKind::FrostShare])
            .unwrap();
        assert_eq!(opened, plain, "a sealed record opens to what was sealed");

        group.bench_function(format!("seal_v{version}"), |bench| {
            bench.iter(|| {
                black_box(
                    sealer
                        .seal_record_as(version, &meta, black_box(&plain))
                        .unwrap(),
                )
            })
        });
        group.bench_function(format!("unseal_v{version}"), |bench| {
            bench.iter(|| {
                black_box(
                    sealer
                        .unseal_record(black_box(&sealed), KEY, &[RecordKind::FrostShare])
                        .unwrap(),
                )
            })
        });
    }
    group.finish();
}

criterion_group!(benches, intent_verify, journal_append, seal_unseal);
criterion_main!(benches);

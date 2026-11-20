// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! The fuzz targets (`frost/fuzz`), run in the normal test suite on stable Rust: each target's
//! generated seeds, its committed crash inputs under `frost/fuzz/regressions/<target>/`, and for
//! `canton_key` the Canton test vectors, go through the same harness function the fuzzer runs. A
//! crash the nightly fuzz job finds is minimized and committed under `regressions/` with its fix,
//! and stays a test from then on.
//!
//! Seeds named `ok-*` and every Canton vector are valid inputs: the harness must accept them, which
//! shows it still reaches past the first parse when the formats change.

#[path = "../../fuzz/src/lib.rs"]
mod harness;

use std::path::{Path, PathBuf};

fn files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<PathBuf> = entries.map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
    out.sort();
    out
}

fn run(target: &str) {
    let (_, body) = harness::TARGETS.iter().find(|(n, _)| *n == target).expect("known target");
    let mut ran = 0;
    for (name, bytes) in harness::generated_seeds(target) {
        let accepted = body(&bytes);
        assert!(accepted || !name.starts_with("ok-"), "{target}: valid seed {name} was refused");
        ran += 1;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for path in files(&root.join("fuzz/regressions").join(target)) {
        body(&std::fs::read(&path).unwrap());
        ran += 1;
    }
    if target == "canton_key" {
        for path in files(&root.join("canton-key/testdata/vectors")) {
            if path.extension().is_some_and(|e| e == "bin") {
                assert!(body(&std::fs::read(&path).unwrap()), "canton_key: vector {} was refused", path.display());
                ran += 1;
            }
        }
    }
    assert!(ran > 0, "{target}: nothing to run");
}

#[test]
fn every_fuzz_target_is_here() {
    let names: Vec<&str> = harness::TARGETS.iter().map(|(n, _)| *n).collect();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/fuzz_targets");
    for path in files(&dir) {
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        assert!(names.contains(&stem.as_str()), "fuzz target {stem} is not in harness::TARGETS");
    }
}

#[test]
fn key_file() {
    run("key_file");
}

#[test]
fn seal_bundle() {
    run("seal_bundle");
}

#[test]
fn share_bundle() {
    run("share_bundle");
}

#[test]
fn canton_key() {
    run("canton_key");
}

#[test]
fn export_file() {
    run("export_file");
}

#[test]
fn intent() {
    run("intent");
}

#[test]
fn grpc() {
    run("grpc");
}

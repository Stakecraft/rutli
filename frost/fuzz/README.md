# Fuzzing the cosigner

Coverage-guided fuzz targets ([cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), libFuzzer)
for everything the cosigner parses from a file or the network. This crate is a workspace of its
own: the frost workspace, its `Cargo.lock` and its license checks do not include it.

| Target | Input | What it reaches |
|---|---|---|
| `key_file` | a key file | `seal::file_version` / `header_of`, `Sealer::unseal_record` (v1, v2), the key store's record parser behind a sealed and a plaintext store (`KeyStore::load_foreign`, as restore reads a backup); the input as the plaintext of a valid v2 envelope of each kind; seal/unseal round trip |
| `seal_bundle` | a node seal bundle | `NodeSealBundle::parse`; write/read round trip |
| `share_bundle` | a share bundle or recipient request | `RecipientRequest::validate`, `request_auth::verify_request`; `ShareBundle` checks (`carried_usage`, `check_carried_id`, `check_against`), and `import_share` as a dry run on a node with a pending recipient |
| `canton_key` | a Canton key in any form | `rutli_canton_key::parse` / `parse_export` / `parse_stored` / `parse_pkcs8` / `parse_public_key` (password-protected exports with the test vectors' password), `export::import_canton`; SPKI round trip |
| `export_file` | an `export-key` file | `export::import` (plaintext; encrypted only with cheap Argon2 parameters), `hosted_import_key_id`; export/import round trip |
| `intent` | mode byte + protobuf | even mode: a `SignedIntent` verified as is; odd mode: a `SignIntent` the harness signs with an allowlisted test identity first, so the checks behind the signature see fuzzer-chosen fields. `IntentVerifier::verify`, `verify_delete`, `verify_ceremony`, `ceremony_id_of`, at a fixed clock |
| `grpc` | selector byte + protobuf | the request decoded and passed to the real Signer or Peer handler of node 1 of a three-node in-process mesh (plaintext dev mode; a FROST key and two hosted keys). Every RPC; `GenerateKey` for RSA is skipped |

The harness bodies are in `src/lib.rs`. Accepted inputs must also satisfy a few invariants (round
trips, a verified intent's digest and key, a gated key never verifying without an approval), checked
with `assert!`, so a wrong answer is a finding as well as a crash.

The `grpc` target runs without TLS, so it meets the handlers' request validation and the node
behind them, not the caller-identity checks (allowlists, certificate CNs); those are covered by the
integration tests. Each input gets a fresh copy of the cluster's key stores, so it sees the same
state whatever ran before it.

**Seeds** are generated at run time (`generated_seeds` in `src/lib.rs`), not committed: most of
them hold key material, and the repository carries none, not even test keys. A target writes its
seeds on its first input when `RUTLI_FUZZ_SEED_DIR` is set. The `canton_key` seeds are the Canton
test vectors in `frost/canton-key/testdata/vectors`. The test PKI and the share node's recipient
secret are made per process, so a seed share bundle opens only in the process that generated it;
in a fuzzing run the bundle checks before the envelope still see a valid bundle.

## Running locally

Needs a nightly toolchain and cargo-fuzz:

```bash
rustup toolchain install nightly-2026-11-15
```

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
```

From `frost/`, write the seeds, then fuzz:

```bash
mkdir -p fuzz/corpus/intent fuzz/seeds/intent "$TMPDIR/empty"
```

```bash
RUTLI_FUZZ_SEED_DIR="$PWD/fuzz/seeds/intent" cargo +nightly-2026-11-15 fuzz run intent "$TMPDIR/empty" -- -runs=0 -detect_leaks=0
```

```bash
cargo +nightly-2026-11-15 fuzz run intent fuzz/corpus/intent fuzz/seeds/intent -- -max_total_time=300 -detect_leaks=0
```

`-detect_leaks=0`: the harness keeps a tokio runtime and key stores in process-wide statics, which
LeakSanitizer reports at exit. A crash is written to `fuzz/artifacts/<target>/`. Minimize it (`cargo fuzz tmin <target> <file>`),
then commit it under `regressions/<target>/` with the fix.

## In the normal test suite

`frost/cosigner/tests/fuzz_regressions.rs` compiles `src/lib.rs` into the cosigner's tests (stable
Rust, no libFuzzer) and runs each target's generated seeds, every file under `regressions/<target>/`
and, for `canton_key`, the Canton vectors. Seeds named `ok-*` and the vectors are valid inputs the
harness must accept, which keeps the harness honest when a format changes.

## CI

`.github/workflows/fuzz.yml`, on the schedule in `docs/release-process.md`: nightly at 02:00 UTC,
ten minutes per target, two targets at a time on the self-hosted runners; a manual run
(`workflow_dispatch`, default an hour per target) for a release candidate; thirty seconds per target
on a pull request that changes this crate. The corpus grows in the Actions cache; crash inputs are
uploaded as artifacts. A failed nightly run opens a `type:test` `prio:p1` issue per failed target,
or comments on the one already open.

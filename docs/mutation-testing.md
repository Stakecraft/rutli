# Mutation testing

[cargo-mutants](https://mutants.rs) changes the code one small edit at a time (a `>` becomes `>=`,
a function returns `Ok(())` without doing anything, a `&&` becomes `||`) and runs the tests against
each change. A change no test notices is a **missed mutant**: the tests would also pass if that code
were wrong. Mutation testing runs weekly on the signing path, where a silent bug costs the most.

## Scope

| Module | File | Tests run per mutant |
|---|---|---|
| `nonce_store` | `frost/core/src/nonce_store.rs` | all of `rutli-frost-core` |
| `session` | `frost/core/src/session.rs` | all of `rutli-frost-core` |
| `sign_policy` | `frost/cosigner/src/sign_policy.rs` | cosigner unit tests, `signing_policy`, `ceremony_intent`, `tombstones` |
| `journal` | `frost/cosigner/src/journal.rs` | as `sign_policy`, plus `audit_cross_check` |
| `intent` | `frost/cosigner/src/intent.rs` | as `sign_policy` |
| `seal` | `frost/cosigner/src/seal.rs` | cosigner unit tests, `seal_cli`, `keyfile_cli`, `restore`, `export_import`, `ceremony_store`, `cluster`, `tombstones` |

Each module runs only the test targets that reach it; the rest of the suite never exercises it and
would only add link time to every mutant. The mapping lives in `scripts/mutants.sh`; settings every
run shares (timeouts, exclusions) in `frost/.cargo/mutants.toml`.

## Running it

The workflow `.github/workflows/mutants.yml` runs every Monday at 06:00 UTC and on demand (Actions →
Mutation testing → Run workflow): one job per module, two at a time, each time-boxed to four hours.
It is a report: missed mutants do not fail it. It fails only when cargo-mutants cannot do its job —
the unmutated tests already fail (exit code 4), a usage error (1) or an internal error (70). A
scheduled run that fails that way (or runs out of time, or produces no results) opens an issue
titled "Mutation testing: the scheduled run failed" (labels `type:test`, `prio:p1`), or comments on
the one already open. A pull request that changes this setup (the workflow, `scripts/mutants.sh`,
`scripts/mutants-summary.py`, `frost/.cargo/mutants.toml`) runs only the `nonce_store` module, as a
check of the plumbing. A full run takes a few hours on two runners; each module runs `--jobs 3`.

Locally, from the repository root, with cargo-mutants installed (`cargo install --locked
cargo-mutants`, the version the workflow pins):

```bash
scripts/mutants.sh --list-modules
scripts/mutants.sh nonce_store
scripts/mutants.sh journal --jobs 4 --list   # what would be tried, without running it
```

Extra options go to cargo-mutants. `MUTANTS_TESTS` overrides the cargo test arguments, e.g. to leave
out the integration tests that bind TCP ports (`signing_policy`, `tombstones`) where that is not
allowed:

```bash
MUTANTS_TESTS="--lib --test ceremony_intent" scripts/mutants.sh intent
```

Results land in `frost/mutants.out/` (`missed.txt`, `caught.txt`, `outcomes.json`, a diff per
mutant under `diff/`).

## Results

Each job uploads its `mutants.out` as the artifact `mutants-out-<module>` (30 days). A final job
merges them into **`mutants-summary.json`** (artifact `mutants-summary`, 90 days) and writes the same
numbers as a table on the run's summary page.

`mutants-summary.json`, schema version 1:

```json
{
  "version": 1,
  "commit": "c9ea60c…",
  "complete": true,
  "runs": 6,
  "baseline_ok": true,
  "unrecognised": 0,
  "modules": {
    "core/src/nonce_store.rs": {
      "caught": 37, "missed": 1, "timeout": 0, "unviable": 3, "total": 41,
      "missed_mutants": ["core/src/nonce_store.rs:120:52: replace >= with < in NonceStore::prune_older_than"]
    }
  },
  "total": { "caught": 0, "missed": 0, "timeout": 0, "unviable": 0, "total": 0 }
}
```

| Field | Meaning |
|---|---|
| `version` | Schema version. A reader refuses a version it does not know; fields are only ever added within a version. |
| `commit` | The commit the mutants were made from. |
| `complete` | Every module's job produced results, every baseline passed, and every outcome was understood (`unrecognised` is 0). A reader that gates on the numbers should require it. |
| `runs` | How many `outcomes.json` files went into the report (one per module job). |
| `baseline_ok` | Every run has one baseline, and the unmutated tests passed in it. |
| `unrecognised` | Outcomes that are no verdict on the tests (a broken build or test tool, a shape this report does not know); listed on the job's log. |
| `modules` | Keyed by the file's path under `frost/`. |
| `caught` | A test failed with the mutant in place — good. |
| `missed` | Every test passed with the mutant in place: a gap in the tests, or an equivalent mutant (below). |
| `timeout` | The tests hung with the mutant in place; usually a loop bound, counted as caught by most readers. |
| `unviable` | The mutant does not compile; says nothing about the tests. |
| `total` | Sum of the four. |
| `missed_mutants` | The missed mutants as cargo-mutants names them, sorted. |

The release QA and the quality report take `missed` per module from the latest scheduled run.

## Handling a missed mutant

1. Read the diff (`mutants.out/diff/`) and ask what bug that edit stands for.
2. If a test should catch it, write that test — next to the code for a unit, in `cosigner/tests/`
   for behaviour across nodes. Re-run the one module to see it caught.
3. If the mutant cannot change behaviour (an *equivalent mutant*: e.g. a `>=` that differs only on
   a value that cannot occur), say why where the code is, or exclude it by name in
   `frost/.cargo/mutants.toml` (`exclude_re`) with the reason next to it.

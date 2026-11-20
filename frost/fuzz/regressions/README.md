# Fuzz regressions

One directory per fuzz target (`key_file/`, `intent/`, …), holding inputs that once crashed it.
`frost/cosigner/tests/fuzz_regressions.rs` replays every file here through the target's harness
function in the normal `cargo test`, so a fixed crash stays fixed.

To add one: minimize the crash input (`cargo +nightly fuzz tmin <target> <crash file>`), copy the
result here as `<target>/<short-description>`, and commit it together with the fix.

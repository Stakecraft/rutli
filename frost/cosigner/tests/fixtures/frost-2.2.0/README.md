# FROST 2.2.0 fixtures

Throwaway test material, written once by frost-ed25519 2.2.0 through this repository's own code
(`regenerate` in `tests/frost_fixtures.rs`). Nothing here protects anything: the keys, shares,
seal bundles and recipient secrets were generated for these tests only and are used nowhere else.
The split key is the namespace key of the throwaway Canton node in `frost/canton-key/testdata/vectors`.

`tests/frost_fixtures.rs` pins these bytes. Every later version of the code must open the key files,
compute the digests in `manifest.json`, re-serialize every JSON file byte for byte, and sign with
the shares. **Do not regenerate them to make a test pass**: a failure means stored or wire data
changed. A new FROST version gets its own directory next to this one.

| Path | What |
|---|---|
| `seal/node-<i>.json` | each node's seal bundle (test-only DEK) |
| `dkg/node-<i>/keys/*.json` | sealed v2 key files after a 2-of-3 DKG (epoch 1) |
| `refresh/node-<i>/keys/*.json` | the same key after a refresh (epoch 2) |
| `*/pkp.json`, `*/pkp.postcard.hex` | the public key package as JSON and as the postcard bytes `pkp_digest` hashes |
| `dkg/wire/`, `refresh/wire/` | round-1 packages (JSON and postcard, as the transcript hash sees them) and round-2 packages |
| `sign/` | the commitments, signing package and signature shares of one signature |
| `split/bundle-node<i>.json`, `split/node-<i>/ceremony/*.recipient` | a split ceremony's share bundles and each node's sealed recipient file |
| `manifest.json` | the digests, group keys, message and signature the tests expect |

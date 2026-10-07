# Rütli 0.3.0 — cluster-hosted keys

**Released:** 2026-10-06 · **Tag:** `v0.3.0` (`a0522e6`) · **Previous:** 0.2.1 (2026-07-17)
**Diff:** 127 files, +25 475 / −179 · **Status:** pre-audit (see README → Status)

```
docker pull ghcr.io/stakecraft/rutli-cosigner:0.3.0
# sha256:bf35937ada817ec7f898b3d793a4fc3b0fa87536092ee09637988d7f287815bd
```

## TL;DR

A Canton participant can now run with **no HSM and no local key state**. The cosigner cluster
hosts the RSA-2048-OAEP encryption keys and AES-256-GCM symmetric keys that Canton can rotate, as
replicated, sealed whole keys, while the Ed25519 namespace key stays genuine 2-of-3 FROST. A
participant restart can no longer destroy an encryption key — the DevNet incident that motivated
this release becomes a non-event.

Also in this release: a **critical fix for an unauthenticated mesh Peer API** (affects every
release up to and including 0.2.1), sealed persistence for the software backend, a per-key
decryption rate limit, and portable export/import of hosted keys.

## Operator action required

| What | Why |
|---|---|
| Add `peer_allowlist` (cosigner CNs) to every cosigner config | Mandatory under TLS; the cosigner refuses to start without it. Shipped compose / k8s / Helm configs already set it; Helm derives `cosigner1..N`. |
| Add `hosted_keys { enabled, write_quorum, anti_entropy_interval_secs, decrypt_rate_limit_per_min }` if you want hosted keys | Opt-in. Defaults: write quorum 2, anti-entropy 300 s, rate limit 6000/min. |
| Driver: `frost.hosted-keys = true`, `frost.delegate = "none"` for a keyless participant | `delegate = "none"` requires `hosted-keys = true`. Canton HOCON spelling is `rsa-oaep-sha-256`, not `RsaEsOaepSha256`. |
| Software backend: set `software { dir, seal-secret-env }` | Heap-only keys stay allowed for tests only and log a startup warning. `dir` without a seal secret is refused. |
| Alert on `rutli_key_replicas`, `rutli_anti_entropy_conflicts_total`, `rutli_unreadable_key_files_total`, `rutli_decrypt_rate_limited_total` | New metrics; the first three are page-worthy, the last one is a compromise canary. |

No data migration. Hosted keys live beside FROST shares in `data_dir/keys/`, so existing
`backup` / `restore` cover them unchanged.

## Added

### Cluster-hosted keys (`hosted_keys` on cosigners, `frost.hosted-keys` on the driver)
- RSA-2048-OAEP-SHA256 and AES-256-GCM keys generated on one cosigner, wrapped per recipient
  (ephemeral X25519 → HKDF-SHA256 → AES-256-GCM, AAD-bound to cluster / key id / spec / recipient),
  replicated to the others and sealed at rest on each. Key material never crosses the mesh in the
  clear, even inside mTLS.
- **Replicated whole keys, not threshold shares.** Security tier matches recoverability tier: the
  key Canton cannot rotate stays in MPC; the keys Canton can rotate get replication. Threshold RSA
  permanently ruled out; thresholdable ECIES is the roadmap (`docs/hosted-keys-design.md`).
- Write quorum 2-of-3 by default, cluster-wide rollback below quorum, anti-entropy, read-repair.
  Keys are create-once-immutable, so replica divergence is a hard error, never auto-reconciled.
  Replication applies to hosted keys only — a copied FROST share would break the threshold scheme.
- RSA-OAEP on `aws-lc-rs`, not the pure-Rust `rsa` crate (RUSTSEC-2023-0071 Marvin side-channel
  still unpatched). All decryption failures collapse to one opaque error: no padding oracle.
- Operator guide `docs/hosted-keys.md`; design record `docs/hosted-keys-design.md`.

### Driver routing (completes v1)
- `rutli-`-prefixed key ids route to the cluster alongside `frost-`: generate, decrypt, symmetric
  encrypt/decrypt, public key, key info, delete.
- Capabilities negotiated from the cluster at startup instead of a hardcoded spec list; an
  unreachable or older cluster falls back to the configured expectation and says so.
- `frost.delegate = "none"` leaves no local backend: any call reaching it is a routing bug and fails
  loudly with the key id. Deliberately **no** fallback to a delegate when the cluster reports a key
  missing — that would silently re-create split custody.

### Export / import of hosted keys
- `rutli-cosigner export-key --key-id … --out FILE --passphrase-env VAR` and
  `import-key --in FILE --passphrase-env VAR`: offline, portable, passphrase-protected copy of one
  hosted key (Argon2id 64 MiB / t=3 → AES-256-GCM, header bound as AAD, 12-char minimum
  passphrase, file mode 0600, both log at WARN).
- Covers the two cases `backup` cannot: a lost seal master secret, and moving a key to another
  cluster or KMS. Import never overwrites differing material. FROST shares cannot be exported.
- Deliberately a CLI, not an RPC: an export RPC would turn a stolen driver cert from a rate-limited
  decrypt oracle into permanent possession of the key. Recovery procedure:
  `docs/disaster-recovery.md` §3d.

### Per-key decryption rate limit
- `hosted_keys.decrypt_rate_limit_per_min` (default 6000, `0` disables), enforced on the cosigner
  where the driver's signing journal cannot be bypassed. Bounds what a stolen driver cert is worth:
  a compromised encryption key reads retrospectively. Refusal is `RESOURCE_EXHAUSTED`; the driver
  does **not** fail over on it, since every node enforces the same ceiling.

### Software-backend sealed persistence (`software { dir, seal-secret-env }`)
- RSA-OAEP, AES and EC keys persisted as AES-256-GCM-sealed files (HKDF-keyed from an injected
  secret, atomic + fsynced writes, ciphertext bound to key id) and reloaded at startup. Fails loudly
  on a wrong secret instead of starting keyless. Incident runbook: `docs/disaster-recovery.md` §3b.

### Distribution and docs
- Published multi-arch cosigner image on GHCR (`linux/amd64`, `linux/arm64`); compose defaults to
  it; Helm chart at `deploy/helm/rutli-cosigner`; `publish-image.yml` pushes on `v*` tags.
- `docs/performance.md`: DevNet multi-region sign latency (~100 ms mean, ~70 ms p50 over 9k+ signs).
- `deploy/devnet/canton-hosted.conf`: end-to-end keyless participant config.
- Whole doc set reconciled against the code.

## Fixed
- `hosted_keys.write_quorum` was validated and documented but never passed to generate; the
  hardcoded 2 was used. Now honoured as a required field.
- gRPC ceremony fence accepted only `dkg` / `refresh`, so every hosted-key generate failed with
  `InvalidArgument`. `genkey` / `delkey` now recognised.
- Cluster-wide fence aborted on the first unreachable peer, so no write could complete with a node
  down. Unreachable peers are now skipped and quorum re-checked; a peer that answers with a
  conflict still aborts.
- Dead-peer detection matched only `UNAVAILABLE` / `DEADLINE_EXCEEDED`; a stopped cosigner surfaces
  as `UNKNOWN("transport error")`. Now matched narrowly on that shape.
- One unreadable key file (wrong seal secret, partial restore, corruption) no longer halts
  anti-entropy for every healthy key. Logged, counted in `rutli_unreadable_key_files_total`, skipped.
- CI: cert ownership for Linux containers (uid 10001), artifact-quota failure on a green job, and
  the TLS smoke pulling the published image instead of building the working tree. Smoke now dumps
  container state and logs on failure.
- Weekly conformance CI: Digital Asset prunes old `public-unstable` dpm snapshots, so the
  daml-components pin inside the Canton tag stopped existing; `publish-canton-deps.sh` now
  overrides it (`DAML_COMPONENTS_VERSION=upstream` restores Canton's pin). Clippy 1.99
  `double_must_use` in prost/tonic codegen exempted; `-D warnings` stays on for hand-written code.

## Security
- **Mesh Peer API was unauthenticated (critical; affects ≤ 0.2.1).** Only the Signer API enforced
  the client-cert allowlist. Every Peer RPC — the raw FROST rounds — accepted any cluster-CA-signed
  cert, including the driver's, and the 34-byte digest guard lived only in the leader. A holder of
  the driver cert could call `SignRound1` / `SignRound2` directly with an arbitrary message and
  aggregate a valid namespace signature offline, bypassing the leader, digest guard, ceremony fence
  and signing journal. Fixed by a mandatory-under-TLS `peer_allowlist` enforced on every Peer RPC,
  plus digest-length enforcement in `Node::sign_round2` so the Peer path fails closed even with a
  misconfigured allowlist.
- Stated cost of hosted keys: an attacker who extracts one encryption key gains retrospective read
  access to recorded traffic encrypted to it. The rate limit bounds online abuse; it does not change
  this.

## Verified
- Real Canton 3.5.6 participant on `backend = "frost"`, `hosted-keys = true`, `delegate = "none"`:
  initialises with zero local keys. Namespace, signing and sequencer-auth Ed25519 keys born via
  cluster DKG and threshold-signed; RSA-2048 encryption key generated as a hosted key and confirmed
  replicated to all three cosigners on disk.
- Write with one cosigner down completes at 2-of-3 quorum; a rebuilt cosigner re-acquires hosted
  keys via anti-entropy.

## Known limitations
- Hosted keys are replicated, not threshold-protected. Threshold ECIES is the planned path.
- Static leader, no Raft (by design: FROST sessions are independent).
- HSM backend validated only against SoftHSM.
- No third-party security audit yet.

## Not in 0.3.0 (landed on `main` after the tag)
- `4517d2f` pin the 0.3.0 image by digest across compose, k8s and Helm
- `504df09` conformance target bumped to Canton v3.6.1 (Scala 2.13.18; driver jar unchanged, 65/65 green)
- `0d9c74e` CI: Canton 3.6 needs an explicit protocol version under `CI=true`

Full detail: [CHANGELOG.md](../CHANGELOG.md) · GitHub release:
https://github.com/Stakecraft/rutli/releases/tag/v0.3.0

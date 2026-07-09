# Code-review fix brief

Actionable work list from the Jul 2026 code review of Rütli.
Execute in priority order. Do not expand scope beyond the items below.
Keep changes minimal, match existing style, and add/adjust tests for every behavioral fix.

**Status:** pre-production, not audited. These fixes harden the stack toward audit readiness;
they do not replace a third-party review.

---

## How to work this list

1. Fix one item (or a tightly related group) at a time.
2. Run the relevant tests after each item:
   - Rust: `cd frost && cargo test && cargo clippy --all-targets -- -D warnings`
   - JVM: `sbt driver/test`
3. Prefer fail-closed / recoverable errors over panics and silent overwrite.
4. Update docs in the same change when the fix contradicts existing prose.
5. Do not add new features, refactors, or drive-by cleanups.

---

## P0 — Correctness / key-safety (do first)

### P0.1 Ceremony lock for DKG and refresh

**Problem:** Concurrent `Signer.Dkg` / `Signer.Refresh` on the same `key_id` can leave
cosigners with different shares (last `keystore.save` wins). Signing sessions are UUID-isolated
and fine; ceremonies are not.

**Where:**
- `frost/cosigner/src/node.rs` — `dkg_part1` / `dkg_part3` / `refresh_part*`
- `frost/cosigner/src/orchestrator.rs` — `run_dkg` / `run_refresh`
- `frost/cosigner/src/service.rs` — `Signer::{dkg,refresh}`

**Fix:**
- Add a per-`key_id` ceremony lock (in-process mutex map is enough for v1; document that
  overlapping driver failover during DKG/refresh is still unsafe across leaders until a
  distributed lease exists).
- While a ceremony is in progress for `key_id`, reject a second DKG or refresh for that key
  with a clear error (e.g. `DaemonError::CeremonyInProgress`).
- Hold the lock from ceremony start through successful `part3` persist (or failure cleanup).

**Tests:**
- Add a cosigner cluster test that starts two overlapping DKG (or DKG+refresh) on the same
  `key_id` and asserts the second fails and on-disk shares remain consistent across nodes.

---

### P0.2 Refuse re-DKG over an existing key

**Problem:** `dkg_part1` does not check whether `key_id` already has a persisted share.
A second DKG silently overwrites. Refresh correctly requires an existing key; DKG should
refuse if one exists.

**Where:** `frost/cosigner/src/node.rs` (`dkg_part1`), optionally orchestrator/service for a
clear gRPC status.

**Fix:**
- If `keystore` already has `key_id`, return an error (e.g. `DaemonError::KeyExists`).
- Do not overwrite. Operators who need a new key must use a new `key_id` (namespace key is
  non-rotatable by Canton design).

**Tests:**
- DKG twice on the same `key_id` → second call fails; first share unchanged on disk.

---

### P0.3 Replace DKG/refresh `expect` panics with recoverable errors

**Problem:** Out-of-order / duplicate Peer RPCs (`part2` twice, `part3` without `part2`)
call `.expect(...)` and abort the process. Any mTLS cluster member can trigger this.

**Where:**
- `frost/core/src/dkg.rs` — `part2` / `part3`
- `frost/core/src/refresh.rs` — same pattern
- Call sites in `frost/cosigner/src/node.rs` / `service.rs` must map the new error to gRPC
  `Status` (invalid argument / failed precondition), not panic.

**Fix:**
- Replace `take().expect(...)` with `take().ok_or(...)` using a typed `CoreError` variant
  (e.g. `InvalidCeremonyState`).
- Never panic on bad Peer RPC ordering.

**Tests:**
- Unit tests: call `part2` twice / `part3` without `part2` → `Err`, process lives.
- Optional: Peer-level test via `LocalPeer` with out-of-order calls.

---

## P1 — Policy / durability guarantees

### P1.1 Fail-closed hash-chained audit log on sign

**Problem:** `RutliDriver` comments claim write-ahead durability (“never leak a signature the
log missed”), but `emitAudit` swallows append failures and still returns the signature.

**Where:** `driver/src/main/scala/com/stakecraft/rutli/RutliDriver.scala` (`audited` /
`emitAudit`)

**Fix:**
- When `auditLog` is configured, if `append` throws, **fail the operation** (do not return
  success). Prefer failing the `Future` with a non-retryable `KmsDriverException`.
- Plain `auditLogging` (logger-only) may stay best-effort.
- Update the comment so it matches behavior.

**Tests:**
- Unit/integration: inject a failing audit log (or unwritable path) and assert `sign`
  fails and no signature is returned to the caller.

---

### P1.2 Persist signing-journal rate-limit window across restart

**Problem:** `SigningJournal.recover()` rebuilds digest sets but not the rolling
`recent` timestamps, so a restart resets the rate limit.

**Where:** `driver/src/main/scala/com/stakecraft/rutli/guard/SigningJournal.scala`

**Fix:**
- On recover, rebuild `recent` from journal line timestamps within the configured window
  (or persist a compact sidecar — prefer deriving from existing JSONL if possible).
- Document the semantics in the class comment.

**Tests:**
- Write N signs under the limit, recreate journal from the same dir, assert the next sign
  within the window is still rate-limited.

---

### P1.3 Dedicated blocking ExecutionContext for FROST + approval polling

**Problem:** Blocking gRPC (`FrostBackend`) and `FileApprovalGate`’s `Thread.sleep` poll
run on Canton’s shared `ExecutionContext`, risking thread starvation under concurrent
gated signs or slow cluster RPCs.

**Where:**
- `driver/src/main/scala/com/stakecraft/rutli/backend/FrostBackend.scala`
- `driver/src/main/scala/com/stakecraft/rutli/policy/ApprovalGate.scala`
- Wire from `RutliDriverFactory.scala` (create/shutdown a bounded blocking pool)

**Fix:**
- Introduce a small dedicated blocking EC (or `ExecutionContext.fromExecutor` with a
  bounded thread pool) for FROST RPCs and approval waits.
- Shut it down in `RutliDriver.close()` / factory lifecycle.
- Keep the Canton EC for non-blocking composition.

**Tests:**
- Existing approval + FROST ITs still pass. Optional: assert factory creates/closes the pool
  without leaking threads (lightweight).

---

## P2 — Daemon hardening

### P2.1 Wire `Cosigner::abort` on failed sign rounds

**Problem:** `abort()` exists in `frost/core/src/session.rs` but is never called. Partial
sign failures leave orphaned RAM nonces in `pending`.

**Where:** `frost/cosigner/src/orchestrator.rs` (`sign`), Peer/LocalPeer plumbing if needed.

**Fix:**
- On round-2 failure or threshold shortfall after round-1, abort the session on peers that
  minted commitments (best-effort).
- Do not weaken nonce-burn semantics.

**Tests:**
- Force a round-2 failure; assert `pending` does not retain the session id on the leader
  node (and ideally peers).

---

### P2.2 Prune failed DKG/refresh session maps

**Problem:** `dkg_sessions` / `refresh_sessions` are only removed on successful `part3`.
Failed ceremonies leak entries; Peer access can amplify memory use.

**Where:** `frost/cosigner/src/node.rs`

**Fix:**
- On `part2`/`part3` error, remove the ceremony id from the map (or TTL-prune stale entries).
- Ensure P0.3 errors also clean up.

**Tests:**
- Trigger a failed ceremony; assert session map size does not grow unbounded across repeats.

---

### P2.3 Keystore `fsync` before rename

**Problem:** Share saves use tmp + rename but do not fsync the file (and ideally the
directory). Nonce store is more durable than the keystore.

**Where:** `frost/cosigner/src/keystore.rs` (`save`)

**Fix:**
- After writing the temp file, `sync_all` the file; after rename, fsync the parent directory
  (same pattern as `nonce_store.rs`).

**Tests:**
- Existing save/load / sealing tests still pass. No need for a crash-injection harness unless
  easy.

---

### P2.4 Restrict who can call Signer ceremonies (minimal RBAC)

**Problem:** Any mTLS cluster member can call `Signer.Dkg` / `Refresh` / `Sign` on any node.

**Where:** `frost/cosigner` TLS / service layer; config

**Fix (minimal, pragmatic):**
- Prefer a config allowlist of client cert CNs/SANs allowed to call `Signer` RPCs
  (driver identity), while Peer mesh remains cluster-member mTLS.
- If full cert-identity binding is too large for this pass, document the gap and at least
  reject `Dkg`/`Refresh` when a ceremony lock would be the only control — but prefer a real
  allowlist if straightforward with tonic interceptors.

**Tests:**
- Unit/config test for allowlist matching. Integration optional.

---

## P3 — Docs drift (same PR as related code, or one docs-only PR)

Fix these so operators are not misled. Paths under `docs/` and deploy READMEs:

| Location | Wrong claim | Correct claim |
|---|---|---|
| `docs/architecture.md` | “mTLS is a follow-up” | mTLS implemented (mesh + driver) |
| `docs/architecture.md` / `docs/phase-2-frost.md` | Raft leader election | Static leader + driver-side failover; Raft deliberately skipped |
| `deploy/frost/README.md` | Refresh still a production TODO | Refresh shipped (`Signer.Refresh` / CLI) |
| `SECURITY.md` | Audit log “lands in Phase 3” | Hash-chained audit log shipped |
| `docs/key-ceremony.md` | “per-cosigner seal secret” | Deploy uses one shared master (`RUTLI_SEAL_SECRET`); per-node DEK via HKDF |
| `docs/phase-2-frost.md` | `frost { endpoint, ... }` singular | `endpoints` (plural) as in `canton-frost.conf` |
| Stale “next steps” / Raft checklist in phase-2 | Lists unfinished gRPC/Raft/deploy | Trim or mark done |

Also refresh stale comments in:
- `driver/.../RutliConfig.scala` (“frost … not yet implemented”)
- `driver/.../RutliDriver.scala` header (“later phases” for approval/audit/journal)

---

## P4 — Nice-to-have (only after P0–P2)

- Reject / warn on FROST `Sign` messages that are not 34 bytes (Canton digest contract);
  keep configurable if tests need other lengths.
- Cap gRPC payload sizes for Peer JSON maps.
- `HsmBackend`: remove provider on `close`; avoid Ed25519 probe leaving orphan token keys.
- Confidential `configWriter`: redact TLS private-key paths; add a redaction unit test.
- CI: add a TLS compose smoke job (or document why not yet); drop `cargo test \|\| cargo test`
  unlocked fallback if lockfile is authoritative.
- Add `deploy/devnet/canton-frost-tls.conf` example matching `docker-compose.tls.yml`.

---

## Out of scope (do not implement in this pass)

- Third-party crypto audit
- Threshold ECDSA / DKLS (Phase 4)
- Networked RTS repair ceremony (primitive may stay; backup/restore remains the DR path)
- Shamir cold-backup productization
- Full MPC-of-HSM / enclave sealing
- Raft consensus layer

---

## Suggested PR breakdown

1. **frost-ceremony-safety** — P0.1 + P0.2 + P0.3 + P2.1 + P2.2  
2. **driver-audit-journal** — P1.1 + P1.2  
3. **driver-blocking-ec** — P1.3  
4. **keystore-fsync** — P2.3  
5. **docs-drift** — P3 (or fold into the PRs that make claims true)  
6. Optional follow-ups — P2.4, P4

---

## Acceptance checklist

- [ ] Overlapping DKG/refresh on same `key_id` is rejected; shares stay consistent
- [ ] Re-DKG on existing `key_id` fails closed
- [ ] Out-of-order DKG/refresh Peer calls return errors (no process panic)
- [ ] Configured hash-chained audit: append failure fails `sign`
- [ ] Rate limit survives journal recover/restart
- [ ] FROST + approval blocking work does not use Canton’s primary EC unbounded
- [ ] `cargo test` + `cargo clippy -D warnings` + `sbt driver/test` green
- [ ] Doc claims for mTLS / Raft / refresh / audit / seal-secret match the code
`)
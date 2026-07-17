# Changelog

All notable changes to Rütli are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [0.2.1] — 2026-07-17

Patch on 0.2.0: cluster-wide ceremony fencing, Signer digest enforcement, TLS CI smoke, sealing
migration, k8s/ops hardening — plus the metrics and soak harness landed right after the 0.2.0 tag.

### Security & robustness
- **Cluster-wide refresh/DKG fence:** before any ceremony crypto, the leader takes the per-key
  guard on every peer (`CeremonyFence`), so no node can start a new sign mid-ceremony. The reverse
  fence also applies — if any peer still holds in-flight sign nonces for that key, the fence fails
  (`SignInProgress`) and is rolled back cluster-wide. Closes the per-node fence gap left after the
  second hardening pass.
- **Canton digest length enforced at Sign:** the Signer API rejects messages that are not exactly
  34 bytes (Canton's `0x1220 ‖ sha256(tx)` wire contract), so a miswired client cannot mint
  signatures over arbitrary payloads through the cluster.
- **Plaintext share migration at startup:** with sealing enabled, any leftover plaintext share
  files are re-sealed immediately on cosigner start (not only on the next write). Seal-secret
  minimum length raised to 32 chars.
- **CI TLS smoke:** PR CI brings up the mTLS + sealed compose cluster and runs Health / DKG /
  Sign through the driver cert (plaintext client must be refused).
- **K8s hardening:** required pod anti-affinity, zone topology spread, PDB (`minAvailable: 2`),
  image tag `0.2.1` (digest-pin guidance), narrower NetworkPolicy (namespace + pod labels),
  example backup/refresh CronJobs.
- **ApproveCli** prints `digest` / `nonce` before signing an approval so humans can verify the
  bound operation. Audit engagement checklist in `docs/audit-prep.md`.

### Added
- **Prometheus metrics** (`metrics_listen`): opt-in plaintext `/metrics` endpoint per cosigner —
  sign throughput/latency/outcomes, ceremony outcomes, round-1 peer skips (quorum-margin canary),
  sign aborts, and an in-flight-sessions gauge. Counts and latencies only; never key material,
  digests, or session ids. Wired into the TLS compose (host ports 9201–9203) and the k8s bundle
  (port `metrics`/9200, scrape annotations, NetworkPolicy ingress for `rutli.io/scraper` pods).
  Alert rules + Grafana dashboard in `deploy/monitoring/`; runbook in `docs/observability.md`.
- **Testnet-soak harness** (`deploy/soak/`): one-command stack — the mTLS/sealed cosigner cluster
  (compose `include:`) plus Prometheus (rules loaded, 45-day retention) and Grafana (dashboard
  pre-provisioned) — a daily PASS/FAIL gate (`soak-check.sh`), and a Splice DevNet validator
  overlay (`validator/`): thin derived canton-participant image injecting `rutli-driver.jar` via
  `EXTRA_CLASSPATH` + an `ADDITIONAL_CONFIG_*` compose overlay wiring `crypto.provider = kms` to
  the cluster — no Splice images forked. Runbook with drill calendar and exit criteria in
  `docs/testnet-soak.md`. Whole KMS half verified live: DKG + threshold signs from every leader,
  a sign with one cosigner down, and a mid-traffic refresh (group key unchanged) — all through
  the mTLS + allowlist path, all visible in Prometheus/Grafana, soak gate green.
- **frost/.dockerignore**: the cosigner image build no longer copies the multi-GB host `target/`
  into its context.

## [0.2.0] — 2026-07-17

Devnet-hardened release: encryption-at-rest for shares, proactive refresh, M-of-N signing
approval, tamper-evident audit, disaster recovery, Docker/k8s deployment — plus two full
code-review hardening passes (all findings fixed and regression-tested). Still pre-audit;
see Status in the README.

### Security & robustness (code-review hardening)
- **Ceremony safety:** DKG/refresh for a key are serialized by a per-key guard (no split-brain
  shares); DKG refuses to overwrite an existing key (can't destroy the non-rotatable namespace key);
  out-of-order ceremony RPCs return errors instead of panicking (closes a remote DoS); the driver no
  longer auto-retries DKG on timeout.
- **Ceremony ownership (split-brain after a crash):** an orphaned ceremony guard is preempted only
  after a timeout, and preemption now also drops the dead leader's leftover session state, so a
  superseded DKG/refresh can no longer persist a share — `part2`/`part3` re-check ownership before
  writing. A new sign is fenced out while a ceremony holds the key. Regression-tested.
- **Sign session hygiene:** a duplicate `round1` for a still-in-flight session id is refused instead
  of silently overwriting live nonces; and when a signature gives up (round-2 failure or a
  threshold shortfall after round 1) the leader best-effort aborts the session on every quorum
  member, freeing their round-1 nonces immediately rather than waiting out the pending-TTL sweep.
- **Config redaction:** the confidential config writer (used when Canton echoes driver config back)
  now also redacts the TLS private-key path, not just the HSM PIN.
- **Audit:** the hash-chained log is now genuinely fail-closed — a successful op that can't be logged
  fails rather than returning an unlogged signature.
- **Signing journal:** the per-key rate limit survives a restart (rebuilt from the persisted window).
- **Signer API allowlist:** client-cert CN allowlist so only the driver (not a cosigner cert) can
  request signatures — **required whenever TLS is enabled** (startup fails without it); optional
  only for plaintext dev setups.
- **Durability/isolation:** keystore share writes fsync file + directory; blocking FROST/approval
  work runs on a dedicated bounded pool (not Canton's EC); in-flight sign sessions are TTL-pruned.
- **Docs:** corrected stale claims (mTLS/Raft/refresh/audit/seal-secret) to match the code.

### Added
- **Deployment: Docker & Kubernetes.** A production-flavored compose
  (`deploy/frost/docker-compose.tls.yml`, mutual TLS + sealed shares) alongside the dev one, and a
  full k8s bundle (`deploy/k8s/`: StatefulSet with per-pod durable PVCs, headless service, mTLS,
  sealed shares via a shared HKDF master secret, NetworkPolicy locking the signing port to the mesh
  + the Canton driver, non-root/read-only-rootfs, anti-affinity) with a runbook covering image
  build, cert/secret creation, DKG, and wiring the Canton driver. The mTLS mesh (cosigner↔cosigner
  and driver↔cosigner) is now verified end-to-end.
- **Signing journal** (`signing-journal`): a persistent, per-key, append-only record of every
  digest signed (fsynced before the signature is released), so there is a complete history for
  equivocation *detection* and forensics; repeats of an already-signed digest are flagged and
  counted (never blocked — Canton legitimately re-signs, and the driver only sees an opaque digest
  with no height/round, so semantic double-sign protection is impossible at this layer and is not
  claimed). Optional per-key rate limit (`max-per-window`) as a runaway/compromise brake. Rebuilds
  its state from disk on restart. Records the digest only, never key material.
- **Disaster recovery**: `rutli-cosigner backup`/`restore` copy a node's sealed shares to/from cold
  storage (encrypted at rest, so backups carry no plaintext key material), and the Repairable
  Threshold Scheme primitive (`rutli-frost-core::repair`) rebuilds a lost share from `t` survivors
  with no backup and no key reconstruction — group key unchanged. Full runbook (single-node, disk
  loss, below-threshold catastrophe, compromise, and the pre-go-live checklist) in
  `docs/disaster-recovery.md`. Tested: a wiped node recovers from backup and the cluster signs;
  a lost share is repaired from helpers and signs under the same group key.
- **M-of-N signing approval** (`approval { ... }` policy): high-value keys (by key-id prefix) are
  gated — a `sign` is held until a threshold of named approvers each drop a valid Ed25519 signature
  over the request into a shared inbox, or it fails non-retryably at timeout. A random per-request
  nonce prevents replay; each approver counts at most once; signatures are verified against the
  configured keys (cryptographic separation of duties, not a counter). Approver CLI:
  `com.stakecraft.rutli.policy.ApproveCli` (`keygen`, `approve`). Default is no gating so nodes
  bootstrap unchanged. Outcomes recorded in the hash-chained audit log. See `docs/approval-quorum.md`.
- **Proactive share refresh** (`Signer.Refresh` RPC + `rutli-cosigner refresh --key-id …`):
  re-randomizes every cosigner's share via a dealer-free DKG-style ceremony while keeping the
  group public key — and therefore the Canton node identity — unchanged. Shares stolen before a
  refresh become useless afterwards, so an attacker must compromise ≥ t nodes within one refresh
  epoch. Every node verifies the group key did not drift before persisting (a diverged refresh
  aborts). Old + new shares cannot combine to sign (tested).
- **Share sealing** (`share_seal.secret_env`): key shares are stored as AES-256-GCM envelopes,
  keyed per node via HKDF-SHA256 from an operator-injected master secret (env var from a secret
  manager — never on disk). A copied disk or backup of `data_dir` no longer yields usable shares.
  Legacy plaintext shares remain readable for migration and are re-sealed on next write; a sealed
  share is refused loudly when sealing is unconfigured or the secret is wrong. Software seam for
  future enclave/HSM sealing.
- **Tamper-evident audit log** (`audit-log-path`): every key operation appends a hash-chained JSONL
  entry (`hash = SHA-256(prev ‖ entry)`), fsynced before the result returns; the chain resumes
  across restarts and is verifiable offline (`HashChainedAuditLog.verify`). Any edit, reorder, or
  deletion breaks the chain at the exact entry. Entries carry operation metadata only — never key
  material or signatures. First piece of the Phase 3 institutional-controls layer.
- **Driver-side failover** across the FROST cosigner roster (`frost.endpoints`): any live cosigner
  leads a request; a node is skipped only when unreachable, never masking a real error. Removes the
  single-leader availability gap without a consensus layer (FROST sessions are independent — no
  replicated log to keep consistent, so Raft would buy nothing here).

### Fixed
- **mTLS cert model**: cosigner certs now carry a shared `rutli-cosigner` SAN, matched by the single
  global `tls.domain` used for every peer dial — so the mutual-TLS mesh actually verifies across
  Docker service names and k8s pod DNS alike (the previous per-node `domain` could not match all
  peers). `gen-frost-certs.sh` and the TLS configs updated; TLS configs also enable share sealing.

## [0.1.0] — 2026-07-03

First tagged release. **Devnet-grade, pre-production** — verified end-to-end against a real Canton
node and a live FROST cluster, but not yet hardened (no Raft, shares stored as plaintext JSON) and
not audited. Do not place production authority keys behind it.

### Added
- **Canton KMS Driver** (`driver/`) implementing the v1 KMS Driver SPI — plugs into an unmodified
  Canton 3.5.x node via `crypto.provider = kms`. Passes the upstream conformance suite (32 tests).
- **Backends** behind a common `KmsBackend` seam:
  - `software` — BouncyCastle, integration testing only.
  - `hsm` — PKCS#11 (SunPKCS11); EC P-256/P-384 signing, RSA-2048 OAEP decryption, AES-GCM,
    key persistence. Verified against SoftHSM.
  - `frost` — routes the Ed25519 namespace/identity key to an external FROST cosigner cluster
    (threshold signing; the whole key never exists on any machine), delegates all other keys to
    the HSM/software backend.
- **FROST cluster** (`frost/`, Rust):
  - `rutli-frost-core` — DKG, two-round signing, crash-safe single-use nonce store.
  - `rutli-cosigner` — gRPC cosigner daemon (Signer + Peer services), DKG/sign orchestration.
- **Mutual TLS** on both hops (mesh + driver→cluster) against one cluster CA.
- Per-operation audit logging; wire-contract capture.
- Deployment: `deploy/frost` (Docker compose 2-of-3, plaintext + TLS configs), `deploy/devnet`
  (Canton node on software or FROST backend). Cert + key tooling in `scripts/`.

### Verified
- Real Canton participant boots on `backend = "frost"`: all Ed25519 node keys born via cluster DKG,
  identity topology threshold-signed by a 2-of-3 quorum and accepted by Canton's verifier.
- FROST output passes strict `ed25519-dalek` and stock JDK Ed25519 verification.
- Signing survives one downed cosigner; nonce reuse refused across restarts; below-threshold
  quorums cannot sign; mTLS rejects uncertified clients.

### Known limitations / not yet done
- Static leader (no Raft leader election).
- Shares stored as plaintext JSON (no enclave/HSM sealing).
- No proactive share refresh; DR procedures documented but not automated.
- No M-of-N approval engine / RBAC / hash-chained audit log (Phase 3).
- HSM backend validated only against SoftHSM.
- No third-party security audit.

[0.2.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.2.0
[0.1.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.1.0

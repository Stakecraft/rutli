# Changelog

All notable changes to Rütli are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Driver-side failover** across the FROST cosigner roster (`frost.endpoints`): any live cosigner
  leads a request; a node is skipped only when unreachable, never masking a real error. Removes the
  single-leader availability gap without a consensus layer (FROST sessions are independent — no
  replicated log to keep consistent, so Raft would buy nothing here).

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

[0.1.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.1.0

# Security policy

This project manages **authority key material for Canton Network / Splice nodes** — the highest-value
secret a node holds. Treat every change as security-critical.

## Status

Pre-release, **unaudited**. The Phase 0 `SoftwareBackend` performs key operations in-process with
software crypto and is for integration testing only. **Never place production namespace/identity,
signing, or encryption keys behind the `SoftwareBackend`.** Production requires an HSM/enclave
(Phase 1) or the FROST MPC cluster (Phase 2).

## Reporting a vulnerability

Do **not** open a public issue for security reports. Use GitHub private vulnerability reporting:
**[Security → Report a vulnerability](https://github.com/Stakecraft/rutli/security/advisories/new)**.
Include a description, reproduction, and impact. We aim to acknowledge within 72 hours.

## Design invariants (must not be violated)

- Private keys never leave the KMS boundary; the Canton process only ever sees public keys and
  signatures (external key storage mode).
- No key type is served by a weaker backend than its policy requires (routing is enforced, not
  advisory).
- FROST signing: fresh per-session nonce commitments, never reused; good CSPRNG; strict per-session
  nonce state; canonical encoding of the group public key and `R` enforced at the boundary.
- Threshold **decryption** is not attempted with bespoke crypto — encryption keys stay in an HSM.
- Audit log entries are append-only and tamper-evident (hash-chained) once Phase 3 lands.

## Scope reminder

The Canton **namespace root key cannot be rotated**. There is no recovery from its loss beyond
restore-from-backup, and no recovery from its compromise beyond node/SV offboarding. Backup, share
refresh, and key-ceremony procedures are in scope precisely because the blast radius is total.

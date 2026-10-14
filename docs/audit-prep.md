# Audit preparation checklist

Pre-audit pack for a third-party review of Rütli (threshold KMS for Canton namespace keys).
Status: **pre-production, not yet audited**. Use this as the engagement brief and evidence index.

## In scope (recommend)

| Area | Paths | Why |
|---|---|---|
| FROST core | `frost/core` (DKG, session, nonce_store, refresh, repair) | Crypto integration + nonce hygiene |
| Cosigner daemon | `frost/cosigner` (orchestrator, node, keystore, seal, tls, service) | Ceremony races, mTLS, sealing, Signer allowlist |
| Scala driver | `driver/.../RutliDriver`, `FrostBackend`, `ApprovalGate`, audit, journal | Policy fail-closed, failover, Canton SPI |
| Wire contract | `docs/wire-contract.md`, Signer 34-byte check | What Canton actually sends |
| Deploy | `deploy/frost` (TLS), `deploy/k8s`, `deploy/soak` | Operator threat model |

## Out of scope (unless requested)

- Upstream `frost-ed25519` math (cite the NCC Group assessment of Zcash FROST, Oct 2023, v0.6.0)
- Canton itself / Splice validator business logic
- Threshold ECDSA (Phase 4 — not shipped)
- Networked RTS repair ceremony (primitive only; DR is backup/restore)

## Evidence already in-repo

- [ ] Unit + cluster tests: `cd frost && cargo test && cargo clippy --all-targets -- -D warnings`
- [ ] Driver tests: `sbt driver/test`
- [ ] CI TLS smoke: `scripts/ci-frost-tls-smoke.sh` (also `.github/workflows/ci.yml` job `frost-tls-smoke`)
- [ ] Soak harness + runbook: `deploy/soak/`, `docs/testnet-soak.md`
- [ ] Hardening history: `CHANGELOG.md` `[0.2.0]` + `[Unreleased]` security sections
- [ ] Ceremony / DR / approval runbooks: `docs/key-ceremony.md`, `docs/disaster-recovery.md`, `docs/approval-quorum.md`

## Threat-model bullets for the auditor

1. **No single host holds the namespace private key** — DKG; shares sealed at rest; mTLS mesh.
2. **Nonce reuse must be impossible** across crash/restart (burn-before-share + fsync markers).
3. **Ceremonies must not split shares** — per-key guard, ownership on part2/part3, cluster-wide fence, reverse fence vs in-flight signs.
4. **Signer API is not “any cluster cert”** — `signer_allowlist` required when TLS is on.
5. **Compliance controls** — fail-closed hash-chained audit; M-of-N Ed25519 approval; signing journal (detection, not semantic double-sign prevention).
6. **Honest limits** — namespace key non-rotatable; journal cannot see height/round; software sealing ≠ HSM/enclave.

## Suggested engagement shape

1. Design / threat-model review (1–2 days) against this doc + `docs/architecture.md`
2. Code review of tables above (focused, not whole monorepo dump)
3. Dynamic testing: TLS smoke + soak drills (failover, mid-traffic refresh, backup/restore)
4. Report with severity; track remediations in CHANGELOG before any mainnet authority key

## Operator go-live gates (post-audit)

- [ ] External report accepted; critical/high findings closed
- [ ] Sustained Splice DevNet soak meeting `docs/testnet-soak.md` exit criteria
- [ ] Key ceremony witnessed (`docs/key-ceremony.md`)
- [ ] DR drill completed (backup + restore of one share)
- [ ] Production deploy: digest-pinned image, required anti-affinity, PDB, TLS + allowlist + sealing

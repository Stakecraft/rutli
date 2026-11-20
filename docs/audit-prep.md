# Audit preparation checklist

Pre-audit pack for a third-party review of Rütli (threshold KMS for Canton namespace keys).
Status: **pre-production, not yet audited**. Use this as the engagement brief and evidence index.

## In scope (recommend)

| Area | Paths | Why |
|---|---|---|
| FROST core | `frost/core` (dkg, session, nonce_store, refresh, repair, dealer) | Crypto integration + nonce hygiene |
| Cosigner daemon | `frost/cosigner` (orchestrator, node, keystore, seal, tls, service, intent, sign_policy, journal) | Ceremony races, mTLS, sealing, Signer allowlist, cosigner-side signing policy |
| Hosted keys | `frost/cosigner` (hosted, wrap, sync, export, ratelimit, verify_hosted) | Replicated whole keys: wrapping, quorum, anti-entropy, tombstones |
| Split ceremony | `frost/cosigner/src/bin/rutli-dealer.rs`, `frost/cosigner` (share_delivery, share_import, request_auth, verify_key), `frost/canton-key` | Import of an existing Canton key; dealer hygiene |
| Scala driver | `driver/.../RutliDriver`, `FrostBackend`, `FrostIntentSigner`, `CantonEcies`, `ApprovalGate`, audit, journal | Policy fail-closed, failover, Canton SPI |
| Wire contract | `docs/wire-contract.md`, Signer 34-byte check | What Canton actually sends |
| Deploy | `deploy/frost` (TLS), `deploy/helm`, `deploy/k8s` | Operator threat model |

## Out of scope (unless requested)

- Upstream `frost-ed25519` math (cite the NCC Group assessment of Zcash FROST, Oct 2023, v0.6.0)
- Canton itself / Splice validator business logic
- Threshold ECDSA (Phase 4 — not shipped)
- Networked RTS repair ceremony (primitive only; DR is backup/restore)
- The `hsm` and `software` delegate backends (`HsmBackend.scala`, `SoftwareBackend.scala`,
  `SoftKeyStore.scala`); the audited shape is `delegate = "none"` with cluster-hosted keys

## Evidence already in-repo

- [ ] Unit + cluster tests: `cd frost && cargo test && cargo clippy --all-targets -- -D warnings`
- [ ] Driver tests: `scripts/publish-canton-deps.sh v3.6.1` (the KMS Driver API is not on Maven
  Central), then `sbt driver/test`
- [ ] CI TLS smoke: `scripts/ci-frost-tls-smoke.sh` (also `.github/workflows/ci.yml` job `frost-tls-smoke`)
- [ ] Mutation testing of the signing path: `scripts/mutants.sh`, weekly report `mutants-summary.json`
  (`.github/workflows/mutants.yml`, `docs/mutation-testing.md`)
- [ ] End-to-end ceremony scripts in CI (`.github/workflows/e2e.yml`: split, carry, ECIES hosted keys), and the whole migration procedure on Canton 3.6.1 (`scripts/e2e-migration.sh`)
- [ ] Property tests and micro-benchmarks (`frost`, `scripts/bench.sh`), the load generator and the cluster suite (`docs/load-testing.md`, `docs/cluster-suite.md`), with a dated run in `docs/performance.md`
- [ ] The production profile (`docs/production-profile.md`): every setting the threat model assumes, and `rutli-cosigner check-config` to read a config against it
- [ ] Release verification: the image signature and attestation (`SECURITY.md`, "Verify the image"), from 0.5.0
- [ ] Soak harness + runbook: `deploy/soak/`, `docs/testnet-soak.md`
- [ ] Hardening history: `CHANGELOG.md` security sections, `[0.2.0]` and `[0.4.0-rc.1]` to
  `[0.4.0-rc.6]`, `[0.4.0]`, `[0.4.1]` and `[Unreleased]` (the hardening for 0.5.0); `docs/security/internal-review-2026-10.md`, `docs/security/threat-model.md`
- [ ] Ceremony / DR / approval runbooks: `docs/key-ceremony.md`, `docs/ceremonies.md`, `docs/split-ceremony.md`, `docs/disaster-recovery.md`, `docs/approval-quorum.md`

## Threat-model bullets for the auditor

1. **No single host holds a FROST private key** (namespace, protocol signing, sequencer auth) — DKG,
   or for an imported key the offline dealer once; shares sealed at rest per node; mTLS mesh.
2. **Nonce reuse must be impossible** across crash/restart (burn-before-share + fsync markers).
3. **Ceremonies must not split shares** — per-key guard, ownership on part2/part3, cluster-wide fence, two-phase staging (signing is not fenced since 0.4.0-rc.4: part 3 only stages, commit evicts the signing state); client-signed ceremony intents (`require_ceremony_intent`), and since 0.4.0-rc.6 a ceremony bound to the leader that fenced it, with a durable fence mark per id.
4. **Signer API is not “any cluster cert”** — `signer_allowlist` required when TLS is on; cosigners pin each other's TLS keys (from 0.5.0, required with TLS), so a certificate minted under the cluster CA is not a peer; a sign session belongs to the peer that opened it.
5. **Compliance controls** — fail-closed hash-chained audit; M-of-N Ed25519 approval; signing journal (detection, not semantic double-sign prevention); approvals, journal and rate limits also enforced by every cosigner on a driver-signed intent (`require_intent`, on by default with TLS from 0.5.0).
6. **Honest limits** — namespace key non-rotatable; journal cannot see height/round; software sealing ≠ HSM/enclave; hosted keys are replicated whole keys, not threshold.

## Suggested engagement shape

1. Design / threat-model review (1–2 days) against this doc, `docs/security/threat-model.md` and `docs/architecture.md`
2. Code review of tables above (focused, not whole monorepo dump)
3. Dynamic testing: TLS smoke + soak drills (failover, mid-traffic refresh, backup/restore)
4. Report with severity; track remediations in CHANGELOG before any mainnet authority key

## Operator go-live gates (post-audit)

- [ ] External report accepted; critical/high findings closed
- [ ] Sustained Splice DevNet soak meeting `docs/testnet-soak.md` exit criteria
- [ ] Key ceremony witnessed (`docs/key-ceremony.md`)
- [ ] DR drill completed (backup + restore of one share)
- [ ] Production deploy: digest-pinned image (signature verified), required anti-affinity, PDB, TLS + allowlist + sealing + peer key pins, `profile: production` and `check-config` exit 0 on every node
- [ ] **Each cosigner in a separate cluster or cloud account**, administered by different people
  (below). One cluster under one administration is one trust domain, and its administrator holds
  every share ([threat model](security/threat-model.md#trust-domains), decision P10). No authority
  key goes live with two cosigners in one trust domain.

### What counts as a separate trust domain

The test: no one person, team, credential or automation can get at the shares of two cosigners
without a second party. With 2-of-3, two cosigners in one domain hold the threshold, so the rule is
one cosigner per domain, not "fewer than `t` per domain". For each cosigner, check:

| Dimension | Separate | Not separate |
|---|---|---|
| Control plane | Its own Kubernetes cluster (own API server, etcd and cluster-admin), or its own host outside any shared orchestrator | Namespaces, node pools, dedicated nodes, taints or anti-affinity in one cluster; virtual clusters on one host cluster; one cluster spread over several zones or regions |
| Cloud account | Its own account, project or subscription, whose admins are not the other cosigners' admins | Separate clusters in one account or project; an organisation-level admin or break-glass role that can take over every account without a second party (restrict and alert on it, or count it as one domain) |
| Credentials | Its own kubeconfig and cloud credentials, seal bundle, node TLS key, secret store, and backup destination with its own write and read credentials | A CI/CD pipeline, GitOps controller or deploy key with cluster-admin (or Secret read) on several clusters; one secret manager or vault path readable by one principal; one backup bucket or one backup credential for several nodes |
| Operator | Different people administer each cosigner; nobody holds admin on two (as in [key-ceremony.md](key-ceremony.md), "No operator controls two shares") | One person or one on-call group with admin rights on several clusters or accounts, even if they are separate clusters |

Shared on purpose, and fine: the participant (driver), which talks to every cosigner with the signer
role only; the digest-pinned image; read-only monitoring that scrapes metrics without exec or Secret
access. The mesh CA key can impersonate any node on the mesh: keep it offline under the ceremony
lead's custody, never with one cosigner's operator.

Regions and zones are for availability, not trust. Cluster-hosted keys (ECIES, RSA, AES) are whole
replicas on every node ([hosted-keys.md](hosted-keys.md)), so separation protects the FROST shares,
not those keys: one node's compromise exposes them wherever it sits.

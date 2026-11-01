# Rütli

**Open-source threshold key management for Canton Network & Splice node authority keys.**

[![CI](https://github.com/Stakecraft/rutli/actions/workflows/ci.yml/badge.svg)](https://github.com/Stakecraft/rutli/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Rütli keeps a Canton node's most dangerous secret — its **namespace / identity key** — safe by never
letting any single machine hold it. Instead of one server storing the key, a small cluster of
machines each hold a *fragment*; signing happens by cooperation, and the whole key never exists
anywhere. It plugs into an **unmodified Canton node** as a KMS driver, so there's nothing to fork.

Think **[Horcrux](https://github.com/strangelove-ventures/horcrux) for Canton**: the node holds no
key; a `t`-of-`n` quorum signs on its behalf.

> *Named after the [Rütli meadow](https://en.wikipedia.org/wiki/R%C3%BCtli), where in 1291 the three
> founding cantons swore the oath that created the Swiss Confederation — a federation of peers with
> no single point of authority. Same idea, applied to your keys.*

**New here? → [QUICKSTART.md](QUICKSTART.md)** gets you from `cargo test` to a live Canton node with
its namespace key in a threshold cluster in three copy-paste steps.

---

## Why it matters

A Canton node's **namespace key** defines its on-chain identity and authorizes every topology change.
If it leaks, an attacker controls the node. If it's lost, every party and Canton Coin balance hosted
under that node is gone — permanently. And it **cannot be rotated**: there is no "issue a new one".

Today the ways to protect it are all compromises: Canton's built-in KMS is **cloud-only** (AWS/GCP,
Enterprise Edition); the self-hosted alternatives are **proprietary** (Blockdaemon Builder Vault, MPCH
Stronghold), and custody platforms (Fireblocks, Dfns) protect party and asset keys rather than the
node's own. None is open-source, self-hosted, *and* real threshold-MPC — one a bank could run and
certify entirely inside its own SOC 2 / ISO 27001 / DORA boundary.

Rütli is that missing option — **the "Web3Signer/Teku of Canton."**

## How it works

```
Canton node  (unmodified)
   │  sends "sign this" — a 34-byte digest
   ▼
Rütli driver  (a jar inside the node)
   • policy · M-of-N approval · audit log
   • routes each key to its backend
   │  runs the threshold signing rounds
   ▼
FROST cluster  (t-of-n cosigners)
   • cosigner A · B · C — one share each
   • separate host / account / region
   • the full key is never assembled
   │  returns a 64-byte Ed25519 signature
   ▼
To Canton it's a normal Ed25519 signature —
it can't tell it was threshold-signed.
```

Canton thinks it's talking to an ordinary KMS. The driver forwards each *"sign this digest"* to the
cluster, which produces a **standard Ed25519 signature** — byte-for-byte indistinguishable from a
single-signer one, so Canton's verifier accepts it unchanged. The key is *born distributed* (no
trusted dealer) and never assembled, not even for an instant.

Behind the driver, a swappable backend routes each key to the right protection:

| Canton key | Backend | Isolation |
|---|---|---|
| **Namespace / identity** (Ed25519) | **FROST MPC cluster** | `t`-of-`n`, one share per host/account/region |
| Protocol signing / sequencer auth (Ed25519) | **FROST MPC cluster** (or HSM) | `t`-of-`n`, like the namespace key |
| Encryption (ECIES P-256; RSA-OAEP also supported) · symmetric (AES) | **cluster-hosted** (or HSM) | sealed whole key per node — *not* threshold |

**What "cluster-hosted" means, precisely.** Canton's encryption and symmetric keys can now live in
the cluster too, so a participant needs **no HSM and no local key state**. But these are *replicated
whole keys*, not threshold shares: generated on one cosigner, sealed at rest per node, copied to the
others, and any node can serve a decrypt. The win is **relocation** — key material leaves the busy,
internet-adjacent Canton host for three hardened, single-purpose nodes — not a threshold property.
The security tier matches the recoverability tier: the one key Canton *cannot* rotate (the namespace
key) stays in real 2-of-3 MPC; the keys that get only replication are exactly the ones Canton *can*
rotate under it. And the cost, stated plainly: an attacker who extracts one encryption key gains
**retrospective** read access to any recorded traffic encrypted to it — rotation fixes the future,
not the past. Threshold RSA is permanently out of scope; the reasoning, and the roadmap to threshold ECIES, are in [docs/hosted-keys.md](docs/hosted-keys.md).

## Features

- **Plugs into unmodified Canton** — implements the official KMS Driver SPI; passes the upstream
  conformance suite. Verified end-to-end on a real Canton 3.6.1 node.
- **Threshold signing (FROST-ed25519)** — DKG, two-round signing, standard RFC 8032 output,
  crash-safe single-use nonce guard.
- **Backends** — `software` (testing), `hsm` (PKCS#11, experimental: verified on SoftHSM only) and `frost` (the MPC
  cluster), which routes non-FROST keys to a delegate: `hsm`, `software`, or `none` — no delegate at
  all, which requires cluster-hosted keys (below).
- **Cluster-hosted keys** — RSA-2048-OAEP encryption and AES-256-GCM symmetric keys held by the
  cosigners themselves: configurable write quorum (2-of-3 by default), wrapped per recipient node so
  key material never crosses the mesh in the clear (not even inside mTLS), healed by anti-entropy
  and read-repair, and covered by the existing `backup`/`restore`. Replicated, not threshold — see
  above — but it takes both the HSM and the last private key off the Canton host.
- **Export/import** — an offline CLI writes a hosted key as a portable, passphrase-encrypted file,
  covering the two cases `backup` cannot: a lost seal secret, and moving to another cluster or KMS.
  Hosted keys only, and deliberately never an RPC — [docs/hosted-keys.md](docs/hosted-keys.md).
- **Mutual TLS** across the mesh and from the driver, with **driver-side failover** (any live
  cosigner leads — a downed node, or one that answers but cannot sign, never blocks signing; each
  failover is recorded in the operation's audit entry).
- **Encryption at rest** — key shares and hosted keys sealed with AES-256-GCM (per-node keys from an
  operator secret); hosted keys are refused outright if sealing is not configured.
- **Proactive refresh** — rotate all shares on a schedule; same key, so an attacker's stolen share
  expires.
- **M-of-N human approval** — high-value signing held until a quorum of named approvers
  cryptographically sign off (separation of duties, not a checkbox).
- **Tamper-evident audit log** — every operation in a hash-chained, offline-verifiable journal.
- **Signing journal** — persistent per-key record for replay detection, plus an optional rate limit.
- **Disaster recovery** — encrypted backup/restore + a share-repair primitive, with a full runbook.
- **Deploy** — Docker Compose and Kubernetes, dev and mTLS-hardened.

## Supported keys and algorithms

With `backend = "frost"` (the production path):

| Canton key | Key spec / algorithm | How Rütli holds it |
|---|---|---|
| Namespace, protocol signing, sequencer authentication | Ed25519 (`EcCurve25519`) | **Threshold:** FROST-ed25519 shares, t-of-n (2-of-3 by default); never assembled |
| Encryption | ECIES P-256 (`EciesHkdfHmacSha256Aes128Cbc`) | **Hosted:** whole key, sealed and replicated on every cosigner (`hosted-keys = true`) |
| Encryption (legacy) | RSA-2048, RSA-OAEP-SHA256 | Hosted, as above |
| Symmetric | AES-256-GCM | Hosted, as above |
| Other signing specs (ECDSA P-256, P-384, secp256k1) | | Not served by the cluster; only through `frost.delegate = "hsm"` (PKCS#11, single token, not threshold) |

- Hosted keys are not threshold-shared: one compromised cosigner can read them. Threshold ECIES is
  planned for 2.0; existing nodes will move to it by an ordinary encryption-key rotation
  ([docs/roadmap.md](docs/roadmap.md)).
- `backend = "hsm"` (PKCS#11) signs with EC P-256, P-384 and secp256k1 (and Ed25519 if the token
  supports it) and decrypts RSA-2048 OAEP. It is verified against SoftHSM only and is outside the
  planned audit.
- `backend = "software"` keeps keys in the driver's memory. It is for tests only.

### Compatibility

| Component | Version | Status |
|---|---|---|
| Canton | 3.6.1 | **Tested:** upstream `KmsDriverTest` conformance in CI, DevNet soak, migration rehearsals |
| Canton | 3.5.x | **Supported:** the KMS driver SPI is byte-identical to 3.6.1; earlier Rütli releases ran end to end on 3.5.6, but 0.4 is not re-tested there |
| Canton | 3.4 and earlier | **Not supported:** driver-based KMS arrived in Canton 3.5 |
| Splice | 0.9.0 | **Tested:** DevNet validator on Rütli since 2026-10-07 |
| JVM (driver) | Java 17 | Bytecode pinned to 17, as Canton requires |
| Driver ↔ cosigners | driver ≥ `0.4.0-rc.4` with cosigners ≥ `0.4.0-rc.6` | From rc.6, cosigners on TLS refuse a DKG or refresh without a client-signed ceremony intent, and drivers older than rc.4 do not sign one. Upgrade the driver to ≥ `0.4.0-rc.4` (and the refresh CronJob's image to the cosigners' release) **before** the cosigners, or set `require_ceremony_intent: false` on every node first; see the rc.6 upgrade note in [CHANGELOG.md](CHANGELOG.md) |

## Install & run

Full walkthrough in **[QUICKSTART.md](QUICKSTART.md)**. The short version:

**Prerequisites:** JDK 17, [sbt](https://www.scala-sbt.org/), Docker, [Rust](https://rustup.rs/), and
a [Canton 3.6.1](https://github.com/digital-asset/canton/releases/tag/v3.6.1) release.

```sh
git clone https://github.com/Stakecraft/rutli.git && cd rutli

# 1. Prove the threshold crypto (no Canton needed):
( cd frost && cargo test )

# 2. Build the driver and run a Canton node on it:
scripts/publish-canton-deps.sh v3.6.1      # fetch the Canton KMS API (not on Maven Central), once
sbt driver/assembly                        # -> driver/target/scala-2.13/rutli-driver.jar
export CANTON_HOME=/path/to/canton-open-source-3.6.1
deploy/devnet/up.sh                        # boots a participant whose keys live in the driver

# 3. Put the namespace key in a real 3-node MPC cluster:
docker compose -f deploy/frost/docker-compose.yml up --build -d
CANTON_CONF=canton-frost.conf deploy/devnet/up.sh
```

## Deployment

- **Docker** — [`deploy/frost`](deploy/frost): `docker-compose.yml` (dev) and `docker-compose.tls.yml`
  (mutual TLS + sealed shares).
- **Kubernetes** — [`deploy/k8s`](deploy/k8s): StatefulSet with durable per-pod storage, mTLS, sealed
  shares, and a NetworkPolicy. See its [README](deploy/k8s/README.md).

Before protecting a real key, run the witnessed **[key ceremony](docs/key-ceremony.md)** and set up
**[disaster recovery](docs/disaster-recovery.md)** — the namespace key is non-rotatable.

## Documentation

| Doc | What |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Get running in minutes |
| [docs/architecture.md](docs/architecture.md) | How it's built, and why |
| [docs/phase-2-frost.md](docs/phase-2-frost.md) | The FROST cluster in depth |
| [docs/hosted-keys.md](docs/hosted-keys.md) | Cluster-hosted RSA/AES keys: what they are, what they are not |
| [docs/hosted-keys-design.md](docs/hosted-keys-design.md) | Why they are replicated and not threshold — the design record, with what did and did not ship |
| [docs/key-ceremony.md](docs/key-ceremony.md) | Witnessed namespace-key generation |
| [docs/key-rotation.md](docs/key-rotation.md) | Which keys rotate, how, and why the root can't |
| [docs/approval-quorum.md](docs/approval-quorum.md) | M-of-N signing approval |
| [docs/disaster-recovery.md](docs/disaster-recovery.md) | Backup, restore, recovery |
| [docs/observability.md](docs/observability.md) | Prometheus metrics, Grafana dashboard, alerts |
| [docs/performance.md](docs/performance.md) | Sign/DKG latency evidence (DevNet multi-region numbers) |
| [docs/testnet-soak.md](docs/testnet-soak.md) | Splice DevNet validator soak: setup, drills, exit criteria |
| [docs/wire-contract.md](docs/wire-contract.md) | Exactly what Canton sends the driver |
| [docs/audit-prep.md](docs/audit-prep.md) | Engagement brief and evidence index for a third-party review |

## Project layout

```
driver/    Canton KMS driver (Scala/JVM) — SPI impl + swappable KmsBackend + policy/audit
frost/     Rust workspace — the FROST MPC cluster
  core/      DKG, threshold signing, nonce guard, refresh, repair (the crypto)
  cosigner/  the gRPC cosigner daemon
deploy/    devnet, Docker Compose, and Kubernetes
docs/      architecture + operational runbooks
scripts/   Canton dep publishing, cert generation, SoftHSM setup
```

## Status

Pre-production and **not yet audited** — do not put a production authority key behind it until a
third-party security review is complete. The full stack above is implemented, CI-green, and verified
end-to-end on a real Canton node. An **HSM is no longer required**: both halves of cluster-hosted
keys — cluster and driver — are done, so `delegate = "none"` is a deployment you can run today, with
no PKCS#11 module and no key material on the participant host. It has been exercised on a Canton
3.5.6 participant with no local key state
([`deploy/devnet/canton-hosted.conf`](deploy/devnet/canton-hosted.conf)): three Ed25519 keys born by
cluster DKG and threshold-signed, plus an RSA-2048 encryption key generated in the cluster and
replicated to all three cosigners. It is still the newest surface in the codebase, so run it on
DevNet before it holds anything you care about, and read
[docs/hosted-keys.md](docs/hosted-keys.md) first — replicated keys are a different security property
from the threshold namespace key, not the same one applied wider. What remains for a 1.0 is
external: a **security audit** and a **Splice testnet validator run**. See
[CHANGELOG.md](CHANGELOG.md).

## Security

Security-critical infrastructure. Never place production keys behind the `software` backend. Report
vulnerabilities privately via GitHub's
[Report a vulnerability](https://github.com/Stakecraft/rutli/security/advisories/new) — see
[SECURITY.md](SECURITY.md).

## Contributing

Issues and PRs welcome. `sbt driver/test` (JVM) and `cd frost && cargo test && cargo clippy` (Rust)
must pass; CI runs both on every PR.

## License

[Apache-2.0](LICENSE). Not affiliated with or endorsed by Digital Asset.

Third-party components bundled into the release artifacts are listed, with their licenses, in
[driver/THIRD-PARTY-LICENSES.txt](driver/THIRD-PARTY-LICENSES.txt) (inside `rutli-driver.jar` under
`META-INF/rutli/`) and [frost/THIRD-PARTY-LICENSES.txt](frost/THIRD-PARTY-LICENSES.txt) (in the
cosigner image under `/usr/share/doc/rutli-cosigner/`, and next to the `rutli-dealer` release binary).

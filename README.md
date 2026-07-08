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
Enterprise Edition); the sovereign alternatives are **proprietary** (MPCH Stronghold) or **SaaS
custodians** (Fireblocks, Dfns). None is open-source, self-hosted, *and* real threshold-MPC — one a
bank could run and certify entirely inside its own SOC 2 / ISO 27001 / DORA boundary.

Rütli is that missing option — **the "Web3Signer/Teku of Canton."**

## How it works

```
   Canton node                Rütli driver (a jar inside the node)         FROST cosigner cluster
  ┌───────────┐   "sign this  ┌───────────────────────────────┐   sign    ┌───────────┐ share 1
  │ participant├──────────────►│ policy · approval · audit log  ├──────────►│ cosigner A│  (region 1)
  │  (unchanged)│   34-byte    │ routes by key type             │  rounds   ├───────────┤
  └───────────┘   digest      └───────────────────────────────┘◄──────────┤ cosigner B│ share 2
        ▲                                    │                   64-byte    ├───────────┤  (region 2)
        └────────────────────────────────────┘   Ed25519 sig     signature  │ cosigner C│ share 3
              standard Ed25519 signature — Canton can't tell it was threshold └───────────┘  (region 3)
```

Canton thinks it's talking to an ordinary KMS. The driver forwards each *"sign this digest"* to the
cluster, which produces a **standard Ed25519 signature** — byte-for-byte indistinguishable from a
single-signer one, so Canton's verifier accepts it unchanged. The key is *born distributed* (no
trusted dealer) and never assembled, not even for an instant.

Behind the driver, a swappable backend routes each key to the right protection:

| Canton key | Backend | Isolation |
|---|---|---|
| **Namespace / identity** (Ed25519) | **FROST MPC cluster** | `t`-of-`n`, one share per host/account/region |
| Protocol / sequencer (ECDSA) | HSM (or threshold ECDSA) | PKCS#11 hardware |
| Encryption (ECIES / RSA-OAEP) | HSM / enclave | hardware, never threshold |

## Features

- **Plugs into unmodified Canton** — implements the official KMS Driver SPI; passes the upstream
  conformance suite. Verified end-to-end on a real Canton 3.5.6 node.
- **Threshold signing (FROST-ed25519)** — DKG, two-round signing, standard RFC 8032 output,
  crash-safe single-use nonce guard.
- **Backends** — `software` (testing), `hsm` (PKCS#11, verified on SoftHSM), `frost` (the MPC cluster).
- **Mutual TLS** across the mesh and from the driver, with **driver-side failover** (any live
  cosigner leads — a downed node never blocks signing).
- **Encryption at rest** — key shares sealed with AES-256-GCM (per-node keys from an operator secret).
- **Proactive refresh** — rotate all shares on a schedule; same key, so an attacker's stolen share
  expires.
- **M-of-N human approval** — high-value signing held until a quorum of named approvers
  cryptographically sign off (separation of duties, not a checkbox).
- **Tamper-evident audit log** — every operation in a hash-chained, offline-verifiable journal.
- **Signing journal** — persistent per-key record for replay detection, plus an optional rate limit.
- **Disaster recovery** — encrypted backup/restore + a share-repair primitive, with a full runbook.
- **Deploy** — Docker Compose and Kubernetes, dev and mTLS-hardened.

## Install & run

Full walkthrough in **[QUICKSTART.md](QUICKSTART.md)**. The short version:

**Prerequisites:** JDK 17, [sbt](https://www.scala-sbt.org/), Docker, [Rust](https://rustup.rs/), and
a [Canton 3.5.6](https://github.com/digital-asset/canton/releases/tag/v3.5.6) release.

```sh
git clone https://github.com/Stakecraft/rutli.git && cd rutli

# 1. Prove the threshold crypto (no Canton needed):
( cd frost && cargo test )

# 2. Build the driver and run a Canton node on it:
scripts/publish-canton-deps.sh v3.5.6      # fetch the Canton KMS API (not on Maven Central), once
sbt driver/assembly                        # -> driver/target/scala-2.13/rutli-driver.jar
export CANTON_HOME=/path/to/canton-open-source-3.5.6
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
| [docs/key-ceremony.md](docs/key-ceremony.md) | Witnessed namespace-key generation |
| [docs/approval-quorum.md](docs/approval-quorum.md) | M-of-N signing approval |
| [docs/disaster-recovery.md](docs/disaster-recovery.md) | Backup, restore, recovery |
| [docs/wire-contract.md](docs/wire-contract.md) | Exactly what Canton sends the driver |

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
end-to-end on a real Canton node. What remains for a 1.0 is external: a **security audit** and a
**Splice testnet validator run**. See [CHANGELOG.md](CHANGELOG.md).

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

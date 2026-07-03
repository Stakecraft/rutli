# Rütli

Open-source, self-hosted **threshold key management for Canton Network & Splice node authority
keys** — implemented as a Canton **KMS Driver** so it plugs into an unmodified Canton node. Think
[Horcrux](https://github.com/strangelove-ventures/horcrux) for Canton: the node holds no keys; a
t-of-n quorum signs on its behalf.

*Named after the [Rütli meadow](https://en.wikipedia.org/wiki/R%C3%BCtli), where in 1291 the three
founding cantons swore the oath that created the Swiss Confederation — a federation born from an
agreement between peers, with no single point of authority. Same idea, applied to your keys.*

> Status: **pre-production, phases 0–1 done, phase 2 core done.** The driver runs inside a real
> Canton 3.5.6 node — all node keys (incl. an **Ed25519 namespace key**) are generated in the KMS
> and identity topology is signed through it; the upstream conformance suite is green. Backends:
> `software` (Phase 0, testing only) and `hsm` (Phase 1, PKCS#11 — verified against SoftHSM incl.
> key persistence across restart). The [FROST MPC core](docs/phase-2-frost.md) (`frost/core`, Rust)
> is implemented and **verified end-to-end with a real Canton node**: a participant booted with
> `backend = "frost"`, its Ed25519 namespace key born via 3-node cluster DKG, and its identity
> topology threshold-signed by a 2-of-3 quorum — accepted by Canton's verifier. No machine ever
> held the whole key. Remaining before production: share sealing (enclave/HSM), proactive refresh,
> DR procedures, and a third-party audit. (mTLS and driver-side failover are done.)

## Why

Canton's most catastrophic secret is the **namespace / identity root key** — it defines a node's
identity and authorizes topology transactions. Losing or leaking it means irrecoverable loss of
all Canton Coin for parties hosted under that namespace, and counts as an "SV failure" that reduces
the network's BFT fault-tolerance buffer. It is also **not rotatable**.

Today the options for protecting it are: Canton's built-in KMS (AWS/GCP only, Enterprise Edition),
proprietary self-hosted vaults (MPCH Stronghold — HSM/air-gap, closed source), or SaaS custodians
(Fireblocks, Dfns). There is no **open-source, self-hosted, real-MPC** option the operator runs and
certifies entirely within its own SOC 2 / ISO 27001 / DORA boundary. This project fills that gap —
the "Web3Signer/Teku of Canton".

## How

We implement the Canton **KMS Driver SPI** (`com.digitalasset.canton.crypto.kms.driver.api.v1`).
Canton calls our driver for every private-key operation; the key never enters the Canton process.
Behind the driver, a `KmsBackend` seam routes each key to the right isolation model:

| Canton key | Backend | Phase |
|---|---|---|
| Namespace / identity (Ed25519) | FROST-ed25519 MPC cluster (`t`-of-`n`, single operator, isolated hosts) | 2 |
| Protocol / sequencer (ECDSA P-256/384) | Threshold ECDSA (DKLS23) or HSM | 4 |
| Asymmetric encryption (ECIES/RSA-OAEP) | HSM / enclave (never threshold) | 1 |

**Delivery is HSM-first:** Phase 1 ships a correct, FIPS-capable driver on an HSM/enclave; MPC
(FROST for the namespace key) lands in Phase 2. See [`docs/architecture.md`](docs/architecture.md).

## Repo layout

```
driver/            The Canton KmsDriver (Scala/JVM). Policy/routing shell + KmsBackend seam.
  src/main/scala/com/stakecraft/rutli/
    RutliDriverFactory.scala       Factory (ServiceLoader entry point).
    RutliDriver.scala              KmsDriver SPI impl — delegates to a KmsBackend.
    RutliConfig.scala              pureconfig-parsed driver config (+ HsmConfig).
    backend/KmsBackend.scala        The internal seam — swappable key backend.
    backend/SoftwareBackend.scala   Phase 0 — BouncyCastle, testing only.
    backend/HsmBackend.scala        Phase 1 — PKCS#11 (SunPKCS11), production-usable.
    backend/FrostBackend.scala      Phase 2 — routes namespace key to the FROST cluster (gRPC).
  src/main/java/com/stakecraft/rutli/grpc/   Generated gRPC stubs (scripts/gen-grpc-java.sh).
  src/main/resources/META-INF/services/   ServiceLoader registration (two factory FQCN files).
  src/test/scala/...                Unit + conformance + live HSM integration tests.
frost/             Rust workspace — the FROST-ed25519 MPC cluster.
  core/            rutli-frost-core: DKG, two-round signing, crash-safe nonce store (tested).
  cosigner/        rutli-cosigner: gRPC cosigner daemon + DKG/sign orchestration (tested).
deploy/devnet/     Canton 3.5.x devnet with crypto.provider = kms pointed at this driver.
deploy/frost/      Docker-compose 2-of-3 cosigner cluster.
scripts/           publish-canton-deps.sh (Canton artifacts), init-softhsm.sh (dev HSM token).
docs/              architecture, wire-contract, phase-{0,1,2} docs.
.github/workflows/ CI: JVM unit tests + assembly and Rust tests+clippy on PR; conformance nightly.
```

## Getting started (Phase 0)

Prereqs: JDK 17+, `sbt`. Then follow [`docs/phase-0-spike.md`](docs/phase-0-spike.md):

```sh
scripts/publish-canton-deps.sh v3.5.6   # resolve Canton API artifacts (not on Maven Central)
sbt driver/test                         # conformance suite green
sbt driver/assembly                     # build the driver fat jar
CANTON_HOME=/path/to/canton-3.5.6 deploy/devnet/up.sh   # boot a KMS-backed Canton node
```

## Security

This is security-critical infrastructure under active early development. It has **not** been
audited. Never place production authority keys behind the `SoftwareBackend`. Report vulnerabilities
privately (see `SECURITY.md`, TODO).

## License

[Apache-2.0](LICENSE).

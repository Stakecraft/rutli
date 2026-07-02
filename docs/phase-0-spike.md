# Phase 0 — integration spike

> **Status: PASSED (2026-07-02).** All acceptance criteria met against Canton v3.5.6:
> conformance suite green (`CONFORMANCE=1 sbt driver/test`, 32 tests incl. upstream
> `KmsDriverTest`/`KmsDriverFactoryTest`); devnet participant initialized end-to-end with all four
> key types born in the driver and identity topology signed through it — verified on both the
> KMS-default path (EC-P256/ECDSA) and the production-target path (**Ed25519 namespace key**, the
> exact algorithm+format the Phase 2 FROST backend produces).

**Goal:** kill all Canton-integration risk before writing any product or MPC code. Prove that a
custom `KmsDriver` we control can be loaded by a real Canton node and used to generate and sign
with the **namespace (identity) key**, end-to-end, on a local devnet.

If this passes, everything after Phase 0 is swapping the backend behind the driver (software → HSM
→ FROST). If it fails, we learn the exact API/format mismatch now, cheaply.

## Acceptance criteria

1. **Conformance:** our `RutliDriver` (with `SoftwareBackend`) passes the upstream
   `KmsDriverTest` and `KmsDriverFactoryTest` from `canton-kms-driver-testing`.
2. **Load:** a Canton 3.x participant boots with `crypto.provider = kms` and our driver `.jar` on
   the classpath, discovered via `ServiceLoader`.
3. **Keygen through the driver:** the node's namespace/identity signing key is generated *by the
   driver* (external key storage mode) — confirmed by the driver receiving `generateSigningKeyPair`
   and `getPublicKey` calls.
4. **Sign a topology transaction:** the node authorizes a topology transaction (e.g. a namespace
   delegation or party allocation). The driver receives the `sign(data, keyId, Ed25519)` call and
   returns a 64-byte `concat` signature that Canton's verifier **accepts**.
5. **Capture the wire contract:** record, for each key type exercised, the exact `algoSpec`
   values, the input byte layout to `sign`, and the signature/format bytes returned. This becomes
   the spec the HSM and FROST backends must satisfy.

The driver module is already scaffolded (`driver/`), written directly against the real v3.5.6 SPI.
It does **not** copy the upstream `mock-kms-driver` — that module depends on Canton-internal classes
(`JceCrypto`, `CryptoSchemes`, in-memory stores) that aren't in the public `kms-driver-api` artifact.
Instead, `SoftwareBackend` performs the crypto directly with BouncyCastle, emitting Canton's exact
formats (Ed25519 raw-64 `concat`, ECDSA `der`, X.509 SPKI public keys).

## Steps

### 0. Prereqs
- JDK 17+ (`java -version` → 17). ✓ present on this machine.
- `sbt` (`brew install sbt`). Not yet installed here.
- A Canton 3.5.x community release for the devnet step (set `CANTON_HOME`):
  https://github.com/digital-asset/canton/releases/tag/v3.5.6

### 1. Resolve the Canton API artifacts
`kms-driver-api` / `kms-driver-testing` are **not on Maven Central**. Resolve them locally:
```sh
scripts/publish-canton-deps.sh v3.5.6
```
This clones Canton at the tag and `publishLocal`s the two modules; `build.sbt` picks them up from the
ivy local repo. (Alternative: set `CANTON_ARTIFACTORY` to Digital Asset's JFrog repo if you have
access.)

### 2. Conformance test
`driver/src/test` already extends the upstream `KmsDriverTest` / `KmsDriverFactoryTest`.
```sh
sbt driver/test
```
Expected: green. **Phase 0 scope:** the driver advertises all four signing key specs + Ed25519/ECDSA
algos, but only `Rsa2048` + `RsaEsOaepSha256` for asymmetric encryption (Canton's KMS-mode default).
The Canton-specific ECIES(P-256) construction is deferred, so the suite exercises RSA-OAEP only.

### 3. Build the driver jar
```sh
sbt driver/assembly   # -> driver/target/scala-2.13/rutli-driver.jar (BouncyCastle bundled)
```

### 4. Devnet node + topology signing
```sh
CANTON_HOME=/path/to/canton-3.5.6 deploy/devnet/up.sh
```
`up.sh` installs the jar on the Canton classpath, starts `participant1` (`crypto.provider = kms`,
`name = "rutli"`), and runs `bootstrap.canton`. A standalone participant's auto-init **requires**
the driver to generate the namespace + signing keys and **sign** its identity topology transactions
(NamespaceDelegation, OwnerToKeyMapping) — so a clean init is the end-to-end proof. The commented
block in `bootstrap.canton` extends this to a connected synchronizer for cross-node topology signing.

### 5. Record the wire contract
With `audit-logging = true`, capture from the driver logs (or add trace logging in
`SoftwareBackend.sign`) the `keyId`, `algoSpec`, input length, and output length/format for each key
type exercised. Save a sample to `docs/wire-contract.md` — it's the spec the HSM + FROST backends
must satisfy.

## Deliverables
- `driver/` module passing the conformance suite.
- `deploy/devnet/` bringing up a KMS-backed Canton node.
- `docs/wire-contract.md` — the exact per-key-type sign/verify contract the HSM + FROST backends
  must match.

## Non-goals (explicitly out of Phase 0)
- Any real HSM, MPC, or FROST code.
- Policy engine, quorum, audit log, RBAC.
- Production key storage, DR, share refresh.
- The Wallet Gateway seam.

# FROST cosigner cluster (dev)

A local 2-of-3 [`rutli-cosigner`](../../frost/cosigner) cluster. Each node holds one key share; no
node ever holds the whole namespace key. The Canton KMS driver's `FrostBackend` (Phase 2, in
progress) connects to any node's `Signer` API to run DKG and to sign.

## Run

```sh
docker compose -f deploy/frost/docker-compose.yml up --build
```

Three cosigners come up on `localhost:9101..9103`. On first start they have no key — trigger DKG
once against any node's `Signer.Dkg` (e.g. with `grpcurl`, or via the `FrostBackend`):

```sh
grpcurl -plaintext -d '{"key_id":"namespace-participant1"}' localhost:9101 rutli.cosigner.v1.Signer/Dkg
# -> { "groupVerifyingKey": "<base64 32-byte Ed25519 group key>" }
```

Then sign Canton's 34-byte pre-hashed payload:

```sh
grpcurl -plaintext -d '{"key_id":"namespace-participant1","message":"<base64 34 bytes>"}' \
  localhost:9101 rutli.cosigner.v1.Signer/Sign
# -> { "signature": "<base64 64-byte Ed25519 signature>" }
```

Kill any single node and signing still works (2-of-3).

## Config

One JSON file per node (`config/cosignerN.json`): its `identifier`, `listen` address, the signing
`threshold`, a durable `data_dir`, and the full `peers` roster. See the files in `config/`.

## Mutual TLS

Add a `tls { ca_cert, cert, key, domain }` block to each node's config and use `https://` peer
endpoints; the server then **requires** a client cert signed by the cluster CA (real mTLS — the
mesh and the driver both authenticate). Generate a dev trust domain:

```sh
scripts/gen-frost-certs.sh 3 deploy/frost/certs   # cluster CA + 3 cosigner certs + a driver cert
```

Example TLS configs are in `config-tls/` (mount `certs/` at `/certs`). The driver enables TLS via
`frost.tls { ca-cert, cert, key, domain }` in its Canton config, pointing at the CA + `driver.{crt,key}`.
With TLS on, a plaintext client is refused at the handshake.

## ⚠️ Not fully production yet

Even with mTLS, this dev topology stores shares as unencrypted JSON, all on one host. A production
deployment must additionally:

- run each cosigner on a **separate host / cloud account / region** (independent blast radius);
- issue certs from the operator PKI (short-lived, rotated) rather than the dev script;
- seal each share in an **enclave/HSM** ("MPC-of-HSM");
- add **proactive share refresh** and encrypted + cold (Shamir) share backups;
- replace the static leader with **Raft** leader election.

See [`docs/phase-2-frost.md`](../../docs/phase-2-frost.md).

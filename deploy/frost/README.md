# FROST cosigner cluster (Docker)

A 2-of-3 [`rutli-cosigner`](../../frost/cosigner) cluster. Each node holds one key share; no node
ever holds the whole namespace key. The Canton KMS driver's `FrostBackend` connects to any node's
`Signer` API to run DKG and to sign.

Two compose files (default image `ghcr.io/stakecraft/rutli-cosigner:0.2.1`; override with
`RUTLI_COSIGNER_IMAGE` or `--build` from `frost/`):
- `docker-compose.yml` — **dev**: plaintext gRPC, unsealed shares. Fastest to try.
- `docker-compose.tls.yml` — **production-flavored**: mutual TLS + AES-256-GCM sealed shares
  (verified end-to-end). Needs certs + a seal secret first (below).

For **Kubernetes**, prefer the Helm chart [`../helm/rutli-cosigner`](../helm/rutli-cosigner) or the
raw manifests in [`../k8s`](../k8s).

## Run (dev)

```sh
docker compose -f deploy/frost/docker-compose.yml up -d          # pulls published image
# docker compose -f deploy/frost/docker-compose.yml up -d --build  # build from source
```

## Run (mTLS + sealed shares)

```sh
scripts/gen-frost-certs.sh 3 deploy/frost/certs                   # CA + per-node certs
export RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"                # from a secret manager in prod
RUTLI_SEAL_SECRET=$RUTLI_SEAL_SECRET \
  docker compose -f deploy/frost/docker-compose.tls.yml up -d
```

The driver connects with `frost.tls` (`ca.crt` + `driver.crt/key`, `domain = "rutli-cosigner"`).

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

Even with mTLS and share sealing available, this dev topology runs all nodes on one host. A production
deployment must additionally:

- run each cosigner on a **separate host / cloud account / region** (independent blast radius);
- issue certs from the operator PKI (short-lived, rotated) rather than the dev script;
- seal each share in an **enclave/HSM** ("MPC-of-HSM");
- add **proactive share refresh** and encrypted + cold (Shamir) share backups;
- (availability is handled by driver-side failover across the roster — see docs/phase-2-frost.md on why Raft is unnecessary here).

See [`docs/phase-2-frost.md`](../../docs/phase-2-frost.md).

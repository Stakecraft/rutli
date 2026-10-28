# FROST cosigner cluster (Docker)

A 2-of-3 [`rutli-cosigner`](../../frost/cosigner) cluster. Each node holds one key share; no node
ever holds the whole namespace key. The Canton KMS driver's `FrostBackend` connects to any node's
`Signer` API to run DKG and to sign.

Two compose files (default image `ghcr.io/stakecraft/rutli-cosigner:0.4.0-rc.5`, pinned by digest; override with
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

The driver connects with `frost.tls` (`ca.crt` + `driver.crt/key`) and names the certificate each
endpoint must present: `endpoints = [{ url = "localhost:9101", tls-name = "cosigner1" }, …]`
(see `deploy/devnet/canton-hosted.conf`). Certificates from releases before 0.4.0-rc.2 also carry
a shared `rutli-cosigner` SAN, so an older config with `tls.domain = "rutli-cosigner"` still
connects; new certificates do not, and a shared name lets any cosigner answer for any endpoint.

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

The example configs opt out of ceremony intents (`"signing_policy": { "require_ceremony_intent": false }`)
so that a hand-run `grpcurl … Signer/Dkg` (and the CI smoke test) can start a DKG: grpcurl cannot sign
the client ceremony intent every cosigner requires by default from 0.4.0-rc.6. Remove the opt-out for
anything driven by the Rütli driver (0.4.0-rc.4 or later signs its DKGs) — see
[approval-quorum.md](../../docs/approval-quorum.md).

### On Linux: cert ownership

The cosigner containers run as **uid 10001**, and a bind-mounted directory keeps its host
ownership. The generated `*.key` files are mode `0600` owned by whoever ran the script, so on Linux
the cosigner cannot read them and exits with `cannot read TLS material … Permission denied`.
(Docker Desktop on macOS masks host ownership, so this does not appear there.) Hand the certs to
the container user:

```sh
sudo RUTLI_CERT_UID=10001 scripts/gen-frost-certs.sh 3 deploy/frost/certs
```

or `sudo chown -R 10001:10001 deploy/frost/certs` after generating. On Kubernetes this is handled
for you — certs come from a Secret with `defaultMode: 0440` and the pod's `fsGroup`.

## Cluster-hosted keys

The `config-tls/` configs also enable **cluster-hosted keys**: the RSA-2048-OAEP encryption keypair
and the AES-256-GCM symmetric key Canton needs are held by the cosigners themselves, instead of by
an HSM or the driver's software backend.

```json
"hosted_keys": { "enabled": true, "write_quorum": 2, "anti_entropy_interval_secs": 300 }
```

The block requires `share_seal`: with sealing off the node refuses to start, because a whole private
key must never sit unsealed on disk. That is why the plaintext dev configs in `config/` omit it —
add it there only alongside a `share_seal` block.

Be clear about what this is. These are **replicated whole keys, not threshold shares**: generated on
one node, wrapped to each recipient and copied to the others, sealed at rest per node, and any node
can serve a decrypt. The Ed25519 namespace key is unchanged — still 2-of-3 FROST, never replicated.
One compromised cosigner yields the hosted keys, and because those keys protect Canton's per-view
session keys, an attacker who extracts one gains *retrospective* read access to any recorded traffic
encrypted to it; rotation fixes the future, not the past. What you buy is relocation: key material
leaves the busy, internet-adjacent participant host for three hardened single-purpose nodes.

`write_quorum: 2` means a new key is reported created once two of three nodes hold it; below quorum
the write rolls back rather than leaving a single copy. The anti-entropy sweep (every 300s, plus
read-repair on demand) is what heals the third node, so it is not optional at a quorum below `n`.

Driver side: `frost.hosted-keys = true` routes `rutli-`-prefixed key ids to the cluster alongside
`frost-`; with it on, `delegate = "none"` becomes possible — no HSM, no local key state.

See [`docs/hosted-keys.md`](../../docs/hosted-keys.md).

## ⚠️ Not fully production yet

Even with mTLS and share sealing available, this dev topology runs all nodes on one host. A production
deployment must additionally:

- run each cosigner on a **separate host / cloud account / region** (independent blast radius);
- issue certs from the operator PKI (short-lived, rotated) rather than the dev script;
- seal each share in an **enclave/HSM** ("MPC-of-HSM");
- add **proactive share refresh** and encrypted + cold (Shamir) share backups;
- (availability is handled by driver-side failover across the roster — see docs/phase-2-frost.md on why Raft is unnecessary here).

See [`docs/phase-2-frost.md`](../../docs/phase-2-frost.md).

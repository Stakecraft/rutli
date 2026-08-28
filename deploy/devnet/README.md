# Devnet

Boots a Canton participant whose crypto is delegated to the `rutli` driver, and runs a smoke test
that proves the driver is loaded and used to generate + sign the node's identity keys.

Three node configs share one launcher (`up.sh`) and one bootstrap script (`bootstrap.canton`). They
differ only in how much custody leaves the participant host:

| Config | Driver backend | Namespace/identity key | Encryption + symmetric keys |
|---|---|---|---|
| `canton.conf` | `software` | on the participant host | on the participant host |
| `canton-frost.conf` | `frost` + `delegate = "software"` | 2-of-3 FROST in the cluster | on the participant host |
| `canton-hosted.conf` | `frost` + `hosted-keys`, `delegate = "none"` | 2-of-3 FROST in the cluster | in the cluster — **replicated, not threshold** |

The first needs nothing but the driver jar; the other two need a running cosigner cluster, and
`canton-hosted.conf` needs one with hosted keys enabled.

Read that table top to bottom as the migration path: prove the integration seam with a software
backend, then move the one key Canton can never rotate into real threshold MPC, then move the
remaining keys off the participant host entirely.

## Prerequisites

1. **Canton 3.5.x community release.** Download the `v3.5.6` release, extract it, and point
   `CANTON_HOME` at the extracted directory:
   - https://github.com/digital-asset/canton/releases/tag/v3.5.6
   ```sh
   export CANTON_HOME=/path/to/canton-open-source-3.5.6
   ```
2. **The driver fat jar.** From the repo root:
   ```sh
   scripts/publish-canton-deps.sh v3.5.6   # first time only: resolve the Canton API artifacts
   sbt driver/assembly                     # -> driver/target/scala-2.13/rutli-driver.jar
   ```
3. **A cosigner cluster**, for `canton-frost.conf` and `canton-hosted.conf` only — see each section
   below. Run `up.sh` from the repo root either way: the cluster configs name their TLS material by
   repo-relative path.

## Run

```sh
deploy/devnet/up.sh                                   # canton.conf — software backend
CANTON_CONF=canton-frost.conf deploy/devnet/up.sh     # FROST namespace key, software delegate
CANTON_CONF=canton-hosted.conf deploy/devnet/up.sh    # everything in the cluster, no HSM
```

`up.sh` puts the driver jar on the Canton classpath via `EXTRA_CLASSPATH` (the release launcher does
not glob `lib/`), starts the participant with the chosen config, and runs `bootstrap.canton`.

## `canton.conf` — software backend

The participant generates its namespace/identity and signing keys **through** the driver (external
key storage) and signs its own identity topology transactions with the namespace key via the
driver's `sign`. That alone exercises the full KMS Driver seam, with nothing else to stand up.

What "pass" looks like:

- The node reaches `initialized = true`. Reaching that state **requires** the driver to have
  generated the namespace + signing keys and signed the identity topology transactions — so a clean
  init is itself the end-to-end proof.
- With `audit-logging = true`, the driver logs each `generateSigningKeyPair` / `sign` / `getPublicKey`
  call. You should see `sign` calls for the namespace key during init.
- `participant1.keys.public.list()` shows the keys, confirming they were produced by the driver.

The config sets no `software { dir, seal-secret-env }`, so the backend is heap-only and logs a
startup warning: keys do not survive a restart. That is fine for a smoke test and wrong everywhere
else — a lost encryption key is unrecoverable
([`docs/disaster-recovery.md`](../../docs/disaster-recovery.md) §3b).

## `canton-frost.conf` — FROST namespace key, software delegate

Prereq: a running cosigner cluster reachable at `frost.endpoints` (`localhost:9101..9103`):

```sh
docker compose -f deploy/frost/docker-compose.yml up -d
```

The Ed25519 namespace key is created by cluster DKG and its topology transactions are signed by
threshold FROST — no single machine ever holds the whole key. Everything else (the RSA encryption
keypair, the AES symmetric key) still comes from the delegate on the participant host. The config
uses `delegate = "software"` so it runs without an HSM; in production use `delegate = "hsm"` and add
the `hsm { ... }` block ([`docs/phase-1-hsm.md`](../../docs/phase-1-hsm.md)) — or move those keys
into the cluster with `canton-hosted.conf` below.

Pass looks the same as above, plus `FROST: initiating distributed key generation for frost-…` in the
driver log and a `frost-`-prefixed key id on each `sign`.

## `canton-hosted.conf` — no local key state, no HSM

The interesting one, and the configuration the 2026-08-12 DevNet incident argues for: a restarted
participant has nothing to lose because it never held a private key. Verified end-to-end against a
real Canton 3.5.6 participant.

- The Ed25519 namespace/identity key is a genuine 2-of-3 FROST threshold key, never assembled.
- The RSA-2048 encryption keypair (and the AES-256-GCM symmetric key, if Canton mints one) are
  **cluster-hosted**: replicated whole keys, sealed at rest on each cosigner. Replicated, *not*
  threshold — one compromised cosigner yields that key. The operator guide is
  [`docs/hosted-keys.md`](../../docs/hosted-keys.md) (§4 covers backup/restore and the offline
  export/import path); recovery runbooks are
  [`docs/disaster-recovery.md`](../../docs/disaster-recovery.md) §3c–§3d.
- `delegate = "none"` installs a backend that refuses every operation with an actionable message.
  There is no software or HSM backend behind the driver at all, so an op that fails to route to the
  cluster fails loudly instead of quietly doing local crypto. The driver rejects `delegate = "none"`
  without `hosted-keys = true` at startup — otherwise nothing would serve the non-FROST keys.
- There is deliberately **no** fallback to the delegate on `NOT_FOUND`. A fallback would silently
  re-split custody, which is exactly the failure this config exists to remove.

### Prereq: a cluster with hosted keys enabled

Hosted keys require mutual TLS and sealed shares — `deploy/frost/config/` (plaintext dev) does not
enable them, and a cosigner refuses to start with `hosted_keys.enabled` and no `share_seal`.

```sh
scripts/gen-frost-certs.sh 3 deploy/frost/certs                 # CA + cosigner certs + driver cert
export RUTLI_SEAL_SECRET="$(openssl rand -hex 32)"              # from a secret manager in prod
docker compose -f deploy/frost/docker-compose.tls.yml up -d
```

`deploy/soak/docker-compose.yml` works too and is the better choice if you want to watch the
metrics: it includes the same TLS cluster and adds Prometheus + Grafana with the Rütli dashboard and
alert rules ([`docs/testnet-soak.md`](../../docs/testnet-soak.md)).

The driver authenticates to the cluster with `deploy/frost/certs/driver.{crt,key}`, whose CN
(`driver`) is on each cosigner's `signer_allowlist`. On Linux, hand the certs to the container user
first — see the cert-ownership note in [`deploy/frost/README.md`](../frost/README.md).

### Run

```sh
CANTON_CONF=canton-hosted.conf deploy/devnet/up.sh
```

### What "pass" looks like

At startup the driver reports what the cluster actually serves — it asks via the `Capabilities` RPC
rather than hardcoding a spec list, so adding a key type later needs no driver release:

```
Loaded driver rutli (API v1) build 0.2.1
FROST: mutual TLS channel to localhost:9101
FROST: mutual TLS channel to localhost:9102
FROST: mutual TLS channel to localhost:9103
FROST: cluster hosts non-FROST keys (rsa-2048-oaep-sha256, aes-256-gcm)
```

Then four keys, all minted in the cluster, none of them on the participant host:

| Key id | Spec | How it was created |
|---|---|---|
| `frost-participant1-namespace` | Ed25519 | cluster DKG, threshold-signed |
| `frost-participant1-sequencer-auth` | Ed25519 | cluster DKG, threshold-signed |
| `frost-participant1-signing` | Ed25519 | cluster DKG, threshold-signed |
| `rutli-enc-participant1-encryption-<uuid>` | RSA-2048 | cluster-hosted, replicated |

Routing is by key-id prefix: `frost-` → threshold Ed25519, `rutli-` → cluster-hosted. The hosted key
reports its replica count as it is created, and the identity topology transactions are then signed
by the FROST quorum:

```
FROST: generating cluster-hosted rsa-2048-oaep-sha256 key rutli-enc-participant1-encryption-6525cd62-…
FROST: hosted key rutli-enc-participant1-encryption-6525cd62-… ready (created=true, replicas=3)
AUDIT sign keyId=frost-participant1-namespace algo=Ed25519 inBytes=34 sigBytes=64 outcome=ok
```

`replicas=3` is the driver's word for it; confirm it on disk. Each cosigner stores one sealed file
per key under `/data/keys/`, FROST shares and hosted keys side by side:

```sh
for n in 1 2 3; do
  docker compose -f deploy/frost/docker-compose.tls.yml exec cosigner$n ls /data/keys
done
# each node: frost-participant1-*.json + the same rutli-enc-….json
```

Three files with the *same* `rutli-enc-…` name on three nodes is the replication claim, checked
rather than trusted. The files are sealed with `RUTLI_SEAL_SECRET`, so they are opaque on disk.

`bootstrap.canton` finishes by printing the participant id and `participant1.keys.public.list()` —
the same four keys, now as Canton sees them (three `EC-Curve25519`, one `Rsa2048`), under a
participant id whose namespace is the fingerprint of the FROST group key.

If no `rutli-` key appears, the cosigners do not actually have hosted keys on. The driver says so —
`driver has hosted-keys enabled but the cluster reports them disabled` — and routes the encryption
key to the delegate, which under `delegate = "none"` refuses it, so the participant fails to
initialize instead of quietly keying itself on the host. That is the intended outcome.

### Gotcha: the HOCON name for RSA-OAEP

Canton's config parser kebab-cases `RsaOaepSha256` and splits the digits, so the encryption
algorithm is spelled **`rsa-oaep-sha-256`** — *not* the driver SPI's `RsaEsOaepSha256`, and not
`rsa-oaep-sha256`. Both of those cost a startup:

```
GENERIC_CONFIG_ERROR(8,0): Cannot convert configuration to a config of class …CantonConfig
  at 'canton.participants.participant1.crypto.encryption.algorithms.default':
    - No valid coproduct option found for '"rsa-es-oaep-sha-256"'.
```

The error names the path but not the accepted values, so pattern-match against pureconfig's
kebab-casing of the Scala enum rather than against the SPI spelling.

## Notes

- The embedded `sequencer1` / `mediator1` in `canton.conf` use the default `jce` provider. They're
  there so you can optionally extend the test to connect the participant to a synchronizer and
  exercise cross-node topology signing (see the commented block in `bootstrap.canton`). The two
  cluster configs omit them — they test the driver's key paths, not synchronizer traffic.
- Node/port config schema tracks Canton 3.5.x. If the release rejects a key, compare against the
  `reference.conf` bundled in `$CANTON_HOME`.
- All three configs use `storage.type = memory`, so every run starts from a clean participant — but
  the cluster does not, and **DKG deliberately refuses to clobber a provisioned key**. A second run
  against the same cluster asks for `frost-participant1-namespace` again and gets `KeyExists`, and
  the participant fails to initialize. That guard is why the namespace key survives an ops mistake;
  wipe the cosigner volumes between runs (`docker compose -f … down -v`). Hosted keys behave
  differently: the driver mints a fresh UUID-suffixed `rutli-enc-…` id per run, so a re-run leaves
  the previous encryption key behind in the cluster rather than colliding with it.

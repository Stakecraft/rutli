# Namespace-key ceremony runbook

The birth of a Canton **namespace / identity key** is the single most consequential event in a
node's life: the key is non-rotatable, its loss or compromise is terminal (see
`docs/disaster-recovery.md`), and it anchors the node's on-chain identity forever. This runbook is
the auditable procedure for generating one under Rütli's FROST backend — a witnessed ceremony with a
signed record, not an unattended `docker compose up`.

Under Rütli the key is **born distributed** (DKG): no machine — and no person in the room — ever
holds the whole key, even for an instant at creation. There is nothing to shard, nothing to destroy
afterwards. The ceremony's job is to establish, and put on the record, that the cluster was set up
correctly and the key that resulted is the one the node now carries.

## Roles

- **Ceremony lead** — runs the procedure, owns the record.
- **Cosigner operators** (`n` of them) — each provisions and controls exactly one cosigner host, in
  a distinct trust domain (separate host / cloud account / region). No operator controls two shares.
- **Witnesses** (≥ 2, independent of the operators) — observe, verify the outputs independently, and
  sign the record.
- **Approvers** — the humans who will later authorize signing (see `docs/approval-quorum.md`); their
  public keys are fixed during the ceremony.

## Parameters to decide first

- **`t`-of-`n`** (threshold / cosigner count). Common: 2-of-3 (tolerates one loss), 3-of-5 (tolerates
  two). `t` = the number that must collude to sign; `n − t` = the number you can lose and still sign.
- **Cosigner placement** — the `n` distinct trust domains. Independence is the whole point; two
  shares in one cloud account is `t` effectively reduced.
- **Seal-secret custody** — where each cosigner's `RUTLI_SEAL_SECRET` lives (secret manager /
  systemd credential / enclave). Separate trust domain from the share backups.
- **Approver set** — the `M`-of-`N` approver keys for the signing policy.

## Pre-ceremony checklist

- [ ] `n` cosigner hosts provisioned, each in its own trust domain, clocks synced.
- [ ] Cluster mTLS PKI generated and distributed: `scripts/gen-frost-certs.sh <n>` → one CA, one
      cert per cosigner, one driver client cert. CA private key handled per your PKI policy.
- [ ] One shared cluster seal master secret minted (`openssl rand -hex 32`) and placed in each
      host's secret manager, exposed to the daemon as `RUTLI_SEAL_SECRET`. Each node derives its own
      per-node encryption key from it via HKDF (salted by node id) — so it's one secret, distinct
      keys. **Never on disk, never in the config.**
- [ ] Each cosigner JSON config authored with `"tls": { … }` and
      `"share_seal": { "secret_env": "RUTLI_SEAL_SECRET" }` set (see `deploy/frost/config-tls/`).
      Plaintext / no-TLS is disqualifying for a real ceremony.
- [ ] Approver keys minted: each approver runs
      `java -cp rutli-driver.jar com.stakecraft.rutli.policy.ApproveCli keygen <name>` and hands the
      printed public-key line to the lead.
- [ ] Canton node host prepared with the `rutli-driver.jar` on the classpath and a `crypto.kms`
      config using `backend = "frost"`, the full cosigner `endpoints`, `frost.tls`, and
      `audit-log-path` set. (Approval is usually left auto for the bootstrap signatures and tightened
      afterwards — see step 6.)
- [ ] Fresh Canton participant (no pre-existing identity): the namespace key cannot be migrated in,
      so the node MUST be new.

## Ceremony

**1. Stand up the cosigner cluster (sealed, mTLS).**
On each of the `n` hosts, with the seal secret present in the environment:
```sh
RUTLI_SEAL_SECRET="$(fetch-from-secret-manager)" \
  rutli-cosigner --config /etc/rutli/cosigner-<i>.json serve
```
Confirm each log line shows `mutual TLS enabled` and `share sealing enabled (AES-256-GCM at rest)`.
If any node logs `running WITHOUT TLS` or `share sealing DISABLED`, **halt** — do not proceed.

**2. Generate the key via node bootstrap (the DKG moment).**
Start the Canton participant once. Its identity auto-init calls the driver, which runs a distributed
key generation across the cluster for the namespace key `frost-<participant>-namespace` (and the
other node keys). This is the witnessed moment — the key comes into existence, distributed, here.
```sh
CANTON_HOME=/opt/canton CANTON_CONF=canton-frost.conf deploy/devnet/up.sh   # or your prod launcher
```
Witnesses confirm the node reaches `initialized` and the bootstrap prints the namespace public key
with `keySpec = EC-Curve25519`.

**3. Record the identity and group key.**
Capture, from the Canton console / node output:
- the participant identity `PAR::<participant>::<fingerprint>` — this is now permanent;
- the namespace key's public key (DER X.509 SubjectPublicKeyInfo, `EC-Curve25519`).

From the driver audit log (`audit-log-path`), capture the `generateSigningKeyPair …
name=<participant>-namespace` and the first `sign … outcome=ok` lines — proof the key was created in
the cluster and used to self-sign the identity topology.

**4. Verify the share distribution.**
On each cosigner, confirm exactly one sealed share file exists for the key and that it is a sealed
envelope, not plaintext:
```sh
ls  <data_dir>/keys/frost-<participant>-namespace.json
head -c 64 <data_dir>/keys/frost-<participant>-namespace.json   # must be a {"v":1,"sealed":true,…} envelope
```
Witnesses confirm `n` distinct hosts each hold one sealed share and that no host holds a plaintext
share or more than one.

**5. Take the founding backups.**
With the cluster quiesced or per-node, back up **each** share to cold storage in its trust domain:
```sh
rutli-cosigner --config /etc/rutli/cosigner-<i>.json backup --out /secure/backups/cosigner-<i>/ceremony
```
Confirm ≥ `t` backups exist in ≥ 2 separated locations (the recoverability line from the DR runbook).
Record where each backup and each seal secret live.

**6. Engage the controls.**
- Tighten the driver `approval` policy to `quorum` for the namespace key prefix and restart the node
  (or apply per your change process), so all *future* topology signatures require the `M`-of-`N`
  approver quorum. Record the approver set (ids + public keys) in the ceremony record.
- Confirm the signing journal (`signing-journal`) and hash-chained audit log (`audit-log-path`) are
  active.
- Set the proactive-refresh schedule (cron/systemd timer running `rutli-cosigner refresh --key-id
  frost-<participant>-namespace`), so any share exposed later has a bounded lifetime.

**7. Sign the record.**
The lead completes the ceremony record (template below); every witness and operator independently
verifies the identity + group key they captured match, and signs.

## Verification any party can repeat later

The node identity `PAR::<participant>::<fingerprint>` and the namespace public key are public and
immutable — anyone can re-read them from the running node and compare to the ceremony record. Any
mismatch means the identity changed (which must never happen outside a documented recovery) and is an
incident.

## Ceremony record template

```
RÜTLI NAMESPACE-KEY CEREMONY RECORD
───────────────────────────────────
Date / time (UTC):        ____________________
Ceremony lead:            ____________________
Canton network / env:     ____________________  (e.g. Splice testnet)
Participant / node name:  ____________________

Threshold:                t = ____  of  n = ____

Cosigners:
  #  identifier  host / trust domain        region     seal-secret location     backup location
  1  __________  _________________________  _________  _______________________  ________________
  2  __________  _________________________  _________  _______________________  ________________
  3  __________  _________________________  _________  _______________________  ________________
  … (n rows)

Outputs (captured & independently verified):
  Namespace key id:        frost-____________________-namespace
  Node identity:           PAR::____________::____________________________  (fingerprint)
  Group verifying key:     (Ed25519, hex) ______________________________________________________
  Namespace pubkey (SPKI): (base64) ____________________________________________________________

Controls engaged:
  Share sealing:           [ ] all cosigners sealed          mTLS: [ ] all cosigners + driver
  Approval policy:         M = ____ of N = ____   approvers (id : pubkey):
                             ____________ : ______________________________________________________
                             ____________ : ______________________________________________________
                             … 
  Audit log path:          ____________________     Signing journal: [ ] enabled
  Refresh schedule:        ____________________     Founding backups: [ ] ≥ t in ≥ 2 locations

Sign-off (each independently verified the identity + group key above):
  Lead:      ______________________  signature ______________________
  Operator1: ______________________  signature ______________________
  …
  Witness1:  ______________________  signature ______________________
  Witness2:  ______________________  signature ______________________
```

Store the completed record with your BCP / audit documentation. It is the reference against which
every future recovery (`docs/disaster-recovery.md`) is verified.

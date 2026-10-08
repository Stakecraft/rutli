# Split ceremony: moving an existing Canton namespace key into a Rütli cluster

**Status:** shipped in v0.4.0 (milestone B2 of [roadmap-migration.md](roadmap-migration.md)).
**Scope:** one existing Canton **Ed25519** key — in practice the namespace key — becomes a `t`-of-`n`
FROST key in a Rütli cluster with the **same public key and fingerprint**, so the namespace and every
party ID under it survive. The Canton side of a migration (new participant UID in the same namespace,
party move) is the B0 shape ([b0-cutover-spike.md](b0-cutover-spike.md)); the full rehearsed
procedure is B4 (`docs/migration.md`).

**Read this first.** A key born by DKG ([key-ceremony.md](key-ceremony.md)) never exists whole. A
key brought in by this ceremony **did**: on the old node, in its database, in its WAL and replicas,
in every backup of that database, in any export file, and — for a few seconds — in the dealer's
memory. Splitting it protects the future (no single cosigner can sign; one lost cosigner is
survivable; after the first refresh, a stolen share or bundle is worthless). It **cannot un-expose
the past**: anyone who copied the key before destruction (§7) holds it forever, and the namespace key
cannot be rotated. For a new node, use DKG. Use this ceremony only to keep an identity that already
exists.

---

## 1. Roles and what each one handles

| Role | Handles | Never handles |
|---|---|---|
| **Ceremony lead** | The record (§8), the go/no-go at each gate | Any key material |
| **Canton operator** | The old node: produces the key file (export or DB row), later the cutover | Cosigner hosts, seal secrets |
| **Dealer operator** | The air-gapped dealer host and the key file on it | Cosigner hosts, seal secrets |
| **Cosigner operators** (`n`) | One cosigner each: `share-recipient`, `import-share`, backups | The key file, other cosigners |
| **Witnesses** (≥ 2) | Independently compare fingerprints and digests at every gate, sign the record | — |

The key file and the dealer host are in a different trust domain from every cosigner and every seal
secret. A person who holds the key file must never also hold `t` seal secrets.

## 2. What the tooling guarantees

- **Offline only.** `share-recipient`, `import-share` and `abort-import` are CLI commands, never RPCs.
  `rutli-dealer` is a separate binary that is not in the cosigner image.
- **The dealer splits only the key you name.** `--expect-fingerprint` is mandatory; a key with a
  different fingerprint, a non-Ed25519 key, or (without `--any-usage`) a key without `namespace`
  usage is refused. Before writing anything it proves: group key == the key's public key byte for
  byte; every share passes VSS with `min_signers == t`; every `t`-subset reconstructs the key and
  produces a signature `verify_strict` accepts (`frost/core/src/dealer.rs`).
- **Each share reaches one node.** It is sealed to a one-time X25519 key that node minted for this
  ceremony and this key id, under an AAD binding node, cluster, key id, ceremony id, group key,
  fingerprint and public-key-package digest (`frost/cosigner/src/share_delivery.rs`). The secret half
  of that key lives sealed under the node's own seal key (`data_dir/ceremony/`, outside `keys/`, so
  never in a backup) and is deleted the moment the share is installed: from then on the bundle opens
  for nobody.
- **The envelope is not a signature.** Anyone who sees a recipient request can seal *something* to
  it. What makes a bundle trustworthy is the check chain at install — the fingerprint you typed, VSS
  against the commitment, the package interpolating to the group key — and `verify-key` comparing
  the package digest across all nodes and signing with the result. A forged bundle can at worst stall
  the ceremony; it cannot install a key someone else controls.
- **Install never overwrites.** `import-share` writes with a no-clobber create; DKG refuses every id
  containing `frost-import-` (`ALREADY_EXISTS`), before and after install, so a DKG can never mint or
  replace an imported key.
- **Provenance is recorded.** Each installed share carries `origin = dealer-split`, the ceremony id,
  the fingerprint and a refresh counter (inside the sealed file). The daemon warns at every start
  while a dealt key has never been refreshed.

## 3. Pre-flight

### 3.1 Parameters

| Item | Value / rule |
|---|---|
| `FP` | The key's Canton fingerprint, `1220…` (68 hex chars). For the namespace key it is the namespace: the part after `::` in `PAR::<uid>::<FP>`. Take it from the **old node** (`keys.public.list` / topology), never from a file the dealer produced. |
| `KEY_ID` | `<prefix>frost-import-<FP[4..12]>`, e.g. `frost-import-cb0e86a9`. `<prefix>` is the new participant's `frost.key-prefix` (empty by default); the driver routes the id to FROST because it starts with `<prefix>frost-`. |
| `CEREMONY` | One id for this ceremony on every node, `[A-Za-z0-9_-]{1,64}`, e.g. `b2-2026-10-20`. |
| `t`-of-`n` | The cluster's configured threshold and roster. Every node's config must agree. |

### 3.2 Location inventory (fill in before you start)

List every place the whole key exists **now**. This list is the input to destruction (§7); anything
missing from it survives the ceremony.

| # | Location | Example (Splice validator on k8s) | Owner |
|---|---|---|---|
| L1 | Live DB rows | `common_crypto_private_keys` in the participant database (`wrapper_key_id` NULL = plaintext) | |
| L2 | WAL, WAL archive, streaming/logical replicas, PITR base backups | Postgres `pg_wal`, archive bucket, replicas | |
| L3 | Logical dumps on cluster storage | the validator's backup PVC: **8 rotating `pg_dumpall` copies** (DevNet) | |
| L4 | Object storage | S3 `canton-k8s-validators-backup` (AES-256-CBC copies): **every object version and delete marker**; check whether object lock / retention is on (it blocks deletion) | |
| L5 | Provider snapshots | CSI / cloud volume snapshots of the Postgres and backup volumes | |
| L6 | Identities dumps | Splice participant identities dumps (they contain the private keys) | |
| L7 | Export files | `ExportKeyPair` / `keys.secret.download` outputs, wherever they were written or copied | |
| L8 | Operator machines | laptops, jump hosts, shell history, download folders | |
| L9 | Dealer media | the live-boot medium and any USB stick that carried the key file | |

Created by the ceremony, and also on the destruction list: the share bundles (sealed, dead after
install), any copy of a bundle inside a pod's `/tmp`, and every cosigner backup taken **between
install and the first refresh** (they hold the dealt shares, sealed; `t` of them plus the seal secret
are the key).

### 3.3 Checklist

- [ ] Cluster healthy: all `n` cosigners ready, version ≥ 0.4.0, mTLS and `share_seal` on (no
      `share sealing DISABLED` / `running WITHOUT TLS` in any log).
- [ ] `KEY_ID` absent on every node, and no DKG for it was ever attempted.
- [ ] **Cosigner backups suspended** for the ceremony window, so no backup captures dealt shares:
      `kubectl -n rutli patch cronjob rutli-cosigner-backup -p '{"spec":{"suspend":true}}'`
      (raw manifests: `cosigner-backup`). Same for any refresh CronJob on this key id.
- [ ] Dealer host: an air-gapped machine booted from a live medium, **no swap** (`swapon --show`
      empty), running as root (so `rutli-dealer` can `mlockall`). The `rutli-dealer` binary built from
      the release tag; its `sha256sum` recorded.
- [ ] The key file obtained from the old node (export, preferably password-protected; or the DB row)
      and carried to the dealer host on removable media. Note L7/L8 for every copy.
- [ ] Location inventory §3.2 complete.

## 4. The ceremony

`C<i>` below is node *i*'s config. On Kubernetes, node *i* is pod `cosigner-<i-1>` with
`/config/cosigner-<i>.json`; every cosigner command runs **inside the live pod** with
`kubectl -n rutli exec cosigner-<i-1> -c cosigner -- …` (the pod already has `RUTLI_SEAL_SECRET`).
Nothing needs the daemon stopped: the install is a no-clobber create and the daemon caches nothing
for an id it does not have.

### Step 1 — recipient requests (each cosigner operator)

```sh
rutli-cosigner --config C<i> share-recipient --key-id "$KEY_ID" --ceremony-id "$CEREMONY" --out /tmp/r<i>.json
kubectl -n rutli exec cosigner-<i-1> -c cosigner -- cat /tmp/r<i>.json > r<i>.json
```

`r<i>.json` is public. It names the node, cluster, key id, ceremony, `t`, `n`, roster and the
one-time `recipient_pub`. Carry all `n` to the dealer host (removable media). Witnesses record each
`recipient_pub`.

### Step 2 — split (dealer operator, air-gapped host)

```sh
read -rs EXPORT_PW && export EXPORT_PW        # only for a password-protected export
rutli-dealer split-key --in namespace.export --password-env EXPORT_PW \
  --expect-fingerprint "$FP" --key-id "$KEY_ID" --threshold <t> \
  --recipient r1.json --recipient r2.json --recipient r3.json --out-dir out/
```

A DB row works too: `--in row.bin`, or hex text from `psql` with `--stored-hex`. The dealer refuses
on any disagreement between the requests, a missing or duplicate node, a wrong fingerprint, or an
existing output file. Outputs in `out/`: `share-<KEY_ID>-node<i>.json` per node (`0600`) and
`dealer-record.json` (public: package, **pkp digest**, recipient keys, binary hash, hardening
outcome). Any `warning:` line about core dumps, dumpability or memory locking goes in the record.

Witnesses record the printed **group key** and **pkp digest**. Then power the dealer host off.

### Step 3 — dry run (each cosigner operator)

```sh
kubectl -n rutli exec -i cosigner-<i-1> -c cosigner -- sh -c 'umask 077; cat > /tmp/share.json' < share-$KEY_ID-node<i>.json
rutli-cosigner --config C<i> import-share --in /tmp/share.json --expect-fingerprint "$FP" --dry-run
```

Every check runs, nothing is written. **Gate A:** all `n` print `"outcome": "dry-run"` and the same
`pkp_digest` as `dealer-record.json`; the fingerprint each operator typed is the one from §3.1, read
from the old node.

### Step 4 — install (each cosigner operator)

```sh
rutli-cosigner --config C<i> import-share --in /tmp/share.json --expect-fingerprint "$FP"
kubectl -n rutli exec cosigner-<i-1> -c cosigner -- rm -f /tmp/share.json /tmp/r<i>.json
```

Prints `"outcome": "installed"`, this node's verifying share and the pkp digest; the recipient secret
is deleted. Running it again with the same bundle prints `"already-installed"`; anything else under
the id is `KeyExists`. Until all `n` nodes have installed, a node without the share cannot *lead* a
sign (`NOT_FOUND`), so do not cut over before Gate B.

### Step 5 — verify (lead, with the driver's client cert, like the refresh CronJob)

```sh
rutli-cosigner --config <operator config> verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test
```

It asks every node for `KeyStatus` and checks: present on all `n`; each answers as its configured
identifier; every group key has fingerprint `FP`; one package digest everywhere (recomputed from the
package); each node's own verifying share is the package's; the package interpolates for `t`; same
provenance. `--sign-test` then has **each node lead one signature** over
`0x1220 ‖ SHA-256("rutli-verify-key/" ‖ CEREMONY ‖ KEY_ID)` and checks it with `verify_strict` under
the Canton key. (Those bytes cannot be a Canton topology hash: Canton's begin with a 4-byte hash
purpose. The test bypasses the driver's approval policy exactly as `refresh` does.)

**Gate B:** `OK`, refresh count 0, digest = `dealer-record.json`, `n` signatures verified.

### Step 6 — refresh, then verify again

```sh
rutli-cosigner --config <operator config> refresh --key-id "$KEY_ID"
rutli-cosigner --config <operator config> verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test
```

**Gate C:** the group key is unchanged, `verify-key` is `OK` with **refresh count 1** and a **new
pkp digest**. From here on the dealt shares — every bundle, every copy the dealer ever held — no
longer combine with the live ones. Be precise about what this buys: refresh re-randomises the
sharing; it does **nothing** about the whole key in §3.2's locations. Its job is to make a leaked
dealt share useless, not to undo the key's history.

### Step 7 — founding backups

Take the founding backups now, after the refresh (they hold refreshed shares only):
[key-ceremony.md](key-ceremony.md) step 5 / [disaster-recovery.md](disaster-recovery.md) §1. Then
resume the backup CronJob (`"suspend": false`) and re-enable any refresh schedule, now including
`KEY_ID`.

### Step 8 — Canton cutover

Per the B0 shape ([b0-cutover-spike.md](b0-cutover-spike.md)): a **new participant UID under the same
namespace**, the imported key registered by KMS id — `RegisterKmsSigningKey(kms_key_id = KEY_ID,
usage = namespace)` must return `FP` — then the party move. Driver and Canton see an ordinary FROST
key: no driver change is involved. The full procedure, including the old node's offboarding, is B4.

### Step 9 — destruction (only after the cutover go)

Not before: until the cutover is confirmed good, the old node (and its key) is the rollback path.
After it, destroy every item of §3.2 and §3.2's "created by the ceremony" list, and record evidence
per item in the destruction record (§8):

| Location | How | Evidence |
|---|---|---|
| L1 DB rows | `DELETE` the key rows, or `DROP DATABASE` of the old participant | the statement and its output; a follow-up `SELECT` |
| L2 WAL / archive / replicas | expire the archive, rebuild or drop replicas, delete PITR base backups older than the DROP | retention settings, listings before/after |
| L3 `pg_dumpall` copies | delete all 8 (and the rotation's next run must not recreate the old DB) | listing before/after |
| L4 S3 | delete **every version and delete marker** (`list-object-versions`), not just current objects; if object lock is on, record the retention end date — the copy exists until then | version listings before/after |
| L5 snapshots | delete every snapshot taken while the key was in the DB | provider listing |
| L6 identities dumps | delete every copy | listing |
| L7/L8 exports, laptops | delete and empty trash; note where secure erase is impossible (SSD, cloud sync) | operator statement |
| L9 dealer media | destroy or securely wipe the boot medium and transfer media | operator statement |
| Bundles, pod `/tmp` copies | delete (they are dead already; this is hygiene) | listing |
| Pre-refresh cosigner backups | delete any backup taken between Step 4 and Step 6 | listing |

**Residual exposure, stated plainly.** Deletion on SSDs, copy-on-write filesystems, cloud storage
and backups-of-backups is not provable erasure. Anyone who obtained the key before Step 9 keeps it,
and a namespace key cannot be rotated. What the ceremony gives is a key that from now on is used only
by a threshold of independent cosigners, survives the loss of `n − t` of them, and can be audited.

## 5. Aborting

Before Gate B, on any doubt, back out per node:

```sh
rutli-cosigner --config C<i> abort-import --key-id "$KEY_ID" --ceremony-id "$CEREMONY" [--yes-delete-installed-share]
```

It always deletes the pending recipient secret (if it belongs to this ceremony). It deletes an
installed share **only** if that share came from this ceremony, was never refreshed, and the flag is
given — so it can never touch a DKG key, another ceremony's key, or a refreshed (live) key. Restart a
running cosigner after deleting a share so it drops any cached copy. There is deliberately no generic
key-destroy command. Then start again from Step 1 with a new `CEREMONY` id.

## 6. Failure table

| Symptom | Meaning | Action |
|---|---|---|
| dealer: `fingerprint … not the expected` | wrong key file, or wrong `FP` typed | stop; re-check `FP` on the old node |
| dealer: `recipients disagree` | a node has a different config (threshold, roster, cluster) or ceremony id | fix the config, redo Step 1 on that node (`--replace`) |
| dealer: `swap is enabled` | the host has swap | `swapoff -a`, or use the right host. `--allow-swap` is for tests |
| `import-share`: `for node 2, this is node 1` | wrong bundle for this node | use `share-<KEY_ID>-node<i>.json` |
| `import-share`: `no pending recipient` | Step 1 not run here, or already installed/aborted | `verify-key`; or redo from Step 1 |
| `import-share`: `failed authentication` | bundle not for this node's current recipient key, or altered | redo Step 1 (`--replace`) and Step 2 for all nodes |
| `import-share`: `KeyExists` | something else is installed under `KEY_ID` | stop; investigate; `abort-import` only if it is this ceremony's |
| `verify-key`: different packages | nodes installed bundles from different dealer runs | `abort-import --yes-delete-installed-share` everywhere, redo |
| `refresh` fails | a node is down, or has no share | fix and re-run, then `verify-key`: a refresh refused at the fence or in part 1 changes nothing, but one that failed while nodes were persisting can leave them on different packages, which `verify-key` reports |
| startup WARN `never been refreshed` | Step 6 not done | do Step 6 |

## 7. Verification anyone can repeat

`verify-key --sign-test` at any time; `RegisterKmsSigningKey`/`keys.public.list` on the new
participant shows `FP`; the namespace in `PAR::<uid>::<FP>` is unchanged. The dealer record and the
`verify-key` output are public and belong in the ceremony record.

## 8. Records

```
RÜTLI SPLIT CEREMONY RECORD
───────────────────────────
Date / time (UTC):          ____________________     Ceremony id: ____________________
Lead:                       ____________________     Network / env: _________________
Old participant:            PAR::________________::__________________________________
Key fingerprint (FP):       1220________________________________________________________________
  read from the old node by: ______________ via: ______________________________
Imported key id:            ____________________frost-import-________   t = ____ of n = ____

Recipients (Step 1):
  node  identifier  pod / host            recipient_pub (hex)                       operator
  1     ________    __________________    ________________________________________  ________
  2     ________    __________________    ________________________________________  ________
  3     ________    __________________    ________________________________________  ________

Dealer (Step 2):
  host / boot medium:       ____________________     swap off: [ ]   ran as root: [ ]
  rutli-dealer sha256:      ________________________________________________________________
  key input:                [ ] export (password)  [ ] export  [ ] DB row  [ ] PKCS#8
  dealer warnings:          ____________________________________________________________
  group key:                ________________________________________________________________
  pkp digest (dealer):      ________________________________________________________________

Gate A dry run (digest per node):  1 ________  2 ________  3 ________   [ ] all equal dealer's
Install (Step 4):                  1 [ ]  2 [ ]  3 [ ]   bundles + /tmp copies removed: [ ]
Gate B verify-key:                 [ ] OK  refresh count 0  signatures 1 [ ] 2 [ ] 3 [ ]
Gate C after refresh:              [ ] OK  refresh count 1  new digest ______________________
Founding backups (after refresh):  locations ___________________________   backups resumed: [ ]
Cutover (B0/B4 shape):             RegisterKmsSigningKey(KEY_ID) returned FP: [ ]   go: [ ]

Sign-off (each independently compared FP, group key and digests):
  Lead: ____________  Dealer op: ____________  Cosigner ops: ____________ ____________ ____________
  Witness 1: ____________  Witness 2: ____________
```

```
DESTRUCTION RECORD — key FP 1220______________________  (after cutover go on ____-__-__)
  #   location                          action taken                    evidence (ref)        by      date
  L1  DB rows                           _____________________________   ___________________   _____   ____
  L2  WAL / archive / replicas          _____________________________   ___________________   _____   ____
  L3  pg_dumpall copies (8)             _____________________________   ___________________   _____   ____
  L4  S3 versions + delete markers      _____________________________   ___________________   _____   ____
      object lock / retention until:    _____________________________
  L5  provider snapshots                _____________________________   ___________________   _____   ____
  L6  identities dumps                  _____________________________   ___________________   _____   ____
  L7  export files                      _____________________________   ___________________   _____   ____
  L8  operator machines                 _____________________________   ___________________   _____   ____
  L9  dealer media                      _____________________________   ___________________   _____   ____
  --  share bundles, pod /tmp copies    _____________________________   ___________________   _____   ____
  --  pre-refresh cosigner backups      _____________________________   ___________________   _____   ____
  Known residual copies (not erasable): ____________________________________________________
  Signed: lead ____________  witness ____________  witness ____________
```

## 9. Rehearsal

`scripts/e2e-split-ceremony.sh` runs Steps 1–6 (plus restarts, a node down and the refusals) on a
local 3-node mTLS cluster from the working tree, with B1's throwaway Canton 3.6.1 namespace key.
The cluster tests in `frost/cosigner/tests/split_ceremony.rs` and `dealer_cli.rs` are the automated
analogue.

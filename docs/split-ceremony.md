# Split ceremony: moving an existing Canton namespace key into a Rütli cluster

**Status:** shipped in v0.4.0 (milestone B2 of [roadmap-migration.md](roadmap-migration.md)).
**Scope:** one existing Canton **Ed25519** key — in practice the namespace key — becomes a `t`-of-`n`
FROST key in a Rütli cluster with the **same public key and fingerprint**, so the namespace and every
party ID under it survive. The same ceremony can carry a protocol signing or sequencer-authentication
key (`rutli-dealer split-key --expect-usage protocol`, ids `<prefix>frost-import-sig-…` /
`…-seqauth-…`, roadmap B6); that is possible and discouraged, see [migration.md](migration.md) §8.
The default, `--expect-usage namespace`, takes a key whose recorded usage is namespace alone, and
asks for `--namespace-fingerprint` (the old node's namespace, from its UID) wherever the usage alone
cannot tell the namespace key from another key, such as a Splice `signing` key, whose usage
`SigningKeyUsage.All` includes namespace. The Canton side of a migration (new participant UID in
the same namespace, party move) is the B0 shape ([b0-cutover-spike.md](b0-cutover-spike.md)); the full rehearsed
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
  different fingerprint, a non-Ed25519 key, or a key whose usage does not match `--expect-usage`
  (default `namespace`: usage namespace alone, or `--namespace-fingerprint` equal to the key) is
  refused, as is an id of the other mode's class (`…frost-import-sig-…` / `…-seqauth-…` are
  protocol ids). Before writing anything it proves: group key == the key's public key byte for
  byte; every share passes VSS with `min_signers == t`; every `t`-subset reconstructs the key and
  produces a signature `verify_strict` accepts (`frost/core/src/dealer.rs`).
- **Each share reaches one node.** It is sealed to a one-time X25519 key that node minted for this
  ceremony and this key id, under an AAD binding node, cluster, key id, ceremony id, group key,
  fingerprint and public-key-package digest (`frost/cosigner/src/share_delivery.rs`). The secret half
  of that key lives sealed under the node's own seal key (`data_dir/ceremony/`, outside `keys/`, so
  never in a backup) and is deleted the moment the share is installed: from then on the bundle opens
  for nobody.
- **A request proves which node made it — forged requests are the dangerous direction.** A request
  names the key the dealer seals a *real* share to; whoever substitutes `t` requests on their way to
  the dealer gets `t` real shares, i.e. the key. So each request is signed with the node's mTLS key
  and carries its certificate chain; the dealer (`--ca-cert`, mandatory) refuses any request that
  does not verify to the cluster CA as coming from certificate CN `cosigner<identifier>`, or whose
  cluster id is not that CA's (`frost/cosigner/src/request_auth.rs`). Independently, each request
  has a **SAS** (16 hex characters of its digest) that witnesses read in the pod and the dealer
  operator must type back (Gate 0). Defeating both needs a CA-issued cosigner key *and* a witness
  who confirms the wrong SAS.
- **The bundle envelope is not a signature.** Anyone who sees a recipient request can seal
  *something* to it. What makes a bundle trustworthy is the check chain at install — the
  fingerprint you typed, VSS against the commitment, the package interpolating to the group key —
  and `verify-key` comparing the package digest across all nodes and signing with **every** `t`-subset
  of them. A forged bundle cannot install a key someone else controls — but it does mean someone
  else had access to the path, so it is handled as a possible exposure (§6), never just retried.
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
      empty), no core handler (`sysctl kernel.core_pattern` not starting with `|`,
      `fs.suid_dumpable` ≠ 2), running as root (so `rutli-dealer` can `mlockall`). The
      `rutli-dealer` binary built from the release tag; its `sha256sum` recorded.
- [ ] The cluster CA certificate on the dealer host: **the exact file** the cosigners use as
      `tls.ca_cert` (the cluster id is a hash of its bytes); its SHA-256 compared by a witness with
      the one in the cluster (`kubectl -n rutli exec cosigner-0 -c cosigner -- sha256sum /certs/ca.crt`).
- [ ] An **operator certificate** for `verify-key` (CN `operator`, issued by the cluster CA —
      `scripts/gen-frost-certs.sh` makes one) and every cosigner config listing it in
      `operator_allowlist` (Helm: `operatorAllowlist`). The operator role may call `KeyStatus` and
      `CeremonySignTest` only — never `Sign` — so no one in the ceremony needs the driver
      certificate. Each cosigner's mTLS certificate has CN `cosigner<identifier>`. On Kubernetes,
      create the operator Secret only for the ceremony and run `verify-key` as the one-off
      `deploy/k8s/job-verify-key.example.yaml`; delete both afterwards.
- [ ] Per-node TLS deployment (chart/manifests ≥ 0.4.0, `tls.layout: perNode` or at least the
      `tls-select` init container): each cosigner container holds only its own mTLS key, so one
      compromised cosigner cannot sign recipient requests as another node. **Residual risk:** whoever
      has `get secrets` in the namespace (or root on a cosigner's node) holds every node's key and
      could sign requests as any node — list those people in the record; Gate 0's SAS, read in the
      pod by a witness, is the control that does not depend on them.
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
one-time `recipient_pub`, and is signed with the node's mTLS key (certificate chain embedded). The
command's last line is `SAS node <i> <16 hex>`. Carry all `n` request files to the dealer host
(removable media).

### Gate 0 — SAS, over an independent channel (witnesses)

For each node, a witness opens **their own** `kubectl exec` session to the pod (not the operator's
session, not a relayed screenshot) and runs the read-only

```sh
rutli-cosigner --config C<i> recipient-sas --key-id "$KEY_ID"
# SAS node <i> <16 hex> ceremony <CEREMONY> key <KEY_ID>
```

which recomputes the SAS from the request stored in the node's sealed recipient file — what the
node actually signed, independent of any file that travelled. It must equal the line
`share-recipient` printed; the witness writes it into the record (§8). The dealer operator types
those recorded values in Step 2. A request file that was
replaced in transit has a different SAS; and even a witness who was fooled would not get a forged
request past the dealer's signature check — the SAS is the second, independent lock.

### Step 2 — split (dealer operator, air-gapped host)

```sh
# Password-protected export: the password lives only in this subshell's environment.
(
  IFS= read -rs EXPORT_PW && export EXPORT_PW
  rutli-dealer split-key --in namespace.export --password-env EXPORT_PW \
    --expect-fingerprint "$FP" --key-id "$KEY_ID" --threshold <t> --ca-cert ca.crt \
    --recipient r1.json --recipient r2.json --recipient r3.json --out-dir out/
  unset EXPORT_PW
)
```

The dealer first verifies every request (signature by the named cosigner's certificate, chain to
`ca.crt`, cluster id) and prints `request node <i>: SAS …` for each; it then asks for each node's
SAS as recorded at Gate 0 (or takes `--confirm-sas <sas1,sas2,…>` in identifier order) and refuses
on any mismatch — all before it reads the key. A DB row works too: `--in row.bin`, or hex text
from `psql` with `--stored-hex`. It also refuses on any disagreement between the requests, a
missing or duplicate node, a wrong fingerprint, swap, a core handler, or an existing output file.
Outputs in `out/`: `share-<KEY_ID>-node<i>.json` per node (`0600`) and `dealer-record.json` (public:
package, **pkp digest**, recipient keys, SAS and signer chains, binary hash, hardening outcome
including `core_pattern` / `suid_dumpable`). Any `warning:` line goes in the record.

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

### Step 5 — verify (lead, with the **operator** certificate)

```sh
rutli-cosigner --config <operator config> verify-key --key-id "$KEY_ID" --expect-fingerprint "$FP" --sign-test
```

`<operator config>` is a cosigner-shaped config whose `tls` block points at `ca.crt` and
`operator.{crt,key}`; the command reads only its roster, threshold and TLS settings. It asks every
node for `KeyStatus` and checks: present on all `n`; each answers as its configured identifier;
every group key has fingerprint `FP`; one package digest everywhere (recomputed from the package);
each node's own verifying share is the package's; the package interpolates for `t`; same
provenance. A public view can be perfect while a node's *secret* share is wrong, so `--sign-test`
then has the cluster sign with **every `t`-subset** of cosigners — `C(n,t)` signatures, 3 for
2-of-3, `{1,2}`, `{1,3}`, `{2,3}`, the leader rotating — through `CeremonySignTest`: the cosigners
sign exactly that quorum, over a digest they compute themselves from the key's provenance,
`0x1220 ‖ SHA-256("rutli-verify-key/" ‖ CEREMONY ‖ KEY_ID)`, and verify-key checks each with
`verify_strict` under the Canton key. (That digest is domain-separated from every hash Canton signs:
Canton hashes `be_i32(HashPurpose.id) ‖ content` (`HashBuilder.scala:192-205`), every purpose Canton
3.6.1 defines is 1–68, or −1 for test hashes (`HashPurpose.scala:52-123`), and this preimage starts
with the ASCII bytes `rutl`, which as a purpose would be 1 920 300 396; equal digests would take a
SHA-256 collision. The operator role cannot ask for any other message, and cannot `Sign`.)

**Gate B:** `OK`, refresh count 0, digest = `dealer-record.json`, every one of the `C(n,t)` quorums
verified.

### Step 6 — refresh, then verify again

```sh
rutli-cosigner --config <driver config> refresh --key-id "$KEY_ID"    # the refresh CronJob's cert
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
given — so it can never touch a DKG key, another ceremony's key, or a refreshed (live) key. There is
deliberately no generic key-destroy command.

**After deleting an installed share, restart that cosigner before anything is imported under the
id again — this is mandatory.** A running daemon that has signed (Gate B) with the share keeps it
cached; a new share installed under the same id would sit next to a stale cached one until the
next restart. On Kubernetes: `kubectl -n rutli delete pod cosigner-<i-1>`, wait for Ready, and
confirm `verify-key` reports the key absent on that node. Then start again from Step 1 with a new
`CEREMONY` id.

## 6. Failure table

| Symptom | Meaning | Action |
|---|---|---|
| dealer: `fingerprint … not the expected` | wrong key file, or wrong `FP` typed | stop; re-check `FP` on the old node |
| dealer: `recipients disagree` | a node has a different config (threshold, roster, cluster) or ceremony id | fix the config, redo Step 1 on that node (`--replace`) |
| dealer: `swap is enabled` | the host has swap | `swapoff -a`, or use the right host. `--allow-swap` is for tests |
| dealer: `a crash would still reach a core handler` | piped `core_pattern` or `suid_dumpable = 2` | `sysctl -w kernel.core_pattern=core fs.suid_dumpable=0`, or use the right host |
| dealer: `recipient request authentication: …` (bad signature, wrong CA, CN not `cosigner<i>`, wrong cluster) | the request was **not** made by the node it names — substituted or altered in transit, or the wrong CA file | **STOP. Treat as an attack on the ceremony.** Do not re-run with other files. Seal nothing; record it; find out who could write to the transfer path. The key has not been exposed by this (nothing was sealed). |
| dealer: `SAS mismatch for node <i>` | the request file is not the one the pod printed | **STOP**, as above |
| `import-share`: `for node 2, this is node 1` | wrong bundle for this node | use `share-<KEY_ID>-node<i>.json` |
| `import-share`: `no pending recipient` | Step 1 not run here, or already installed/aborted | `verify-key`; or redo from Step 1 |
| `import-share`: `failed authentication` | the bundle was not sealed to this node's current recipient key, or was altered — i.e. something other than the dealer's output reached this node | **STOP. Treat as a possible key exposure.** Someone had write access to the bundle path, and may have had read access to the other bundles or tampered with the requests the dealer saw. Investigate (dealer record vs Gate 0 SAS, transfer media, who touched the files) **before any re-deal**; never just redo Steps 1–2. If a dealt bundle may have reached someone else, the ceremony's output is suspect: abort everywhere and decide on the key with the lead. |
| `import-share`: `KeyExists` | something else is installed under `KEY_ID` | stop; investigate; `abort-import` only if it is this ceremony's |
| `verify-key`: different packages | nodes installed bundles from different dealer runs | `abort-import --yes-delete-installed-share` everywhere, restart those cosigners (§5), redo |
| `verify-key`: a sign-test quorum fails | a node's secret share does not match the package (corrupted, mis-installed), or a node is down | do not proceed; `verify-key` names the quorum; investigate that node |
| `refresh` fails | a node is down, or has no share | fix and re-run, then `verify-key`: a refresh refused at the fence or in part 1 changes nothing |
| `refresh` half-applied on an imported key (`verify-key`: different packages, refresh counts disagree) | some nodes persisted the refreshed sharing, others did not | the key id is a **dead end**: there is no safe way to merge the two sharings. Re-run the whole ceremony under a **new `KEY_ID`** (new `CEREMONY`, Steps 1–7) from the old node's key, then cut over to the new id; abort the old id's leftovers per node. (Before the cutover the old node still holds the key.) |
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

Recipients (Step 1) and Gate 0 (SAS read in the pod, independent session):
  node  identifier  pod / host            SAS (16 hex)        read by (witness)   operator
  1     ________    __________________    ________________    ________________    ________
  2     ________    __________________    ________________    ________________    ________
  3     ________    __________________    ________________    ________________    ________
  CA file sha256 (cluster = dealer host): ______________________________________   [ ] equal

Dealer (Step 2):
  host / boot medium:       ____________________     swap off: [ ]   ran as root: [ ]
  core_pattern / suid_dumpable:  __________________ / ____   all requests verified: [ ]
  SAS confirmed at the dealer (equal to Gate 0): [ ]
  rutli-dealer sha256:      ________________________________________________________________
  key input:                [ ] export (password)  [ ] export  [ ] DB row  [ ] PKCS#8
  dealer warnings:          ____________________________________________________________
  group key:                ________________________________________________________________
  pkp digest (dealer):      ________________________________________________________________

Gate A dry run (digest per node):  1 ________  2 ________  3 ________   [ ] all equal dealer's
Install (Step 4):                  1 [ ]  2 [ ]  3 [ ]   bundles + /tmp copies removed: [ ]
Gate B verify-key (operator cert): [ ] OK  refresh count 0  quorums {1,2} [ ] {1,3} [ ] {2,3} [ ]
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

`scripts/e2e-split-ceremony.sh` runs Steps 1–6 (with SAS confirmation, a forged request and a
wrong SAS refused, the operator certificate refused on `Sign` and `Refresh`, restarts, a node down)
on a local 3-node mTLS cluster from the working tree, with B1's throwaway Canton 3.6.1 namespace key.
The cluster tests in `frost/cosigner/tests/split_ceremony.rs` and `dealer_cli.rs` are the automated
analogue.

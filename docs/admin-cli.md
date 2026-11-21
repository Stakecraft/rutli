# Admin CLI

Which command does what to a key, where it runs and which credential it needs. Details are in the
linked pages.

There is no separate admin tool. Canton creates keys through the driver, the offline tools import
them, and everything an operator reads or checks afterwards is a `rutli-cosigner` subcommand.
`rutli-dealer` is a second binary on purpose: it handles a whole private key, runs only on the
air-gapped dealer host and is not in the cosigner image.

## Commands by task

| Task | Command | Credential |
|---|---|---|
| Generate a FROST key (namespace, signing) | Canton, at bootstrap or from the console (`keys.secret.generate_signing_key`); the driver runs the DKG. [key-ceremony.md](key-ceremony.md) | The driver certificate (`signer_allowlist`, `signer_acl`). It signs the ceremony intent |
| Generate a hosted key (encryption) | Canton (`keys.secret.generate_encryption_key`), with `hosted-keys = true` in the driver. [hosted-keys.md](hosted-keys.md) | The driver certificate. It signs the generate intent |
| Import an Ed25519 key as shares | `rutli-dealer split-key` on the dealer host; `share-recipient`, `recipient-sas`, `import-share` on each cosigner. [split-ceremony.md](split-ceremony.md) | Each node's own config, TLS key and seal. The dealer holds the key itself |
| Import an ECIES key | `rutli-cosigner import-key` on one cosigner; the cluster replicates it. [hosted-keys.md](hosted-keys.md#export-and-import-portable-copies) | That node's config and seal |
| Show a cluster key: public key, fingerprint, origin, epoch | `rutli-cosigner key show --key-id ID` | An operator certificate (`operator_allowlist`) |
| Fingerprint of a public key file | `rutli-cosigner key fingerprint --in FILE` | None. Offline |
| Verify a key against the fingerprint you expect | `key show --expect-fingerprint FP`, or `verify-key` (FROST, adds `--sign-test`) and `verify-hosted` | An operator certificate |
| Refresh the shares of a FROST key | `rutli-cosigner refresh --key-id ID`. [key-rotation.md](key-rotation.md#2-share-refresh--rotate-the-secret-keep-the-key-rütli) | A refresher certificate (`refresh_allowlist`), or the driver certificate while `signing_policy.signer_may_refresh` is on. It signs the ceremony intent |
| Rotate a signing or encryption key | Canton console. [key-rotation.md](key-rotation.md#the-recipe) | The namespace key, through the driver |
| Delete a hosted key | `rutli-cosigner delete-hosted-key`; undo with `hosted-undelete` on each node. [hosted-keys.md](hosted-keys.md#delete) | A certificate on `hosted_keys.delete_allowlist`, plus approvals if configured |
| Delete a FROST key | No command for a key in use. `abort-import` backs out of a split ceremony, `discard-partial-key` removes a legacy partial DKG ([ceremonies.md](ceremonies.md)) | |

The operator role (`operator_allowlist`) can read key status and run the fixed sign test, and
nothing else: no signing, decrypting, generating, refreshing or deleting, unless the same
certificate name is also put on another allowlist. `deploy/k8s/client-config.yaml` has a client
config for it (`client-operator.json`).

Backup, restore, `export-key` and the key-file commands are in
[disaster-recovery.md](disaster-recovery.md), seal bundles in
[runbook-per-node-seal.md](runbook-per-node-seal.md), stuck ceremonies in
[ceremonies.md](ceremonies.md), `residue-scan` in [residue-scan.md](residue-scan.md), `check-config`
in [production-profile.md](production-profile.md).

## `key show`

```sh
rutli-cosigner --config client-operator.json key show --key-id acme1-frost-signing
```

```
key show acme1-frost-signing (FROST) — no expected fingerprint: the nodes' own report, compared with nothing
  node 1 https://…: fp 1220… digest … own-share ok origin dkg ceremony "" refreshes 0
  node 2 https://…: fp 1220… digest … own-share ok origin dkg ceremony "" refreshes 0
  node 3 https://…: fp 1220… digest … own-share ok origin dkg ceremony "" refreshes 0
  group key d75a…511a
  pkp digest …
  fingerprint 1220…
  origin dkg epoch 1 refreshes 0 threshold 2
OK
```

The `fingerprint` line, and `fingerprint` in the JSON report, are there only when every check
passed. A report that ends in `FAILED` names no fingerprint for the cluster; each node's own is in
its line.

It asks every node in the config's roster and exits non-zero unless all of them hold the key and
agree on it. A `<prefix>rutli-…` id is read as a hosted key, any other id as a FROST key, the
same rule the cosigners apply. The checks are those of `verify-key` and `verify-hosted`: the same
two read-only RPCs, the same code. `--json` prints the report; its `kind` is `frost` or `hosted`.

For a hosted key it prints the public key (SPKI, hex) and the fingerprint; the spec is in each
node's line. A symmetric key (AES) has neither. `OK` then means only that every node holds a key of
that spec under the id, not that it is the same key.

A hosted key under an id without the `rutli-` tag can only be left over from before 0.4.0-rc.6.
`key show` looks for a FROST key there and fails; use `verify-hosted` for such an id.

**The output is the cluster's own report.** Each node says what it holds. Without
`--expect-fingerprint` nothing is compared with anything you know from elsewhere, so `OK` means the
nodes agree and nothing more. A compromised node can report what it likes.

- To check a key, pass the fingerprint from the other side: `keys.secret.list` on the participant,
  or the old node for an import.
- Never take the `--expect-fingerprint` of `import-key`, `import-share` or `verify-key` from
  `key show`. That value has to come from outside the cluster.
- `key show` does not sign. After a split ceremony use `verify-key --sign-test`.

## `key fingerprint`

```sh
rutli-cosigner key fingerprint --in namespace.pub
```

Prints the Canton fingerprint (`1220…`) on stdout and what the file was read as on stderr. It needs
no config and no network. It reads:

- a Canton public key file (`keys.public.download`),
- X.509 SubjectPublicKeyInfo as DER, as one `PUBLIC KEY` PEM block, or as hex (what `key show`
  prints for a hosted key),
- a raw Ed25519 public key as 64 hex digits (what `key show` prints as the group key).

Public keys only. A private key in PEM, PKCS#8 or a Canton key export is refused. 64 hex digits
are always read as a public key, and a raw Ed25519 private seed looks the same: never give this
command a secret.

## What the CLI does not do

- **List keys.** Take the ids from Canton: `keys.secret.list` shows each key's KMS id.
- **Generate keys.** Canton does, through the driver, so the key is registered where it is used and
  the generation is in the driver's audit log.
- **Import over the network.** Imports are local to a node, by design.

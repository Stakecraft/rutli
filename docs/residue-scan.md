# Residue scan

`rutli-cosigner residue-scan` lists the key material on a node's volume, and in the backups you
name, that is not the node's live, current state. Typical uses are after a refresh, a DEK rotation,
a split ceremony or a key deletion, and before a volume or a backup leaves your control.

```bash
rutli-cosigner --config <node.json> residue-scan [--backup <dir|tar>]... [--legacy-master-env VAR] [--json]
```

It reads `data_dir` and every `--backup`. A backup can be a directory, a plain (uncompressed) tar
such as the backup sidecar's `node-<id>-<stamp>.tar`, or a single key file. Decompress a compressed
archive first. The scan writes nothing and deletes nothing.

**What it can say.** "Nothing found on the paths given", never "the key is destroyed". A file walk
sees files, not the bytes a deleted file left on the disk, nor anything outside the paths it was
given. Every report ends with a fixed **NOT CHECKED** block that says so (see below).

## Next to a running daemon

The scan can run inside the cosigner's pod while the daemon serves:

- it takes no lock: not the daemon's instance lock, not any file lock;
- it opens files read-only, never creates a directory and never follows a symbolic link, not even
  one swapped in after the walk looked (files are opened with no-follow and must be regular);
- a file that disappears or appears while the scan walks its directory (a refresh, a backup run) is
  reported as `[changed]`, not as an error.

A test runs scans in a loop beside a signing cluster, with the node's instance lock held and a
refresh in the middle: every signature succeeds within its deadline and no scan reports a read
error.

## What it needs

The node's config, and its seal keys (`share_seal`) to tell which DEK sealed a file:

- **v2 key files** name their DEK in the clear header; nothing is decrypted.
- **v1 key files** are opened once with the current DEK. Only the record's `epoch` and kind are
  read; the plaintext is wiped from memory straight away.
- Without `share_seal` the scan still runs, and NOT CHECKED says sealed files were not told apart by
  DEK.

## Findings

One line per finding, most severe first:

```text
[finding] <class>: <path> key=<key id> epoch=<n> dek=<dek id>
```

A field the file does not reveal prints as `-`. A path inside a tar is `<tar>!<entry name>`. The
entry name is only printed; it is never turned into a path on this machine.

| Class | What it is |
|---|---|
| `plaintext` | An unsealed key file. |
| `hosted-copy` | A copy of a cluster-hosted key outside the live store. A hosted key has no threshold at rest, so one copy is the whole key. |
| `tombstone` | A deleted hosted key's tombstone, live or copied. It keeps the key until its purge time. |
| `legacy-master-dek` | With `--legacy-master-env`: this node's current DEK, or a previous DEK it still holds, is the legacy master's derivation. |
| `non-current-dek` | A key file sealed under a DEK other than the node's current one. |
| `older-epoch` | A FROST share of an older epoch than the live file. |
| `not-live-key` | A key file for a key id this node does not hold. |
| `staged-orphan` | `keys/.staged/<id>.<ceremony>.json` of a ceremony this node does not have in progress (for example an aborted ceremony's quarantine). |
| `ceremony-material` | Split-ceremony files under `data_dir/ceremony/` (pending recipient secrets). |
| `other-dir` | A directory the cosigner does not use (`backup-*`, `retired-*`, anything unknown). Its contents are classified too. |
| `temp-file` | A temporary file left by a write (`*.tmp`, `.create-*.tmp`). |
| `lost-found` | A non-empty `lost+found`. |

Other lines:

- `[unclassified] <path>: <reason>`: something the scan could not place, for example a key file of
  another node, a symbolic link (never followed), a file that is not a key file in the key store, a
  `lost+found` it may not read, a ceremony record that does not parse, a v1 file the current DEK
  opens that holds no known record, or a copy of a newer epoch than the live file. It counts like a
  finding.
- `[error] <path>: <reason>`: a path that could not be read, for example an unreadable or truncated
  tar. The scan is incomplete.
- `[changed] <path>: vanished during the scan` or `appeared during the scan (not read)`.

Not reported: the live files of the live store under the current DEK, sign journals, ceremony vote
records, cleared-intent and epoch-proven markers (`keys/.cleared/`, `keys/.proven/`), and a backup copy that matches the live file (the same epoch and
the current DEK). Every copy of a hosted key or tombstone outside the live store is reported, because
one copy is the whole key.

## The legacy master

`--legacy-master-env VAR` names an env var holding the legacy shared master
(`share_seal.secret_env`). The scan derives this node's DEK from it, compares it with every DEK the
node holds in constant time, then drops the master. Neither value is printed or written to the JSON.

An unset, empty or short value is refused (exit 2), so a typo never becomes "no finding". When the
config names `share_seal.secret_env` and the flag is not given, NOT CHECKED says the legacy-master
check was not done.

## NOT CHECKED

Printed with every report, whatever was found:

- freed blocks on the volume: a deleted or replaced file's bytes stay on disk until overwritten;
- volume and storage snapshots;
- the history of the seal Secrets in the cluster's store (old revisions until compaction);
- the legacy master secret and its escrow copies;
- copies off this volume: backup destinations, operator machines, ceremony media, scratch volumes and
  `/tmp` (only the paths given with `--backup` were read);
- core dumps and swap.

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | Nothing found on the paths given. |
| 1 | Findings or unclassified entries. |
| 2 | A path could not be read (the scan is incomplete), `data_dir` or a `--backup` does not exist, the config or the seal keys do not load, or `--legacy-master-env` was refused. |

A read error wins over findings: a scan that could not read everything exits 2.

## Limits

The scan reads only files whose name ends in `.json`, `.tmp` or `.recipient` (plus `*.tar` inside a
backup directory). Each read is capped at 4 MiB. A tar is read in place, header by header; only
those entries are read, and each is classified before the next is read, so one entry at a time is in
memory. The scan stops with a read error after 200,000 entries in one tar, or after
1,000,000 directory entries in one scan. Directories deeper than 32 levels are reported, not walked.

## JSON (`--json`)

Schema `rutli-residue-scan/1`. The output carries paths, key ids, epochs, record classes and DEK ids
(a public, truncated hash) only, never key material. A test checks the exact set of fields.

```json
{
  "schema": "rutli-residue-scan/1",
  "node": 1,
  "data_dir": "/data",
  "backups": ["/backup/node-1-20261120T0300.tar"],
  "findings": [
    {
      "class": "older-epoch",
      "path": "/backup/node-1-20261120T0300.tar!./frost-participant1-namespace.json",
      "key_id": "frost-participant1-namespace",
      "epoch": 4,
      "dek": "1a2b3c4d",
      "note": null
    }
  ],
  "unclassified": [{ "path": "/data/keys/stray", "reason": "unknown file in the key store" }],
  "errors": [{ "path": "/backup/broken.tar", "error": "not a readable tar at offset 0: header checksum mismatch" }],
  "changed": [{ "path": "/data/keys/.staged/frost-a.c1.json", "change": "vanished" }],
  "live": { "frost": 2, "hosted": 1, "tombstones": 0 },
  "not_checked": ["freed blocks on the volume: ...", "..."],
  "exit": 2
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `rutli-residue-scan/1`. |
| `node` | integer | The config's `identifier`. |
| `data_dir` | string | The scanned `data_dir`. |
| `backups` | string[] | The `--backup` paths, in order. |
| `findings[]` | object[] | Most severe first. |
| `findings[].class` | string | One of the classes above. |
| `findings[].path` | string | File or directory; `<tar>!<entry>` inside a tar; `share_seal: …` for `legacy-master-dek`. |
| `findings[].key_id` | string or null | From the v2 header, else from the file name. |
| `findings[].epoch` | integer or null | From the v2 header or the v1/plaintext record. |
| `findings[].dek` | string or null | The DEK id (8 hex chars). |
| `findings[].note` | string or null | Set on `hosted-copy`, `tombstone` and `legacy-master-dek`. |
| `unclassified[]` | `{path, reason}` | |
| `errors[]` | `{path, error}` | |
| `changed[]` | `{path, change}` | `change` is `vanished` or `appeared`. |
| `live` | `{frost, hosted, tombstones}` | Counts of the live store's files. |
| `not_checked` | string[] | The fixed list, plus the legacy-master or no-`share_seal` line when it applies. |
| `exit` | integer | The process's exit code. |

New fields may be added within schema version 1. A removed or renamed field changes the version.

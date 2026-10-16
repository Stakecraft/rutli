# Audit cross-check: the driver's audit log against the cosigners' sign journals

The driver's hash-chained audit log (`audit-log-path`) shows edits and reordering, but it cannot show
that entries are missing from its end. A shorter log still has a valid chain. A signature made with a
stolen driver certificate, outside the driver, never reaches that log at all.

Since 0.4.0-rc.2 each cosigner keeps its own record of every signature it takes part in: the **sign
journal** (`data_dir/journal/<key_id>/*.jsonl`). It is append-only and hash-chained, and each entry is
fsynced before the signature share leaves the node. A journal entry carries the request id of the
driver's signing intent and the message signed. The driver writes the same id into the sign's audit
entry as `intent=<hex>`, and the SHA-256 of the exact bytes it signed as `msg=<hex>`:

```
sign keyId=frost-ns algo=Ed25519 inBytes=34 msg=<64 hex> intent=<32 hex> sigBytes=64 outcome=ok
```

`rutli-cosigner audit-cross-check` compares the two sides. A journaled message matches a driver line
when the SHA-256 of the journal's `digest` bytes equals the line's `msg=`.

| Finding | What it means |
|---|---|
| A request in a cosigner journal but not in the driver audit | Entries were cut from the end of the driver audit, or someone signed with the driver's certificate without going through the driver. Investigate either way. |
| A message journaled under an audited request id that no `msg=` of that request id names (`… was signed OUT OF BAND — the driver audit log signed only msg=<sha256> (seq N) …`) | The driver draws a fresh request id for every sign and binds one message to it, so this message was signed with the driver's certificate outside the driver, re-using an audited request id. The line names both the message the driver signed and the one signed out of band (its journaled digest and `msg=` hash), and which journals hold it. Journal entries are compared per authorized operation (key, request id, message), as the cosigners charge them, not per bare request id. |
| For audit lines without `msg=` (a driver from 0.4.0-rc.2 or earlier): one request id journaled over more messages than the driver audit has signs for it | The same out-of-band signing, but such a line does not say which message the driver signed, so the check can only count. |
| An `outcome=ok` sign in the driver audit that fewer than `--min-journals` journals hold (with `msg=`: that exact message) | A journal was lost or rolled back (for example, a node restored from an old volume), or not every journal was supplied. |
| Journal entries with `purpose: "no-intent"` | Signatures nobody can attribute: an older driver or leader, accepted while `signing_policy.require_intent` was off. Pass `--allow-no-intent` for the rollout window. After that, treat them as unexplained signatures. |
| A broken hash chain on either side (exit 2) | The file was edited. Keep the evidence. |

What is not compared:

- Entries older than the other side's first record: journal retention (`journal_retention_days`,
  `journal_max_mib_per_key`), or a driver audit log that started later. The report gives a count of these.
- `sign-test` entries. These come from the split ceremony's `verify-key --sign-test` over a fixed digest,
  not from driver signatures.
- Driver signs without an intent (`intent=none`). They happen without TLS, or while no cosigner reported
  a cluster id.
- Nothing is lost for old logs: a sign line without `msg=` is matched on its request id alone, and the
  report gives a count of these (`driver sign(s) without msg= (an older driver)`). One log can mix both
  kinds across a driver upgrade.
- A key that no supplied journal holds at all. Make sure every node's journal is copied in full.

## Running it

The check is offline and read-only, and it needs no cosigner config. Copy the journals **first** and
the driver audit log **second**. That way every journaled signature that completed has already been
audited. A sign still in flight while you copy can still show up once as a discrepancy. If it does, run
the check again.

```bash
# 1. Each cosigner's journal (the image ships tar, so kubectl cp works):
for i in 1 2 3; do
  kubectl -n rutli cp "rutli-node-$i-0:/data/journal" "./journals/cosigner$i"
done
# 2. Then the driver's audit log, from the participant's state volume:
kubectl -n <participant-ns> cp "<participant-pod>:/rutli-state/audit.jsonl" ./audit.jsonl

# 3. Compare. --min-journals 2 = the threshold, since every node's journal is supplied.
rutli-cosigner audit-cross-check \
  --driver-audit ./audit.jsonl \
  --journal ./journals/cosigner1 --journal ./journals/cosigner2 --journal ./journals/cosigner3 \
  --min-journals 2
```

Exit status: `0` means consistent, `1` means discrepancies (each listed on a `DISCREPANCY:` line), and `2`
means a file is unreadable or a hash chain is broken.

Run it on a schedule, for example weekly alongside the soak check, and after any incident involving the
participant host or the driver certificate. The journals answer a question the driver can no longer
answer once it has been compromised: which signatures the cluster actually produced.

## Journal format

One JSON object per line, in segments of up to 4 MiB named by their first sequence number:

```json
{"seq":12,"ts_ms":1792159730123,"node":2,"key_id":"frost-participant1-namespace","purpose":"sign",
 "request_id":"<32 hex>","intent_sha256":"<64 hex>","digest":"<68 hex: the 34-byte Canton digest>",
 "session_id":"sign-…","signer_cn":"driver","approvers":["alice","carol"],"prev":"<64 hex>","hash":"<64 hex>"}
```

`hash = SHA-256("rutli-journal-v1\n" ‖ the entry's JSON without "hash")`, and `prev` is the previous
entry's hash. A key's first entry has `prev` = 64 zeros. When retention has deleted older segments, the
first remaining entry's `prev` is taken as given.

A torn final line is truncated on the next start, with a warning. That is a crash mid-append, which was
never fsynced, so no share was released for it. Any other damage makes the node refuse to sign with that
key until an operator has looked. The other nodes keep the cluster signing.

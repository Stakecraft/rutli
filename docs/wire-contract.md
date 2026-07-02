# Wire contract — what Canton actually sends the driver

Captured from a live devnet run (Canton v3.5.6, participant auto-init, Ed25519 pinned) with
`audit-logging = true`. This is the contract every backend (HSM, FROST, DKLS) must satisfy.
Raw capture: `AUDIT` lines in the Canton log.

## Call sequence at node bootstrap

For each key the participant needs, Canton calls, in order:

```
generateSigningKeyPair(spec, name)   -> keyId          (driver chooses the id, ≤300 chars)
keyExistsAndIsActive(keyId)          -> ok
getPublicKey(keyId)                  -> SPKI DER bytes + spec
...later...
sign(data, keyId, algo)              -> signature bytes
```

Keys created on auto-init (names are Canton-chosen):

| Key name | Spec requested | Purpose |
|---|---|---|
| `participant1-namespace` | `EcCurve25519` (as configured) | namespace / identity root — signs topology txs |
| `participant1-sequencer-auth` | `EcCurve25519` | sequencer authentication |
| `participant1-signing` | `EcCurve25519` | protocol signing |
| `participant1-encryption` | `Rsa2048` (driver-advertised) | asymmetric decryption |

## The `sign` call — the FROST-relevant facts

```
sign keyId=sig-participant1-namespace-… algo=Ed25519 inBytes=34 sigBytes=64
```

- **Input is 34 bytes, always** — Canton pre-hashes. The payload is a multihash-prefixed SHA-256
  digest: `0x12 0x20 ‖ sha256(message)` (0x12 = sha2-256, 0x20 = 32-byte length; the same `1220`
  prefix visible in Canton key fingerprints). The driver never sees the topology transaction
  itself, only the 34-byte digest.
- **Output must be exactly 64 bytes** for Ed25519 — raw `R‖S` (`concat` format), no DER, no
  envelope. Canton verified these signatures during init (node reached `initialized`), confirming
  format acceptance end-to-end.
- ECDSA (`EcDsaSha256`/`EcDsaSha384`) output is DER (`SEQUENCE` of r,s) — verified separately in
  the unit suite against stock JDK verifiers.
- Signing is **low-frequency**: a handful of calls at bootstrap, then only on topology changes.
  Latency budget for an MPC round-trip is generous (seconds are fine).

Implications for the Phase 2 FROST backend:
- The message handed to the FROST rounds is the 34-byte digest — small, fixed-size, no streaming.
- Note Ed25519(RFC 8032) internally hashes the message again; Canton's pre-hash is the *message*
  from FROST's perspective. No Ed25519ph — plain Ed25519 over the 34 bytes.

## `getPublicKey` — export format

- Ed25519: **44-byte** DER X.509 SubjectPublicKeyInfo (12-byte algo header + 32-byte raw key).
- RSA-2048: **294-byte** SPKI.
- EC (P-256/P-384): SPKI with **uncompressed** point, per the SPI contract.

## Other observed constraints

- Data size bounds (from the SPI docs, respected by Canton): `sign` data ≤ 4kb (real: 34 bytes),
  symmetric encrypt plaintext ≤ 4kb, asymmetric/symmetric ciphertext ≤ 6144 bytes.
- `keyName` is Canton-generated, human-meaningful (`participant1-namespace`) — safe to embed in the
  driver's `keyId` for operator-legible audit logs (we do).
- The namespace key signs **multiple times** during a single bootstrap (one per identity topology
  transaction) — backends must handle repeated signing sessions for the same key.

## Reproduce

```sh
sbt driver/assembly
CANTON_HOME=/path/to/canton-3.5.6 deploy/devnet/up.sh
grep AUDIT log/canton.log
```

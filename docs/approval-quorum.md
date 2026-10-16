# M-of-N signing approval

Hold high-value signing operations until a quorum of humans cryptographically approves them. This is
the institutional separation-of-duties control: even with the node, the driver, and the FROST
cluster all healthy, a gated key does not sign until `M` of `N` named approvers each authorize the
specific request.

## What it can and cannot do

The Rütli driver only ever receives an **opaque pre-hashed payload** from Canton (the 34-byte
digest — see `docs/wire-contract.md`). So approval is expressed over the **KMS key**, not
transaction semantics: an approver authorizes "a signature by key *X* over digest *D*", not "add
party Y". Richer, content-aware approval would require context Canton does not pass at the KMS-driver
layer. Be honest about this with auditors.

### Where approvals are enforced — today, only in the driver

> ⚠️ **Approvals do not yet bind at the cosigners.** The quorum is checked inside the Rütli driver,
> in the Canton participant's process, before it calls the cluster. The cosigners themselves never
> see an approval and sign any well-formed request from an allowed caller. So, until cosigner-side
> intent enforcement lands (a driver-signed intent carrying the approval proof, verified by every
> participating cosigner before it releases a signature share — planned in the audit remediation),
> the gate can be bypassed by:
>
> - **anyone holding the driver's client certificate and key** (CN on `signer_allowlist`): they can
>   call `Signer.Sign` on any cosigner directly, without the driver, its approval gate or its
>   signing journal;
> - **a compromised cosigner**: its mesh certificate can drive the raw signing rounds on its peers
>   (`peer_allowlist` admits it by design), so it can obtain the other shares it needs for a
>   threshold signature over a digest of its choosing.
>
> What the gate does give today: the participant itself — Canton, the driver, anyone who can only
> make the *node* request a signature — cannot sign with a gated key without the quorum, and every
> decision is in the hash-chained audit log. Treat it as a control on the participant, not on the
> cluster. Protect the driver key accordingly (it is, for now, a signing credential for every
> non-gated *and* gated key), and do not describe approvals to auditors as cluster-enforced until the
> intent enforcement ships.

## Model

- Each approver holds an **Ed25519 keypair**; only the public keys go in the policy.
- A gated `sign` writes a pending request with a **random per-request nonce**, so its request id is
  unique and an approval can never be replayed onto another request.
- The request id is `hex(SHA-256(keyId ‖ digest ‖ nonce))`. `ApproveCli` **recomputes it from the
  keyId, digest and nonce it displays** and refuses to sign (exit 1) if it does not match, so a
  tampered pending file cannot make an approver sign an id bound to a different digest than the one
  shown.
- An approval is an **Ed25519 signature over the request id** by an approver key. The driver verifies
  every signature against the configured keys and counts **each approver at most once** — separation
  of duties is cryptographic, not advisory.
- The `sign` call blocks (up to `timeout`) until the threshold is met, then proceeds to the backend
  (for the namespace key: quorum approval happens *before* the FROST threshold signature, in the
  driver — the cosigners do not check it yet; see above). No quorum
  in time → the operation fails non-retryably, and the outcome is written to the audit log.

Default is **no gating** — nodes bootstrap and low-value keys sign without interaction. Operators opt
specific keys into `quorum` by key-id prefix (the namespace key id is `frost-…name…`).

> ⚠️ Bootstrap: a node's identity keys are signed automatically at first startup. If you gate the
> namespace key from the very first boot, an approver must be present to approve those bootstrap
> signatures. The common pattern is to bring the node up with the key auto-approved, then tighten the
> policy to `quorum` for ongoing topology operations. Choose per your threat model.

## Configure

In the Canton node's `crypto.kms.config`:

```hocon
approval {
  inbox-dir = "/var/rutli/approvals"   # shared dir approvers can write to
  timeout   = 30m
  rules = [
    # Matches the full key id: with `frost.key-prefix = "soak1-"` this must be "soak1-frost-".
    { key-id-prefix = "frost-", mode = "quorum", threshold = 2 }
  ]
  approvers = [
    { id = "alice", public-key-base64 = "MCowBQYDK2VwAyEA..." },
    { id = "bob",   public-key-base64 = "MCowBQYDK2VwAyEA..." },
    { id = "carol", public-key-base64 = "MCowBQYDK2VwAyEA..." }
  ]
}
```

## Approver workflow

```sh
# one-time: each approver mints a key; give the printed line to whoever maintains the policy
java -cp rutli-driver.jar com.stakecraft.rutli.policy.ApproveCli keygen alice
#   -> writes alice.key (keep secret) and prints { id = "alice", public-key-base64 = "..." }

# when a signature is pending, approve it (poll the inbox, or wire to your alerting):
java -cp rutli-driver.jar com.stakecraft.rutli.policy.ApproveCli approve \
  --inbox /var/rutli/approvals --id alice --key alice.key --all
```

The inbox is a plain directory (`pending/`, `approvals/`) — mount it as shared storage, or sync via
your secret manager / ticketing integration. Approvers never see or hold key material; they only
attest to request ids.

## Audit

With `audit-log-path` set, every gated `sign` records its outcome (approved / denied+timeout) in the
tamper-evident hash-chained log, so the approval history is itself verifiable offline.

# M-of-N signing approval

Hold high-value signing operations until a quorum of humans has cryptographically approved them. This
is the institutional separation-of-duties control. Even with the node, the driver and the FROST cluster
all healthy, a gated key does not sign until `M` of `N` named approvers have each authorized that
specific request. Once `signing_policy.require_intent` is on, **every cosigner checks the approvals
itself**, not only the driver.

## What it can and cannot do

The Rütli driver only ever receives an **opaque pre-hashed payload** from Canton (the 34-byte digest,
see `docs/wire-contract.md`). So approval is expressed over the **KMS key**, not over transaction
semantics. An approver authorizes "a signature by key *X* over digest *D*", not "add party Y".
Content-aware approval would need context that Canton does not pass at the KMS-driver layer. Be
honest about this with auditors.

### Where approvals are enforced: in the driver and at every cosigner

Every FROST sign carries a **signing intent** (audit C2). The driver signs it with its own mTLS key.
It names the cluster, the key, the exact digest, a random request id and a validity of a few minutes,
and it carries the approvals the driver's gate collected: the request nonce and each approver's
Ed25519 signature. Every cosigner that takes part in the signature verifies the intent **itself**. It
checks the certificate chain to the cluster CA, that the signer CN is on its `signer_allowlist`, the
signer's key pin if one is configured, the signature, the cluster, key, digest and expiry, the signer's
key ACL, and the approvals against **its own** `signing_policy.rules` and `approvers`. It does this
before it commits to a nonce (round 1), and again before it releases its signature share (round 2).
Each node also journals every share it releases, durably, before the share leaves
(`docs/audit-cross-check.md`).

With `require_intent` on, on every node:

| Who | Without approvals for a gated key | Non-gated key |
|---|---|---|
| Canton / the participant | Held by the driver gate, then refused by the cosigners | Signs |
| **Holder of the driver certificate and key**, bypassing the driver | **Refused by every cosigner** (it needs `M` approver keys) | Signs, but only keys in its `signer_acl` prefixes, within the per-node rate limits, journaled on every participating node, never `Refresh` (once `signer_may_refresh` is off) |
| **A compromised cosigner** (its share, its mesh certificate) | Refused | **Refused**: an honest peer releases a share only for a digest that a valid driver intent names. It can re-use an intent it has seen for another signature over the *same* digest, at most `max_shares_per_request` times |
| A compromised leader | Refused | Cannot change the digest between rounds or mint an intent |

What this still does not do: a driver-key thief can sign **non-gated** keys. Nothing inside the
cluster can tell the driver from its key. The point is to bound that (ACLs, rate limits), to record
it (journals, `audit-cross-check`), and to require humans for the keys that matter (gated keys).
Revoke a stolen driver key with a pin (`signer_pins`, below). No CA is needed.

> ⚠️ **Until `require_intent` is on, on every node, approvals are driver-side only.** In the default
> verify-if-present mode an intent that is present is verified in full, gated keys included, but a
> request **without** an intent is accepted and counted (`rutli_sign_intent_absent_total`). Anyone
> who can call the cluster without the driver (the driver key's holder, or a compromised cosigner
> driving a peer) can still omit the intent. One lenient node is enough: in a 2-of-3 cluster a
> compromised node needs only one honest peer that does not require intents. Do not describe
> approvals as cluster-enforced until the switch below is complete.

## Model

- Each approver holds an **Ed25519 keypair**; only the public keys go in the policy.
- A gated `sign` writes a pending request with a **random per-request nonce**, so its request id is
  unique and an approval can never be replayed onto another request.
- The request id is `hex(SHA-256(keyId ‖ SHA-256(digest) ‖ nonce))` (`FileApprovalGate.requestIdFor`;
  the cosigners compute it the same way, pinned by a shared test vector). `ApproveCli` **recomputes it from the
  keyId, digest and nonce it displays** and refuses to sign (exit 1) if it does not match, so a
  tampered pending file cannot make an approver sign an id bound to a different digest than the one
  shown.
- An approval is an **Ed25519 signature over the request id** by an approver key. The driver verifies
  every signature against the configured keys and counts **each approver at most once** — separation
  of duties is cryptographic, not advisory.
- The `sign` call blocks (up to `timeout`) until the threshold is met, then proceeds to the backend.
  The FROST backend puts the nonce and the approvals into the signing intent, and every cosigner
  recomputes the request id from the key, the digest it is asked to sign and that nonce, and counts
  valid signatures by **its own** configured approvers. If quorum is not reached in time, the
  operation fails non-retryably and the outcome is written to the audit log. If a cosigner's rules
  demand more than the driver collected, it refuses with PERMISSION_DENIED ("approval required"),
  which is non-retryable and visible.

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

On **every cosigner**, the same rules and approver keys go in `signing_policy` (Helm:
`signingPolicy`). The values are the same: the approver's `public-key-base64` becomes
`public_key_spki_b64`. The cosigners are authoritative. If their policy and the driver's drift apart,
the stricter one decides, and a refusal is loud.

```jsonc
"signing_policy": {
  "rules":     [ { "key_id_prefix": "frost-", "mode": "quorum", "threshold": 2 } ],
  "approvers": [ { "id": "alice", "public_key_spki_b64": "MCowBQYDK2VwAyEA..." },
                 { "id": "bob",   "public_key_spki_b64": "MCowBQYDK2VwAyEA..." },
                 { "id": "carol", "public_key_spki_b64": "MCowBQYDK2VwAyEA..." } ]
}
```

### The rest of the cosigner signing policy

All per node, in `signing_policy`. The defaults are in brackets.

| Setting | Meaning |
|---|---|
| `require_intent` [false] | A round without a valid intent is refused. Off: verified if present, accepted and counted if absent |
| `signer_acl` [none] | Client CN → key-id prefixes it may use (`""` = every key). Checked on every key-scoped Signer RPC and on the intent signer at every node. Give each tenant's driver its own CN and prefix |
| `signer_acl_required` [false] | A signer CN without an ACL entry is refused |
| `signer_pins` [none] | Client CN → SHA-256 of the SubjectPublicKeyInfo of each key allowed under that CN: `openssl x509 -in driver.crt -noout -pubkey \| openssl pkey -pubin -outform DER \| sha256sum`. A CA-valid certificate with an unpinned key is refused on the Signer API and as an intent signer. This is **revocation without the CA**: issue a new driver certificate and replace the pin |
| `signer_may_refresh` [true] | The driver role keeps `Refresh`. Turn it off once the refresh job uses a `refresh_allowlist` certificate (top-level `refresh_allowlist`, Refresh + KeyStatus only; it may be the operator's CN) |
| `sign_rate_limit_per_min` / `_per_day` [300 / 20 000] | Per key, per node. Charged once per intent request id: retries, t-subsets and leader failovers of one driver call share a single charge. Rebuilt from the journal after a restart. `rate_limits: [{key_id_prefix, per_min, per_day}]` overrides by prefix. Put a tight rule on namespace keys, e.g. 10/min and 200/day |
| `max_shares_per_request` [8] | The most shares one request id gets from this node |
| `intent_max_lifetime_secs` / `clock_skew_secs` [300 / 120] | The driver's intents live 180 s. A node whose clock is off by more than the skew refuses every intent: fail closed, so watch NTP |
| `journal_retention_days` / `journal_max_mib_per_key` [90 / 64] | Sign journal retention (`data_dir/journal`), bounded for 1 Gi volumes |

New metrics: `rutli_sign_intent_absent_total`, `rutli_sign_policy_refusals_total{reason}`,
`rutli_sign_rate_limited_total`, `rutli_signer_acl_absent_total`, `rutli_sign_journal_entries_total`,
`rutli_sign_journal_errors_total` (`docs/observability.md`), with alerts in
`deploy/monitoring/prometheus-rules.yml` (`RutliSignJournalErrors`, `RutliSignPolicyRefusals`,
`RutliSignIntentAbsent`, `RutliSignRateLimited`, `RutliSignerAclAbsent`).

## Switching enforcement on

The defaults keep a rolling upgrade, and a driver older than intents, working. Switch on in this
order:

1. **Every cosigner on this release** (0.4.0-rc.2 or later), defaults unchanged. Signing keeps
   working in both directions. Each node verifies intents when they are present and journals every
   share. `rutli_sign_intent_absent_total` counts the older driver's signs.
2. **The driver release** (participant restart). It signs an intent for every FROST sign and carries
   the approvals. It learns the cluster id from the cosigners (`Capabilities`: the value a majority
   of the endpoints report; learned again if a cosigner refuses an intent for its cluster), or you
   set `frost.cluster-id` (recommended: then no cosigner's answer decides it). `frost.sign-intents =
   off` stops attaching intents — an emergency switch that works only while `require_intent` is off.
   Check that `rutli_sign_intent_absent_total` stops growing on every node, and
   that the journals show `"purpose":"sign"` entries with request ids
   (`rutli-cosigner audit-cross-check`).
3. **Policy on every node, identical everywhere:** approval `rules`/`approvers` matching the
   driver's; `signer_acl` for each signer CN; `signer_pins` for the driver key (strongly recommended
   where the CA key is lost, as on the DevNet soak); rate-limit rules for namespace keys. Move the
   refresh CronJob to the refresher certificate (`refresh_allowlist`, `deploy/k8s/cronjob-refresh.yaml`;
   until a `refresher` certificate exists, the operator certificate with `refresh_allowlist:
   [operator]`).
4. **Flip on every node**, as a rolling restart: `require_intent: true`, `signer_acl_required: true`,
   `signer_may_refresh: false` (and `require_epoch_match: true` from batch C phase 2). From the moment
   the **last** node enforces, a compromised cosigner or a driver-key thief without approvals can no
   longer sign a gated key, and nothing signs without a journaled intent.
   **Ceremony intents** (0.4.0-rc.4): `require_ceremony_intent: true`, once the driver release that
   signs DKG intents runs and the refresh CronJob's image is this release (its
   `rutli-cosigner refresh` signs refresh intents). First check that
   `rutli_ceremony_intent_absent_total` no longer grows after a DKG or refresh. Each node that
   enforces then refuses, on its own, any DKG/refresh fence or part 1 without a valid ceremony
   intent naming exactly that ceremony. So a compromised cosigner can no longer start ceremonies on
   it (`docs/ceremonies.md`, "Ceremony intents"). The flag works per node: an older leader drops
   the intent and is refused by an enforcing node, so enforce only after the whole cluster runs this
   release. Where only the driver certificate can refresh (no refresher certificate yet, as on the
   DevNet soak, whose CA key is lost), a refresh needs `signer_may_refresh: true` and the CLI pointed
   at the driver certificate; that is today's constraint, unchanged by intents.
5. Schedule `rutli-cosigner audit-cross-check` (weekly, and after any incident). From now on, do not
   pass `--allow-no-intent`: an intent-less journal entry is an unexplained signature.

Rollback: turning a flag off is immediate (restart). A driver downgrade needs `require_intent` (and
`require_ceremony_intent`) off first, or every sign (and DKG) is refused. Same for a refresh CronJob
image older than this release.

## Approving hosted-key deletes

Hosted-key deletes (audit M2) use the same approvers, enforced at every cosigner and nowhere else:
`hosted_keys.delete_approval_threshold` on every node (0 = none; at least 1 is recommended in
production, decision P8) names how many distinct `signing_policy.approvers` must approve. The delete
role itself is `hosted_keys.delete_allowlist` (`docs/hosted-keys.md`, Delete).

A delete approval is **domain-separated** from a signing approval (audit F6): its request id is
computed over the key field `delete:<key id>` instead of the bare key id —
`hex(SHA-256("delete:" ‖ key id ‖ SHA-256(delete digest) ‖ nonce))`, with the delete digest
SHA-256(`"rutli-delete-key-v1\n"` ‖ key id). Key ids never contain `:`, so no signing request id is
ever a delete's, and an approver shown a "sign" request can never be approving a delete (or vice
versa). `ApproveCli approve` reads the operation from that authenticated keyId — it prints
`operation = DELETE hosted key <id>` or `operation = SIGN with key <id>` — checks a delete's digest is
the delete digest of that key, and refuses a request whose `operation` field contradicts its id. The
signing request id is unchanged (the driver's format; golden vectors on both sides). Delete approvals
collected by an older `rutli-cosigner` (bare key id) are refused by upgraded nodes: re-issue the
delete.

```sh
# the delete-role operator (its certificate in the client config):
rutli-cosigner --config client-operator.json delete-hosted-key --key-id <id> \
  --approvals-inbox /var/rutli/approvals --approvals 2
# each approver, from the same inbox (it shows the operation — DELETE hosted key <id> — keyId and
# the digest it recomputes the id from):
java -cp rutli-driver.jar com.stakecraft.rutli.policy.ApproveCli approve \
  --inbox /var/rutli/approvals --id alice --key alice.key --request <requestId>
```

The driver signs delete intents for Canton's `deleteKey` without approvals; with a threshold set,
those deletes are refused (`rutli_delete_intent_refusals_total{reason="approval"}`) and go through
the operator command instead.

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
tamper-evident hash-chained log, so the approval history is itself verifiable offline. Each sign's
entry carries its intent request id (`intent=<hex>`). Each cosigner's sign journal holds the same id
together with the approvers whose signatures counted, so `rutli-cosigner audit-cross-check` can show
that the two records agree (`docs/audit-cross-check.md`).

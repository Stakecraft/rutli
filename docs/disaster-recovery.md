# Disaster recovery runbook

The Canton **namespace / identity key is non-rotatable** and its loss is total — losing control of it
means losing every party and Canton Coin balance hosted under that node's namespace, permanently.
There is no "generate a new one". So for a FROST-backed node, DR is existential and must be planned
before go-live, not after an incident.

Rütli holds that key as a `t`-of-`n` FROST sharing: no machine ever holds the whole key, and the key
survives the loss of up to `n − t` cosigners with no action at all. This runbook covers the cases
beyond that.

## Threat/loss matrix

| Event | Recoverable? | Procedure |
|---|---|---|
| Up to `n − t` cosigners down | Yes, automatically | Signing continues; the driver fails over to live cosigners. Rebuild the lost nodes at leisure (below). |
| A cosigner's disk lost, share backup exists | Yes | **Restore from backup** (§1). |
| A cosigner's disk lost, no backup | Yes, if ≥ `t` others survive | **Repair the share** from survivors (§2). |
| More than `n − t` cosigners lost simultaneously | Only from backups | **Restore ≥ `t` shares** from cold backups (§3). Without backups this is unrecoverable — which is why §4 is mandatory. |
| Suspected key compromise (≥ `t` shares may be exposed) | Mitigate, not undo | The key cannot be rotated. **Proactively refresh** (invalidates pre-refresh shares) and escalate to a governance decision on the node's future. See `docs/phase-2-frost.md`. |

## §1 Restore a single cosigner from backup

Shares are encrypted at rest (see share sealing), so backups carry no plaintext key material.

```sh
# routine, per cosigner, on a schedule — with the node stopped or the share dir quiesced:
rutli-cosigner backup  --config /etc/rutli/cosigner-2.json --out /secure/backups/cosigner-2/$(date +%F)

# recover a wiped node:
rutli-cosigner restore --config /etc/rutli/cosigner-2.json --from /secure/backups/cosigner-2/2026-07-01 --force
# then start the daemon; it rejoins with its old share (same group key).
```

Store backups **off the node's host** and, ideally, geographically separated. Because the shares are
sealed, the backup is only usable together with the node's seal secret (which lives in your secret
manager, not on disk) — keep the two recovery inputs in separate trust domains.

## §2 Repair a lost share from survivors (no backup)

If a cosigner is destroyed and its share was never backed up, `t` surviving cosigners can rebuild
exactly its old share via the Repairable Threshold Scheme — without any of them, or the recovered
node, ever learning the group secret. The group key is unchanged. The cryptographic primitive is
implemented and tested (`rutli-frost-core::repair`); the networked cosigner-mesh ceremony that drives
it over gRPC is the current build's follow-up. Until it ships, prefer §1 (keep backups) as the
first-line recovery.

## §3 Catastrophic restore (below threshold lost at once)

If more than `n − t` cosigners are lost at the same time, live signing stops (you're below
threshold) but the key is **not** lost as long as you hold **≥ `t` share backups**:

1. Provision fresh cosigner hosts.
2. `rutli-cosigner restore` at least `t` shares from cold backups onto them (with their seal
   secrets).
3. Start the daemons; the cluster reaches threshold and signs again (verified group key unchanged).
4. Rebuild the remaining cosigners (§1 restore, or re-add and repair once §2 ships) to return to full
   `n`, then **proactively refresh** so the temporarily-assembled quorum's shares are rotated.

## §3b Lost delegate encryption key (software backend without persistence)

**Symptom:** after a participant restart, fatal crash on catch-up:
`KmsDecryptError: key not found: enc-encryption-…` → `SYNC_SERVICE_SYNCHRONIZER_DISCONNECTED` →
`FATAL UnrecoverableError`. FROST signing keys are fine (they live in the cluster); the RSA/ECIES
encryption key served by a heap-only software delegate died with the old JVM.

**Why this is unrecoverable in place:** Canton publishes the encryption *public* key in topology;
peers encrypt views to it, and the catch-up stream already contains ciphertext under it. A freshly
generated key cannot decrypt that history, and rotation only changes *future* traffic. The private
key was never persisted — no backup contains it.

**Recovery (accept a bounded data gap):**
1. Do not reconnect yet. Enable repair commands on the participant and use
   `participant.repair.ignore_events` over the poison sequencer range (the `first/last sequencing
   timestamp` values in the fatal log). Those events' effects are lost for this participant.
2. Reconnect. If the node hits further decrypt misses for the same key id, repeat step 1 for the
   new range — iterate until clean. (Traffic addressed to the dead key keeps arriving until
   rotation propagates.)
3. Rotate the encryption key via Canton topology (console: generate a new encryption key and
   register it; the transaction is signed by the namespace key, which the FROST cluster still
   holds — node identity is untouched). New traffic becomes decryptable.
4. **Before the next restart**, make the replacement key durable — see prevention below.

**Prevention:** never run a real node with a heap-only software delegate. Either configure sealed
disk persistence for the software backend:

```hocon
config {
  backend = "frost"
  software = {
    dir             = "/rutli-state/softkeys"   # durable volume (PVC on k8s)
    seal-secret-env = "RUTLI_SOFT_SEAL_SECRET"  # openssl rand -hex 32, from a secret manager
  }
  frost = { delegate = "software", … }
}
```

(the driver refuses `dir` without a seal secret, and fails loudly on a wrong secret rather than
starting keyless), or use an HSM delegate. Include the `softkeys/` directory and its secret in the
same backup discipline as cosigner shares.

## §4 What you MUST have in place before go-live

- **≥ `t` cosigner share backups**, encrypted (sealed) and stored in ≥ 2 separated locations. This is
  the difference between "recoverable" and "irrecoverable" for the catastrophic case.
- **Seal secrets** for those shares in a secret manager, in a different trust domain from the backups.
- A **documented, rehearsed** restore drill (test §1 and §3 on a devnet with the same tooling — the
  cluster test `a_lost_node_recovers_from_a_share_backup_and_the_cluster_signs` is the automated
  analogue).
- A **proactive-refresh schedule** so a share exposed at any point has a bounded useful lifetime.
- A **key-ceremony record**: who ran DKG, the `t`/`n` chosen, cosigner host/account/region for each
  share, and where each backup + seal secret lives. Keep it with your BCP documentation.

## Verifying a recovery

After any restore/repair, confirm the node identity did not change:

```sh
# the group verifying key (and therefore the Canton namespace) must be identical to before
rutli-cosigner refresh --config … --key-id frost-<node>-namespace   # prints the group key; compare
# and confirm the participant still reports the same PAR::…::<fingerprint> identity in the Canton console.
```

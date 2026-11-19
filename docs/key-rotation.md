# Key rotation

A Canton node holds several kinds of key. Most rotate normally; one — the namespace root — cannot,
by design. This page says which is which, how to rotate the ones you can, and what to do about the
one you can't. It applies whether Rütli's backend is `hsm` or the `frost` MPC cluster: rotation is a
Canton operation, and the driver just holds the resulting keys.

## The keys on a node

| Key | Purpose | Rotatable? |
|---|---|---|
| **Namespace (root) key** | Anchors identity — the namespace **is** the hash of this key's public part — and authorizes every topology change. | ❌ **No** |
| **Signing key(s)** | Signs protocol messages / transactions (proof-of-ownership). | ✅ Yes |
| **Encryption key** | Asymmetric decryption of confidential views. | ✅ Yes |
| **Sequencer-authentication key** | Authenticates the node to the sequencer. | ✅ Yes |

(These four are exactly the key types Canton delegates to an external KMS in "external key storage"
mode — the ones Rütli holds.)

## Rotating the rotatable keys

Canton rotates **staged: it activates the new key first, then deactivates the old one**, so there
is no signing gap. A rotation is a change to the node's `OwnerToKeyMapping`, signed by the
namespace key (on a `frost` node, a threshold signature).

### The recipe

This is the path that was rehearsed: the in-place migration rehearsal (B8, 2026-11-01, Canton
3.6.1, cosigners on 0.4.0-rc.6) rotated the encryption key onto a new hosted ECIES key and the
signing key onto a new FROST key this way. The full console blocks, with their assertions, are in
[runbook-migration-inplace.md](runbook-migration-inplace.md) 5.2.

1. **Check first.** The node is connected, and its Authorized store and the synchronizer show the
   same `OwnerToKeyMapping`. For a signing key the driver must be able to sign a ceremony intent
   (driver 0.4.0-rc.4 or later, its certificate allowed for the key prefix). For an encryption key
   the driver runs with `hosted-keys = true`.
2. **Generate the new key through the driver.** Canton asks the driver, the driver creates the key
   in the cluster and Canton registers it.

   ```scala
   // encryption: a new cluster-hosted ECIES key
   val encNew = p.keys.secret.generate_encryption_key("encryption-r1", Some(EncryptionKeySpec.EcP256))
   // signing: a new FROST key from a DKG
   val sigNew = p.keys.secret.generate_signing_key("signing-r1",
     SigningKeyUsage.ProtocolWithProofOfOwnership ++ SigningKeyUsage.SequencerAuthenticationOnly,
     Some(SigningKeySpec.EcCurve25519))
   ```
3. **Rotate the mapping.**

   ```scala
   p.topology.owner_to_key_mappings.rotate_key(p.id.member, encOld, encNew)
   // and for the signing key
   p.topology.owner_to_key_mappings.rotate_key(p.id.member, sigOld, sigNew)
   ```

   `encOld` and `sigOld` are the public keys being replaced, from `keys.secret.list`.

   Wait until the old fingerprint has left the synchronizer's mapping. After a signing-key
   rotation, disconnect and reconnect the synchronizer so that sequencer authentication uses the
   new key.
4. **Check the new key in the cluster.** Its KMS id is in `keys.secret.list`.

   ```sh
   rutli-cosigner --config client-operator.json key show \
     --key-id <kms id> --expect-fingerprint <fingerprint Canton printed>
   ```

   Every node must hold it ([admin-cli.md](admin-cli.md)). In the rehearsal the new hosted key
   was on all three nodes within a minute.
5. **Ping, then back up the cosigners.** The backup taken before the rotation does not hold the new
   keys.

**Never `keys.secret.delete` the old key.** Under KMS that deletes the key in the cluster, and it
may still be needed to decrypt views in flight. The old key stays registered and is no longer in
the mapping.

**Canton 3.7 (Splice 0.10):** `rotate_key`, `add_key(s)`, `remove_key` and the `rotate_*` commands
below take an optional `synchronizerId`. Without it Canton detects the synchronizer itself, which
only works when exactly one is registered and connected. During an LSU window the predecessor and
the successor are both registered, so pass the id, or do not rotate in the window. The recipe was
rehearsed on Canton 3.6.1, not on 3.7. PV 37 also caps an owner at 20 signing keys
(`max_signing_keys_per_entity`). Rotation removes the old key from the mapping, so the count stays
flat; an `add_key` without a matching `remove_key` makes it grow. See
[splice-0.10.md](splice-0.10.md).

### Other console commands

- `keys.secret.rotate_node_key(fingerprint, name)` and `rotate_node_keys()` do the same in one
  call: generate through the driver, then change the mapping. **Not rehearsed with Rütli.**
- `keys.secret.rotate_kms_node_key` rotates onto a key that already exists in the KMS, named by
  its KMS id. **It does not apply to keys Canton generates in Rütli:** `generate_*` creates and
  registers such a key in one step, and there is no way to create a key in the cluster ahead of
  Canton. It could only take an imported key. **Not rehearsed.**

## Why the namespace root key cannot be rotated

Because **namespace = hash(root public key)**, and the namespace is the node's permanent, on-chain
identity — every party hosted on the node, and the node's very existence in the topology, is
namespaced under that hash. Change the root key → different hash → **a different node**. It is not a
missing feature; the root key *is* the identity, the way a fingerprint is not something you rotate.

## What to do about the un-rotatable root

You don't rotate the root — you rotate *around* it. Two complementary techniques:

### 1. Namespace delegation — keep the root offline, rotate delegates

Canton lets the root key **delegate** topology-signing authority to one or more intermediate keys (a
`NamespaceDelegation`). Keep the **root key offline / air-gapped**, brought out only to (re)issue
delegations; let an online **delegated key** do day-to-day topology signing. Delegated keys **are
rotatable** — issue a new delegation, retire the old. So the identity anchor stays cold and fixed
while the operational signing key rotates like any other.

This is the recommended posture for high-value nodes, and it composes with Rütli: the offline root
can itself be a FROST-held key you only convene the cluster for on rare ceremonies, while a
delegated online key handles routine signing.

### 2. Share refresh — rotate the secret, keep the key (Rütli)

When the root key is held online in the FROST cluster, you can't change the key, but you can
re-randomize the **shares** under it — same public key, same identity, fresh secret material:

```sh
rutli-cosigner --config /etc/rutli/client-refresher.json \
  refresh --key-id frost-<participant>-namespace
```

The config is a client config with the refresher certificate, whose CN is on every cosigner's
`refresh_allowlist` (the driver certificate can refresh only while
`signing_policy.signer_may_refresh` is on). The command signs a ceremony intent with that
certificate when it can learn the cluster id (`cluster_id` in its config, or a majority of the
roster). Without an intent a TLS cosigner refuses the refresh by default
([ceremonies.md](ceremonies.md#ceremony-intents), `deploy/k8s/cronjob-refresh.yaml`). A
cosigner's own certificate is refused.

Run it on a schedule. Any share an attacker may have captured is now useless — they must re-breach
≥ `t` cosigners within a single refresh window. This is the closest thing to "rotating" the root, and
it is Rütli-specific. See [phase-2-frost.md](phase-2-frost.md).

Best practice combines both: an **offline/delegated** root **and** periodic **share refresh** on
whatever root material is online.

## If the root is actually compromised

There is no rotation. If ≥ `t` shares of the namespace key are believed exposed:

1. **Refresh immediately** — invalidates the exposed shares if the attacker has not already used
   them.
2. If the key may already have been misused, escalate to governance: **offboard the node and stand up
   a new identity** (the "SV failure" path). The old namespace is abandoned.

This asymmetry is exactly why Rütli layers the other controls around the root — M-of-N approval, the
audit log and signing journal, share sealing, and frequent refresh — since the ultimate key can
never be swapped. Full procedure: [disaster-recovery.md](disaster-recovery.md).

## Summary

- **Signing / encryption / sequencer-auth keys** — rotate any time: generate the new key through
  the driver, then `owner_to_key_mappings.rotate_key` ([the recipe](#the-recipe)). No downtime
  (staged activate-then-deactivate).
- **Namespace root key** — never rotates (it *is* the identity). Instead: keep it **offline and
  delegate**, and **refresh its shares** regularly if it's online in the cluster.
- **Compromise of the root** — refresh, then offboard/rebuild; there is no in-place replacement.

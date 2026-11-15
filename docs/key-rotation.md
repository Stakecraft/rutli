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

Canton rotates **staged — it activates the new key first, then deactivates the old one** — so there
is no signing gap. From the Canton console:

```scala
// rotate every node key at once
myNode.keys.secret.rotate_node_keys()

// or rotate a single key
myNode.keys.secret.rotate_node_key(oldKeyFingerprint, "new-key-name")
```

Under the hood each rotation is two topology transactions on the node's `OwnerToKeyMapping`,
**authorized (signed) by the namespace key**:

```scala
myNode.topology.owner_to_key_mappings.add_key(newKey.fingerprint, newKey.purpose)
myNode.topology.owner_to_key_mappings.remove_key(oldKey.fingerprint, oldKey.purpose)
```

**With Rütli there is nothing extra to do.** `rotate_node_key(s)` calls the driver's
`generateSigningKeyPair` / `generateEncryptionKeyPair` to mint the new key in the backend, then
Canton signs the topology change with the namespace key (which, for a `frost` node, is the
threshold signature). On a `frost` node a new Ed25519 signing key is a FROST DKG (the driver signs
its ceremony intent when intents are on), and a new encryption key is a cluster-hosted key (`hosted-keys = true`) or
goes to the delegate. The new key lives behind the same driver; the old one is deactivated but
stays registered. Do not `keys.secret.delete` it: under KMS that deletes the key in the backend,
and it may still be needed to decrypt views in flight. Rotate on your normal schedule, or
immediately if a non-root key is suspected exposed.

**Canton 3.7 (Splice 0.10):** these commands, and `owner_to_key_mappings.add_key(s)` / `remove_key` / `rotate_key`, take an
optional `synchronizerId`. Without it Canton auto-detects the synchronizer, which only works when exactly one is registered
and connected. During an LSU window the predecessor and the successor are both registered, so pass the id, or do not
rotate in the window. PV 37 also caps an owner at 20 signing keys (`max_signing_keys_per_entity`). Rotation removes the
old key from the `OwnerToKeyMapping`, so the count stays flat. An `add_key` without a matching `remove_key` makes it
grow. See [splice-0.10.md](splice-0.10.md).

The in-place migration rehearsal (B8, 2026-11-01) rotated the encryption key onto a new hosted
ECIES key and the signing key onto a new FROST key with `generate_encryption_key` /
`generate_signing_key` and `owner_to_key_mappings.rotate_key`, with the cosigners on
0.4.0-rc.6. `rotate_node_keys()` itself was not rehearsed. The commands are in
[runbook-migration-inplace.md](runbook-migration-inplace.md) 5.2.

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

- **Signing / encryption / sequencer-auth keys** — rotate any time with `rotate_node_key(s)`; Rütli
  mints the replacement behind the driver. No downtime (staged activate-then-deactivate).
- **Namespace root key** — never rotates (it *is* the identity). Instead: keep it **offline and
  delegate**, and **refresh its shares** regularly if it's online in the cluster.
- **Compromise of the root** — refresh, then offboard/rebuild; there is no in-place replacement.

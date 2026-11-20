# Production profile

The threat model ([security/threat-model.md](security/threat-model.md)) assumes that every
enforcement setting is on. Several of them are off by default, so that rolling upgrades and labs
keep working. The production profile is one setting that requires all of them:

```json
{ "profile": "production", ... }
```

| `profile` | At startup |
|---|---|
| `production` | The cosigner refuses to start while any **required** setting below is not at its production value. The error names each one. **Advisory** findings are logged and never refuse. |
| `lab` | The findings are logged; nothing is refused. For compose, LocalNet and lab clusters. Never for an authority key. |
| unset | As `lab`, with a warning. **Unset becomes `production` in 0.6.** |

The Helm chart and the manifests in `deploy/k8s/` ship with `production`. The compose examples in
`deploy/frost/` and the DevNet driver configs in `deploy/devnet/` say `lab` explicitly.

## `check-config`

```bash
rutli-cosigner --config /config/cosigner-1.json check-config
```

This lists the same findings without starting anything: one `[required]` or `[advisory]` line per
setting, with what the file says and what the profile requires. It reads only the config file: no
key store, no secret, no file the config names. So it can run on any machine, against a copy of the
live config. It works under any `profile`.

| Exit | Meaning |
|---|---|
| `0` | No required finding (advisory ones may be listed). |
| `1` | Required findings: a `production` node would refuse to start. |
| `2` | The config does not load: a parse error, an unknown key, or a structural error. |

## Cosigner: what the profile requires

| Setting | Default | Production requires | Why |
|---|---|---|---|
| `tls` | optional | present | Without mTLS there are no roles and no intents. A plaintext node verifies nothing. |
| `tls.allow_expired_ca` | `false` | `false` | An emergency setting for a CA rotation. |
| `tls.require_peer_pins` | unset = on | on (not `false`) | Without peer key pins, any certificate with a peer's name under the cluster CA is that peer: a replaced node's old certificate, or one minted by whoever holds the CA key. |
| `share_seal` | optional | `secret_file` (a per-node seal bundle), no `secret_env` | Key files are plaintext without sealing. The legacy shared secret opens every node's files (P10, [runbook-per-node-seal.md](runbook-per-node-seal.md)). |
| `signer_allowlist` | required with TLS | non-empty | Only the driver may sign. |
| `operator_allowlist` | optional | non-empty | `verify-key` without a credential that can sign. |
| `refresh_allowlist` | optional | non-empty | The refresh job gets a credential that cannot sign. |
| `signing_policy.signer_may_refresh` | `true` | `false` | A stolen driver certificate must not drive refreshes. |
| `signing_policy.require_intent` | unset = on with TLS | on (not `false`) | No share for a digest no authorized client asked for (C2). |
| `signing_policy.require_ceremony_intent` | unset = on with TLS | on (not `false`) | No DKG, refresh or hosted-key generation that no authorized client asked for. |
| `signing_policy.require_epoch_match` | `false` | `true` | A leader must say which sharing of the key it signs with. |
| `signing_policy.signer_acl_required` | `false` | `true` | Every signer CN is limited to its key prefixes. |
| `signing_policy.signer_acl` | empty | an entry for every `signer_allowlist` CN | The same. |
| `signing_policy.signer_pins` | empty | a pin for every `signer_allowlist` CN | Revocation without the CA: a certificate with another key is refused under the same CN. |
| `signing_policy.sign_rate_limit_per_min`, `_per_day` | 300, 20000 | above 0 | A brake on bulk signing with a stolen credential. |
| `signing_policy.rate_limits` | empty | `per_min` and `per_day` above 0 in every rule | A rule with 0 turns the brake off for its prefix. |
| `ceremony_sign_test_rate_limit_per_min` | 10 | above 0 | Every sign test burns a nonce marker on each signer. |
| `keyfile.write_version` | 1 | 2 | Key files bound to the cluster, node and key (M4). |
| `keyfile.cluster_uuid` | unset | set, the same on every node | Required by v2. |
| `keyfile.accept_v1` | `true` | `false` | Once every file is v2. |
| `cluster_id` | derived from `tls.ca_cert` | set explicitly | A CA rotation must not change it ([ca-rotation.md](ca-rotation.md)). |
| `cluster_id_change_allowed` | `false` | `false` | Only for one deliberate start. |
| `hosted_keys.decrypt_rate_limit_per_min` (hosted keys on) | 6000 | above 0 | Bounds what a stolen driver certificate can decrypt. |
| `hosted_keys.delete_approval_threshold` (with `delete_allowlist`) | 0 | at least 1 | A delete needs a human approval. |
| `hosted_keys.commitment_key` (hosted keys on) | derived on the legacy master | set | The per-node seal bundle needs it. |
| `signing_policy.rules` | empty | **advisory**: a `quorum` rule whose prefix covers a namespace key (`<prefix>frost-namespace` from a Splice validator, `<prefix>frost-<node>-namespace` from Canton's auto-init) | Human approval of namespace-key signatures ([approval-quorum.md](approval-quorum.md)). A deployment decision, so it is reported and never refuses. |

The intent rows are not listed separately for a node without TLS: the `tls` row covers them.

Coming with a pending change (it adds its own row when it lands): `signing_policy.refresh_min_interval_secs`
(a minimum interval between refreshes).

## Driver: what the profile requires

The same setting in the driver's block, `crypto.kms.config`:

```hocon
crypto.kms.config = { profile = "production", backend = "frost", ... }
```

A production driver with a required finding stops the participant at startup with a config error
that names each setting. The offline check reads a Canton config file, or the driver block alone:

```bash
java -cp rutli-driver.jar com.stakecraft.rutli.tools.ConfigCheck \
  --config participant.conf --at canton.participants.participant1.crypto.kms.config
```

Its exit codes are those of `check-config` above.

| Setting | Default | Production requires | Why |
|---|---|---|---|
| `backend` | `software` | `frost` | The namespace key on the cosigner cluster, never in the participant. |
| `frost.delegate` | `hsm` | `hsm`, or `none` with `hosted-keys` | `software` keeps keys in the participant's memory or a local file. |
| `frost.tls` | optional | present | No mTLS, no intents, no roles. |
| `frost.tls.allow-expired-ca` | `false` | `false` | An emergency setting for a CA rotation. |
| `frost.endpoints` | a bare url is allowed | at least 2, each with its own, distinct `tls-name` | A group key is believed on two agreeing answers. Without a per-endpoint name, one cosigner certificate can answer for every address. |
| `frost.sign-intents` | `on` | `on` | `off` is an emergency switch. |
| `frost.cluster-id` | learned from the cluster | set | A learned value follows a majority of the cosigners; a set one cannot be steered. |
| `audit-log-path` | unset | set | The hash-chained audit log `audit-cross-check` compares with the journals. |
| `signing-journal` | unset | set | The driver's own record of every signature. |
| `hsm.pin` (with an HSM) | — | not inline; use `hsm.pin-env` | The PIN stays out of the config file. |
| `approval` | unset | **advisory**: a quorum rule for the namespace key (`<key-prefix>frost-namespace`) | Human approval of namespace-key signatures. A deployment decision, so it is reported and never refuses. |

Placement is not a config setting and the profile cannot check it: each cosigner in its own cluster
or cloud account is a go-live gate ([audit-prep.md](audit-prep.md#operator-go-live-gates-post-audit)).

## Upgrading

With this release the chart's `profile` defaults to `production`. **An existing install that does
not meet the list stops starting after a chart upgrade.** Do it in this order:

1. Take the live config of one node, for example
   `kubectl -n rutli exec <pod> -c cosigner -- cat /config/cosigner-1.json > live.json`.
2. Run `rutli-cosigner --config live.json check-config` with the new image (or binary).
3. Fix every `[required]` line in your values. The usual order is the one in
   [approval-quorum.md](approval-quorum.md), "Switching enforcement on":
   - the roles and ACLs and pins first;
   - then key-file v2: set `keyfile.cluster_uuid`, then `write_version: 2`, then let every node
     re-seal; `accept_v1: false` comes last, once every file is v2;
   - then `cluster_id`, set to the current derived value.
4. Render the chart with the new values, run `check-config` on the rendered config again, then
   upgrade.

If you cannot meet the list yet (a key-file migration in progress, or the legacy topology), set
`profile: lab` for the upgrade. Remove it once `check-config` exits 0. The chart refuses
`production` with `topology: legacy` at render time.

The other commands (`restore`, `keyfile migrate`, and so on) load the config the way the node does.
Under `production` with required findings they refuse too. Run them with the config as it will be,
or under `lab`. An older cosigner binary does not know the `profile` key and refuses the file, so
roll back the chart and the image together.

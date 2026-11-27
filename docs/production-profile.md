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
| `signing_policy.refresh_min_interval_secs` | 259200 (72 h) | at least 259200 (not `0`, not a shorter interval) | A stolen refresher certificate must not move a key to new epochs faster than backups follow ([ceremonies.md](ceremonies.md#refresh-interval)). |
| `keyfile.write_version` | 1 | 2 | Key files bound to the cluster, node and key (M4). |
| `keyfile.cluster_uuid` | unset | set, the same on every node | Required by v2. |
| `keyfile.accept_v1` | `true` | `false` | Once every file is v2. |
| `cluster_id` | derived from `tls.ca_cert` | set explicitly | A CA rotation must not change it ([ca-rotation.md](ca-rotation.md)). |
| `cluster_id_change_allowed` | `false` | `false` | Only for one deliberate start. |
| `hosted_keys.decrypt_rate_limit_per_min` (hosted keys on) | 6000 | above 0 | Bounds what a stolen driver certificate can decrypt. |
| `hosted_keys.delete_approval_threshold` (with `delete_allowlist`) | 0 | at least 1 | A delete needs a human approval. |
| `hosted_keys.commitment_key` (hosted keys on) | derived on the legacy master | set | The per-node seal bundle needs it. |
| `signing_policy.rules` | empty | **advisory**: a `quorum` rule whose prefix covers a namespace key (`<prefix>frost-namespace` from a Splice validator, `<prefix>frost-<node>-namespace` from Canton's auto-init) | Human approval of namespace-key signatures ([approval-quorum.md](approval-quorum.md)). A deployment decision, so it is reported and never refuses. |
| `signing_policy.journal_max_mib_per_key` | 64 | **advisory**: at least an estimate of one day's journal at the highest daily sign limit (`sign_rate_limit_per_day` or a `rate_limits` rule): one share per charge, 600 bytes each, plus 8 MiB | Retention never deletes the last 24 h of a key's journal (the rate limit is rebuilt from it when the journal opens), so on a busy day the journal grows past a smaller cap. An estimate for typical entries, not a bound on disk use (replayed intents, sign tests and gated keys write more), so it is reported and never refuses. |

The intent rows are not listed separately for a node without TLS: the `tls` row covers them.

`peer_deadlines.sign_round1_ms` (default 2000) and `peer_deadlines.sign_round2_ms` (default 5000) are not
checked by the profile: any value within the bounds (500 to 5000 and 1000 to 9000 ms) is accepted under `production`, and the defaults are recommended. Raise them only
when the peer-call latency histogram shows less than a 3x margin
([architecture.md](architecture.md), "Peer liveness").

`signing_policy.refresh_interval_waived_at` is not checked by the profile: it is the incident path
past the refresh interval, lets one refresh of a key through and lapses 24 h after its time
([ceremonies.md](ceremonies.md#refresh-interval)). A node warns at every start while it is in the
config.

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
| `frost.endpoints` | a bare url is allowed | at least 2, each with its own, distinct `tls-name` | A group key is believed on a roster majority of agreeing answers. Without a per-endpoint name, one cosigner certificate can answer for every address, and count more than once. |
| `frost.sign-intents` | `on` | `on` | `off` is an emergency switch. |
| `frost.cluster-id` | learned from the cluster | set | A learned value follows a majority of the cosigners; a set one cannot be steered. |
| `frost.pin-dir` | unset | set, on the participant's durable volume | Group-key pins that survive a restart. Without them, one cosigner answering another key blocks the first pin after every restart ([disaster-recovery.md](disaster-recovery.md#3i-the-drivers-group-key-pins-frostpin-dir)). |
| `frost.expected-group-keys` | empty | **advisory**: an entry for the namespace key, its group key from the key ceremony record | The operator's anchor: a first pin must equal it. |
| `audit-log-path` | unset | set | The hash-chained audit log `audit-cross-check` compares with the journals. |
| `signing-journal` | unset | set | The driver's own record of every signature. |
| `hsm.pin` (with an HSM) | — | not inline; use `hsm.pin-env` | The PIN stays out of the config file. |
| `approval` | unset | **advisory**: a quorum rule for the namespace key (`<key-prefix>frost-namespace` from a Splice validator, `<key-prefix>frost-<node>-namespace` from Canton's auto-init), or a rule over every FROST key | Human approval of namespace-key signatures. A deployment decision, so it is reported and never refuses. |

Placement is not a config setting and the profile cannot check it: each cosigner in its own cluster
or cloud account is a go-live gate ([audit-prep.md](audit-prep.md#operator-go-live-gates-post-audit)).

Encryption at rest for Kubernetes Secrets is the same kind of item: turn it on in the cluster
([Kubernetes: encrypt data at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)).
It covers a stolen control-plane disk or an etcd backup. It does not cover someone who is allowed
to read Secrets through the API. The cosigner cannot check it from inside the cluster, so it is on
the operator's list (issue #334).

One more item of the same kind: **one cosigner cluster per key owner, unless all its participants
belong to the same organisation.** The profile makes the API separation between participants firm
(ACL entries and pins for every driver CN); it adds no boundary between them on disk or in memory
([isolation-levels.md](isolation-levels.md)).

## Process hardening (every profile)

At start, before it opens a key store, the cosigner daemon turns core dumps off: `RLIMIT_CORE = 0`
and, on Linux, `PR_SET_DUMPABLE = 0`. Not dumpable also means another process of the same user
cannot ptrace it or read `/proc/<pid>/mem`; `kubectl exec` and the exec readiness probe start new
processes and are not affected. One start-up line says what took effect:

```text
INFO core dumps off: RLIMIT_CORE=0, not dumpable rlimit_core_zero=true not_dumpable=true core_pattern=… suid_dumpable=0
```

If a setting does not take effect, a `WARN core dumps not fully off: …` line names it. A process
that made itself non-dumpable is not dumped on Linux, whatever `kernel.core_pattern` and
`fs.suid_dumpable` say. Off Linux only `RLIMIT_CORE` applies.

Key shares are also wiped from memory when the process drops them: the share loaded from a key
file, the signing cache's copy (on eviction, refresh, shutdown) and the shares a ceremony builds.
Since frost 3.0 the FROST library also wipes the old share it consumes during a refresh. Not wiped:
intermediate scalars inside the library (refresh, DKG, signing), which are plain copyable values.

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
   - then `cluster_id`, set to the current derived value;
   - `signing_policy.refresh_min_interval_secs`: remove the key (the default is 72 h) or set it to
     259200 or more (at most 2592000, 30 days). A `production` config written for 0.5.0-rc.1 with `0` or a shorter interval
     stops starting with the next release.
4. Render the chart with the new values, run `check-config` on the rendered config again, then
   upgrade.

If you cannot meet the list yet (a key-file migration in progress, or the legacy topology), set
`profile: lab` for the upgrade. Remove it once `check-config` exits 0. The chart refuses
`production` with `topology: legacy` at render time.

The other commands (`restore`, `keyfile migrate`, and so on) load the config the way the node does.
Under `production` with required findings they refuse too. Run them with the config as it will be,
or under `lab`. A cosigner on 0.4.0 or 0.4.1 ignores the `profile` key (and the peer pin keys): it rejects unknown
keys only in `keyfile`. A config written for 0.5.0 therefore gives none of these guarantees on such
a binary. Check the running version (`--version`, or the image digest) before relying on them.

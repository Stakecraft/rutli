# Upgrading a cluster to 0.5.0

For operators of a cluster that runs 0.4.0 or 0.4.1. 0.5.0 is not released yet: this page describes
the first release candidate, `0.5.0-rc.1`, and it will be re-checked against each later candidate
and the release. It gathers the
upgrade notes that the changelog gives per change, in the order to do them. Each step names the page
with the detail.

0.5.0 is a security release: several protections that were off or optional in 0.4.x are on by
default, and some of them refuse to start without a setting you must add first. Do the steps in
this order. Nothing here changes the key files or the wire format; a cluster with some nodes on
0.4.x and some on 0.5.0 keeps signing.

## Before you start

- Run 0.4.1 or 0.4.0 on every node, and the driver on 0.4.0-rc.4 or later. A driver older than
  `0.4.0-rc.3`, or one with `frost.sign-intents = off`, does not sign intents: see step 4.
- Take a backup of every node (`backup`, or the chart's backup sidecar) and check that it restores.
  A refresh in the next days would make backups of the older epoch unable to restore that node (they stay sensitive)
  ([disaster-recovery.md](disaster-recovery.md), "Backups and refreshes").
- Check that no ceremony is running (`rutli_ceremonies_staged` is 0 on every node).
- **Order: the driver first, then the cosigners one at a time** (steps 1 and 2 change and check
  the config only; the driver and the cosigners follow in step 6). A 0.5.0 driver works against 0.4.x
  cosigners; a 0.4.x driver signs no generate intent, which a 0.5.0 cosigner requires to create a
  hosted key.
- **Do not create or delete hosted keys while the cluster runs mixed versions** (onboarding a new
  node, rotating an encryption key). From the driver upgrade until every cosigner runs 0.5.0,
  pause both. Serving keys that exist keeps working. The cluster does not enforce this fully; it
  is an operating rule. Detail: [hosted-keys.md](hosted-keys.md), "Upgrading from 0.4.0 (mixed
  versions)".
- Read [CHANGELOG.md](../CHANGELOG.md), the `## [0.5.0-rc.1]` section (later `## [0.5.0]`). This page lists what you must do, not what
  changed.

## 1. Pin every cosigner's TLS key, while the nodes still run 0.4.x

With TLS, a 0.5.0 cosigner refuses to start unless every entry of its peer roster carries the
SHA-256 of that node's certificate key (`peers[].tls_spki_sha256`), and its own certificate's key is
in its own entry. 0.4.0 and 0.4.1 ignore these keys (they reject unknown keys only in `keyfile`), so you can add them
first and nothing restarts that does not have to. For the same reason a config written for 0.5.0
gives none of these guarantees on a 0.4.x binary: check the running version (`--version`, or the
image digest) before relying on them.

1. Get each cosigner's pin: `rutli-cosigner tls spki cosigner1.crt cosigner2.crt cosigner3.crt`.
   `scripts/gen-frost-certs.sh` prints the pins of the certificates it makes and writes
   `peer-pins.json`, a Helm values file.
2. Add them to every node's config. With Helm, set `peerPins` (node id → pin) and install this
   chart with the image still at 0.4.x: only the ConfigMap changes. Keep `peerPins` in the saved
   values; a later `helm upgrade` needs them.
3. Do not swap a certificate during the upgrade. To roll a key later: [ca-rotation.md](ca-rotation.md) §10.

To upgrade without pins, set `tls.require_peer_pins: false` (Helm: `tls.requirePeerPins=false`).
The node warns at start and exports a non-zero `rutli_peer_pins_unpinned`. This is an opt-out. Without pins a
node still accepts whatever presents a valid certificate for a peer's name.

Detail: CHANGELOG ("Cosigners pin each other's TLS keys"), chart README ("Peer key pins"),
[threat-model.md](security/threat-model.md) ("Holder of the cluster CA key").

## 2. Check the config against the profile, with the new binary

0.5.0 adds `profile`. Unset behaves as `lab` (it logs what is missing and starts) and **becomes
`production` in 0.6**. The Helm chart and `deploy/k8s` set `production`: a chart upgrade stops a
node that does not meet the list. A 0.5.0 cosigner also refuses a config key it does not know,
which 0.4.x did not (a misspelt `require_intnet` used to be dropped).

1. Copy the live config of one node to a workstation.
2. Run `rutli-cosigner --config live.json check-config` with the new image or binary. Exit 0: no
   required finding. Exit 1: a `production` node would refuse to start. Exit 2: the file does not
   load, for example an unknown key. It reads only the file, so any machine will do.
3. Fix what it lists, in the order [production-profile.md](production-profile.md) ("Upgrading") gives. If you cannot meet
   the list yet, set `profile: lab` for the upgrade and remove it once `check-config` exits 0.
   The chart refuses `production` with `topology: legacy`.
4. Do the same for the driver. It has the same `profile` in `crypto.kms.config` (unset = `lab`, `production` in 0.6), and `com.stakecraft.rutli.tools.ConfigCheck` lists its findings offline ([production-profile.md](production-profile.md)). Start the participant with your current `crypto.kms.config`. The driver
   now also stops on a key it does not know and on a misspelt approval `mode` (the modes are
   `quorum` and `auto`, in lowercase). It reads an approver's key as `public-key-base64`; the old
   `public-key-base-64` still works.

Under `production`, `restore`, `keyfile migrate` and the other commands that load the config refuse
too while a required finding is open. Run them with the config as it will be, or under `lab`.

## 3. Refresh interval

A key is refreshed at most once per 72 hours (`signing_policy.refresh_min_interval_secs`, default
259200, at most 30 days; `0` turns it off, with a warning). Every node checks it, and a node on
0.5.0 refuses a refresh, led by any node, that comes inside the interval. A refresh needs every node, so
the limit holds as soon as one node runs 0.5.0.

- Scripts, drills and runbooks that refresh twice in a row will fail. Give test configs
  `refresh_min_interval_secs: 0`, with `profile: lab`: under `production` a node refuses to start
  with `0` or any interval under 72 h (259200), and `check-config` lists it. This check is new
  after 0.5.0-rc.1: a `production` config from rc.1 that sets the key lower must remove it or raise
  it before the upgrade.
- Set `signer_may_refresh: false`. While it is on, a stolen driver certificate can still refresh once
  per interval.
- Backups follow refreshes: the chart's backup sidecar backs up within `backup.checkEverySecs`
  (default 300 s) of a change to a node's key files. Outside the chart, run `backup` after every
  refresh.
- Incident path, one refresh past the interval: `signing_policy.refresh_interval_waived_at`.

Detail: [ceremonies.md](ceremonies.md) ("Refresh interval"), [disaster-recovery.md](disaster-recovery.md).

## 4. Signing intents are required with TLS

`signing_policy.require_intent` is on by default with TLS. A sign round without a client-signed
intent is refused. A driver on 0.4.0-rc.3 or later with `frost.sign-intents` at its default signs
every sign with an intent, and a rolling upgrade keeps signing. Otherwise set `require_intent: false`
(Helm: `signingPolicy.require_intent`) on every node first, and remove it once the driver signs
intents. The ceremony intents were already required by default since 0.4.0-rc.6.

A hand-run `grpcurl … Signer/Sign` against the TLS compose example is now refused; the CI smoke
test runs on copies that opt out.

Detail: [approval-quorum.md](approval-quorum.md) ("Switching enforcement on").

## 5. Sign session limits and the new alerts

A sign session now belongs to the peer that opened it, and one opener holds at most 256 sessions
per key and 20 per signing request (the key's total stays 1024). An honest leader stays far below
these numbers: about as many sessions as it has signs in flight. No setting. A refusal is counted in
`rutli_sign_session_owner_refusals_total` and `rutli_sign_sessions_refused_total{cap}`.

Re-apply the alert rules (`deploy/monitoring/prometheus-rules.yml`, or the rendered
`deploy/monitoring/k8s/prometheusrule.yaml`). The alerts added since 0.4.0 include
`RutliGrpcAcceptErrors` and `RutliGrpcConnectionsNearLimit` (both already in 0.4.1), `RutliSignSessionCapReached`,
`RutliSignSessionOwnerRefused`, `RutliSignUnknownSessions`, `RutliRefreshRefused`,
`RutliRefreshOffSchedule`, `RutliBackgroundLoopRestarted`, and for peer liveness `RutliPeerDown`,
`RutliPeerFlapping` and `RutliNoQuorum`. A sign round 2 for a session a node no longer holds now
answers `ABORTED`, not `INTERNAL`.

Peer calls now have short deadlines (sign round 1 2 s, round 2 5 s) and every leader keeps a
liveness state per peer (`docs/architecture.md`, "Peer liveness"). Nothing to configure. During
the rolling upgrade a 0.4.x member's key-store refusal reaches a 0.5.0 leader as a plain
`UNAVAILABLE` (read as unreachable until its next probe answers, within a second). A 0.4.x member
reports no load, so a 0.5.0 leader cannot tell it busy from stalled and never marks it stalled: a
round deadline on it excludes it from that signature only, and the next signature may include it
again (and pay that deadline again if it is still slow). Only no answer at all opens its breaker.
Both end with the upgrade. A Sign that runs out of attempts now carries the
`rutli-error: attempts-exhausted` trailer on the same `UNAVAILABLE`.

## 6. Upgrade one cosigner at a time

Moving the image is the step that needs care. First the driver (a participant restart): signing,
DKG and decryption are unchanged against 0.4.x cosigners, and creating hosted keys is refused until
the cosigners are upgraded.

**For the duration of the roll, raise the driver's sign attempt timeout to 12 s.** A 0.5.0 driver
gives one sign attempt at one cosigner 5 s (`frost.sign-attempt-timeout`, default `5s`) and then
fails over. A 0.4.x cosigner that leads a signature waits up to 10 s for a peer that is
restarting: its peer RPC deadline is 10 s, and its peer channels send no keepalive pings (0.5.0
cosigners do). With the defaults the driver gives up first, and the signature is dropped while a
cosigner restarts. Set it in the driver's `frost` block when you restart the participant for the
driver upgrade:

```hocon
frost { sign-attempt-timeout = 12s }   # during the roll only; must not exceed request-timeout (30 s)
```

Remove it (back to the default `5s`) after the last cosigner runs 0.5.0, at the participant's next
restart. Detail: [architecture.md](architecture.md), "Deadlines, keepalive and what Canton waits
for".

Then, per cosigner, wait for the gate before the next:

1. Upgrade one node to 0.5.0. It checks that every roster entry has a pin and that its own key is in
   its own entry. The log shows `peer N TLS key pins` for every node.
2. Gate: signatures complete through this node, `rutli_peer_pin_refusals_total` stays 0, and
   `check-config` is as you expect.
3. Repeat for the other nodes. The pin protection holds once every node runs 0.5.0.

**The chart now rolls one cosigner at a time.** Before this change, one `helm upgrade` restarted
all three cosigners together: measured on a real three-node cluster on 2026-11-20, upgrading from
0.4.1 to a build of `main` under 5 signatures a second, about 11 s with no cosigner up, 54 of 750
signatures `UNAVAILABLE` ([issue #173](https://github.com/Stakecraft/rutli/issues/173)). The per-node
StatefulSets now use `updateStrategy.type: OnDelete`: `helm upgrade` changes the spec and restarts no
pod, and `scripts/upgrade-cosigners.sh` restarts the cosigners one by one, waiting for each to be
Ready and the other two to stay Ready:

```sh
helm upgrade rutli deploy/helm/rutli-cosigner -n rutli -f values.yaml -f certs/peer-pins.json --set image.tag=…
scripts/upgrade-cosigners.sh -n rutli --release rutli --dry-run   # the plan
scripts/upgrade-cosigners.sh -n rutli --release rutli             # one node at a time
scripts/upgrade-cosigners.sh -n rutli --release rutli --status    # running vs target revision
```

Use `--settle 300` while the nodes still run 0.4.x. A change that is not in the pod template (pins in
the ConfigMap, a rotated certificate) restarts nothing by itself, with or without `OnDelete`: run the
script with `--force` to restart every node one at a time. Detail: chart README, "Upgrading: one
cosigner at a time". The legacy topology (one three-replica StatefulSet) rolls one pod at a time by
itself, and cannot run the production profile.

Rollback of one node to 0.4.x works with the same config: 0.4.x ignores the new keys, and the other
nodes still pin its unchanged key. With the Helm chart, roll back the chart and the image together.

## 7. After the upgrade

- Every node: `check-config` exits 0 under `production`; `rutli_peer_pins_unpinned` is 0.
- `verify-key` for every key reports one epoch and no stale node.
- Run `verify-key --sign-test` and `keyfile prove` only after every node runs 0.5. A 0.4.x node
  answers only the version 1 sign test, which a 0.5 `verify-key` refuses.
- Expect `RutliKeyEpochUnproven` for every key whose key file is more than three days old, until
  you prove its epoch: `verify-key --sign-test --json` from a workstation, then `keyfile prove` on
  every node ([ceremonies.md](ceremonies.md), "Proving an epoch"). Do it after the first refresh
  on 0.5.0 too. A proof recorded from an older `verify-key` report (sign-test message version 1)
  still counts, and `backup-retain` warns about it until the epoch is proven again on 0.5.
- Then, in your own time: key-file v2 and `accept_v1: false`, and per-node seal bundles if you still
  share one seal secret ([runbook-per-node-seal.md](runbook-per-node-seal.md)). Both are on the
  production list.

## Related

- [production-profile.md](production-profile.md): the list the profile checks, setting by setting.
- [ca-rotation.md](ca-rotation.md), [key-ceremony.md](key-ceremony.md),
  [disaster-recovery.md](disaster-recovery.md), [key-rotation.md](key-rotation.md),
  [migration.md](migration.md): the runbooks. They name the pins where a certificate or a node changes.
- [CHANGELOG.md](../CHANGELOG.md): the per-change notes.

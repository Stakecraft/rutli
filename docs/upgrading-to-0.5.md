# Upgrading a cluster to 0.5.0

For operators of a cluster that runs 0.4.0 or 0.4.1. 0.5.0 is not released yet: this page describes
`main`, and it will be re-checked against the release candidate and the release. It gathers the
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
  A refresh in the next days would make backups of the older epoch useless for that node
  ([disaster-recovery.md](disaster-recovery.md), "Backups and refreshes").
- Check that no ceremony is running (`rutli_ceremonies_staged` is 0 on every node).
- Read [CHANGELOG.md](../CHANGELOG.md), `## [Unreleased]`. This page lists what you must do, not what
  changed.

## 1. Pin every cosigner's TLS key, while the nodes still run 0.4.x

With TLS, a 0.5.0 cosigner refuses to start unless every entry of its peer roster carries the
SHA-256 of that node's certificate key (`peers[].tls_spki_sha256`), and its own certificate's key is
in its own entry. 0.4.0 and 0.4.1 ignore these keys, so you can add them first and nothing restarts
that does not have to.

1. Get each cosigner's pin: `rutli-cosigner tls spki cosigner1.crt cosigner2.crt cosigner3.crt`.
   `scripts/gen-frost-certs.sh` prints the pins of the certificates it makes and writes
   `peer-pins.json`, a Helm values file.
2. Add them to every node's config. With Helm, set `peerPins` (node id → pin) and install this
   chart with the image still at 0.4.x: only the ConfigMap changes. Keep `peerPins` in the saved
   values; a later `helm upgrade` needs them.
3. Do not swap a certificate during the upgrade. To roll a key later: [ca-rotation.md](ca-rotation.md) §10.

To upgrade without pins, set `tls.require_peer_pins: false` (Helm: `tls.requirePeerPins=false`).
The node warns at start and exports `rutli_peer_pins_unpinned`. This is an opt-out. Without pins a
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
4. Do the same for the driver: start the participant with your current `crypto.kms.config`. The driver
   now also stops on a key it does not know and on a misspelt approval `mode` (the modes are
   `quorum` and `auto`, in lowercase). It reads an approver's key as `public-key-base64`; the old
   `public-key-base-64` still works.

Under `production`, `restore`, `keyfile migrate` and the other commands that load the config refuse
too while a required finding is open. Run them with the config as it will be, or under `lab`.

## 3. Refresh interval

A key is refreshed at most once per 72 hours (`signing_policy.refresh_min_interval_secs`, default
259200, at most 30 days; `0` turns it off, with a warning). Every node checks it, and a node on
0.5.0 refuses a refresh led by a 0.4.x node. So the limit holds as soon as one node runs 0.5.0.

- Scripts, drills and runbooks that refresh twice in a row will fail. Give test configs
  `refresh_min_interval_secs: 0`.
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
`RutliGrpcAcceptErrors`, `RutliGrpcConnectionsNearLimit`, `RutliSignSessionCapReached`,
`RutliSignSessionOwnerRefused`, `RutliSignUnknownSessions`, `RutliRefreshRefused`,
`RutliRefreshOffSchedule` and `RutliBackgroundLoopRestarted`. A sign round 2 for a session a node no
longer holds now answers `ABORTED`, not `INTERNAL`.

## 6. Upgrade one cosigner at a time

Moving the image is the step that needs care. Per node, wait for the gate before the next:

1. Upgrade one node to 0.5.0. It checks that every roster entry has a pin and that its own key is in
   its own entry. The log shows `peer N TLS key pins` for every node.
2. Gate: signatures complete through this node, `rutli_peer_pin_refusals_total` stays 0, and
   `check-config` is as you expect.
3. Repeat for the other nodes. The pin protection holds once every node runs 0.5.0.

**One `helm upgrade` restarts all three cosigners.** The chart's three per-node StatefulSets change
in one apply and restart together, and the PodDisruptionBudget does not apply to a StatefulSet's own
update. Measured on a real three-node cluster on 2026-11-20, upgrading from 0.4.1 to a build of
`main` under 5 signatures a second: about 11 s with no cosigner up, 54 of 750 signatures failed
with `UNAVAILABLE`, and the keys were unchanged afterwards. Until the chart can roll one node at a
time ([issue #173](https://github.com/Stakecraft/rutli/issues/173)), plan the image upgrade as an
outage of about that length, not as a rolling upgrade. The config-only steps above (pins) do not
restart anything.

Rollback of one node to 0.4.x works with the same config: 0.4.x ignores the new keys, and the other
nodes still pin its unchanged key. With the Helm chart, roll back the chart and the image together.

## 7. After the upgrade

- Every node: `check-config` exits 0 under `production`; `rutli_peer_pins_unpinned` is absent.
- `verify-key` for every key reports one epoch and no stale node.
- Then, in your own time: key-file v2 and `accept_v1: false`, and per-node seal bundles if you still
  share one seal secret ([runbook-per-node-seal.md](runbook-per-node-seal.md)). Both are on the
  production list.

## Related

- [production-profile.md](production-profile.md): the list the profile checks, setting by setting.
- [ca-rotation.md](ca-rotation.md), [key-ceremony.md](key-ceremony.md),
  [disaster-recovery.md](disaster-recovery.md), [key-rotation.md](key-rotation.md),
  [migration.md](migration.md): the runbooks. They name the pins where a certificate or a node changes.
- [CHANGELOG.md](../CHANGELOG.md): the per-change notes.

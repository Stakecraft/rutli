# Cosigners on plain Linux hosts (systemd, Ansible)

How to run the three cosigners without Kubernetes: one hardened systemd service per host, installed
by hand from [`deploy/systemd/`](../deploy/systemd/) or with the Ansible role in
[`deploy/ansible/`](../deploy/ansible/).

**Status.** New in 0.6. This install path is not part of the v0.5.0 audit scope. The unit files and
the role pass their linters and the config they write passes `check-config`; a full install on
three hosts has not been recorded yet. Until it has, treat this page as a starting point and run it
in a lab first.

Supported: Debian 12 and 13, x86_64 and aarch64. Other distributions with systemd 250 or later and
cgroup v2 should work and are not tested.

## What this covers

| Covered | Not covered |
|---|---|
| The cosigner daemon on its host: binary, config, service, backups | The Canton participant and the driver jar. You run the participant your own way; see [The driver side](#the-driver-side) |
| Upgrades one host at a time, rollback of the binary | Creating key material: seal bundles, certificates, the CA |
| An example of the firewall rules | Applying firewall rules |
| | Any ceremony: DKG, refresh, restore, the split ceremony |

The role never creates, reads or moves a key share, a seal bundle or a private key, and it never
starts a ceremony. Under the production profile it does not carry any secret at all.

## Layout on the host

| Path | Owner, mode | What |
|---|---|---|
| `/opt/rutli-cosigner/<version>/rutli-cosigner` | root, 0755 | The binary of one release. Older releases stay for rollback. |
| `/usr/local/bin/rutli-cosigner` | link | Points at the release in use. |
| `/etc/rutli-cosigner/cosigner.json` | root:rutli, 0640 | The node's config. No secret in it. |
| `/etc/rutli-cosigner/ca.crt`, `cosigner.crt` | root:rutli, 0644 | The cluster CA and this node's certificate. |
| `/etc/rutli-cosigner/secrets/seal.json`, `tls.key` | root:root, 0400 in a 0700 directory | The node's seal bundle and TLS private key. |
| `/var/lib/rutli-cosigner` | rutli, 0700 | `data_dir`: the sealed key files and the journals. Never removed by the role. |
| `/var/backups/rutli-cosigner` | rutli, 0700 | Local backups (sealed key files only). |

The daemon runs as the user `rutli`, which cannot read `/etc/rutli-cosigner/secrets`. systemd
passes the two files to the service only (`LoadCredential`), in memory, under
`/run/credentials/rutli-cosigner.service/`; the config names those paths. The unit also gives the
service a read-only file system apart from `data_dir`, a private `/tmp` in memory, no capabilities,
no swap and no core dumps. The comments in
[`rutli-cosigner.service`](../deploy/systemd/rutli-cosigner.service) say what each line is for.

## Get the binary

From 0.6.0 the release assets include `rutli-cosigner-<version>-linux-x86_64` and
`-linux-aarch64`, signed like the other assets. Verify the file on the control machine with the
commands in [releasing.md, "Release assets"](releasing.md#release-assets) (`cosign verify-blob`,
`gh attestation verify`, then `SHA256SUMS`), and give the role the path and the sha256 from
`SHA256SUMS`. The role compares the sha256 on the control machine and again on the host, and the
hosts download nothing.

For a release without that asset, build it from the tag:
`cargo build --release --locked -p rutli-cosigner --bin rutli-cosigner` in `frost/`, on the oldest
distribution you run (the binary links to the system's glibc).

To run the published container image under systemd instead, see
[Alternative: the image under podman](#alternative-the-image-under-podman).

## Lab

For trying the install and for tests. `profile: lab` refuses nothing. **Never for an authority
key.**

One control machine reaches all three hosts and holds every certificate and seal bundle. That is
what makes it a lab.

1. On the control machine, in a checkout of the release tag:

   ```bash
   mkdir -p deploy/ansible/files/seal
   scripts/gen-frost-certs.sh 3 deploy/ansible/files/certs
   for i in 1 2 3; do rutli-cosigner seal new-node --node $i --out deploy/ansible/files/seal/node-$i.json; done
   ```

   `deploy/ansible/files/` is git-ignored. Put the verified binary there too.
2. Copy `deploy/ansible/inventory/lab.example.yml` to `inventory/lab.yml`. Set the three host names,
   the version, the binary's path and its sha256.
3. Install and start:

   ```bash
   cd deploy/ansible
   ansible-playbook -i inventory/lab.yml playbooks/install.yml
   ```

4. On a host: `systemctl status rutli-cosigner`, `journalctl -u rutli-cosigner`, and
   `sudo runuser -u rutli -- rutli-cosigner --config /etc/rutli-cosigner/cosigner.json health`.

The cosigners now wait for a driver. A lab participant is described in
[`deploy/devnet/`](../deploy/devnet/README.md).

## Production

Read [production-profile.md](production-profile.md), [key-ceremony.md](key-ceremony.md) and the
go-live gates in [audit-prep.md](audit-prep.md#operator-go-live-gates-post-audit) first. This
section only says what is different on plain hosts.

**One host per cosigner, and nothing above them.** Each cosigner has its own host, on its own site
or account. No machine and no person can become root on two of them. That includes the Ansible
control machine: one that reaches all three hosts as root is by itself above the 2-of-3 threshold.
So in production each host has its own inventory file, its own operator and its own SSH credential,
and the playbooks run for one host at a time.

**The secrets are placed by a person.** The seal bundle of a node is minted offline at the key
ceremony and reaches only that node. The role refuses the lab variables under `production`; it
checks that the two files exist as `root:root 0400` and reads nothing but their metadata.

On each host, by that host's operator:

1. Put the two secrets in place, then remove the copy they arrived on:

   ```bash
   sudo install -d -m 0700 -o root -g root /etc/rutli-cosigner/secrets
   sudo install -m 0400 -o root -g root node-1.json /etc/rutli-cosigner/secrets/seal.json
   sudo install -m 0400 -o root -g root cosigner1.key /etc/rutli-cosigner/secrets/tls.key
   ```

2. Write this host's inventory from `deploy/ansible/inventory/production.example.yml`. Every value
   in it is public. The roster, the peer pins, `rutli_cosigner_cluster_id` and the policy are the
   same on all three hosts: agree on them once and compare the three files.
3. Install:

   ```bash
   cd deploy/ansible
   ansible-playbook -i inventory/cosigner1.yml playbooks/install.yml
   ```

   The role runs `rutli-cosigner check-config` on the new config before it replaces the old one.
   Under `production` any `[required]` finding stops the run and nothing is changed; the output
   names each setting.
4. When all three run, continue with the key ceremony. The role has no part in it.

Each cosigner's certificate carries the name `cosigner<id>`. Peers and the driver verify that name,
whatever host name or address the endpoint uses.

## Upgrade

One host at a time. With threshold 2 of 3 nothing can sign while two cosigners are down.

`playbooks/install.yml` never restarts a running cosigner: it installs the new files and says that
a restart is pending. `playbooks/upgrade.yml` does the restart. For each host it:

1. installs the new binary and config (the new binary checks the new config first);
2. checks that the gRPC port of every other cosigner answers, and stops if one does not
   (`-e rutli_cosigner_allow_degraded=true` when the upgrade is the repair of this one node);
3. restarts the service and waits for `rutli-cosigner health`;
4. waits `rutli_cosigner_settle_seconds` (120). `health` proves the key store and the port, not
   that the peer connections are back.

**Lab:** set the new version, path and sha256 in the inventory, then
`ansible-playbook -i inventory/lab.yml playbooks/upgrade.yml`. It takes the hosts in turn and stops
at the first failure.

**Production:** each operator runs it for their host, one after the other:
`ansible-playbook -i inventory/cosigner1.yml playbooks/upgrade.yml`. Before the next host starts,
check the cluster with a sign test (`verify-key --sign-test`, [admin-cli.md](admin-cli.md)).

Read the release's upgrade notes before the first host; for 0.4.x to 0.5.0 that is
[upgrading-to-0.5.md](upgrading-to-0.5.md). A config change without a new binary is rolled out the
same way.

## Rollback

The binary of the previous release is still in `/opt/rutli-cosigner/<old version>/`. Set
`rutli_cosigner_version`, the path and the sha256 back and run `playbooks/upgrade.yml` for that
host. Two limits:

- The old binary must accept the config. An older release rejects config keys it does not know.
- Key files written by the new release may not be readable by the old one (key-file version 2,
  [upgrading-to-0.5.md](upgrading-to-0.5.md)). The release notes say when a rollback stops being
  possible.

## Backups

Two timers back up this node's **sealed** key files, its cleared-delete markers and its sign
journals, the same content as the chart's backup sidecar:

- `rutli-cosigner-backup.timer`: daily at 03:17 UTC;
- `rutli-cosigner-backup-check.timer`: every five minutes, a backup only if the key files changed.
  Every refresh moves the node to a new epoch and its older backups no longer restore it, so a
  backup follows each refresh without a manual step. Disable this timer for the window of a split
  ceremony ([split-ceremony.md](split-ceremony.md)).

The backup service runs as the cosigner's user with less than the cosigner has: no seal bundle, no
TLS key, a read-only data directory, no network. Each run logs `BACKUP_OK …` or `BACKUP_FAILED …`
(`journalctl -u rutli-cosigner-backup -u rutli-cosigner-backup-check`); a failed run leaves the
unit in the failed state. Alert on either. Before the node holds its first key the daily run fails with
`reason=no-key-files-…`; that is expected until the key ceremony.

By default the archives go to `/var/backups/rutli-cosigner` on the same host, with retention by
epoch ([disaster-recovery.md](disaster-recovery.md)). That covers a wiped or corrupted data
directory, not the loss of the host. To send them elsewhere, install an executable
`/etc/rutli-cosigner/backup-ship`: it is called with the tar and the node id and must exit non-zero
on failure. It needs the network, so add a drop-in for both backup services:

```ini
# /etc/systemd/system/rutli-cosigner-backup.service.d/ship.conf (and …-backup-check.service.d/)
[Service]
PrivateNetwork=no
IPAddressDeny=any
IPAddressAllow=192.0.2.40
```

Each node ships to its own destination with its own credential. A destination that holds the
backups of two nodes holds sealed files only; the seal bundles must never be stored with them.

## Offline commands and restore

`restore`, `keyfile …`, `ceremony resolve` and the other commands that open the key store need the
daemon's user and its two credentials. Run them through the wrapper:

```bash
sudo systemctl stop rutli-cosigner        # only for the commands that need the daemon stopped
sudo rutli-cosigner-cli restore …
sudo systemctl start rutli-cosigner
```

One node at a time; the other two keep signing. While a node is stopped on purpose, run the role
with `-e rutli_cosigner_start=false` or not at all, so that it does not start the node again.
The procedures themselves are in [disaster-recovery.md](disaster-recovery.md).

## Firewall

The role does not touch the firewall. [`nftables.example.nft`](../deploy/systemd/nftables.example.nft)
shows the rules that match the chart's NetworkPolicy:

| Port | From |
|---|---|
| 9101 (gRPC, mTLS) | the two other cosigners and the participant that runs the driver |
| 9200 (metrics, plain HTTP) | the Prometheus server only |

Outbound, the cosigner needs port 9101 of the two other cosigners and DNS. By default the role
binds the metrics port to `127.0.0.1`; set `rutli_cosigner_metrics_listen` to the address
Prometheus reaches.

## Monitoring

Metrics, the alert rules in [`deploy/monitoring/prometheus-rules.yml`](../deploy/monitoring/prometheus-rules.yml)
and the dashboard are the same as for the chart ([observability.md](observability.md)). The logs
are in the journal: `journalctl -u rutli-cosigner`. systemd restarts the daemon when it exits with
an error; five failed starts in five minutes stop the unit, which is what a config refused by the
production profile looks like.

## The driver side

The participant needs the driver jar and three endpoints, each with the cosigner's TLS name:

```hocon
endpoints = [
  { url = "cosigner1.example.internal:9101", tls-name = "cosigner1" },
  { url = "cosigner2.example.internal:9101", tls-name = "cosigner2" },
  { url = "cosigner3.example.internal:9101", tls-name = "cosigner3" }
]
```

Everything else about the driver is in [production-profile.md](production-profile.md#driver-what-the-profile-requires)
and [migration.md](migration.md).

## Scheduled refresh

A refresh is a ceremony, so the role does not schedule it. Run
`rutli-cosigner --config client-refresher.json refresh --key-id …` from the machine that holds the
refresher certificate, on a systemd timer or by hand
([ceremonies.md](ceremonies.md); `deploy/k8s/cronjob-refresh.yaml` shows the command).

## Differences from the Helm chart

| Chart | Plain hosts |
|---|---|
| One values file renders all three configs | One inventory per host in production; you compare the shared values yourself |
| Secrets are Kubernetes Secrets mounted as files | Files in a root-only directory, passed as systemd credentials |
| NetworkPolicy | Your host firewall; an example is provided |
| Readiness probe takes a sick node out of the Service | No Service: the driver's failover routes around a node that answers `UNAVAILABLE` |
| `scripts/upgrade-cosigners.sh` | `playbooks/upgrade.yml` |
| Backup sidecar, PVC destination | Timers, a local directory or a ship hook |
| `maintenanceNodes` | `systemctl stop` and `rutli-cosigner-cli` |
| Pod anti-affinity, PodDisruptionBudget | Three hosts; nothing restarts a cosigner except you |

## Alternative: the image under podman

If you prefer the signed container image to a host binary, a systemd unit can run it with podman
(`podman run` in `ExecStart`, or a Quadlet file). Verify the image digest first
([SECURITY.md](../SECURITY.md#verify-the-image)) and pin it by digest. Keep the same rules as above:

- mount the config and the certificates read-only, the data directory read-write, `/tmp` as tmpfs,
  with `--read-only --cap-drop=all --security-opt=no-new-privileges`;
- give the container the seal bundle and the TLS key as files that only its user (uid 10001 in the
  image) can read, never as environment variables;
- the paths in the config are then the paths inside the container.

The repository ships no unit for this and the role does not install it. The sandbox lines of
`rutli-cosigner.service` would apply to podman, not to the cosigner, so the container flags carry
that part. The project has not run this variant.

## Removing a cosigner

Stop and disable the service and the timers. Do not delete `/var/lib/rutli-cosigner` or the
backups unless the node's share is meant to be destroyed
([key-material-handling.md](key-material-handling.md)).

# systemd units for one cosigner on a plain Linux host

The full page is [docs/bare-metal.md](../../docs/bare-metal.md). The Ansible role in
[`deploy/ansible/`](../ansible/) installs exactly these files; they can also be installed by hand.

| File | Goes to | What it is |
|---|---|---|
| `rutli-cosigner.service` | `/etc/systemd/system/` | The daemon. The seal bundle and the TLS key reach it as systemd credentials. |
| `rutli-cosigner-backup.service`, `.timer` | `/etc/systemd/system/` | A daily backup of the sealed key files and the journals. |
| `rutli-cosigner-backup-check.service`, `.timer` | `/etc/systemd/system/` | A backup within five minutes of a change to the key files (a refresh). |
| `rutli-cosigner-backup` | `/usr/local/libexec/` | The backup script both services run. |
| `rutli-cosigner-cli` | `/usr/local/sbin/` | Runs a `rutli-cosigner` command with the daemon's user and credentials. |
| `nftables.example.nft` | nowhere | An example of the firewall rules. Nothing installs it. |

Needs systemd 250 or later. Written for Debian 12 and 13, Ubuntu 24.04.

None of these files creates, copies or moves key material, and none starts a ceremony.

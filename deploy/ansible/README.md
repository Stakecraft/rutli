# Ansible role: one cosigner on a plain Linux host

The full page is [docs/bare-metal.md](../../docs/bare-metal.md). Read its "Lab" or "Production"
section before the first run; the two are not the same procedure.

```text
roles/rutli_cosigner/           the role (variables: roles/rutli_cosigner/defaults/main.yml)
playbooks/install.yml           install or update the files; never restarts a running cosigner
playbooks/upgrade.yml           restart onto a new binary or config, one host at a time
inventory/lab.example.yml       three lab hosts from one control machine
inventory/production.example.yml  ONE production host; each host has its own inventory
tests/render.yml                renders the config for an inventory without touching a host
```

The role installs the unit files and scripts of [`deploy/systemd/`](../systemd/), so use it from a
checkout of the release tag. It needs ansible-core 2.16 or later on the control machine and
Debian 12/13 or Ubuntu 24.04 with systemd 250 or later on the host.

What the role never does: create, read or move a key share, a seal bundle, a private key or a CA;
run a ceremony; delete the data directory; change the firewall. Under the production profile it
takes no secret from the control machine and only checks that the two secret files are on the host.

`inventory/*.yml` (except the examples) and `files/` are git-ignored: keep your inventory and the
lab material out of the repository.

Checks: `scripts/ci-deploy-hosts.sh` (the "Host install files" workflow runs it).

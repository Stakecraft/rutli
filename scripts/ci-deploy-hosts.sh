#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# Checks of the plain-host install files: deploy/systemd and deploy/ansible (docs/bare-metal.md).
#
#   scripts/ci-deploy-hosts.sh            (from anywhere)
#
# Needs shellcheck, yamllint, ansible-lint and ansible-playbook. The systemd part needs
# systemd-analyze (systemd 250 or later) and sudo, because `systemd-analyze verify` resolves the
# binaries a unit names: it installs placeholder files at those paths. So it runs only with
# CI=true (a throwaway runner) and is skipped elsewhere, with a line that says so.
#
# Nothing here starts a cosigner. What is checked: the scripts (shellcheck), the YAML, the role
# against ansible-lint's production profile, the playbooks' syntax, the config the role's template
# renders for both example inventories, and that systemd accepts every unit file.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="$REPO/deploy/systemd"
A="$REPO/deploy/ansible"

echo "== shellcheck"
shellcheck "$S/rutli-cosigner-backup" "$S/rutli-cosigner-cli" "${BASH_SOURCE[0]}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== the two backup services differ only where they should"
# rutli-cosigner-backup-check.service is the backup service plus --if-changed, with its own runtime
# directory; the sandbox lines must stay the same in both.
for u in rutli-cosigner-backup rutli-cosigner-backup-check; do
  grep -vE '^(#|Description=|ExecStart=|RuntimeDirectory=)' "$S/$u.service" >"$WORK/$u.settings"
done
if ! diff "$WORK/rutli-cosigner-backup.settings" "$WORK/rutli-cosigner-backup-check.settings"; then
  echo "error: the settings of the two backup services have drifted apart" >&2
  exit 1
fi

cd "$A"
ANSIBLE_HOME="$WORK/ansible"
ANSIBLE_LOCAL_TEMP="$WORK/ansible/tmp"
ANSIBLE_REMOTE_TEMP="$WORK/ansible/rtmp"
ANSIBLE_NOCOLOR=1
export ANSIBLE_HOME ANSIBLE_LOCAL_TEMP ANSIBLE_REMOTE_TEMP ANSIBLE_NOCOLOR

echo "== yamllint"
yamllint -c .yamllint .

echo "== ansible-lint"
ansible-lint --offline

echo "== playbook syntax"
ansible-playbook -i inventory/lab.example.yml playbooks/install.yml playbooks/upgrade.yml --syntax-check

echo "== render the config for both example inventories"
for inv in lab production; do
  mkdir -p "$WORK/render/$inv"
  ansible-playbook -i "inventory/$inv.example.yml" tests/render.yml -e "rutli_cosigner_test_out=$WORK/render/$inv" >"$WORK/render-$inv.log" 2>&1 \
    || {
      cat "$WORK/render-$inv.log"
      exit 1
    }
  echo "ok: $inv ($(find "$WORK/render/$inv" -name '*.json' | wc -l | tr -d ' ') config(s))"
done
# With a cosigner binary at hand the rendered configs also go through check-config: the production
# example must meet the production profile (exit 0); the lab example must load (exit 0 or 1).
if [ -n "${RUTLI_COSIGNER:-}" ]; then
  echo "== check-config on the rendered configs ($RUTLI_COSIGNER)"
  for f in "$WORK"/render/production/*.json; do
    "$RUTLI_COSIGNER" --config "$f" check-config
  done
  for f in "$WORK"/render/lab/*.json; do
    rc=0
    "$RUTLI_COSIGNER" --config "$f" check-config >/dev/null || rc=$?
    [ "$rc" -le 1 ] || {
      echo "error: $f does not load (check-config exit $rc)" >&2
      exit 1
    }
  done
else
  echo "skipped: check-config on the rendered configs (set RUTLI_COSIGNER=/path/to/rutli-cosigner)"
fi

echo "== systemd-analyze verify"
if [ "${CI:-}" != "true" ]; then
  echo "skipped: runs only with CI=true (it installs placeholder files under /usr/local with sudo)"
  exit 0
fi
systemd-analyze --version | head -n 1
sudo install -D -m 0755 /bin/true /usr/local/bin/rutli-cosigner
sudo install -D -m 0755 "$S/rutli-cosigner-backup" /usr/local/libexec/rutli-cosigner-backup
id rutli >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin rutli
units=("$S"/*.service "$S"/*.timer)
systemd-analyze verify --recursive-errors=no "${units[@]}"
# The exposure score of the daemon's unit, for the reviewer. Informational: no threshold is set
# until the score has been compared with a run on a real host.
systemd-analyze security --offline=true --no-pager "$S/rutli-cosigner.service" | tail -n 3 || true
echo "ok: systemd accepts ${#units[@]} unit files"

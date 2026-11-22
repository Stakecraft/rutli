#!/usr/bin/env bash
# Copyright 2026 StakeCraft LLC
# SPDX-License-Identifier: Apache-2.0
# CI gate for the deployment manifests (audit C3/M3): lint and render the Helm chart in both
# topologies, check that it refuses to render without TLS key pins, check deploy/k8s is the current render, run scripts/check-deploy-policy.sh on every
# perNode render and on the kustomize build, and prove the checker still rejects the deprecated
# legacy topology. Also pins that the DevNet soak's values still render the legacy StatefulSet, so a
# plain `helm upgrade` cannot move the live soak by accident.
#
#   scripts/ci-deploy-policy.sh        (from anywhere; needs helm 3, kubectl, yq v4, jq)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C="$REPO/deploy/helm/rutli-cosigner"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

# Every render needs TLS key pins (peerPins; tls.requirePeerPins unset = on). ci/peer-pins-values.yaml
# holds placeholders: with it alone it is the chart's defaults, and it stands in for the pins the
# live soak install carries in its own values.
PINS="$C/ci/peer-pins-values.yaml"

echo "==> peer pins: the bare defaults must not render, the explicit opt-out must"
if helm template rutli "$C" -n rutli >/dev/null 2>"$OUT/no-pins.err"; then
  echo "the chart rendered without peerPins — the pin requirement is broken" >&2
  exit 1
fi
grep -q 'peerPins."1" is missing' "$OUT/no-pins.err" || { cat "$OUT/no-pins.err" >&2; exit 1; }
helm template rutli "$C" -n rutli --set tls.requirePeerPins=false >"$OUT/no-pins-opt-out.yaml"
grep -q '"require_peer_pins": false' "$OUT/no-pins-opt-out.yaml" \
  || { echo "tls.requirePeerPins=false did not reach the cosigner configs" >&2; exit 1; }
echo "no peerPins: refused; tls.requirePeerPins=false: rendered with the opt-out"

echo "==> helm lint"
helm lint "$C" -f "$PINS" >/dev/null
for v in "$C"/ci/*.yaml; do helm lint "$C" -f "$v" >/dev/null; done
# The soak still runs the legacy topology, which cannot meet the production profile (the chart's
# default): its upgrade needs `profile: lab` (docs/production-profile.md, "Upgrading"). Without it
# the chart refuses to render, so a plain `helm upgrade` cannot move the soak either.
SOAK_LAB=(--set profile=lab)
helm lint "$C" -f "$REPO/deploy/soak/cosigner-values.yaml" -f "$PINS" "${SOAK_LAB[@]}" >/dev/null

echo "==> render"
helm template rutli "$C" -n rutli -f "$PINS" >"$OUT/pernode-default.yaml"
for v in "$C"/ci/*.yaml; do helm template rutli "$C" -n rutli -f "$v" >"$OUT/$(basename "$v" .yaml).yaml"; done
helm template rutli "$C" -n rutli -f "$REPO/deploy/soak/cosigner-values.yaml" -f "$PINS" "${SOAK_LAB[@]}" >"$OUT/soak.yaml"
if helm template rutli "$C" -n rutli -f "$REPO/deploy/soak/cosigner-values.yaml" -f "$PINS" >/dev/null 2>&1; then
  echo "the soak's legacy values render under the production profile — the chart's legacy guard is broken" >&2
  exit 1
fi
kubectl kustomize "$REPO/deploy/k8s" >"$OUT/k8s.yaml"

echo "==> deploy/k8s is the current chart render"
"$REPO/scripts/render-k8s.sh" --check

echo "==> policy: perNode renders and deploy/k8s must pass"
for f in pernode-default pernode-values pernode-migrated-soak-values k8s; do
  printf '%s: ' "$f"
  "$REPO/scripts/check-deploy-policy.sh" "$OUT/$f.yaml"
done

echo "==> update strategy: perNode StatefulSets are OnDelete (an upgrade must not restart all cosigners at once)"
for f in pernode-default pernode-values pernode-migrated-soak-values k8s; do
  n="$(yq -N 'select(.kind == "StatefulSet") | .metadata.name' "$OUT/$f.yaml" | wc -l | tr -d ' ')"
  bad="$(yq -N 'select(.kind == "StatefulSet") | select(.spec.updateStrategy.type != "OnDelete") | .metadata.name' "$OUT/$f.yaml")"
  if [ "$n" -lt 3 ] || [ -n "$bad" ]; then
    echo "$f: $n StatefulSets, without updateStrategy OnDelete: ${bad:-none}" >&2
    exit 1
  fi
done
echo "perNode renders: OnDelete on every StatefulSet"
legacy_strategy="$(yq -N 'select(.kind == "StatefulSet") | .spec.updateStrategy' "$OUT/legacy-values.yaml" "$OUT/soak.yaml" | grep -vx -e null -e '---' || true)"
if [ -n "$legacy_strategy" ]; then
  echo "the legacy StatefulSet must not get an updateStrategy (it already rolls one pod at a time): $legacy_strategy" >&2
  exit 1
fi
echo "legacy renders: no updateStrategy, unchanged"
helm template rutli "$C" -n rutli -f "$C/ci/pernode-values.yaml" --set updateStrategy.type=RollingUpdate >"$OUT/rolling.yaml"
[ "$(yq -N 'select(.kind == "StatefulSet") | .spec.updateStrategy.type' "$OUT/rolling.yaml" | sort -u)" = RollingUpdate ] \
  || { echo "updateStrategy.type=RollingUpdate was not honoured" >&2; exit 1; }
if helm template rutli "$C" -n rutli -f "$C/ci/pernode-values.yaml" --set updateStrategy.type=Bogus >/dev/null 2>&1; then
  echo "an unknown updateStrategy.type was accepted" >&2
  exit 1
fi
echo "updateStrategy.type: RollingUpdate honoured, unknown values refused"

echo "==> scripts/upgrade-cosigners.sh against a fake kubectl"
"$REPO/scripts/test-upgrade-cosigners.sh" | tail -1

echo "==> policy: the legacy topology must be rejected"
if "$REPO/scripts/check-deploy-policy.sh" "$OUT/legacy-values.yaml" 2>/dev/null; then
  echo "check-deploy-policy.sh ACCEPTED the legacy topology — the checker is broken" >&2
  exit 1
fi
echo "legacy-values: rejected, as it must be"

echo "==> policy: a backup sidecar with the node's TLS key or a writable data mount must be rejected"
for mutation in \
  '.volumeMounts += [{"name": "certs", "mountPath": "/certs"}]' \
  '(.volumeMounts[] | select(.name == "data") | .readOnly) = false'; do
  yq "(select(.kind == \"StatefulSet\") | .spec.template.spec.containers[] | select(.name == \"backup\")) |= ($mutation)" \
    "$OUT/pernode-values.yaml" >"$OUT/mutated.yaml"
  if "$REPO/scripts/check-deploy-policy.sh" "$OUT/mutated.yaml" 2>/dev/null; then
    echo "check-deploy-policy.sh ACCEPTED a backup sidecar with: $mutation — the checker is broken" >&2
    exit 1
  fi
done
echo "mutated sidecars: rejected, as they must be"

echo "==> policy: a disk-backed or unbounded emptyDir on a cosigner pod must be rejected"
for mutation in \
  '(.spec.template.spec.volumes[] | select(.name == "tmp") | .emptyDir) = {}' \
  '(.spec.template.spec.volumes[] | select(.name == "tmp") | .emptyDir) = {"medium": "Memory"}' \
  '(.spec.template.spec.volumes[] | select(.name == "backup-work") | .emptyDir) = {"sizeLimit": "1Gi"}'; do
  yq "(select(.kind == \"StatefulSet\") | select(.metadata.name | test(\"n1\"))) |= ($mutation)" \
    "$OUT/pernode-values.yaml" >"$OUT/mutated.yaml"
  if "$REPO/scripts/check-deploy-policy.sh" "$OUT/mutated.yaml" 2>/dev/null; then
    echo "check-deploy-policy.sh ACCEPTED: $mutation — the checker is broken" >&2
    exit 1
  fi
done
echo "disk-backed or unbounded scratch volumes: rejected, as they must be"

echo "==> the soak's values still render the legacy StatefulSet (no topology/PVC change on upgrade)"
sts="$(yq -N 'select(.kind == "StatefulSet") | .metadata.name' "$OUT/soak.yaml")"
claims="$(yq -N 'select(.kind == "StatefulSet") | .spec.volumeClaimTemplates[].spec.accessModes[]' "$OUT/soak.yaml")"
if [ "$sts" != "rutli-cosigner" ] || [ "$claims" != "ReadWriteOnce" ]; then
  echo "deploy/soak/cosigner-values.yaml no longer renders the live soak's StatefulSet (got: $sts / $claims)" >&2
  exit 1
fi
echo "soak: StatefulSet rutli-cosigner, ReadWriteOnce claims — unchanged"

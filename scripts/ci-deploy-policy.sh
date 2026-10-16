#!/usr/bin/env bash
# CI gate for the deployment manifests (audit C3/M3): lint and render the Helm chart in both
# topologies, check deploy/k8s is the current render, run scripts/check-deploy-policy.sh on every
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

echo "==> helm lint"
helm lint "$C" >/dev/null
for v in "$C"/ci/*.yaml; do helm lint "$C" -f "$v" >/dev/null; done
helm lint "$C" -f "$REPO/deploy/soak/cosigner-values.yaml" >/dev/null

echo "==> render"
helm template rutli "$C" -n rutli >"$OUT/pernode-default.yaml"
for v in "$C"/ci/*.yaml; do helm template rutli "$C" -n rutli -f "$v" >"$OUT/$(basename "$v" .yaml).yaml"; done
helm template rutli "$C" -n rutli -f "$REPO/deploy/soak/cosigner-values.yaml" >"$OUT/soak.yaml"
kubectl kustomize "$REPO/deploy/k8s" >"$OUT/k8s.yaml"

echo "==> deploy/k8s is the current chart render"
"$REPO/scripts/render-k8s.sh" --check

echo "==> policy: perNode renders and deploy/k8s must pass"
for f in pernode-default pernode-values pernode-migrated-soak-values k8s; do
  printf '%s: ' "$f"
  "$REPO/scripts/check-deploy-policy.sh" "$OUT/$f.yaml"
done

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

echo "==> the soak's values still render the legacy StatefulSet (no topology/PVC change on upgrade)"
sts="$(yq -N 'select(.kind == "StatefulSet") | .metadata.name' "$OUT/soak.yaml")"
claims="$(yq -N 'select(.kind == "StatefulSet") | .spec.volumeClaimTemplates[].spec.accessModes[]' "$OUT/soak.yaml")"
if [ "$sts" != "rutli-cosigner" ] || [ "$claims" != "ReadWriteOnce" ]; then
  echo "deploy/soak/cosigner-values.yaml no longer renders the live soak's StatefulSet (got: $sts / $claims)" >&2
  exit 1
fi
echo "soak: StatefulSet rutli-cosigner, ReadWriteOnce claims — unchanged"

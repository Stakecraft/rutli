#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Helm / Kubernetes metrics: kubeconform on the rendered manifests. Renders what
# scripts/ci-deploy-policy.sh renders (the chart's defaults with placeholder peer pins, every
# ci/*.yaml and the soak values) plus every tracked kustomization. Schemas come from a pinned commit of
# yannh/kubernetes-json-schema; kinds without a schema there (CRDs such as PrometheusRule) are
# skipped and counted separately. kube-linter runs its default checks on the same manifests.
# Needs helm and kubectl (for kustomize). Run by collect.sh.
set -euo pipefail
# shellcheck source=scripts/quality/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
q_init k8s
W="$Q_WORK/k8s"
R="$W/rendered"
mkdir -p "$R" "$W/cache"
K8S_VERSION=1.31.0
SCHEMAS="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/e0c72a1bc5f409d1685c0e1323460c8a98cd7459/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json"
KEYS=(k8s.kubeconform.invalid k8s.kubeconform.skipped k8s.resources k8s.kubelinter.findings)
cd "$Q_ROOT"

q_need kubeconform "${KEYS[@]}" || exit 0
q_need helm "${KEYS[@]}" || exit 0
q_need kubectl "${KEYS[@]}" || exit 0
q_tool kubeconform kubeconform -v
q_tool helm helm version --short

# render NAME ARGS...: one helm template run into $R/helm-NAME.yaml.
render() {
  local name="$1"
  shift
  helm template rutli "$@" -n rutli >"$R/helm-$name.yaml" 2>>"$W/helm.err" || failed+=("$*")
}

failed=()
for chart in deploy/helm/*/; do
  [ -f "$chart/Chart.yaml" ] || continue
  name="$(basename "$chart")"
  # Since peer pins became mandatory the bare defaults no longer render: ci/peer-pins-values.yaml is
  # the defaults plus placeholder pins (as in ci-deploy-policy.sh). Older trees render bare.
  pins="${chart}ci/peer-pins-values.yaml"
  [ -f "$pins" ] || render "$name-default" "$chart"
  for v in "$chart"ci/*.yaml; do
    [ -f "$v" ] && render "$name-$(basename "$v" .yaml)" "$chart" -f "$v"
  done
  # The soak's legacy values, as ci-deploy-policy.sh renders them (pins, profile lab) where the
  # chart has those, plain before.
  soak=deploy/soak/cosigner-values.yaml
  if [ -f "$soak" ] && [ -f "$pins" ]; then
    render "$name-soak" "$chart" -f "$soak" -f "$pins" --set profile=lab
  elif [ -f "$soak" ]; then
    render "$name-soak" "$chart" -f "$soak"
  fi
done
while read -r k; do
  d="$(dirname "$k")"
  kubectl kustomize "$d" >"$R/kustomize-${d//\//_}.yaml" 2>"$W/kustomize.err" || failed+=("$d")
done < <(q_files '*kustomization.yaml')

if [ ${#failed[@]} -gt 0 ]; then
  for k in "${KEYS[@]}"; do q_null "$k" "render failed: ${failed[*]}"; done
  exit 0
fi

if q_need kube-linter k8s.kubelinter.findings; then
  q_tool kube-linter kube-linter version
  kube-linter lint --format json "$R" >"$W/kube-linter.json" 2>"$W/kube-linter.err" || true
  # "Reports" is null, not [], when nothing is found.
  if jq -e '.Summary' "$W/kube-linter.json" >/dev/null 2>&1; then
    q_metric k8s.kubelinter.findings "$(jq '.Reports // [] | length' "$W/kube-linter.json")"
  else
    tail -5 "$W/kube-linter.err" >&2
    q_null k8s.kubelinter.findings "kube-linter failed"
  fi
fi

kubeconform -strict -ignore-missing-schemas -kubernetes-version "$K8S_VERSION" \
  -schema-location "$SCHEMAS" -cache "$W/cache" -summary -output json "$R"/*.yaml \
  >"$W/kubeconform.json" 2>"$W/kubeconform.err" || true
if ! jq -e '.summary' "$W/kubeconform.json" >/dev/null 2>&1; then
  tail -5 "$W/kubeconform.err" >&2
  for k in "${KEYS[@]::3}"; do q_null "$k" "kubeconform failed"; done
  exit 0
fi
# A schema that cannot be downloaded is an error of the run, not of the manifests.
if jq -e '[.resources[]? | select(.status == "statusError" and (.msg | test("failed downloading schema")))] | length > 0' \
  "$W/kubeconform.json" >/dev/null; then
  for k in "${KEYS[@]::3}"; do q_null "$k" "kubeconform could not download schemas"; done
  exit 0
fi
q_metric k8s.kubeconform.invalid "$(jq '.summary.invalid + .summary.errors' "$W/kubeconform.json")"
q_metric k8s.kubeconform.skipped "$(jq '.summary.skipped' "$W/kubeconform.json")"
q_metric k8s.resources "$(jq '.summary.valid + .summary.invalid + .summary.errors + .summary.skipped' "$W/kubeconform.json")"
q_info k8s.rendered "$(find "$R" -name '*.yaml' -exec basename {} \; | sort | tr '\n' ' ')"

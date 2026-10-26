#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# CI gate for the alert rules: `promtool check rules` on deploy/monitoring/prometheus-rules.yml (the
# source of truth the compose/soak stacks load) and on the rule groups of the rendered
# PrometheusRule (deploy/monitoring/k8s/prometheusrule.yaml), which must also be the current render
# of the former. Duplicate rules are fatal (--lint-fatal). Every PromQL expression of the Grafana
# dashboard (deploy/monitoring/grafana-dashboard.json) is parsed the same way, as recording rules.
#
#   scripts/ci-prometheus-rules.sh     (from anywhere; needs python3 + PyYAML, yq v4, and docker
#                                       or PROMTOOL=/path/to/promtool)
#
# promtool is the pinned prom/prometheus image (by digest) unless PROMTOOL names a binary.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
M="$REPO/deploy/monitoring"
# prom/prometheus:v3.5.0 (LTS), multi-arch index digest.
PROMTOOL_IMAGE="prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996"
OUT="$(mktemp -d "$REPO/.promtool.XXXXXX")" # under the repo: docker on macOS shares it by default
trap 'rm -rf "$OUT"' EXIT

promtool() {
  if [ -n "${PROMTOOL:-}" ]; then
    "$PROMTOOL" "$@"
  else
    docker run --rm --user "$(id -u):$(id -g)" -v "$REPO:$REPO:ro" -w "$PWD" --entrypoint promtool "$PROMTOOL_IMAGE" "$@"
  fi
}

echo "==> promtool version"
promtool --version | head -1

echo "==> promtool check rules: prometheus-rules.yml"
promtool check rules --lint=duplicate-rules --lint-fatal "$M/prometheus-rules.yml"

echo "==> k8s/prometheusrule.yaml is the current render of prometheus-rules.yml"
python3 "$M/k8s/render-prometheusrule.py" >"$OUT/rendered.yaml"
if ! diff -u "$M/k8s/prometheusrule.yaml" "$OUT/rendered.yaml"; then
  echo "deploy/monitoring/k8s/prometheusrule.yaml is stale: run" >&2
  echo "  deploy/monitoring/k8s/render-prometheusrule.py > deploy/monitoring/k8s/prometheusrule.yaml" >&2
  exit 1
fi

echo "==> promtool check rules: the PrometheusRule's groups"
kind="$(yq -N '.kind' "$M/k8s/prometheusrule.yaml")"
[ "$kind" = "PrometheusRule" ] || { echo "k8s/prometheusrule.yaml: kind is '$kind', not PrometheusRule" >&2; exit 1; }
yq '{"groups": .spec.groups}' "$M/k8s/prometheusrule.yaml" >"$OUT/prometheusrule-groups.yml"
promtool check rules --lint=duplicate-rules --lint-fatal "$OUT/prometheusrule-groups.yml"

echo "==> promtool parses every grafana-dashboard.json query"
python3 - "$M/grafana-dashboard.json" >"$OUT/dashboard-queries.yml" <<'PY'
import json, sys

def panels(ps):
    for p in ps:
        yield p
        yield from panels(p.get("panels", []))

d = json.load(open(sys.argv[1]))
rules, ids = [], set()
for p in panels(d["panels"]):
    if p["id"] in ids:
        sys.exit(f"grafana-dashboard.json: duplicate panel id {p['id']}")
    ids.add(p["id"])
    for t in p.get("targets", []):
        rules.append({"record": f"dashboard:panel{p['id']}:{t['refId']}", "expr": t["expr"]})
if not rules:
    sys.exit("grafana-dashboard.json: no queries found")
json.dump({"groups": [{"name": "grafana-dashboard", "rules": rules}]}, sys.stdout, indent=1)
PY
promtool check rules "$OUT/dashboard-queries.yml"

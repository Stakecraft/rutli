#!/usr/bin/env bash
# Deployment policy gate (audit C3): no principal and no pod spec may collapse the cosigners' trust
# domains into one. Reads rendered Kubernetes manifests (multi-document YAML) and fails on:
#
#   1. RBAC that grants pods/exec, pods/attach, pods/* or * — exec into a cosigner hands over its
#      environment, its files and its process memory; a Role that can do it on every cosigner is
#      every share at once (the removed backup CronJob's Role was exactly that).
#   2. A container env var RUTLI_SEAL_SECRET, or any env/envFrom sourced from a seal Secret — the
#      shared seal master derives every node's DEK, and an env var is readable through exec and
#      /proc/<pid>/environ.
#   3. A pod spec that references more than one seal Secret, or more than one cosigner TLS Secret —
#      every kubelet that runs the pod may read, and materialises, everything its spec names.
#   4. A seal Secret mounted into any container other than `cosigner` (e.g. a backup sidecar), or a
#      cosigner TLS Secret mounted into one (the backup sidecar ships sealed key files and sign
#      journals; it never needs the node's TLS key).
#   5. A container other than `cosigner` that mounts a cosigner's `data` volume writable — the
#      backup sidecar reads it, it never writes it.
#
#   scripts/check-deploy-policy.sh FILE...            (FILE '-' = stdin)
#   helm template rutli deploy/helm/rutli-cosigner -f deploy/helm/rutli-cosigner/ci/pernode-values.yaml \
#     | scripts/check-deploy-policy.sh -
#
# Secrets are recognised by name: seal Secrets match $SEAL_SECRET_REGEX (default ^rutli-seal), node
# TLS Secrets match $TLS_SECRET_REGEX (default ^rutli-cosigner-tls). Requires yq (mikefarah v4) and
# jq. Exit 0 = clean, 1 = violations (listed), 2 = usage/tooling error.
set -euo pipefail

SEAL_SECRET_REGEX="${SEAL_SECRET_REGEX:-^rutli-seal}"
TLS_SECRET_REGEX="${TLS_SECRET_REGEX:-^rutli-cosigner-tls}"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 FILE... (rendered manifests; - for stdin)" >&2
  exit 2
fi
for tool in yq jq; do
  command -v "$tool" >/dev/null || { echo "$0: $tool is required" >&2; exit 2; }
done

docs="$(for f in "$@"; do
  if [ "$f" = - ]; then yq -o=json -I=0 '.' -; else yq -o=json -I=0 '.' "$f"; fi
done)"

violations="$(jq -rs --arg seal "$SEAL_SECRET_REGEX" --arg tls "$TLS_SECRET_REGEX" '
  def podspec:
    if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
    elif (.kind | IN("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"))
      then .spec.template.spec
    elif .kind == "Pod" then .spec
    else null end;
  def what: "\(.kind)/\(.metadata.name // "?")";
  def containers($ps): ($ps.containers // []) + ($ps.initContainers // []) + ($ps.ephemeralContainers // []);
  # Every Secret a volume brings in: [volume name, secret name].
  def volsecrets($ps):
    ($ps.volumes // [])[] as $v
    | ( ($v.secret.secretName // empty), (($v.projected.sources // [])[] | .secret.name // empty) )
    | [$v.name, .];
  # Every Secret a container env brings in.
  def envsecrets($ps):
    containers($ps)[]
    | ( ((.env // [])[] | .valueFrom.secretKeyRef.name // empty),
        ((.envFrom // [])[] | .secretRef.name // empty) );

  [ .[] | select(. != null) ] as $docs
  | [
      # 1. exec/attach RBAC
      ( $docs[] | select(.kind == "Role" or .kind == "ClusterRole") | . as $r
        | (.rules // [])[]
        | select((.resources // []) | any(. == "pods/exec" or . == "pods/attach" or . == "pods/*" or . == "*"))
        | "\($r | what): grants \(.resources | join(",")) (verbs \(.verbs // [] | join(","))) — no principal may exec into or attach to cosigner pods" ),

      ( $docs[] | (podspec) as $ps | select($ps != null) | what as $w
        # 2. seal material through the environment
        | ( containers($ps)[] | . as $c | (.env // [])[] | select(.name == "RUTLI_SEAL_SECRET")
            | "\($w): container \($c.name) has env RUTLI_SEAL_SECRET — the shared seal master (use a per-node seal bundle file)" ),
          ( envsecrets($ps) | select(test($seal))
            | "\($w): seal Secret \(.) is exposed through a container environment" ),
        # 3. more than one node'"'"'s secrets in one pod spec
          ( ([volsecrets($ps)[1], envsecrets($ps)] | map(select(test($seal))) | unique) as $s
            | select(($s | length) > 1)
            | "\($w): pod spec references \($s | length) seal Secrets (\($s | join(", "))) — at most one node'"'"'s" ),
          ( ([volsecrets($ps)[1]] | map(select(test($tls))) | unique) as $t
            | select(($t | length) > 1)
            | "\($w): pod spec references \($t | length) cosigner TLS Secrets (\($t | join(", "))) — at most one node'"'"'s" ),
        # 4. seal Secret (and node TLS Secret) only in the cosigner container
          ( [volsecrets($ps) | select(.[1] | test($seal)) | .[0]] as $sealvols
            | containers($ps)[] | select(.name != "cosigner") | . as $c
            | (.volumeMounts // [])[] | select(.name as $n | $sealvols | index($n))
            | "\($w): container \($c.name) mounts seal volume \(.name) — only the cosigner container may" ),
          ( [volsecrets($ps) | select(.[1] | test($tls)) | .[0]] as $tlsvols
            | containers($ps)[] | select(.name != "cosigner") | . as $c
            | (.volumeMounts // [])[] | select(.name as $n | $tlsvols | index($n))
            | "\($w): container \($c.name) mounts the cosigner TLS volume \(.name) — only the cosigner container may" ),
        # 5. the data volume is read-only for everything but the cosigner
          ( containers($ps)[] | select(.name != "cosigner") | . as $c
            | (.volumeMounts // [])[] | select(.name == "data" and (.readOnly // false) != true)
            | "\($w): container \($c.name) mounts the data volume writable — only the cosigner container may write it" )
      )
    ]
  | unique | .[]
' <<<"$docs")"

if [ -n "$violations" ]; then
  echo "deploy policy: FAILED" >&2
  while IFS= read -r v; do echo "  - $v" >&2; done <<<"$violations"
  exit 1
fi
echo "deploy policy: OK ($(jq -s 'map(select(. != null)) | length' <<<"$docs") documents)"

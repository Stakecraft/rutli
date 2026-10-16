{{/*
Copyright 2026 StakeCraft
SPDX-License-Identifier: Apache-2.0
*/}}
{{- define "rutli-cosigner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "rutli-cosigner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "rutli-cosigner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "rutli-cosigner.labels" -}}
helm.sh/chart: {{ include "rutli-cosigner.chart" . }}
{{ include "rutli-cosigner.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: rutli
{{- end }}

{{- define "rutli-cosigner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rutli-cosigner.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "rutli-cosigner.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
{{- end }}

{{/* The validated topology: "legacy" or "perNode". Every template branches on this. */}}
{{- define "rutli-cosigner.topology" -}}
{{- $t := .Values.topology | default "perNode" }}
{{- if eq $t "legacyStatefulSet" }}{{ $t = "legacy" }}{{ end }}
{{- if not (has $t (list "legacy" "perNode")) }}
{{- fail (printf "topology must be legacy or perNode, got %q" $t) }}
{{- end }}
{{- if eq (toString .Values.backup.mode) "exec" }}
{{- fail "backup.mode=exec was removed: the exec-based backup CronJob could exec into every cosigner and read every node's seal secret (audit C3). Use topology=perNode with backup.enabled=true (a per-node sidecar)." }}
{{- end }}
{{- if and (eq $t "legacy") .Values.backup.enabled }}
{{- fail "backup.enabled needs topology=perNode: the exec-based backup CronJob was removed (audit C3) and the backup sidecar is per node. Migrate first (docs/runbook-per-node-seal.md)." }}
{{- end }}
{{- $t }}
{{- end }}

{{/*
topology=perNode: the roster as a JSON list of nodes with every default filled in. Use as
  {{- $nodes := include "rutli-cosigner.nodes" . | fromJsonArray }}
(numbers come back as float64 — wrap in int).
*/}}
{{- define "rutli-cosigner.nodes" -}}
{{- $fullname := include "rutli-cosigner.fullname" . }}
{{- $src := .Values.nodes }}
{{- if not $src }}
{{- $src = list }}
{{- range $i := until (int .Values.replicaCount) }}{{ $src = append $src (dict "id" (add $i 1)) }}{{ end }}
{{- else if ne (len $src) (int .Values.replicaCount) }}
{{- fail (printf "nodes has %d entries but replicaCount is %d — set both" (len $src) (int .Values.replicaCount)) }}
{{- end }}
{{- $out := list }}
{{- $seen := dict }}
{{- range $n := $src }}
{{- $id := int $n.id }}
{{- if lt $id 1 }}{{ fail "nodes[].id must be ≥ 1" }}{{ end }}
{{- if hasKey $seen (toString $id) }}{{ fail (printf "nodes: id %d is listed twice" $id) }}{{ end }}
{{- $_ := set $seen (toString $id) true }}
{{- $out = append $out (dict
      "id" $id
      "existingClaim" ($n.existingClaim | default "")
      "dataClaim" ($n.existingClaim | default (printf "data-%s-n%d" $fullname $id))
      "sealSecret" ($n.sealSecret | default (printf "%s%d" $.Values.seal.perNodeSecretPrefix $id))
      "tlsSecret" ($n.tlsSecret | default (printf "%s%d" $.Values.tls.perNodeSecretPrefix $id))
      "distPublicKey" ($n.distPublicKey | default "")
      "backupClaim" ($n.backupClaim | default "")
      "backupSecret" ($n.backupSecret | default "")
      "service" (printf "%s%d" $.Values.perNode.servicePrefix $id)) }}
{{- end }}
{{- $out | toJson }}
{{- end }}

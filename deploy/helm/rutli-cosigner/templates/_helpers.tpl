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

{{/*
Backup Job identity. Deliberately NOT the cosigner selector labels: the backup pod must never be
adopted by the StatefulSet or admitted by the cosigner NetworkPolicies.
*/}}
{{- define "rutli-cosigner.backup.name" -}}
{{- printf "%s-backup" (include "rutli-cosigner.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "rutli-cosigner.backup.labels" -}}
helm.sh/chart: {{ include "rutli-cosigner.chart" . }}
app.kubernetes.io/name: {{ include "rutli-cosigner.name" . }}-backup
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backup
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: rutli
{{- end }}

{{/* The cosigner pod names, <fullname>-0 … <fullname>-(replicaCount-1), as a YAML flow list. */}}
{{- define "rutli-cosigner.podNames" -}}
{{- $fullname := include "rutli-cosigner.fullname" . }}
{{- $names := list }}
{{- range $i := until (int .Values.replicaCount) }}{{ $names = append $names (printf "%s-%d" $fullname $i) }}{{ end }}
{{- $names | toJson }}
{{- end }}

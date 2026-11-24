{{/*
Copyright 2026 StakeCraft LLC
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

{{/* perNode: how a changed pod template reaches the pods. OnDelete (default) or RollingUpdate. */}}
{{- define "rutli-cosigner.updateStrategy" -}}
{{- $t := .Values.updateStrategy.type | default "OnDelete" }}
{{- if not (has $t (list "OnDelete" "RollingUpdate")) }}
{{- fail (printf "updateStrategy.type must be OnDelete or RollingUpdate, got %q" $t) }}
{{- end }}
{{- $t }}
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

{{/*
The peer pins (values.peerPins) for the roster ids in .ids, validated, as JSON: {"<id>": [hex...]}.
Use as
  {{- $pins := include "rutli-cosigner.peerPins" (dict "root" . "ids" $ids) | fromJson }}
Fails on a node with no pins while tls.requirePeerPins is not false, an id outside the roster, a
value that is not 64 hex, more than two values, or one value under two nodes.
*/}}
{{- define "rutli-cosigner.peerPins" -}}
{{- $root := .root }}
{{- $src := $root.Values.peerPins | default dict }}
{{- $required := ne (toString $root.Values.tls.requirePeerPins) "false" }}
{{- $roster := dict }}
{{- range $id := .ids }}{{ $_ := set $roster (toString (int $id)) true }}{{ end }}
{{- range $k, $_ := $src }}
  {{- if not (hasKey $roster (toString $k)) }}
    {{- fail (printf "peerPins.%q names no node of the roster (ids %s)" (toString $k) (keys $roster | sortAlpha | join ", ")) }}
  {{- end }}
{{- end }}
{{- $out := dict }}
{{- $owner := dict }}
{{- range $id := .ids }}
  {{- $key := toString (int $id) }}
  {{- $list := index $src $key }}
  {{- if not $list }}
    {{- if $required }}
      {{- fail (printf "peerPins.%q is missing: pin every cosigner's TLS key (rutli-cosigner tls spki cosigner%s.crt, or -f certs/peer-pins.json from scripts/gen-frost-certs.sh), or set tls.requirePeerPins: false" $key $key) }}
    {{- end }}
  {{- else }}
    {{- if not (kindIs "slice" $list) }}
      {{- fail (printf "peerPins.%q must be a list of one or two SHA-256 hex values" $key) }}
    {{- end }}
    {{- if gt (len $list) 2 }}
      {{- fail (printf "peerPins.%q lists %d keys — at most 2: the current key and, during a key roll, the next" $key (len $list)) }}
    {{- end }}
    {{- $clean := list }}
    {{- range $pin := $list }}
      {{- $pin = toString $pin | lower }}
      {{- if not (regexMatch "^[0-9a-f]{64}$" $pin) }}
        {{- fail (printf "peerPins.%q: %q is not 64 hex characters (the SHA-256 of the certificate's SubjectPublicKeyInfo)" $key $pin) }}
      {{- end }}
      {{- if hasKey $owner $pin }}
        {{- fail (printf "peerPins.%q pins %s, which peerPins.%q pins too — one TLS key cannot be two nodes" $key $pin (get $owner $pin)) }}
      {{- end }}
      {{- $_ := set $owner $pin $key }}
      {{- $clean = append $clean $pin }}
    {{- end }}
    {{- $_ := set $out $key $clean }}
  {{- end }}
{{- end }}
{{- $out | toJson }}
{{- end }}

{{/*
The `peer_deadlines` config object from .Values.peerDeadlines (call only when it is non-empty).
Fails the render on an unknown key or a value outside the bounds the cosigner enforces at startup.
*/}}
{{- define "rutli-cosigner.peerDeadlines" -}}
{{- $pd := .Values.peerDeadlines }}
{{- if not (kindIs "map" $pd) }}
{{- fail (printf "peerDeadlines must be a map (signRound1Ms, signRound2Ms), got %s" (kindOf $pd)) }}
{{- end }}
{{- range $k, $_ := $pd }}
{{- if not (has $k (list "signRound1Ms" "signRound2Ms")) }}
{{- fail (printf "peerDeadlines.%s is not a known key (signRound1Ms, signRound2Ms)" $k) }}
{{- end }}
{{- end }}
{{- $specs := list
  (dict "key" "signRound1Ms" "json" "sign_round1_ms" "min" 500 "max" 5000)
  (dict "key" "signRound2Ms" "json" "sign_round2_ms" "min" 1000 "max" 9000) }}
{{- $parts := list }}
{{- range $s := $specs }}
{{- if hasKey $pd $s.key }}
{{- $raw := index $pd $s.key }}
{{- if not (has (kindOf $raw) (list "int" "int64" "float64")) }}
{{- fail (printf "peerDeadlines.%s must be an integer between %d and %d, got %#v" $s.key $s.min $s.max $raw) }}
{{- end }}
{{- $v := int64 $raw }}
{{- if or (ne (float64 $v) (float64 $raw)) (lt $v (int64 $s.min)) (gt $v (int64 $s.max)) }}
{{- fail (printf "peerDeadlines.%s must be an integer between %d and %d, got %#v" $s.key $s.min $s.max $raw) }}
{{- end }}
{{- $parts = append $parts (printf "\"%s\": %d" $s.json $v) }}
{{- end }}
{{- end }}
{{- printf "{ %s }" (join ", " $parts) }}
{{- end }}

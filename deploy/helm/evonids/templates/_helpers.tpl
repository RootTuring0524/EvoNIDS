{{/*
EvoNIDS chart helpers. Copyright © EvoNIDS project contributors.
SPDX-License-Identifier: Apache-2.0
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "evonids.name" -}}
{{- default .Chart.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "evonids.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Chart label (name-version).
*/}}
{{- define "evonids.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Selector labels shared by every workload (stable across components).
*/}}
{{- define "evonids.selectorLabels" -}}
app.kubernetes.io/name: {{ include "evonids.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component selector labels. Usage:
  {{- include "evonids.componentSelectorLabels" (dict "ctx" $ "component" "api") }}
*/}}
{{- define "evonids.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "evonids.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Standard full labels for chart-owned objects.
*/}}
{{- define "evonids.labels" -}}
helm.sh/chart: {{ include "evonids.chart" . }}
{{ include "evonids.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Component labels (chart labels + component). Usage like componentSelectorLabels.
*/}}
{{- define "evonids.componentLabels" -}}
{{ include "evonids.chart" .ctx }}
{{ include "evonids.componentSelectorLabels" . }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
{{- end }}

{{/*
Resource names per component.
*/}}
{{- define "evonids.apiFullname" -}}
{{ printf "%s-api" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "evonids.webFullname" -}}
{{ printf "%s-web" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "evonids.postgresFullname" -}}
{{ printf "%s-postgres" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "evonids.migrationFullname" -}}
{{ printf "%s-migration" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "evonids.dataVolumeFullname" -}}
{{ printf "%s-data" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "evonids.postgresPvcFullname" -}}
{{ printf "%s-postgres" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
ConfigMap / Secret names consumed by every workload. When
secrets.existingSecret is set, all secretKeyRefs point at that name.
*/}}
{{- define "evonids.configName" -}}
{{ printf "%s-config" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "evonids.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secret" (include "evonids.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Image references.
*/}}
{{- define "evonids.apiImage" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.apiRepository .Values.image.tag }}
{{- end }}
{{- define "evonids.webImage" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.webRepository .Values.image.tag }}
{{- end }}
{{- define "evonids.postgresImage" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.postgresRepository .Values.image.postgresTag }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "evonids.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "evonids.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Namespace name used by the optional Namespace object and by nothing else
(all chart resources use .Release.Namespace).
*/}}
{{- define "evonids.namespaceName" -}}
{{- default .Release.Namespace .Values.namespace.name }}
{{- end }}

{{/*
Runtime URL of the api service (used by NUXT_BACKEND_API_BASE).
*/}}
{{- define "evonids.apiBackendBase" -}}
{{- printf "http://%s:%d/api/v1" (include "evonids.apiFullname" .) (int .Values.api.service.port) }}
{{- end }}

{{/*
Checksum of the rendered ConfigMap — pod template annotations use it so that
any values change rolls Deployments/StatefulSets.
*/}}
{{- define "evonids.configChecksum" -}}
{{- include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end }}

{{/*
Checksum of the rendered Secret (only a digest — never a secret value).
*/}}
{{- define "evonids.secretChecksum" -}}
{{- include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
{{- end }}

{{/*
Expand the name of the chart.
*/}}
{{- define "dns-deception.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "dns-deception.fullname" -}}
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

{{/*
Common labels.
*/}}
{{- define "dns-deception.labels" -}}
helm.sh/chart: {{ include "dns-deception.name" . }}-{{ .Chart.Version }}
{{ include "dns-deception.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Format domain configs as zone=upstream,zone=upstream.
*/}}
{{- define "dns-deception.domains" -}}
{{- range $i, $d := .Values.dns.domains }}{{ if $i }},{{ end }}{{ $d.zone }}{{ if $d.upstream }}={{ $d.upstream }}{{ end }}{{- end }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "dns-deception.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dns-deception.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

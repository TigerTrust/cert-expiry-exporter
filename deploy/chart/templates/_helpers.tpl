{{- define "cert-expiry-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "cert-expiry-exporter.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{- define "cert-expiry-exporter.labels" -}}
app.kubernetes.io/name: {{ include "cert-expiry-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: tigertrust
{{- end }}

{{- define "cert-expiry-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cert-expiry-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

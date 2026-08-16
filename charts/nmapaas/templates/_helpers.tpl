{{- define "nmapaas.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nmapaas.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "nmapaas.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nmapaas.labels" -}}
app.kubernetes.io/name: {{ include "nmapaas.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "nmapaas.apiSecret" -}}
{{- default (printf "%s-api" (include "nmapaas.fullname" .)) .Values.auth.existingSecret -}}
{{- end -}}

{{- define "nmapaas.vpnSecret" -}}
{{- default (printf "%s-vpn" (include "nmapaas.fullname" .)) .Values.vpn.existingSecret -}}
{{- end -}}

{{- define "nmapaas.locations" -}}
{{- range $index, $location := .Values.locations }}{{ if $index }},{{ end }}{{ $location.name }}{{ if $location.subnet }}:{{ $location.subnet }}{{ end }}{{ end -}}
{{- end -}}

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

{{- define "nmapaas.piaSecret" -}}
{{- default (printf "%s-pia" (include "nmapaas.fullname" .)) .Values.pia.existingSecret -}}
{{- end -}}

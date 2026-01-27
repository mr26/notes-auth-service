{{- define "auth-gateway.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "auth-gateway.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

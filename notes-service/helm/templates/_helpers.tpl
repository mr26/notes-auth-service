{{- define "notes-service.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "notes-service.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}


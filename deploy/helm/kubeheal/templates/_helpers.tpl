{{/* images.* may be a bare repository (tag defaults to the chart's appVersion) or a full reference (tag or digest kept). */}}
{{- define "kubeheal.image" -}}
{{- $root := index . 0 -}}{{- $ref := index . 1 -}}
{{- if regexMatch "(:[^/]+|@.+)$" $ref }}{{ $ref }}{{ else }}{{ $ref }}:{{ $root.Chart.AppVersion }}{{ end -}}
{{- end -}}

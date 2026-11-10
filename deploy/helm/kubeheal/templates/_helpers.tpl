{{/* Namespace every namespaced KubeHeal object lives in. */}}
{{- define "kubeheal.namespace" -}}
{{- .Values.namespace -}}
{{- end -}}

{{/* Protected namespaces, fixed by the RBAC design (RoleBindings and EXEC_NAMESPACES). */}}
{{- define "kubeheal.tiers" -}}
prod staging dev
{{- end -}}

{{/* Image reference. Args: dict "root" $ "image" <map with repository, optional tag>. */}}
{{- define "kubeheal.image" -}}
{{- $g := .root.Values.global -}}
{{- printf "%s%s:%s" $g.imageRegistry .image.repository (default $g.imageTag .image.tag) -}}
{{- end -}}

{{/* imagePullSecrets block (pod spec level). */}}
{{- define "kubeheal.pullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end }}
{{- end -}}

{{/* resources block, only when the values are set (no defaults on purpose). Arg: the resources map. */}}
{{- define "kubeheal.resources" -}}
{{- if . }}
resources:
{{ toYaml . | indent 2 }}
{{- end }}
{{- end -}}

{{/*
Redis connection env. REDIS_URL carries the password through the variable the components already read,
so no agent code changes: Kubernetes expands $(REDIS_PASSWORD) because it is declared first.
*/}}
{{- define "kubeheal.redisEnv" -}}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.auth.existingSecret }}
      key: {{ .Values.redis.auth.key }}
- name: REDIS_URL
  value: "redis://:$(REDIS_PASSWORD)@{{ .Values.redis.serviceName }}:6379"
{{- end -}}

{{/* MinIO client credentials env (ledger writers). Arg: optional flag "optional" => secret refs optional. */}}
{{- define "kubeheal.minioClientEnv" -}}
{{- $opt := .optional | default false -}}
- name: MINIO_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.minio.clientSecret }}
      key: access-key
{{- if $opt }}
      optional: true
{{- end }}
- name: MINIO_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.minio.clientSecret }}
      key: secret-key
{{- if $opt }}
      optional: true
{{- end }}
{{- end -}}

{{/* extraEnv map rendered as env entries. */}}
{{- define "kubeheal.extraEnv" -}}
{{- range $k, $v := . }}
- name: {{ $k }}
  value: {{ $v | toString | quote }}
{{- end }}
{{- end -}}

{{/* Prometheus scrape annotations. Arg: dict "port" <int>. */}}
{{- define "kubeheal.scrapeAnnotations" -}}
prometheus.io/scrape: "true"
prometheus.io/path: /metrics
prometheus.io/port: {{ .port | quote }}
{{- end -}}

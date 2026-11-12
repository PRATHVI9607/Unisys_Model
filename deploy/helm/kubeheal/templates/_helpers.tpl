{{/* Namespace every namespaced KubeHeal object lives in. */}}
{{- define "kubeheal.namespace" -}}
{{- .Values.namespace -}}
{{- end -}}

{{/* Protected namespaces, fixed by the RBAC design (RoleBindings and EXEC_NAMESPACES). */}}
{{- define "kubeheal.tiers" -}}
prod staging dev
{{- end -}}

{{/* NAMESPACE_TIER_MAP value ("ns=tier,ns2=tier2", sorted by namespace) from .Values.namespaceTierMap; empty when unset.
     Read by the Health and Security agents (agents/common/tiers.py); a namespace in no tier stays "unknown". */}}
{{- define "kubeheal.tierMap" -}}
{{- $pairs := list -}}
{{- range $ns, $tier := (.Values.namespaceTierMap | default dict) -}}
{{- $pairs = append $pairs (printf "%s=%s" $ns $tier) -}}
{{- end -}}
{{- join "," $pairs -}}
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

{{/* Dedicated containment HMAC key, separate from the Redis credential. */}}
{{- define "kubeheal.containmentHmacEnv" -}}
- name: CONTAIN_HMAC_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.containment.hmacSecret.name }}
      key: {{ .Values.containment.hmacSecret.key }}
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

{{/*
Container securityContext: the global baseline plus the optional per-component hardening switches
(off by default, must be verified on k3d before use). Arg: dict "root" $ "h" <hardening map or nil>.
*/}}
{{- define "kubeheal.ctx" -}}
{{- $base := deepCopy .root.Values.global.containerSecurityContext -}}
{{- if .h -}}
{{- if .h.runAsNonRoot -}}
{{- $_ := set $base "runAsNonRoot" true -}}
{{- with .h.runAsUser }}{{- $_ := set $base "runAsUser" . -}}{{- end -}}
{{- end -}}
{{- if .h.readOnlyRootFilesystem -}}
{{- $_ := set $base "readOnlyRootFilesystem" true -}}
{{- end -}}
{{- end -}}
{{ toYaml $base }}
{{- end -}}

{{/* /tmp emptyDir, only when the root filesystem is read-only. Arg: the hardening map or nil. */}}
{{- define "kubeheal.tmpMount" -}}
{{- if . }}{{- if .readOnlyRootFilesystem }}
volumeMounts:
  - {name: tmp, mountPath: /tmp}
{{- end }}{{- end }}
{{- end -}}
{{- define "kubeheal.tmpVolume" -}}
{{- if . }}{{- if .readOnlyRootFilesystem }}
volumes:
  - name: tmp
    emptyDir: {}
{{- end }}{{- end }}
{{- end -}}

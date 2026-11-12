# KubeHeal Helm chart

Installs the KubeHeal control plane (health agent, security agent DaemonSet, fusion agent, Executor,
dashboard, the inference service (the three legacy neural model servers are optional), Redis, the MinIO ledger store, the kill switch, platform policy). It
replaces `scripts/install.sh`, which stays in the repo for reference. Nothing here has been installed on a
cluster yet: `helm lint` and `helm template` pass and the tests in `tests/test_platform_*.py` check the
rendered objects. Cluster behaviour is checked on k3d in P10.

## Install

```
helm install kubeheal deploy/helm/kubeheal -n kubeheal --create-namespace \
    -f deploy/helm/kubeheal/values-<env>.yaml -f <your owner values>
```

`<env>` is `dev`, `staging`, `prod` or `k3d-demo`. `values-k3d-demo.yaml` is complete on its own (its numbers
are labelled demo choices). dev, staging and prod are not: see the next section.

## Values every owner must supply

These are owner decisions, not defaults. `values-dev/staging/prod.yaml` leave them unset on purpose, so
`helm template` fails with a message naming the key ("is required ... owner decision") until they are given:

- `namespaces.quotas.<prod|staging|dev>.hard` (ResourceQuota `spec.hard`) and `.limits` (LimitRange `spec.limits`)
- `redis.persistence.size`

`values-lab-example.yaml` shows the shape for the private lab cluster of the synopsis (3 nodes, 4 cores and 8 GB
each). It is an example, not a recommendation: every number in it is labelled "chosen configuration for the lab
cluster, not measured". Real owners supply their own values:

```
helm template kubeheal deploy/helm/kubeheal -f deploy/helm/kubeheal/values-prod.yaml \
    -f deploy/helm/kubeheal/values-lab-example.yaml
```

CPU and memory requests and limits are unset by default. Measure them with `eval/resource_profile.py` (Prometheus
or metrics-server, run against the cluster under the load you size for), then merge the values snippet it writes.

## Secrets that must exist first

None of them is created by the chart (no secret value is ever in a values file), except the Redis one when
`redis.auth.password` is passed at install time.

| Secret | Keys | Used by |
|---|---|---|
| `kubeheal-dashboard-admin` | `token` | dashboard, as `KUBEHEAL_ADMIN_TOKEN`. The pod does not start without it. With a blank token every mutating endpoint answers 503. |
| `kubeheal-redis` | `password` | Redis `--requirepass` and every component, through `REDIS_URL=redis://:$(REDIS_PASSWORD)@redis-master:6379`. Use a URL-safe password. |
| `kubeheal-minio-root` | `root-user`, `root-password` | MinIO and the bootstrap Job (`scripts/minio_secret.ps1`) |
| `kubeheal-minio-client` | `access-key`, `secret-key` | ledger writers: fusion agent, Executor, dashboard, model servers (registry download) |

Example: `kubectl -n kubeheal create secret generic kubeheal-dashboard-admin --from-literal=token=<token>`.

## Namespace and RBAC

- The release namespace `kubeheal` is not templated. Create it with `--create-namespace` (or set
  `namespaces.createReleaseNamespace=true` for a `helm template | kubectl apply` flow). The chart does create
  `prod`, `staging` and `dev` (label `kubeheal/tier`) unless `namespaces.create=false`.
- RBAC (ServiceAccounts, ClusterRoles, Roles, bindings, kill switch roles) is rendered by the chart from the same
  rules as `k8s/rbac/rbac.yaml` and `k8s/kill-switch.yaml`; `tests/test_platform_chart.py` fails if they diverge.
  Do not apply both. If you apply the plain manifests instead, install with `--set rbac.create=false
  --set namespaces.create=false`.
- A cluster where `k8s/rbac/rbac.yaml`, `k8s/kill-switch.yaml` or `k8s/minio.yaml` were applied with kubectl
  collides with Helm on object ownership. Use a fresh cluster or remove those objects first.
- The kill switch ConfigMap `kubeheal-mode` is rendered with `killSwitch.mode: test` (dry run). There is no
  other toggle for the ConfigMap itself.

## Executor settings (fail closed)

The Executor needs `PROMETHEUS_URL`, `SNAPSHOT_CLASS`, `CANARY_WINDOW_S`, `ROLLOUT_TIMEOUT_S` and
`ROLLOUT_POLL_S`. The chart always renders all of them (the five P7 settings and `CONTAIN_FREEZE_TIMEOUT_S`) from `executor.env`, with the owner's chosen defaults (chosen,
not measured; `tests` compare them with `agents/executor/config.py` DEFAULTS). Override any of them with
`--set executor.env.NAME=value`. Overriding one to an empty string still renders it, and the Executor then
escalates to a human before it writes anything, instead of guessing. `SNAPSHOT_CLASS` names a VolumeSnapshotClass
that must exist in the cluster (P10 creates `csi-hostpath-snapclass` on k3d).

## Inference service (V5-I2, default scorer)

- `inference.enabled` (default true) renders `templates/inference.yaml`: one Deployment `kubeheal-inference` (port 8000,
  image `kubeheal/inference-server:v5` from `dockerfiles/Dockerfile.inference`), a Service, a PodDisruptionBudget and one
  HPA. It serves the two LightGBM bundles shipped in the image (`models/bundles`): `POST /v1/health/predict`,
  `/v1/security/predict` and the `_batch` variants. Liveness is `/healthz`, readiness `/readyz` (200 only when BOTH
  bundles are loaded); a missing or invalid bundle answers 503, never a fallback model.
- The HPA uses the same `hpa.mode` and targets as the model servers below (queue-depth gauge
  `kubeheal_model_inflight_requests`, so the prometheus-adapter rule is unchanged), bounds from `inference.hpa`.
- The health and security agents get `INFERENCE_URL` and score only through the inference service (V5-D4, V5-S2);
  they no longer read `HEALTH_MODEL_URL` or `SECURITY_MODEL_URL`, and the chart no longer sets those or `DCM_URL`
  (a set `DCM_URL` would switch Fusion onto the legacy DCM path). With the inference service down they fail closed
  (model unavailable notice).
- Hardening is on by default for this pod (uid 10001, read-only root filesystem, emptyDir on `/tmp`). Not verified
  on a cluster yet. `inference.modelDir` sets `KUBEHEAL_MODEL_DIR` (empty: the shipped bundles).
- NetworkPolicy: only the health and security agents and Prometheus reach it.

## Model servers (legacy neural servers)

The Health, Security and DCM neural servers are LEGACY and render only with `modelServers.legacy.enabled=true`
(default false). Nothing was deleted: code, images and templates are still in the repo.

- 2 replicas, PodDisruptionBudget `minAvailable: 1`, topology spread (hard in `values-prod.yaml`, soft elsewhere).
- Autoscaling `hpa.mode`: `queue` (default, min 2, max 8) uses the per-pod gauge
  `kubeheal_model_inflight_requests`, exported by each server (scoring requests running plus waiting for a worker;
  `/health` and `/metrics` are not counted), through prometheus-adapter as a Pods metric. The target
  `hpa.queue.targetAverageValue` has a CHOSEN DEFAULT that is not a measurement; P11 tunes it. The adapter rule is in
  ConfigMap `kubeheal-prometheus-adapter-rule` and must be merged into prometheus-adapter's `rules.custom` by you.
  `latency` is a documented fallback (needs its own target) and `cpu` an even weaker one (needs CPU requests set).
  Exactly one HPA per server is rendered. No ServiceMonitor is created: ConfigMap `kubeheal-prometheus-scrape-snippet`
  has one scrape job that discovers every KubeHeal pod through its `prometheus.io/*` annotations.
- `modelServers.<name>.modelFormat` sets `MODEL_FORMAT`: `pt` (default) or `onnx`. Only the DCM serves ONNX. The
  health and security servers answer 503 if asked for it, because their ONNX export drops outputs they return. ONNX
  needs a `.onnx` file placed in the image or a mounted volume at `MODEL_ONNX_PATH` (nothing builds one into the
  image, the MinIO registry download is ignored in ONNX mode) and `onnxruntime` in the image (it is in
  `services/dcm_server/requirements.txt` but the base image does not install it yet). A missing file fails closed.

## Network, ingress and hardening

- NetworkPolicy: default-deny ingress, then allows: agents, dashboard and Prometheus to the model servers; the
  KubeHeal components to Redis and MinIO; the ingress controller namespace and Prometheus to the dashboard. This relies
  on the CNI allowing node-to-pod traffic for kubelet probes; check on k3d. Optional egress lockdown:
  `networkPolicy.egress.enabled=true` plus `networkPolicy.egress.apiServerCIDR` (DNS, API server, Redis, MinIO, model
  servers, Prometheus). Both are unverified on a cluster.
- Ingress for the dashboard: class `nginx` in the generic values, `traefik` in `values-k3d-demo.yaml`. The dashboard
  admin token travels in clear text unless the connection uses TLS: set `ingress.tls` (and `ingress.host`) everywhere
  outside the demo.
- The dashboard uses the same MinIO writer user as the other ledger writers (`kubeheal-minio-client`, policy
  `kubeheal-ledger-writer`: list, get, put). A read-only user would be tighter.
- Optional container hardening, off by default: `<component>.hardening.runAsNonRoot`, `.readOnlyRootFilesystem` and
  `.runAsUser` for the health agent, fusion agent, dashboard and the three model servers (a read-only root mounts an
  emptyDir at `/tmp`). They must be verified on k3d before use: images may write to other paths or run as root. The
  Executor already runs non-root with a read-only root filesystem (also not yet verified on a cluster).
- The security agent DaemonSet runs as root with `hostPID: true` and the `SYS_PTRACE` and `DAC_READ_SEARCH`
  capabilities by design: it reads `/proc/<pid>` of every pod. It never writes to the cluster.

## Redis

AOF is on, on a PVC (StatefulSet), with a password from a Secret. The Executor trusts every message on the
`kubeheal.exec` stream, so only Fusion and the dashboard should write to Redis. The chart does not enforce that: all
KubeHeal components share one password and the NetworkPolicy only keeps other pods out. Per-component Redis ACL
users need an audit of every key the agents use and are not done.

# Operations

This document covers how to install, demo, reset and observe KubeHeal, how to collect lab data, and
how to troubleshoot. The architecture is described in [architecture.md](architecture.md).

## Install

You need `kubectl`, `helm`, `uv`, and either `minikube` or `docker` plus a cluster your kubectl
points at. The lab measurements used an 8 CPU / 8 GB minikube with the docker driver.

```bash
minikube start --cpus=8 --memory=8g
./deploy/scripts/install.sh
```

`install.sh` is idempotent and fails loudly. It runs five steps:

1. **Build** `kubeheal.invalid/{inference,agents,dashboard,chaos}:v5` from `deploy/docker/` (see [Images](#images)). On minikube the images are built straight into the node. Otherwise they are built with docker, and you push them yourself.
2. **Add the Helm repos** `prometheus-community` and `falcosecurity`.
3. **Install the dependencies:**
   - **Prometheus:** `kube-prometheus-stack` 92.10.1 in `monitoring`, with `deploy/k8s/helm/monitoring-values.yaml`.
   - **Falco:** `falco` 9.2.0 in `falco`, with `deploy/k8s/helm/falco-values.yaml` and `--set-file customRules...=deploy/k8s/falco-kubeheal-rules.yaml`.
     The values trace only the syscalls the rule needs (`base_syscalls.custom_set`). If you add an `evt.type` to the rule, add it to `custom_set` too. Check the final set with `falco --dry-run -o log_level=debug -o log_stderr=true`.
4. **Deploy** with `kubectl apply -k deploy/k8s/` (namespace, RBAC, Redis with its credentials Job, the five components, the ServiceMonitor and the PodMonitor), then `kubectl apply -f deploy/demo/victim-app.yaml`. The victim app is podinfo with a PVC and a load generator in namespace `demo`, which has tier `prod`.
5. **Wait** for every rollout.

### Cluster guard

`install.sh`, `demo.sh`, `reset.sh`, `seed_demo.sh`, `smoke.sh`, `evaluate.py` and `training/collect/run_lab.sh` rewrite
Deployments and delete pods and namespaces. They all run `deploy/scripts/lib/guard.sh` first: it prints
`kubectl context: <name>` and refuses (exit 2) unless the current context is `minikube` or `k3d-kubeheal`.
To use another lab cluster, name its context: `--force-context NAME` (NAME must equal
`kubectl config current-context`; a different name is refused). `KUBECONFIG` is honoured as usual. The verified context is
pinned (`KH_CTX`): the scripts' `kubectl` and `helm` calls pass `--context`, so a `kubectl config use-context` in another
terminal mid-run cannot redirect them.

### k3d (local, throwaway)

```bash
./deploy/k3d/create.sh                    # cluster `kubeheal`: 1 server + 2 agents, docker containers
export KUBECONFIG=~/.kube/kubeheal-k3d.yaml   # create.sh prints the file; it never touches ~/.kube/config
./deploy/scripts/install.sh --target k3d  # docker build + `k3d image import` (no registry), then the same steps as above
./deploy/scripts/smoke.sh                 # deploy check, see below
./deploy/k3d/delete.sh
```

`create.sh` writes only to `$KUBEHEAL_K3D_KUBECONFIG`, else a single-file `$KUBECONFIG`, else
`~/.kube/kubeheal-k3d.yaml`, and passes `--kubeconfig-update-default=false --kubeconfig-switch-context=false`
to k3d, so your current context never changes. `KUBEHEAL_K3D_AGENTS=N` sets the agent count. k3s enforces
NetworkPolicy (kube-router) and bundles metrics-server. The nodes are docker containers on the host kernel, so the eBPF
sensor works when the host has BTF (`/sys/kernel/btf/vmlinux`) and `bpf` in `/sys/kernel/security/lsm`; on a
host without them use `EVENT_SOURCE=falco ./deploy/scripts/install.sh --target k3d`. Pin k3d to a release you checked
(tested: v5.8.3, k3s v1.31.5).

### Helm chart

`deploy/helm/kubeheal` renders the same objects as the kustomize install (`tests/test_helm.py` compares them for dev,
production and Falco). `values.yaml` is the single place for images, `mode`, `eventSource` (`sensor`|`falco`), resources and
the fusion limits; profiles are `values-k3d.yaml` and `values-production.yaml` (== `overlays/production`).

```bash
helm upgrade --install kubeheal deploy/helm/kubeheal -n kubeheal --create-namespace --set namespace.create=false   # dev
./deploy/scripts/install.sh --helm [--target k3d] [--production --registry HOST/PATH]   # same, plus images and the rest of install
```

The chart covers the control plane only; Prometheus and Falco stay separate Helm releases (`install.sh`). Use either
kustomize or Helm for one cluster, not both.

### Install from GHCR

Every `v*` tag publishes multi-arch (linux/amd64, linux/arm64) images `ghcr.io/prathvi9607/kubeheal-{inference,agents,dashboard,sensor,chaos}:<version>`
(`:latest` only for final releases) and the chart `oci://ghcr.io/prathvi9607/charts/kubeheal` (`.github/workflows/release.yml`;
chart `version` = `appVersion` = the tag without the `v`). The chart's default images are those, at the chart's `appVersion`.
Prometheus (and Falco, if used) stay separate releases: `install.sh` installs them; the commands below install the control plane only.

```bash
helm install kubeheal oci://ghcr.io/prathvi9607/charts/kubeheal --version 1.0.0 -n kubeheal --create-namespace --set namespace.create=false
```

Images, SBOMs and provenance are signed/attested keylessly (GitHub OIDC, Sigstore). Verify before you install:

```bash
ID='^https://github.com/PRATHVI9607/Unisys_Model/\.github/workflows/release\.yml@refs/tags/v1\.0\.0$'
ISSUER=https://token.actions.githubusercontent.com
for n in inference agents dashboard sensor chaos; do
  cosign verify --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" ghcr.io/prathvi9607/kubeheal-$n:1.0.0 >/dev/null && echo "ok $n"
done
cosign verify --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" ghcr.io/prathvi9607/charts/kubeheal:1.0.0 >/dev/null && echo "ok chart"
docker buildx imagetools inspect ghcr.io/prathvi9607/kubeheal-sensor:1.0.0 --format '{{json .SBOM}}'   # SBOM (provenance: .Provenance)
```

Dev installs keep the locally built `kubeheal.invalid/*` images through `values-dev.yaml` (`install.sh --helm` adds it).

### Platforms

All images are built for linux/amd64 and linux/arm64 (AWS Graviton, Ampere, Apple-silicon k3d). Python wheels for
every locked dependency exist for aarch64 (checked in `uv.lock`, cp313 manylinux); base images are pinned by multi-arch index digest.

- Build: `docker buildx build --platform linux/amd64,linux/arm64 -f deploy/docker/Dockerfile.<name> .` (arm64 Python stages need
  QEMU on an amd64 builder: `docker run --privileged --rm tonistiigi/binfmt --install arm64`). The sensor image cross-compiles on the
  builder's own arch (no QEMU for the Rust/clang build). `install.sh --production` builds and pushes multi-arch (`--platform`
  overrides); dev installs build the host arch only (`--platform linux/arm64` for one other platform).
- Event source: the eBPF sensor needs the kernel features below; without them use Falco (`EVENT_SOURCE=falco`; `install.sh --target k3d`
  switches by itself when the host kernel lacks BTF or the bpf LSM). Check a node: `ls /sys/kernel/btf/vmlinux; cat /sys/kernel/security/lsm`.

| Kernel need | Why | Without it |
|---|---|---|
| BTF (`CONFIG_DEBUG_INFO_BTF`, `/sys/kernel/btf/vmlinux`) | CO-RE relocation of the kernel structs | sensor does not start; Falco's modern eBPF also needs BTF |
| >= 5.17 | `bpf_loop` for the path walk | sensor does not start |
| `CONFIG_BPF_LSM=y` and `bpf` in the active LSMs (`lsm=...,bpf` boot parameter) | `lsm/` hooks, immune to inlining | the sensor falls back per hook to `fexit/`, blind where the kernel inlined the `security_*` function (startup log `hooks ... =fexit`, or a WARNING) |
| BPF trampolines (arm64 >= 6.0; x86_64 always) | `lsm/` and `fexit/` attach through them | on arm64 below 6.0 the sensor cannot attach: use Falco |

Managed Kubernetes node images (all **unverified**: from memory of vendor kernel configs, not tested here; always check a node as above):

| Platform | BTF | CONFIG_BPF_LSM | `bpf` in default `lsm=` |
|---|---|---|---|
| EKS, Amazon Linux 2023 (x86_64 and Graviton, kernel 6.1/6.12) | expected yes | expected yes | expected no: needs a boot parameter |
| GKE, Container-Optimized OS | expected yes | unknown | unknown |
| GKE / AKS, Ubuntu node images | expected yes | expected yes | expected no (`apparmor` etc. only): needs a boot parameter |
| Apple-silicon k3d (Docker Desktop / Colima VM kernel) | varies | usually no | no: expect the Falco fallback |

Where a node's `lsm=` cannot be changed (most managed node pools), run `fexit/` only (accept the inlined-hook blindness, read the
startup line) or use Falco. Arm64 syscall names differ (no `open`, `creat`, `rename`, `unlink`, `chmod`; only the `*at` family): the
sensor maps them by build arch and the model sees the same groups.

### Dev vs production

The manifests live in `deploy/k8s/base/`; two kustomizations build them:

| Install | Command | Includes |
|---|---|---|
| Dev / demo / lab (default) | `kubectl apply -k deploy/k8s` or `./deploy/scripts/install.sh` | Everything in `base/`: dashboard, **1** inference replica. Cheapest; fits a small cluster or minikube. |
| Production | `./deploy/scripts/install.sh --production --registry HOST/PATH [--tag TAG]` (applying the overlay directly leaves its images at `registry.invalid`, so pods do not start) | `base/` minus the dashboard (Deployment, Service, ServiceAccount), plus: a CPU HorizontalPodAutoscaler for inference (min **2** replicas, max 6, 70% of the 10m request) and a PodDisruptionBudget (`minAvailable: 1`); PriorityClass `kubeheal-security` (value 1000000, below the `system-*` classes) on the security-agent DaemonSet, fusion, the health agent, inference and Redis so app pods are evicted first under node pressure; DaemonSet rolling update `maxUnavailable: 10%`; Redis high availability (3 Redis + 3 Sentinels, see "Redis high availability") instead of the single Redis. |

Every safety setting (enforce mode and rails, securityContexts, probes, resources, RBAC, NetworkPolicy) is the same in both.
The fusion agent stays a single `Recreate` replica (one consumer-group owner), so it has no PDB.

- The HPA needs **metrics-server** (`metrics.k8s.io`). minikube ships it as an addon; check with `kubectl get apiservice v1beta1.metrics.k8s.io`.
- `kubectl apply -k` does not prune. Switching a dev install to production leaves the dashboard running; delete it with
  `kubectl -n kubeheal delete deploy/kubeheal-dashboard svc/kubeheal-dashboard sa/kubeheal-dashboard`.
- `--production` builds `HOST/PATH/{inference,agents}:TAG` (and `sensor`) as multi-arch images with `docker buildx` and pushes them (TAG defaults to the git short SHA), then applies the overlay through a temporary kustomization that points its fail-closed `registry.invalid/kubeheal/*` images at that registry. It skips the demo app and the chaos image. The dev install rebuilds the `:v5` images in place, so it restarts the KubeHeal workloads (not Redis) after applying.
- Preview either build without a cluster: `kubectl kustomize deploy/k8s/overlays/production`.

### Network policy enforcement (required)

Quarantine is a deny-all NetworkPolicy, and Redis and inference accept only KubeHeal's own pods through
NetworkPolicies. All of this needs a CNI that **enforces** NetworkPolicy: Calico, Cilium, kindnet (minikube
and kind, recent releases), Antrea, or Weave do; **flannel alone does not** (policies are accepted and
silently ignored). Check before you rely on it: from a pod outside the allow-list,
`nc -zv redis-master.kubeheal.svc 6379` must time out.

- `redis-agents-only`: only pods labelled `app` in {health, security, fusion agents, dashboard} reach Redis :6379.
- `kubeheal-inference-clients`: only the health and security agents, the dashboard (Models page), plus namespace `monitoring` (the
  ServiceMonitor scrape), reach inference :8000. If Prometheus runs in another namespace, edit the policy.
- `kubeheal-dashboard-clients`: only pods in namespace `kubeheal` (and, in Helm with `ingress.enabled`, `ingress.controllerNamespace`) reach the dashboard :8080.
- `kubectl port-forward` is not subject to NetworkPolicy, so the scripts below keep working.

### Redis credentials

Redis runs with ACLs (`deploy/k8s/base/redis.yaml`). Job `kubeheal-redis-secret` creates Secret
`kubeheal/kubeheal-redis` once with random passwords: keys `<user>-password` and `<user>-url` for users
`default` (admin), `health`, `security`, `fusion`, `dashboard`. Each component's `REDIS_URL` comes from its
`<user>-url` key. Health, security and dashboard can only touch their own keys (the dashboard reads only);
only fusion and the admin can run scripts. Pods that need the Secret wait until the Job has created it.

- Ops scripts use the admin user through the Redis container's `REDISCLI_AUTH`:
  `kubectl -n kubeheal exec deploy/redis -- redis-cli ...`. Note that `redis-cli` exits 0 on error replies
  (`NOAUTH`, `NOPERM`), so check its output.
- From the host: `kubectl -n kubeheal port-forward svc/redis-master 16379:6379`, then
  `redis://default:$(kubectl -n kubeheal get secret kubeheal-redis -o jsonpath='{.data.default-password}' | base64 -d)@localhost:16379/0`.
- Denied commands are listed by `redis-cli ACL LOG`.
- **Rotate** (all passwords at once):
  `kubectl -n kubeheal delete secret kubeheal-redis job/kubeheal-redis-secret --ignore-not-found && kubectl apply -k deploy/k8s && kubectl -n kubeheal rollout restart deploy ds`.
- The dashboard user is read-only except `kubeheal:approval:*`, `kubeheal:mode` and the `kubeheal.approvals` / `kubeheal.ledger`
  streams (operator approvals and the kill switch). It cannot write baselines, specs, locks, breakers or done markers.

### Admin token

The same Job creates Secret `kubeheal/kubeheal-admin` (key `token`, random 32 bytes, once; it is kept on re-apply). The
dashboard reads it as `KUBEHEAL_ADMIN_TOKEN` and requires it for admin actions (approvals, mode switch).

- Read: `kubectl -n kubeheal get secret kubeheal-admin -o jsonpath='{.data.token}' | base64 -d`
- Rotate: `kubectl -n kubeheal delete secret kubeheal-admin job/kubeheal-redis-secret --ignore-not-found && kubectl apply -k deploy/k8s && kubectl -n kubeheal rollout restart deploy/kubeheal-dashboard`
  (the Job keeps `kubeheal-redis`, so Redis passwords do not change). Or set your own: `kubectl -n kubeheal create secret generic kubeheal-admin --from-literal=token=... --dry-run=client -o yaml | kubectl apply -f -`, then restart the dashboard.

### Containment signing key

The same Job creates Secret `kubeheal/kubeheal-contain-hmac` (key `key`, random 32 bytes, once). Fusion signs the containment
requests it puts on `kubeheal.contain` with it (`CONTAIN_HMAC_KEY`) and the security agents verify them, so a writer of that
stream alone cannot freeze pods. Rotate like the admin token (delete the Secret and the Job, re-apply, restart fusion and the
security-agent DaemonSet together).

### Alerts

Fusion posts alerts to `ALERT_WEBHOOK_URL`, read from the optional key `url` of Secret `kubeheal-alerts`; without the Secret
nothing is sent. Set it with `kubectl -n kubeheal create secret generic kubeheal-alerts --from-literal=url=https://... && kubectl -n kubeheal rollout restart deploy/kubeheal-fusion-agent`,
or with Helm `--set alerts.webhookUrl=...` (the URL then also sits in the Helm release record).

### Single sign-on

Optional. Without it the console uses the admin token (above). With it, an oauth2-proxy sidecar in the dashboard pod signs
users in and the dashboard runs with `KUBEHEAL_AUTH_MODE=proxy`: any signed-in user can read, only admins can write
(approve, reject, release, mode), and the ledger actor is the authenticated identity, never a self-declared name. Tokens and `X-Actor`
are ignored in that mode, and the identity headers are ignored in token mode.

**Why a sidecar.** The dashboard then listens on `127.0.0.1` only, so only the proxy in the same pod can reach it. On top of that
the proxy adds `X-Kubeheal-Proxy: <proxy-secret>`, and the dashboard rejects (401) any request without it, which also closes
`kubectl port-forward` to the pod port. A separate Deployment would need a NetworkPolicy plus that secret, and any pod that got through
could forge `X-Auth-Request-*`. Cost: one more 32 Mi container per dashboard replica.

**GitHub (default, free).** Collaborators of the repo in `OAUTH2_PROXY_GITHUB_REPO` (default `PRATHVI9607/Unisys_Model`; extra logins in
`OAUTH2_PROXY_GITHUB_USERS`) may sign in and are viewers. Admins are the logins in `admin-users` (case-insensitive; admins must also be able to sign
in). The actor is the GitHub login. A private repo needs the scope `user:email repo` (`OAUTH2_PROXY_SCOPE`).

1. GitHub, Settings, Developer settings, OAuth Apps, New OAuth App. Homepage URL `http://localhost:4180`. Authorization callback URL
   `http://localhost:4180/oauth2/callback` for the port-forward setup, or `https://<ingress host>/oauth2/callback` behind an Ingress.
2. Generate a client secret on the app page. Create the Secret (never in git or values):
   ```bash
   kubectl -n kubeheal create secret generic kubeheal-sso \
     --from-literal=client-id=<client id> --from-literal=client-secret=<client secret> \
     --from-literal=cookie-secret=$(openssl rand -base64 32 | head -c 32) \
     --from-literal=proxy-secret=$(openssl rand -hex 24)
   ```
   (`proxy-secret` is the shared secret between the proxy and the dashboard, not part of the OAuth App.)
3. Deploy. Kustomize: an overlay with `resources: [<path>/deploy/k8s/base]` and `components: [<path>/deploy/k8s/components/sso]`
   (edit the `kubeheal-sso` ConfigMap literals in the component, or merge your own). Helm:
   `--set sso.enabled=true --set sso.githubRepo=PRATHVI9607/Unisys_Model --set 'sso.adminUsers={PRATHVI9607}'`
   (`values-production.yaml` already lists the repo collaborators as admins: PRATHVI9607, K-aligrapher, Codexhack286, nullpointerx0; dev values keep the admin token)
   (`sso.allowedUsers={...}` for extra viewers; with `ingress.enabled` the callback and secure cookie follow `ingress.host`).
4. Open it: `kubectl -n kubeheal port-forward svc/kubeheal-dashboard 4180:8080`, then http://localhost:4180. Pods stay in
   `CreateContainerConfigError` until the Secret exists (closed, not open).

**Other OIDC providers** (Google, Microsoft Entra ID, Okta, Keycloak, Dex). Helm `sso.provider=oidc`, `sso.issuerURL`
(Google `https://accounts.google.com`; Entra `https://login.microsoftonline.com/<tenant>/v2.0`; Okta, Keycloak and Dex: the realm or org issuer),
Secret `client-id` and `client-secret` from the IdP, redirect URI as above, and `sso.adminUsers` (emails) and/or `sso.adminGroups` (values of the
`groups` claim; the scope asks for `groups`: Entra needs "groups" in the token configuration, Keycloak a groups mapper). Kustomize: swap the
component's `OAUTH2_PROXY_*` literals (`PROVIDER=oidc`, `OIDC_ISSUER_URL`, `SCOPE=openid email profile groups`, `OIDC_GROUPS_CLAIM=groups`),
`actor-claim=email` and set `admin-users` or `admin-groups`.

**Console.** Shows `user (admin|viewer)` and a sign-out link (`/oauth2/sign_out`); viewers see "Admin only" instead of approve/mode controls.
**Check it.** `curl -i http://localhost:4180/oauth2/userinfo` (signed in, in the browser) shows the identity. As a viewer a POST gets 403; with a
forged `X-Auth-Request-User` straight at the pod port it gets 401. Not exercised against a live IdP yet: verify with Dex on k3d
(`sso.provider=oidc`, issuer the Dex Service URL, a static client, admin by email).

### Alert routing

Rules: `deploy/k8s/base/alerts/kubeheal-rules.yaml` (PrometheusRule, installed with the kustomize base, or by Helm when `monitoring.enabled` and
`alerting.enabled`; needs the Prometheus Operator CRDs; `monitoring-values.yaml` makes Prometheus select every rule).

| Alert | Severity | Fires when |
|---|---|---|
| `KubeHealPodKilled`, `KubeHealWorkloadPatched` | info | `kubeheal_fusion_outcomes_total{outcome="pod_killed"\|"patched"}` rose in 5 m |
| `KubeHealApprovalPending` | warning | `kubeheal_fusion_approvals_pending` (ZCARD of the pending-approvals set, refreshed by fusion's housekeeping loop) is above 0 for 10 m |
| `KubeHealSensorDown` | critical | `kubeheal_sensor_up == 0` for 2 m, except on agents whose `kubeheal_security_event_source{source="falco"}` is set (`EVENT_SOURCE=falco`: no sensor runs) |
| `KubeHealEventLagHigh` | critical | p95 `kubeheal_security_event_lag_seconds` above 5 s for 5 m |
| `KubeHealFusionDown` | critical | no `up == 1` for job `kubeheal-fusion-agent` for 2 m |
| `KubeHealDetectionSlow` | warning | p95 `kubeheal_fusion_detection_to_action_seconds` above 2 s for 10 m |
| `KubeHealRedisMemoryHigh` | warning | `redis_memory_used_bytes / redis_memory_max_bytes` above 0.8 for 5 m. needs the `redis_exporter` sidecar (production overlay and `values-production.yaml` enable it; off in dev, where the alert stays silent). See "Redis memory metrics" below |
| `KubeHealCircuitOpen` | warning | `kubeheal_fusion_circuit_opens_total{action="kill"\|"patch"}` rose in 5 m (an action was skipped by the hourly budget) |
| `KubeHealFrozenOverdue` | critical | `kubeheal_security_frozen_overdue > 0` for 1 m |

**Redis memory metrics.** `deploy/k8s/components/redis-exporter` (Helm `redis.exporter.enabled`, needs Redis HA) adds a digest-pinned `oliver006/redis_exporter` sidecar to
each Redis pod, scraped on :9121 through the `redis-headless` Service by the `kubeheal` ServiceMonitor (NetworkPolicy `redis-exporter-scrape` admits only namespace `monitoring`).
It logs in as ACL user `exporter` (Secret key `kubeheal-redis/exporter-password`): `+info +ping +client|setname +client|setinfo +slowlog|get +slowlog|len +latency|latest +latency|histogram +command|info`,
no keys, no channels, no `CONFIG GET` (it could read `masterauth`). Checked against `redis:7.4.12` with the real ACL: no NOPERM and an empty `ACL LOG`.
An install that predates it has no such key (the credentials Job keeps an existing Secret): add it and restart Redis:
`kubectl -n kubeheal patch secret kubeheal-redis -p "{\"stringData\":{\"exporter-password\":\"$(openssl rand -hex 32)\"}}"`, then `kubectl -n kubeheal rollout restart sts/redis`.

Syntax check: `deploy/scripts/promtool-check.sh` (pinned `prom/prometheus` image). `tests/test_alerting.py` checks that every `kubeheal_*` metric in a rule is exported by the code.

**Alertmanager.** `monitoring-values.yaml` has it off (laptop) with a ready severity route (critical to pager, warning to chat, info to chat
once a day) and the Slack, PagerDuty and email receivers commented out, because Alertmanager will not start when a referenced secret file is missing. To use them:
```bash
kubectl -n monitoring create secret generic kubeheal-alertmanager \
  --from-literal=slack-url=https://hooks.slack.com/services/... --from-literal=pagerduty-key=... --from-literal=smtp-password=...
```
then set `alertmanagerSpec.secrets: [kubeheal-alertmanager]`, uncomment the receivers you use, point the routes at them, and
`helm upgrade monitoring ... --set alertmanager.enabled=true -f deploy/k8s/helm/monitoring-values.yaml`. This is separate from fusion's own webhook alerts (previous section).

### Grafana

`monitoring-values.yaml` enables Grafana (no default dashboards, random admin password, no Ingress) and its sidecar loads
ConfigMap `kubeheal-grafana-dashboard` (label `grafana_dashboard=1`, namespace `monitoring`, from `deploy/k8s/base/grafana/kubeheal-overview.json`):
decisions and outcomes, detection to freeze latency, containment, event lag, event/evaluation rates, inference latency and
requests, KubeHeal CPU and memory, mode and approvals/alerts. There is no sensor-drops panel: the sensor only logs its drop
counters (`kubeheal-sensor stats:`), it exports no metric.

```bash
kubectl -n monitoring port-forward svc/monitoring-grafana 3000:80
kubectl -n monitoring get secret monitoring-grafana -o jsonpath='{.data.admin-password}' | base64 -d   # user: admin
```

### Dashboard Ingress (Helm only)

Off by default. `--set ingress.enabled=true --set ingress.host=HOST --set ingress.tlsSecretName=SECRET [--set ingress.className=nginx]`;
the chart refuses to render without a host and a TLS Secret, and adds HOST to the dashboard's `DASHBOARD_ALLOWED_HOSTS`. Put your
ingress controller's authentication in front too: the admin token protects only the admin actions.

### Inference load test and HPA

`uv run --all-extras python deploy/scripts/loadtest_inference.py --in-cluster --hpa kubeheal-inference --duration 180 --concurrency 48` drives
`/v1/health/predict_batch` (64 rows per request) from inside the health-agent pod (the only client NetworkPolicy admits; the
Service then balances across replicas), prints p50/p95/p99 and the HPA's replica/CPU timeline. The HPA exists in production or with
`helm ... --set inference.autoscaling.enabled=true --set inference.resources.requests.cpu=100m` (needs metrics-server).

### Smoke test

`./deploy/scripts/smoke.sh` (after `install.sh`; guarded; exits non-zero on failure) checks: all pods Ready; every Redis
user authenticates and `ACL DRYRUN` allows and denies the expected commands; inference `/readyz`; dashboard `/api/stats` with an
accepted Host header (a foreign one gets 400; `--skip-dashboard` for `--production`); the detection-test workload in `khe-smoke-sec`
gets AUTO_KILL; a bad image on a Deployment with a baseline in `khe-smoke-health` gets AUTO_PATCH and the image is
restored. It runs in enforce mode on its own `khe-smoke-*` namespaces only and removes them and their Redis keys on exit.

### Redis persistence

Redis keeps the streams and the health baselines (the AUTO_PATCH targets) in an AOF on PVC `redis-data`
(1Gi, default StorageClass): `appendonly yes`, `appendfsync everysec` (at most ~1 s of writes lost on a
crash), RDB preamble, no RDB snapshots. A restart replays the AOF; the pod is not Ready (PING answers
`LOADING`) until that finishes. Without persistence, the health agent would re-baseline whatever is live
after a Redis restart, drift included. `maxmemory 192mb` with `noeviction`: a full Redis fails writes
rather than dropping baselines, so watch `used_memory` (`redis-cli INFO memory`). The 512Mi limit leaves
room for the copy-on-write of an AOF rewrite fork. Keep Redis in namespace `kubeheal`: the Falco and sensor
rules exclude that namespace from `/data` monitoring. To wipe all state: delete PVC `redis-data` with Redis
scaled to 0.

### Redis high availability

Optional; the dev install keeps one Redis. The production overlay (`deploy/k8s/components/redis-ha`) and Helm
`redis.ha.enabled` (true in `values-production.yaml`) replace it with:

- StatefulSet `redis`: 3 pods (1 primary + 2 replicas), a 1Gi PVC each, AOF as in the single install, the same ACL users
  and Secret `kubeheal-redis`, plus a `replicator` ACL user (`+psync +replconf +ping`, its own password in Secret `kubeheal-redis-ha`, created by the credentials Job; an install made before this key existed gets it on the next apply, then restart the Redis and Sentinel pods)
  that replicas use as `masteruser`. Roughly 1.5Gi of requests for the three.
- StatefulSet `redis-sentinel`: 3 Sentinels, quorum 2, `down-after-milliseconds` 5000. Password-protected: clients log in as ACL user `default` with `sentinel-password` from `kubeheal-redis-ha` (`REDIS_SENTINEL_PASSWORD`, wired to every client) and may only run `sentinel masters|replicas|get-master-addr-by-name`, ping, auth, hello; peers use user `peer`. Also behind NetworkPolicies `redis-sentinel-clients`; they authenticate to Redis as `default`.
- Preferred pod anti-affinity per node (a cluster with fewer than 3 nodes still schedules, without HA), a PodDisruptionBudget
  `minAvailable: 2` on each set, NetworkPolicies `redis-agents-only` (unchanged) and `redis-peers`.
- Agents and dashboard get `REDIS_SENTINELS`; `REDIS_URL` still supplies each component's ACL user and password and its host is
  ignored. `REDIS_SENTINEL_MASTER` (default `kubeheal`) is optional. Service `redis-master` and
  `deploy/redis` do not exist in HA: run admin commands on the primary,
  `kubectl -n kubeheal exec redis-N -c redis -- redis-cli ...` (`redis-cli role` tells which pod; or ask a Sentinel:
  `kubectl -n kubeheal exec redis-sentinel-0 -- redis-cli -p 26379 sentinel get-master-addr-by-name kubeheal` gives the primary's pod IP).

**Failover.** Killing the primary promotes a replica in roughly 10 to 20 s (`down-after` 5 s + election). The clients' Sentinel pool
resolves the new primary on the next reconnect; redis-py turns READONLY from a demoted primary into a ConnectionError. Every agent
loop already catches `RedisError` and retries on the same client (fusion's consumer loop sleeps 1 s, the security contain loop
1 s, the health agent logs and retries; `tests/test_redis_ha.py` covers the fusion loop), so no pod restarts. Streams and consumer
groups replicate, so fusion keeps its group position and unacked entries (XAUTOCLAIM) after the switch.
A restarted Redis pod asks the Sentinels who the primary is and joins as a replica; only on a first boot is `redis-0` the primary.

**What can be lost.** Replication is asynchronous: writes the old primary acknowledged but had not yet shipped are lost when it
dies. `min-replicas-to-write 1` and `min-replicas-max-lag 10` bound that: a primary that has lost all replicas for 10 s stops
accepting writes (NOREPLICAS) instead of accumulating more. The window is the replication lag, normally milliseconds, and
the cost is that with both replicas down writes fail until one returns. Effects are fail-safe: a lost event is
re-published by the next security window; a lost ack means redelivery, and a double action is prevented by the
`kubeheal:done:*` markers, the incident lock and the kill's pod-UID precondition (a second kill of the same UID is a no-op); a
lost baseline write is re-learned from the next spec change.

**Switching an existing install.** HA uses new PVCs (`data-redis-N`); the old `redis-data` is not migrated, so the health agent
re-learns baselines. Verify with `deploy/scripts/realworld/redis_failover.sh` (k3d, `KUBEHEAL_K3D_AGENTS=3`): it kills the
primary during an attack loop, reports the failover time and asserts that kills continue and no action is duplicated.

### Images

Our images are named `kubeheal.invalid/<name>:v5`. The reserved `.invalid` TLD never resolves, so with
`imagePullPolicy: IfNotPresent` a node either has the image locally (minikube builds it there) or the pull
fails. It never falls back to `docker.io/kubeheal/*`, which anyone could register. (`.local` would not be
safe: it is mDNS and can resolve on the LAN.) Production maps these names to `registry.invalid/kubeheal/*`
and then to your `--registry`. Base images in `deploy/docker/` and Redis are pinned by digest: bump the tag
and digest together.

To protect your own data volumes, add their mount points to `kh_data_dirs` in
`deploy/k8s/falco-kubeheal-rules.yaml` (default `/data`) and re-run `install.sh`.

## Enforce vs observe

| `KUBEHEAL_MODE` | Behaviour |
|---|---|
| `observe` (code default) | Fusion decides and publishes `ActionEvent`s with outcome `would_kill` or `would_patch`. Nothing in the cluster changes. |
| `enforce` (shipped in `deploy/k8s/base/fusion-agent-deployment.yaml`) | AUTO_KILL and AUTO_PATCH are executed, behind the safety rails |

```bash
kubectl -n kubeheal set env deploy/kubeheal-fusion-agent KUBEHEAL_MODE=observe   # dry-run
kubectl -n kubeheal set env deploy/kubeheal-fusion-agent KUBEHEAL_MODE=enforce
```

Any unknown value falls back to `observe`. The protected namespaces, the `kubeheal.io/protected=true`
label, the incident lock and the circuit breakers apply in both modes.

Two settings help when rolling KubeHeal out to a new cluster:

- **Exclusions.** Use `EXTRA_PROTECTED_NAMESPACES` on all three agents to exclude namespaces. Fusion also skips any namespace labelled `kubeheal.io/protected=true` (`kubectl label ns NAME kubeheal.io/protected=true`; picked up within 5 min, the namespace cache TTL). If that lookup fails, the namespace is treated as unprotected.
- **Tiers.** Label namespaces with `kubeheal.io/namespace-tier: prod|staging|dev`. In dev, only the rule-based rollback acts automatically.

## Demo

```bash
./deploy/scripts/reset.sh          # clean slate; then wait ASSESS_DELAY_S (60 s) for baselines
./deploy/scripts/demo.sh           # A then B, prompting between steps on a terminal
./deploy/scripts/demo.sh --seed    # also publish a few sample actions first (never to the health/security streams fusion consumes) (deploy/scripts/seed_demo.sh)
```

- **A. Config drift.** The demo patches `demo/victim-app` (podinfo under load) from a 500m CPU limit to 20m. 60 s later the health agent assesses the post-change window, and fusion logs a decision. AUTO_PATCH restores the baseline template. HUMAN or OBSERVE leaves the drift for a person, and `reset.sh` puts it back.
- **B. Ransomware-like workload.** The demo applies `deploy/chaos/chaos-pods.yaml`. Its init container marks `/data` (the victim's PVC) as a sandbox. `deploy/chaos/detection-test-workload.py` then creates `khtest_*` files and overwrites them with random bytes. It touches only files it created, and refuses to run without the `.kubeheal-sandbox` marker. The chain is Falco → security agent → AUTO_KILL: the pod is labelled `kubeheal.io/quarantined`, gets a deny-all NetworkPolicy, and is deleted. The script prints the time from `kubectl apply` to the decision.

To show the rule path, give the victim app an image that does not exist. The new pods go to
`ErrImagePull` or `ImagePullBackOff`, and fusion rolls back at any tier and model confidence.

```bash
kubectl -n demo set image deploy/victim-app app=ghcr.io/stefanprodan/podinfo:0.0.0-missing
```

`reset.sh` refuses to run unless `kubectl config current-context` is `minikube`, or you pass
`--force-context <that context>`. It does the following:

1. Deletes chaos pods and leftover quarantine policies.
2. Recreates `victim-app` from its manifest (delete, then apply).
3. Deletes the Redis state of namespace `demo` only: its stream entries and event copies, and its baselines,
   specs, locks, circuit breakers and idempotency markers. Other namespaces and the consumer groups stay.
4. Restarts the agents.

## Dashboard

```bash
kubectl -n kubeheal port-forward svc/kubeheal-dashboard 8080:8080   # http://localhost:8080
# local, against a port-forwarded Redis:
REDIS_URL=redis://dashboard:<dashboard-password>@localhost:16379/0 KUBEHEAL_ADMIN_TOKEN=<token> \
  uv run --all-extras uvicorn dashboard.fastapi_app:app --port 8080
```

The dashboard answers only Host headers in `DASHBOARD_ALLOWED_HOSTS` (default: `localhost`, `127.0.0.1` and the
`kubeheal-dashboard` Service names; add your Ingress host there) and sends a strict Content-Security-Policy:
all script and CSS come from `/static` (no inline code, no style attributes), and `/ws` rejects a cross-site
`Origin`. It has no Kubernetes access. Reads are open; every write goes through the admin token.

**Pages** (keys `1` to `5` switch between them, arrow keys walk a table):

- **Overview:** mode banner (the effective mode fusion reports in `kubeheal:mode:effective`: Enforce, Observe, or "Fusion not reporting" when the key is gone; the runtime switch shows as a second line only when it differs), KPIs (pods killed, workloads patched, awaiting approval, guard rails hit, detection-to-kill latency p50/p95, containment requested), the live action table with a decision filter, and the health and security signals. KPIs cover the newest 200 actions. Detection-to-kill is the action time minus the end of the security window that triggered an AUTO_KILL (dry-run kills included, approved kills excluded: they waited for a human). The action table is sorted newest first.
- **Incident detail** (click a row): decision, mode, outcome, containment, rationale, a decision trail with the time from detection to action, and the linked security and health events with top factors, class probabilities, changed fields and failure reasons. Missing values render as `—`.
- **Approvals:** HUMAN decisions fusion held back, with the candidate action. Approve or reject opens an inline confirmation with a reason. Listed from fusion's pending index `kubeheal:approvals:pending` (newest first), so items older than the 200-action buffer still show; a pending item shows when it expires (1 h after it was raised). State shows live: `approve requested`, `executing`, `executed`, `failed`, `rejected`, `expired`. A reason being typed survives live updates.
- **Ledger:** paged, filterable (namespace, kind, actor), read-only. A filtered page examines at most 1000 entries.
- **Mode:** the runtime kill switch (`observe` forces dry-run at once; `enforce` only works if the fusion manifest also says enforce). Switching asks for confirmation on the page and is ledgered.
- **Models:** versions from the inference `/readyz`, plus training metrics when `models/<task>/meta.json` is readable (`KUBEHEAL_MODELS_DIR`, default `models`; the dashboard image does not ship them, so it shows versions only unless you mount them). Skipped quietly when inference is unreachable.

Theme follows the OS (button in the sidebar cycles system, light, dark).

**Admin access.** (SSO instead of tokens: "Single sign-on" above.) Set `KUBEHEAL_ADMIN_TOKEN` (the manifest reads it from a Secret). Unset: every write route answers 503. A write needs `Authorization: Bearer <token>`: missing is 401, wrong is 403. The page keeps the token in `sessionStorage` (gone when the tab closes) and sends it only as that header, so there are no cookies and no CSRF surface. For a real identity set `KUBEHEAL_ADMIN_TOKENS="maria:token1,li:token2"` (name before the first `:`): the matching name is the actor and `X-Actor` is ignored. With only the shared `KUBEHEAL_ADMIN_TOKEN` the actor is `admin`, or `admin:<X-Actor>` (free text, sanitized, 40 characters: a label, not an identity). Both can be set. Wrong tokens are limited to 10 per client, then about 10 a minute (429); the client is the TCP peer address, so behind a proxy or port-forward all users share one allowance. Keep the dashboard off the public internet.

**Approval protocol.** Fusion writes `kubeheal:approval:<HUMAN action event id>` (JSON, 24 h TTL, `state` `pending` then `executing`, `executed`, `failed` or `rejected`). The dashboard never changes `state`. On approve or reject it runs `WATCH` on that key, then in one `MULTI`: sets `requested {decision, actor, approval_id, ts_ms}` on it (a second decision gets 409), `XADD kubeheal.approvals {approval_id, action_event_id, decision: approve|reject, actor, reason, ts_ms}` and `XADD kubeheal.ledger` (kind `approval` or `rejection`). Fusion consumes the stream and moves `state` along. A missing key is 404 (never raised, or expired).

**Redis commands the dashboard uses** (for the ACL): `PING`, `XREVRANGE` and `XREAD` on the three event streams and on `kubeheal.ledger`; `HGETALL kubeheal:{kind}:{id}`; `GET kubeheal:mode`, `GET kubeheal:mode:effective`, `ZREVRANGE kubeheal:approvals:pending`, `MGET`/`GET kubeheal:approval:*`; and, admin only, `WATCH`/`MULTI`/`EXEC`, `SET kubeheal:mode`, `SET kubeheal:approval:*` (with `KEEPTTL`), `XADD kubeheal.approvals` (`MAXLEN ~` 10000), `XADD kubeheal.ledger` (`MAXLEN ~` `LEDGER_MAXLEN`; fusion trims by age). The dashboard only adds the `requested` object to an approval record and leaves every other field as fusion wrote it.

**Environment:** `REDIS_URL`, `LOG_LEVEL`, `DASHBOARD_ALLOWED_HOSTS`, `KUBEHEAL_ADMIN_TOKEN` and `KUBEHEAL_ADMIN_TOKENS` (new), SSO only: `KUBEHEAL_AUTH_MODE` (`token` default | `proxy`), `KUBEHEAL_PROXY_SECRET`, `KUBEHEAL_ADMIN_USERS`, `KUBEHEAL_ADMIN_GROUPS`, `KUBEHEAL_ACTOR_CLAIM` (`email` default | `user`), `INFERENCE_URL` (new here, same default as the agents; needs a NetworkPolicy path to inference for the Models page), `KUBEHEAL_MODELS_DIR` (new).

**How it works:**

- **Ingest.** A single background task backfills the newest 200 entries per stream (`XREVRANGE`), then tails all three with `XREAD BLOCK 1000 COUNT 100`. Entries are parsed with the contract's `from_fields()`. A malformed entry is logged and skipped.
- **Memory.** The newest 200 events per kind are kept in memory, and the counts in the UI cover that window. Older details come from the `kubeheal:{kind}:{id}` hashes (24 h TTL).
- **Push.** Batches go to every WebSocket client at once. A client that does not accept a message within 2 s is dropped and reconnects. Redis outages retry with backoff from 1 s to 30 s. New actions are announced to screen readers through an `aria-live` region.

| Endpoint | Returns |
|---|---|
| `GET /` | The console (single page, hash routes) |
| `GET /healthz`, `GET /readyz` | 200 while up; ready is 200 if Redis answered in the last 10 s, else 503 |
| `GET /api/stats` | Event counts, `kills`, `patches` (and `_dry_run`), `human`, `guard_rails`, `containment_requested`, `latency_ms {p50,p95,n}`, `redis_connected`, `window` |
| `GET /api/events?kind=health\|security\|action&limit=1..200` | Newest first |
| `GET /api/events/{kind}/{event_id}` | One event: 404 if unknown, 503 if Redis is needed and down |
| `GET /api/approvals`, `GET /api/approvals/{id}` | Queue with state; 404 if the approval key is gone |
| `POST /api/approvals/{id}/approve\|reject` | Admin. `{reason}`. 404 / 409 as above |
| `GET /api/mode`, `POST /api/mode` | `{runtime, effective, last_action_mode}`; admin `{mode: observe\|enforce, reason}` |
| `GET /api/ledger?limit&cursor&namespace&kind&actor` | Newest first, `next_cursor` for the next page. Ledger and approvals reads are rate-limited per client (burst 20, then 2 a second; 429) |
| `GET /api/models` | Inference versions and bundle metrics |
| `GET /api/admin/session` | Admin. Checks the token |
| `GET /api/me` | `{mode, user, admin}`; in proxy mode the signed-in identity (401 without the proxy secret) |
| `WS /ws` | Server to client: `stats`, `events` (oldest to newest), `resync` (after a Redis reconnect: refetch) |

**Browser tests.** `tests/ui/` drives the real app with Playwright and fake Redis. Install the browser once with
`uv run playwright install chromium`; without it the tests skip. Run them with `uv run --all-extras pytest tests/ui`;
`KUBEHEAL_SHOTS=<dir>` also writes screenshots.

## Benchmark

```bash
./deploy/scripts/bench.sh [--duration 300] [--runs 5] [--out FILE]
```

Run it against the deployed stack in enforce mode (about 15 min with the defaults). Phase 1 runs a
protected, benign heavy-I/O pod for `--duration` seconds and samples `kubectl top` (Falco, security
agent, inference) and the Falco events file size every 15 s. Phase 2 runs the detection-test workload
`--runs` times (20 files/s, created then encrypted at once) and times the first malicious operation (logged by the workload) to the AUTO_KILL action. Results go to `--out` (default
`training/data/collected/bench-<ts>.json`). On exit the script deletes the `kubeheal-bench` namespace and
its circuit-breaker keys. Results are in [architecture.md](architecture.md#resources).

## Lab data collection

Only run collection against a lab cluster.

```bash
mkdir -p training/data/collected
nohup training/collect/run_lab.sh --hours 12 >> training/data/collected/run_lab.out 2>&1 &
# options: --health-slots N (default 12)  --security-slots N (default 5; Falco caps it at ~5-6 on 8 CPU)
#          0 slots skips that collector
uv run --all-extras python -m training.datasets.collected export      # afterwards: gz exports + dataset card
```

`run_lab.sh` runs these steps:

1. Builds the agents and chaos images and pre-pulls the lab images.
2. Applies `deploy/k8s/` and restarts the agents.
3. **Turns capture on** (`KUBEHEAL_CAPTURE=1` on the security DaemonSet).
4. Port-forwards Redis (`localhost:16379`) and Prometheus (`localhost:19090`).
5. Runs `drift_lab.py` and `security_lab.py` concurrently.
6. Writes a resource log once a minute to `training/data/collected/resources.log`, covering node, Prometheus, Redis, the Falco file size and Falco queue drops.

On any exit, whether normal, error, INT or TERM, the script cleans up:

- It stops the collectors.
- It deletes the `kubeheal-lab` namespace.
- It **restores `KUBEHEAL_CAPTURE=0`** and verifies the change.
- It kills the port-forwards.

The collectors append to `training/data/collected/*.jsonl`, so you can resume a run by starting the
script again. Both collectors pause new samples while node memory is above `--max-node-mem-gib`
(default 6).

Lab Deployments and pods carry `kubeheal.io/protected=true`, so fusion records decisions for them
but never acts on them, even in enforce mode.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Falco pods crash-loop on a new kernel with the BPF verifier error `invalid mem access 'scalar'` (prog `signal_deliver`) | Falco 0.45.0's modern probe is rejected by the 7.x verifier. `falco-values.yaml` pins `image.tag: 0.45.1-rc1`. Move to 0.45.1 once it is released. The modern eBPF driver needs kernel BTF (`/sys/kernel/btf/vmlinux`). |
| No security events at all | The Falco DaemonSet is not running, or `/var/run/falco/events.jsonl` is missing on the node (the agent logs that it is waiting for the file). The workload might also not write under a `kh_data_dirs` path, or its namespace might be protected or outside `WATCH_NAMESPACES`. Check `kubeheal_security_falco_events_total`. |
| Security windows arrive minutes late, or Falco is OOMKilled | Falco is over capacity. `outputs_queue.capacity: 100000` makes it drop alerts (logged as `queue out of memory`) instead of OOM-looping. Give Falco more CPU (limit 2) or run fewer security slots. Check that `base_syscalls.custom_set` is still set, since without it Falco traces 87 syscalls instead of 38. |
| `kubectl exec ... sh` fails on a KubeHeal pod | The inference, agents and dashboard images are distroless and have no shell. Use `kubectl debug -it <pod> --image=busybox --target=<container>`. |
| The events file grows without bound | The agent could not open it for writing, so hole punching is off (there is a warning in the agent log). The hostPath mount must be writable. |
| Prometheus is OOMKilled or slow during long lab runs | Lab pods churn hundreds of series per hour. `monitoring-values.yaml` keeps only the series `agents/health_agent/prometheus.py` queries (keep-lists), with retention 6 h and a 1.5 GiB limit. If you add a metric to `build_queries()`, add it to the matching keep regex too. |
| Health events lack request, error or latency features | The app pods need the label `kubeheal.io/scrape=true` and a port named `http` that serves `http_requests_total` and `http_request_duration_seconds_bucket`. Without them those features are `None`, which is valid but weaker. |
| No health event after a change | Assessments run 60 s after the change (sooner on a posture violation or failed rollout). The first sight of a workload stores a baseline without an assessment. A change back to the baseline is not assessed. If inference is unavailable, the agent retries every 60 s (see `kubeheal_health_assessments_total{outcome}`). |
| AUTO_PATCH escalates to HUMAN with `escalated_no_baseline` | No baseline is stored, for example for a workload not yet seen, or after PVC `redis-data` was wiped. Baselines are re-learned when the agent first sees each workload. |
| Agents stuck in `CreateContainerConfigError`, Redis in `ContainerCreating` | Secret `kubeheal-redis` does not exist yet. Check `kubectl -n kubeheal logs job/kubeheal-redis-secret` (it needs the agents image). |
| Agent logs `NOPERM` / `NOAUTH` from Redis | The ACL in `redis.yaml` does not allow that command or key for the component, or the Secret was rotated without restarting the pods. `redis-cli ACL LOG` names the user, command and key. |
| Actions say `skipped_circuit_open` | The per-workload hourly budget is spent. Wait out the hour, or clear the `kubeheal:cb:*` keys (`reset.sh` clears those of namespace `demo`; it refuses to run unless the context is minikube or `--force-context <current context>` is given). |
| Capture is still on after a collection run was killed with `-9` | Run `kubectl -n kubeheal set env ds/kubeheal-security-agent KUBEHEAL_CAPTURE=0`. Capture only adds the `kubeheal.security.capture` stream (capped by MAXLEN). It never changes decisions. |
| `/readyz` of inference returns 503 | A bundle in `models/{health,security}` is missing or does not match its `meta.json`. The logs name the task. Retrain or restore the bundle and rebuild the image. |


## Upgrading: containment HMAC

Freeze entries on `kubeheal.contain` are still signed in the previous release's pipe-joined format (`uid|ns|pod|event|ts`), so a
rolling upgrade (new fusion, old security agents, or the reverse) keeps freezing pods. Thaw entries (new) are signed as a JSON array
and an old security agent refuses them: release works only once every security agent is upgraded. New security agents verify both
freeze formats. A later release will switch freezes to JSON and drop the pipe format; upgrade all components before that one.

Also new: release records of a frozen pod live 7 days (nothing thaws it), the dashboard SSO cookie is `SameSite=strict`, and Helm
`sso.provider=oidc` requires `sso.emailDomains` and/or `sso.allowedGroups`.

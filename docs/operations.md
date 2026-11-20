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

### Dev vs production

The manifests live in `deploy/k8s/base/`; two kustomizations build them:

| Install | Command | Includes |
|---|---|---|
| Dev / demo / lab (default) | `kubectl apply -k deploy/k8s` or `./deploy/scripts/install.sh` | Everything in `base/`: dashboard, **1** inference replica. Cheapest; fits a small cluster or minikube. |
| Production | `./deploy/scripts/install.sh --production --registry HOST/PATH [--tag TAG]` (applying the overlay directly leaves its images at `registry.invalid`, so pods do not start) | `base/` minus the dashboard (Deployment, Service, ServiceAccount), plus: a CPU HorizontalPodAutoscaler for inference (min **2** replicas, max 6, 70% of the 10m request) and a PodDisruptionBudget (`minAvailable: 1`); PriorityClass `kubeheal-security` (value 1000000, below the `system-*` classes) on the security-agent DaemonSet, fusion, the health agent, inference and Redis so app pods are evicted first under node pressure; DaemonSet rolling update `maxUnavailable: 10%`. |

Every safety setting (enforce mode and rails, securityContexts, probes, resources, RBAC, NetworkPolicy) is the same in both.
The fusion agent stays a single `Recreate` replica (one consumer-group owner), so it has no PDB.

- The HPA needs **metrics-server** (`metrics.k8s.io`). minikube ships it as an addon; check with `kubectl get apiservice v1beta1.metrics.k8s.io`.
- `kubectl apply -k` does not prune. Switching a dev install to production leaves the dashboard running; delete it with
  `kubectl -n kubeheal delete deploy/kubeheal-dashboard svc/kubeheal-dashboard sa/kubeheal-dashboard`.
- `--production` builds `HOST/PATH/{inference,agents}:TAG` with docker and pushes them (TAG defaults to the git short SHA), then applies the overlay through a temporary kustomization that points its fail-closed `registry.invalid/kubeheal/*` images at that registry. It skips the demo app and the chaos image. The dev install rebuilds the `:v5` images in place, so it restarts the KubeHeal workloads (not Redis) after applying.
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

- **Exclusions.** Use `EXTRA_PROTECTED_NAMESPACES` on all three agents to exclude namespaces.
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

**Admin access.** Set `KUBEHEAL_ADMIN_TOKEN` (the manifest reads it from a Secret). Unset: every write route answers 503. A write needs `Authorization: Bearer <token>`: missing is 401, wrong is 403. The page keeps the token in `sessionStorage` (gone when the tab closes) and sends it only as that header, so there are no cookies and no CSRF surface. For a real identity set `KUBEHEAL_ADMIN_TOKENS="maria:token1,li:token2"` (name before the first `:`): the matching name is the actor and `X-Actor` is ignored. With only the shared `KUBEHEAL_ADMIN_TOKEN` the actor is `admin`, or `admin:<X-Actor>` (free text, sanitized, 40 characters: a label, not an identity). Both can be set. Wrong tokens are limited to 10 per client, then about 10 a minute (429); the client is the TCP peer address, so behind a proxy or port-forward all users share one allowance. Keep the dashboard off the public internet.

**Approval protocol.** Fusion writes `kubeheal:approval:<HUMAN action event id>` (JSON, 24 h TTL, `state` `pending` then `executing`, `executed`, `failed` or `rejected`). The dashboard never changes `state`. On approve or reject it runs `WATCH` on that key, then in one `MULTI`: sets `requested {decision, actor, approval_id, ts_ms}` on it (a second decision gets 409), `XADD kubeheal.approvals {approval_id, action_event_id, decision: approve|reject, actor, reason, ts_ms}` and `XADD kubeheal.ledger` (kind `approval` or `rejection`). Fusion consumes the stream and moves `state` along. A missing key is 404 (never raised, or expired).

**Redis commands the dashboard uses** (for the ACL): `PING`, `XREVRANGE` and `XREAD` on the three event streams and on `kubeheal.ledger`; `HGETALL kubeheal:{kind}:{id}`; `GET kubeheal:mode`, `GET kubeheal:mode:effective`, `ZREVRANGE kubeheal:approvals:pending`, `MGET`/`GET kubeheal:approval:*`; and, admin only, `WATCH`/`MULTI`/`EXEC`, `SET kubeheal:mode`, `SET kubeheal:approval:*` (with `KEEPTTL`), `XADD kubeheal.approvals` (`MAXLEN ~` 10000), `XADD kubeheal.ledger` (`MAXLEN ~` `LEDGER_MAXLEN`; fusion trims by age). The dashboard only adds the `requested` object to an approval record and leaves every other field as fusion wrote it.

**Environment:** `REDIS_URL`, `LOG_LEVEL`, `DASHBOARD_ALLOWED_HOSTS`, `KUBEHEAL_ADMIN_TOKEN` and `KUBEHEAL_ADMIN_TOKENS` (new), `INFERENCE_URL` (new here, same default as the agents; needs a NetworkPolicy path to inference for the Models page), `KUBEHEAL_MODELS_DIR` (new).

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

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
- `kubeheal-inference-clients`: only the health and security agents, plus namespace `monitoring` (the
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
REDIS_URL=redis://dashboard:<dashboard-password>@localhost:16379/0 uv run --all-extras uvicorn dashboard.fastapi_app:app --port 8080
```

The dashboard answers only Host headers in `DASHBOARD_ALLOWED_HOSTS` (default: `localhost`, `127.0.0.1` and the
`kubeheal-dashboard` Service names; add your Ingress host there) and sends a strict Content-Security-Policy:
all script and CSS come from `/static`, and `/ws` rejects a cross-site `Origin`.

The dashboard is a read-only console with no write endpoints and no Kubernetes access.

**The UI** has three sections:

- **Actions:** decision, a `dry-run` badge in observe mode, outcome, score, compound score and summary. The detail view shows the rationale and links to the underlying health and security events.
- **Health:** label, risk, `uncertain` (the conformal set has more than one label), and the changed-field count.
- **Security:** label, risk, `uncertain`, the event count and the window.

Event details show the top factors as SHAP contribution bars, the class probabilities and the
changed fields. Missing values render as `—`.

**How it works:**

- **Ingest.** A single background task backfills the newest 200 entries per stream (`XREVRANGE`), then tails all three with `XREAD BLOCK 1000 COUNT 100`. Entries are parsed with the contract's `from_fields()`. A malformed entry is logged and skipped.
- **Memory.** The newest 200 events per kind are kept in memory, and the counts in the UI cover that window. Older details come from the `kubeheal:{kind}:{id}` hashes (24 h TTL).
- **Push.** Batches go to every WebSocket client at once. A client that does not accept a message within 2 s is dropped and reconnects. Redis outages retry with backoff from 1 s to 30 s.

| Endpoint | Returns |
|---|---|
| `GET /` | The console |
| `GET /healthz` | 200 while the process is up |
| `GET /readyz` | 200 if Redis answered in the last 10 s, else 503 |
| `GET /api/stats` | `health_events`, `health_high_risk` (risk ≥ 0.7), `security_events`, `security_high_risk`, `actions`, `actions_dry_run`, `redis_connected`, `window` |
| `GET /api/events?kind=health\|security\|action&limit=1..200` | Newest first |
| `GET /api/events/{kind}/{event_id}` | One event: 404 if unknown, 503 if Redis is needed and down |
| `WS /ws` | Server → client messages: `stats`, `events` (oldest → newest), `resync` (after a Redis reconnect: refetch) |

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

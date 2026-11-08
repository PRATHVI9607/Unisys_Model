# KubeHeal architecture

This document covers what each component does, the contracts between components, how detections
become decisions and actions, the runtime configuration, and how failures are handled. The system
diagram is at the top of the [README](../README.md). Models and data are covered in
[models-and-data.md](models-and-data.md), and running the system in [operations.md](operations.md).

## Components

| Component | Kind (namespace `kubeheal`) | Entry point | Responsibility |
|---|---|---|---|
| **inference** | Deployment ×1 (dev) / 2–6 with an HPA (production), `kubeheal/inference:v5` | `uvicorn kubeheal.inference.app:app` (:8000) | Loads `models/{health,security}` at startup and serves `POST /v1/{task}/predict`. Never serves untrained weights: a missing bundle makes that task, and `/readyz`, return 503. |
| **health-agent** | Deployment ×1, `kubeheal/agents:v5` | `python -m agents.health_agent.agent` (:8080) | Watches Deployments and assesses each real spec change `ASSESS_DELAY_S` (60 s) after it is seen, sooner on a posture violation or failed rollout. Derives `failure_reasons`, publishes a `HealthEvent`, and keeps the spec and baseline keys up to date. |
| **security-agent** | DaemonSet, `hostPID`, `kubeheal.invalid/agents:v5` + `kubeheal.invalid/sensor:v5` | `python -m agents.security_agent.agent` (:8080) + `kubeheal-sensor` | Tails the Falco-shaped JSON of its node's event source and builds per-pod windows. Adds file entropy, write bytes and network-out bytes, scores a pod every 1 s or as soon as it has 32 new events, and publishes a `SecurityEvent` when risk ≥ 0.4. **It observes only.** |
| **fusion-agent** | Deployment ×1, `strategy: Recreate` | `python -m agents.fusion_agent.agent` (:8080) | The single decision point and the only component that changes the cluster. It pairs events, scores correlation, runs the pure policy, acts or records `would_*`, and publishes an `ActionEvent` for every decision. |
| **dashboard** | Deployment ×1 | `uvicorn dashboard.fastapi_app:app` (:8080) | Read-only console that tails the three streams and pushes them over WebSocket. It has no Kubernetes access. |
| **redis** | Deployment ×1, `redis:7.4.2-alpine` | `redis-master:6379` | Holds the streams and keys. It is ephemeral (no RDB or AOF), capped at 256 MB with `noeviction`, and a NetworkPolicy allows only same-namespace clients. |
| Prometheus | Helm `kube-prometheus-stack` 92.10.1, namespace `monitoring` | `prometheus-operated:9090` | cAdvisor, kube-state-metrics and app `/metrics` (PodMonitor `kubeheal.io/scrape=true`), every 15 s, with keep-lists. |
| Event source: sensor (default) | container `sensor` in the security-agent DaemonSet (`sensor/`) | `/var/run/kubeheal/events.jsonl` (emptyDir shared with the agent) | Rust + libbpf. `lsm/` programs (fallback `fexit/`) on `file_open`, `path_rename`, `path_unlink`, `path_truncate`, `file_truncate`, `path_chmod`; filters in the kernel (pod cgroups under `kubepods`, resolved path prefix `/data/`, namespace `kubeheal` excluded) and writes Falco-shaped JSON lines. See `sensor/README.md`. |
| Event source: Falco (`EVENT_SOURCE=falco`) | Helm `falco` 9.2.0, namespace `falco` | `/var/run/falco/events.jsonl` (hostPath) | Modern eBPF, loading **only** `deploy/k8s/falco-kubeheal-rules.yaml`. `deploy/k8s/components/falco-source` drops the sensor and mounts this directory as the agent's `events` volume. Single event thread: ~1900 alerts/s per node. |

Shared code lives in `kubeheal/`, which every image copies: `contracts.py`, `features/`, `ml/` and
`correlation.py`. Only the inference image and training import `lightgbm`.

## Contracts (`kubeheal/contracts.py`)

All names below are defined in `kubeheal/contracts.py` and nowhere else, so a rename is a one-file
change. Stream entries are flat `str → str` maps: nested values are compact JSON, booleans are
`"1"`/`"0"`, and `None` is `""` (`to_fields()` / `from_fields()`).

### Streams

| Stream | Producer → consumer | Payload |
|---|---|---|
| `kubeheal.health.events` | health-agent → fusion (group `fusion`), dashboard | `HealthEvent` |
| `kubeheal.security.events` | security-agent → fusion (group `fusion`), dashboard | `SecurityEvent` |
| `kubeheal.actions` | fusion → dashboard | `ActionEvent` |
| `kubeheal.deadletter` | fusion | The original fields plus `_stream`, `_id` and `_error` |
| `kubeheal.contain` | fusion → every security-agent (each node acts on its own pods) | `{pod_uid, namespace, pod, event_id, ts_ms}`: freeze this pod's cgroup now. Written only for an enforce-mode AUTO_KILL that passed every check. `MAXLEN ~ 1000`. |
| `kubeheal.security.capture` | security-agent (only when `KUBEHEAL_CAPTURE=1`) → `training/collect/security_lab.py` | `SecurityEvent` for **every** scored window, whatever its risk |

Every other XADD uses `MAXLEN ~ 10000` (`STREAM_MAXLEN`).

### Redis keys

| Key | Written by | Meaning |
|---|---|---|
| `kubeheal:spec:{ns}:{workload}` | health | Last spec the agent recorded, API-shaped JSON (older agents stored the canonical form; both hash the same). Deleted on a DELETE event or when a full re-list no longer contains the Deployment. |
| `kubeheal:baseline:{ns}:{workload}` | health (read by fusion) | Restore target for AUTO_PATCH: set on first sight, then promoted only when a new spec is benign **and certain relative to the current baseline** and its rollout completed. Stored API-shaped, so fusion restores `template` verbatim (canonical form camelCases user-data keys such as csi `volumeAttributes`). |
| `kubeheal:{health\|security\|action}:{event_id}` | every publisher | Hash copy of an event for dashboard detail lookups. TTL 24 h, and at most 10000 per kind (the stream's horizon): Redis runs `noeviction`, so an unbounded count would end in failed writes. Written in the same MULTI as the XADD. |
| `kubeheal:index:{health\|security\|action}` | every publisher | List of the hash-copy keys, newest first, trimmed to 10000; trimmed-off copies are deleted |
| `kubeheal:done:{event_id}` | fusion | Idempotency marker for one consumed event: the `ActionEvent` it produced (JSON, `SET NX`, TTL 1 h). A redelivery after a failed publish/XACK republishes it instead of acting again. |
| `kubeheal:lock:{ns}:{Kind}/{name}` | fusion | Incident lock on the controller acted on (`Deployment/web`, `DaemonSet/agent`, `Pod/x` for a bare pod): `SET NX PX 10000`, a unique token per holder, and an owner-checked heartbeat every 3 s (Lua) |
| `kubeheal:cb:{kill\|patch}:{ns}:{Kind}/{name}` | fusion | Circuit-breaker counter of **successful** actions on that controller: checked (`GET`) before acting, `INCR` plus `EXPIRE NX 3600` in one transaction after a success. Both run under the incident lock on the same target, which serialises check → act → count across replicas. |

### Labels and annotations

| Label | Where | Meaning |
|---|---|---|
| `kubeheal.io/protected=true` | pod, or its controller (Deployment, StatefulSet, DaemonSet, Job) | KubeHeal never acts on it |
| `kubeheal.io/quarantined=true` | pod, set by fusion | Selected by the pod's deny-all quarantine NetworkPolicy |
| `kubeheal.io/namespace-tier=prod\|staging\|dev` | namespace | Tier multiplier. Without it, the tier comes from the name (`prod` → prod, `stag` → staging, otherwise dev). |
| `kubeheal.io/scrape=true` | app pods | Scraped by the `kubeheal-apps` PodMonitor (request, error and latency metrics) |
| `kubeheal.io/metrics=true` | KubeHeal Services | Scraped by the `kubeheal` ServiceMonitor |

Built-in protected namespaces are `kube-system`, `kube-public`, `kube-node-lease` and `kubeheal`.

### Event models

| Model | Fields |
|---|---|
| `Prediction` (inference response) | `model_version`, `label`, `risk` (Σ p·class_risk), `probabilities`, `prediction_set`, `uncertain` (set ≠ one label), `top_factors[]` (`feature`, `value`, `contribution`), `latency_ms` |
| common to `HealthEvent` / `SecurityEvent` | `event_id`, `namespace`, `workload` (owning Deployment, which is the join key), `pod`, `timestamp_ms`, `model_version`, `label`, `risk`, `uncertain`, `probabilities`, `top_factors`, `features` |
| `HealthEvent` | adds `spec_changed`, `changed_fields` (dotted paths, at most 50), `has_baseline`, `failure_reasons` (rollout failures seen after the change, plus `policy:<feature>` posture violations relative to the baseline; empty if none) |
| `SecurityEvent` | adds `window_start_ms`, `window_end_ms`, `n_events` |
| `ActionEvent` | `event_id`, `namespace`, `workload`, `pod`, `decision`, `mode` (`observe`\|`enforce`), `outcome`, `score`, `compound_score`, `rationale`, `summary`, `health_event_id`, `security_event_id`, `timestamp_ms` |

Labels and class risks are listed in index order, which is also the model class order:

| Task | Labels | Class risk |
|---|---|---|
| health | `benign`, `degradation`, `critical` | 0.05, 0.60, 0.95 |
| security | `benign`, `suspicious`, `ransomware`, `exfiltration` | 0.05, 0.45, 0.95, 0.85 |

### Inference API (:8000)

- `POST /v1/health/predict` and `POST /v1/security/predict` take `{"features": {name: float|null}, "request_id"?}` and return a `Prediction`.
  - Error responses: a feature name neither the bundle nor the agents know returns 422 (names the bundle does not list are ignored; names it lists but nobody sends are scored as missing), NaN or Inf returns 422, more than 200 keys returns 422, a body over 64 KiB returns 413 (by Content-Length, or by counting received bytes for a chunked body), and a task whose bundle is not loaded returns 503.
- `POST /v1/health/predict_batch` and `POST /v1/security/predict_batch` take `{"items": [<predict body>, ...]}` (1 to 256 items) and return a list of `Prediction` in the same order. The body cap is 1 MiB (256 × 4 KiB); the per-item rules above apply.
- **Explanations are computed only where they are used.** TreeSHAP is most of the inference CPU, so security predictions with risk below `SECURITY_PUBLISH_RISK` (0.4, in `contracts.py`; the same threshold the agent publishes at) return `top_factors: []`. Every published security event is therefore explained. Health predictions are always explained. Batch cost for mostly-benign security windows: 3.91 → 0.80 ms per row.
  - Prediction runs with `num_threads=1` in the threadpool.
- `GET /healthz` always returns 200.
- `GET /readyz` returns 200 only when both bundles are loaded and every feature a bundle lists is one the agents send (`unsent_features` otherwise), together with the model versions. `/healthz` and `/readyz` are `async` so they never queue behind predictions in the threadpool.
- `GET /metrics` returns `kubeheal_inference_requests_total`, `_latency_seconds` and `_predictions_total`.

## Detection pipelines

### Health: configuration drift

1. **Watch.** A Deployment watch (all namespaces, or one per entry in `WATCH_NAMESPACES`) keeps the API-shaped `spec` and hashes its `canonical_spec` (camelCase, empty values dropped). Only a changed `spec_hash` counts; while an HPA targets the Deployment (`autoscaling/v2` list every 30 s), `spec.replicas` is left out of the hash and the diff. Status-only updates just refresh the "rollout complete" flag. Each (re)start and every 410 does a full list first, replays it, and drops in-memory state and Redis spec/baseline keys of Deployments no longer listed, then watches from the list's `resourceVersion`.
2. **Debounce.** A per-workload timer fires `ASSESS_DELAY_S` (60 s) after the change was first seen. A newer change restarts the timer, but never past `ASSESS_DELAY_S` after the first still-pending change (the window starts there), so churn cannot postpone an assessment forever. The assessment comes sooner when the change adds a posture violation (at once) or when a failed rollout shows up (polled every `POLL_S` = 2 s). After the first event the spec stays *tracked* until its rollout completes, a newer spec supersedes it, the Deployment is deleted, or `progressDeadlineSeconds` (default 600) + 60 s pass; a failure reason confirmed on two consecutive polls that the first event did not carry is published as a **follow-up** `HealthEvent` for the same spec (same `changed_fields`, full reason set, at most once per new reason). Assessments run off the watch loop, at most 8 at a time.
3. **Compare.** The first time a workload is seen, its spec is stored as both spec and baseline, assumed good. A spec equal to the stored baseline (an AUTO_PATCH restore or a manual rollback) is recorded without an assessment.
4. **Features.**
   - **Metrics:** `agents/health_agent/prometheus.fetch_window` queries the 11 raw metrics over `[change seen, assess time]` at a 15 s step, in raw SI units.
   - **Features:** `health_features(old, new, window)` returns 36 features (24 spec-diff and 12 metric). A missing metric is `None`, never 0.
   - **Failure reasons:** `failure_reasons` collects Kubernetes evidence that the new spec cannot run. The agent lists the Deployment's pods by its `selector.matchLabels`, keeps only those owned by one of its ReplicaSets (ownerReference `<deployment>-<pod-template-hash>`, so an overlapping canary's pods never count), and of those keeps the ones created at or after the change (with 5 s of slack). For each one it records an init or app container waiting in `ImagePullBackOff`, `ErrImagePull`, `InvalidImageName`, `CrashLoopBackOff`, `CreateContainerConfigError`, `CreateContainerError` or `RunContainerError`, and a last termination reason of `OOMKilled`. It also adds `ProgressDeadlineExceeded` when the watched status shows `Progressing=False` for the current generation. It also adds `ReadinessNeverPassed` when every app container of a new pod runs, a container with a readiness probe is still not ready, and that has lasted longer than `max(60 s, initialDelay + period × failureThreshold [+ the same for a startupProbe] + 30 s)` (Kubernetes defaults 0 / 10 / 3, so 60 s for a probe with defaults). Pods of the previous ReplicaSet, terminating pods, and containers without a readiness probe are ignored. If listing the pods fails, only the pod evidence is lost. These reasons are not model features.
   - **Policy violations:** the agent also adds one `policy:<feature>` entry for each security-posture weakening the spec introduces **relative to the baseline**: `privileged_added`, `root_user_added` (`runAsUser: 0` / `runAsNonRoot: false`), `capabilities_added`, `host_namespace_added` (hostNetwork/hostPID/hostIPC), `host_path_added`, plus the unit-typo rules `cpu_cut_10x` / `memory_cut_10x` (a container's limit or request falls ≥ 10× vs the baseline **and** to below 50m CPU / 32Mi; a 2–4× rightsizing or `500m → 100m` never trips them). These come from the existing spec-diff features. Because they are judged against the baseline, a violation left in place is reported again on every later change. **A spec is never promoted to baseline while `failure_reasons` is non-empty (including after a follow-up) or its rollout is unfinished**, so a model that rates a posture weakening benign can't make it the restore target.
5. **Predict and publish.** The agent calls `/v1/health/predict`, then XADDs the `HealthEvent` and saves the spec **after** the publish succeeds.
6. **Promote the baseline.** The new spec becomes the baseline only if the model calls it benign and certain **against the current baseline** (re-predicted when the previous spec was not the baseline) **and** its rollout completed: `kubectl rollout status` semantics: observedGeneration is current, `updatedReplicas == spec.replicas`, `status.replicas == updatedReplicas` (no old-ReplicaSet pod left) and `availableReplicas >= updatedReplicas`. A bad image or a crash-looping spec therefore never becomes the restore target.

### Security: ransomware-like file activity

1. **Capture.** The sensor (default) or a single Falco rule, *KubeHeal Data File Activity*, emits file syscalls of `CAPTURED_GROUPS` (read, write, rename, unlink, truncate, chmod) on `kh_data_dirs` (default `/data`) from containers in pods. The rule hooks no `read()`/`write()`: it captures `open`, `openat`, `openat2` and `creat`, and `open_syscall` classifies each by `evt.arg.flags` into `open_w` (write intent: `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, or `creat`) or `open_r`. So `frac_read` and `frac_write` are per-file opens by intent, and `frac_open` is kept as a feature but is always 0 live. A test keeps the rule's `evt.type` list and `CAPTURED_GROUPS` in sync.
2. **Tail.** `FalcoTail` starts at the end of the file and follows rotation and truncation. It punches holes over consumed bytes, so the tmpfs file stays bounded by the unread tail.
3. **Window.** The agent keeps one window per `(namespace, pod)`: at most 512 events within 60 s of the newest event. A new `k8s.pod.uid` for the same name starts a fresh window and cooldown. Pods idle for 300 s are evicted.
4. **Evaluate.** A pod with new events is evaluated on the `EVAL_INTERVAL_S` timer (1 s), or at once when it has `BURST_EVENTS` = 32 new events.
   - **Entropy:** the entropy of the first 16 KiB of up to 8 recently written files, read through `/proc/{pid}/root`. A bounded LRU cache keyed by path and stat signature (device, inode, size, mtime, ctime) skips re-reading unchanged files; ctime cannot be set back, so in-place encryption that restores size and mtime is still re-read. Every path component is opened with `O_NOFOLLOW`, and only regular files are read. Falco reports PIDs from the root PID namespace, so on nested nodes (minikube docker driver, kind) the agent finds a local PID of the container via `/proc/*/cgroup`.
   - **Counters:** on each evaluation the agent samples two counters (at most 32 samples per pod):
     - **Write bytes:** the sum of `wbytes=` in the pod's cgroup v2 `io.stat`, read through `/proc/1/root/sys/fs/cgroup`. Both the systemd and cgroupfs layouts are supported. This counts block-device writes at writeback.
     - **Network-out bytes:** the TX bytes of every interface except `lo` in `/proc/{pid}/net/dev`, which is the pod's network namespace.
   - **Rates:** `write_bytes_per_s` and `net_out_bytes_per_s` are the counter increase between the first and last sample inside the event window, divided by the window length. They are `None` with fewer than 2 samples (a pod's first evaluation), after a counter reset, or when a counter is unreadable.
   - **Features:** `security_features(...)` returns 26 features, and the agent calls `/v1/security/predict`.
5. **Publish.** The agent resolves pod → ReplicaSet → Deployment (cached 300 s, or 30 s after a failed lookup). It publishes when risk ≥ 0.4, with a 60 s per-pod cooldown that a label change bypasses. If scoring fails, the window is re-scored on the next tick.

The agent never kills anything and never fabricates events. Falco events without a namespace, pod or
`evt.type` are dropped.

## Correlation (`kubeheal/correlation.py`)

`compound_score(health, security)` is a deterministic score in [0, 1] with plain-English reasons. It
is 0 unless both events have the same `namespace` and `workload` and `|Δt| ≤ 120 s`. Otherwise it is
the sum of these terms:

| Weight | Term |
|---|---|
| 0.35 | security risk |
| 0.25 | health risk |
| 0.15 | suspicious activity started before or during the degradation |
| 0.15 | degradation **not** explained by a resources, replicas, image, probe, command or args change |
| 0.07 | resource pressure: max of cpu and mem `util_max`, capped at 1 |
| 0.03 | write stress: `files_written_per_s / 10`, capped at 1 |

The score is halved unless security risk ≥ 0.4 **and** health risk ≥ 0.3. A score ≥ 0.6
(`COMPOUND_THRESHOLD`) marks a compound incident.

## Decision policy (`agents/fusion_agent/decision_policy.py`)

The policy is a pure function with every threshold defined as a module constant.
`tests/test_decision_policy.py` pins the table.

- **Adjusted score:** `adj = min(1, risk × TIER × (1.15 if compound))`.
- **Tier multipliers:** prod **1.2**, staging **1.0**, dev **0.7**.
- **Tier source:** fusion reads the namespace label (cached 5 min) and falls back to the name heuristic.
- **Uncertain** means the conformal prediction set is not a single label.

The rules are evaluated in order, and the first match wins:

| # | Decision | Condition |
|---|---|---|
| 1 | **AUTO_KILL** | security label ∈ {ransomware, exfiltration}, not uncertain, security adj ≥ **0.85** |
| 2 | **AUTO_PATCH** (rule) | `failure_reasons` non-empty (failed rollout and/or posture policy violation), spec changed, `has_baseline`, security risk < **0.4**. Applies at any tier and any model confidence. The rationale says `rule: failed rollout (…)`, `rule: policy violation (…)`, or both. |
| 3 | **AUTO_PATCH** (model) | health label ≠ benign, not uncertain, health adj ≥ **0.85**, security risk < **0.4**, `has_baseline` |
| 4 | **HUMAN** | max adj ≥ **0.65** |
| 5 | **HUMAN** | uncertain and max adj ≥ **0.4** |
| 6 | **OBSERVE** | max adj ≥ **0.4** |
| 7 | **BENIGN** | otherwise |

The highest possible dev-tier model score is 1 × 0.7 × 1.15 = 0.805, below every model AUTO_*
threshold. In dev namespaces only the rollback rule can act automatically.

```mermaid
flowchart TD
  IN["event(s) for one namespace/workload<br/>paired when |Δt| ≤ 120 s"] --> ADJ["adj = min(1, risk × tier × compound)<br/>tier: prod 1.2 · staging 1.0 · dev 0.7<br/>compound: ×1.15 if correlation ≥ 0.6"]
  ADJ --> KILL{"security: ransomware or exfiltration,<br/>certain, adj ≥ 0.85?"}
  KILL -- yes --> AK(["AUTO_KILL"])
  KILL -- no --> RULE{"rollback rule:<br/>failure_reasons non-empty,<br/>spec changed, baseline,<br/>security risk below 0.4?"}
  RULE -- "yes (any tier, any confidence)" --> AP(["AUTO_PATCH"])
  RULE -- no --> MODEL{"health: not benign, certain,<br/>adj ≥ 0.85, baseline,<br/>security risk below 0.4?"}
  MODEL -- yes --> AP
  MODEL -- no --> HU1{"max adj ≥ 0.65?"}
  HU1 -- yes --> HU(["HUMAN"])
  HU1 -- no --> HU2{"uncertain and<br/>max adj ≥ 0.4?"}
  HU2 -- yes --> HU
  HU2 -- no --> OB1{"max adj ≥ 0.4?"}
  OB1 -- yes --> OB(["OBSERVE"])
  OB1 -- no --> BE(["BENIGN"])
  AK --> RAILS
  AP --> RAILS
  RAILS["safety rails, in order:<br/>protected namespace → skipped_protected<br/>no pod / no baseline → escalated to HUMAN<br/>kubeheal.io/protected=true → skipped_protected<br/>unknown controller / unsafe baseline → escalated to HUMAN<br/>observe mode → would_kill / would_patch<br/>lock held → skipped_locked<br/>hourly budget spent → skipped_circuit_open"]
```

### Pairing

Fusion keeps unpaired events in memory per workload. An incoming event is paired with the other
kind's pending event if they are at most 120 s apart, and the pair is re-decided with the compound
flag. If the pair yields the same AUTO_* decision that was already executed for the lone partner,
the outcome is `already_handled`. Events older than `MAX_EVENT_AGE_S` (300 s) are acked and skipped.
If the namespace no longer exists (404), there is nothing left to act on: the decision is OBSERVE with
outcome `namespace_gone` (the rationale keeps what the policy alone said), not a HUMAN escalation that
the name-heuristic tier would otherwise produce.

## Actions and safety rails

`FusionAgent.act` applies the steps below in order. Every decision, including dry-run ones, is
published as an `ActionEvent`.

1. **Not automatic** (HUMAN, OBSERVE or BENIGN): outcome `none`.
2. **Protected namespace** (built-in set or `EXTRA_PROTECTED_NAMESPACES`): `skipped_protected`.
3. **AUTO_KILL without a pod name**: decision becomes HUMAN, `escalated_no_pod`. **AUTO_PATCH without a readable baseline**: HUMAN, `escalated_no_baseline`.
4. **Target state.**
   - **Kill:** read the pod and the event's workload Deployment in parallel (pod 404 gives `pod_already_gone`; a different UID than the event's gives `skipped_stale_pod`). Resolve the pod's controller from its `controller=true` ownerReference: ReplicaSet → its Deployment (the mapping is cached 5 min; the Deployment is still read fresh), StatefulSet / DaemonSet / Job as themselves, a bare pod is its own target. Any other controller kind (for example an Argo Rollout) cannot be checked: HUMAN, `escalated_unknown_owner`. If the pod, its controller or the event's Deployment has `kubeheal.io/protected=true`: `skipped_protected`.
   - **Patch:** read the Deployment (404 gives `workload_gone`). If it is protected: `skipped_protected`. The baseline comes from Redis, which other pods can reach, so it is validated, never trusted: it must be a pod template whose labels match the Deployment's `matchLabels` (a `matchExpressions` selector always escalates), and it must not weaken posture against the live template (the health agent's `policy_violations`: privileged, root, added capabilities, host namespaces, hostPath, 10x resource cuts). Otherwise HUMAN, `escalated_unsafe_baseline`.
5. **Observe mode**: `would_kill` or `would_patch`. Nothing changes.
6. **Incident lock** `kubeheal:lock:{ns}:{Kind}/{name}`, on the controller, so every pod of one DaemonSet shares it. If it is held elsewhere: `skipped_locked`.
7. **Circuit breaker** (checked under the lock, so there is no TOCTOU race). If `MAX_KILLS_PER_HOUR` or `MAX_PATCHES_PER_HOUR` successful actions already hit this controller in the hour: `skipped_circuit_open`. Only `pod_killed` and `patched` are counted, so timeouts, 404s and 409s do not spend the budget.
8. **Act.**
   - **AUTO_KILL:**
     1. XADD `{pod_uid, namespace, pod, event_id, ts_ms}` to `kubeheal.contain`, concurrently with the steps below: the security agent on the pod's node freezes its cgroup within milliseconds. Best effort: it never delays the kill by more than 1 s and a Redis error never fails it. `ActionEvent.containment` is `requested` or `failed`; metric `kubeheal_fusion_containment_total{result}`.
     2. Label the pod `kubeheal.io/quarantined=true`. The patch carries `metadata.uid`, so a successor that reuses the name gets 409 (`skipped_stale_pod`).
     3. Create the NetworkPolicy `kubeheal-quarantine-{pod}` (concurrently with step 2). It selects the quarantine label, denies all ingress and egress, and has an `ownerReference` to the pod, so it is garbage-collected with the pod. A 409 from an earlier attempt is fine.
     4. Only then delete the pod with grace period 0 and a UID precondition (the UID read in step 4), so the pod is never alive without isolation.
     5. Count the success in the breaker. Outcome: `pod_killed`.
   - **AUTO_PATCH:**
     1. JSON-patch `replace /spec/template` with the baseline template.
     2. Also `replace /spec/replicas` when `changed_fields` contains `replicas`.
     3. Count the success. Outcome: `patched`. The health agent then sees the baseline spec and records it without an assessment.
9. **Kubernetes errors.** A call that takes longer than 10 s gives `failed:kube_timeout`. An API error gives `failed:api_{status}_{reason}`.

### Sequence: ransomware-like activity → AUTO_KILL

```mermaid
sequenceDiagram
  autonumber
  participant W as Workload pod
  participant F as Falco
  participant SA as security-agent (same node)
  participant INF as inference
  participant R as Redis
  participant FU as fusion-agent
  participant K as kube-apiserver

  W->>F: openat / write / rename / unlink on /data
  F->>SA: JSON line (evt.type, fd.name, fs.path.*, proc.pid, k8s.pod.*)
  Note over F,INF: append to the pod window (max 512 events, last 60 s)
  loop 1 s timer (EVAL_INTERVAL_S) or 32 new events, pods with new events
    Note over F,INF: entropy of up to 8 recently written files via /proc/{pid}/root
    Note over F,INF: sample pod cgroup io.stat wbytes and<br/>netns TX bytes (/proc/{pid}/net/dev)
    SA->>INF: POST /v1/security/predict {26 features}
    INF-->>SA: label ransomware, risk, conformal set, top 5 SHAP factors
  end
  SA->>K: pod → ReplicaSet → Deployment (cached 5 min)
  SA->>R: XADD kubeheal.security.events + HSET kubeheal:security:{id} (risk ≥ 0.4, 60 s cooldown)
  R->>FU: XREADGROUP group fusion
  Note over R,FU: pair with a health event of the same<br/>ns/workload within 120 s, compound score
  FU->>K: GET namespace (kubeheal.io/namespace-tier, cached 5 min)
  Note over R,FU: decide(): certain ransomware, security adj ≥ 0.85 → AUTO_KILL
  FU->>K: GET pod ∥ GET event's Deployment, then the controller chain (RS cached 5 min)
  Note over FU,K: kubeheal.io/protected on pod or controller → skipped
  FU->>R: SET NX kubeheal:lock:{ns}:{Kind}/{name} (10 s TTL, owner-checked heartbeat)
  FU->>R: GET kubeheal:cb:kill:{ns}:{Kind}/{name} (< MAX_KILLS_PER_HOUR)
  FU->>R: XADD kubeheal.contain {pod_uid, …} → node's security agent freezes the cgroup
  FU->>K: PATCH pod label kubeheal.io/quarantined=true (uid precondition) ∥ CREATE deny-all NetworkPolicy
  FU->>K: DELETE pod (grace 0, uid precondition) → policy garbage-collected with it
  FU->>R: INCR kubeheal:cb:kill:{ns}:{Kind}/{name}
  FU->>R: SET NX kubeheal:done:{event_id} (outcome)
  FU->>R: MULTI: XADD kubeheal.actions (AUTO_KILL, pod_killed) + XACK
```

### Sequence: config drift → health assessment → AUTO_PATCH (rule path and model path)

```mermaid
sequenceDiagram
  autonumber
  actor U as Operator / CI
  participant K as kube-apiserver
  participant HA as health-agent
  participant P as Prometheus
  participant INF as inference
  participant R as Redis
  participant FU as fusion-agent

  U->>K: change Deployment spec (patch / apply)
  K-->>HA: watch MODIFIED
  Note over HA,P: canonical_spec + spec_hash differ → (re)start the ASSESS_DELAY_S timer
  Note over HA: ASSESS_DELAY_S = 60 s later, or earlier on a posture violation or failed rollout (a newer change restarts the clock)
  HA->>R: GET kubeheal:spec and kubeheal:baseline
  alt new spec equals the baseline (restore or rollback)
    HA->>R: SET kubeheal:spec, no assessment
  else real spec change
    HA->>P: query_range, 11 raw metrics<br/>[change, assess time], step 15 s
    HA->>K: list pods by selector → failure_reasons<br/>(new pods: ImagePullBackOff, CrashLoopBackOff, OOMKilled, ...)
    HA->>INF: POST /v1/health/predict {24 spec-diff + 12 metric features}
    INF-->>HA: label, risk, conformal set, top 5 SHAP factors
    HA->>R: XADD kubeheal.health.events<br/>(changed_fields, has_baseline, failure_reasons)
    HA->>R: SET kubeheal:spec, SET kubeheal:baseline only if<br/>benign + certain vs baseline and rolled out
    R->>FU: XREADGROUP group fusion
    alt rule path
      Note over INF,FU: failure_reasons non-empty, spec changed,<br/>baseline, security risk < 0.4 → AUTO_PATCH
    else model path
      Note over INF,FU: certain non-benign, health adj ≥ 0.85,<br/>security risk < 0.4, baseline → AUTO_PATCH
    else neither
      Note over INF,FU: HUMAN / OBSERVE / BENIGN, nothing changes
    end
    opt AUTO_PATCH and KUBEHEAL_MODE=enforce
      FU->>R: GET kubeheal:baseline
      FU->>K: GET Deployment (kubeheal.io/protected?)
      FU->>R: lock + INCR kubeheal:cb:patch:{ns}:{workload}<br/>(≤ MAX_PATCHES_PER_HOUR)
      FU->>K: JSON-patch replace /spec/template (and /spec/replicas if it changed)
      K-->>HA: watch MODIFIED, spec equals baseline → recorded, not assessed
    end
    FU->>R: XADD kubeheal.actions, then XACK
  end
```

## Runtime configuration

Every environment variable a manifest sets is read by code, and every variable the code reads is
listed here.

| Env var | Code default | Manifest | Read by |
|---|---|---|---|
| `REDIS_URL` | `redis://redis-master.kubeheal.svc:6379/0` | from Secret `kubeheal-redis` `<user>-url` (per-component ACL user) | health, security, fusion, dashboard |
| `INFERENCE_URL` | `http://kubeheal-inference.kubeheal.svc:8000` | same (health, security) | health, security |
| `PROMETHEUS_URL` | `http://prometheus-operated.monitoring.svc:9090` | same | health |
| `ASSESS_DELAY_S` | `60` | `60` | health; `drift_lab.py` imports it |
| `WATCH_NAMESPACES` | empty = all | not set | health (one watch per namespace), security (filter) |
| `EXTRA_PROTECTED_NAMESPACES` | empty | `falco,monitoring` | health, security, fusion |
| `FALCO_EVENTS_PATH` | `/var/run/falco/events.jsonl` | `/var/run/kubeheal/events.jsonl` (shared `events` volume: the sensor's emptyDir, or Falco's hostPath with `components/falco-source`) | security |
| `CGROUP_ROOT` | `/host/sys/fs/cgroup` | `/host/sys/fs/cgroup` (host cgroup v2, read-write) | security (containment: `cgroup.freeze`) |
| `PROC_ROOT` | `/proc` | `/host/proc` | security |
| `EVAL_INTERVAL_S` | `1` | `1` | security (timer; a pod with 32 new events is scored at once) |
| `KUBEHEAL_CAPTURE` | `0` | `0` (`run_lab.sh` sets `1` for a run) | security |
| `KUBEHEAL_MODE` | `observe` (unknown values fall back to observe) | `enforce` | fusion |
| `MAX_KILLS_PER_HOUR` / `MAX_PATCHES_PER_HOUR` | `3` / `5` | `3` / `5` | fusion (per controller) |
| `HOSTNAME` | `socket.gethostname()` | set by Kubernetes | fusion (consumer name) |
| `KUBEHEAL_MODEL_DIR` | `models` (the image's `/app/models`) | not set | inference |
| `DASHBOARD_ALLOWED_HOSTS` | `localhost,127.0.0.1,kubeheal-dashboard` and its `.kubeheal`, `.svc`, `.svc.cluster.local` names | not set | dashboard (Host header allow-list) |
| `LOG_LEVEL` | `INFO` | `INFO` | all |

The toolchain is Python 3.13 and uv, with a single `pyproject.toml` and `uv.lock`. There is one extra
per image (`inference`, `agents`, `dashboard`, plus `training`). The inference, agents and dashboard
images build a uv-managed standalone CPython plus `uv sync --frozen --no-dev --no-editable --extra <x>`
(bytecode compiled), prune what is never imported (CPython tests/IDLE/Tk/pip, the duplicate libpython
`.so`, `-O` bytecode, stubs, headers, packages' `tests/`) and copy the result into
`gcr.io/distroless/cc-debian12` (glibc, libstdc++, libgomp for LightGBM, plus zlib copied in for numpy).
There is no shell in them: debug with `kubectl debug --image=busybox --target=<container>`. They run
as uid 10001, except the security agent (uid 0, see RBAC). The chaos image stays on `python:3.13-slim`
because its init container runs `sh -c`.

| Image | Before (`python:3.13-slim`) | After (distroless) |
|---|---|---|
| `kubeheal/inference:v5` | 537 MB (409 MB layers) | 412 MB (311 MB layers); scipy, a hard dependency of lightgbm, is 100 MB of it |
| `kubeheal/agents:v5` | 368 MB (289 MB layers) | 282 MB (221 MB layers) |
| `kubeheal/dashboard:v5` | 331 MB (253 MB layers) | 249 MB (188 MB layers) |

Sizes are `docker image inspect` on a containerd-snapshotter docker (compressed + unpacked) and the
sum of the unpacked layers, measured 2026-10-17.

## Ports, probes and metrics

| Component | Port | Probes | Healthy means | Metrics |
|---|---|---|---|---|
| inference | 8000 | liveness `/healthz`, readiness `/readyz` | Process up; ready = both bundles loaded | `kubeheal_inference_*` |
| health-agent | 8080 | startup (5 s × 60) + liveness `/healthz` | Every watch loop active within the last 420 s | `kubeheal_health_assessments_total{outcome}`, `_watch_errors_total` |
| security-agent | 8080 | startup + liveness `/healthz` | Tail and eval loops ticked within max(60 s, 6 × `EVAL_INTERVAL_S`) | `kubeheal_security_falco_events_total`, `_evaluations_total{outcome}` |
| fusion-agent | 8080 | startup + liveness `/healthz` | Progress (a poll, an entry processed or a Kubernetes call returned) within the last 30 s | `kubeheal_fusion_decisions_total`, `_outcomes_total`, `_deadlettered_total`, `_stale_events_total`, `_containment_total{result}` |
| dashboard | 8080 | liveness `/healthz`, readiness `/readyz` | Ready = Redis answered within 10 s | none |
| redis | 6379 | readiness `redis-cli ping`, liveness TCP | n/a | n/a |

The agents serve `/healthz` only after Redis answers, which is why they have the long startup probe.

### Resources

Measured with `kubectl top` while the lab collection (`training/collect/`) was running, so these are an
upper bound. Requests ≈ p95; limits ≥ 2 × requests and memory limits ≥ 1.5 × peak. The 500m CPU limits
are kept so Python startup (imports) is not throttled during rollouts.

| Component | Observed CPU / memory (peak) | Requests | Limits |
|---|---|---|---|
| inference (×1 dev, 2–6 prod) | 8m / 89Mi per replica | 10m / 96Mi | 500m / 192Mi |
| health-agent | 11m / 91Mi | 15m / 96Mi | 500m / 192Mi |
| security-agent (per node) | 126m / 119Mi | 150m / 128Mi | 500m / 256Mi |
| fusion-agent | 5m / 83Mi | 10m / 96Mi | 500m / 192Mi |
| dashboard | 5m / 48Mi | 10m / 64Mi | 500m / 128Mi |
| redis | 34m / 43Mi (`used_memory` ≤ 38M) | 40m / 64Mi | 500m / 320Mi (above `--maxmemory 256mb`) |
| Falco (Helm) | 1.9 CPU / 294Mi under lab load | 100m / 256Mi | 2 / 1Gi (1 CPU was throttled and OOMKilled) |

Falco traces only the syscalls its one rule needs (`base_syscalls.custom_set` + `repair: true` in
`deploy/k8s/helm/falco-values.yaml`): 38 syscalls instead of the 87 of its default state set (`all: false`). The
dropped ones are socket, accept, connect, bind, epoll, eventfd, pipe, mount and similar. `read` and
`write`, which dominate the volume, are dropped too: the rule matches opens, renames, unlinks,
truncates and chmods only (Tier 1).

Measured with `deploy/scripts/bench.sh` (same bench, minikube 8 CPU / 8 GB, 300 s heavy-I/O load: a
64 MiB `dd`/`cp` loop):

| | before (read/write hooked) | after (Tier 1) |
|---|---|---|
| Falco CPU p50 / max | 1985m / 1987m | 53m / 253m |
| Falco memory p50 | 565 Mi | 209 Mi |
| Falco events file growth | 822 KB/s | 9.6 KB/s |
| Security agent CPU p50 | 73m | 9m |
| Security agent memory p50 | 94 Mi | 83 Mi |

Before, Falco was saturated under that load and dropped events; kills arrived a median ~144 s after the
workload started. After Tier 1 the pipeline publishes a window ~5 s after pod start with no drops.

Final bench before the hard-negative hardening (security model `security-5.0.0-a49c7ed8`, 300 s load, 5 runs; kill time counts from the
workload's first malicious operation, which the workload logs):

| | previous bench (interim model) | final bench |
|---|---|---|
| Falco CPU p50 / max | 60m / 135m | 49m / 49m |
| Falco memory p50 | 212 Mi | 195 Mi |
| Security agent CPU p50 / max | 10m / 26m | 8m / 9m |
| Security agent memory p50 | 88 Mi | 84 Mi |
| Inference CPU p50 / max (total) | 6m / 15m | 6m / 6m |
| Falco events file growth / unread backlog | 8.0 KB/s / 3.1 MB | 8.9 KB/s / 2.7 MB |
| Kill time at 20 files/s, per run | 9.6, 8.8, 8.8, 9.5, 9.5 s | 2.26, 2.23, 2.12, 2.34, 2.25 s |
| Kill time at 180 files/s (default), 3 runs | not measured | 0.65, 0.67, 0.72 s |

At 20 files/s the first security event arrives 2.1 to 2.3 s after the first overwrite and the kill follows
45 to 65 ms later, so the latency is the time to the first confident event. The workload creates its files
and starts encrypting at once, so setup events fill the pod window and the model needs its 64-event recent
tail to fill with encryption events. With the lab's 65 s quiet gap before encryption the same 20 files/s workload is killed in
0.26 s and 0.75 s (2 runs). Lowering the latency for the no-gap case needs a model or feature change (more lab
runs without a quiet gap, or a shorter `RECENT_EVENTS`), not a policy change.

Bench of the shipped bundle `security-5.0.0-c6fa12d8` (new lab data with gaps of 0 to 80 s, rename-kind features, hard negatives including
start-up bursts; 120 s load, 5 runs at 20 files/s, 3 runs at 180 files/s): kill time 0.46, 0.70, 0.56, 0.55, 0.47 s at 20 files/s and 0.75, 0.55, 0.64 s
at 180 files/s (previous bundle `ca2438d3`: 8.7 to 9.0 s and 1.17 to 1.34 s). The back-to-back no-gap case is no longer slow, so the paragraph above
describes the previous bundle. Three benign pods rewriting config through temp-file + rename (about 80 per second each) and three benign pods
rotating logs with gzip (60 s, prod-tier namespace, not protected) produced no AUTO_KILL. Details and the variant table in
[docs/models-and-data.md](models-and-data.md#rename-kind-features-variants-a-to-d).

### Scaling

The per-cluster components are flat: inference, health agent, fusion agent, Redis (and the dashboard in
dev) do not grow with the node count, roughly 0.1 CPU and ~0.5Gi in requests in total. Only inference
scales with load: the production overlay (`deploy/k8s/overlays/production`) runs it at 2–6 replicas
behind a CPU HPA and a PDB. The per-node cost is Falco plus the security agent, one of each per node:
150m / 128Mi + 100m / 256Mi in requests, and up to 126m / 119Mi + 1.9 CPU / 294Mi measured under lab
load (table above). Falco dominates and scales with file-syscall volume on `kh_data_dirs`, not with
node count. In production both security components run at PriorityClass `kubeheal-security`, and the
DaemonSet rolls 10% of nodes at a time.

## RBAC (`deploy/k8s/base/rbac/rbac.yaml`)

Each component has its own ServiceAccount and ClusterRole, and only fusion can change anything.

| ServiceAccount | Permissions |
|---|---|
| `kubeheal-health` | `apps/deployments`: get, list, watch. `pods`: list (rollout-failure evidence for `failure_reasons`). `autoscaling/horizontalpodautoscalers`: list (replicas an HPA owns are not drift; without it the agent logs a warning and treats scaling as drift). |
| `kubeheal-security` | `pods`: get. `apps/replicasets`: get. These are needed for owner resolution. |
| `kubeheal-fusion` | `pods`: get, patch, delete. `namespaces`: get (tier label). `apps/deployments`: get, patch. `apps/replicasets`, `apps/statefulsets`, `apps/daemonsets`, `batch/jobs`: get (pod to controller: protected check, lock and breaker key). `networking.k8s.io/networkpolicies`: create. |
| `kubeheal-dashboard` | none (`automountServiceAccountToken: false`) |
| inference, redis | no token mounted |

Container hardening: every container runs with `RuntimeDefault` seccomp, a read-only root filesystem,
`allowPrivilegeEscalation: false` and all capabilities dropped. The security agent is the exception:
it runs as uid 0 with `hostPID`, adds `SYS_PTRACE` and `DAC_READ_SEARCH` to read other containers'
files through `/proc/{pid}/root`, mounts `/proc` read-only and mounts the Falco directory writable
(for hole punching).

## Failure handling

- **Delivery.**
  - **Acks:** fusion uses a consumer group created at `$` with MKSTREAM, so a fresh deploy never replays history. It acks only after an event is handled successfully, in the same MULTI as the `ActionEvent` publish.
  - **Idempotency:** the outcome is stored at `kubeheal:done:{event_id}` before publishing, so a redelivery after a failed publish or XACK republishes it instead of patching or killing twice. Only a crash between the action and that one `SET` can repeat an action; the repeat is then harmless (the pod is gone → `pod_already_gone`; re-patching the same template is a no-op).
  - **Retries:** an unacked entry is re-claimed with `XAUTOCLAIM` after 60 s idle.
  - **Dead-lettering:** malformed entries go to `kubeheal.deadletter` immediately, and entries that fail 3 deliveries go there too. Both are then acked.
- **Redis restarts.** Redis is ephemeral. On `NOGROUP`, fusion recreates the group and keeps consuming. At startup fusion removes idle consumers of earlier pods that have nothing pending. Every other Redis error in fusion's loop (OOM, timeouts) is logged and retried after 1 s, never a crash loop; a dead-letter write that fails leaves the entry pending for a later retry. Agents wait for Redis at startup with backoff (30 attempts). The health agent re-learns baselines on first sight.
- **Single consumer.** The fusion Deployment has one replica with `strategy: Recreate`. Agents exit on SIGTERM (`agents/common.run`), so a terminating pod never consumes alongside its replacement. The pairing buffer is in memory: a restart forgets unpaired events, which were already decided alone.
- **Inference down.**
  - **Health:** the spec stays unsaved and is re-assessed after 60 s. No fake assessment is published.
  - **Security:** the window is re-scored on the next tick.
  - **Inference:** the service itself reports 503 instead of guessing.
- **Prometheus partially down.** Failed queries are logged, and those metrics are missing (`None`). They are never set to 0.
- **Kubernetes API.** A watch that fails reconnects with exponential backoff (1 s to 60 s). A 410 (expired `resourceVersion`) triggers a re-list. Every fusion API call has a 10 s timeout.
- **Falco.** If the events file is missing, the agent waits for it and reads it from the beginning once it appears. It follows rotation (inode change, draining the old file first) and truncation. A line with no newline within 1 MiB is dropped. If the file is not writable, hole punching is disabled and a warning is logged.

## Why v5 (what was wrong with v4)

v5 replaced the v4 deep-model stack (GATv2 + BiLSTM health model, Transformer + Conv1D security model,
a learned correlation module and three torch model servers). An audit had found these problems:

1. Serve-time inputs never matched training inputs. Specs arrived snake_case instead of camelCase, metrics were scaled 1e3 to 1e9× differently, six metric columns were always 0 in training, and synthetic syscall events entered the live path. The live health score was noise.
2. One of the four health classes had zero samples, and about 430 pre-drift rows (spec unchanged) were labelled harmful.
3. Random row splits over roughly 140 unique spec pairs leaked between train and validation, so the reported F1 of 0.80 was optimistic.
4. The security data was trivially separable by tokens (`.locked`, fixed lengths, entropy ranges per label), so its F1 of 1.0 meant nothing.
5. The conformal threshold was calibrated on training data and then never used. The "SHAP" was a metric mean deviation, and the causal-chain timestamps were hard-coded.
6. AUTO-KILL created a namespace-wide egress NetworkPolicy that cut DNS for every pod and was never removed.
7. There were no protected namespaces. One shared ClusterRole could delete pods, Deployments and namespaces cluster-wide.
8. The security agent `os.kill`-ed PIDs from a stale cache keyed without the node, and an inverted check fired on most processes.
9. AUTO-PATCH read a baseline key that nothing wrote. It never worked.
10. Model servers fell back to random weights on a failed load and still reported ready. The export gates passed when reports were missing.
11. Fusion never fused: the join keys of the two agents never matched, the consumer group replayed history, failed events were acked, and the lock token was constant.
12. Seven environment knobs in the manifests were read by no code.
13. Three multi-GB torch images served models that run in about 5 ms. Streams had no MAXLEN, and the agents blocked their event loops.
14. `torch==2.2.0` could not install on Python 3.13. The demo scripts exited non-zero on success. The 44 tests passed without testing the train/serve contract.

v5 answers these with engineered features shared by training and serving, LightGBM, real
split-conformal sets, exact TreeSHAP, a single torch-free inference service, least-privilege RBAC, a
pod-scoped quarantine, a working baseline, and contract tests.

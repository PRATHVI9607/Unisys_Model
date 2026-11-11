# V5 integration plan

Status: ANALYSIS ONLY. Nothing from v5 has been ported, merged or run. Waiting for the owner's decisions (section 8).

## 0. Basis and rules of this document

- Source analysed: `origin/main` at `48a59aa` ("model built almost done", an empty-diff commit; the content tip is `7d5844b`), fetched 2026-11-11 (fetch only, no pull into any local branch). Merge base with our `main` and `work` is `b419053`. 32 commits (2026-11-06 to 2026-11-11), 269 files changed against `main`. The tree was extracted read-only with `git archive` into a scratch directory and read there.
- Method: reading code, docs, manifests and the shipped model metadata. No v5 code, test, script or model was executed by us. Every v5 number below is a quotation with its source file. None is a measurement of ours. Where v5's own documents disagree with each other or with its manifests, that is stated in section 9.
- Decision already made by the owner: OUR architecture is final (Executor as the only writer, kill switch, audit ledger, recovery, Helm, approvals). v5 is a source of improvements, not a replacement. v5 cannot be merged: it deleted the v4 layout (`k8s/`, `services/`, `dockerfiles/`, `models/*`, `.claude`, demo) and restructured into `kubeheal/`, `deploy/`, `sensor/`, `training/`. Porting means taking ideas and selected files.
- Our invariants, used below to judge conflicts:
  - I1 No Kubernetes write outside `agents/executor/`; every write passes `actions._write` and its kill-switch gate.
  - I2 Kill switch is the ConfigMap `kubeheal-mode` (`test` default and fail-safe, `enforce`), watched, per-namespace label can only be stricter, every change in the ledger.
  - I3 Append-only ledger (MinIO, object lock) with the failure policy of P7-RR-10; recovery (rolling snapshots, restore, scan) in the Executor.
  - I4 Fusion decides with the pure `decision_policy.py` (fail closed on missing or invalid input); HUMAN decisions go through the approval flow.
  - I5 Golden baseline written once with SET NX; only the documented tool replaces it.
  - I6 Deploy with the Helm chart `deploy/helm/kubeheal`; demo only under `demo/`.
  - I7 Every cluster command uses `--context k3d-kubeheal`; never delete user data; no training or data collection without the owner's go.

## 1. What v5 is (one paragraph)

v5 is a teammate's rewrite of the whole project around two LightGBM classifiers (health and security) behind one FastAPI inference service, with features computed by a single shared module (`kubeheal/features/`) used identically by training, the lab collectors and the live agents. It adds a rule-based rollback path, a Rust/libbpf eBPF sensor that replaces Falco as the default event source, a deterministic correlation formula instead of a learned correlation module, kustomize manifests with a Redis ACL and AOF persistence, a training pipeline with grouped splits and gates, lab datasets collected on a minikube node, and a live evaluation driver with a recorded scorecard. Fusion acts on the cluster itself (no Executor, no ledger, no snapshot recovery). Source: `README.md`, `docs/architecture.md`.

## 2. Inventory of v5 improvements, grouped

Legend. Port: Yes (take with light adaptation), Adapt (take the idea, rewrite for our design), Optional, No. Effort: S, M, L. Task IDs refer to section 7.

### A. Detection logic (health)

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Canonical spec (camelCase, empty values dropped) and `spec_hash`; only a changed hash counts; status-only updates ignored | `agents/health_agent/agent.py` `on_event`, `kubeheal/features/quantity.py` | `agents/health_agent/agent.py`, `baseline.py` `drift_view` | Adapt | S | We already exclude `replicas` from `drift_view`. v5 excludes it only while an HPA targets the Deployment (HPA list every 30 s). Ours excludes it always. Keep ours unless the owner wants replica drift when no HPA exists. |
| Debounce: one timer per workload, `ASSESS_DELAY_S` 60 s, a newer change restarts it but never later than the delay after the first pending change; earlier assessment on a posture violation or failed rollout (polled every 2 s) | `agent.py` `schedule`, `_poll`, `_fire` | Our Health Agent has a 300 s per-Deployment cooldown and assesses on the event | Adapt | M | Changes when evidence is taken. Interacts with our P6-D2 (OBSERVE rescheduling, branch `wip/docs-p6d2`). Decide together. V5-D4 |
| Follow-up `HealthEvent` for the same spec when a failure reason appears later (confirmed on two polls, at most once per reason) | `agent.py` `_track` | Health Agent publish path; Fusion pairing | Adapt | M | Needs idempotency per spec in Fusion/Executor (we have action markers). V5-D4 |
| Full list plus watch from the list's `resourceVersion`; re-list on 410; drop state for vanished Deployments; at most 8 concurrent assessments | `agent.py` `watch_loop`, `relist` | Our `watch_deployments` | Adapt | S | Check our 410 handling first; take only the gaps. V5-D4 |
| Metric window `[change seen, assess time]` at 15 s step, the same function used by the lab collector | `agents/health_agent/prometheus.py` | `metric_queries.py`, `prometheus_client.py` (60 steps of 5 s, 15 channels) | Optional | M | Only relevant if models change (section 6). Our window and channel set are tied to our current model. |
| Missing metric is `None`, never 0 | `kubeheal/features/health.py` | We already flag missing metrics and use width 1.0 | No | n/a | Equivalent. |

### B. Rule-based rollback and posture policy

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| `policy_violations(base, spec)`: privileged added, root user added, capabilities added, host namespaces, hostPath, and `cpu_cut_10x` / `memory_cut_10x` (limit or request falls 10x or more AND below 50m CPU / 32Mi) judged against the baseline | `agent.py` `policy_violations`, `_resource_cut`; constants `CUT_FLOORS` at `agent.py:76` | New pure module in `agents/health_agent/`; result carried on the Health event | Yes | M | Boundary fact from the code: the test is `now < floor` with floor 0.05 cores, so a request and limit of exactly `50m` (our demo drift, 500m to 50m) does NOT trip `cpu_cut_10x`. Floor and strictness are owner decisions. V5-D2 |
| Rule path in the policy: `failure_reasons` non-empty, spec changed, baseline present, security risk below 0.4 gives AUTO_PATCH at any tier and any model confidence | `agents/fusion_agent/decision_policy.py` rule 2 | `agents/fusion_agent/decision_policy.py` (pure, reserved file) | Adapt | M | Our policy gates every automatic action on both CI widths (`CI_WIDTH_LIMIT` 0.15), burn-in, `models_ok`, protected label and breakers. A rule that bypasses model confidence is a policy change. Proposal: rule path allowed to bypass the CI width and burn-in only, never the kill switch, protected label, breakers, `models_ok`-independent checks, canary or Executor validation. Owner decision D2. V5-D3 |
| Baseline safety validation before restore: pod template labels match the Deployment selector (`matchExpressions` always escalates), baseline must not weaken posture against the live template | `agents/fusion_agent/agent.py` (target state, patch) | `agents/executor/validation.py` | Yes | S | Strengthens our Executor; no conflict. V5-D6 |

### C. `failure_reasons`

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Kubernetes evidence the new spec cannot run: waiting reasons (`ImagePullBackOff`, `ErrImagePull`, `InvalidImageName`, `CrashLoopBackOff`, `CreateContainerConfigError`, `CreateContainerError`, `RunContainerError`), `OOMKilled`, `ProgressDeadlineExceeded`, `ReadinessNeverPassed` | `agent.py` `pod_failure_reasons`, `readiness_never_passed`, `progress_deadline_exceeded` | Health Agent; new field on our health event | Yes | M | Needs RBAC `pods list` and `horizontalpodautoscalers list` for the Health Agent (read only). Must stay in `k8s/rbac/` and the Helm RBAC template in step; `tests/test_rbac_*` must agree. V5-D1 |
| Pod ownership: keep only pods owned by the Deployment's ReplicaSets, created at or after the change (5 s slack) | `agent.py` `owned_by` | same | Yes | S | Part of V5-D1. |

### D. Baseline promotion

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Baseline set on first sight, then promoted when the model calls the new spec benign and certain relative to the current baseline AND the rollout completed (`kubectl rollout status` semantics); never promoted while `failure_reasons` is non-empty | `agent.py` `_promote`, `rollout_complete` | `agents/health_agent/baseline.py`, `scripts/baseline_tool.py` | Adapt | M | Conflicts with invariant I5 (golden baseline written once, never overwritten). Our open item P7-RR-11 (re-baseline after a restore changed the claim name and image digest) needs some promotion mechanism anyway. Proposal: keep golden immutable, add a separate `candidate` record that v5's promotion rule can fill, promotion to golden only by approval (dashboard) or the documented tool. Owner decision D3. V5-D5 |
| `rollout_complete` helper | `agent.py:92` | Executor canary and restore (P7-RR-2, RR-11) | Yes | S | Reuse in V5-D5 and P7-RR-11. |

### E. eBPF sensor

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Rust + libbpf sensor, `lsm/` hooks (fallback `fexit/`) on `file_open`, `path_rename`, `path_unlink`, `path_truncate`, `file_truncate`, `path_chmod`; kernel-side filter (pod cgroups, `/data/` prefix, namespace `kubeheal` excluded); writes Falco-shaped JSON lines to a shared emptyDir | `sensor/` (`src/main.rs`, `src/pods.rs`, `src/render.rs`, `src/bpf/sensor.bpf.c`, `Dockerfile`, `README.md`) | Optional event source beside our Falco consumer / replay (`agents/security_agent/falco_client.py`) | Optional | L | Output is Falco-shaped, so our consumer may read it unchanged (to verify field by field against `falco_client.py`). Sensor needs BTF, `bpf_loop` (kernel 5.17 or newer), the `bpf` LSM active, x86_64 (README "Privileges", "Limits"). Our AGENTS.md notes Falco eBPF is unreliable in Docker Desktop on Windows; the same limitation is expected for the sensor and was NOT verified. Its measured results were taken on a CachyOS kernel (README "Measured"). Adds `BPF` and `PERFMON` capabilities to a DaemonSet container (security review needed). Cannot be verified on this machine; needs a Linux lab host. V5-S4 |

### F. Falco rules

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| One rule, "KubeHeal Data File Activity": opens (flags give read or write intent), renames, unlinks, truncates, chmods on `/data` only, pods only, namespace `kubeheal` excluded; no `read()` or `write()` hooks; Falco `base_syscalls.custom_set` limited set | `deploy/k8s/falco-kubeheal-rules.yaml`, `deploy/k8s/helm/falco-values.yaml` | `k8s/falco-kubeheal-rules.yaml`, `k8s/falco.yaml` | Adapt | S | Compare rule by rule with ours. Our model's token set must match the captured syscalls (v5 keeps a test that syncs the rule's `evt.type` list with `CAPTURED_GROUPS`; adopt that test idea). Falco is not installed on our k3d cluster, so no live check. V5-S1 |

### G. Entropy and counters

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Entropy of the first 16 KiB of up to 8 recently written files via `/proc/{pid}/root`; every path component opened with `O_NOFOLLOW`, regular files only; bounded LRU cache keyed by device, inode, size, mtime, ctime | `agents/security_agent/agent.py` | `agents/security_agent/entropy_sampler.py` (30 samples 2 s apart via `/proc/<pid>/fd`) | Adapt | S/M | Take the `O_NOFOLLOW`, regular-file and stat-signature cache hardening. Do not change the sampling design that our Conv1D-SE model consumes. V5-S2 |
| Write bytes per second from the pod cgroup v2 `io.stat` `wbytes`; network-out bytes per second from `/proc/{pid}/net/dev` | `agents/security_agent/agent.py` | New counters on the Security event | Optional | M | Useful only if the security model consumes them (they are features of v5's model). Needs host cgroup mount. Decide after the model choice. V5-S3 |
| Window per `(namespace, pod)`: at most 512 events within 60 s; fresh window on a new pod UID; eviction after 300 s idle; scoring on a 1 s timer or 32 new events | `agents/security_agent/agent.py` | `syscall_window.py` | Adapt | S | Compare with ours; our D-5 replay path does not yet emit a Security event (open item), so check windowing there first. |

### H. Correlation

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Deterministic `compound_score`: zero unless same namespace and workload and within 120 s; weighted sum (0.35 security risk, 0.25 health risk, 0.15 onset before degradation, 0.15 degradation not explained by a config change, 0.07 resource pressure, 0.03 write stress), halved unless both sides are elevated; compound at 0.6 or more | `kubeheal/correlation.py` | Our learned DCM (`models/dcm`, server, `correlation_score`, `compound_flag`) | Optional | S | The formula is deterministic and explainable. Our DCM reports `best_val_auroc` 0.9556 (`models/dcm/checkpoints/dcm_report.json`) on generated pairs. Port the formula as a fallback and as a comparison baseline in the evaluation, not as a replacement. V5-M5 |

### I. Fusion and action path (reference only, our Executor stays)

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Idempotency marker per consumed event (`SET NX`), XAUTOCLAIM after 60 s, dead-letter after 3 deliveries, consumer cleanup | `agents/fusion_agent/agent.py` | `agents/common/stream_reliability.py`, P6-R1, Executor markers | No | n/a | We have equivalents. Compare in review only. |
| Quarantine as pod label patch with `metadata.uid` precondition plus deny-all NetworkPolicy with an ownerReference to the pod (garbage collected with the pod); pod delete with UID precondition | `agents/fusion_agent/agent.py` | `agents/executor/quarantine.py` | Adapt | S | Check that our quarantine policy has an ownerReference and UID checks. Our recovery model differs: deleting the pod alone does not help (the ReplicaSet remounts the volume); v5 has no PVC recovery. Do not port the delete as the remediation. V5-F1 |
| Protected-owner checks (pod, controller or event Deployment label `kubeheal.io/protected=true`); unknown controller kinds escalate to HUMAN; stale-pod guard | `agents/fusion_agent/agent.py` | Executor `guard.py`, `validation.py` | Adapt | S | Compare with `guard.py`. Note the label name differs (`kubeheal.io/protected` versus our `kubeheal/protected`). V5-F1 |
| Pairing buffer: events of one workload within 120 s are re-decided together with the compound flag; `already_handled` outcome; `namespace_gone` outcome (decision OBSERVE, not HUMAN) | `agents/fusion_agent/agent.py` | `agents/fusion_agent/agent.py` | Adapt | S | Check our handling of a deleted namespace. V5-F2 |
| Containment: on AUTO_KILL fusion writes `kubeheal.contain`; the security agent on that node freezes the pod cgroup (`cgroup.freeze`) within milliseconds | `agents/security_agent/agent.py` `contain_loop`, `agents/fusion_agent/agent.py` | none | No for now | L | Conflicts with I1 and with "the Security Agent observes only": it is a host write performed by the Security Agent with a read-write host cgroup mount, hostPID and uid 0. If wanted, it must become an Executor step. Owner decision D5. V5-S5 |
| Per-controller circuit breakers (`MAX_KILLS_PER_HOUR` 3, `MAX_PATCHES_PER_HOUR` 5) and an owner-token incident lock with heartbeat | `agents/fusion_agent/incident_lock.py` | `agents/fusion_agent/breakers.py`, `incident_lock.py` | No | n/a | Ours exist (3 containments and 10 patches per hour in `decision_policy.py`). Different numbers; keep ours. |

### J. Inference service

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Single service `POST /v1/{health,security}/predict` and `predict_batch` (1 to 256 items); body caps (64 KiB, 1 MiB), 422 on unknown feature names, NaN or Inf, more than 200 keys; `/readyz` only when bundles loaded and every listed feature is one the agents send; 503 when a bundle is missing (never random weights) | `kubeheal/inference/app.py`, `docs/architecture.md` | `services/*_server` | Adapt | M | Input validation, batch and the readiness contract are model-independent ideas. We already fail closed on missing checkpoints (P1 F1). V5-I1 |
| TreeSHAP only for published windows (security risk at or above 0.4); exact SHAP from LightGBM `pred_contrib=True` | `kubeheal/inference/app.py` | our `shap_explainer.py` (KernelExplainer helper, real one not finished, P6-D6) | Optional | M | Only with LightGBM models (option b). |
| LightGBM bundle format (`model.txt` + `meta.json` with features, class risk, conformal q, metrics, data sha256) and `ModelBundle.load` refusing a feature mismatch | `kubeheal/ml/bundle.py` | `services/ckpt.py` | Optional | M | Pattern is worth taking even for torch checkpoints (we have the preprocess version sidecar). |

### K. Training pipeline and lab datasets

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Parity by construction: one feature module; collectors record the features the live agent computed; training refuses a recorded feature set that differs from the current list | `docs/models-and-data.md`, `training/datasets/collected.py` (not in the archive listing; referenced by docs) | `models/health_model/preprocess.py` (our shared preprocessing, P5-Q2a) | Adapt | M | We already have shared preprocessing and a parity test; the collector-records-agent-output rule is the new part. V5-M1 |
| `training/train.py`: grouped 80/10/10 split, 5-fold grouped CV, held-out lab families, gates with floors and no-regression check (`--regression-tol`), exit 1 and write nothing on failure, missing-value dropout copies | `training/train.py` | `models/train_*.py`, `models/validate_all_models.py` | Adapt | L | Our P12 retraining is NOT approved. The evaluation protocol (grouped split, held-out families, gates) is the transferable part. V5-M3 |
| Lab collectors for health (`drift_lab.py`, podinfo slots, 19 or 21 change families) and security (`security_lab.py`, benign real-tool workloads and a sandboxed detection-test pod), `run_lab.sh` | `training/collect/` | none | Optional | L | Target minikube; `run_lab.sh` rewrites Deployments and deletes the lab namespace (refuses unless context is `minikube`). Would need adaptation to `--context k3d-kubeheal`, to our agents' outputs, and the owner's explicit go for any collection run. V5-M2 |
| Synthetic security generator with hard negatives (atomic rename, logrotate gz, dpkg, git/npm, restic-like backup repos, package trees) and a trickle ransomware positive | `training/synth_security.py` | `models/generate_security_training_data.py` | Optional | M | Source of the benign hard-negative families that v5 says stop false kills. V5-M2 |
| Datasets | `training/data/health_lab.jsonl.gz`, `security_lab.jsonl.gz`, `health_drift.csv`, dataset card `training/data/README.md` | none | see section 6 | n/a | Facts in section 6. |

### L. Evaluation driver and measured results

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Live evaluation driver: sections A automated, B false-kill soak with real tools, C detection sweep, D resilience, E drift, F resources; prints raw TSV | `deploy/scripts/evaluate.py` | `eval/p11_harness.py` (branch `wave/P11`), P11-E1 to E7 | Adapt | L | The driver has no context pinning (it uses the current kubectl context; `reset.sh` and `run_lab.sh` check for `minikube`). It scales inference and fusion to zero, restarts Redis, Falco and the health agent, and creates and deletes `khe-*` namespaces. Must be rewritten to `--context k3d-kubeheal`, run in `test` mode by default, with destructive sections only on throwaway namespaces and the owner's go. V5-E1 |
| Resource and kill-latency benchmark | `deploy/scripts/bench.sh` | `eval/resource_profile.py` (P9-H4) | Adapt | S | V5-E2 |
| Recorded scorecard (39 of 39 attack pods killed, 0 false kills on 11 workloads, 6 of 8 harmful drift changes rolled back) | `docs/evaluation.md` | none | Reference only | n/a | One run per workload on minikube. Quote only with its caveats (section 6). We must not reuse these as our results. |

### M. Deploy, kustomize, Helm

| v5 item | Source | Maps onto | Port | Effort | Conflict or note |
|---|---|---|---|---|---|
| Redis with one ACL user per component (per-key patterns, read-only dashboard, only fusion may EVAL), passwords generated in-cluster by a Job and kept in a Secret, AOF on a 1Gi PVC, NetworkPolicy admitting only the agents and the dashboard | `deploy/k8s/base/redis.yaml` | `deploy/helm/kubeheal/templates/redis.yaml` (AOF on PVC plus password, P9-H6) | Adapt | S | We have one password. Per-component users limit who can write `kubeheal.exec` (the Executor trusts that stream, see P9-H6). Strongly aligned with our threat model. Mind that v5's `fusion` user may write `kubeheal:*`; ours needs Executor and dashboard users. V5-P3 |
| NetworkPolicies, hardened container settings (RuntimeDefault seccomp, read-only root, drop ALL), distroless images, image digests pinned | `deploy/k8s/base/*`, `deploy/docker/` | Helm templates, `dockerfiles/` | Optional | M | Distroless removes the shell (debug via `kubectl debug`). Torch images are a separate question. V5-P5 |
| Production overlay: inference HPA 2 to 6 plus PDB, PriorityClass for the security components, DaemonSet rolling 10 percent at a time | `deploy/k8s/overlays/production/` | Helm values (HPA 2 to 8 on queue depth already, P9-H3) | No | n/a | We have an HPA, PDB and topology spread. Compare PriorityClass only. |
| Prometheus via `kube-prometheus-stack` values, PodMonitor scrape label `kubeheal.io/scrape=true`, keep-lists | `deploy/k8s/helm/monitoring-values.yaml`, `prometheus-config.yaml` | `demo/k3d/values-monitoring.yaml`, Helm monitoring template | Adapt | S | Compare keep-lists and scrape interval (v5 states 15 s). |

### N. Tests

| v5 item | Source | Port | Effort | Note |
|---|---|---|---|---|
| Contract and parity tests (train versus serve features, Falco rule versus `CAPTURED_GROUPS`, agent versus fusion field contract), manifest tests, dashboard tests, decision-policy table test | `tests/` (`test_agent_fusion_contract.py`, `test_features_*.py`, `test_manifests.py`, `test_security_ppm.py`, `test_decision_policy.py`, ...) | Adapt | M | Take the test ideas for every ported item. Do not copy files that depend on `kubeheal/` modules we do not have. |
| Evaluation doc states `pytest` 323 passed, `cargo test` 4 passed | `docs/evaluation.md` scorecard | Reference only | n/a | Not verified by us. |

### O. CI

| v5 item | Source | Port | Effort | Note |
|---|---|---|---|---|
| GitHub Actions: `uv sync --frozen`, `ruff check`, `pytest`, `kubectl kustomize` render of both overlays, `bash -n` of scripts, image builds without push | `.github/workflows/ci.yml` | Adapt | S | We have no CI workflow. Adapt to our layout: pytest, `helm lint` and `helm template` for each values file, image builds. Needs a workflow file only; nothing is pushed by us. V5-P1 |

### P. uv and pyproject

| v5 item | Source | Port | Effort | Note |
|---|---|---|---|---|
| `pyproject.toml` with one extra per image, `uv.lock`, `.python-version`, ruff rules (E, F, W, I, B, UP, ASYNC, S) | `pyproject.toml`, `uv.lock` | Optional | M | v5 requires Python 3.13 (`requires-python = ">=3.13"`). Our environment is Python 3.11 because `torch==2.2.0` cannot run on 3.13 (PROGRESS, Machine). If the neural models stay, adopt uv and ruff at Python 3.11 only. Decide after the model choice. V5-P2 |

### Q. Dashboard

v5's dashboard is a read-only console with no Kubernetes access (`dashboard/fastapi_app.py`, event detail views). Ours has approvals, kill-switch admin, ledger and incident views. Port: No, except possibly event-detail drilldowns (S). Not scheduled.

## 3. Conflicts with our design (summary table)

| # | v5 behaviour | Our design | Resolution proposed |
|---|---|---|---|
| C1 | Fusion changes the cluster itself (`patch_namespaced_pod`, `delete_namespaced_pod`, `create_namespaced_network_policy`, `patch_namespaced_deployment`) | Only the Executor writes; every write behind `_write` | Port decisions, evidence and validation only. Every v5 action becomes an Executor request. |
| C2 | Mode is the env var `KUBEHEAL_MODE` (`observe` default in code, `enforce` in the shipped manifest `deploy/k8s/base/fusion-agent-deployment.yaml`), read once at start | ConfigMap `kubeheal-mode`, watched, fail safe to `test`, namespace label can only be stricter, ledger entry per change | Keep ours. Never import the env var. Note the naming: v5 `observe` equals our `test`. |
| C3 | Pod delete with grace 0 is the remediation for ransomware; no data recovery | Quarantine, forensic snapshot, scale to 0, restore a clean snapshot to a new PVC, scan, lift quarantine (P7-RR-3 to RR-6, RR-9); `delete pods` is not in the Executor's RBAC | Do not port the kill. Port detection quality only. |
| C4 | Containment through `cgroup.freeze` written by the Security Agent (hostPID, uid 0, read-write host cgroup mount) | Security Agent observes only; writes live in the Executor | Not ported by default (D5). |
| C5 | Redis: v5's own docs call it ephemeral with no RDB or AOF (`docs/architecture.md`, `docs/evaluation.md`), but the current manifest `deploy/k8s/base/redis.yaml` runs AOF (`--appendonly yes`) on a 1Gi PVC with ACL users. The docs are stale. v5 has no durable audit record: actions live in the `kubeheal.actions` stream (MAXLEN about 10000) and 24 h hash copies | Redis with AOF on a PVC plus password (P9-H6); durable record is the MinIO object-lock ledger (I3) | Keep ledger as the record. Take the per-component ACL users (V5-P3). |
| C6 | Baseline is promoted automatically (benign, certain, rolled out) | Golden baseline written once; only the tool replaces it (I5) | Candidate baseline with approved promotion (D3, V5-D5). |
| C7 | Restore replaces the whole `spec.template` with the baseline | Executor saves a rollback point, patches only drifted fields, `maxUnavailable` 0, canary watch with rollback and escalation (P7-RR-1, RR-2) | Keep ours. Use v5's validation checks as extra guards (V5-D6). |
| C8 | Decision enum AUTO_KILL, AUTO_PATCH, HUMAN, OBSERVE, BENIGN; confidence is a conformal set (`uncertain` when the set is not a single label) | AUTO_CONTAIN, AUTO_PATCH, HUMAN_CONTAIN, HUMAN_PATCH, OBSERVE, BENIGN; confidence gate is `health_ci_width` and `sec_ci_width` at most 0.15 (`CI_WIDTH_LIMIT`), burn-in, `models_ok` | If the model layer changes, redefine the gate in terms of the new output. See section 6, question M2. |
| C9 | Field attribution for patching: v5's event carries `changed_fields` from the spec diff; the model only supplies a label, risk and top factors (feature names such as `cpu_limit_ratio`) | Our policy input `health_field_top` comes from the model's attribution; the Executor escalates `no_drift_at_field` when the attributed field is not drifted. This is the open P10 finding: the Health Model's top field was `template.spec.initContainers[0].securityContext` instead of the CPU field. In both recorded drift events the whole `field_attribution_json` map is flat (the first ten printed entries are 0.008695653639733791 or 0.008695651777088642, per the results file), so `top_field` is the first of equal values, not a ranking. Mapping fixes alone will not help; the attribution values are the problem | Take the idea: derive candidate fields from the diff against the baseline (deterministic), use the model only for severity. Independent of the model choice. Part of V5-D3 and the open attribution item. |
| C10 | Tier label `kubeheal.io/namespace-tier`, protected label `kubeheal.io/protected`, streams `kubeheal.health.events`, `kubeheal.security.events`, `kubeheal.actions`, `kubeheal.contain` | `kubeheal/tier` (not yet read by agents), `kubeheal/protected`, `kubeheal.exec`, `kubeheal.ledger.pending`, our stream names | Never import names; map explicitly. Update docs if a name is shared. |
| C11 | Circuit breakers per controller, 3 kills and 5 patches per hour | Sliding window, 3 containments and 10 patches per hour (`decision_policy.py`) | Keep ours. |
| C12 | Python 3.13, uv, LightGBM only (no torch) | Python 3.11 venv for torch 2.2.0 | Depends on model choice (V5-P2). |
| C13 | v5 scripts check for context `minikube` or use the current context (`evaluate.py` has no check) and delete namespaces | Only `--context k3d-kubeheal`; never delete user data | Every ported script is rewritten to pin the context and avoid deletes outside throwaway namespaces. |
| C14 | Data collection and evaluation run against live drift and attack workloads on the cluster (enforce mode in the eval run) | Mode `test` by default; owner's go for anything that writes | Run in `test` mode first; `enforce` runs only on throwaway namespaces with the owner's go. |

## 4. Mapping of v5 components onto ours

| v5 | Ours | Relationship |
|---|---|---|
| `agents/health_agent/` | `agents/health_agent/` | Same role. Take detection helpers (V5-D1, D2, D4). |
| `agents/security_agent/` | `agents/security_agent/` | Same role. Take hardening (V5-S2) and optional counters and sensor input. |
| `agents/fusion_agent/` | `agents/fusion_agent/` + `agents/executor/` | v5 fusion = our fusion + the Executor's action code. Only the decision logic, pairing and validation map. |
| `kubeheal/inference/`, `kubeheal/ml/` | `services/*_server`, `models/*` | Depends on section 6. |
| `kubeheal/correlation.py` | `models/dcm`, DCM server | Formula as fallback and baseline (V5-M5). |
| `kubeheal/features/` | `models/health_model/preprocess.py`, agents' input builders | Concept of one shared module. |
| `sensor/` | Falco consumer and replay | Optional source (V5-S4). |
| `deploy/k8s` kustomize | `deploy/helm/kubeheal` | Compare, do not adopt kustomize. |
| `training/` | `models/train_*.py` | Evaluation protocol and collectors (section 6). |
| `deploy/scripts/evaluate.py`, `bench.sh` | `eval/`, P11 | Adapt (V5-E1, E2). |
| no equivalent | Executor, ledger, kill switch, snapshots and restore, approvals, Helm, k3d demo | Ours only. |

## 5. Facts about v5's design that matter for porting

- The health event carries `failure_reasons` (rollout failures plus `policy:<feature>` posture violations) from Kubernetes itself, and fusion's rule path uses them. The model is explicitly left to judge subtle drift such as throttling, latency and memory pressure (`docs/models-and-data.md`, Features).
- v5's own live evaluation lists two drift blind spots that remain: a readiness probe to a wrong path ended at HUMAN with benign 0.40, and a CPU request and limit of 5m was rated BENIGN with risk 0.10 (`docs/evaluation.md`, section E and Weaknesses 3). That evaluation was run on 2026-11-07; the `cpu_cut_10x` and `ReadinessNeverPassed` rules appear in the code at the fetched tip, so whether the evaluation text is stale for those two cases is not known (no commit date for the rule was established here).
- v5's kill path was measured only for pod deletion latency (median 1.46 s, p90 4.93 s over 39 attack pods; `docs/evaluation.md`, section C). It says nothing about data recovery.

## 6. Model layer: facts for the owner's choice

Options: (a) keep our neural models and retrain them on v5's lab datasets; (b) use v5's LightGBM models inside our architecture; (c) evaluate both on the same held-out lab data. This section only gives facts. No new number was computed. Nothing was trained or run.

### 6.1 Our models today (sources in our repo)

| Item | Fact | Source |
|---|---|---|
| Health Model | GATv2 plus BiLSTM, 1,028,595 parameters, labels benign, low_risk_drift, harmful_performance_degradation, critical_config_error; `best_val_f1` 0.7979; `conformal_q` 0.7303 | `models/health_model/checkpoints/health_report.json` |
| Conformal file disagrees | `health_conformal.json` holds q 0.5469 while the report holds 0.7303 | `models/health_model/checkpoints/health_conformal.json`, `docs/kubeheal/SCAN_REPORT.md` section 4 |
| Health training data | 4,782 labelled samples in `models/health_model/dit-merged-complete.csv` | `docs/kubeheal/SCAN_REPORT.md` section 6, `docs/kubeheal/PROGRESS.md` ("Health inputs") |
| Health training inputs | Windows built from 9 scalar CSV columns broadcast over 60 steps with noise; six of the 15 channels are zero in training; the request-rate channel held replicas/100. Serving now uses the same preprocessing (`PREPROCESS_VERSION v1-legacy`, parity test) and keeps the quirks on purpose because the checkpoint depends on them. Live scores are not validated on real cluster windows | `docs/kubeheal/PROGRESS.md`, "Health inputs: training vs serving" |
| Security Model | Transformer plus Conv1D-SE, 530,838 parameters, five labels; `best_val_f1` 1.0; `conformal_q` 0.0818 | `models/security_model/checkpoints/security_report.json` |
| Security data | 14,000 generated traces plus live Falco captures; an F1 of exactly 1.0 matches the spec note that the generator was too easy; it says nothing about real traces | `docs/kubeheal/SCAN_REPORT.md` sections 4 and 6 |
| DCM | 191,073 parameters, `best_val_auroc` 0.9556, trained on 5,000 generated compound pairs | `models/dcm/checkpoints/dcm_report.json`, `SCAN_REPORT.md` section 6 |
| Held-out evaluation | None recorded in our repo | not found |
| Live behaviour (P10, one run, k3d, test mode) | With all 15 metrics present, drift event `health_ci_width` 0.1192; the model's top field was `template.spec.initContainers[0].securityContext`, not the drifted CPU field; Executor escalated `no_drift_at_field`. An earlier complete window had width 0.2607 and gave `human_patch` | `docs/kubeheal/results/p10-k3d-2026-11-11.md` (numbers confirmed by Claude from the verbatim output in Codex's session log) |

### 6.2 What v5 collected (sources are v5 files)

| Item | Fact | Source (in `origin/main`) |
|---|---|---|
| Health lab data | 2,998 rows, 277 groups; labels benign 2,064, critical 614, degradation 320; workload is podinfo in namespace `kubeheal-lab`; scenario families listed in the dataset card (args, cpu, mem, env, image, meta, posture, probe, replicas, volume mount, combined, revert) | `training/data/README.md`, `models/health/meta.json` (`data.rows` 2998, `data.groups` 277) |
| Health labels | From observed impact, not scenario name: `critical` = posture change, scaled to zero, ready ratio below 0.5, rollout not complete, pod waiting in a failure state, any restart or OOMKill, or 5xx ratio above 5 percent; `degradation` = p99 at least 2x the minute before (and at least 10 ms more), CPU throttling above 25 percent, or memory above 90 percent of the limit | `docs/models-and-data.md`, Lab collection |
| Health record fields (first record of `health_lab.jsonl.gz`) | `id, source, task, run_id, group, slot, family, scenario, params (ops and base recipe), revert, label, label_reasons, features (derived), changed_fields, agent (the live agent's prediction), obs, pre_p99_s, t_change_ms, t_event_ms`. The record has derived features only: no full old and new spec and no raw metric series. | read from the file with Python in isolated mode (field names only) |
| Legacy health CSV | `training/data/health_drift.csv`, 4,782 data rows by line count (4,783 lines with header); the docs say 48 runs, only about 9 with a harmful label, and 506 `Synthetic*` rows dropped on load | file, `docs/models-and-data.md`, Datasets and Legacy CSV cleaning. Whether it is the same data as our `dit-merged-complete.csv` was not compared. |
| Security lab data | 46,606 rows, 596 groups; labels benign 43,148 and ransomware 3,458; short-lived pods running ordinary file workloads (labelled benign) or the sandboxed detection-test workload (`deploy/chaos/detection-test-workload.py`, creates plain files, waits, overwrites with random bytes, optional rename) | `training/data/README.md` |
| Security record fields (first record) | `source, scenario, params, group, label, label_reasons, pod_phase, features, n_events, window_start_ms, window_end_ms, model_version, model_label, model_risk`. The first record carries no raw events. The docs say rows collected later store raw events and entropy samples (`events_json`, `entropy_json`, or a per-pod `events_log`); how many rows have them was NOT checked. | file (first record only), `docs/models-and-data.md`, Raw events |
| Security synthetic part | Final bundle data: 49,964 rows, 1,954 groups; lab 46,606 plus synthetic 3,358 (6.72 percent); `suspicious` and `exfiltration` are 100 percent synthetic, benign hard negatives 4.56 percent of benign, ransomware 0 percent synthetic | `models/security/meta.json` (`data.synthetic_fraction_by_class`), `docs/models-and-data.md` Metrics |
| Collection environment | Single minikube node, podinfo only for health; one ransomware simulator for security; Falco as the event source for the lab rows | `docs/models-and-data.md` Known limitations |

### 6.3 v5 features

- Health: 36 features, 24 spec-diff features (resources ratios, replicas, image, security posture, probes, env, command, size) plus 12 metric features from the window (`cpu_util_mean/max`, `cpu_throttle_mean`, `mem_util_mean/max`, `latency_p99_mean/max`, `latency_trend`, `error_ratio`, `request_rate_log`, `restarts_delta`, `ready_ratio`). Raw metrics: 11 (`cpu_usage_cores`, `cpu_limit_cores`, `cpu_throttled_ratio`, `memory_working_set_bytes`, `memory_limit_bytes`, `request_rate_rps`, `error_rate_rps`, `latency_p99_s`, `restarts_total`, `replicas_desired`, `replicas_ready`). `failure_reasons` is NOT a model feature. Source: `docs/models-and-data.md`; `models/health/meta.json` lists 36 feature names.
- Security: window features over file syscalls on the data volume (syscall mix, paths, extensions, rename kinds, transforms of read originals, entropy of the first 16 KiB of written files, byte counters, short-horizon features over the last 64 events). The prose says 45 features in `docs/models-and-data.md` and 26 in `docs/architecture.md`; `models/security/meta.json` lists its own feature names (see section 9, doc inconsistencies). Only file syscalls are captured live, so network, mmap and exec fractions are always 0 at serve time.

### 6.4 v5 reported metrics (quoted, with source)

Health bundle `health-5.0.0-a374e498` (`models/health/meta.json`, created 2026-11-08T00:25:49+00:00):
- grouped 5-fold CV: macro-F1 0.9386, n 2,694; per class F1 benign 0.9689, critical 0.9012, degradation 0.9458; critical recall 0.9044; coverage 0.9005; mean set size 0.9191.
- test split: macro-F1 0.9024, n 304; critical F1 0.8406.
- held-out family (every row involving the family held out), pooled macro-F1 0.6605, gate threshold 0.62 (`gate` block). Per family in the same file, for example `args_stress` accuracy 0.3077 (n 130), `cpu_limit_down` 0.9541 (n 196), `cpu_limit_up` 1.0 (n 95).
- conformal q 0.31195; latency p50 6.255 ms, p99 8.816 ms (single row including TreeSHAP; `docs/models-and-data.md` notes it was measured with other training jobs running).
- Gate baseline was the previous bundle `health-5.0.0-421cec83`; `docs/models-and-data.md` says the extra 479 rows leave macro-F1 within noise (0.926 plus or minus 0.014 versus 0.920 plus or minus 0.017, 5 seeds), and calls the older held-out figure 0.858 optimistic because combined and revert rows of the held-out family stayed in training.

Security bundle `security-5.0.0-c6fa12d8` (`models/security/meta.json`, created 2026-11-07T16:51:06+00:00):
- grouped 5-fold CV macro-F1 0.9994 (n 45,452); test macro-F1 1.0 (n 4,512); ransomware recall in CV 0.9991; the docs call security macro-F1 alone inflated by the synthetic-only classes, so the gates use lab-only rows.
- docs Metrics table: held-out-family pooled macro-F1 0.999 over benign plus ransomware (the `meta.json` figure is 0.50 because exfiltration and suspicious do not occur in lab families); conformal q 3.9e-6 (serving floors it at 0.05); latency p50 13.0 ms, p99 15.7 ms.
- docs rows marked "Eval" (pod-level ransomware recall 177 of 178; benign pods falsely killed 0 of 418 in 5-fold CV and leaving each benign family out; first overwrite to first kill-eligible window median 2.21 s, p90 2.72 s): `docs/models-and-data.md` states "scripts are not in the repo" for these, so they cannot be reproduced from v5.
- live (`docs/evaluation.md`, one run per workload, minikube 2026-11-07): 39 of 39 attack pods killed, median latency 1.46 s and p90 4.93 s; 0 AUTO_KILL on 11 real-tool workloads (npm reached ransomware 0.84 on 2 windows and went to HUMAN; restic reached 0.82 under load and went to HUMAN); a kill under a 20-pod load came about 160 s late; drift: 6 of 8 harmful changes rolled back, 0 false patches on 3 benign changes.
- `docs/evaluation.md` records the deployed health bundle as `health-5.0.0-421cec83`, not the shipped `a374e498`.

v5's own caveats (`docs/models-and-data.md`, Known limitations): exfiltration rests entirely on synthetic data; narrow health data (one workload type, one node); one ransomware simulator; 60 s health window; the conformal guarantee assumes exchangeability; safety rests on synthetic hard negatives; a different rename-heavy benign workload may still be killed.

### 6.5 What each option needs (facts, not a recommendation)

| | (a) Keep our neural models, retrain on v5 lab data | (b) Use v5 LightGBM inside our architecture | (c) Evaluate both on the same held-out lab data |
|---|---|---|---|
| Input compatibility | Our Health Model needs a YAML graph of the old and new spec and a 60-step by 15-channel window through our preprocessing. v5 health records hold 36 derived features, the generating recipe (`params.base`, `params.ops`) and `changed_fields`; they hold no full specs and no metric windows. Retraining our GATv2 plus BiLSTM from this file alone is not possible; new collection with a modified collector, or regeneration of specs from the recipe with metric windows still missing, would be needed. Security: needs raw events and entropy series; present only for rows collected with raw events (extent unchecked). | Needs our agents to compute v5's features. Health: 24 spec-diff features (a pure function of two specs; our agent has both) and 12 metric features from 11 raw metrics at a 15 s step over the window since the change; our window is 60 steps of 5 s on 15 channels. Security: events must be the same file-syscall view with the same windowing. Port of `kubeheal/features/` is the main work. | Needs inputs for both models. Our neural models cannot score v5's records for the reason in column (a). v5's LightGBM can score a record only through its stored `features`. A like-for-like comparison therefore needs rows that carry both representations, i.e. new collection through our own agents (or raw-event rows for security). |
| Labels | Our labels: 4 health, 5 security. v5: 3 health (benign, degradation, critical), 4 security (benign, suspicious, ransomware, exfiltration). A mapping is needed, and our `ransomware_staging` versus `ransomware_active` split has no v5 counterpart. | Our policy and Executor consume risk, label, `health_field_top`, CI width; v5 provides label, risk (class-risk weighted), conformal set, top factors (feature names). Fields come from the diff instead (C9). | Group and family keys exist in v5 records (`group`, `family`), so grouped and held-out-family splits are reproducible. Our repo has no held-out numbers to compare against. |
| Confidence gate | Unchanged (`CI_WIDTH_LIMIT` 0.15). | `health_ci_width` (as our server computes it, one minus the largest class probability, per PROGRESS P10 findings) would be replaced by the conformal-set test (certain means a single label). Redefining S-POL-6 is an owner decision. | n/a |
| Runtime | torch 2.2.0, Python 3.11, `torch_geometric` (not installed in the current environment, so our health model cannot be tested here; PROGRESS REV-3). | LightGBM and numpy only, Python 3.13 in v5 (could be pinned lower); no torch or GPU. Latency figures are v5's (health p50 6.255 ms, security p50 13.031 ms single row including TreeSHAP). | n/a |
| Training | Requires the owner's approval (P12); training is slow and GPU-bound per AGENTS.md. | The shipped bundles exist (`models/health`, `models/security`, about 11 MB for `models/` including both); no training needed to start. Retraining on our own data would also need approval. | Evaluation of existing checkpoints needs no training. |
| Data provenance | Lab data from a teammate's minikube lab with podinfo and one ransomware simulator. | Same. Plus 6.72 percent synthetic security rows. | Held-out lab rows share the lab's simulators, so they test generalisation across families, not across real malware or real workloads. |
| Our open P10 finding (attribution mismatch) | Not addressed by new data alone; attribution still comes from the model. | Addressed if fields come from the diff (C9). | Orthogonal. |

Observation (not a decision): the detection-logic ports in group D (V5-D1 to V5-D3, V5-D6) do not depend on the model choice, and field attribution from the spec diff (C9) removes the open attribution mismatch under any option.

## 7. Proposed order of porting work (checklist task IDs)

Sizes S, M, L. All tasks keep invariants I1 to I7: Executor-only writes, kill-switch gate, ledger, context pinning, no training or collection without the owner's go. Tasks that touch `agents/fusion_agent/decision_policy.py`, `agents/executor/` or `k8s/rbac/` are for the stronger agent only (marked R).

Phase V5-0: prerequisites (no behaviour change)
- [ ] V5-0a S. Add the owner's decisions (section 8) to `docs/kubeheal/PROGRESS.md` and mark which tasks below are approved.
- [ ] V5-0b S. Read-only script (under `eval/`) that reports, for the v5 lab files, which record fields exist and the share of security rows with raw events. Output stored in `docs/kubeheal/results/`. Needed before any model option is costed.

Phase V5-D: detection and rule path (model independent, highest value for the demo)
- [ ] V5-D1 M. `failure_reasons` in the Health Agent (`pod_failure_reasons`, `readiness_never_passed`, `ProgressDeadlineExceeded`, ownership filter) with tests; Health RBAC `pods list` and HPA `list` in `k8s/rbac/` and the Helm RBAC template with the RBAC parity test (R for the RBAC part).
- [ ] V5-D2 M. Pure posture and cut rules module (`policy_violations`, `cpu_cut_10x`, `memory_cut_10x`) with tests, after decision D1 on the floor and strictness.
- [ ] V5-D3 M, R. Policy rule path for rollback (after decision D2), carrying `failure_reasons`; deterministic changed-field list derived from the diff replaces model attribution for the Executor patch target (C9); policy table tests; Fusion passes the evidence; ledger rationale.
- [ ] V5-D6 S, R. Executor validation: selector match and no posture weakening against the live template, before any patch.
- [ ] V5-D4 M. Debounce with maximum postponement, early assessment, follow-up events, re-list on 410; decide together with P6-D2 (branch `wip/docs-p6d2`).
- [ ] V5-D5 M, R. Candidate baseline and approved promotion (after decision D3); share `rollout_complete` with P7-RR-11.

Phase V5-I: serving contracts (model independent)
- [ ] V5-I1 M. Input validation, batch endpoint and readiness contract (unsent or unknown features) for our model servers; tests.

Phase V5-M: model layer (starts after decision M1)
- [ ] V5-M1 M. One shared feature module with a train-versus-serve parity test and a collector-records-agent-output rule (applies to any option).
- [ ] V5-M5 S. Port `compound_score` as a deterministic fallback and as the comparison baseline for the DCM.
- [ ] V5-M3 M. Held-out evaluation harness (grouped split by group, held-out families, per-family report), run on existing checkpoints only. No training.
- [ ] V5-M2 L. Lab collectors adapted to `--context k3d-kubeheal` and to our agents; collection run only with the owner's explicit go.
- [ ] V5-M4 L. Option (a) or (b) implementation after the decision. (a) needs P12 approval; (b) needs V5-I2.
- [ ] V5-I2 L. LightGBM serving behind our model-server contract (bundle format with `meta.json`, feature check), only for option (b) or (c).

Phase V5-S: security sensing
- [ ] V5-S1 S. Falco rule and `falco-values` comparison, plus a test that keeps the rule's `evt.type` list and our captured syscall groups in sync.
- [ ] V5-S2 S/M. Entropy sampler hardening (`O_NOFOLLOW`, regular files only, stat-signature cache); tests.
- [ ] V5-S3 M. Write-bytes and network-out counters, only if the chosen security model uses them.
- [ ] V5-S4 L. eBPF sensor as an optional chart component; field-by-field check against `falco_client.py`; verification only on a Linux lab host, not Docker Desktop.
- [ ] V5-S5 L, R. Containment by cgroup freeze routed through the Executor, only if decision D5 says yes.

Phase V5-F: fusion and Executor hardening checks
- [ ] V5-F1 S, R. Compare quarantine (ownerReference, UID preconditions) and protected-owner and unknown-controller handling with v5; fix gaps.
- [ ] V5-F2 S. Deleted-namespace outcome and pairing re-decision check.

Phase V5-E: evaluation
- [ ] V5-E1 L. Port the scenario sets of `evaluate.py` (false-kill soak with real tools, detection sweep, drift, resilience) onto the P11 harness (`wave/P11`), pinned to `--context k3d-kubeheal`, `test` mode first. Results only from recorded runs.
- [ ] V5-E2 S. Resource and latency benchmark adaptation of `bench.sh` with `eval/resource_profile.py`.

Phase V5-P: platform
- [ ] V5-P1 S. CI workflow: pytest, `helm lint` and `helm template` per values file, image builds without push.
- [ ] V5-P3 S, R. Redis per-component ACL users (Executor trusts `kubeheal.exec`), keeping AOF and password generation.
- [ ] V5-P2 M. uv and ruff at Python 3.11, after the model choice.
- [ ] V5-P5 M. Hardened images (distroless, digest pinning), optional.

Suggested sequence: V5-0a, V5-0b, V5-D1, V5-D2, V5-D6, V5-D3, V5-I1, V5-S1, V5-S2, V5-F1, V5-F2, V5-P1, V5-D4, V5-D5, V5-P3; then the model tasks after the owner's choice (V5-M1, V5-M3, V5-M5, then V5-M2, V5-M4, V5-I2); then V5-E1, V5-E2; V5-S3, V5-S4, V5-S5, V5-P2, V5-P5 last.

## 8. Decisions needed from the owner (nothing is ported until these are answered)

- D1. Floor and strictness of the 10x cut rule (v5: below 50m CPU or 32Mi with a strict comparison, which does not flag a drift to exactly 50m). Keep v5's floor, raise it, or change the comparison.
- D2. May the rule-based rollback path bypass the model confidence gate (CI width and burn-in) in `decision_policy.py`, with every other gate kept (kill switch, protected label, breakers, Executor validation, canary)? Or must it also pass the CI gate?
- D3. Baseline promotion: keep the golden baseline write-once and add an approved candidate promotion (proposed), adopt v5's automatic promotion, or do neither.
- M1. Model layer: (a), (b) or (c) from section 6, and whether new lab collection through our own agents is allowed (V5-M2) and under which cluster conditions.
- M2. If (b) or (c): how the confidence gate is redefined (conformal single-label set versus CI width 0.15).
- D5. Containment by cgroup freeze: routed through the Executor, or not ported.
- D6. Whether the eBPF sensor is worth porting given it cannot be verified on this Docker Desktop machine.
- D7. Whether P6-D2 (OBSERVE rescheduling, branch `wip/docs-p6d2`) is merged first, since V5-D4 changes the same scheduling area.

## 9. Inconsistencies inside v5's own material (check before quoting v5)

- Redis: `docs/architecture.md` and `docs/evaluation.md` say Redis is ephemeral with no AOF; `deploy/k8s/base/redis.yaml` (current) runs AOF on a PVC with ACL users.
- Mode: docs say fusion defaults to `observe` in code (true, `agents/fusion_agent/agent.py`) and the shipped manifest sets `enforce`.
- Security feature count: 45 (`docs/models-and-data.md`), 26 (`docs/architecture.md`), and a feature list in `models/security/meta.json` that is neither (counted from the file when the plan was written; not re-verified).
- Drift families: 19 (`training/data/README.md`, `docs/models-and-data.md` diagram) versus 21 weighted families (`docs/models-and-data.md` text).
- Evaluation used `health-5.0.0-421cec83`; the shipped health bundle is `a374e498`.
- The "Eval" security rows cite scripts that are not in the repo; the commit `48a59aa` has no file changes.
- The documented held-out figure for health changed from 0.858 to 0.661 after the held-out definition was tightened (their text); read the current number.

## 10. Not done and not claimed

- No v5 test, script, sensor build, training or model load was run. No v5 number was reproduced.
- Whether our Falco consumer can read the sensor's JSON unchanged, whether Falco or the sensor works on Docker Desktop here, and how many v5 security rows carry raw events are all unverified.
- Our own model numbers above are stored report values, not re-measured.

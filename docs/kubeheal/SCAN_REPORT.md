# KubeHeal scan report

Scan date: 2026-11-10 (demo is 2026-11-11). Repo scanned: `Unisys_Model` (clone of `origin/main`).
Mode: read-and-report. No tracked file was edited, nothing was pushed, no branch was created.
Nothing was measured beyond what is stated in "Test and server results". Any number below comes from
a file in the repo or from a run made during this scan. Everything else is "not measured".

---

## 1. Git state

- Repo root: `C:/My_projects_1/cLOUD/Unisys_Model`. This is a nested clone inside a separate local
  repo (`cLOUD`) that has unrelated history.
- Current branch: `main`, tracking `origin/main`. Default branch on the remote: `main`.
- Local branches: `main` only.
- Remote branches: `main`, `master`, `kali`, `test`, `feat/dit-sec-train-integrate`.
- `work` and `demo` do not exist, locally or on the remote.
- Local commit `88ce586 docs: add CLAUDE.md and KubeHeal project spec` is 1 ahead of `origin/main`.
  It contains exactly `CLAUDE.md` and `docs/kubeheal/PROJECT_SPEC.md`. Not pushed.
- Working tree: clean before this report. `SCAN_REPORT.md` is the only uncommitted file.

| Branch | Ahead / behind `origin/main` | Notes |
|---|---|---|
| `origin/main` | 0 / 0 | Newest work (v4, 2026-06-05 to 2026-06-08). Last commit `b419053 fix(health-agent): only assess on real spec drift`. |
| `origin/test` | 0 ahead, 27 behind | Fully contained in `main`. Nothing unique. |
| `origin/feat/dit-sec-train-integrate` | 0 ahead, 25 behind | Fully contained in `main`. Nothing unique. |
| `origin/kali` | 6 ahead, 45 behind | Older v3-era fixes (2026-05-07 to 05-11): `install.sh` resource cuts for an 8 GB machine, health agent dict access fix, `Dockerfile.ransomware`, README rewrite. Touches `scripts/install.sh`, several `k8s/*.yaml`, `dockerfiles/Dockerfile.security`, `scripts/demo.sh`. Diverged from `main`; not reviewed commit by commit. |
| `origin/master` | 9 ahead, 49 behind | Oldest line (2026-05-02 to 05-10): DIT-Sec v3 training outputs, Colab notebook, training docs, `uv.lock`. Diff vs `main` is 79 files. Diverged; not reviewed commit by commit. |

Last 10 commits of `main`: `b419053`, `067a3d8`, `11f7695` (all 2026-06-08), `fd244cc`, `50da676`,
`0abaa15`, `ae4b832`, `c043217`, `c41705a`, `462e236` (2026-06-05). For the other branches the table
gives the ahead/behind counts and the intent from commit subjects; a full 10-commit listing per branch
is not included here (run `git log origin/<branch> -10` to see it).

Observation: `.claude/settings.local.json` is tracked in the repo. It is a local settings file and
probably should not be.

## 2. Inventory

171 tracked files. Large tracked binaries (sizes from disk):
- `models/health_model/checkpoints/best_health_model.pt` 4.1 MB
- `models/security_model/checkpoints/best_security_model.pt` 2.2 MB
- `models/dcm/checkpoints/best_dcm.pt` 0.8 MB
- `models/health_model/dit-merged-complete.csv` 19.4 MB (training data)
- `models/_archive_v3/` includes a second 19.4 MB CSV and two v3 `.pt` files (8.2 MB and 1.8 MB)
- `docs/architecture-flow.png` 0.4 MB, two screenshots at repo root

| Folder | Contents |
|---|---|
| `agents/` | `health_agent` (Watch API + Prometheus), `security_agent` (/proc, entropy, Falco), `fusion_agent` (decision policy, incident lock, executes actions). No separate executor. |
| `services/` | FastAPI servers: `health_model_server` (8001), `security_model_server` (8002), `dcm_server` (8003). |
| `models/` | Model code (GATv2+BiLSTM, Transformer+Conv1D-SE, DCM, interpretation), train/export/calibrate scripts, checkpoints, training CSV, `_archive_v3`. |
| `dashboard/` | FastAPI dashboard, static JS, template. |
| `k8s/` | Plain manifests, RBAC, CRDs, Falco config and rules, Prometheus config. |
| `dockerfiles/` | One per component plus a shared ML base. |
| `scripts/` | `install.sh` (Minikube), `demo.sh`, `reset.sh`, `seed_demo.sh`. |
| `demo/` | `victim-app.yaml` (namespace `demo`, includes a PVC and an Ingress). |
| `chaos/` | Ransomware simulator and chaos pods. |
| `kernel/` | eBPF probe file and a kernel monitor script. |
| `tests/` | 7 test files, 44 tests. |
| `docs/` | Architecture flow (md, mmd, png) and the new `docs/kubeheal/` folder. |
| Root | `KUBEHEAL_V4_PRD.md`, `KubeHeal_PRD_v3.docx`, `DASHBOARD.md`, `README.md`, `requirements.txt`, `pytest.ini`, `CLAUDE.md`. |

No Helm chart in the repo. No ONNX files are tracked (export scripts exist).

## 3. Spec comparison

Status key: Implemented, Partial, Stub, Diverges, Missing.

### S-HA Health Agent (`agents/health_agent/`)

| ID | Status | Evidence |
|---|---|---|
| S-HA-1 | Implemented | `agent.py` `watch_deployments`: reconnect loop, resumes from resourceVersion, restarts on 410, 300 s timeout. Watches only Deployments labelled `kubeheal.io/watch=true`. |
| S-HA-2 | Diverges | No golden baseline. `_save_spec` overwrites `kubeheal:spec:<ns>:<name>` in Redis on every event, so the "baseline" is the previous spec. Persistent drift replaces it. |
| S-HA-3 | Diverges | Diff is previous spec vs new spec, not live vs golden. After one drift event the drifted spec becomes the reference. |
| S-HA-4 | Partial | `prometheus_client.py` queries 15 PromQL expressions as instant values and broadcasts each across 60 steps. It is not a real 60-step window. Missing metrics become 0.0. |
| S-HA-5 | Implemented | `_prometheus_cache` keyed by (namespace, pod) with polling/backoff. Key uses the Deployment name, not a pod. |
| S-HA-6 | Diverges | Runs as ServiceAccount `kubeheal`, which has write verbs cluster-wide (see S-EX-1). |

### S-SA Security Agent (`agents/security_agent/`)

| ID | Status | Evidence |
|---|---|---|
| S-SA-1 | Partial | `proc_scanner.py` supports cgroups v1 and v2 with `lru_cache`, and has tests, but `agent.py` does not import it. The agent uses its own in-file `ProcessScanner`, which splits the cgroup path on `/` and only recognises namespaces named default, kube-system, kubeheal. |
| S-SA-2 | Implemented | `_sample_write_bytes` reads `write_bytes` from `/proc/<pid>/io`, deltas every 2 s. |
| S-SA-3 | Stub | Entropy is computed from hard-coded paths `/data/test_{0..19}.dat`; the 30-step series is synthesized as `entropy_avg + 0.1*(i%3)`. Not 30 real samples 2 s apart. |
| S-SA-4 | Partial | Falco consumer exists with a 256-event window, but is off by default (`FALCO_ENABLED=false`). When no real events exist, `synth_events` fabricates a syscall list from the early signals. |
| S-SA-5 | Diverges | Agent creates NetworkPolicies and calls `os.kill(pid, 9)` itself (`_direct_kill`, risk >= 0.90), bypassing the Fusion Agent and decision policy. |

### S-HM Health Model server

| ID | Status | Evidence |
|---|---|---|
| S-HM-1 | Implemented | `POST /health/score`, `GET /health` in `services/health_model_server/main.py`. |
| S-HM-2 | Implemented | `health_model.py` defaults: GATv2 3 layers x 8 heads, BiLSTM 2 layers, cross-attention. Param count in `health_report.json`: 1,028,595. |
| S-HM-3 | Implemented | Response has risk, 4 labels, probabilities, field attribution, top field and metric, CI, 128-dim embedding. |
| S-HM-4 | Diverges | Missing or unloadable checkpoint logs a warning and serves random weights. `/health` still returns `model_loaded: true`. Not fail closed. A checkpoint file does exist in the repo. |

### S-SM Security Model server

| ID | Status | Evidence |
|---|---|---|
| S-SM-1 | Implemented | `POST /security/score`, `GET /health`. |
| S-SM-2 | Implemented | Transformer 4 heads x 2 layers, `norm_first=True`, CLS token; Conv1D kernels 3, 7, 15 with SE. |
| S-SM-3 | Implemented | 5 labels and 64-dim embedding per the report and encoder code. The entropy-spike flag field was not individually checked. |
| S-SM-4 | Diverges | Same random-weights fallback as the health server. |

### S-DCM DCM server

| ID | Status | Evidence |
|---|---|---|
| S-DCM-1 | Implemented | `POST /dcm/correlate`, `GET /health`. |
| S-DCM-2 | Implemented | `cross_modal_attention.py`. |
| S-DCM-3 | Implemented | `COMPOUND_THRESHOLD = 0.60`, `score > 0.60`; chain and NL summary returned. |
| S-DCM-4 | Implemented | `train_dcm.py` sets base models to eval and `requires_grad_(False)`. Training was not run. |

DCM server cold-start path: no checkpoint means `trained: false` and compound is forced off. That is
a documented fallback, but it is also silent random weights.

### S-INT Interpretation

| ID | Status | Evidence |
|---|---|---|
| S-INT-1 | Implemented | `models/interpretation/field_name_mapper.py`. |
| S-INT-2 | Partial | `shap_explainer.py` uses KernelExplainer for metrics only and falls back to attention for YAML/syscalls. |
| S-INT-3 | Partial | `causal_chain_builder.py` exists. No attack onset time T0 found. |
| S-INT-4 | Implemented | Template NL summary, no LLM call. The optional redacted LLM summary does not exist (it is optional in the spec). `agents/fusion_agent/interpretation_client.py` exists but nothing imports it. |

### S-MQ Messaging

| ID | Status | Evidence |
|---|---|---|
| S-MQ-1 | Implemented | Streams `kubeheal.health.events`, `kubeheal.security.events`, `kubeheal.dcm.events`, `kubeheal.actions`. |
| S-MQ-2 | Implemented | Consumer group `fusion`, `xreadgroup`. |
| S-MQ-3 | Missing | No `XAUTOCLAIM`, `XPENDING` or `XCLAIM` anywhere. Messages are `XACK`ed in a `finally` block, so a failed handler still acks the message. |
| S-MQ-4 | Diverges | `install.sh` installs Redis standalone with persistence off. |

### S-FA Fusion Agent

| ID | Status | Evidence |
|---|---|---|
| S-FA-1 | Implemented | Per-pod buffers with a 30 s correlation window. |
| S-FA-2 | Partial | Calls the DCM over HTTP. Does not call the interpretation layer directly (`interpretation_client.py` unused). |
| S-FA-3 | Implemented | `make_decision` is called for every pair. |
| S-FA-4 | Partial | TTL 10 s, heartbeat 3 s, Lua check-and-delete exist. But every caller uses the default token `"1"`, so the owner check cannot tell replicas apart. |

Manifest runs 2 Fusion replicas.

### S-EX Remediation Executor

| ID | Status | Evidence |
|---|---|---|
| S-EX-1 | Missing | No separate Executor. Write actions are methods on the Fusion Agent. All components, including both agents and the model servers, use one ServiceAccount `kubeheal` bound by ClusterRoleBinding to a ClusterRole with get/list/watch/create/update/patch/delete on pods, services, configmaps, namespaces, deployments, replicasets, statefulsets, networkpolicies, and more. Not scoped per namespace. |
| S-EX-2 | Stub | `_execute_patch` calls `patch_namespaced_deployment`, but reads its golden spec from Redis key `kubeheal:baseline:<ns>:<dep>`. Nothing in the repo writes that key, so the path always returns `no_baseline_escalated`. It also patches the whole pod template, not only the top field. No rollback point, no maxUnavailable setting, no 3-window p99 check. |
| S-EX-3 | Diverges | `_execute_kill` creates a fixed-name NetworkPolicy `kubeheal-quarantine` with `podSelector: {}` (the whole namespace) and egress only to same-namespace pods, then deletes the pod with grace 0. No pod label, no scale-to-zero, no forensic snapshot, no restore. |
| S-EX-4 | Partial | Each decision is written to the Redis stream `kubeheal.actions`. Not a ledger, not per step. |

Actual Kubernetes API calls found in the repo: `patch_namespaced_deployment`, `delete_namespaced_pod`,
`create_namespaced_network_policy` (Fusion Agent and Security Agent). No scale, no VolumeSnapshot call,
no PVC restore call anywhere.

### S-DB Dashboard

| ID | Status | Evidence |
|---|---|---|
| S-DB-1 | Partial | FastAPI app exists. The only Ingress manifest is for the demo victim app. Access in `install.sh` is by port-forward. |
| S-DB-2 | Missing | Routes are all GET (`/api/health-events`, `/api/security-events`, `/api/stats`, `/api/combined-events`, `/api/events/{id}`). No approve or reject. HUMAN decisions have nowhere to go. |

### S-REC Record

| ID | Status | Evidence |
|---|---|---|
| S-REC-1 | Missing | No MinIO ledger, no object lock. |
| S-REC-2 | Missing | No Prometheus counters in agents or services. Grafana only comes with the stock kube-prometheus-stack; no KubeHeal dashboards. |
| S-REC-3 | Partial | `models/upload_to_registry.py` pushes to MinIO if run. Servers load `.pt` from local disk. |

### Section 2 Decision policy (`agents/fusion_agent/decision_policy.py`)

The module is pure (no I/O imports). Tests in `tests/test_decision_policy.py` pass (see section 4).

| ID | Status | Evidence |
|---|---|---|
| S-POL-1 | Missing | Policy has no "server failed" input. DCM failure returns zeros. Health agent falls back to a local heuristic with `ci_width=1.0` (which pushes high risk to HUMAN). Security agent falls back to heuristics and can still direct-kill. No deadline logic. |
| S-POL-2 | Implemented | Tier 1.20 / 1.00 / 0.70; compound 1.15 applied to both scores when `compound_flag`. Tier comes from the namespace name: contains "prod", contains "stag", else dev. |
| S-POL-3 | Diverges | Thresholds match (0.85). Decision is named `AUTO_KILL` and executed as quarantine plus pod delete, not "contain". |
| S-POL-4 | Implemented | `health_adjusted >= 0.85 and sec_risk < 0.4`. |
| S-POL-5 | Partial | 0.65 and 0.40 thresholds match. OBSERVE only logs; no 3x sampling happens. |
| S-POL-6 | Partial | CI width limit 0.15 and kill circuit breaker (3 per namespace per hour, Redis counter, TTL 3600 from first increment) exist. Patch breaker is keyed per pod name, not per Deployment (limit 10). No protected-namespace label guard. |
| S-POL-7 | Partial | 0.95 and 0.90 burn-in thresholds exist, switched by env `BURN_IN_MODE`. No 2000-sample counter. |

`Thresholds.RANSOMWARE_DIRECT_KILL = 0.98` is defined and never used.

### Section 3 Remediation

| ID | Status | Evidence |
|---|---|---|
| S-RD-1 | Missing | No rollback point saved. |
| S-RD-2 | Partial | Whole template restore attempted, not only the top field. Cannot run (S-EX-2). |
| S-RD-3 | Missing | No maxUnavailable handling. |
| S-RD-4 | Missing | No post-patch verification or rollback. |
| S-RR-1 | Missing | No snapshot scheduler. `install.sh` only enables the Minikube snapshot addons. |
| S-RR-2 | Diverges | Namespace-wide policy, no pod label (see S-EX-3). |
| S-RR-3 | Missing | No forensic snapshot. |
| S-RR-4 | Missing | Pod delete only. |
| S-RR-5 | Missing | |
| S-RR-6 | Missing | |
| S-RR-7 | Missing | |

### Section 4 Cloud and platform

| ID | Status | Evidence |
|---|---|---|
| S-CL-1 | Missing | No HPA. Model servers run 1 replica. |
| S-CL-2 | Missing | No PodDisruptionBudget or topology spread. |
| S-CL-3 | Partial | Each manifest has one `limits:` block. Values are not from measured profiles; "not measured". |
| S-CL-4 | Diverges | Namespaces created: `kubeheal`, `demo`, `monitoring`, `kubeheal-demo`. No prod/staging/dev, no ResourceQuota or LimitRange. KubeHeal is excluded from actions only because the Health Agent watches the `kubeheal.io/watch=true` label. |
| S-CL-5 | Missing | No NetworkPolicy for the `kubeheal` namespace. |
| S-CL-6 | Missing | Shell installer only, Minikube. |
| S-CL-7 | Diverges | Installer is Minikube. No k3d script. |
| S-CL-8 | Partial | `export_*.py` exist for all three models; a commit message says the health GATv2 export was parity-verified. No ONNX artifacts are tracked and servers load PyTorch `.pt`. Parity not re-checked here. |

### Section 5 Kill switch

| ID | Status | Evidence |
|---|---|---|
| S-KS-1 to S-KS-6 | Missing | No `kubeheal-mode` ConfigMap, no `kubeheal/mode` label, no test/enforce code, no mode-change ledger entries, no RBAC for it. The only dry-run behaviour is accidental: if no kube config can be loaded, the Fusion Agent returns `dry_run_no_kube`. |

## 4. Test and server results

Environment found: global Python 3.13.17, torch 2.12.0, fastapi 0.115.6, numpy 2.3.5, pytest 9.0.3.
No virtualenv in the repo. `requirements.txt` pins torch 2.2.0, `numpy<2`, `torch-geometric>=2.5.0`.
`torch_geometric` is not installed here. Nothing was installed.

Command: `PYTHONPATH=. python -m pytest tests/ -q`
Result: 44 tests, 42 passed, 2 failed.
- `tests/test_encoders.py::test_yaml_gat_shapes`: `ModuleNotFoundError: torch_geometric`
- `tests/test_integration_full_pipeline.py::test_full_v4_pipeline`: same missing module

Both failures are environment gaps, not shown to be code defects. Not run: those two tests with
torch-geometric present.

Model servers (started for about 25 s each, `GET /health`, then stopped by timeout):
- Security Model Server, port 8002: log "Loaded security model from .../best_security_model.pt (530,838 params)". `/health` returned `model_loaded: true`. Trained weights loaded.
- DCM server, port 8003: log "Loaded DCM from .../best_dcm.pt (191,073 params)". `/health` returned `trained: true`. Trained weights loaded.
- Health Model Server, port 8001: not started, because it imports `torch_geometric` (not installed). Not run.

Stored training numbers (from files in the repo, not re-measured):
- `health_report.json`: best_val_f1 0.7979, conformal_q 0.7303. `health_conformal.json` holds q 0.5469. The two files disagree about the conformal quantile.
- `security_report.json`: best_val_f1 1.0, conformal_q 0.0818. `security_conformal.json` holds q 0.0827.
- `dcm_report.json`: best_val_auroc 0.9556.
- A security validation F1 of exactly 1.0 matches the spec note that the generator was too easy. It says nothing about real traces.

Not run: model training, any cluster, `scripts/demo.sh`, latency or throughput measurements ("not measured").

## 5. k3d readiness

What is Minikube-specific in the current scripts:
- `install.sh` requires `minikube` and runs `minikube start --addons=ingress,metrics-server,csi-hostpath-driver,volumesnapshots` and `eval "$(minikube docker-env)"`. None of that exists in k3d.
- Images are built into Minikube's Docker daemon and used with `imagePullPolicy: IfNotPresent`. On k3d each image needs `k3d image import` or a k3d registry. 9 images are built: base, health-model, security-model, dcm, health-agent, security-agent, fusion-agent, dashboard, ransomware-simulator (tag `v4`).
- `demo/victim-app.yaml` uses `storageClassName: standard` (Minikube). k3d's default class is `local-path`.
- VolumeSnapshot CRDs, snapshot controller and a snapshot-capable CSI driver are only provided by the Minikube addons here. Nothing in the repo installs them for k3d. No snapshot code exists anyway.
- Falco is installed with `driver.kind=ebpf` via Helm, errors swallowed (`|| echo skipped`). `CLAUDE.md` already warns that Falco eBPF is unreliable inside k3d on Windows and macOS Docker Desktop. Falco consumer is off by default.
- Ingress: Minikube NGINX addon vs k3s Traefik. The dashboard is reached by port-forward, so this only affects the victim app's Ingress.
- Security Agent uses `hostPID: true`, `privileged: false`, two hostPath mounts. Should schedule on k3d nodes; not tested.
- Redis, Prometheus (kube-prometheus-stack, namespace `monitoring`) and Falco come from Helm, so `helm` is required. Health Agent default Prometheus URL `prometheus-operated.monitoring.svc.cluster.local:9090` matches that chart. MinIO and prometheus-adapter are not installed by any script.
- RBAC: one ClusterRole and ClusterRoleBinding, not scoped per namespace.

On this machine: `docker` and `kubectl` are on PATH (Docker Desktop). `k3d` and `helm` were not found. Host is Windows, which `CLAUDE.md` flags for Falco.

## 6. Demo readiness (spec section 7)

| Item | Rating | Reason |
|---|---|---|
| D-1 k3d cluster, app in `prod` | Needs work (medium) | No k3d script. Victim app is in namespace `demo`, which the agents classify as tier `dev`. See risk 1. |
| D-2 Three servers with trained checkpoints | Needs work (small) | Security and DCM loaded trained weights here. Health server not run here (missing torch-geometric) but a checkpoint is committed. Add a startup check, because a bad load serves random weights with `model_loaded: true`. |
| D-3 Drift end to end | Needs work (large) | Baseline never written (so the patch always escalates), "baseline" is the previous spec, whole-template patch, and Fusion derives the Deployment name by stripping two dash segments from a name that is already the Deployment name. |
| D-4 Kill switch | Needs work (medium) | Nothing exists, and semantics are still pending your confirmation. |
| D-5 Ransomware replay and quarantine | Needs work (medium) | Quarantine policy exists but is namespace-wide. Simulator exists. No trace replay; Falco off by default; without it the agent synthesizes events. |
| D-6 Fail-closed on model pod delete | Needs work (medium) | No fail-closed path; fallbacks lean the other way for security. |
| D-7 Snapshot restore | Not feasible by tomorrow | No snapshot, scale or restore code, plus CSI and snapshotter setup on k3d. |
| D-8 HPA | Needs work (small) | No HPA manifest. metrics-server ships with k3s, CPU HPA needs only a manifest. |
| D-9 DCM compound, dashboard, Grafana | Needs work (small) | DCM server trained and ran here. Dashboard is read-only. No KubeHeal metrics for Grafana. |

## 7. Risks and open questions

Top risks for tomorrow, most serious first:
1. Namespace tier. The victim app is in `demo`, tier `dev` (x0.70). Health risk can reach at most 0.70 adjusted, so AUTO_PATCH (0.85) can never fire there. The namespace name must contain "prod" (x1.20) for D-3 to be reachable.
2. The drift remediation path cannot succeed as written (D-3): empty baseline key, previous-spec comparison, Deployment-name derivation.
3. No Windows-friendly install path: k3d and helm missing, scripts are Minikube, images need `k3d image import`.
4. Random-weights fallback in all three servers, reported as healthy.
5. Security Agent kills processes and applies network policy on its own at risk >= 0.90, outside the policy and any future kill switch. A test mode would not stop it.
6. Quarantine policy applies to the whole namespace and is never lifted except by `reset.sh`.
7. Environment: `torch_geometric` is not installed in the Python found here; `requirements.txt` pins torch 2.2.0 against 2.12.0 installed.

Biggest gaps between the spec (synopsis) and the code for `work`:
- No Executor component, no ledger, no approve/reject UI, no kill switch.
- No snapshot, scale-to-zero or restore path (all of S-RR).
- No golden baseline, no real 60-step metric window, no entropy sampling from live files.
- No HPA, PDB, quotas, NetworkPolicies, Helm chart, Redis AOF, stream reclaim, per-component RBAC.
- Fail-closed policy rule not implemented; Falco path off by default.

Questions for you:
1. Is `origin/main` the real base for `work`? `test` and `feat/dit-sec-train-integrate` add nothing over it. `kali` has 6 unique commits (Minikube resource fixes). Do you want any of them?
2. Kill switch: confirm the proposed semantics in `CLAUDE.md`. Should it also gate the Security Agent's direct kill?
3. Demo namespace: rename `demo` to a name containing "prod", or change tier mapping?
4. Your OS and RAM (WSL2 or native Windows), and whether k3d and helm may be installed.
5. May I install `torch-geometric` (and match torch) in a virtualenv to run the two failing tests and the Health server?
6. Should `.claude/settings.local.json` stay tracked?

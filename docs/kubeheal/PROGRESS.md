# KubeHeal build progress

Resume state for the autonomous build. Plan: `IMPLEMENTATION_PLAN.md`. Target: `PROJECT_SPEC.md`.
Branch: `work` (created from local `main` at 88ce586). `demo` is created from `work` in P10.
Nothing is ever pushed by the agent.

## Machine (checked 2026-11-10)

| Item | Value | Source |
|---|---|---|
| CPU | 13th Gen Intel Core i7-13700HX, 16 cores, 24 logical processors | `Get-CimInstance Win32_Processor` |
| RAM | 34,053,414,912 bytes (about 31.7 GiB) | `Get-CimInstance Win32_ComputerSystem` |
| Docker Desktop | 24 CPUs, 16,613,306,368 bytes memory (about 15.5 GiB), server 29.6.2 | `docker info` |
| OS | Windows 11, PowerShell 7 plus Git Bash | environment |
| Tools installed this session | k3d 5.9.0 (winget `k3d.k3d`), Helm 4.3.1 (`Helm.Helm`; winget only offers v4), k6 (`GrafanaLabs.k6`) | winget |
| Python | venv `.venv` on Python 3.11.9 (global 3.13 cannot run torch 2.2.0) | `py -3.11` |

Sizing: Docker Desktop has about 15.5 GiB, so the k3d stack (1 server, 2 agents, Prometheus, Redis, MinIO,
three model servers, agents, dashboard) is sized to stay under roughly 10 GiB, leaving headroom for builds.
Real usage is measured later and recorded under `docs/kubeheal/results/`.

## Decisions (from the user, 2026-11-10)

- Base: local `main` (88ce586). Work on `work`. `demo` from `work` in P10. Ignore kali, master, test, feat/dit-sec-train-integrate.
- Kill switch: `test` = dry run, no Kubernetes write call anywhere (including the Security Agent), ledger says "would have". `enforce` = normal. This supersedes the "pending confirmation" wording in the spec and CLAUDE.md.
- Machine: native Windows, Docker Desktop, PowerShell.
- Tools may be installed (Python, k3d, helm, k6, charts).
- Before P12 training: stop and ask.

## Phase status

| Phase | Status |
|---|---|
| P0 Environment and guardrails | done (deny rules not proven enforced in-session; git-level push block verified) |
| P1 Core correctness | done, see log |
| P2 Executor and least-privilege RBAC | done, see log |
| P3 Kill switch | done, see log |
| P4 Record | done, see P4 checklist |
| P5 Sense | done, merged (a6ef46a), see P5 log |
| P6 Decide | in progress on wave/P6 (worktree scratchpad/wt/P6, last commit 36d436d, may have uncommitted work); NOT merged, NOT reviewed; see docs/kubeheal/NEXT_FOR_CODEX.md |
| P7 Remediation paths | code done and merged (5bd3558), proven with fakes only; open items P7-RR-9 to RR-11 and P6-D7, RR-7 needs P10 |
| P8 Dashboard | done, merged (218029c) |
| P9 Platform | done, merged (see merge commit); helm lint and template pass with lab example overlay; nothing run on a cluster yet |
| P10, P11, P13 | not started |
| P12 Model hardening | NOT started; P12-H (retraining on live cluster data) is not approved |

## Task checklist

Legend: `[x]` done, `[~] <agent>` in progress, `[ ]` open. `size: S` can be taken by a small local model
(it must not touch `decision_policy.py`, `agents/executor/`, `k8s/rbac/`); M and L need a stronger agent.
Each line: ID, goal, files, verify. "needs" lists tasks that must be done first. Tests run with
`PYTHONPATH=. .venv\Scripts\python.exe -m pytest tests/ -q`.

### P0 to P3 (done)
- [x] P0 environment, venv, guardrails, branch `work`, PROGRESS.md
- [x] P1 core correctness F1 to F9 (see P1 log)
- [x] P2 Executor service and least-privilege RBAC (see P2 log)
- [x] P3 kill switch (see P3 log)
- [x] AGENTS-1 agent-neutral instructions, `.githooks/pre-push`, subagents, this checklist (Claude Code, 2026-11-10)

### Review fixes after P0 to P3 (2026-11-10, done)
- [x] REV-1 P1: Health Agent no longer emits a heuristic score when the Health Model is unavailable (fail closed); Fusion takes the pod only from a security event and does not queue contain without one; circuit breakers count only enforced actions, after queueing; incident lock heartbeat extends only its own lock (Lua); Executor ledger target built with `json.dumps`; AUTO-KILL text removed from README, demo.sh, architecture docs.
- [x] REV-2 P3: `contain()` stops (no pod delete) when the quarantine policy cannot be created; live kill-switch test restores the original namespace label and checks kubectl return codes; no-writes detector also flags `call_api` and `collection_*` deletes.
- [x] REV-4 P7 review (work 1ba19b2): legacy `actions.contain` and `patch_to_baseline` removed (they held a `delete pods` call that RBAC does not grant; tests migrated to `_write` gate tests), canary metric-source exception rolls back, `refused` outcomes counted as refused, unused `_record_step` removed, snapshot skip recorded once. Live RBAC check on k3d-kubeheal after applying the manifest: 696 checks, 0 failures (2026-11-10, this machine; VolumeSnapshot checks skipped, CRD not installed until P10). Remaining items are P7-RR-9 to RR-11 and P6-D7.
- [ ] REV-3 deferred, small: log a warning when namespace labels never load in `ModeWatcher`; unit test for Fusion mode-watcher start failure; document that a drifted spec seen first becomes the golden baseline; camelCase/snake_case parity test for `yaml_diff_to_graph`; owner decision on tightening `.claude/settings.json` deny patterns (`git checkout .*`, `git restore *`, narrower `Remove-Item *.git*`) and removing the inactive `.git/hooks/pre-push`.

### Owner decisions (2026-11-11)
- Executor settings are CHOSEN DEFAULTS, NOT MEASUREMENTS, tunable by environment and Helm values: `PROMETHEUS_URL=http://prometheus-operated.monitoring.svc.cluster.local:9090`, `SNAPSHOT_CLASS=csi-hostpath-snapclass` (P10 must create a VolumeSnapshotClass with exactly this name), `CANARY_WINDOW_S=30`, `ROLLOUT_TIMEOUT_S=180`, `ROLLOUT_POLL_S=5`. In code: `agents/executor/config.py` `DEFAULTS` apply when the variable is absent from the process environment; a variable set but empty or invalid still escalates (fail closed). Helm values: set by the P9 builder (extra brief).
- Victim app metrics: no guessed names. A small victim app under `demo/victim-app/` (FastAPI with prometheus_client) exports `http_requests_total` (labels method, path, status) and `http_request_duration_seconds` (histogram), with a ServiceMonitor; container inputs use the real series `container_cpu_cfs_throttled_periods_total` / `container_cpu_cfs_periods_total`, `container_memory_working_set_bytes`, `kube_pod_container_status_restarts_total`. See tasks P5-Q1, P10-V1, P10-V2.

### Health inputs: training vs serving (found 2026-11-11, option A done)
Status: **Drift pipeline complete; inputs now match training preprocessing; live Health Model scores are not yet validated on real cluster windows. Retraining on live cluster data (P12-H) is a future step, not approved yet.** Drift detection currently relies mainly on the configuration diff; metric-based evidence is limited in the current checkpoint and is addressed by P12-H.
Finding. The Health Model was trained on windows built from 9 scalar CSV columns (broadcast over 60 steps with noise), scaled by constants, while serving passed raw Prometheus values. Facts checked in `models/train_health_model.py` and the CSV (4782 rows): units in the CSV are cores (CPU), MiB (memory limit), seconds (latency), bytes (working set), and `app_instance_count` is the replica count; six of the 15 channels are zero in training (`memory_rss_bytes`, `http_p50_latency_ms`, `http_p999_latency_ms`, `network_receive_bytes`, `network_transmit_bytes`, `disk_io_bytes`); the `http_request_rate` channel holds replicas/100 because a dict-key overwrite in the old CSV map replaced `request_rate` with `app_instance_count`; `cpu_throttle_percent` is a usage/limit proxy in 0..1; several scaling constants do not match the CSV units (latency seconds divided by 2000, CPU cores divided by 2000), so those channels sit near zero in training.
Fix (P5-Q2a, done): one shared module `models/health_model/preprocess.py` reproduces that training scaling exactly. Training (`build_metric_window`) and serving (`services/health_model_server`) both call it; the Health Agent sends the raw window plus the replica count and logs the real CFS throttle ratio separately (`cfs_throttle_percent`, not a model input). Parity: `tests/test_health_preprocess_parity.py` compares against a frozen copy of the old training code, bit for bit on all 4782 CSV rows, and through the real server endpoint.
Version guard (2026-11-11): `PREPROCESS_VERSION = "v1-legacy"` in `models/health_model/preprocess.py`; the checkpoint's expected version is the sidecar `models/health_model/checkpoints/best_health_model.preprocess.json` (registry checkpoints carry `<stem>.preprocess.json` next to the object); `services/health_model_server` raises `PreprocessVersionMismatch` at startup and does not start when the sidecar is missing or differs (random-weights development mode has no checkpoint and is not checked). Tests: `tests/test_health_preprocess_version.py`.
What this does not do: it does not validate the model on live data, and the quirks above (six dead channels, replicas in the request-rate channel, constants that do not match units) are kept on purpose because the checkpoint depends on them. P12-H (not approved) would retrain on live windows through the same preprocessing. `models/generate_health_training_data.py` stores raw live windows: they must go through `preprocess_window` before training.

### P4 Record: ledger and metrics (touches `agents/common/`, `k8s/`, `deploy/grafana/`, `services/`)
- [x] P4-L1 size: M. Added `Ledger.append(incident_id, step, payload)` with per-incident sequence keys, an in-memory backend, and a MinIO client adapter. Added validation and overwrite refusal tests. Focused tests: 7 passed with system Python 3.13. Full suite collection unavailable because the project venv launcher targets an inaccessible Python 3.11 install and system Python lacks `redis` and `aiohttp`.
- [x] P4-L2 size: M. Added `k8s/minio.yaml` with a persistent single-node MinIO-compatible SILO service, bootstrap Job, versioned object-lock bucket with default COMPLIANCE retention, and least-privilege ledger writer (list/get/put, no delete). Added `scripts/minio_secret.ps1` to generate root/client Secrets without printing values and `scripts/ledger_check.py` to append a disposable incident and attempt deleting only its exact version. k3d check passed: version ID present, COMPLIANCE retention reported, version-specific delete refused (`InvalidRequest`). The official MinIO Quay image returned 401 in this environment, so the manifest uses SILO, a maintained MinIO-compatible fork, pinned to `RELEASE.2026-11-09T00-00-00Z`. `python -m pytest tests/test_ledger.py tests/test_fusion_reliability.py tests/test_killswitch.py -q`: 51 passed; manifest server-side dry-run passed; `git diff --check` passed. Needs: P4-L1.
- [x] P4-M2 size: M. Exposed Prometheus `/metrics` from all eight components: worker agents use dedicated listeners; model servers and dashboard use FastAPI routes. Added container ports, Prometheus discovery jobs, and runtime metric updates for model latency, decisions, actions, dry runs, and mode escalations. Added `prometheus-client` to component image/dependency manifests. Focused P4 tests: 55 passed, 1 skipped; `py_compile`, all Kubernetes YAML parsing, and `git diff --check` passed.
- [x] P4-L3 size: M. Fusion now appends detection, scores, decision/rationale, and pending approval-request records using the shared ledger; ledger I/O runs off the event loop, and a write failure leaves the input unacked. In-memory integration test verifies records and incident ID linkage. Focused Fusion/ledger tests: 16 passed. P4-L2 now wires deployed Fusion to MinIO.
- [x] P4-L4 size: L. Executor now records each gated write attempt/result, final outcome, escalation, and ConfigMap mode changes in the ledger. Ledger I/O runs off the event loop; watcher logging failures do not interrupt mode updates. Focused Executor/kill-switch tests: 9 passed, including dry-run and mid-action stop records. P4-L2 now wires deployed Executor to MinIO.
- [x] P4-M1 size: S. Added component-local Prometheus metric registry and helpers for decisions, actions/outcomes, escalations, dry-run actions, model latency, queue depth, and stream lag. Added `prometheus-client>=0.20.0` to requirements. Focused metrics and ledger tests: 9 passed with system Python 3.13.
- [x] P4-G1 size: S. Added `deploy/grafana/kubeheal-overview.json` with decision/action rates, model latency, queue depth/stream lag, available KubeHeal replicas, dry-run actions, and escalations. Test validates JSON and confirms every queried metric exists in P4-M1 or the scraped kube-state-metrics set. Dashboard test: 1 passed.
- [x] P4-R1 size: M. All three model servers now try the configured `MODEL_REGISTRY_OBJECT` in MinIO at startup, then fall back to the baked-in checkpoint if the object is absent, unreadable, or invalid. The selected source is exposed in `/health`; temporary downloads are removed. Model deployments reference the existing `kubeheal-minio-client` Secret optionally (owner approved 2026-11-10), use `kubeheal-ledger` object prefixes, and therefore still start without MinIO. Fake-store tests: 5 passed, including success, missing credentials, download failure, corrupt object fallback, and manifest wiring. `py_compile`, model manifest parsing, and `git diff --check` passed. Limitation: the existing shared ledger credential also has `PutObject` access; model-server access is not read-only.
- [x] P4-I1 size: M. Added `tests/test_record_pipeline.py`: a high-risk incident passes through Fusion and the Executor with one shared ledger; detection, scores, decision, Executor dry-run step, and result all share an incident ID, and the dry-run causes no Kubernetes writes. Focused integration test: 1 passed. Live k3d `scripts/ledger_check.py` result from 2026-11-10: created object version with COMPLIANCE retention; exact-version delete refused (`InvalidRequest`). Needs: P4-L2, P4-L3, P4-L4.

### P5 Sense: real signals (touches `agents/health_agent/`, `agents/security_agent/`, `tests/fixtures/`)
- [x] P5-H1 size: M. Health Agent real Prometheus `query_range`, 60 steps of 5 s per pod, 15 metrics, missing metrics flagged (not 0). Files: `agents/health_agent/`. Verify: unit tests with a fake Prometheus response. Needs: none.
- [x] P5-H2 size: S. Fixtures and tests for P5-H1 (full window, missing metric, short window). Verify: pytest. Needs: P5-H1.
- [x] P5-S1 size: M. Security Agent entropy sampler: 30 samples, 2 s apart, of data written by the suspect process via `/proc/<pid>/fd` targets on the pod volume, bounded read size. Files: `agents/security_agent/`. Verify: unit test on a temp directory. Needs: none.
- [x] P5-S2 size: M. Falco consumer (enabled when available) and replay mode streaming recorded Falco JSON traces from files. Files: `agents/security_agent/`. Verify: test replays a fixture into the event pipeline. Needs: none.
- [x] P5-S3 size: S. Recorded Falco fixtures under `tests/fixtures/falco/` and a test that replay feeds the Security Model input. Verify: pytest. Needs: P5-S2.
- [x] P5-S4 size: S. Remove synthetic syscall fabrication from live paths (keep in tests or replay tooling). Verify: grep test that live code has no fabrication. Needs: P5-S2.

- [ ] P5-Q1 size: M. Align the Health Agent PromQL to the real series (see Owner decisions): keep the 15 column names and meanings, change the `app-guess` rows in `agents/health_agent/metric_queries.py` to the victim-app contract (`http_requests_total{method,path,status}`, `http_request_duration_seconds` histogram, labels `namespace` and `pod` come from the ServiceMonitor), update the module docstring (no longer guesses), tests. Verify in P10-V2. Needs: P10-V1 for the contract.
- [x] P5-Q2a size: L. Shared Health Model preprocessing for training and serving (`models/health_model/preprocess.py`), parity tests, agent sends replicas and logs the real CFS ratio. Done 2026-11-11 (option A, owner decision). No retraining.
- [ ] P12-H size: L. NOT APPROVED, not started: retrain on live cluster windows through the shared preprocessing and recalibrate. Waits for the owner's go. P12-H fix list for the retrain (checkpoint then gets a NEW preprocessing version, for example `v2`, and a sidecar to match): (1) correct the dict-key overwrite in the CSV map so the `http_request_rate` channel holds the real request rate (today it holds replicas/100); (2) fill the six zeroed channels (`memory_rss_bytes`, `http_p50_latency_ms`, `http_p999_latency_ms`, `network_receive_bytes`, `network_transmit_bytes`, `disk_io_bytes`) from live windows; (3) use scaling constants that match the real units (latency in ms or s consistently, CPU in cores or millicores consistently, memory in bytes), and make `cpu_throttle_percent` the real CFS ratio if that is what is wanted; (4) bump `PREPROCESS_VERSION` in `models/health_model/preprocess.py` and keep `v1-legacy` readable only for the old checkpoint; (5) the trainer writes the sidecar (already wired in `train_health_model.py`), `upload_to_registry.py` ships it, and the server refuses a mismatch.

### P6 Decide: complete policy and fusion (touches `agents/fusion_agent/`, `agents/common/`, `tests/`)
- [~] builder-E (wave/P6) P6-D1 size: L. `models_ok` input to the pure policy: missing or late model response means HUMAN; per-call deadlines in Fusion. Files: `decision_policy.py` (stronger agent only), `agents/fusion_agent/`. Verify: policy tests plus timeout test. STOPPED HERE (HANDOFF): policy inputs committed on wave/P6 (3ea4dd7); not reviewed or merged.
- [~] builder-E (wave/P6) P6-D2 size: M. OBSERVE triples sampling for that pod for a bounded period. Verify: test on sampling rate and expiry. Needs: P5-H1. STOPPED HERE: observe sampling committed on wave/P6 (36d436d), agent side of the contract still needs a change in agents/health_agent and agents/security_agent; not reviewed.
- [~] builder-E (wave/P6) P6-D3 size: L. Protected-namespace label guard: `kubeheal/protected=true` means never automatic. Files: `decision_policy.py`, Fusion. Verify: policy test. STOPPED HERE: committed on wave/P6 (36d436d); not reviewed.
- [~] builder-E (wave/P6) P6-D4 size: L. Circuit breakers as sliding windows: patches per Deployment 10/hour, containments per namespace 3/hour. Verify: window tests. STOPPED HERE: committed on wave/P6 (36d436d); not reviewed.
- [~] builder-E (wave/P6) P6-D5 size: M. Burn-in driven by a real counter of metric samples (2000), not only an env var. Verify: test with counter below and above. STOPPED HERE: committed on wave/P6 (36d436d); not reviewed.
- [~] builder-E (wave/P6) P6-D6 size: M. Wire `interpretation_client.py`: field mapper, SHAP (KernelExplainer for metrics, attention fallback documented), causal chain with attack onset T0. Verify: tests with a stub model. STOPPED HERE: not started or uncommitted in the P6 worktree (check `git -C <wt/P6> status`).
- [~] builder-E (wave/P6) P6-D7 size: M. From the P7 review: Fusion emits a `restore` request after contain (or after human approval) with `t0_ms` (attack onset from the causal chain) and `workload_kind`. Today no Fusion code sets them, so every restore escalates `t0_missing`. Also handle the two security events per incident from P5 (initial and complete) and read `model_scored`, `syscall_source`, `entropy_valid_samples`. Files: `agents/fusion_agent/`. STOPPED HERE: not started or uncommitted in the P6 worktree; tests/test_fusion_incident.py was untracked.
- [~] builder-E (wave/P6) P6-R1 size: M. Redis stream reliability for Fusion AND the Executor (`agents/executor/main.py` also never reads its pending list): `XAUTOCLAIM` of stale pending entries, dead-letter stream after N failures, escalate after N tries. Verify: pending-reclaim test with two consumers for both consumers. (From P1 and P2 reviews.) STOPPED HERE: shared reclaim and Executor consume path committed on wave/P6 (2e3a6b1); not reviewed.

### P7 Remediation paths (touches `agents/executor/` only; write paths: stronger agent)
Drift (canary):
- [x] P7-RR-1 size: L. Save rollback point; patch only drifted fields; maxUnavailable 0. Verify: unit test with a fake API.
- [x] P7-RR-2 size: L. Canary watch: p99 latency and CPU throttling for 3 windows; keep or roll back; escalate on rollback; each step to ledger. Needs: P7-RR-1, P4-L1.
Ransomware:
- [x] P7-RR-3 size: L. Rolling VolumeSnapshots every 5 min, keep 12, for PVCs in protected namespaces (Executor-owned scheduler or CronJob with scoped SA). Verify: unit test of retention.
- [x] P7-RR-4 size: L. Quarantine: pod label plus deny-all NetworkPolicy selecting the label; forensic on-demand snapshot. Verify: unit test.
- [x] P7-RR-5 size: L. Scale owner to 0 and remember replicas; choose newest rolling snapshot before T0; restore a new PVC; repoint workload; redeploy with image pinned by digest; scale back. Verify: unit tests; end-to-end in P10.
- [x] P7-RR-6 size: L. Entropy re-check on the restored volume; lift quarantine if clean, else keep isolated and escalate. Verify: unit test. Needs: P7-RR-4, P7-RR-5.
- [x] P7-RR-8 size: L. From P2 review: validate Executor stream fields and pod ownership; patch only the named drift field; quarantine only labelled pods; trim Executor RBAC to dispatched write verbs. Verify: unit tests and RBAC manifest assertions. The live `kubectl auth can-i` check must be rerun after this RBAC manifest is applied.
- [ ] P7-RR-9 size: L. From the P7 review. Production entropy check for restore: `ExecutorService.entropy_check` is never wired, so a real restore always ends `restored_kept_isolated: entropy result unknown` (fail safe, but "restored" is only reachable in tests). Decide how the Executor obtains an entropy verdict for the restored volume (for example a short-lived read-only Job that reuses `agents/security_agent/entropy_sampler.py`) and wire it. Files: `agents/executor/`.
- [ ] P7-RR-10 size: L. From the P7 review. Redelivery and cleanup: write the result record before the ack and make patch and restore idempotent per `incident_id` (today a redelivery gives `escalated:preflight_error` or `no_drift_at_field`); metrics are counted before `_record`; use the saved rollback point after an Executor restart; await the rollback rollout; pin initContainer images too; create the quarantine policy only after the pod and owner check; remove the `kubeheal/original-replicas` annotation after a restore; operator unfreeze for `SnapshotFreeze` keys; give the snapshot scheduler its own incident id per run; decide whether a failing ledger write should fail closed. Needs: P6-R1.
- [ ] P7-RR-11 size: M. From the P7 review. After a restore the golden baseline must be re-baselined (new claimName, digest image), otherwise the drift path reverts the restore. Files: `agents/health_agent/baseline.py`, `scripts/baseline_tool.py`, Executor hook. Needs: P7-RR-9.
- [ ] P7-RR-7 size: M. Measure RPO and RTO on k3d and write `docs/kubeheal/results/`. Verify: results file generated by a script. Needs: P10 cluster.

### P8 Dashboard (touches `dashboard/`)
- [x] P8-D1 size: M. Approve and reject flow for HUMAN decisions (writes `kubeheal.exec` and the ledger). Verify: API tests. Needs: P4-L1.
- [x] P8-D2 size: M. Incident page: scores, CIs, SHAP view, causal chain with T0, ledger timeline. Verify: page renders against a seeded incident. Needs: P6-D6, P4-L1.
- [x] P8-D3 size: M. Kill switch status and toggle with admin token, mode history. Verify: API test for toggle with and without token.
- [x] P8-D4 size: S. Ingress manifests (Traefik on k3d, NGINX in generic values). Verify: `kubectl apply --dry-run=client`.

- [ ] P8-D5 size: M. Owner request 2026-11-11, do on `work` AFTER the P9 and P6 merges and BEFORE P10: the dashboard approval claim (`CLAIM_TTL_S`, now 30 days) gets a short chosen default TTL (about 10 minutes, documented as tunable, labelled chosen not measured); startup reconciliation in the dashboard that scans claims against the exec stream and the ledger and completes (writes the missing `approved`) or releases claims with no matching record; an admin-only 'release claim' action that writes a ledger entry (`claim_released`, actor). Files: `dashboard/`, tests `tests/test_dashboard_*.py`. Tests for each (short TTL, reconciliation complete and release, release action needs the token and writes the ledger entry).

### P9 Cloud platform (touches `deploy/helm/`, `k8s/`, `eval/`)
- [x] P9-H1 size: M. Helm chart `deploy/helm/kubeheal` replacing `scripts/install.sh`; values-dev, staging, prod, k3d-demo. Verify: `helm lint` and `helm template` for all four.
- [x] P9-H2 size: S. Namespaces prod, staging, dev with ResourceQuota, LimitRange, `kubeheal/tier` label. Verify: `helm template`.
- [x] P9-H3 size: M. Model servers: 2+ replicas, PDB minAvailable 1, topology spread, HPA 2 to 8 on request queue depth through prometheus-adapter (servers export the metric); CPU HPA only as documented fallback. Needs: P4-M1.
- [x] P9-H4 size: M. (script written and unit-tested, NOT run on a cluster: needs the cluster owner in P10) Resource profile script in `eval/` that measures usage; requests and limits come from the recorded measurement. Needs: cluster (cluster owner).
- [x] P9-H5 size: S. NetworkPolicy around `kubeheal` (only agents, dashboard, Prometheus reach model servers). Verify: `helm template`; enforcement check in P10.
- [x] P9-H6 size: S. Redis with AOF on a PVC, plus Redis auth (the Executor trusts every message on `kubeheal.exec`, so only Fusion and the dashboard may write to Redis). Verify: `helm template`. (From P2 review.)
- [x] P9-H8 size: S. Executor in the chart: image build and apply (legacy `scripts/install.sh` does not deploy it), readiness and liveness probes, securityContext. Verify: `helm template`. (From P2 review.)
- [x] P9-H7 size: M. ONNX or `.pt` serving by config where export parity holds (existing export scripts). Verify: tests with config switch.

### P10 k3d environment and `demo` branch (cluster owner only)
- [ ] P10-U1 size: L. Create `demo` from `work`; `demo/k3d/up.ps1` and `down.ps1` (cluster, kubeconfig fix, CSI hostpath, external-snapshotter, VolumeSnapshotClass, NetworkPolicy check, Prometheus, prometheus-adapter, Redis, MinIO, Helm install, image build and import). Needs: P9.
- [ ] P10-U2 size: M. Falco install attempt with automatic replay fallback and clear message. Needs: P5-S2.
- [ ] P10-U3 size: M. Victim apps in prod (PVC with real files) and one in dev.
- [ ] P10-U4 size: L. `demo/scripts/demo.ps1` numbered steps covering the full list in the plan. Needs: P6, P7, P8.
- [ ] P10-U5 size: S. `demo/README.md` (run order, expected output, what to say, limitations). It must carry the status line: "Drift pipeline complete; inputs now match training preprocessing; live Health Model scores are not yet validated on real cluster windows. Retraining on live cluster data (P12-H) is a future step, not approved yet. Drift detection currently relies mainly on the configuration diff; metric-based evidence is limited in the current checkpoint and is addressed by P12-H."
- [ ] P10-U6 size: L. Acceptance: `up.ps1`, all demo steps, reset, twice in a row without manual fixes.

- [ ] P10-V1 size: M. `demo/victim-app/`: small FastAPI app with prometheus_client exporting `http_requests_total` (method, path, status) and `http_request_duration_seconds` (histogram), Dockerfile, Deployment and Service for prod and dev, ServiceMonitor. Verify: unit test of the exporter; scrape on k3d in P10-V2. Needs: P9 (chart or manifests), Prometheus operator in P10-U1.
- [ ] P10-V2 size: M. On k3d verify that each of the 15 Health Agent queries returns data for the victim Deployment and record the result per query in this file (query, series returned yes/no, sample value, date). Needs: P10-V1, P10-U1.
- [ ] P10-U7 size: M. On k3d verify the queue-depth autoscaling chain (owner decision 2026-11-11, S-CL-1): the per-pod gauge `kubeheal_model_inflight_requests` is scraped, prometheus-adapter exposes it (`kubectl get --raw /apis/custom.metrics.k8s.io/v1beta1/namespaces/kubeheal/pods/*/kubeheal_model_inflight_requests` returns values) and `kubectl describe hpa` shows the HPA reading it (not `<unknown>`); record the outputs here with date. Needs: P9 merge with the gauge, P10-U1 (Prometheus and adapter).
- [ ] P10-V3 size: S. Create the VolumeSnapshotClass `csi-hostpath-snapclass` (exact name, owner decision) in `up.ps1`; check `scripts/rbac_check.py` snapshot checks once the CRD exists.

### P11 Evaluation harness (touches `eval/`, `docs/kubeheal/results/`; cluster owner runs)
- [ ] P11-E1 size: M. k6 load test 10 to 200 simulated pods, p50 and p95 vs replicas. Also tune the queue-depth HPA target (a CHOSEN DEFAULT in the chart values, not a measurement) from the measured replicas-versus-load data.
- [ ] P11-E2 size: M. Chaos runs (Chaos Mesh or kubectl): detection continuity, fail-closed rate.
- [ ] P11-E3 size: M. RPO and RTO runs against a database volume. Needs: P7.
- [ ] P11-E4 size: M. End-to-end time-to-action per stage.
- [ ] P11-E5 size: M. Baselines (Falco rules only, fixed entropy threshold, diff-only drift, single replica, pod delete only).
- [ ] P11-E6 size: S. FP32 vs FP16 latency and memory.
- [ ] P11-E7 size: S. Each results file states machine, cluster and date. Verify: scripts produce CSV plus markdown.

## P0 log

Plan: switch to `work`; copy plan into repo; update CLAUDE.md; push-blocking guards and verify; untrack
`.claude/settings.local.json`; venv with torch 2.2.0 + requirements; run tests; start Health server;
create the k3d cluster early (P2, P4, P9 need it for acceptance); write this file.

Notes so far:
- `IMPLEMENTATION_PLAN.md` was in `Downloads`; copied to `docs/kubeheal/`.
- `prompts/06-resume.md` did not exist in the kit; written in the repo.
- Added `httpx>=0.25,<0.28` to `requirements.txt` (TestClient needs it; 0.28 breaks starlette 0.36).
- `.gitattributes` created: LF for all text (so shell scripts and images are not broken by CRLF), CRLF for `.ps1`.
- Tests: 44 passed in the venv (includes the two torch_geometric tests).
- Health Model server started locally: log line "Loaded health model from ...best_health_model.pt (1,028,595 params)", `/health` returned `model_loaded: true`. (Meaning of that flag is fixed in P1/F1.)
- Push blocking:
  - Deny rules written to `.claude/settings.json` for both the Bash and PowerShell tools (push in every form, reset --hard, clean, checkout --, branch -D, deleting .git, k3d cluster delete).
  - Test result: with those rules present, `git push --dry-run` via Bash, via PowerShell and via `git -C` were NOT blocked in this session (dry-run only, nothing was sent). So the rules are not proven enforced here; this session may not have reloaded settings, or the local `bypassPermissions` mode overrides them. The user should restart the session or check `/permissions`.
  - Because of that, push is blocked at the git level instead, and this was verified: `remote.origin.pushurl` is set to an invalid value, and `.githooks/pre-push` (enabled by `git config core.hooksPath .githooks`, commit 7729bc7; it replaced the earlier `.git/hooks/pre-push` that checked `KUBEHEAL_ALLOW_PUSH`, now inactive) rejects unless `ALLOW_PUSH=1`. `git push --dry-run origin work` now fails from Bash, PowerShell and with `-C`; a real push to a scratch bare repo was rejected by the hook. Fetch still works.
  - To push later, the user restores the URL (see final summary).

- k3d cluster `kubeheal` created (1 server, 2 agents, `-p 8080:80@loadbalancer`, k3s v1.35.5+k3s1, kernel 6.18.33.2-microsoft-standard-WSL2). Kubeconfig points at `host.docker.internal`, which is refused on this machine, so the cluster entry was set to `https://127.0.0.1:48349` (TLS works). Scripts must repeat that fix after `k3d cluster create`. A pre-existing user cluster `hybrid-demo` exists and is never touched. Always use `--context k3d-kubeheal`.

## P1 log (core correctness)

Plan: F1 fail-closed model servers; F2 golden baseline (SET NX, live vs golden, reset tool); F3 explicit
workload name in events; F4 ack only on success; F5 unique lock token; F6 Security Agent on
`proc_scanner`; F7 Security Agent no longer acts; F8 AUTO_KILL to CONTAIN; F9 conformal file decision;
static test that no Kubernetes write or `os.kill` exists outside `agents/executor/`.

Done:
- F1: `services/ckpt.py`. Missing/corrupt checkpoint: `/health` 503 `model_loaded:false`, score endpoints 503. `ALLOW_RANDOM_WEIGHTS=true` serves random weights and `/health` says `random_weights:true`. Applied to health, security and DCM servers (the DCM cold-start fallback is gone). Tests: `test_model_servers_fail_closed.py`.
- F2: `agents/health_agent/baseline.py`; golden baseline written once with SET NX at `kubeheal:baseline:<ns>:<deployment>`; `replicas` excluded from drift; spec serialised as camelCase JSON via `ApiClient.sanitize_for_serialization` (the old `to_dict()` gave snake_case keys that cannot be patched back). Reset tool `scripts/baseline_tool.py`. Tests: `test_golden_baseline.py`. Note: the model input format changed from snake_case to camelCase keys for multi-word fields; the committed checkpoint was trained on whatever the training CSV used (not re-checked here).
- F3: events carry `deployment`; Fusion keys correlation, locks and circuit breakers by `<ns>:<deployment>`; dash-stripping removed. Security events get the workload from the pod owner chain (Pod, ReplicaSet, Deployment) through the read-only `PodIndex`. This also fixes a pairing bug from the scan: health events were keyed by Deployment name and security events by pod name, so they never paired.
- F4: `_handle_entry` acks only after success; failures stay pending (reclaim and dead-letter are P6).
- F5: lock token is `uuid4().hex` per acquisition.
- F6: Security Agent uses `proc_scanner.PodIndex` + `scan_pids` (cgroup v1 and v2, any namespace, no `kubectl` subprocess). Tests: `test_proc_scanner_index.py`.
- F7: removed `_direct_kill`, `os.kill`, the agent's own NetworkPolicy. It only publishes events (risk >= 0.40).
- F8: `AUTO_KILL/HUMAN_KILL` to `AUTO_CONTAIN/HUMAN_CONTAIN`, `circuit_breaker_kills` to `circuit_breaker_containments`, `RANSOMWARE_DIRECT_KILL` removed, env and seed script renamed.
- F9: decision and facts in `docs/kubeheal/CONFORMAL.md`. The loaded quantile is not used in the interval; this stays open until P12.
- All Kubernetes writes moved to `agents/executor/actions.py` (Fusion calls it in-process until P2 makes the Executor a service). `tests/test_no_writes_outside_executor.py` enforces this for every later phase.

Acceptance: 72 tests pass (`PYTHONPATH=. .venv\Scripts\python.exe -m pytest tests/ -q`, 2026-11-10, this machine). No write call outside `agents/executor/`.
Deferred: none.
Next step: P2 Remediation Executor service and least-privilege RBAC (needs the k3d cluster, already running).

## P2 log (Executor and least-privilege RBAC)

Plan: Executor service on a new stream `kubeheal.exec`; Fusion only publishes requests; one
ServiceAccount per component; read-only roles for agents and dashboard; write verbs for the Executor only
through RoleBindings in prod, staging, dev; hard target guard; `kubectl auth can-i` proof.

Done:
- `agents/executor/main.py` (consumer group `executor`, ack only after handling, outcome written to `kubeheal.actions`), `guard.py` (never acts on `kubeheal`, `kube-system`, `kube-public`, `kube-node-lease`; only `EXEC_NAMESPACES`, default prod,staging,dev), `Dockerfile.executor`, `k8s/executor-deployment.yaml`.
- Fusion Agent no longer has Kubernetes clients; `_execute` publishes `kubeheal.exec` requests with an `incident_id` and records `queued_for_executor`.
- `k8s/rbac/rbac.yaml` rewritten: 8 ServiceAccounts (model servers and DCM mount no token), ClusterRoles `kubeheal-observer`, `kubeheal-namespace-reader`, `kubeheal-executor-read`, `kubeheal-executor-write` (bound only by RoleBindings in prod/staging/dev). Namespaces prod/staging/dev created with `kubeheal/tier` labels. All manifests point at their own ServiceAccount. The Security Agent DaemonSet lost the `KILL` capability.
- Applied to the k3d cluster `kubeheal`. `scripts/rbac_check.py`: 224 checks, 0 failures (agents, servers and dashboard cannot patch, delete or create in prod/staging/dev/kube-system/kubeheal; executor can in prod/staging/dev and cannot in kube-system, kubeheal, default, cannot read secrets or create clusterrolebindings). The 5 VolumeSnapshot checks per case are skipped until the CRD is installed in P10 (script prints a note). Pytest wrapper `tests/test_rbac_k3d.py` skips when the cluster is unreachable.

Acceptance: 79 tests pass (2026-11-10, this machine). RBAC matrix proven on k3d.
Deferred: VolumeSnapshot verbs checked only after the CRD exists (P10). The Executor image is not built or deployed yet (P9/P10).
Next step: P3 kill switch (ConfigMap `kubeheal-mode`, Watch API, policy input, Executor gate).

## P3 log (kill switch)

Plan: ConfigMap `kubeheal-mode` + namespace label, Watch API (not polling), unreadable means test, fresh
install `test`, pure policy with `mode` input and `dry_run` result, Executor hard gate before every
write, mid-action stop with escalation, read-only components, admin-only write Role.

Done:
- `agents/common/killswitch.py`: pure `normalize` / `effective_mode` / `is_dry_run`, and `ModeWatcher` (Watch API on the single ConfigMap via field selector, and on namespaces; reconnect loops; unreadable, missing key, deleted ConfigMap or any value other than exactly `enforce` mean `test`; namespace labels not loaded or watch broken also mean `test`; history of mode changes with an `on_change` hook that P4 connects to the ledger).
- Semantics decision (within spec S-KS-2): the global mode is absolute. The label `kubeheal/mode=test` makes one namespace stricter while the global mode is `enforce`. The label can never enable enforcement while the global mode is `test`. Recorded here as an interpretation, not a spec change.
- Policy stays pure: `DecisionInput.mode` (default `test`), `DecisionOutput.dry_run`. The decision itself is identical in both modes (Sense, Score, Decide always run).
- Fusion Agent watches the mode (read only), passes it to the policy, marks queued requests `dry_run`.
- Executor: its own `ModeWatcher`; `RequestGate` combines its own reading with the request's `dry_run` flag (can only get stricter); `actions._write` is the single choke point and asks the gate right before every write. Outcomes: `DRY RUN: would have CONTAIN prod/pod (create_quarantine_policy, delete_pod)` and, when the mode flips between steps, `stopped_mode_test: ...` plus an entry on stream `kubeheal.escalations` (`required: human`). A missing gate blocks.
- `k8s/kill-switch.yaml`: ConfigMap `kubeheal-mode` (`mode: test`), Role `kubeheal-mode-reader` (get/list/watch of that one ConfigMap) for fusion-agent, executor, dashboard; Role `kubeheal-mode-admin` (get/patch/update of that one ConfigMap) bound to the dashboard ServiceAccount only (its toggle endpoint will require an admin token in P8). Applied to the cluster; `scripts/rbac_check.py` now has 245 checks, 0 failures.
- Security Agent: it has no write call at all (P1), so the gate covers it by construction; the static tests prove it.
- Tests: `tests/test_killswitch.py` (pure rules, watcher state, policy, actions gate, mid-action stop, Executor escalation, static check that every write method is only passed to `_write`, and a live Watch-API test on k3d that flips the ConfigMap and a namespace label and restores them). The cluster ConfigMap was restored to `test` after the test.
- Mode changes are logged now (`KILL SWITCH mode a -> b`); the ledger entry is added in P4 through the `on_change` hook.

Acceptance: 108 tests pass (2026-11-10, this machine), including the live test on k3d. Tests cover gate, fallback, override, mid-action stop.
Deferred: ledger entry for mode changes (P4); dashboard toggle with admin token (P8).
Next step: P4 Record (MinIO with object lock, ledger writer used by every component, Prometheus metrics, Grafana JSON).

## P5 log (Sense: real signals)

Built on `wave/P5`, reviewed, fixed, merged into `work` (a6ef46a). Done:
- Health: 15 concurrent `query_range` calls, 60 steps of 5 s per pod, `MetricWindow` with mask and missing list; no usable metric at all raises `PrometheusUnavailable` and publishes nothing; with any missing metric the event carries `health_ci_width` 1.0 (the Health Model server drops the mask and scores zero-filled columns; a mask-aware server is open work). PromQL table in `metric_queries.py`; the three `http_*` queries are marked `app-guess` (names appear nowhere else in the repo).
- Security: entropy sampler (30 samples, 2 s apart, bounded reads, `O_NONBLOCK|O_NOFOLLOW`, fstat, off the event loop); unknown entropy is empty, never 0; events without a model score carry `sec_ci_width` 1.0 and `model_scored=false`, so they cannot reach AUTO_CONTAIN.
- Falco: `FALCO_MODE=auto|live|replay|off`; replay only by explicit `FALCO_MODE=replay` plus `FALCO_REPLAY_PATH`; hand-written fixtures in `tests/fixtures/falco/` (README says they are not captures); a CRITICAL rule triggers alone, WARNING rules need a burst; synthetic event fabrication removed from live paths.
- Merge work on `work`: `evt.type=%evt.type` added to the Falco rule outputs, DaemonSet and image use `FALCO_MODE=auto`, Falco priority table pinned by a test (source: falcosecurity/client-go pkg/api/schema, values as given by the owner).
- Not measured: anything against a real Prometheus or Falco. The ransomware simulator writes low-entropy bytes, so the entropy signal will not fire on it (Falco and write-byte triggers still work). Entropy only sees descriptors open at sample time.

## P7 log (remediation paths)

Built on `wave/P7`, merged with P4 (5bd3558), reviewed, fixed (33410dd). Done: canary drift patch (field-level JSON Patch with test guards, rollback point in Redis, maxUnavailable 0, 3 windows, roll back and escalate), per-incident pod-label quarantine, rolling and forensic snapshots (every 300 s, keep 12), restore to a new PVC from the newest snapshot before `t0_ms` with digest-pinned image, entropy re-check, request validation, injectable `record_step`. Executor write RBAC is exactly the verbs these paths use; static tests tie every write method to a permission and allow write verbs only for the Executor and the one-ConfigMap kill-switch toggle (dashboard). Live RBAC check after applying the manifest to `k3d-kubeheal`: 696 checks, 0 failures (2026-11-10; VolumeSnapshot checks skipped until the CRD exists in P10).
Not proven: everything that needs a real API server, CSI snapshots or Prometheus (fakes only). With the shipped Deployment (no env values, no entropy check wired) every patch and restore escalates and no snapshots are taken, by design: see "Open owner decisions".

## Test status

2026-11-10, this machine, `.venv` Python 3.11.9: full suite `pytest tests/ -q` (pytest.ini sets the basetemp to `.pytest-tmp/run`): 337 passed, 2 skipped (the symlink and FIFO tests, which Windows cannot create), 0 failed, including the live k3d tests. Note for other tools: the venv's interpreter is the Microsoft Store Python 3.11 (`pyvenv.cfg`); it runs from Claude Code's shell but a sandboxed Codex session could not execute it.

## Session note

Wave 2 batch 1 (P7, P5) and the review fixes are merged. Next: P9 with P8 in parallel (two builders), then P6; P10 and P11 are sequential and owned by the orchestrator (cluster owner).

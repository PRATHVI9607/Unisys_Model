# KubeHeal full implementation plan

Goal: implement everything in `docs/kubeheal/PROJECT_SPEC.md` (sections 1 to 5) on branch `work`, then
build a `demo` branch that shows the **entire** system running on k3d on this machine (native Windows,
Docker Desktop, PowerShell). Starting point: `docs/kubeheal/SCAN_REPORT.md`.

Progress is tracked in `docs/kubeheal/PROGRESS.md` (create it in phase P0). Every phase ends with:
all tests green, a commit (or several), and a PROGRESS.md entry. A new session resumes from PROGRESS.md.

Kill switch semantics (decided): `test` = dry run. Sense, Score, Decide and Record run; no Kubernetes
write call happens anywhere (Fusion Agent, Executor, Security Agent); the ledger records
"DRY RUN: would have ...". `enforce` = normal.

Acceptance criteria are written so they can be checked by a test or a command. A phase is not done
until every criterion is met or explicitly recorded in PROGRESS.md as deferred with a reason.

---

## P0. Environment and guardrails

- Create a Python virtualenv in the repo (`.venv`, gitignored) with a Python version that the pinned
  requirements support (torch 2.2.0 needs Python 3.11 or 3.12; install it with winget if missing).
  Install `requirements.txt` including torch-geometric (CPU wheels are fine).
- Configure Claude Code permission deny rules for this project so these are blocked even in auto mode:
  any `git push`, `git push --force`, `git reset --hard`, `git clean`, `git checkout -- .`,
  `git branch -D`, deleting the `.git` folder, `k3d cluster delete` of any cluster not named `kubeheal`.
  Verify by attempting `git push --dry-run` and confirming it is blocked.
- Untrack `.claude/settings.local.json` and gitignore it.
- Create branch `work` from local `main` (which contains commit 88ce586).
- Create `docs/kubeheal/PROGRESS.md`.

Acceptance: all 44 tests pass in the venv (including the two torch_geometric tests); Health Model
server starts locally and `/health` reports the checkpoint loaded; push is blocked.

## P1. Core correctness (from the scan)

- F1 Model servers fail closed: missing or unloadable checkpoint means `/health` 503 with
  `model_loaded: false`, score endpoints 503. Random weights only with `ALLOW_RANDOM_WEIGHTS=true`.
- F2 Golden baseline: SET NX `kubeheal:baseline:<ns>:<deployment>` on first sight; drift diff is live
  vs golden; reset tool documented.
- F3 Deployment name carried explicitly in events; remove the dash-stripping derivation.
- F4 Fix `XACK` in `finally`: ack only after successful handling.
- F5 Incident lock: unique token per replica and incident (not "1").
- F6 Security Agent: use `proc_scanner.py` (cgroups v1/v2, any namespace) instead of the in-file scanner.
- F7 Security Agent stops acting on its own (no `_direct_kill`, no own NetworkPolicies).
- F8 Rename AUTO_KILL to CONTAIN everywhere; remove unused `RANSOMWARE_DIRECT_KILL`.
- F9 Reconcile the conformal quantile mismatch (`health_report.json` vs `health_conformal.json`):
  decide which file the server uses, document it, no new numbers invented.

Acceptance: unit tests for each; no write call exists outside the component that P2 makes the Executor.

## P2. Remediation Executor and least-privilege RBAC

- New component `agents/executor/` (Deployment, 1 replica is fine, can be 2 with the lock). It consumes
  approved actions from a Redis stream `kubeheal.exec` and is the **only** component with write verbs.
- Separate ServiceAccounts: health-agent, security-agent, fusion-agent, model servers, dashboard,
  executor. Agents and servers get read-only Roles/ClusterRoles. Executor gets write verbs only through
  RoleBindings in protected namespaces (prod, staging, dev) plus snapshot verbs.
- Fusion Agent publishes actions to `kubeheal.exec`; it no longer calls write APIs.
- `kubeheal` namespace excluded from all actions (hard check in the Executor).

Acceptance: `kubectl auth can-i` checks in a test script prove agents cannot patch/delete and the
executor cannot write in `kube-system` or `kubeheal`.

## P3. Kill switch (full)

- ConfigMap `kubeheal-mode` (ns `kubeheal`, key `mode`), namespace label `kubeheal/mode` override.
- Watched via the Watch API (not polled) in Fusion Agent and Executor; unreadable means `test`;
  fresh install default `test`.
- Policy stays pure: mode is an input; result carries `dry_run`.
- Executor hard gate before every write call; mid-action switch to `test` stops before the next step
  and escalates to HUMAN.
- Only a dedicated admin Role may modify the ConfigMap; components get read only.
- Every mode change is written to the ledger (P4) and to logs.
- Dashboard toggle (P7) uses an admin token.

Acceptance: tests for gate, fallback, override, mid-action stop.

## P4. Record: ledger and metrics

- MinIO in the cluster (bucket with object lock / versioning, compliance or governance mode as
  supported). Append-only ledger: one object per step, key `incidents/<incident_id>/<seq>-<step>.json`.
- Every component that decides or acts writes ledger entries (detection, scores, decision with reasons,
  approval, each executor step, result, mode changes).
- Prometheus metrics endpoint in every component: decisions by type, actions by type and outcome,
  escalations, dry-run actions, model latency, queue depth, stream lag.
- Grafana dashboard JSON under `deploy/grafana/` (KubeHeal overview: decisions, actions, latency,
  queue depth, replicas).
- MinIO also used as the model registry (servers can pull a model version at start, fallback to the
  baked-in checkpoint).

Acceptance: an integration test (or script) creates an incident and the ledger objects appear; deleting
an object is refused when object lock is available (record if not supported in the chosen MinIO mode).

## P5. Sense: real signals

- Health Agent: real 60-step Prometheus range query (`query_range`, 5 s step) per pod; 15 metrics;
  missing metrics flagged, not silently 0.
- Security Agent: real entropy sampling: 30 samples, 2 s apart, of data actually written by the
  suspect process (for example via `/proc/<pid>/fd` targets on the pod's volume, using the host path),
  bounded read size.
- Falco: consumer enabled when available. Add a **replay mode** that streams recorded Falco JSON
  traces from files (for testing and for machines where Falco cannot run). Record traces from the
  ransomware simulator when Falco is available.
- Remove synthetic syscall fabrication from live paths (keep it only in tests or replay tooling).

Acceptance: unit tests with recorded fixtures; replay mode demonstrably feeds the Security Model.

## P6. Decide: complete the policy and fusion

- `models_ok` input: missing or late model response means HUMAN (fail closed). Per-call deadlines.
- OBSERVE actually triples sampling for that pod for a bounded period.
- Protected-namespace label guard (`kubeheal/protected=true` means never automatic).
- Patch circuit breaker per Deployment (10/hour), containment per namespace (3/hour), both sliding
  windows.
- Burn-in driven by a real counter of metric samples (2000), not only an env var.
- Wire the interpretation layer (`interpretation_client.py`): field mapper, SHAP (metrics via
  KernelExplainer, attention fallback documented), causal chain **with attack onset T0**.
- Redis stream reliability: `XAUTOCLAIM` of stale pending entries, ack only on success, dead-letter
  stream after N failures.

Acceptance: tests for every rule; pending-reclaim test with two consumers.

## P7. Remediation paths (full)

Drift (canary):
- Save rollback point; patch only drifted fields; maxUnavailable 0; watch p99 latency and CPU
  throttling for 3 windows; keep or roll back; escalate on rollback. All steps in ledger.

Ransomware (contain, then restore):
- Rolling VolumeSnapshots every 5 min, keep 12, for PVCs in protected namespaces (Executor-owned
  scheduler or CronJob with a scoped ServiceAccount).
- Quarantine: pod label + deny-all NetworkPolicy selecting the label.
- Forensic on-demand snapshot.
- Scale owner (Deployment/StatefulSet) to 0, remember replicas.
- Choose newest rolling snapshot before T0; restore a new PVC from it; repoint the workload to it;
  redeploy with image pinned by digest; scale back.
- Re-check entropy on the restored volume; lift quarantine if clean, else keep isolated and escalate.

Acceptance: end-to-end test on k3d (P10) shows data restored from a pre-T0 snapshot; RPO and RTO are
**measured** and written to `docs/kubeheal/results/` (no invented values).

## P8. Dashboard

- Approve / reject flow for HUMAN decisions (writes to `kubeheal.exec` and the ledger).
- Incident page: scores, CIs, SHAP view, causal chain with T0, ledger timeline.
- Kill switch status and toggle (admin token), mode history.
- Served behind Ingress (Traefik on k3d, NGINX in the generic chart values).

Acceptance: API tests for approve/reject and toggle; page renders against a seeded incident.

## P9. Cloud platform

- Helm chart `deploy/helm/kubeheal` replacing `scripts/install.sh` (keep the old script for reference),
  with values files: `values-dev.yaml`, `values-staging.yaml`, `values-prod.yaml`, `values-k3d-demo.yaml`.
- Namespaces prod / staging / dev with ResourceQuota and LimitRange; tier from a namespace label
  `kubeheal/tier` (fallback to the current name rule).
- Model servers: 2+ replicas, PDB minAvailable 1, topology spread, HPA min 2 max 8 on **request queue
  depth** via prometheus-adapter (servers export the metric); CPU HPA only as a documented fallback.
- Requests and limits set from a **measured** resource profile (script in `eval/`); record the
  measurement.
- NetworkPolicy around the `kubeheal` namespace (only agents, dashboard, Prometheus reach model servers).
- Redis with AOF on a PVC.
- ONNX serving where parity holds (use existing export scripts and parity checks); servers can load
  ONNX or `.pt` by config.

Acceptance: `helm lint` and `helm template` pass for all values files; chart installs on k3d.

## P10. k3d full environment and `demo` branch

- Create `demo` from `work` at this point. Demo-only files under `demo/k3d/` and `demo/scripts/`.
  Core fixes found here go to `work` first, then merge `work` into `demo`.
- PowerShell scripts: `up.ps1` (tools check, cluster 1 server + 2 agents, CSI hostpath driver +
  external-snapshotter CRDs/controller + VolumeSnapshotClass, NetworkPolicy enforcement check,
  Prometheus + prometheus-adapter, Redis AOF, MinIO, Helm install with `values-k3d-demo.yaml`, image
  build and `k3d image import`), `down.ps1`.
- Falco: try to install; if it fails on this machine, use replay mode automatically and print that
  clearly.
- Victim apps in `prod` (with a PVC holding real files) and one in `dev`.
- `demo.ps1` numbered steps covering **everything**: status; mode; drift detect, canary patch and
  verification; drift with forced rollback; kill switch dry run then enforce; ransomware detect,
  quarantine, forensic snapshot, scale to 0, restore from pre-T0 snapshot, entropy check, lift;
  compound incident via DCM; HUMAN approval through the dashboard; fail-closed by killing a model
  server; Fusion replica crash and pending reclaim; HPA scale-out under k6 load and PDB; ledger and
  Grafana tour; reset.
- `demo/README.md`: run order, expected output, what to say, and an honest limitations section.

Acceptance: `up.ps1` from scratch then all demo steps then reset, twice in a row, without manual fixes.

## P11. Evaluation harness (synopsis Table 5)

- `eval/` scripts: k6 load test (10 to 200 simulated monitored pods) with p50/p95 vs replicas;
  Chaos Mesh (or kubectl-based) chaos runs with detection continuity and fail-closed rate;
  RPO/RTO runs against a database volume; end-to-end time-to-action per stage; baselines
  (Falco rules only, fixed entropy threshold, diff-only drift, single replica, pod delete only);
  FP32 vs FP16 latency and memory.
- Results to `docs/kubeheal/results/` as CSV + short markdown, generated by the scripts. Only measured
  values; each file states machine, cluster and date.

Acceptance: each script runs end to end on k3d and produces its results file.

## P12. Model hardening (compute heavy: ask before running training)

- Scenario-stratified split for the drift dataset; report leakage risk.
- Security generator: held-out ransomware variants (speeds, partial/intermittent encryption,
  rename vs in-place), benign high-entropy hard negatives (gzip, backup, transcoding).
- Capture live traces (Falco or replay of simulator runs) for a real held-out test set.
- Retrain, recalibrate conformal at 90%, re-run evaluation, update reports from actual runs only.

Acceptance: new reports generated by the scripts; old and new numbers both kept with dates.

## P13. Documentation

- README rewrite for the v4.1 system; architecture doc updated to the real component list;
  `docs/kubeheal/SPEC_VS_CODE.md` final status table (all S-* IDs), with anything still missing listed.

---

## Order and stop points

Wave structure (current; P0 to P3 are done):
- Wave 1: P1 then P2 (sequential). Done.
- Wave 2 (parallel builders in git worktrees, at most 2 at a time to save usage): P4 (ledger and metrics),
  P5 (sensing), P7 (remediation, in the Executor), P9 (Helm and platform). Merge order: P7, P5, P4, P9. P3 is done.
  Integration step after the merges: kubeheal-reviewer on each phase, fix findings, full test run.
- Wave 3 (parallel): P6 (decide), P8 (dashboard).
- Wave 4 (sequential, the orchestrator owns the k3d cluster): P10, then P11.
- Agents without subagents run the same tasks sequentially, one worktree or branch at a time, following the
  "Task checklist" in `PROGRESS.md` and the handoff protocol in `AGENTS.md`.

Run P0 to P11 in order (waves above). P12 starts only after the user says go. Stop and ask the user only for:
- anything that needs a password, account, payment, or cloud credentials;
- running training (P12);
- deleting data the user created, or anything outside this repo and the `kubeheal` k3d cluster;
- a phase that would change the spec itself (record the proposed change in PROGRESS.md and continue
  with the rest if possible).
Never push. The user pushes manually after reviewing.

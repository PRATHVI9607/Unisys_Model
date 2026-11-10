# CLAUDE.md: KubeHeal

This file gives Claude Code the context for this repository. Read it fully before doing anything.
The target design lives in `docs/kubeheal/PROJECT_SPEC.md`. Treat that spec as the source of truth
for what the finished project should do, and treat the code as the source of truth for what exists today.

## What this project is

KubeHeal is a Cloud Computing Experiential Learning project (RVCE, CSE). It is an in-cluster
self-healing control plane for Kubernetes that handles two failures:

1. **Configuration drift**: for example a CPU limit silently changed from 500m to 50m. Probes keep
   passing, so Kubernetes never reacts, while latency rises.
2. **Container ransomware**: a compromised container encrypts files on a PersistentVolume.
   Deleting the pod does not help because the ReplicaSet remounts the same volume.

It works as a five-stage pipeline: **Sense -> Score -> Decide -> Act -> Record**.

- Sense: Health Agent (Watch API diff vs golden baseline + Prometheus window) and Security Agent
  (DaemonSet: Falco syscalls, cgroup process->pod mapping, write entropy).
- Score: Health Model (GATv2 + BiLSTM), Security Model (Transformer + Conv1D-SE), each a FastAPI
  inference service with split-conformal intervals.
- Decide: Fusion Agent with the DCM (correlation of the two embeddings) and a pure, unit-tested
  decision policy (`agents/fusion_agent/decision_policy.py`).
- Act: Remediation Executor, the only component with write permissions.
- Record: append-only audit ledger in MinIO, Prometheus counters, Grafana.

## Branch plan

| Branch | Purpose | Lifetime |
|---|---|---|
| `work` | The complete project, matching `docs/kubeheal/PROJECT_SPEC.md`. All real code changes land here first. | Permanent |
| `demo` | Branched from `work`. A trimmed, reliable version for a live demo on a local machine using **k3d**. Shortcuts and hard-coded demo values are allowed here. | For the demo on 2026-11-11 only. Tag it (`demo-2026-11-11`) afterwards, then it is discontinued. |

Rules:
- A bug fix to core code (models, agents, policy, executor, servers) is committed on `work` first,
  then cherry-picked or merged into `demo`. Never fix core code only on `demo`.
- Demo-only material lives under `demo/` (k3d cluster config, demo Helm values, numbered demo
  scripts, sample apps) so merges from `work` stay conflict-free.
- Never force-push. Never rewrite history on a branch that exists on the remote.

## Kill switch (faculty-requested feature, not yet built)

Faculty asked for a kill switch: "when it is in test mode do not use it, else use it".
Proposed behaviour, **pending confirmation from the project owner (pv)**:

- Two modes: `test` and `enforce`.
- `test` = dry run. Sense, Score, Decide and Record still run. Act is skipped. The ledger records
  "DRY RUN: would have <ACTION> <target>".
- `enforce` = normal behaviour.
- Source of truth: ConfigMap `kubeheal-mode` in the `kubeheal` namespace. Optional per-namespace
  override with label `kubeheal/mode=test|enforce`.
- Checked in two places: the Fusion Agent (marks decisions as dry run) and the Remediation Executor
  (hard gate right before every Kubernetes write call).
- Fail safe: if the mode cannot be read, behave as `test`. Fresh installs default to `test`.
- If switched to `test` mid-action, the Executor stops before the next step and escalates to a human.
- Every mode change is written to the ledger.

Do not implement it until asked; first report what exists.

## Working rules for Claude Code in this repo

- **Scan and report before changing anything.** When asked to analyse, do not edit, commit, push,
  create branches, or run destructive git commands (`reset --hard`, `clean`, `checkout -- .`, force push).
- **Ask before pushing** to any remote branch, every time.
- **Do not run model training** (`models/train_*.py`) unless explicitly asked. It is slow and GPU-bound.
- **No invented numbers.** Never write a metric, latency, F1, AUROC or cost into code comments, docs,
  READMEs or reports unless it came from a run you performed or a file in the repo. Say "not measured" instead.
- **Be honest about status.** Distinguish clearly between implemented, partial, stubbed, and missing.
  If a server silently falls back to random weights, say so.
- Prefer small, reviewable commits with clear messages.
- Keep `decision_policy.py` pure (no I/O) and keep its tests passing.
- Output style for reports: plain, direct, no em dashes.

## Environment notes

- Target local cluster for the demo: **k3d** (k3s in Docker). Known k3s differences from the spec:
  - default storage (local-path) does **not** support VolumeSnapshots; needs CSI hostpath driver + external-snapshotter
  - ships **Traefik**, not NGINX Ingress
  - has a built-in NetworkPolicy controller (verify enforcement)
  - Falco eBPF inside k3d is unreliable on Windows or macOS Docker Desktop; a recorded-trace replay fallback may be needed
  - metrics-server is included; queue-depth HPA additionally needs Prometheus + prometheus-adapter
- The original install script targets Minikube (`scripts/install.sh`).

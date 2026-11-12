# AGENTS.md: KubeHeal

Single source of instructions for every AI tool that works in this repo (Claude Code, Codex CLI,
OpenCode with a local model, others). Read it fully before doing anything.
The target design lives in `docs/kubeheal/PROJECT_SPEC.md`. Treat that spec as the source of truth
for what the finished project should do, and treat the code as the source of truth for what exists today.
The build plan is `docs/kubeheal/IMPLEMENTATION_PLAN.md`; live state is `docs/kubeheal/PROGRESS.md`
and `.ai/handoff.md`.

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
- Act: Remediation Executor (`agents/executor/`), the only component with write permissions.
- Record: append-only audit ledger in MinIO, Prometheus counters, Grafana.

## Branch plan

| Branch | Purpose | Lifetime |
|---|---|---|
| `work` | The complete project, matching `docs/kubeheal/PROJECT_SPEC.md`. All real code changes land here first. | Permanent |
| `demo` | Branched from `work` in P10. A trimmed, reliable version for a live demo on a local machine using **k3d**. Shortcuts and hard-coded demo values are allowed here. | For the demo on 2026-11-11 only. Tag it (`demo-2026-11-11`) afterwards, then it is discontinued. |

Rules:
- A bug fix to core code (models, agents, policy, executor, servers) is committed on `work` first,
  then cherry-picked or merged into `demo`. Never fix core code only on `demo`.
- Demo-only material lives under `demo/` (k3d cluster config, demo Helm values, numbered demo
  scripts, sample apps) so merges from `work` stay conflict-free.
- Never force-push. Never rewrite history on a branch that exists on the remote.
- Base branch is local `main`; helper branches (worktrees) are named `wave/<phase>` or `wip/<task-id>`
  and are merged into `work` by the orchestrator.

## Kill switch (decided semantics, built in P3)

- Two modes: `test` and `enforce`.
- `test` = dry run. Sense, Score, Decide and Record still run. No Kubernetes write call happens anywhere
  (Fusion Agent, Executor, Security Agent). The ledger records "DRY RUN: would have <ACTION> <target>".
- `enforce` = normal behaviour.
- Source of truth: ConfigMap `kubeheal-mode` (key `mode`) in the `kubeheal` namespace. Optional
  per-namespace label `kubeheal/mode=test|enforce`; the global mode is absolute, so the label can make a
  namespace stricter but can never enable enforcement while the global mode is `test`.
- Watched through the Watch API (not polled) in the Fusion Agent and the Executor. The Executor hard gate
  (`actions._write`) runs right before every Kubernetes write call.
- Fail safe: if the mode cannot be read, behave as `test`. Fresh installs default to `test`.
- If switched to `test` mid-action, the Executor stops before the next step and escalates to a human.
- Every mode change is written to the ledger (hook exists, connected in P4).
- Baseline promotion (V5-D5) is gated too: the Health Agent overwrites the golden baseline automatically (dev and
  staging) only in mode `enforce`; in `test` or an unreadable mode it writes a `baseline_promotion_dry_run` ledger
  entry and changes nothing. `scripts/baseline_tool.py` (reset, restore) is an operator action and is NOT gated.
- The cgroup freeze of a contained pod (V5-S5) is requested by the Executor behind the same gate and carried out by
  the node-local Security Agent, which checks the mode again right before it writes; in `test` nothing is frozen.

## Working rules (all agents)

- **Autonomous build rules (in force since 2026-11-10).**
  - Work phase by phase from `docs/kubeheal/IMPLEMENTATION_PLAN.md`; track state in `docs/kubeheal/PROGRESS.md`.
  - Make small commits on `work` (or on `demo` for demo-only files) after tests pass. Never push.
  - Never run destructive git commands. Never delete user data. Never touch Kubernetes contexts other
    than the k3d cluster named `kubeheal` (always pass `--context k3d-kubeheal`). A pre-existing user
    cluster `hybrid-demo` must never be touched.
  - No invented numbers anywhere. Metrics in docs come only from scripts that were run, with date and machine.
  - Before training models (phase P12), stop and ask.
  - Decided: base branch is local `main`, work happens on `work`, `demo` is branched from `work` in P10.
- **Ask before pushing**: agents never push. The owner pushes (see Push guard).
- **Do not run model training** (`models/train_*.py`) unless explicitly asked. It is slow and GPU-bound.
- **No invented numbers.** Never write a metric, latency, F1, AUROC or cost into code comments, docs,
  READMEs or reports unless it came from a run you performed or a file in the repo. Say "not measured" instead.
- **Be honest about status.** Distinguish clearly between implemented, partial, stubbed, and missing.
  If a server silently falls back to random weights, say so.
- Prefer small, reviewable commits with clear messages.
- Keep `decision_policy.py` pure (no I/O) and keep its tests passing.
- After P2: no Kubernetes write call outside `agents/executor/` (`tests/test_no_writes_outside_executor.py`).
  After P3: every write goes through `actions._write` and its kill-switch gate.
- Output style for reports and docs: plain, direct, no em dashes.
- Tests: `PYTHONPATH=. .venv\Scripts\python.exe -m pytest tests/ -q` (Windows venv, Python 3.11).

## Push guard (every tool obeys it)

- `.githooks/pre-push` exits 1 unless the environment variable `ALLOW_PUSH=1` is set. It is enabled with
  `git config core.hooksPath .githooks`. **A new clone must run that same command.**
- `remote.origin.pushurl` is also set to an invalid value, so a push cannot reach the remote by accident.
  Fetch still works.
- Claude Code additionally has deny rules in `.claude/settings.json` for push and destructive git commands.
- Agents must never set `ALLOW_PUSH` and never restore the push URL.
- The owner pushes in PowerShell with:
  `$env:ALLOW_PUSH=1; git push ...; Remove-Item Env:ALLOW_PUSH`

## Environment notes

- Machine: native Windows 11, Docker Desktop (about 15.5 GiB for Docker), PowerShell 7 plus Git Bash.
  Details in `docs/kubeheal/PROGRESS.md`.
- Target local cluster for the demo: **k3d** (k3s in Docker), cluster `kubeheal`, kubeconfig server is
  `https://127.0.0.1:<port>` (the `host.docker.internal` entry does not work here; scripts repeat the fix
  after `k3d cluster create`). Known k3s differences from the spec:
  - default storage (local-path) does **not** support VolumeSnapshots; needs CSI hostpath driver + external-snapshotter
  - ships **Traefik**, not NGINX Ingress
  - has a built-in NetworkPolicy controller (verify enforcement)
  - Falco eBPF inside k3d is unreliable on Windows or macOS Docker Desktop; a recorded-trace replay fallback may be needed
  - metrics-server is included; queue-depth HPA additionally needs Prometheus + prometheus-adapter
- The original install script targets Minikube (`scripts/install.sh`); P9 replaces it with a Helm chart.
- Only the orchestrating agent (cluster owner) uses the k3d cluster, except where a task says otherwise.

## Handoff protocol (every agent must follow)

At start:
1. Read `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`,
   `docs/kubeheal/PROGRESS.md` (the "Task checklist" section) and `.ai/handoff.md`.
2. Run `git status` and `git log --oneline -15`.
3. Claim the next unchecked task by marking it `[~] <agent name>` in the checklist.

While working:
- Work in small commits. Never end a session with uncommitted changes: commit, or commit to a
  `wip/<task-id>` branch with a WIP message.

At end (or when usage or context runs low):
- Mark the task done `[x]`, or describe exactly where it stopped in the checklist line.
- Update `.ai/handoff.md` (agent, date, branch, last commit, what is next, open issues). Keep it short and
  current: replace stale content, do not append a history log.

Always:
- Never push. Never set `ALLOW_PUSH`. Never run destructive git commands.
- Smaller local models take only tasks marked `size: S` in the checklist and must not edit
  `decision_policy.py`, the Executor's write paths (`agents/executor/`), or RBAC (`k8s/rbac/`); leave those to a
  stronger agent.
- Agents without subagents run the plan's tasks sequentially, one worktree or branch at a time.

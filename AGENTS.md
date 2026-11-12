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
- Score: shipped LightGBM Health and Security bundles behind the inference service, with split-conformal
  prediction sets and TreeSHAP factors. Every serving request passes through `ModelBundle.restrict()`.
- Decide: Fusion Agent uses deterministic correlation (`compound_score`); LightGBM does not provide the
  embeddings required by the legacy DCM. The pure, unit-tested policy (`agents/fusion_agent/decision_policy.py`)
  requires an exactly one-label conformal set for automatic actions (M2).
- Act: Remediation Executor (`agents/executor/`), the only agent with remediation Kubernetes write permissions. It validates requests, records intent before each write, and checks the kill switch before every write. The node-local Security Agent performs the cgroup freeze only after an authenticated Executor request and its own mode check. The dashboard has a separate narrow permission to update the kill-switch ConfigMap with admin authentication.
- Record: append-only audit ledger in MinIO, Prometheus counters, Grafana.

The neural model servers and DCM are legacy components and are disabled by default. Shipped security bundle
validation figures use synthetic classes and do not establish live model quality. Retraining is not approved.
On 2026-11-12, cgroup freeze and operator thaw were read back on a k3d scratch pod. A separate F3 run
verified the stream-driven Fusion-to-Executor containment and restore chain on a scratch Deployment in
`staging`. Its alert was scripted with model fields from the D-5 replay because Falco was absent; this does
not verify live Sense/detection. Both results are k3d-only, not real-node validation. See
`docs/kubeheal/results/live_freeze_check_2026-11-12.md` and `docs/kubeheal/demo-evidence/F3/RUNBOOK_F3.md`.

## Branch plan

| Branch | Purpose | Lifetime |
|---|---|---|
| `work` | The complete project, matching `docs/kubeheal/PROJECT_SPEC.md`. All real code changes land here first. | Permanent |
| `demo` | Branched from `work` in P10. A trimmed version for rehearsals and live demonstrations on a local machine using **k3d**. Shortcuts and hard-coded demo values are allowed here. | Demo branch; no fixed retirement date. |

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

## Containment order and message authentication

For ransomware containment, the Executor applies and records the steps in this order: freeze the target pod;
take the forensic snapshot; quarantine the workload; scale it to zero; restore the volume from the snapshot
created before T0; run the entropy rescan Job; lift quarantine only after a clean scan; then record the final
result. A failed or unreadable scan keeps the workload isolated and escalates to a human.

The containment freeze request and Security Agent result, plus the operator thaw protocol, use HMAC-SHA256.
`CONTAIN_HMAC_KEY` comes from the chart-managed `kubeheal-containment-hmac` Secret, key `key`; the chart
injects it only into Executor and Security Agent pods. The operator thaw tool must be supplied the same key
through secure operator secret handling. Redis authentication uses a separate Secret, so a Redis credential
alone cannot sign containment messages. A Kubernetes operator who can read the HMAC Secret can sign them.
Never print or log Secret values.

## Verified on k3d (2026-11-12)

- The F3 scratch Deployment chain completed in `staging`. The final enforce window was 45 seconds; 5 restored
  files were scanned and 0 were high entropy. The alert was scripted, so this verifies the Fusion-to-Executor
  chain, not live Falco sensing. This run does not establish real-node behavior. See
  `docs/kubeheal/demo-evidence/F3/RUNBOOK_F3.md`.
- The D-5 hand-written replay produced a model-scored Security event and Fusion dry-run on k3d. It is not a
  live Falco capture or Executor containment. See `docs/kubeheal/demo-evidence/F3/10_d5_rerun.txt` and
  `docs/kubeheal/demo-evidence/F3/11_d5_rerun_ledger.jsonl`.
- One F11 synthetic scoring-load run used 32 VUs for 90 seconds, passed 121,088/121,088 checks, measured
  median 22.86 ms and p95 38.45 ms, and scaled HPA replicas 2 -> 7 -> 2 in 7m14s. This is one run, not a
  performance guarantee. See `docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md`.
- A post-merge repeat scaled 2 -> 8 -> 2 but had 12 connection refusals out of 99,431 checks, so it is not a
  clean load result. Grafana's queue-depth and available-replica panels and Prometheus samples are recorded in
  `docs/kubeheal/demo-evidence/F11/grafana-hpa-api-2026-11-12.json`; no Grafana screenshot was captured because
  the renderer is not installed.
- P11 E1 has no accepted benchmark: both runs failed. U6's full acceptance run twice is **not measured**.
  Do not reuse F11 numbers as P11 or U6 results. See `docs/kubeheal/results/p11/P11_COVERAGE.md`.

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
- Live integration tests that can contact k3d, Redis, or MinIO must require an explicit `KUBEHEAL_LIVE_*_TEST=1`
  opt-in and skip by default. A connectivity probe itself counts as live access; do not put it in a decorator
  evaluated while pytest imports a test module. Keep `tests/test_live_test_safety.py` inventory current.
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

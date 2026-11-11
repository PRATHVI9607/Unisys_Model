# KubeHeal continuation notes for parallel Codex sessions (2026-11-11, written by Claude at a usage limit)

Read first: `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`, the Task checklist plus the
section "P10 findings (2026-11-11...)" in `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md`. Newest copies are on branch `demo`
(and mirrored to `work`).

## State

- Branches: `work` (all core fixes, 897 passed and 2 skipped at the last full run, plus 2 cluster-only tests that pass on the
  live cluster), `demo` (`work` plus `demo/`), `wave/P11` (clean, at `e611844`, no work done), `wip/docs-p6d2` (`48b1f00`, one
  partial unreviewed edit of `agents/health_agent/agent.py`, no docs written), older `wave/P5..P9` (merged, kept). Nothing pushed.
- Worktrees: main folder `C:/My_projects_1/cLOUD/Unisys_Model` (branch `demo`); `C:/My_projects_1/cLOUD/Unisys_Model-wt-P11`
  (`wave/P11`); `C:/My_projects_1/cLOUD/Unisys_Model-wt-docs` (`wip/docs-p6d2`).
- Cluster `kubeheal` (k3d, context `k3d-kubeheal`) is RUNNING and healthy. Chart installed, prometheus-adapter installed, victim
  apps in prod (with PVC) and dev. Kill-switch mode is `test`. Victim in prod is restored to limits 500m, requests 100m.
  Verified on it: P10-V2 (14 of 15 queries return data; `http_error_rate` is empty because there are no 5xx), P10-U7 (HPA reads
  the queue-depth metric), `scripts/rbac_check.py` (696 checks, 0 failures), the 2 live tests.

## Rules for every session

- Only `--context k3d-kubeheal`. Never touch `hybrid-demo`. Never push, never set `ALLOW_PUSH`. No destructive git commands.
  No training (P12 not approved). No invented numbers.
- Temporary files and pytest base temp only under `.pytest-tmp*/` (for example `--basetemp=.pytest-tmp/<name>`).
- `git add` and `git commit` may need an approval prompt: ask for it, do not work around it. Commit small, never leave
  uncommitted work (use `wip/<task-id>` with a WIP message if unfinished).
- Run tests with `$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=.pytest-tmp/<name>`.
- Reserved for Claude (do not do these): `agents/fusion_agent/decision_policy.py`, Executor write paths (`agents/executor/`),
  RBAC (`k8s/rbac/`), conflicting merges, final reviews, any policy override.

## SESSION 1: cluster owner (main folder, branch `demo`, the only session that may use the cluster)

Findings so far (details in PROGRESS "P10 findings"):
- The drift injection must patch requests AND limits to 50m (limits alone is rejected: request 100m > limit 50m).
- Victim Deployments needed the label `kubeheal.io/watch=true` (now in `demo/k3d/victim.yaml`, applied).
- Drift is detected, but Fusion decides OBSERVE (adjusted score 0.49, health_ci_width 1.0, burn-in active, prod not labelled
  protected=false). AUTO_PATCH is therefore unreachable with this Health Model checkpoint. Owner decision pending: HUMAN path
  demo, policy override on `work` (Claude), or P12-H retraining. Do not decide it yourself.
- Executor logged a ledger `S3Error` at startup (MinIO bootstrap still running); entry kept in `kubeheal.ledger.pending`.
  `scripts/ledger_check.py` works later. Check that the pending list drained.
- Health Agent logs `Unclosed client session` (aiohttp leak): fix on `work`.

Next, in order:
1. Check whether `health_ci_width=1.0` is a fallback (grep the Health Model server code) and that the trained checkpoint
   loaded (`kubectl --context k3d-kubeheal -n kubeheal logs <health-model pod> | head -60`). Check the Security Model CI width.
2. Check that `kubeheal.ledger.pending` drained (Redis in pod `redis-0`, password in secret `kubeheal-redis`).
3. Ask the owner which drift path to demo. Meanwhile do the unblocked steps: D-6 (kill a model server mid-incident, expect a
   HUMAN escalation), D-5 and Falco attempt with a fixed time limit (P10-U2, else replay mode; chart `falcoMode`), D-7 snapshot
   restore, D-8 HPA scale-out with the pinned `grafana/k6:0.54.0` image as an in-cluster Job.
4. Write `demo/scripts/demo.ps1` (P10-U4; it does not exist) with the steps from the plan, using `demo/k3d/lib.ps1` helpers
   (`K`, `Hc`). Add a reset step. Update `demo/README.md` only with observed results.
5. P10-U6 acceptance twice in a row, then P11 (cluster parts) after the owner approves.
Files to touch: `demo/**`, `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`. Core fixes go to `work` first, then
`git switch demo; git merge work`. Do not touch: `decision_policy.py`, `agents/executor/`, `k8s/rbac/`.
Verify: `.\demo\k3d\up.ps1 -Stage <name>`, `scripts/rbac_check.py`, `demo/scripts/verify_health_queries.py`.

## SESSION 2: P11 scripts (new worktree, branch from `work`, NO cluster)

Use the existing `C:/My_projects_1/cLOUD/Unisys_Model-wt-P11` (branch `wave/P11`, already at `work`'s state) or make a new
one. Build under `eval/` only, tests in `tests/test_eval_*.py`, results README in `docs/kubeheal/results/README.md`:
- k6 as an in-cluster Job (`grafana/k6:0.54.0`, node affinity away from model servers, resource limits), 10 to 200 simulated pods,
  p50 and p95 vs replicas; chaos runs (detection continuity, fail-closed rate); RPO and RTO harness; baseline comparisons
  (Falco rules only, fixed entropy threshold, diff-only drift, single replica, pod delete only); FP32 vs FP16 benchmark script;
  result writers that stamp machine, cluster and date and write "not measured" where nothing ran.
- Unit-test with fakes (injectable kubectl runner). Do not run any script against a cluster, no kubectl, k3d, helm.
Files not to touch: everything outside `eval/`, `tests/test_eval_*.py`, `docs/kubeheal/results/README.md`; never
`decision_policy.py`, `agents/executor/`, `k8s/rbac/`, PROGRESS or handoff (report instead).
Verify: `pytest tests/test_eval_*.py -q --basetemp=.pytest-tmp/p11`, then the full suite once.

## SESSION 3: docs and P6-D2 (new worktree, branch from `work`, NO cluster)

Use `C:/My_projects_1/cLOUD/Unisys_Model-wt-docs` (branch `wip/docs-p6d2`, contains one partial unreviewed edit of
`agents/health_agent/agent.py`: review it, finish or discard that edit) or make a fresh branch from `work`.
- `docs/kubeheal/SPEC_VS_CODE.md`: every `S-*` ID in PROJECT_SPEC.md with status and evidence (file, function, test; check the
  code, write "unverified" if unsure).
- `docs/kubeheal/ARCHITECTURE.md` matching the real components (mermaid or text diagram, planned things marked planned).
- Root `README.md` draft, honest about the Health Model limits (live scores not validated on real cluster windows, drift
  detection mainly the config diff, retraining P12-H not approved, no training run).
- P6-D2: Health Agent OBSERVE rescheduling in `agents/health_agent/` with tests. A 300 s OBSERVE TTL divided by factor 3 does
  not define a cadence, so first read the P6-D2 notes in PROGRESS (Session pause section) and choose a documented default.
Files to touch: those docs, `agents/health_agent/**`, matching tests. Not to touch: `eval/`, `decision_policy.py`,
`agents/executor/`, `k8s/rbac/`, PROGRESS, handoff.
Verify: full suite with `--basetemp=.pytest-tmp/docs`.

## Open task list (any session, no cluster, small)

P7-RR-11 (re-baseline after restore, Executor hook is Claude's), P7-RR-12 (Claude), REV-3 graph test (needs `torch_geometric`),
P6-D6 KernelExplainer background data, Health Agent aiohttp session leak (`agents/health_agent/`, on `work`).

## Pitfalls

- PowerShell's `h` alias shadows a function named `H`; the demo helper is `Hc`. `K` forwards piped stdin.
- `k3d`, `helm` are not on PATH (`demo/k3d/lib.ps1` finds them). `k6` is not installed locally.
- CSI hostpath volumes exist only on node `k3d-kubeheal-agent-0`; workloads with PVCs are pinned there.
- Every threshold in code is a chosen default; write no metric that a run did not produce.
- The Claude Code deny rules blocked `k3d cluster delete hybrid-demo-guardtest` and `git push --dry-run` in both Bash and
  PowerShell (re-tested 2026-11-11), so the deny rules are enforced in this setup.

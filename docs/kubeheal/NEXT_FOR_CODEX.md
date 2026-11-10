# Next for Codex (handoff from Claude Code, 2026-11-11)

Read `AGENTS.md` first, then `.ai/handoff.md` and the "Task checklist" in `docs/kubeheal/PROGRESS.md`.
Never push, never set `ALLOW_PUSH`, no destructive git commands, no invented numbers, no em dashes in docs.

## State

- Repo: `C:\My_projects_1\cLOUD\Unisys_Model` (the nested repo, not the outer `cLOUD`). Branch `work`, tree clean, no merge in progress.
  Last code commit before the handoff docs: `81106b8`. Last full suite on `work`: 534 passed, 2 skipped (the symlink and FIFO tests, Windows cannot create them), 0 failed.
- Merged into `work`: P0 to P5, P7, P8, P9, the shared Health Model preprocessing and its version guard (`v1-legacy`), the owner's Executor defaults.
- NOT merged, builder was still running when the handoff was written:
  - worktree `C:/Users/PV/AppData/Local/Temp/claude/b422cec1e7851a5a/17647aa4-3fa3-4021-8d2d-0fd5df60e364/scratchpad/wt/P6`, branch `wave/P6`, base `218029c`, last commit `36d436d`
    (commits: `3ea4dd7` policy inputs, `2e3a6b1` shared stream reclaim and dead letter, `36d436d` fusion models_ok/protected/breakers/burn-in/observe). It may have UNCOMMITTED work (three untracked files `tests/fusion_helpers.py`, `tests/test_fusion_decide.py`, `tests/test_fusion_incident.py` were present) and tasks P6-D6, P6-D7 and the review are not done. Do not touch this worktree or branch. Claude reviews and merges it.
- Kept merged branches (do not delete): `wave/P5`, `wave/P7`, `wave/P8`, `wave/P9`.
- Other worktrees: none besides P6.
- Cluster: k3d cluster `kubeheal` is running (mode ConfigMap is `test`). Only Claude uses it. Never touch `hybrid-demo`.

## Environment

- Python: `.venv\Scripts\python.exe` (Python 3.11.9, torch 2.2.0+cpu). It is the Microsoft Store Python; it runs from Claude Code's shell but a sandboxed Codex session could not execute it. First run `.venv\Scripts\python.exe --version`. If it fails, do NOT recreate `.venv`: tell the owner.
- Test command (pytest.ini already sets `--basetemp=.pytest-tmp/run`): `$env:PYTHONPATH="."; .venv\Scripts\python.exe -m pytest tests/ -q -k "not live and not rbac_k3d"`
- Temp folders only under the ignored `.pytest-tmp*/` path. `helm` is at `C:\Users\PV\AppData\Local\Microsoft\WinGet\Packages\Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe\windows-amd64\helm.exe` (not on PATH).
- Codex needs the owner's approval for `git add` and `git commit` (the owner will approve). Commit small, on `work`, after tests pass; if you must stop mid-task, commit to `wip/<task-id>` with a WIP message.

## The next tasks, in order (each is safe for Codex)

1. **P8-D5** (owner request). Dashboard approval claim hardening.
   - Goal: `CLAIM_TTL_S` (now 30 days) becomes a short chosen default (about 10 minutes, documented as tunable, labelled "chosen, not measured"); startup reconciliation in the dashboard scans claims against the exec stream and the ledger and either completes (writes the missing `approved`) or releases claims with no matching record; an admin-only "release claim" action writes a ledger entry `claim_released` with the actor.
   - Touch: `dashboard/admin_routes.py`, `dashboard/ledger_view.py`, `dashboard/fastapi_app.py` (startup hook only), `tests/test_dashboard_*.py` (new tests for the short TTL, reconciliation complete and release, release action needs the admin token and writes the ledger entry).
   - Do NOT touch: `agents/`, `decision_policy.py`, `dashboard/mode_admin.py` (the only dashboard write, pinned by tests), `k8s/rbac/`, `tests/test_no_writes_outside_executor.py`.
   - Verify: `... pytest tests/test_dashboard_approvals.py tests/test_dashboard_killswitch.py tests/test_no_writes_outside_executor.py -q`, then the full command above.
2. **P10-V1** (victim app contract, owner decision: no guessed metric names).
   - Goal: `demo/victim-app/`: small FastAPI app with `prometheus_client` exporting `http_requests_total` (labels `method`, `path`, `status`) and `http_request_duration_seconds` (histogram), a Dockerfile, Deployment and Service manifests for namespaces `prod` and `dev`, and a ServiceMonitor. Optional PVC with real files in `prod` is P10-U3 (leave it).
   - Touch: `demo/victim-app/` only, plus `tests/test_demo_victim_app.py` (exporter unit test with the FastAPI TestClient).
   - Do NOT touch: core code, `k8s/` existing files, `deploy/helm/`.
   - Verify: the new test plus the full command. Do not build images or use the cluster.
3. **P5-Q1** (needs task 2).
   - Goal: in `agents/health_agent/metric_queries.py` change the `app-guess` rows to the victim-app contract (names unchanged; update the docstring so the `http_*` names are no longer called guesses; `basis` becomes e.g. "demo-victim-app contract"). Keep the 15 column names, order and meaning.
   - Touch: `agents/health_agent/metric_queries.py`, `tests/test_sense_health_window.py` only if it asserts the `app-guess` basis.
   - Do NOT touch: `models/health_model/preprocess.py` (the preprocessing and its version guard), `decision_policy.py`.
   - Verify: `... pytest tests/test_sense_health_window.py tests/test_health_preprocess_parity.py -q`.
4. **Grafana panel** for the new gauge (size S). Add a panel for `kubeheal_model_inflight_requests` to `deploy/grafana/kubeheal-overview.json`; keep `kubeheal_queue_depth` (a test needs it). Verify: `... pytest tests/test_grafana_dashboard.py -q`.
5. **PROGRESS bookkeeping** after each task: mark `[x]`, update `.ai/handoff.md`.

## Leave these for Claude (do not edit)

- Anything in `agents/fusion_agent/decision_policy.py`.
- Executor write paths: `agents/executor/` (all of it), `agents/executor/actions.py`, and RBAC: `k8s/rbac/rbac.yaml`, `k8s/kill-switch.yaml`, `scripts/rbac_check.py`, the RBAC static tests.
- `models/health_model/preprocess.py`, the checkpoint sidecar and the server version guard.
- Merges of wave branches (`wave/P6` is not merged yet and will conflict in places), and any review of them.
- All cluster work: P10-U1 to U7, P10-V2, P10-V3, P11. P12 and P12-H (retraining) are NOT approved: do not start them and do not run `models/train_*.py`.

## Pitfalls

- Nothing in the chart (`deploy/helm/kubeheal`) has run on a cluster; do not describe it as verified.
- Executor settings are chosen defaults, not measurements (`agents/executor/config.py` `DEFAULTS`). The queue-depth HPA target (4) is a chosen default too.
- Live Health Model scores are not validated on real cluster windows; drift detection relies mainly on the configuration diff. Keep that status line wherever you write demo docs.
- Edit files with LF line endings preserved (`.gitattributes` is LF for text, CRLF for `.ps1`). Git prints CRLF warnings on Windows; they are harmless.

## Update: P6 builder finished (appended after the handoff)

This supersedes the "may have UNCOMMITTED work" and "P6-D6, P6-D7 not done" wording above and the "STOPPED HERE" notes on the P6 lines in PROGRESS.md.

- Branch `wave/P6`, worktree `C:/Users/PV/AppData/Local/Temp/claude/b422cec1e7851a5a/17647aa4-3fa3-4021-8d2d-0fd5df60e364/scratchpad/wt/P6`, base `218029c`, last commit `7f95f6c`. Everything is committed (5 commits: `3ea4dd7`, `2e3a6b1`, `36d436d`, `b40e9ee`, `7f95f6c`), the worktree is clean, nothing pushed. NOT reviewed, NOT merged, `work` untouched. Claude reviews and merges it later (it will conflict in places because `work` moved on: P9 merge, version guard); Codex must not merge it or edit it.
- Builder's own report, NOT verified by the orchestrator: 595 passed, 2 skipped in the worktree (base had 423); all checks use in-memory fakes (new `tests/fake_redis.py`), no cluster, no real Redis, DCM HTTP calls faked.
- Done on the branch (per the builder):
  - D1, D3, D5 policy: `models_ok` (default False), `namespace_protected` (default True), `metric_samples_seen` (None means burn-in); invalid or NaN confidence widths mean HUMAN; `decision_policy.py` stays pure (a test checks its imports); Fusion deadlines `DCM_DEADLINE_S` 5.0 and `INTERPRETATION_DEADLINE_S` 4.0 (chosen, not measured); protected label through `ModeWatcher.protected_for()` (unreadable or unknown means protected); burn-in counter in Redis ends at 2000.
  - D4 sliding-window circuit breakers (Redis sorted sets `kubeheal:cbw:*`), recorded after the enqueue, never for dry runs.
  - D2 OBSERVE sampling contract `agents/common/sampling.py` (factor 3, `OBSERVE_PERIOD_S` 300, chosen).
  - D6 `interpretation_client.py`: `correlate`, `explain`, T0 parsing and T0 causal chain, attribution normalisation, `kernel_metric_attribution` (tested with a stub model; no explainer wired by default).
  - D7 initial and complete security events share one incident; after `executed_contain` with outcome `contained` Fusion queues `restore` (with `t0_ms`, `workload_kind`); without T0, an unsupported kind, or a protected namespace it escalates once.
  - R1 `agents/common/stream_reliability.py` (XAUTOCLAIM, delivery count, `kubeheal.deadletter`, escalation, lease heartbeat) used by Executor and Fusion; the Executor keeps a result marker per incident, action and dry-run flag so a redelivered finished request is acked without re-running.
- Edits the builder made outside its folders (forced by the fail-closed defaults): `tests/test_killswitch.py`, `tests/test_executor.py`, `tests/test_record_pipeline.py`, `tests/test_remediation_validation.py`, `agents/common/killswitch.py`.
- Missing or needed elsewhere (not done):
  - Security Agent must publish `t0_ms` (earliest suspicious Falco `ts`; `timestamp_ms` is publish time and must never be used). Until then every contain escalates `t0_unknown` and no restore is ever requested.
  - Health and Security agents must read the sampling contract (`sampling_factor`, `scaled_interval`).
  - `models/interpretation`: a real KernelExplainer in the Health server (today it uses variance); the DCM chain's `T+x s` offsets are hard-coded templates.
  - `dockerfiles/Dockerfile.fusion` and the chart: new optional env vars with chosen defaults (`DCM_DEADLINE_S`, `INTERPRETATION_DEADLINE_S`, `OBSERVE_PERIOD_S`, `INCIDENT_DEDUP_TTL_S`, `INCIDENT_CONTEXT_TTL_S`, `KUBEHEAL_PENDING_IDLE_MS` 60000, `KUBEHEAL_MAX_DELIVERIES` 5, `KUBEHEAL_RECLAIM_INTERVAL_S`, `KUBEHEAL_RECLAIM_BATCH`, `KUBEHEAL_DEADLETTER_MAXLEN`).
  - Dashboard should show `incident_update`, `restore_requested`, `fusion_escalation`; it reads only the first `decision` and `detection` record.
  - P7-RR-10 is only partly covered (finished requests are idempotent; a crash in the middle of a canary is not).
- Demo impact on a fresh install: burn-in lasts until 2000 health events (thresholds 0.95 and 0.90); heuristic-only security events always go to HUMAN; restore is never requested automatically; `ModeWatcher.protected_for()` returns True until the first namespace list succeeds.
- Unverified by the builder: whether one health event counts as one metric sample (an assumption); XAUTOCLAIM and XPENDING checked only against its own fake (the Redis chart image is unpinned, `reset.sh` uses `redis:7-alpine`); the interpretation deadline bounds only an injected explainer.

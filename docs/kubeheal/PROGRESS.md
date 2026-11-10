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
| P3 to P13 | not started |

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
  - Because of that, push is blocked at the git level instead, and this was verified: `remote.origin.pushurl` is set to an invalid value, and `.git/hooks/pre-push` rejects unless `KUBEHEAL_ALLOW_PUSH=1`. `git push --dry-run origin work` now fails from Bash, PowerShell and with `-C`; a real push to a scratch bare repo was rejected by the hook. Fetch still works.
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

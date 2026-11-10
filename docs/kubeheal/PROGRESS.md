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
| P0 Environment and guardrails | in progress |
| P1 to P13 | not started |

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

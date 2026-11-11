# KubeHeal next agent handoff

This file is tool-neutral. It is the first resume point for Codex, Claude Code, or another repository agent.
Read `AGENTS.md`, `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md` before changing files or using the cluster.

## Current checkout

- Active checkout: `C:/My_projects_1/cLOUD/Unisys_Model`, branch `demo`. Nothing is uncommitted after the Claude session of 2026-11-11 that wrote this file.
- Do not push or set `ALLOW_PUSH`. No model training is approved. Shared core fixes go to `work` first, then merge `work` into `demo`; demo-only scripts stay under `demo/`.
- Run `git branch -v` for the tips. Reviewed and merged on 2026-11-11: `wave/P11` into `work` (`a1590d1`), `wip/docs-p6d2` into `work` (`bbe55a0`), `work` into `demo` (`a02c508`). Full suite at `a02c508`: 935 passed, 2 skipped.

## Branches and worktrees

| Branch | State | Worktree |
|---|---|---|
| `demo` | Active | `C:/My_projects_1/cLOUD/Unisys_Model` |
| `work` | Complete project, all core fixes | `C:/My_projects_1/cLOUD/Unisys_Model-wt-metric-query` (kept: it is the only checkout of `work`) |
| `wave/P11`, `wip/docs-p6d2` | Merged into `work`; branches kept, worktrees removed | none |
| `main`, `wave/P5` to `wave/P9`, `wave/docs-p6d2` | Base and historical | none |

`origin/main` ("v5", a teammate's rewrite) was fetched and analysed only: `docs/kubeheal/V5_INTEGRATION_PLAN.md`. Nothing from it is ported. Wait for the owner's decisions listed in section 8 of that plan.

## Cluster state

Not re-checked by Claude in the 2026-11-11 review session (no cluster command was run). As last recorded by Codex: cluster `kubeheal` running, global mode `test`, prod and dev `victim-app` at request 100m / limit 500m, Health Model Deployment and HPA at 2 replicas, Security Agent in `FALCO_MODE=auto` (Falco not installed), temporary replay and k6 resources removed. Every Kubernetes command must use `--context k3d-kubeheal`; never `hybrid-demo`.

## Next tasks, in order

1. **Rebuild the Health Agent image and verify the aiohttp fix.** `b229491` fixed the per-call `ApiClient` leak; the running image predates it. `demo/k3d/images.ps1` then check the Health Agent log for `Unclosed client session`.
2. **D-5 replay emits no Security event.** Reported by Codex: 21 hand-written events were consumed and the model-client latency metric advanced, but no `kubeheal.security.events` record appeared. Check `agents/security_agent/syscall_window.py` windowing and the publish threshold, add a focused test in `tests/test_sense_falco_replay.py`, then a bounded replay with the mode kept `test`. Do not claim live Falco.
3. **Health Model attribution.** Both observed drift events have a flat `field_attribution_json` (`docs/kubeheal/results/p10-k3d-2026-11-11.md`), so `top_field` is arbitrary and the Executor escalates `no_drift_at_field`. Add focused tests before any fix. A model-independent option is deriving candidate fields from the spec diff (V5 plan, C9). Keep the 0.15 CI gate. Policy and Executor changes are for the stronger agent.
4. **P10-U6 acceptance.** Full `up.ps1`, all demo steps, reset, twice in a row without manual fixes. Requires PowerShell 7. Keep mode `test`, keep drift injection paired at 50m request and limit, restore `100m/500m`. The demo scripts were reviewed and fixed on 2026-11-11 but not re-run end to end afterwards.
5. Remaining checklist items in `PROGRESS.md`: P7-RR-7, RR-11, RR-12, P6-D6, P11-E1 to E7 (the P11 harness exists but has not been run), P12 not approved.

## Known facts

- P10 numbers confirmed from Codex's session log (k6 run, HPA 2 to 4 to 8 to 2, CI widths 0.2607 and 0.1192) are in `docs/kubeheal/results/p10-k3d-2026-11-11.md`. The 21 replayed events, the sample counts per channel and the 15 sample values in P10-V2 are reported but not confirmed.
- The Executor logged a transient MinIO `S3Error` during bootstrap; the queued fallback record drained. Not reproduced.
- Review items left open on purpose: see "Known review items not fixed" in `PROGRESS.md`.

## Useful checks

```powershell
git status
git branch -v
git worktree list
git log --oneline -15
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode
$env:PYTHONPATH='.'; .venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=.pytest-tmp/<task>
```

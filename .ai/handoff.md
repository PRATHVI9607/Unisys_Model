# Handoff

- **Agent:** Claude Code (orchestrator)
- **Date:** 2026-11-11
- **Status:** STOPPED at a usage limit. k3d cluster `kubeheal` is running and healthy, kill-switch mode `test`, nothing pushed, no subagent running.
- **Branches:** `work` core fixes, `demo` = `work` plus `demo/`, `wave/P11` (clean, no work done), `wip/docs-p6d2` (`48b1f00`, partial unreviewed edit of `agents/health_agent/agent.py`). Worktrees: main folder (`demo`), `../Unisys_Model-wt-P11`, `../Unisys_Model-wt-docs`.

## Done this session

- Guard test re-run: `k3d cluster delete hybrid-demo-guardtest` and `git push --dry-run` were both blocked by the deny rules in Bash and PowerShell. No hook needed.
- P10: `up.ps1 -Stage install|adapter|victim` run. P10-V2 done (14 of 15 queries return data), P10-U7 done (HPA reads `kubeheal_model_inflight_requests`), `rbac_check.py` 696 checks 0 failures, both live tests pass. Victim Deployments now carry `kubeheal.io/watch=true`.
- Manual drift try: drift detected, decision OBSERVE (health_risk 0.41, CI width 1.0, burn-in on). AUTO_PATCH is unreachable with the current Health Model checkpoint. Owner decision needed (see PROGRESS "P10 findings").

## Next

See `docs/kubeheal/NEXT_FOR_CODEX.md` (three parallel sessions: cluster owner on `demo`, P11 scripts, docs plus P6-D2). `demo/scripts/demo.ps1` does not exist yet.

## Open issues

- Drift scoring gap (owner decision: HUMAN path demo, policy override on `work`, or P12-H).
- Executor ledger `S3Error` at startup; check that `kubeheal.ledger.pending` drained.
- Health Agent aiohttp `Unclosed client session` leak.
- Not checked: whether `health_ci_width=1.0` is a fallback; trained checkpoint load in the model pods.
- P7-RR-11, P7-RR-12, REV-3 graph test, P6-D6 background data.

## Rules that still apply

Only `--context k3d-kubeheal`; never touch `hybrid-demo`. Never push, never set `ALLOW_PUSH`, no destructive git commands, no training, no invented numbers.

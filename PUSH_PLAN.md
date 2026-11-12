# Push plan (draft, do not push)

The owner pushes. This file is a rehearsal checklist and must be refreshed after the final green merge. Never set `ALLOW_PUSH` and never run a push command from an agent session. Current base refs at authoring: `work` `f29dd1c`, `demo` `9986b73`, `origin/main` `48a59aa7195ea14f8366a4338293f095c8803daf`. These are starting refs, not final push hashes.

## Ten-line change summary versus `origin/main`

1. Replaces legacy neural scoring in the active path with shipped LightGBM Health and Security bundles.
2. Uses split-conformal prediction sets and TreeSHAP factors; requires exactly one label for automatic action.
3. Uses deterministic Health/Security correlation in Fusion; legacy DCM and neural servers are disabled by default.
4. Keeps the kill switch fail-closed in test mode and records would-have actions without Kubernetes writes.
5. Routes Kubernetes writes through the Remediation Executor with request validation and per-write mode checks.
6. Adds Health Agent baseline candidates, automatic dev/staging promotion, dashboard prod approval, and ledger records.
7. Adds canary drift remediation, snapshots, restore, entropy rescan, quarantine, and cgroup freeze containment paths.
8. Adds dashboard incident, kill-switch, baseline, containment, ledger, and release controls.
9. Adds local k3d deployment, monitoring, HPA/load scaffolding, replay fixtures, and demo evidence workflow.
10. Adds safety tests, P11 evaluation tooling, acceptance scripts, operator docs, and measured evidence where available.

This summary describes intended/implemented scope accumulated in the local branches. Reconcile every line with the final `git diff origin/main...demo`; remove or qualify any item not merged or verified. Do not claim measured model or performance quality from synthetic bundle metadata.

## Final checks after the rehearsal

Run from the repository root in PowerShell. `work` must be green before merging, then `demo` must be green after the merge. Live tests are separate explicit commands and are not part of the default suite.

```powershell
git status
git log --oneline -10 work
git log --oneline -10 demo
git diff --check origin/main...work
git diff --check origin/main...demo
Push-Location ..\Unisys_Model-wt-metric-query
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=$env:TEMP\kubeheal-final-work --deselect tests/test_rbac_k3d.py
Pop-Location
Push-Location .
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe -m pytest tests/ -q -p no:warnings --basetemp=$env:TEMP\kubeheal-final-demo --deselect tests/test_rbac_k3d.py
Pop-Location
```

After each default suite, run the live RBAC acceptance only when explicitly scheduled and safe: `$env:KUBEHEAL_LIVE_RBAC_TEST='1'; ..\Unisys_Model\.venv\Scripts\python.exe -m pytest tests/test_rbac_k3d.py -q; Remove-Item Env:KUBEHEAL_LIVE_RBAC_TEST`. The kill-switch integration test intentionally changes mode and must run only as a scripted demo step with `KUBEHEAL_LIVE_KILLSWITCH_TEST=1`, then verify that mode is restored to `test`.

## Merge and scan commands

Review the final diffs before staging. Never merge a red branch. Run these only after recorded green suites:

```powershell
git switch demo
git merge --no-ff work
```

Secret and artifact review, scoped to the actual final diff:

```powershell
git diff --name-only origin/main...demo
git diff --check origin/main...demo
git status --short
rg -n -i "(AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|password\s*[:=]|token\s*[:=]|secret\s*[:=]|\.env|kubeconfig)" --glob "!*.png" --glob "!*.lock" .
```

Review every match manually, including ignored/untracked files and generated artifacts. Confirm no `.venv`, kubeconfig, Secret data, private keys, `.env`, or unreviewed large binaries are in the diff. Confirm `.gitignore` excludes local environments, secrets, generated images/values, and demo scratch output.

Before handing control to the owner, update `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`, this plan's work/demo hashes, exact suite counts, F1-F13 states, verified-on-k3d note, and the rehearsed runbook result. Record unmeasured values as `not measured`. No agent pushes.

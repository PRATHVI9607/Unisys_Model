# Push plan (owner-only, do not push from this session)

Last checked 2026-11-12 23:05 IST. Branch tips before this audit update: `work` `b1e2dc3`, `demo` `992b732`, `origin/main` `48a59aa7195ea14f8366a4338293f095c8803daf`. Work is merged into demo. Nothing has been pushed and `ALLOW_PUSH` was not set.

## Ten-line change summary versus `origin/main`

1. Moves active scoring to LightGBM Health and Security models with split-conformal sets and TreeSHAP explanations.
2. Requires a single-label conformal result before automated decisions and uses the inclusive D1 10x rule.
3. Adds deterministic Health/Security Fusion and D-5 replay into the Security event path.
4. Adds fail-closed test mode, a kill switch, and would-have ledger entries without Kubernetes writes.
5. Makes Executor the Kubernetes writer and validates requests before writes.
6. Adds signed Redis containment request/result messages using the dedicated HMAC Secret.
7. Adds baseline candidates, dev/staging promotion, prod dashboard approval, and ledger records.
8. Adds freeze, forensic snapshot, quarantine, restore, entropy rescan, and release workflows.
9. Adds incident and baseline dashboard controls, queue-depth HPA, Grafana panels, and k3d deployment assets.
10. Adds safety tests, live acceptance scripts, P11 evaluation scaffolding, runbook steps, and evidence artifacts.

## Current verification

- Full suites: `work` 2,158 passed, 11 skipped in 90.05s; `demo` 2,158 passed, 11 skipped in 66.43s. Default suite leaves cluster/Redis/MinIO/mode tests opt-in.
- F3 is live-verified through restore; Sense input was scripted because Falco is absent. F4 HMAC test-mode smoke passed signed, unsigned, and tampered message cases.
- Cluster runs demo tag `b20261112215116`, Helm revision 13, mode `test`. Last readback was 2026-11-12 22:28 IST. Any later cluster touch checks `docs/kubeheal/CLUSTER_LOCK.md`; commit a lock before enforce or Helm upgrade and remove it after.
- Secret/artifact scan of the 377-path `origin/main...demo` diff found one credential-pattern match: a 21-character placeholder-like test fixture assignment in `tests/test_dashboard_seed.py`. No `.env`, kubeconfig, virtual environment, or binary artifact was changed in that diff. `.gitignore` excludes local environments, generated values, image tags, admin token, and pytest temp data; model checkpoint exceptions are intentional.
- `git diff --check origin/main...demo` reports existing whitespace in CSI comments, trailing spaces in captured k6 transcripts, and blank lines at EOF. This was not a clean check.
- The cluster HPA repeat scaled 2 -> 8 -> 2 with 12 refused checks; an earlier HPA run passed 121,088/121,088 and Grafana API/Prometheus evidence is saved, but a visual screenshot is missing.

## Feature state before final rehearsal

- F1 DONE: opt-in live-test safety guard, scratch pod absent, merged worktree metadata pruned.
- F2 DONE: D-5 replay emitted a real scored Security event and Fusion/Executor test-mode evidence.
- F3 DONE: live containment through restore; scripted Sense caveat above.
- F4 DONE: live test-mode HMAC smoke refused unsigned and tampered messages.
- F5 NOT DONE: live baseline promotion and ledger entry not verified.
- F6 NOT DONE: full live Executor validation acceptance not verified.
- F7 NOT DONE: live M2/D1/rollback sequence not verified.
- F8 NOT DONE: populated dashboard approval/rejection/release walkthrough not verified.
- F9 NOT DONE: paired kill-switch test/enforce live scenario has no validated safe trigger.
- F10 NOT DONE: live canary patch and bad-p99 rollback not verified.
- F11 NOT DONE: scaling was measured, but post-merge run had 12 refusals and no Grafana screenshot.
- F12 NOT DONE: `up.ps1` acceptance has not passed twice from a clean baseline.
- F13 NOT DONE: accepted P11 evaluation not measured; uncovered metrics remain `not measured`.

## Remaining steps before owner push

1. After the 23:30 IST merge cutoff, rehearse `docs/kubeheal/DEMO_RUNBOOK.md` once from a fresh cluster start. Capture output/screenshots under `docs/kubeheal/demo-evidence/`; use only verified features as live steps and record explicit skips for the rest.
2. If any code changes, rerun the full suite on work, merge only green work into demo, then rerun the full suite on demo and record exact counts.
3. Update README.md and AGENTS.md with final verified design and measured figures only; retain the `Verified on k3d` qualification.
4. Refresh `docs/dev-notes/PROGRESS.md`, `.ai/handoff.md`, this plan, and mode `test`; commit each completed task.
5. Review `git diff --check`, the full diff against origin, secret/artifact scan, and `git status`; do not include local credentials, environments, or large binaries.

## Exact final verification commands

Run from the demo checkout in PowerShell. The default suite is the full suite; live tests stay opt-in.

```powershell
git status
git log --oneline -10 work
git log --oneline -10 demo
git diff --check origin/main...work
git diff --check origin/main...demo
$env:PYTHONPATH='.'
Push-Location ..\Unisys_Model-wt-metric-query
.\.venv\Scripts\python.exe -m pytest tests -q -p no:warnings
Pop-Location
Push-Location .
.\.venv\Scripts\python.exe -m pytest tests -q -p no:warnings
Pop-Location
git status --short
```

After a green work suite, the authorized integration sequence is `git -C ..\Unisys_Model-wt-metric-query merge --no-ff <reviewed-branch>` followed by `git merge --no-ff work` in the demo checkout. Re-run the demo suite after the merge. Do not add `git push` to this plan; the owner pushes outside this agent session.

The owner performs any eventual push. Never run `git push`, never set `ALLOW_PUSH`, and do not claim a feature or metric that is not supported by saved evidence.

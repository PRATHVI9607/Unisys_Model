# F3b: drift and baseline after a restore

Date 2026-11-12. Read only: no cluster write was made for this check (one Redis GET of the prod baseline, one pod-log read, code reading, offline run of the real code and the shipped health bundle).

## Findings

1. **F3 never exercised this path.** The Health Agent only watches Deployments labelled `kubeheal.io/watch=true` (`WATCH_LABEL_SELECTOR`). The F3 scratch Deployments did not carry the label, so no baseline was recorded for them and no health event was published (`kubeheal.health.events` length 40 before and after window 3). The live F3 run says nothing about drift.
2. **A restore leaves the Deployment drifted against its golden baseline.** The baseline is the whole spec minus `replicas` (`baseline.drift_view`). `restore.py` repoints `volumes[].persistentVolumeClaim.claimName` to the new `<pvc>-restore-<incident>` claim and pins every image to `repo@sha256:...`; the baseline still has the old claim and the image tags. Offline, with the real prod/victim-app baseline: `is_drifted` True, changed paths `containers[0].image`, `initContainers[0].image`, `volumes[0].persistentVolumeClaim.claimName`.
3. **The shipped health model scores that diff `critical`, risk 0.6954, one-label set (spec diff only; no Prometheus window).** Decision policy on that answer: dev `observe`; staging `human_patch` (0.695); prod `human_patch` (0.834, just under the 0.85 automatic threshold). What real metrics would add is not known; a higher score in an unprotected, known tier is `auto_patch`.
4. **That patch would put the encrypted volume back.** `drift.build_patch` over those three paths produces `replace .../claimName -> victim-data` (the old, encrypted PVC) plus the image tags. A human approving the `human_patch`, or an automatic patch above the threshold in `enforce`, would revert the restore. This is the bug.

## Fix (branch `wave/claude-F3b`, from `wave/claude-F3` d0ed188)

`agents/executor/drift.py`: `validate_patch_target` refuses any patch that changes, adds or drops a PVC claim (`patch_changes_volume_claim`); the request escalates to a human before any write, like the selector and posture checks. Other candidate fields of the same Deployment still patch normally. Tests: `tests/test_executor_volume_claim_guard.py` (8 tests, including the restore-shaped case through `canary_patch`). `sim_output_after_fix.txt` shows the real-shape diff now refused.

## Still true after the fix (not fixed here)

- The baseline stays stale until an operator re-baselines: `scripts/baseline_tool.py reset <namespace> <deployment>`, then touch the Deployment so the Health Agent records the live spec (operator action, no ledger entry). Until then the Health Agent keeps flagging drift and Fusion keeps asking for human approval; with the guard, approving it escalates instead of reverting.
- In `dev` and `staging` an automatic baseline promotion (mode `enforce`, benign verdict) would also replace the golden record; that was not observed.
- Not observed live: a restored, watched Deployment. A live confirmation needs a labelled scratch Deployment and a patch that mimics the restore in test mode; not done because this check was read only.
- Incidental: the Health Agent logs its Redis URL, password included, at startup (`Redis URL: redis://:<password>@redis-master:6379`). That is a credential in pod logs; the code that logs it was not changed here.

`golden_prod_victim_app_baseline_read_2026-11-12.json` is the baseline read from Redis; the digest in the simulation is a made-up value (`ab` repeated), only its shape matters.

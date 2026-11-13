# F2 demo image replay evidence

- Date/time: 2026-11-13 07:14 IST (01:44 UTC)
- Machine/context: Windows 11, `k3d-kubeheal`
- Helm revision: 15
- Demo image tag: `b20261113071011`
- Mode: `test` before and after; read back both times
- Command: `.venv\Scripts\python.exe scripts\d5_replay_runner.py --timeout-s 120`
- Raw output: `d5-demo-image-rerun-2026-11-13.txt`
- Result: the hand-written replay produced a Security Agent model-scored ransomware event (`prediction_set=[ransomware]`, risk `0.9500`, `owner_resolved=true`), Fusion queued `auto_contain`, and the Executor appended `DRY RUN: would have CONTAIN ...` to `kubeheal.actions`.
- Cleanup: runner verified `FALCO_MODE=auto`, replay mount removed, and mode remained `test`.
- Kubernetes workload writes: none. This verifies the replay path through Security, Fusion, and Executor dry-run on the rebuilt demo images. It is not a live Falco capture or enforce containment.
- Executor stream readback for incident `inc-20261113-014415-70268e61` is recorded in the raw output's companion evidence: queued action and dry-run outcome. No credentials or Secret values were captured.

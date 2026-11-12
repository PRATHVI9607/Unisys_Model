# KubeHeal k3d live demo runbook

This runbook is for the `k3d-kubeheal` context only. It does not claim an end-to-end feature is working until its evidence folder contains a dated terminal transcript and screenshots from the rehearsed run. Never use `hybrid-demo`. Keep `kubeheal-mode` in `test`; F3 and F9 currently have no verified live trigger, and the F10 script is test-mode only. Do not open an enforce window until a reviewed scratch trigger and automatic cleanup are documented.

## Common preflight

**Planned time (estimate):** 5 minutes. **Show:** running cluster, workloads, mode, and Helm release. **Expected:** context reachable, workloads ready, release deployed, mode `test`.

```powershell
docker ps --format "table {{.Names}}\t{{.Status}}"
kubectl --context k3d-kubeheal get nodes -o wide
kubectl --context k3d-kubeheal -n kubeheal get pods -o wide
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
helm --kube-context k3d-kubeheal list -n kubeheal
```

If any component is not ready, stop at the preflight and show the saved output in `docs/kubeheal/demo-evidence/preflight/`. Do not continue with a partially deployed cluster.

## F2. D-5 replay to Security event

**Planned time:** up to 2 minutes for the runner's 120-second bounded operation. **Show:** the hand-written trace and the runner's Security event, matching Fusion action, and cleanup confirmation. **Expected output:** `Security event:` includes `syscall_source=replay` and the current `prod/victim-app` identity; `Fusion action:` targets the same pod and has `dry_run=true`; the final line confirms the replay mount was removed and mode remains `test`. This verifies replay-to-Security-to-Fusion dry-run only. It does not test Executor containment or live Falco capture.

```powershell
Get-Content tests/fixtures/falco/ransomware_pv_encrypt_new_rules.jsonl
.\.venv\Scripts\python.exe scripts\d5_replay_runner.py --timeout-s 120
```

The runner refuses unless mode is already `test`, Falco mode is `auto`, and there is exactly one running prod victim pod. It uses only context `k3d-kubeheal`, adapts the hand-written fixture to that pod's identity, temporarily patches the Security Agent on its node, and restores the original DaemonSet and removes the temporary ConfigMap in `finally`. Do not manually patch the DaemonSet. Use only a candidate containing the bounded-cleanup correction in `b516a0d`. **Live run reported on k3d on 2026-11-12 at 13:18 UTC:** the run produced the Security event and Fusion dry-run action recorded in [F2 replay evidence](demo-evidence/F2/d5-replay-2026-11-12.md). The first cleanup attempt failed; a subsequent run with the corrected bounded-cleanup runner completed restoration and cleanup, verified `FALCO_MODE=auto`, removed the replay mount, and left mode `test`. The correction reserves time for cleanup, verifies DaemonSet restoration, and deletes the owned ConfigMap only after restoration succeeds. This proves replay-to-Security-to-Fusion dry-run only. The Fusion action targeted the pod name as a deployment, and an earlier Executor request was refused for pod/workload mismatch; this is not F3 containment evidence. F4 unsigned/tampered-message rejection is also not verified by this replay. The fixture is synthetic, not a Falco capture. Screenshots and a raw terminal transcript were not saved for this run; capture them during rehearsal. If the live runner fails, use `.\.venv\Scripts\python.exe -m pytest tests/test_d5_replay_runner.py -q` as offline fallback, save the real test output and fixture screenshot, and do not substitute unit output for the Security event.

## F3. Alert-driven ransomware containment

**Planned time (estimate):** 10 minutes. **Show:** one alert through Fusion, Executor intake, freeze confirmation, forensic snapshot, quarantine, scale to zero, restore from before T0, entropy rescan Job, quarantine release, and ordered ledger entries. **Expected order:** freeze -> forensic snapshot -> quarantine -> scale to 0 -> restore -> entropy rescan -> lift quarantine -> ledger records. The live check must be launched from the alert path and use a scratch workload in `dev`.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,job,pvc,volumesnapshot -o wide
kubectl --context k3d-kubeheal -n kubeheal port-forward service/kubeheal-dashboard 8500:5000
```

**NOT VERIFIED live:** there is no validated end-to-end alert trigger for this full chain on this branch. Do not open an enforce window or use the direct freeze helper as a substitute. Safe fallback command: `python -m pytest tests/test_remediation_ransomware.py -q`; show test output and read-only object state from the first block. Save the transcript, output, and screenshots under `docs/kubeheal/demo-evidence/F3/`, clearly labeling them as test evidence. A live fallback requires the full event-to-ledger transcript and screenshots; none are saved yet.

## F4. HMAC on Redis containment messages

**Time:** reserve 2 minutes; smoke runner timeout is 60 seconds. **Show:** the dedicated Secret name without its contents, then the three signed-result checks. Never reveal Secret data or expose a Redis URL/password.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get secret kubeheal-containment-hmac -o name
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
.\.venv\Scripts\python.exe scripts\containment_hmac_smoke.py --timeout-s 60
```

Run the smoke command only after the smoke runner is integrated into the candidate and only while mode is already `test`. Its exact expected lines are a target pod with `mode=test`, `signed: status=dry_run ... result_hmac=valid`, `unsigned: status=refused reason=invalid_hmac ... result_hmac=valid`, and `tampered: status=refused reason=invalid_hmac ... result_hmac=valid`, followed by `Cleanup verified: run-owned Redis messages/results removed; mode remains test`. This exercises three mode-test stream requests and cleans only run-owned keys. **NOT VERIFIED live:** the smoke runner has fake-transport tests but has not been run against k3d. Never run in a different mode or during another acceptance window. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_containment_hmac_smoke.py -q`; capture actual output and a redacted Secret-name screenshot under `docs/kubeheal/demo-evidence/F4/`. A unit result is not live HMAC evidence.

## F5. Baseline promotion

**Time estimate:** 4 minutes when a real candidate exists. **Show:** dev/staging automatic promotion and its ledger entry; then the prod candidate, operator approval, and ledger entry.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

Open `http://127.0.0.1:8500/baseline-candidates` and `http://127.0.0.1:8500/approvals`. Approval and rejection are `POST /api/baseline-candidates/{namespace}/{deployment}/approve` and `/reject`, with JSON `{"candidate_id":"...","reason":"..."}` and an admin bearer token. Use the interactive dashboard token field; never put a real token in a transcript. Expected: a candidate status change and a corresponding ledger record. **NOT VERIFIED live:** no safe candidate-generation trigger or before/after promotion evidence is available, so do not approve a fabricated candidate. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_baseline_promotion.py tests/test_dashboard_baseline.py -q`; capture test output and candidate/approval page screenshots (redacted) in `docs/kubeheal/demo-evidence/F5/`. Unit/UI evidence is not a live promotion.

## F6. Executor request validation

**Time estimate:** 3 minutes. **Show:** a valid request accepted for an allowed target, then malformed, stale, mismatched-UID, protected-namespace, and incomplete requests refused before any write.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get pods -l app=executor -o wide
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,networkpolicy -o wide
```

Expected for the eventual live trigger: Executor validation outcomes show accepted/refused reasons, and the rejected cases leave workload state unchanged. **NOT VERIFIED live:** no safe request injector is available. Do not write directly to Redis or patch a workload to fabricate an Executor request. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_remediation_validation.py tests/test_executor_containment_v5.py -q`; save actual output and a read-only before/after workload listing in `docs/kubeheal/demo-evidence/F6/`. This is validation-test evidence, not live Executor intake.

## F7. Conformal, D1, and rollback policy

**Time estimate:** 4 minutes. **Show:** a single-label prediction set, an ambiguous set held for a human, inclusive D1 behavior at `<=50m` CPU or `<=32Mi` memory, and a rollback that requires a fresh Security Model response.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get deployment,service | Select-String 'inference|fusion'
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
```

Expected live output must include the prediction set and policy decision for each boundary case; the rollback must cite a fresh Security response. **NOT VERIFIED live:** there is no validated scenario command for these inputs and outcomes. Do not present generic logs as proof. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_policy_rules.py tests/test_decision_policy.py -q`; save actual output in `docs/kubeheal/demo-evidence/F7/` and label live behavior not verified.

## F8. Dashboard operations

**Time estimate:** 5 minutes with a populated incident. **Show:** incidents, approve/reject controls, admin-token kill switch, baseline candidates, containment status, ledger timeline, and SnapshotFreeze status/release. Keep the token out of screen captures and saved output.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

Open `http://127.0.0.1:8500/approvals` for incidents/actions, `http://127.0.0.1:8500/baseline-candidates` for candidates, and `http://127.0.0.1:8500/incidents/{incident_id}` for the timeline, containment details, and SnapshotFreeze card. The kill switch route is `GET/POST /api/kill-switch`; POST JSON is `{"mode":"test"}` or `{"mode":"enforce"}` with an admin bearer token. Do not put that token in a command transcript. For this runbook, keep mode `test`; do not use `enforce` as a demonstration toggle. Baseline approval/rejection endpoints are listed in F5. On the incident page, a held freeze displays namespace/PVC and the release form; enter a reason of at least ten characters and use `force` only when intentionally releasing an open incident. The API is `POST /api/incidents/{incident_id}/release-snapshot-freeze`. In mode `test`, expected outcome is a dry-run ledger entry and no release. The release control requires the dashboard implementation commit to be integrated into the candidate. **NOT VERIFIED live:** no populated incident has been walked through the complete control set. Do not claim approval/rejection/release effects from an empty dashboard. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_dashboard_incident.py tests/test_dashboard_approvals.py tests/test_dashboard_freeze.py tests/test_dashboard_killswitch.py tests/test_dashboard_baseline.py -q`; capture actual test output and token-redacted screenshots in `docs/kubeheal/demo-evidence/F8/`.

Before and after any authorized scripted window, verify:

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

**Expected:** each control reflects its resulting state and the ledger contains the associated operator action. Fallback: redacted screenshots and API transcript in `docs/kubeheal/demo-evidence/F8/`.

## F9. Kill switch end to end

**Time estimate:** 4 minutes once the paired test/enforce trigger is validated. **Show:** test-mode Sense/Score/Decide/Record with a `would have` ledger entry and unchanged Kubernetes state; then the same bounded scratch scenario in enforce mode with an applied action.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
```

Expected live proof is a before/after workload comparison and the matching ledger entries for both scripted windows; log only each authorized window's start/end in the project record. **NOT VERIFIED live end-to-end:** no validated paired scratch trigger exists. Do not toggle to `enforce` or substitute log inspection for the trigger. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_killswitch.py tests/test_dashboard_killswitch.py -q`; save test output plus mode/ledger screenshots under `docs/kubeheal/demo-evidence/F9/`. This is test evidence, not a live Kubernetes action.

## F10. Drift healing and rollback

**Time estimate:** up to 12 minutes for the existing test-mode drift walkthrough. **Show:** the drifted CPU fields, dry-run decision, and restored manifest. The full feature additionally requires canary-only drift-field patching, a rollback point, p99 measurement, and rollback after a bad p99.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action drift -ObserveSeconds 30 -ProbeSeconds 30
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
```

The script asserts mode `test`, temporarily changes only `prod/victim-app` CPU request/limit to 50m/50m, waits for a new action, and restores 100m/500m in `finally`. Expected from this script is a dry-run drift record and restored 100m/500m; it does not apply a canary patch. **NOT VERIFIED live healing/rollback.** The estimate includes the script's 330-second cooldown, metric probe/observe waits, and two rollouts; duration has not been measured. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_remediation_drift.py -q`; save actual output and before/after manifests plus ledger output in `docs/kubeheal/demo-evidence/F10/`. Do not claim p99 rollback without a live record.

## F11. Queue-depth HPA and Grafana

**Measured run duration:** 7m14s; plan 8 minutes for this run, baseline check, and Grafana view. **Show:** queue metric increasing under k6 load, HPA scaling 2 -> 7 -> 2, then the queue-depth and replicas panels.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\hpa_load.ps1 -Vus 32 -DurationSeconds 90 -SampleSeconds 10 -ScaleDownWaitSeconds 330
kubectl --context k3d-kubeheal -n kubeheal get hpa kubeheal-inference -o wide
kubectl --context k3d-kubeheal -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Open `http://127.0.0.1:3000` and select the KubeHeal overview dashboard. The script checks mode `test`, waits for the HPA baseline, creates a bounded k6 job plus scoped NetworkPolicy/ConfigMap, emits samples and k6 summary, and cleans only its run-owned resources in `finally`. **Measured once on 2026-11-12:** 32 VUs for 90 seconds; 121,088/121,088 checks passed; median 22.86 ms, p95 38.45 ms; HPA 2 -> 7 -> 2; duration 7m14s. See [the saved run report](demo-evidence/F11/hpa-run-2026-11-12.md). This one synthetic scoring-load run is not a performance guarantee. The earlier script attempt failed because `Out-String -NoNewline` flattened the JS file; temporary resources were cleaned up, and the fix is `6f97f88`. No full terminal screenshots were saved. Fallback: use the recorded k6/HPA report, then capture fresh Grafana screenshots in `docs/kubeheal/demo-evidence/F11/` and label them as a fallback, not a rerun.

### Separate P11 evaluation status

Do not combine F11's successful HPA test with P11 E1. **P11 E1 result: not measured (both attempts failed).** Attempt 1: 0/297 checks passed, 297 connection refusals; latency `not measured`. Attempt 2: 111,564/111,576 checks passed, 12 first-second refusals to `10.43.219.57:8000`, no HTTP status. It observed median 24.02 ms and p95 40.33 ms on a failed run; these are not an accepted benchmark. In attempt 2 HPA sampled 2 -> desired 4 -> current 4/desired 8 -> 8/8, then read-only recovery verified 2/2 with two ready endpoints; cleanup succeeded. Exact reports and raw files are under `results/p11/`; see `results/p11/P11_COVERAGE.md`. E2 was not run. P11 E2, E3 RPO/RTO, E4 stage timing, E5 comparisons, E6 precision/memory, and V5-E1 are `not measured` in the coverage report; no values are inferred from another feature's run.

## Evidence checklist

After each rehearsal, save raw terminal output and screenshots in `docs/kubeheal/demo-evidence/F2/` through `F11/`, with a README containing date, machine, cluster, exact command, result, duration, and deviations. Redact credentials, tokens, Secret data, and customer data. If a feature is not exercised successfully, mark it `not verified` and use the evidence fallback; do not present a unit test as live evidence.

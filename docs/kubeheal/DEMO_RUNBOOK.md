# KubeHeal k3d live demo runbook

This runbook is for the `k3d-kubeheal` context only. It does not claim an end-to-end feature is working until its evidence folder contains a dated terminal transcript and screenshots from the rehearsed run. Never use `hybrid-demo`. Keep `kubeheal-mode` in `test` except for the bounded, scripted F3, F9, and F10 windows below; restore `test` immediately after each window.

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

**Planned time (estimate):** 5 minutes. **Show:** replay input, Security Agent logs, Redis stream event, then Fusion incident decision. **Expected:** the trace is associated with the live victim identity; a model-scored single-label `ransomware` event can proceed to automatic containment, while heuristic-only or uncertain evidence becomes `HUMAN`. Do not claim a live Falco capture: the fixture is hand-written.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs daemonset/security-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal get pods -l app=fusion-agent -o wide
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
```

**NOT VERIFIED live:** this branch has no deployed replay mount/trigger or validated Redis stream inspection command. Do not patch the DaemonSet or claim a live replay. Safe fallback command: `python -m pytest tests/test_sense_falco_replay.py -q`; show the fixture with `Get-Content tests/fixtures/falco/ransomware_pv_encrypt_new_rules.jsonl`. Save the exact terminal output and a screenshot of the fixture/test result under `docs/kubeheal/demo-evidence/F2/`. The fallback demonstrates parser/model-publish tests only, not a cluster Security event. Live trigger remains pending.

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

**Planned time (estimate):** 3 minutes. **Show:** the key name in the Secret metadata only, a signed accepted request/result, and unsigned and tampered messages refused. Never reveal Secret data.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get secret
kubectl --context k3d-kubeheal -n kubeheal logs daemonset/security-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
```

**NOT VERIFIED live:** this branch has no validated trigger for signed, unsigned, and tampered stream messages. The safe cluster commands above inspect Secret names and recent logs; they do not prove HMAC rejection. Never print or decode Secret data. Fallback: save actual output from `kubectl --context k3d-kubeheal -n kubeheal get secret kubeheal-redis -o name` plus redacted log screenshots under `docs/kubeheal/demo-evidence/F4/`; mark HMAC results not verified until the focused HMAC tests and safe live trigger are present.

## F5. Baseline promotion

**Planned time (estimate):** 4 minutes. **Show:** a dev/staging promotion and ledger entry, then a prod candidate in the dashboard and approval producing a ledger entry.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
kubectl --context k3d-kubeheal -n kubeheal logs deployment/health-agent --since=5m
```

Open `http://127.0.0.1:8500/baseline-candidates` and `http://127.0.0.1:8500/approvals`; the tested route names are `/baseline-candidates` and `/approvals`. Candidate approval/rejection routes are `POST /api/baseline-candidates/{namespace}/{deployment}/approve` and `/reject`, with `Authorization: Bearer <admin-token>` and JSON `{"candidate_id":"...","reason":"..."}`. Use only the UI with an ephemeral demo token; do not put a token in a command transcript. **NOT VERIFIED live:** no safe dev/staging candidate-generation trigger is available on this branch and no live before/after promotion evidence is saved. Safe fallback command: `python -m pytest tests/test_baseline_promotion.py tests/test_dashboard_baseline.py -q`; capture actual output and screenshots of the existing dashboard routes under `docs/kubeheal/demo-evidence/F5/`. This is test/UI evidence, not a live promotion.

## F6. Executor request validation

**Planned time (estimate):** 3 minutes. **Show:** valid request accepted for an allowed target, followed by malformed, stale, mismatched-UID, protected-namespace, and incomplete requests rejected before writes.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,networkpolicy -o wide
```

**NOT VERIFIED live:** no safe live request injector is available; do not write directly to Redis or patch a workload to fabricate an Executor request. Safe fallback command: `python -m pytest tests/test_remediation_validation.py tests/test_executor_containment_v5.py -q`. Capture the actual test output and a read-only before/after workload listing under `docs/kubeheal/demo-evidence/F6/`. This does not count as live Executor intake.

## F7. Conformal, D1, and rollback policy

**Planned time (estimate):** 4 minutes. **Show:** a one-label prediction set, an ambiguous set held for a human, an inclusive 10x cut at 50m CPU or 32Mi memory, then a rollback that proceeds only with a fresh Security Model response below the policy threshold.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-inference --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
```

**NOT VERIFIED live:** there is no validated scenario command that drives all three policy cases through the live model and Fusion path. Safe fallback command: `python -m pytest tests/test_policy_rules.py tests/test_decision_policy.py -q`; capture the actual output and the relevant policy response in `docs/kubeheal/demo-evidence/F7/`. Until live requests show one-label, ambiguous, inclusive `<=50m`/`<=32Mi`, and fresh Security response behavior, label this step not verified.

## F8. Dashboard operations

**Planned time (estimate):** 5 minutes. **Show:** incidents, approve/reject, admin-token kill-switch toggle, baseline approval, containment status, ledger view, and SnapshotFreeze release. Keep the token out of screen capture and saved output.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
```

Open `http://127.0.0.1:8500/approvals` for incidents, approve/reject, kill switch, and ledger links. Use `/baseline-candidates` for baseline candidates and `/incidents/{incident_id}` for the timeline. SnapshotFreeze release is `POST /api/incidents/{incident_id}/release-snapshot-freeze` with a JSON reason of at least ten characters; add `force:true` for an open incident. The UI/API uses the dashboard admin token; enter it only in the interactive UI session. A release in mode `test` records a dry-run and removes nothing. **NOT VERIFIED live:** no live incident has been through the complete control set, so do not claim approval/rejection or release effects from an empty dashboard. Safe fallback command: `python -m pytest tests/test_dashboard_incident.py tests/test_dashboard_approvals.py tests/test_dashboard_freeze.py tests/test_dashboard_killswitch.py tests/test_dashboard_baseline.py -q`; capture actual output and token-redacted screenshots in `docs/kubeheal/demo-evidence/F8/`. Before and after any authorized scripted window, verify:

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

**Expected:** each control reflects its resulting state and the ledger contains the associated operator action. Fallback: redacted screenshots and API transcript in `docs/kubeheal/demo-evidence/F8/`.

## F9. Kill switch end to end

**Planned time (estimate):** 4 minutes. **Show:** in test, Sense/Score/Decide/Record produce a "would have" ledger action and no Kubernetes change; in enforce, the same bounded scratch action occurs.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
```

**NOT VERIFIED live end-to-end:** the dashboard mode API exists, but there is no validated bounded scratch alert/action trigger for the paired test/enforce proof. Do not toggle to enforce without that scenario and cleanup. Safe fallback command: `python -m pytest tests/test_killswitch.py tests/test_dashboard_killswitch.py -q`; save actual output plus redacted mode/ledger screenshots under `docs/kubeheal/demo-evidence/F9/`. This is test evidence, not a live Kubernetes action.

## F10. Drift healing and rollback

**Planned time (estimate):** up to 12 minutes for the existing drift walkthrough. **Show:** drifted fields, the canary patch touching only those fields, rollback point, observed p99, and rollback after a bad p99 result.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action drift -ObserveSeconds 30 -ProbeSeconds 30
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
```

The script asserts mode `test`, temporarily changes only `prod/victim-app` CPU request/limit to 50m/50m, waits for a new action, and restores 100m/500m in `finally`. This is a drift-signal/dry-run walkthrough, not the requested Executor canary patch or bad-p99 rollback. **NOT VERIFIED live healing.** Time is not measured; reserve up to 12 minutes for its 330-second cooldown, metric probe/observe waits, and two rollouts. Safe fallback command: `python -m pytest tests/test_remediation_drift.py -q`; save actual test output plus before/after manifests and ledger output under `docs/kubeheal/demo-evidence/F10/`. Do not claim p99 rollback without a live record.

## F11. Queue-depth HPA and Grafana

**Time:** 8 minutes for the single measured run (7 minutes 14 seconds elapsed). **Show:** the queue metric rising during k6 traffic, HPA replicas increasing from 2 to 7, then returning to 2 after load stops; show the Grafana dashboard panels for queue depth and replicas.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\hpa_load.ps1 -Vus 32 -DurationSeconds 90 -SampleSeconds 10 -ScaleDownWaitSeconds 330
kubectl --context k3d-kubeheal -n kubeheal get hpa kubeheal-inference -o wide
kubectl --context k3d-kubeheal -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Open Grafana at `http://127.0.0.1:3000` and select the KubeHeal overview dashboard. The script checks mode `test`, waits for the HPA baseline, creates a bounded k6 job and scoped policy, prints the HPA values and k6 summary, and removes its temporary resources in `finally`. **Measured once on 2026-11-12:** 32 VUs for 90 seconds, 121,088 of 121,088 checks passed, median 22.86 ms, p95 38.45 ms, HPA 2 -> 7 -> 2; elapsed 7m14s. See [the recorded result](docs/kubeheal/demo-evidence/F11/hpa-run-2026-11-12.md). This single synthetic scoring-load run is not a performance guarantee. The earlier attempt failed because `Out-String -NoNewline` flattened the JS file; its temporary resources were cleaned up. The fix is committed as `6f97f88`. The successful run did not save full terminal screenshots; capture those during the final rehearsal. Fallback: recorded k6 output and HPA samples plus fresh Grafana screenshots in `docs/kubeheal/demo-evidence/F11/`.

### Separate P11 runner attempt

Do not confuse the successful F11 script run above with the P11 runner. The P11 E1 attempt on 2026-11-12 returned 0 checks passed and 297 failed requests out of 297 (`connection refused` to inference `:8000`). Its p50 and p95 are **not measured**. The failed attempt, raw log, HPA samples, and cleanup record are in `docs/kubeheal/results/p11/P11_E1_ATTEMPT_2026-11-12.md`; do not show its zero-duration latency values as measurements. E1 must be rerun after the narrow k6-to-inference NetworkPolicy rule is reviewed and safely deployed.

## Evidence checklist

After each rehearsal, save raw terminal output and screenshots in `docs/kubeheal/demo-evidence/F2/` through `F11/`, with a README containing date, machine, cluster, exact command, result, duration, and deviations. Redact credentials, tokens, Secret data, and customer data. If a feature is not exercised successfully, mark it `not verified` and use the evidence fallback; do not present a unit test as live evidence.

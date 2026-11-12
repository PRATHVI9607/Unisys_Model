# KubeHeal k3d live demo runbook

This runbook is for the `k3d-kubeheal` context only. Never use `hybrid-demo`. Keep `kubeheal-mode` in `test` except during explicitly scripted, logged enforce windows. F3 is live-verified from Fusion onward with scripted Sense input because Falco is absent. Do not run the F3 prefix-based cleanup helper; it must be made run-ID-safe first.

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

**Planned time:** up to 2 minutes for the runner's 120-second bounded operation. **Show:** the hand-written trace, real Security Agent event, Fusion decision, Executor intake, and cleanup confirmation. **Expected output:** `Security event:` includes `syscall_source=replay`, `deployment=victim-app`, `owner_resolved=true`, and the single `ransomware` label; `Fusion action:` targets that Deployment with `dry_run=true`; the Executor records would-have entries; the final line confirms cleanup and mode `test`.

```powershell
Get-Content tests/fixtures/falco/ransomware_pv_encrypt_new_rules.jsonl
.venv\Scripts\python.exe scripts\d5_replay_runner.py --timeout-s 120
```

The runner requires mode `test`, Falco mode `auto`, and exactly one running prod victim pod. It adapts the hand-written fixture to that pod, temporarily patches the Security Agent on its node, and restores the DaemonSet and removes the temporary ConfigMap in `finally`. Do not patch the DaemonSet manually. The live D-5 rerun is recorded in [F3 D-5 evidence](demo-evidence/F3/10_d5_rerun.txt): the real Security Agent scored and published the event, Fusion queued it, and the Executor recorded dry-run entries. This proves replay through Security, Fusion, and Executor intake, not live Falco capture or enforce containment. The fixture is synthetic. If the live runner fails, use `python -m pytest tests/test_d5_replay_runner.py -q` as an offline fallback, but do not present unit output as a Security event.

## F3. Alert-driven ransomware containment (live chain acceptance, scripted Sense input)

**Status: LIVE-VERIFIED for the chain from Fusion through restore. Sense is scripted because Falco is absent; this is not live detection.**

Evidence: `docs/kubeheal/demo-evidence/F3/`.

**Planned time (estimate):** 5 minutes including preparation and the rehearsal. Measured once: prep plus rehearse took about 13 seconds and the enforce window 45 seconds (see below). **Show:** one scripted alert through Fusion and the stream into the Executor, then freeze, forensic snapshot, quarantine, scale to 0, restore from the snapshot taken before T0, entropy rescan Job, quarantine lifted, and the ordered ledger entries. **Expected order:** freeze -> forensic snapshot -> quarantine -> scale to 0 -> restore -> entropy rescan -> lift quarantine -> `restored`.

### What is real and what is scripted

Say this out loud in the demo. It is the honest scope of the claim.

- **Scripted:** the alert. Falco is not installed on this k3d cluster, and the Security Agent's /proc-only path cannot produce a model score (no syscall window), so no non-replay alert exists here. Replay events are forced to dry run by design and are never used to enforce. `f3_window.py` therefore publishes ONE Security event on `kubeheal.security.events` with `syscall_source=scripted_window`. Its model fields (label `ransomware`, risk 0.9500, one-label set, top factors, model `security-5.0.0-c6fa12d8`) are copied from the event the real Security Agent published for the hand-written D-5 fixture scored by the real inference service. Identity, timestamps and T0 are the scratch pod's. The Sense stage is therefore not exercised by F3; F2 covers replay through Security and Fusion.
- **Real:** everything from Fusion onward (the HMAC signature on the freeze request is in the stream entry itself, `88_hmac_requests_and_breaker.txt`): the decision (`auto_contain`), `kubeheal.exec`, Executor intake and validation, the HMAC-signed freeze request to the node-local Security Agent and its signed answer, every Kubernetes write through the kill-switch gate, the Jobs, PVCs and snapshots, and the ledger.
- **Scripted setup:** the rolling snapshot before T0 is created by the script with the manifest the Executor's scheduler uses (`volume_snapshot`), because the scheduler only writes in `enforce`.
- **Namespace:** the scratch Deployment is in `staging`, not `dev`. The dev tier multiplier (0.70) cannot reach the 0.85 automatic containment threshold with a 0.95 risk; staging (1.00) can.

### Preflight (estimate: 1 minute)

0. Containment circuit breaker: a real (non dry-run) automatic containment in a namespace is limited to 3 per hour (`CB_CONTAIN_LIMIT_PER_HOUR`, per namespace). The three windows of 2026-11-12 used the staging allowance (`88_hmac_requests_and_breaker.txt`); a fourth staging window before 15:01:33Z on that day would have been human-gated, not automatic. Check `kubectl --context k3d-kubeheal -n kubeheal exec redis-0 -- redis-cli ZRANGE kubeheal:cbw:contain:staging 0 -1 WITHSCORES` before a window; rehearsals in `test` do not count.
1. Read `docs/kubeheal/CLUSTER_LOCK.md`. If another agent holds the lock, wait. Add your line, commit, remove it afterwards.
2. Mode must be `test`, all pods Ready, and the Executor image must contain the HMAC code:

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
kubectl --context k3d-kubeheal -n kubeheal get pods
kubectl --context k3d-kubeheal -n kubeheal exec deploy/executor -- grep -c sign_fields /app/agents/executor/freeze.py
kubectl --context k3d-kubeheal -n kubeheal exec deploy/executor -- grep -c _parse_result_line /app/agents/executor/restore_entropy.py
```

Both counts must be non-zero. An Executor image from before the HMAC change sends unsigned freeze requests, the Security Agent refuses them (`invalid_hmac`), and the containment ends `contained_with_gaps` with no restore. This happened on 2026-11-12 (window 1 below).

### Run (use a new name every attempt)

```powershell
$env:F3_NAME = "f3-scratch-d"          # new each time: a SnapshotFreeze key outlives its PVC
.venv\Scripts\python.exe docs/kubeheal/demo-evidence/F3/f3_window.py prep       # test mode: scratch Deployment, PVC, clean files, pre-T0 snapshot
.venv\Scripts\python.exe docs/kubeheal/demo-evidence/F3/f3_window.py rehearse   # test mode: expect "DRY RUN: would have CONTAIN ..."
# start an independent dead-man switch in a second terminal BEFORE the window:
#   sleep 400; kubectl --context k3d-kubeheal -n kubeheal patch cm kubeheal-mode --type merge -p '{"data":{"mode":"test"}}'
.venv\Scripts\python.exe docs/kubeheal/demo-evidence/F3/f3_window.py window     # ONE enforce window, mode forced back to test in `finally`
.venv\Scripts\python.exe docs/kubeheal/demo-evidence/F3/ledger_dump.py <incident_id from the output>
kubectl --context k3d-kubeheal -n staging get deployment,pod,job,pvc,volumesnapshot,networkpolicy -o wide
# Inspect each returned object and remove only resources bearing this run's unique name and ownership labels.
```

The window script confirms the switch to `enforce` in both Fusion pods, the Executor and the Security Agent on the scratch pod's node before it writes anything (it aborts back to `test` otherwise), writes high-entropy `.locked` files into the scratch volume at T0, publishes the alert, then polls the action and escalation streams. It stops at the first of: `executed_restore`, an `executed_contain` that is not exactly `contained`, an escalation, or 300 seconds. The mode goes back to `test` in `finally`.

### Expected output (window of 2026-11-12, `80_enforce_window_attempt3.txt`)

```text
ENFORCE WINDOW START 2026-11-12T14:15:49Z
mode switch seen in executor / both fusion-agent pods / security-agent on the node
action stream: auto_contain incident=inc-20261112-141554-1d76b1ed outcome=queued_for_executor dry_run=false
action stream: executed_contain ... outcome=contained
action stream: restore_requested ... outcome=queued_for_executor dry_run=false
action stream: executed_restore ... outcome=restored
ENFORCE WINDOW END 2026-11-12T14:16:34Z; mode now test
```

Ledger (`81_attempt3_ledger.jsonl`, 42 entries, UTC): alert accepted 14:15:55.1; `freeze_confirmed` 14:15:56.2 (cgroup `kubepods/burstable/pod806d422c-...`, `mode_seen: enforce`); `forensic_snapshot_created`; `quarantine_policy_created`; `pod_labelled`; `result: contained` 14:15:56.2; `restore_requested` 14:15:56.3; `scaled_to_zero` 14:15:56.6; `restored_pvc_created` from `kubeheal-roll-...-1794492929` (taken at 14:15:30Z, before T0 at 14:15:53Z); `repointed_and_pinned` (image pinned by digest); `scaled_back`; `entropy_checked` clean, 5 files scanned, 0 high entropy; `quarantine_labels_removed`; `quarantine_lifted` 14:16:28.8; `result: restored`. After the window the restored pod's `/data` holds only the five `clean_*.txt` files (the eight `.locked` files and the note are gone) and no quarantine label or NetworkPolicy remains. The window wrote exactly 42 incident ledger entries plus 2 `mode_change` entries (test to enforce, enforce to test) and nothing else; prod and dev workloads and the prod snapshots were unchanged. Measured once on this machine: 45 seconds of enforce, about 35 seconds from the published alert to `restored` (14:15:54 to 14:16:29 on the action stream). One run is not a performance claim.

### Not verified

- Sense: no live detection of the scratch pod's writes (see scope above).
- Falco rules, a real node (k3d only), and tampered or replayed HMAC messages. One incidental fact: in window 1 an unsigned freeze request was refused by the Security Agent with `invalid_hmac` and the Executor recorded `freeze_unconfirmed`; that is unsigned rejection, not tamper testing.
- The drift path after a restore: the golden baseline for the restored workload was not checked or re-baselined (the window ended right after `restored`). `restore.py` documents that an operator must re-baseline.

### Cleanup and state left behind

Do not run `f3_window.py cleanup` until its prefix-based deletion is replaced by run-ID label selection. It can delete unrelated `f3-*` or `kubeheal-*` resources. The successful run left four stale SnapshotFreeze keys and two fail-safe escalations from deleted scratch objects; show the dashboard ledger/status honestly.

`cleanup` aborts if `staging` holds anything whose name does not start with `f3-` or `kubeheal-`; otherwise it deletes everything in `staging` (the scratch objects, the forensic and rolling snapshots, the old PVC and the restored PVC). SnapshotFreeze keys are NOT removed and have no TTL: `kubeheal:snapfreeze:staging:f3-scratch-data`, `...f3-scratch-b-data`, `...f3-scratch-c-data`, `...f3-scratch-b-data-restore-inc-20261112-140632-c8ed65b8`. They are harmless for deleted PVCs; release them from the dashboard (F8) or leave them.

### Defects this found (fixed on `wave/claude-F3`)

1. D-5 target (`7871bab`): the Security Agent published the pod name as `deployment` when its pod index did not know the pod, and the Executor refused the request. It now resolves pod -> ReplicaSet -> Deployment (or StatefulSet) through ownerReferences before publishing, publishes an empty `deployment` and `owner_resolved=false` when no owner is found, and Fusion queues no containment for such an event (it escalates to a human). Cause: the index did not know the pod at publish time; why it did not (for example a stale index right after the DaemonSet restarted) is not proven. Verified live: the outcome (the D-5 rerun in test mode now carries `deployment: victim-app` and the Executor accepts it, `10_d5_rerun.txt`). Not observed live: the live-read fallback and the fail-closed branches; they are covered by `tests/test_owner_resolution.py`. A successful live resolve logs nothing, so the rerun cannot show whether the index or the new live read supplied the owner.
2. Executor image (deploy, no code change): the cluster ran an Executor image built before the HMAC change. Rebuilt and deployed.
3. Entropy scan result (`98df6b5`): the Kubernetes client returns a one-line JSON pod log as a Python repr (single quotes), `json.loads` failed, and every restore ended `restored_kept_isolated:entropy result unknown`. `restore_entropy.py` now falls back to `ast.literal_eval`. Window 2 (`60_enforce_window_attempt2.txt`, `61_attempt2_ledger.jsonl`) shows the failure; window 3 shows the fix.

### Windows run (three, not one)

| # | Start to end (UTC) | Result |
|---|---|---|
| 1 | 14:01:28 - 14:01:42 | contain ran; freeze refused `invalid_hmac` (old Executor image); `contained_with_gaps`, no restore (correct fail-safe) |
| 2 | 14:06:28 - 14:07:04 | full chain; entropy result unreadable; `restored_kept_isolated`, quarantine kept (correct fail-safe) |
| 3 | 14:15:49 - 14:16:34 | full chain, `restored`, quarantine lifted |

Mode was `test` before and after every window (read back), with a dead-man switch armed for each. The escalations from windows 1 and 2 (`contained_with_gaps`, `restored_kept_isolated`) remain on `kubeheal.escalations` and show as open human items on the dashboard; they refer to deleted scratch objects.

Operator writes outside the Executor (all in the scratch namespace, all disclosed): `prep` creates the scratch Deployment, PVC and the pre-T0 snapshot, `window` execs the "attack" writes, and one manual debug scan Job (`f3-debug-scan`, built with `job_body` against the restored PVC of window 2) was applied to find the entropy defect; `cleanup` deletes them.

## F4. HMAC on Redis containment messages

**Time:** reserve 2 minutes; smoke runner timeout is 60 seconds. **Show:** the configured Secret name and key reference without reading their value, then the three signed-result checks. Never reveal Secret data or expose a Redis URL/password.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get secret kubeheal-containment-hmac -o name
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
.\.venv\Scripts\python.exe scripts\containment_hmac_smoke.py --timeout-s 60
```

The chart provisions the dedicated Secret `kubeheal-containment-hmac`, key `key`; it is separate from Redis credentials. The command prints only its name. The runner checks mode `test` before and after, sends three uniquely named Redis stream requests, verifies the signed request/result, checks unsigned and tampered requests are refused with `invalid_hmac`, and removes only run-owned request/result keys. **LIVE-VERIFIED in mode test on 2026-11-12:** raw output is saved at [F4 HMAC smoke](demo-evidence/F4/hmac-smoke-2026-11-12.txt). It reported signed `dry_run`, unsigned and tampered `refused`, all result HMACs valid, cleanup verified, mode remained `test`. This did not open an enforce window and made no Kubernetes workload writes. **For future runs, hold a committed exclusive cluster lock for the whole smoke:** the signed freeze request is a real request and could actuate if another operator changes mode after the runner's test-mode check but before the Security Agent consumes it. Safe fallback: `python -m pytest tests/test_containment_hmac_smoke.py -q`; unit output is not live HMAC evidence.

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


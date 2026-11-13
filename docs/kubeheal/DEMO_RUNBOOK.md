# KubeHeal k3d live demo runbook

This runbook is for the `k3d-kubeheal` context only. Never use `hybrid-demo`. Keep `kubeheal-mode` in `test` except during explicitly scripted, logged enforce windows. F3 is live-verified from Fusion onward with scripted Sense input because Falco is absent. The F3 cleanup helper selects only resources carrying its unique run label or incident IDs found in its own action stream; review its printed targets before relying on the cleanup result.

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

The F3 cleanup helper now deletes only resources carrying the unique `kubeheal.io/f3-run` label for the selected `F3_NAME`, plus resources labelled with incident IDs found in that run's action or escalation stream. It prints the exact targets before deletion and refuses if no run-owned resources are found. Review that list before cleanup. Historical runs left four orphan SnapshotFreeze keys and two fail-safe escalations from deleted scratch objects; those are separate operator records and are handled as such below.

After confirming the selected `F3_NAME` resources and associated incident-labelled objects are scratch artifacts, run cleanup in mode `test`. It does not remove SnapshotFreeze keys. Those keys must be released separately only after confirming their PVCs are absent and recording the operator action.

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

Mode was `test` before and after every window (read back), with a dead-man switch armed for each. On 2026-11-13, append-only `human_resolution` ledger entries were added for the two historical fail-safe escalations (`contained_with_gaps`, `restored_kept_isolated`). Their original `kubeheal.escalations` stream entries remain; the scratch objects and associated orphan SnapshotFreeze keys are gone. See `demo-evidence/F3/101_operator_cleanup_2026-11-13.md`.

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

Open `http://127.0.0.1:8500/baseline-candidates` and `http://127.0.0.1:8500/approvals`. Approval and rejection are `POST /api/baseline-candidates/{namespace}/{deployment}/approve` and `/reject`, with JSON `{"candidate_id":"...","reason":"..."}` and an admin bearer token. Use the interactive dashboard token field; never put a real token in a transcript. Expected: a candidate status change and a corresponding ledger record. The dashboard now checks the target namespace's `kubeheal/mode` label and fails closed if it cannot read it. **NOT VERIFIED live:** the 2026-11-13 API/page read returned zero baseline candidates; there is no safe candidate-generation trigger, so do not approve a fabricated candidate. See `demo-evidence/F5/F5_baseline_promotion_2026-11-13.md`. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_baseline_promotion.py tests/test_dashboard_baseline.py -q`; unit/UI evidence is not a live promotion.

## F6. Executor request validation

**Time estimate:** 3 minutes. **Show:** a valid request accepted for an allowed target, then malformed, stale, mismatched-UID, protected-namespace, and incomplete requests refused before any write.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get pods -l app=executor -o wide
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,networkpolicy -o wide
```

Expected for the eventual live trigger: Executor validation outcomes show accepted/refused reasons, and the rejected cases leave workload state unchanged. **NOT VERIFIED live:** no supported live request injector is available. Do not write directly to Redis or patch a workload to fabricate an Executor request. See `demo-evidence/F6/F6_invalid_request_status_2026-11-13.md`. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_remediation_validation.py tests/test_executor_containment_v5.py -q`; this is validation-test evidence, not live Executor intake.

## F7. Conformal, D1, and rollback policy

**Time estimate:** 4 minutes. **Show:** a single-label prediction set, an ambiguous set held for a human, inclusive D1 behavior at `<=50m` CPU or `<=32Mi` memory, and a rollback that requires a fresh Security Model response.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get deployment,service | Select-String 'inference|fusion'
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
```

Expected live output must include the prediction set and policy decision for each boundary case; the rollback must cite a fresh Security response. **NOT VERIFIED live:** there is no validated scenario command for these inputs and outcomes. Do not present generic logs as proof. See `demo-evidence/F7/F7_policy_live_status_2026-11-13.md`. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_policy_rules.py tests/test_decision_policy.py -q`; label live behavior not verified.

## F8. Dashboard operations

**Time estimate:** 5 minutes with a populated incident. **Show:** incidents, approve/reject controls, admin-token kill switch, baseline candidates, containment status, ledger timeline, and SnapshotFreeze status/release. Keep the token out of screen captures and saved output.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

Open `http://127.0.0.1:8500/approvals` for incidents/actions, `http://127.0.0.1:8500/baseline-candidates` for candidates, and `http://127.0.0.1:8500/incidents/{incident_id}` for the timeline, containment details, and SnapshotFreeze card. The kill switch route is `GET/POST /api/kill-switch`; POST JSON is `{"mode":"test"}` or `{"mode":"enforce"}` with an admin bearer token. Do not put that token in a command transcript. For rehearsal, return mode to `test` immediately after any authorized toggle. Baseline approval/rejection endpoints are listed in F5. On the incident page, a held freeze displays namespace/PVC and the release form; enter a reason of at least ten characters and use `force` only when intentionally releasing an open incident. The API is `POST /api/incidents/{incident_id}/release-snapshot-freeze`. In mode `test`, expected outcome is a dry-run ledger entry and no release. The 2026-11-13 read-through returned 61 incidents and 16 pending items; the F3 incident had no held SnapshotFreeze and the baseline API had zero candidates. Page/API reads and F9's authenticated kill-switch toggle are recorded in F8/F9 evidence, but the complete interactive control set was not exercised and no screenshot was captured. Do not claim approve/reject/release effects. See `demo-evidence/F8/F8_dashboard_readthrough_2026-11-13.md`.

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

The dashboard toggle is **verified on 2026-11-13**: the authenticated API switched `test -> enforce -> test`, both changes were written to the ledger, a dead-man switch was armed, and final readback was `test`/dry-run. No remediation event was generated during the short enforce interval, so the paired test-mode zero-write versus enforce-mode applied-action comparison remains **not measured**. Test-mode dry-run evidence is recorded in F2/F3/F4. See `demo-evidence/F9/README.md` and `dashboard-toggle-demo-2026-11-13.json`. Do not claim an enforce-mode workload action from the toggle alone. Safe fallback: `.\.venv\Scripts\python.exe -m pytest tests/test_killswitch.py tests/test_dashboard_killswitch.py -q`.

## F10. Drift healing and rollback

**Time estimate:** up to 12 minutes for the existing test-mode drift walkthrough. **Show:** the drifted CPU fields, dry-run decision, and restored manifest. The full feature additionally requires canary-only drift-field patching, a rollback point, p99 measurement, and rollback after a bad p99.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action drift -ObserveSeconds 30 -ProbeSeconds 30
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
```

The script asserts mode `test`, temporarily changes only `prod/victim-app` CPU request/limit to 50m/50m, waits for a new action, and restores 100m/500m in `finally`. On 2026-11-13, live Prometheus queries returned 15/15 series; Fusion recorded a `human_patch` dry-run (confidence 0.7316), and the workload returned to request 100m/limit 500m. See `demo-evidence/F10/F10_drift_walkthrough_2026-11-13.md`. This did not apply a canary patch. **Live drift sensing and dry-run are verified; canary healing and bad-p99 rollback are not measured.** Do not claim p99 rollback without a live record.

## F11. Queue-depth HPA and Grafana

**Measured run duration:** 7m14s in the successful run; plan 8 minutes for load, baseline check, and Grafana view. **Show:** queue metric increasing under k6 load, HPA scaling, then the queue-depth and replicas panels. A post-merge repeat scaled 2 -> 8 -> 2 but had 12 connection refusals during scale-up, so do not present it as a clean load result.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\hpa_load.ps1 -Vus 32 -DurationSeconds 90 -SampleSeconds 10 -ScaleDownWaitSeconds 330
kubectl --context k3d-kubeheal -n kubeheal get hpa kubeheal-inference -o wide
kubectl --context k3d-kubeheal -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Open `http://127.0.0.1:3000` and select the KubeHeal overview dashboard. The script checks mode `test`, waits for the HPA baseline, creates a bounded k6 job plus scoped NetworkPolicy/ConfigMap, emits samples and k6 summary, and cleans only its run-owned resources in `finally`. The earlier successful run on 2026-11-12 measured 32 VUs for 90 seconds; 121,088/121,088 checks passed; median 22.86 ms, p95 38.45 ms; HPA 2 -> 7 -> 2; duration 7m14s. A post-merge repeat scaled 2 -> 8 -> 2 but had 12 connection refusals out of 99,431 checks and is not a clean load result. Dashboard panel definitions and Prometheus samples for the repeat are in [Grafana API evidence](demo-evidence/F11/grafana-hpa-api-2026-11-12.json). The Grafana image renderer is not installed, so no screenshot was captured; save a visual screenshot during rehearsal if the browser is available. The earlier script attempt failed because `Out-String -NoNewline` flattened the JS file; cleanup succeeded, and the fix is `6f97f88`. These synthetic scoring-load runs do not measure the full incident pipeline or establish a performance guarantee.

### Separate P11 evaluation status

The 2026-11-13 F11 demo-image rerun had 12 first-timestamp connection refusals out of 72,328 checks (32 VUs, 90 seconds), with observed median 37.49 ms and p95 61.87 ms on that failed run. HPA scaled 2 -> 8 -> 2 and the script cleaned its run-owned resources. No Grafana screenshot was captured because the browser surface was unavailable and the renderer is not installed. See `demo-evidence/F11/hpa-run-2026-11-13.txt`.

Do not combine F11's clean HPA run with P11 E1. **P11 E1 is not an accepted benchmark:** the two 2026-11-12 attempts and the 2026-11-13 attempt failed. The latest used 32 VUs/90s, 66,807/66,819 checks passed, with 12 first-timestamp connection refusals to `10.43.219.57:8000`. It observed median 40.01 ms and p95 71.16 ms on the failed run; latency status remains `not measured`. The same pattern occurred in F11. Current evidence is consistent with a first-second Service/data-plane race, but does not identify the refusing component. The P11 runner cleaned its Job and ConfigMap, HPA returned to baseline, and mode remained `test`. **P11 E2 was measured:** deleting one inference pod from a 2/2 baseline returned to 2 Ready replicas in 1.25 seconds. E3-E6 and V5-E1 remain not measured for the reasons in [`F13 evidence`](demo-evidence/F13/P11_live_status_2026-11-13.md) and [`P11 coverage`](results/p11/P11_COVERAGE.md).

## F12. U6 repeat acceptance

U6 passed twice on a separately created `kubeheal-rehearsal` cluster. Both `up.ps1 -Stage all -SkipImages` runs used vendored `kube-prometheus-stack` and `prometheus-adapter` archives without Helm repository DNS. Images were supplied from the local image cache, so a populated local cache remains a prerequisite. Each install was followed by the scripted drift scenario: 15/15 metric queries returned samples, Fusion recorded `human_patch` with `dry_run=true` in mode `test`, and the script restored CPU request/limit to 100m/500m. The separate cluster was then deleted as authorized. The original `k3d-kubeheal` and its PVCs remain untouched. See `demo-evidence/F12/U6_offline_rehearsal.md` and the raw transcripts alongside it.

## Evidence checklist

After each rehearsal, save raw terminal output and screenshots in `docs/kubeheal/demo-evidence/F1/` through `F13/`, with a README or report containing date, machine, cluster, exact command, result, duration, and deviations. Redact credentials, tokens, Secret data, and customer data. If a feature is not exercised successfully, mark it `not verified` or `not measured` and use the evidence fallback; do not present a unit test as live evidence. The 2026-11-13 rehearsal work used the existing cluster and did not constitute a fresh-cluster end-to-end rehearsal.

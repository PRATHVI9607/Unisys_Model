# KubeHeal k3d live demo runbook

This runbook is for the `k3d-kubeheal` context only. Never use `hybrid-demo`. Keep `kubeheal-mode` in `test` except during explicitly scripted, logged enforce windows. F3 is live-verified from Fusion onward with scripted Sense input because Falco is absent. The F3 cleanup helper selects only resources carrying its unique run label or incident IDs found in its own action stream; review its printed targets before relying on the cleanup result.

## Rehearsal status, 2026-11-13

The acceptance pass used the existing `k3d-kubeheal` cluster and preserved its PVCs. U6 was separately proven twice from fresh state on the disposable `kubeheal-rehearsal` cluster using vendored charts. A live scripted input is not a claim about model quality or an unscripted signal.

| Step | Status | Evidence / limit |
|---|---|---|
| Preflight | LIVE | Nodes, Ready pods, Helm revision 17, image tags, mode `test`, and all three protected PVCs read back. |
| F1 | FALLBACK | Full suites are the safety evidence; live-test integrations remain opt-in. |
| F2 | LIVE | D-5 replay rerun during rehearsal; model-scored Security event, Fusion/Executor dry-run, run-owned cleanup. |
| F3 | LIVE | Scripted alert through containment and restore; not live Falco sensing. |
| F4 | LIVE | Rehearsal rerun: signed accepted as dry-run, unsigned/tampered refused, run-owned Redis records cleaned. |
| F5 | LIVE | Scripted dev auto-promotion with ledger; scripted prod candidate waits for dashboard approval and promotion in a dead-man-protected window. |
| F6 | LIVE | Four signed invalid requests refused before freeze; frozen count zero; temporary label restored. |
| F7 | LIVE | Scripted M2 HUMAN gate, D1 CPU/memory inclusive edges, rollback withheld without fresh Security response and queued with one. |
| F8 | LIVE / FALLBACK | Incident, approval/rejection, baseline, kill-switch, ledger and status controls have screenshots/results. SnapshotFreeze release is FALLBACK because no held target exists. |
| F9 | LIVE / FALLBACK | Dashboard test/enforce/test and ledger changes verified with dead-man. Paired same-input dry-run versus applied-action comparison remains FALLBACK. |
| F10 | LIVE | Scripted canary patch kept after three improving windows; separate scripted prod canary rolled back on bad p99. |
| F11 | LIVE | Warmed 32-VU/90-second run passed 113,873/113,873 checks, 0 refusals, p50 24.03 ms, p95 37.9 ms; HPA 2 -> 8 -> 2 and Grafana screenshot saved. |
| F12 / U6 | LIVE | Two full offline chart installs plus scripted drift on a separate fresh cluster; original cluster/PVCs preserved. Local image cache is required. |
| F13 / P11 | LIVE / FALLBACK | E1 passed 112,327/112,327, 0 refusals, p50 24.34 ms, p95 38.19 ms; E2 recovery 1.25 s. E3-E6 and V5-E1 are not measured for documented reasons. |

The D-5 rehearsal initially exposed that F10 scratch pods shared the victim image label. The runner was tightened to exclude pods labelled `kubeheal.io/scripted=F10`; focused tests passed 9/9, and the rehearsal retry passed. Both failed initial attempts are retained in the REHEARSAL folder.

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

Open `http://127.0.0.1:8500/baseline-candidates` and `http://127.0.0.1:8500/approvals`. Approval and rejection are `POST /api/baseline-candidates/{namespace}/{deployment}/approve` and `/reject`, with JSON `{"candidate_id":"...","reason":"..."}` and an admin bearer token. Use the interactive dashboard token field; never put a real token in a transcript. The dashboard checks target namespace mode and fails closed if unreadable. **LIVE-VERIFIED with scripted, PVC-free targets:** dev config change auto-promoted and wrote its baseline ledger entry; prod config change created a candidate and the dashboard approved it in a bounded, dead-man-protected enforce window. Mode returned to `test`. This validates the promotion path, not Health Agent model quality. See `demo-evidence/F5/F5_scripted_run_2026-11-13.txt` and `README.md`.

## F6. Executor request validation

**Time estimate:** 3 minutes. **Show:** a valid request accepted for an allowed target, then malformed, stale, mismatched-UID, protected-namespace, and incomplete requests refused before any write.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get pods -l app=executor -o wide
kubectl --context k3d-kubeheal -n kubeheal logs deployment/executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,networkpolicy -o wide
```

Expected: Executor validation outcomes show accepted/refused reasons, and rejected cases leave workload state unchanged. **LIVE-VERIFIED using a run-owned signed protocol input:** four signed requests (bad namespace, protected label, unknown action, missing pod UID) were refused; each signed result verified, each reported `frozen=0`, the temporary label was restored, and owned Redis entries were removed. No freeze occurred. Security Agent refusal logs and signed result hashes are the proof; the current implementation does not append these refusals to MinIO ledger. See `demo-evidence/F6/F6_signed_invalid_run_2026-11-13.txt`.

## F7. Conformal, D1, and rollback policy

**Time estimate:** 4 minutes. **Show:** a single-label prediction set, an ambiguous set held for a human, inclusive D1 behavior at `<=50m` CPU or `<=32Mi` memory, and a rollback that requires a fresh Security Model response.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get deployment,service | Select-String 'inference|fusion'
kubectl --context k3d-kubeheal -n kubeheal logs deployment/fusion-agent --since=5m
```

Expected live output must include the prediction set and policy decision for each boundary case; the rollback must cite a fresh Security response. **LIVE-VERIFIED with scripted inputs in mode `test`:** M2 `{degraded, benign}` reached `human_pending`; D1 emitted CPU 500m to 50m and memory 320Mi to 32Mi policy cases at inclusive thresholds; rule rollback was held without a fresh Security model response and queued with one. The queued Executor action remained dry-run; no Kubernetes write occurred. See `demo-evidence/F7/F7_scripted_run_2026-11-13.txt`.

## F8. Dashboard operations

**Time estimate:** 5 minutes with a populated incident. **Show:** incidents, approve/reject controls, admin-token kill switch, baseline candidates, containment status, ledger timeline, and SnapshotFreeze status/release. Keep the token out of screen captures and saved output.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

Open `http://127.0.0.1:8500/approvals` for incidents/actions, `http://127.0.0.1:8500/baseline-candidates` for candidates, and `http://127.0.0.1:8500/incidents/{incident_id}` for the timeline, containment details, and SnapshotFreeze card. The kill switch route is `GET/POST /api/kill-switch`; POST JSON is `{"mode":"test"}` or `{"mode":"enforce"}` with an admin bearer token. Do not put that token in a command transcript. For rehearsal, return mode to `test` immediately after any authorized toggle. Baseline approval/rejection endpoints are listed in F5. The F8 walkthrough captured screenshots of incident approval/rejection, baseline approval/rejection, incident details, ledger/status views, and kill-switch test/enforce state. Scripted incident and baseline controls were exercised in test mode; approval was a dry-run and rejection resolved the items. **SnapshotFreeze release is FALLBACK:** no incident had a held freeze target, so the release control could not safely be submitted. Evidence: `demo-evidence/F8/F8_dashboard_walkthrough_2026-11-13.md` and `screenshots-2026-11-13/`.

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

The authenticated dashboard toggle is **LIVE-VERIFIED**: `test -> enforce -> test`, both changes ledgered, dead-man armed, final mode readback `test`. F8 captured screenshots of the dashboard toggle itself. F5 and F10 separately prove bounded scripted enforce actions under a dead-man; F9's exact paired same-input dry-run versus applied-action comparison remains **not measured**. See `demo-evidence/F9/README.md`, `dashboard-toggle-demo-2026-11-13.json`, and F8 screenshots.

## F10. Drift healing and rollback

**Time estimate:** up to 12 minutes for the existing test-mode drift walkthrough. **Show:** the drifted CPU fields, dry-run decision, and restored manifest. The full feature additionally requires canary-only drift-field patching, a rollback point, p99 measurement, and rollback after a bad p99.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action drift -ObserveSeconds 30 -ProbeSeconds 30
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\demo.ps1 -Action status
```

The basic script asserts mode `test`, temporarily changes only `prod/victim-app` CPU request/limit to 50m/50m, waits for a new action, and restores 100m/500m in `finally`. It verifies drift sensing and dry-run. **Canary and rollback are also LIVE-VERIFIED using scripted, PVC-free run-owned targets** in a separate bounded window: dev canary patch kept after three windows; prod scratch canary rolled back in window 1 when real p99 rose from 495.21 ms to 4,407.69 ms. The script read back restored CPU resources and mode `test`; dead-man logged start/end. See `demo-evidence/F10/README.md`, `F10_scripted_run_30de436bd53a4ceebb89b2586414bb18.txt`, and ledger metrics.

## F11. Queue-depth HPA and Grafana

**Measured run:** 32 VUs for 90 seconds; reserve about 13 minutes including scale-down and Grafana review. **Show:** queue metric increasing under k6 load, HPA scaling, then the queue-depth and replicas panels. The accepted 2026-11-13 rerun passed 113,873/113,873 checks with no refusals and scaled 2 -> 8 -> 2. Earlier failed runs remain retained but are not acceptance evidence.

```powershell
pwsh -ExecutionPolicy Bypass -File .\demo\scripts\hpa_load.ps1 -Vus 32 -DurationSeconds 90 -SampleSeconds 10 -ScaleDownWaitSeconds 330
kubectl --context k3d-kubeheal -n kubeheal get hpa kubeheal-inference -o wide
kubectl --context k3d-kubeheal -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Open `http://127.0.0.1:3000` and select the KubeHeal overview dashboard. The script checks mode `test`, waits for the HPA baseline, creates a bounded k6 job plus scoped NetworkPolicy/ConfigMap, emits samples and k6 summary, and cleans only its run-owned resources in `finally`. The accepted 2026-11-13 rerun measured 32 VUs for 90 seconds; 113,873/113,873 checks passed; median 24.03 ms, p95 37.9 ms; HPA 2 -> 8 -> 2. Five successful sequential warm-up requests are excluded from the measured stage and disclosed in the raw output. The screenshot is `demo-evidence/F11/grafana-f11-2026-11-13.png`. Earlier failed runs remain in the evidence folder and are not clean load results. These synthetic scoring-load runs do not measure the full incident pipeline or establish a performance guarantee.

### Separate P11 evaluation status

The earlier 2026-11-13 F11 run had 12 first-timestamp connection refusals out of 72,328 checks and is retained as failed evidence. The clean warmed rerun used 32 VUs for 90 seconds: 113,873/113,873 checks passed, zero request failures, median 24.03 ms, p95 37.9 ms, HPA 2 -> 8 -> 2. Readiness waited for both inference endpoints; the script waited five seconds after its scoped NetworkPolicy and k6 performed a five-second settle plus five sequential HTTP 200 warmups. These warm-ups are disclosed and excluded from the measured stage. A Grafana screenshot is saved at `demo-evidence/F11/grafana-f11-2026-11-13.png`.

Do not combine F11 with P11 E1. A P11 run with the same readiness gate, five-second settle, and five successful HTTP 200 warm-ups passed 112,327/112,327 checks at 32 VUs/90s, with zero refusals, p50 24.34 ms and p95 38.19 ms. E2 recovery remains 1.25 seconds. E3-E6 and V5-E1 are **not measured** for the specific reasons in [`F13 evidence`](demo-evidence/F13/P11_live_status_2026-11-13.md) and [`P11 coverage`](results/p11/P11_COVERAGE.md). Do not reuse failed-run latency as accepted data.

## F12. U6 repeat acceptance

U6 passed twice on a separately created `kubeheal-rehearsal` cluster. Both `up.ps1 -Stage all -SkipImages` runs used vendored `kube-prometheus-stack` and `prometheus-adapter` archives without Helm repository DNS. Images were supplied from the local image cache, so a populated local cache remains a prerequisite. Each install was followed by the scripted drift scenario: 15/15 metric queries returned samples, Fusion recorded `human_patch` with `dry_run=true` in mode `test`, and the script restored CPU request/limit to 100m/500m. The separate cluster was then deleted as authorized. The original `k3d-kubeheal` and its PVCs remain untouched. See `demo-evidence/F12/U6_offline_rehearsal.md` and the raw transcripts alongside it.

## F13. P11 coverage

E1 and E2 are live measured as listed above. **E3-E6 and V5-E1 are FALLBACK / not measured**, with concrete scenario and safety reasons in `results/p11/P11_COVERAGE.md`; the old V5-E1 runner is not context-pinned and can restart services or remove `khe-*` namespaces, so it was not run against the original cluster.

## Evidence checklist

After each rehearsal, save raw terminal output and screenshots in `docs/kubeheal/demo-evidence/F1/` through `F13/`, with a README or report containing date, machine, cluster, exact command, result, duration, and deviations. Redact credentials, tokens, Secret data, and customer data. If a feature is not exercised successfully, mark it `not verified` or `not measured` and use the evidence fallback; do not present a unit test as live evidence. The 2026-11-13 rehearsal used the existing original cluster without deleting it or its PVCs; fresh-start U6 was separately rehearsed twice on the disposable cluster.

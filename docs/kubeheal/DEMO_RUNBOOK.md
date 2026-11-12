# KubeHeal k3d live demo runbook

This runbook is for the `k3d-kubeheal` context only. It does not claim an end-to-end feature is working until its evidence folder contains a dated terminal transcript and screenshots from the rehearsed run. Never use `hybrid-demo`. Keep `kubeheal-mode` in `test` except for the bounded, scripted F3, F9, and F10 windows below; restore `test` immediately after each window.

## Common preflight

**Time:** 5 minutes. **Show:** running cluster, workloads, mode, and Helm release. **Expected:** context reachable, workloads ready, release deployed, mode `test`.

```powershell
docker ps --format "table {{.Names}}\t{{.Status}}"
kubectl --context k3d-kubeheal get nodes -o wide
kubectl --context k3d-kubeheal -n kubeheal get pods -o wide
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
helm --kube-context k3d-kubeheal list -n kubeheal
```

If any component is not ready, stop at the preflight and show the saved output in `docs/kubeheal/demo-evidence/preflight/`. Do not continue with a partially deployed cluster.

## F2. D-5 replay to Security event

**Time:** 5 minutes. **Show:** replay input, Security Agent logs, Redis stream event, then Fusion incident decision. **Expected:** the trace is associated with the live victim identity; a model-scored single-label `ransomware` event can proceed to automatic containment, while heuristic-only or uncertain evidence becomes `HUMAN`. Do not claim a live Falco capture: the fixture is hand-written.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs daemonset/kubeheal-security-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal get pods -l app.kubernetes.io/component=fusion-agent -o wide
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-fusion-agent --since=5m
```

The fixture to replay is `tests/fixtures/falco/ransomware_pv_encrypt_new_rules.jsonl`. The exact replay mount/trigger and Redis stream inspection interface are pending the F2 implementation and must be written into `docs/kubeheal/demo-evidence/F2/README.md` before rehearsal; do not improvise a live DaemonSet patch. Fallback: show the dated replay transcript, input fixture, and matching incident screenshot under `docs/kubeheal/demo-evidence/F2/`.

## F3. Alert-driven ransomware containment

**Time:** 10 minutes. **Show:** one alert through Fusion, Executor intake, freeze confirmation, forensic snapshot, quarantine, scale to zero, restore from before T0, entropy rescan Job, quarantine release, and ordered ledger entries. **Expected order:** freeze -> forensic snapshot -> quarantine -> scale to 0 -> restore -> entropy rescan -> lift quarantine -> ledger records. The live check must be launched from the alert path and use a scratch workload in `dev`.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-fusion-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,job,pvc,volumesnapshot -o wide
kubectl --context k3d-kubeheal -n kubeheal port-forward service/kubeheal-dashboard 8080:80
```

Open the dashboard ledger view at `http://127.0.0.1:8080` and filter to the incident ID. Open an enforce window only after the scratch workload, baseline, snapshot class, and cleanup steps are recorded in the dated evidence README. In a `finally` block restore test mode: `kubectl --context k3d-kubeheal -n kubeheal patch configmap kubeheal-mode --type merge -p '{"data":{"mode":"test"}}'`. Fallback: show the full event-to-ledger transcript and screenshots under `docs/kubeheal/demo-evidence/F3/`; the earlier direct freeze helper check is not an acceptable fallback for the full flow.

## F4. HMAC on Redis containment messages

**Time:** 3 minutes. **Show:** the key name in the Secret metadata only, a signed accepted request/result, and unsigned and tampered messages refused. Never reveal Secret data.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get secret
kubectl --context k3d-kubeheal -n kubeheal logs daemonset/kubeheal-security-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-executor --since=5m
```

**Expected:** requests/results carry `hmac_sha256`; signed messages are accepted; missing or invalid HMAC is refused as `invalid_hmac` before a freeze or Kubernetes write. `CONTAIN_HMAC_KEY` comes from the existing Redis Secret reference; do not print it or decode the Secret. The test fixture for unsigned and tampered messages and the safe live trigger are pending the HMAC merge/rehearsal. Fallback: dated focused-test transcript and redacted log screenshots in `docs/kubeheal/demo-evidence/F4/`.

## F5. Baseline promotion

**Time:** 4 minutes. **Show:** a dev/staging promotion and ledger entry, then a prod candidate in the dashboard and approval producing a ledger entry.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-health-agent --since=5m
```

Open `http://127.0.0.1:8500/baseline-candidates` and `http://127.0.0.1:8500/approvals`; show the dev/staging promotion, prod candidate, approver identity, resulting baseline revision, and ledger record. The admin API is `POST /api/baseline-candidates/{namespace}/{deployment}/approve` with `Authorization: Bearer <admin-token>` and JSON `{"candidate_id":"...","reason":"..."}`. Use the UI for the demo and do not put the token in a command transcript. **Expected:** automatic promotion only for eligible dev/staging cases; prod waits for dashboard approval. Fallback: dated before/after candidate screenshots and corresponding ledger transcript in `docs/kubeheal/demo-evidence/F5/`.

## F6. Executor request validation

**Time:** 3 minutes. **Show:** valid request accepted for an allowed target, followed by malformed, stale, mismatched-UID, protected-namespace, and incomplete requests rejected before writes.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-executor --since=5m
kubectl --context k3d-kubeheal -n dev get deployment,pod,networkpolicy -o wide
```

**Expected:** invalid requests leave the Kubernetes object listing unchanged and produce refusal/escalation records. Fallback: dated validation-test transcript and before/after listings in `docs/kubeheal/demo-evidence/F6/`.

## F7. Conformal, D1, and rollback policy

**Time:** 4 minutes. **Show:** a one-label prediction set, an ambiguous set held for a human, an inclusive 10x cut at 50m CPU or 32Mi memory, then a rollback that proceeds only with a fresh Security Model response below the policy threshold.

```powershell
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-inference --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-fusion-agent --since=5m
```

**Expected:** no automatic action for empty or multi-label sets; 500m to 50m is eligible for D1; missing or stale Security response sends rollback to `HUMAN`. Fallback: dated policy and live-response transcript in `docs/kubeheal/demo-evidence/F7/`.

## F8. Dashboard operations

**Time:** 5 minutes. **Show:** incidents, approve/reject, admin-token kill-switch toggle, baseline approval, containment status, ledger view, and SnapshotFreeze release. Keep the token out of screen capture and saved output.

```powershell
kubectl --context k3d-kubeheal -n kubeheal port-forward svc/kubeheal-dashboard 8500:5000
```

Open `http://127.0.0.1:8500/approvals` for incidents, approve/reject, kill switch, and ledger links. Use `/baseline-candidates` for prod promotions and `/incidents/{incident_id}` for the timeline. SnapshotFreeze release is `POST /api/incidents/{incident_id}/release-snapshot-freeze` with a JSON reason of at least ten characters; add `force:true` for an open incident. The UI/API uses the dashboard admin token; inject it only into the interactive session. Toggle back to `test` before closing the window, then verify:

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
```

**Expected:** each control reflects its resulting state and the ledger contains the associated operator action. Fallback: redacted screenshots and API transcript in `docs/kubeheal/demo-evidence/F8/`.

## F9. Kill switch end to end

**Time:** 4 minutes. **Show:** in test, Sense/Score/Decide/Record produce a "would have" ledger action and no Kubernetes change; in enforce, the same bounded scratch action occurs.

```powershell
kubectl --context k3d-kubeheal -n kubeheal get configmap kubeheal-mode -o jsonpath='{.data.mode}'
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-fusion-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-executor --since=5m
```

For enforce, use only the scripted scratch scenario and restore `test` immediately in its cleanup path. **Expected:** test produces no Kubernetes writes; enforce produces the accepted action and ledger entries. Fallback: mode, object-before/after, and ledger transcript under `docs/kubeheal/demo-evidence/F9/`.

## F10. Drift healing and rollback

**Time:** 6 minutes. **Show:** drifted fields, the canary patch touching only those fields, rollback point, observed p99, and rollback after a bad p99 result.

```powershell
kubectl --context k3d-kubeheal -n prod get deployment victim-app -o yaml
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-health-agent --since=5m
kubectl --context k3d-kubeheal -n kubeheal logs deployment/kubeheal-executor --since=5m
```

**Expected:** unchanged fields remain byte-for-byte equivalent in the rendered spec; the ledger records the rollback point before patching and rollback after failed verification. Use a bounded canary and restore the demo baseline. Fallback: dated manifests, p99 query output, and ledger transcript in `docs/kubeheal/demo-evidence/F10/`.

## F11. Queue-depth HPA and Grafana

**Time:** 15 minutes. **Show:** queue depth rising during k6 traffic, HPA desired replicas increasing, then returning toward baseline after load stops; show the Grafana dashboard panels for queue depth and replicas.

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\demo\scripts\hpa_load.ps1 -Vus 32 -DurationSeconds 90
kubectl --context k3d-kubeheal -n kubeheal get hpa kubeheal-inference -o wide
kubectl --context k3d-kubeheal -n monitoring port-forward svc/monitoring-grafana 3000:80
```

Open Grafana at `http://127.0.0.1:3000` and select the KubeHeal overview dashboard. The script checks mode `test`, waits for the HPA baseline, creates a bounded k6 job and scoped policy, prints the HPA values and k6 summary, and removes its temporary resources in `finally`. **Expected:** HPA metrics are numeric and replicas change under load; do not state a scale latency or throughput unless measured in the run. The 2026-11-12 attempt failed because `Out-String -NoNewline` flattened the JS file and k6 reported no exported functions. The cleanup removed the temporary Job, ConfigMap, and NetworkPolicy. The file-staging fix is committed as `6f97f88`; this attempt is a failed diagnostic, not F11 evidence. Re-run after the fix and save new output. Fallback: prior failure output plus new k6 output, HPA snapshots, and Grafana screenshots in `docs/kubeheal/demo-evidence/F11/`.

## Evidence checklist

After each rehearsal, save raw terminal output and screenshots in `docs/kubeheal/demo-evidence/F2/` through `F11/`, with a README containing date, machine, cluster, exact command, result, duration, and deviations. Redact credentials, tokens, Secret data, and customer data. If a feature is not exercised successfully, mark it `not verified` and use the evidence fallback; do not present a unit test as live evidence.

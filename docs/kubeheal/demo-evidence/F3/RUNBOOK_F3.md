## F3. Alert-driven ransomware containment (live, scratch Deployment)

Replace the current F3 section of `docs/kubeheal/DEMO_RUNBOOK.md` with this text. Evidence: `docs/kubeheal/demo-evidence/F3/`.

**Planned time (estimate):** 5 minutes including preparation and the rehearsal. Measured once: prep plus rehearse took about 13 seconds and the enforce window 45 seconds (see below). **Show:** one scripted alert through Fusion and the stream into the Executor, then freeze, forensic snapshot, quarantine, scale to 0, restore from the snapshot taken before T0, entropy rescan Job, quarantine lifted, and the ordered ledger entries. **Expected order:** freeze -> forensic snapshot -> quarantine -> scale to 0 -> restore -> entropy rescan -> lift quarantine -> `restored`.

### What is real and what is scripted

Say this out loud in the demo. It is the honest scope of the claim.

- **Scripted:** the alert. Falco is not installed on this k3d cluster, and the Security Agent's /proc-only path cannot produce a model score (no syscall window), so no non-replay alert exists here. Replay events are forced to dry run by design and are never used to enforce. `f3_window.py` therefore publishes ONE Security event on `kubeheal.security.events` with `syscall_source=scripted_window`. Its model fields (label `ransomware`, risk 0.9500, one-label set, top factors, model `security-5.0.0-c6fa12d8`) are copied from the event the real Security Agent published for the hand-written D-5 fixture scored by the real inference service. Identity, timestamps and T0 are the scratch pod's. The Sense stage is therefore not exercised by F3; F2 covers replay through Security and Fusion.
- **Real:** everything from Fusion onward (the HMAC signature on the freeze request is in the stream entry itself, `88_hmac_requests_and_breaker.txt`): the decision (`auto_contain`), `kubeheal.exec`, Executor intake and validation, the HMAC-signed freeze request to the node-local Security Agent and its signed answer, every Kubernetes write through the kill-switch gate, the Jobs, PVCs and snapshots, and the ledger.
- **Scripted setup:** the rolling snapshot before T0 is created by the script with the manifest the Executor's scheduler uses (`volume_snapshot`), because the scheduler only writes in `enforce`.
- **Namespace:** the scratch Deployment is in `staging`, not `dev`. The dev tier multiplier (0.70) cannot reach the 0.85 automatic containment threshold with a 0.95 risk; staging (1.00) can.

### Preflight (estimate: 1 minute)

0. Containment circuit breaker: a real (non dry-run) automatic containment in a namespace is limited to 3 per hour (`CB_CONTAIN_LIMIT_PER_HOUR`, per namespace). The three windows of 2026-11-12 used the staging allowance (`88_hmac_requests_and_breaker.txt`); a fourth staging window before 15:01:33Z on that day would have been human-gated, not automatic. Check `kubectl --context k3d-kubeheal -n kubeheal exec redis-0 -- redis-cli ZRANGE kubeheal:cbw:contain:staging 0 -1 WITHSCORES` before a window; rehearsals in `test` do not count.
1. Check that nobody else is using the cluster; if someone is, wait. Note your use in a local, untracked note and remove it afterwards.
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
.venv\Scripts\python.exe docs/kubeheal/demo-evidence/F3/f3_window.py cleanup    # staging only; run with the same F3_NAME
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

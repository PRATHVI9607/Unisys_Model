# KubeHeal acceptance handoff, 2026-11-13

## State

- Nothing pushed; `ALLOW_PUSH` was not set. No training or `PROJECT_SPEC.md` changes.
- `work` is already an ancestor of `demo`. At the start of this checkpoint, `work` was `32101ab`; see `git log` for the current documentation head.
- Full test suites passed sequentially with separate temp directories: `work` 2,166 passed, 11 skipped in 94.20s; `demo` 2,166 passed, 11 skipped in 79.92s.
- Only context permitted is `k3d-kubeheal`. Latest cluster read: mode `test`, Helm revision 17, images `b20261113071011`, inference `/readyz` HTTP 200 with both shipped bundles loaded, workloads Ready, HPA 2/2, MinIO/Redis/prod victim PVCs Bound.
- U6 and the fresh-cluster rehearsal are incomplete. Two `up.ps1 -Stage all -SkipImages` attempts failed at Helm repo DNS (`prometheus-community.github.io`); local install/adapter/victim stages and the reversible reset succeeded. Do not run `down.ps1` without owner approval; it deletes PVCs.
- Verified MinIO and Redis backups are outside the repo at `C:\My_projects_1\cLOUD\KubeHeal-PreClean-20261113-1430`: MinIO versioning enabled, 1,117 object versions copied with no delete markers and no size mismatches; Redis RDB transfer is 124,041 bytes and SHA-256 matches the in-pod file, with a separate copy of the Redis persistence directory.

## Feature status

| Feature | Current status |
|---|---|
| F1 safety | Full default suites pass; live tests remain opt-in. |
| F2 replay | LIVE on demo images: model-scored Security event and Fusion/Executor dry-run. Not a live Falco capture. |
| F3 containment | LIVE on k3d scratch workload; scripted alert, 38-second enforce window, 5 restored files scanned, 0 high-entropy. Not real-node/Falco verification. |
| F4 HMAC | LIVE in test mode: signed accepted; unsigned/tampered refused; owned request/result keys cleaned. |
| F5 baseline | Not measured live: no baseline candidate. |
| F6 request validation | Not measured live: no supported live request injector; no Redis event fabricated. |
| F7 M2/D1/rollback | Not measured live: no validated controlled input path. |
| F8 dashboard | API/pages returned 200; 61 incidents, 16 pending, no baseline candidate, no held F3 freeze. Full controls and screenshots unavailable. |
| F9 kill switch | Authenticated dashboard toggle recorded `test -> enforce -> test`; no remediation ran during enforce, so paired applied-action proof is absent. |
| F10 drift | Live sensing and test-mode `human_patch` dry-run; restored request 100m/limit 500m. Canary heal/bad-p99 rollback not measured. |
| F11 HPA/Grafana | Prior clean run remains measured (32 VUs/90s, 121,088/121,088, median 22.86 ms, p95 38.45 ms, HPA 2 -> 7 -> 2). Latest rerun failed with 12 first-timestamp refusals out of 72,328 checks; no screenshot. |
| F12 U6 | Incomplete; two full all-stage starts failed at chart repository DNS. No data removed. |
| F13 P11 | E1 not accepted: latest 66,807/66,819 checks, 12 first-timestamp refusals; refusing component unknown. E2 measured 1.25s one-pod recovery. E3-E6/V5-E1 not measured with reasons. |

Evidence is under the relevant `docs/kubeheal/demo-evidence/F*` directories, `docs/kubeheal/demo-evidence/REHEARSAL`, and `docs/kubeheal/results/p11/P11_COVERAGE.md`. Do not present failed-run latency as accepted benchmark data or scripted F3 input as live sensing.

## Remaining work

1. If owner approves PVC deletion, run the backed-up fresh-cluster rehearsal from `DEMO_RUNBOOK.md`, rebuild from `demo` if necessary, and restore/verify mode `test`. Otherwise preserve PVCs and leave the fresh-start step marked FALLBACK.
2. Resolve the Helm repo DNS issue before retrying the full `up.ps1 -Stage all`; do not hide the failure by claiming separate local stages are a full U6 pass. Complete two `up + scenario + reset` runs if the full stage becomes available.
3. Improve or diagnose the inference Service's first-second refusal before claiming a clean F11 or accepted P11 E1. Keep all failed attempt raw files.
4. Capture dashboard and Grafana screenshots when browser access or a renderer is available. Do not fabricate a screenshot from API JSON.
5. Keep F5-F8, F10 rollback, P11 E3-E6/V5-E1 as `not measured` until a safe, controlled live scenario exists.
6. Finish docs and push prep on `demo`: README, AGENTS, PROGRESS, this handoff, `PUSH_PLAN.md`, full diff/secret scan versus `origin/main`, final suites, mode `test`, lock released. Commit each task. `work` already precedes `demo`; merge only if its ancestry changes.

Never push, never set `ALLOW_PUSH`, never train, never edit `PROJECT_SPEC.md`, and never delete PVC data without explicit owner approval. Preserve `.ai/handoff.md` as the concise current state.

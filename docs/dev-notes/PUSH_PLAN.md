# Push plan (owner-only, do not push)

**Prepared:** 2026-11-13. **Status:** READY TO PUSH, pending owner review/approval. Nothing was pushed; `ALLOW_PUSH` was not set. No training or `PROJECT_SPEC.md` edits were made. The owner performs any eventual push.

## Branches and verification

- `origin/main` fetched at `48a59aa7195ea14f8366a4338293f095c8803daf`.
- `work` full suite: **2,169 passed, 11 skipped in 82.92s**.
- `demo` full suite after merging `work`: **2,178 passed, 11 skipped in 89.30s**.
- `work` is an ancestor of `demo`. Full suites used Python 3.11 and separate temporary directories.
- Original `k3d-kubeheal`: all three nodes Ready; workload pods Ready (MinIO bootstrap Job Completed); Helm revision 17 deployed; demo image tag `b20261113071011`; inference `/readyz` HTTP 200 with health/security bundles; HPA 2 replicas; Redis, MinIO, and prod victim PVCs Bound; mode `test`.
- U6 passed twice on a separate fresh `kubeheal-rehearsal` cluster using vendored `kube-prometheus-stack` and `prometheus-adapter` charts, no Helm repository DNS, and locally cached images. The separate cluster was deleted after both runs. Original cluster and PVCs were preserved.
- Final runbook rehearsal is recorded in `docs/kubeheal/demo-evidence/REHEARSAL/rehearsal-2026-11-13.md`. Original cluster remained in test mode; no original cluster/PVC deletion occurred.

## Feature readiness

| Feature | Status | Evidence / limit |
|---|---|---|
| F1 safety | PASS | Full default suites pass; live integrations remain opt-in. |
| F2 replay | LIVE | Model-scored replay event and Fusion/Executor dry-run. Hand-written replay, not live Falco capture. |
| F3 containment | LIVE | Scripted Sense alert through freeze, snapshot, quarantine, restore, entropy rescan and ledger; 5 files scanned, 0 high entropy in the accepted run. Not live Falco sensing or real-node validation. |
| F4 HMAC | LIVE | Signed accepted in test mode; unsigned/tampered refused; run-owned records cleaned. |
| F5 baseline promotion | LIVE | Scripted PVC-free dev auto-promotion with ledger, plus prod dashboard approval in logged dead-man-protected enforce window. Does not establish model quality. |
| F6 request validation | LIVE | Four signed invalid requests refused, response HMACs valid, frozen count zero, namespace label restored. Refusal logs/results are proof; the current implementation does not append these refusals to MinIO ledger. |
| F7 policy gates | LIVE | Scripted M2 HUMAN, D1 inclusive CPU/memory boundaries, and rule rollback held without fresh Security response then queued with one. Executor request remained dry-run. |
| F8 dashboard | PARTIAL | Screenshots and UI results cover the walkthrough. SnapshotFreeze release is not measured because no held target existed. |
| F9 kill switch | PARTIAL | Authenticated dashboard test/enforce/test and ledger verified with dead-man. Same-input paired applied-action comparison is not measured. |
| F10 drift | LIVE | Scripted dev canary patch kept after three windows; prod canary rolled back on bad p99 from 495.21 ms to 4,407.69 ms. Mode/test and resource restoration verified. |
| F11 HPA/Grafana | LIVE | 32 VUs/90 s, 113,873/113,873 checks, 0 refusals, p50 24.03 ms, p95 37.9 ms, HPA 2 -> 8 -> 2; five-call warm-up disclosed and included in F11 aggregate count; screenshot saved. |
| F12 U6 | LIVE | Two fresh-cluster offline installs and scripted drift runs on the separate rehearsal cluster. Local image cache is required. |
| F13 P11 | PARTIAL | E1: 112,327/112,327, 0 refusals, p50 24.34 ms, p95 38.19 ms. E2 recovery 1.25 s. E3-E6 and V5-E1 are not measured with concrete reasons in `docs/kubeheal/results/p11/P11_COVERAGE.md`. |

## Diff and secret review

The high-confidence diff scan found zero AWS access keys, GitHub/Slack tokens, private-key headers, or URL credentials. The broader credential-assignment scan produced 13 candidates across demo configuration, environment/Secret references, scripted dashboard helpers, docs, an existing model source, and a test fixture. The fixture candidate is a nonfunctional test placeholder; no credential value is reported. `gitleaks` is not installed in this environment. Re-run the secret scan after any later change.

The targeted `git diff --check` on README, AGENTS, docs/dev-notes/PUSH_PLAN.md, docs/dev-notes/NEXT_FOR_CODEX.md, DEMO_RUNBOOK, PROGRESS, the final rehearsal report, and the updated F5-F7 status notes passed. The full `git diff --check origin/main` reports 1,803 findings across the large base-to-head diff, including captured terminal output and pre-existing whitespace in other changed files. Per instruction, captured output was left unchanged; the new source/docs in this acceptance pass were checked separately. Review the full output before pushing if whitespace normalization is required.

## Remaining limits for owner review

1. F3 used scripted Sense input because Falco is absent; this is not live detection or real-node validation.
2. F8 SnapshotFreeze release and F9 same-input paired enforcement comparison remain not measured.
3. P11 E3-E6 and V5-E1 remain not measured with reasons documented.
4. U6 requires local images to be available; the chart setup itself is network-free.
5. No original cluster or PVC was deleted. Do not run cluster teardown as part of push preparation.

## Final owner checklist

1. Review the final `work` and `demo` diffs and this feature table.
2. Confirm mode `test`, Helm revision/tag/readiness, and that `docs/kubeheal/CLUSTER_LOCK.md` has been released.
3. Confirm the repository is clean and no secret scan finding is unresolved.
4. Push only from the owner's environment and approval. This agent did not push and will not set `ALLOW_PUSH`.

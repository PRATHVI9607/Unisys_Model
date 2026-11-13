# Push plan (owner-only, do not push)

**Prepared:** 2026-11-13. **Decision:** NOT READY TO PUSH. Nothing was pushed and `ALLOW_PUSH` was not set. No training or `PROJECT_SPEC.md` changes were made.

Current local `work` head is **32101ab**; `demo` contains this final push-prep documentation and includes `work`. `origin/main` is locally `48a59aa`. No push was attempted.

## Change summary versus `origin/main`

1. Uses the shipped LightGBM Health and Security bundles with split-conformal prediction sets and TreeSHAP factors.
2. Requires an exactly one-label conformal set and other gates before automatic actions; D1's 10x threshold is inclusive.
3. Uses deterministic Fusion correlation and a replay path for Security events.
4. Defaults to fail-closed test mode, records would-have actions, and gates Kubernetes writes.
5. Restricts remediation writes to the Executor and validates requests before writes.
6. Authenticates containment requests/results and operator thaw messages with the dedicated HMAC Secret.
7. Provides baseline candidates, dashboard approval, incident operations, and append-only MinIO ledger records.
8. Provides freeze, snapshots, quarantine, scale-to-zero, restore, entropy rescan, and quarantine release.
9. Adds the dashboard, queue-depth HPA, Grafana panel definitions, and k3d deployment assets.
10. Adds safety tests, replay/load scripts, P11 evaluation scaffolding, runbook documentation, and evidence.

## Verification

- Full suites passed: work **2,166 passed, 11 skipped, 94.20s**; demo **2,166 passed, 11 skipped, 79.92s**. Suites were sequential and used isolated temp directories.
- Latest k3d read: mode `test`; Helm revision 17; demo image tag `b20261113071011`; inference `/readyz` HTTP 200 with both bundles loaded; KubeHeal/monitoring/victim pods Ready; HPA 2/2; Redis, MinIO, and prod victim PVCs Bound.
- F3's 2026-11-13 scripted-alert containment completed in staging with a 38-second enforce window, five restored files scanned, and zero high-entropy files. Falco sensing and real-node behavior are not verified.
- F4 test-mode HMAC smoke accepted signed and refused unsigned/tampered messages. F9 authenticated mode toggle wrote `test -> enforce -> test` ledger entries; no enforce-mode remediation action occurred. F10 verified live drift sensing and a `human_patch` dry-run; canary healing and p99 rollback remain unmeasured.
- F5 candidate promotion, F6 live invalid-request intake, F7 live policy boundaries/rollback, and F8 complete interactive controls are not fully live-verified. F11's 2026-11-13 run had 12 first-timestamp refusals out of 72,328 checks; its observed 37.49 ms median and 61.87 ms p95 are from a failed run. No Grafana screenshot was captured.
- U6 did not pass twice: both full `up.ps1 -Stage all` attempts failed at chart-repository DNS. P11 E1 is not accepted (latest: 66,807/66,819 checks, 12 initial refusals); E2 measured 1.25 seconds to recover one deleted inference pod; E3-E6 and V5-E1 are not measured.
- A full fresh-cluster rehearsal is not complete. Two verified data backups are outside the repo at `C:\My_projects_1\cLOUD\KubeHeal-PreClean-20261113-1430`; running `down.ps1` still requires owner approval because it deletes PVCs.

## Diff and secret review

The diff from `origin/main` currently contains 416 paths. The final added-line scan covered 228,086 lines on `work` and 229,268 on `demo`. Each found one high-risk credential-assignment pattern: a 21-character test placeholder in `tests/test_dashboard_seed.py` containing the word `test`; no credential value was printed. No AWS, GitHub, Slack token, private-key, or URL-credential pattern was found. Re-run the scan after any later change.

`git diff --check origin/main...work` reports 97 findings and `git diff --check origin/main...demo` reports 131 findings, chiefly captured terminal whitespace, CSI comment trailing spaces, and blank lines at EOF. These checks are not clean. Do not remove whitespace from raw run transcripts if doing so changes the recorded output.

## Before the owner pushes

1. Obtain approval before deleting/recreating the cluster; complete the fresh-start rehearsal only after that approval.
2. Resolve the Helm repository DNS failure and complete two full U6 runs, or leave U6 explicitly incomplete.
3. Capture browser/Grafana screenshots when available; do not claim screenshots from API output.
4. Keep F5-F8, F10 rollback, P11 E1 accepted load, E3-E6, and V5-E1 marked not measured until valid live evidence exists.
5. Re-run full suites after any code merge, repeat diff and secret scans, confirm test mode and released lock, and review the final diff.

Do not add `git push` to this plan. The owner performs any eventual push outside this agent session. Never push or set `ALLOW_PUSH` here.

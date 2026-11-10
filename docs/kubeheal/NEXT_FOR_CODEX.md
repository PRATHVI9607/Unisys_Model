# KubeHeal continuation notes (2026-11-11)

Read `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`, the Task checklist in `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md` before continuing. This is navigation; `PROGRESS.md` is the detailed task record.

## Current state

- Repository: `C:\My_projects_1\cLOUD\Unisys_Model`, branch `work`.
- Last committed code: `3690c9f feat(P6): publish Falco attack onset timestamp`.
- REV-3 fixes are ready locally; no P6 worktree is modified.
- P6 was reviewed and merged from `wave/P6` to `work` as `391b8ac`. No push occurred.
- Do not use Kubernetes or touch `hybrid-demo`; cluster tasks remain with Claude. Do not train models; P12-H is not approved.

## Work completed in this continuation

- P10-V1 (`68018bc`): demo victim app emits `http_requests_total` and `http_request_duration_seconds`; manifests, ServiceMonitor and unit tests. No cluster or image build.
- P5-Q1, P9-G1 and P10-U5 (`3c80df4`): Health Agent HTTP metric contract docs, Grafana model-inflight panel, demo README/run order.
- P8-D5 (`b7436e3`): approval claim startup reconciliation, 600-second chosen/tunable TTL, admin claim release with ledger audit. Focused tests passed; no Redis integration check.
- P6 review/merge (`391b8ac`): 24 files, no conflicts. Focused P6 suite: 273 passed, 1 skipped, 1 failed due to missing `shap==0.44.0` in global Python 3.13. Broad non-cluster suite excluding inaccessible Helm test: 610 passed, 3 skipped, 17 failed due to missing dependencies/Python 3.11 environment. Full suite is not green in this shell.
- P6-D2 partial (`b9238b7`): Security Agent consumes OBSERVE sampling requests; Health Agent remains event-driven.
- P6-D7 (`3690c9f`): Security Agent derives `t0_ms` from earliest valid Falco source timestamp, never publish time. Focused tests: 110 passed, 2 Windows skips. No live Falco or cluster check.
- REV-3: ModeWatcher warns once when namespace labels/watch fail and remains fail-closed; Fusion watcher-start fallback has a test; first-sight baseline behavior is documented. The graph contract is camelCase: training records use camelCase, and the live Health Agent uses `ApiClient.sanitize_for_serialization`; no generic key rewriting is appropriate. Focused tests: 76 passed, 1 skipped.

## Open decisions and next work

- The inactive `.git/hooks/pre-push` remains untouched; `.githooks/pre-push` is configured. The owner updated `.claude/settings.json`; do not revise those rules.
- P6-D2 recommendation: add bounded periodic Health scoring while the existing workload OBSERVE key is active, using the same 60x15 metric pipeline and expiring request. Do not alter input shape or extend the TTL on each sample. Await owner direction before implementing.
- P6-D6 SHAP helper exists, but serving is not wired to a real KernelExplainer. A valid background-data source is not identified; do not invent one.
- Continue eligible non-cluster work in checklist order, starting with P7-RR-9 (Executor restore entropy verdict). Keep P7-RR-7 and P10/P11 cluster verification with Claude. P7-RR-10/11 need review before editing.
- Exact P6 review/test findings and task status are recorded under the P6 section in `docs/kubeheal/PROGRESS.md`.

Never push, never set `ALLOW_PUSH`, never run destructive Git commands, and never claim the full suite is green based on the current environment.

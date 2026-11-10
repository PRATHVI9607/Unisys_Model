# Handoff

- **Agent:** Codex
- **Date:** 2026-11-11
- **Branch:** `work`; latest commit before current P6-D7 changes `b9238b7 feat(P6): honor observe sampling in security agent`.
- **Goal:** Continue KubeHeal per `docs/kubeheal/IMPLEMENTATION_PLAN.md`; never push or set `ALLOW_PUSH`.
- **Current worktree:** P6-D7 source-timestamp integration and refreshed progress/handoff notes are uncommitted. User authorized review/merge and related commits. No merge is in progress.

## Completed

- P10-V1 committed as `68018bc`: victim app, Prometheus counter/histogram, Kubernetes manifests, ServiceMonitor, 3 tests passed; no cluster use.
- P5-Q1, P9-G1 and P10-U5 committed as `3c80df4`: victim app HTTP metric contract in Health Agent docs/query metadata, Grafana model-inflight panel, and demo run guide. Focused set passed 20 tests across Health window, Grafana and victim app.
- P6 reviewed and merged from `wave/P6` at `7f95f6c` as `391b8ac`, no merge conflicts. The branch base was `218029c`; 24 files changed in the diff. Git's external-worktree ownership protection prevented `git -C` status/log, so review used local branch refs. Focused P6 suite: 273 passed, 1 skipped, 1 failed because `shap` is missing from global Python 3.13 (the helper's documented fallback ran). Broad suite excluding inaccessible Helm test: 610 passed, 3 skipped, 17 failed, primarily unavailable `torch_geometric`, `shap` and Python 3.11 model-server environment. The full suite is not green in this shell.
- P8-D5 implementation is complete locally. Claim TTL is 600 s by chosen default, tunable with `KUBEHEAL_APPROVAL_CLAIM_TTL_S`; startup reconciliation checks ledger and exact exec stream record; admin-only release endpoint appends `claim_released` with actor before deleting the claim. Dashboard approvals, kill-switch, incident and no-writes tests: 78 passed. No Redis integration check.
- P6-D2 partial: Security Agent now queries the bounded OBSERVE key before each subsequent entropy sample and scales the interval. Entropy/Falco/Fusion sampling tests: 78 passed, 2 Windows skips. Health Agent has no periodic observation loop; this task remains open until its sampling schedule is designed safely.

## Files changed since the last commit

- P6-D7 implemented locally: normalized Falco events retain source time (Falco `evt.time` nanoseconds are converted to UTC if top-level time is absent); Security Agent emits `t0_ms` from the earliest valid trigger-window `ts`. It never substitutes publish time. Focused Falco, entropy and Fusion restore/reliability tests: 110 passed, 2 Windows skips. No cluster/live Falco check.

- `dashboard/admin_routes.py`: short/tunable TTL, claim enumeration and exact stream lookup, startup reconciliation helper, admin release endpoint.
- `dashboard/fastapi_app.py`: startup invokes reconciliation after dashboard services initialize.
- `tests/test_dashboard_approvals.py`, `tests/test_dashboard_seed.py`: TTL, recovery, release/auth/audit coverage and service fakes.
- `agents/security_agent/agent.py`, `agents/security_agent/entropy_sampler.py`, `tests/test_sense_entropy_sampler.py`, `tests/test_sense_falco_replay.py`: Security side of factor-3 OBSERVE sampling.
- `agents/security_agent/falco_client.py`, `agents/security_agent/syscall_window.py`, `tests/test_sense_falco_replay.py`: source timestamp preservation and T0 publication.
- `docs/kubeheal/PROGRESS.md`: P6 review/test outcomes, P8-D5 completion, remaining task states.
- `docs/kubeheal/NEXT_FOR_CODEX.md`: concise current status and navigation for Claude.
- `.ai/handoff.md`: this handoff.

## Open issues and next step

- P6-D2 remains incomplete: Security Agent consumes the request, but Health Agent has no periodic observation loop. Its sampling schedule needs a safe design.
- P6-D6 remains incomplete: the real metric KernelExplainer is not wired into serving/Fusion; the helper falls back to channel deviation unless injected.
- P8-D5 is committed in `b7436e3`; Security half of P6-D2 is committed in `b9238b7`. Run `git diff --check`, commit P6-D7, then continue eligible non-cluster follow-ups. P6-D2 still needs a Health Agent schedule; P6-D6 still needs actual KernelExplainer wiring. Keep cluster work with Claude; do not train models (P12-H unapproved).
- No Kubernetes cluster, Redis service, or model training was used. Never touch `hybrid-demo`.

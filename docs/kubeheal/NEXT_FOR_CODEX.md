# KubeHeal continuation notes (2026-11-11)

Read `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`, the Task checklist in `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md` before continuing. This file is a short navigation note; `PROGRESS.md` is the detailed task record.

## Current repository state

- Root: `C:\My_projects_1\cLOUD\Unisys_Model`; branch `work`.
- Latest commit: `b7436e3 feat(P8): reconcile approval claims on startup`.
- Earlier continuation commit: `3c80df4 docs: record KubeHeal continuation and P6 review`; P10-V1 is `68018bc`.
- P6 branch `wave/P6` (base `218029c`, five commits through `7f95f6c`) was reviewed through the local branch ref and merged without conflicts as `391b8ac`. Git ownership policy blocked direct inspection of the external P6 worktree from this sandbox. No push occurred.
- P8-D5 is committed as `b7436e3`.
- Cluster `k3d-kubeheal` belongs to Claude. Do not use Kubernetes, touch `hybrid-demo`, or run cluster tasks. Do not train models; P12-H needs the owner's explicit approval.

## Completed in this continuation

- P10-V1: committed victim app, Prometheus counter/histogram, manifests, ServiceMonitor and tests (`68018bc`). No image build or cluster verification.
- P5-Q1: aligned Health Agent HTTP PromQL documentation and contract to the victim app; no query columns changed.
- P9-G1: added `kubeheal_model_inflight_requests` Grafana panel.
- P10-U5: added `demo/README.md` with run order and honest limitations; demo scripts are still absent.
- P6: reviewed and merged. P6-D1, D3, D4, D5 and R1 passed focused tests; D2/D6/D7 remain partial/open. Exact findings and test results are in `PROGRESS.md` under P6.
- P6-D2 partial: Security Agent consumes the bounded OBSERVE key before each next entropy sample; focused entropy/Falco/Fusion sampling tests passed (78, 2 platform skips). Health Agent has no periodic sampling loop, so task remains open.
- P8-D5: 600-second chosen approval claim TTL (override `KUBEHEAL_APPROVAL_CLAIM_TTL_S`), startup reconciliation by exact exec-stream ID and admin-only claim release with `claim_released` ledger record. Focused dashboard tests: 78 passed. No real Redis check.

## P6 review findings and test limits

- P6-D2: Fusion writes the factor-3 sampling request, but Health and Security Agents do not consume it. Health sensing is event-driven, so the polling/scheduling design remains open.
- P6-D6: interpretation client and KernelExplainer helper exist; a live KernelExplainer is not wired. Fusion has no model/background inputs for it; helper falls back to channel deviation without an injected explainer.
- P6-D7: Fusion gates restore on `t0_ms`, workload kind, context and protected-namespace state. Security Agent does not publish earliest suspicious Falco `ts` as `t0_ms`; no live restore is reachable yet. Do not substitute event publish time.
- Focused P6 tests: 273 passed, 1 skipped, 1 failed because this Python 3.13 environment lacks required `shap==0.44.0`; the documented fallback was observed.
- Broad non-cluster tests excluding the Helm test: 610 passed, 3 skipped, 17 failed. Failures involve missing `torch_geometric`, `shap`, and Health Model server imports/checkpoint tests tied to the unavailable Python 3.11 venv. The Helm test could not collect because Windows denied access to the installed Helm executable. Do not report the full suite as green.
- No real Redis verification or cluster verification was run.

## Next work

1. Commit the tested Security half of P6-D2 and its progress/handoff update.
2. Continue the non-cluster P6 follow-ups or P7 review fixes in checklist order if they are not on the Claude-only list. Do not start cluster tasks.
3. Remaining Claude-owned cluster work: P10-U1..U4, U6..U7, P10-V2/V3, P11 and P7-RR-7. P12-H training is not approved.

Never push, never set `ALLOW_PUSH`, never run destructive Git commands. No invented metrics or results.

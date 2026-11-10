# KubeHeal continuation notes (2026-11-11)

Read `AGENTS.md`, `docs/kubeheal/PROJECT_SPEC.md`, `docs/kubeheal/IMPLEMENTATION_PLAN.md`, the Task checklist in `docs/kubeheal/PROGRESS.md`, and `.ai/handoff.md` before continuing. The checklist is the detailed task record; this file is navigation.

## Current state

- Repository: `C:\My_projects_1\cLOUD\Unisys_Model`, branch `work`.
- P7-RR-9 is implemented locally in the current session. The code and verification are described in its checklist entry in `PROGRESS.md`; review that entry and the diff/commits before taking the next task.
- P6 was reviewed and merged from `wave/P6` into `work` as `391b8ac`. Do not modify `wave/P6` or its worktree.
- P10-V1 app work is in `68018bc`; P10-V2 and other cluster verification remain with Claude. Do not access Kubernetes or `hybrid-demo`.
- No model training is approved; P12-H remains out of scope. Never push or set `ALLOW_PUSH`.

## Relevant completed work

- P10-V1 (`68018bc`): `demo/victim-app/` exports the Health Agent's HTTP metric names and includes its deployment/service/ServiceMonitor and tests. No image build or cluster verification.
- P5-Q1, P9-G1, P10-U5 (`3c80df4`): Health Agent HTTP metric contract documentation, Grafana model-inflight panel, and demo instructions.
- P8-D5 (`b7436e3`): approval-claim startup reconciliation and admin claim release. TTL 600 seconds is a chosen default, not a measurement; real Redis behavior was not checked.
- P6-D2 Security sampling (`b9238b7`) and P6-D7 Falco source timestamp (`3690c9f`) are committed; no live Falco/cluster check.
- REV-3 fixes (`c8931ba`) are committed; the graph contract test remains open due missing `torch_geometric` in the current Python environment.

## Decisions and limitations

- Keep Health Agent OBSERVE event-driven for now. The OBSERVE TTL is a freshness limit and does not define sampling cadence. Do not claim a 100-second interval from a 300-second TTL and factor 3. Design sampling cadence, incident correlation, and cooldown together before implementing periodic scoring.
- P7-RR-9 now uses an Executor-created Job to scan restored PVCs read-only. Any incomplete or unreadable scan stays unknown and isolated. The Job uses the Executor image by default; verify it can be pulled from prod/staging/dev and provision pull secrets there if needed. The scanner deadline and resource settings are chosen defaults, not measured performance.
- Local scanner/remediation/static/no-writes test run passed 73 tests with 4 datetime deprecation warnings; `py_compile` passed. The chart test could not collect because Windows denied access to the installed Helm executable under the user WinGet directory. Do not claim chart parity or cluster verification.
- Full-suite status is not green in the current shell; see the older environment/test details in `PROGRESS.md`.

## Next work

- P7-RR-10 is eligible because its declared dependency P6-R1 is marked complete. Review the list in `PROGRESS.md`; make small, tested changes and do not run Kubernetes tests.
- P7-RR-11 follows P7-RR-9. P7-RR-7 and P10/P11 require cluster verification and stay with Claude.
- P6-D6 still lacks a legitimate KernelExplainer background-data source; do not invent one.

Never push, never set `ALLOW_PUSH`, never run destructive Git commands, and never report unverified metrics as measured.

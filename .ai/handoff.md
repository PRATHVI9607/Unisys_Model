# Handoff

- **Agent/date:** Codex tests/demo/docs, 2026-11-12. Nothing pushed or merged.
- **Goal:** Finish safe P11 E1/E2 evidence and update demo docs.
- **What changed and why:** E1 attempt was invalid: 297/297 requests failed, 0/297 checks passed, so latency is `not measured`. Runner validates k6 checks and failed requests, records failed counts, and exits nonzero on a failed load. Added exact attempt evidence. Integrated a separate NetworkPolicy allowing only same-namespace `app=kubeheal-p11-k6` pods to reach inference on `.Values.inference.port`; chart tests include custom port 8123.
- **Files touched:** `eval/p11_run.py`, `tests/test_p11_run.py`, `docs/kubeheal/results/p11/*`, `deploy/helm/kubeheal/templates/networkpolicy.yaml`, `tests/test_platform_chart.py`, `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`.
- **Checks:** P11 focused suite: 41 passed. Chart tests after custom-port follow-up: 6 passed, 101 deselected. Full suite pending.
- **Open issues:** The NetworkPolicy has not been deployed. No cluster upgrade or rerun. Mode stayed `test`; temporary E1 Job/ConfigMap were cleaned; persistent data untouched. E2 is paused.
- **Next step:** Run the full suite with `.pytest-tmp/full`; wait for clearance before any cluster action.

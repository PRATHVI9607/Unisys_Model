# Handoff

- **Agent/date:** Codex tests/demo/docs, 2026-11-12. Nothing pushed or merged to demo.
- **Goal:** Finish safe P11 E1/E2 evidence and update demo docs.
- **What changed and why:** E1 attempt failed: 297/297 requests, 0/297 checks passed, latency `not measured`; artifacts record the failure. Runner validates k6 outcomes. Integrated the narrow same-namespace P11-to-inference ingress policy, using `.Values.inference.port`, and chart tests for the custom-port case.
- **Files touched:** P11 runner/tests/evidence, `deploy/helm/kubeheal/templates/networkpolicy.yaml`, `tests/test_platform_chart.py`, `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`.
- **Checks:** Full suite with repo venv and `--basetemp=.pytest-tmp/full`: 2,101 passed, 11 skipped, 262 warnings, 164.59 seconds. No cluster calls during the suite.
- **Open issues:** Policy is not deployed. Mode stayed `test`; failed-run Job/ConfigMap were cleaned; persistent data untouched. E1 rerun and E2 remain paused pending orchestrator clearance.
- **Next step:** Wait for clearance to deploy the approved policy in test mode, rerun E1, verify successful requests and HPA recovery to 2/2, then run E2.

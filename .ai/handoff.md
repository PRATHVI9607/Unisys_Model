# Handoff

- **Agent/date:** Codex tests/demo/docs, 2026-11-12. Nothing pushed or merged.
- **Goal:** Finish safe P11 E1/E2 evidence and update demo docs.
- **What changed and why:** E1 attempt was invalid: 297/297 requests failed with connection refused, 0 checks passed, so result is `failed` and latency is `not measured`. Runner now validates k6 checks and HTTP failures, records failed counts, and exits nonzero for a failed load. Added exact attempt evidence. Focused suite: 41 passed.
- **Files touched:** `eval/p11_run.py`, `tests/test_p11_run.py`, `docs/kubeheal/results/p11/*` (attempt evidence and generated coverage), `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`.
- **Open issues:** Read-only live state confirms Service/target port 8000, `/v1/health/predict`, two Ready endpoints, and HPA 2/2. NetworkPolicy default deny blocks `app=kubeheal-p11-k6`; Agent2 is implementing a narrow allowance. E2 and E1 rerun remain paused. Mode stayed `test`; temp Job/ConfigMap cleaned; persistent data untouched.
- **Next step:** Review Agent2's policy change; rerun E1 only after safe deployment and successful preflight. Wait for HPA 2/2, then run the approved E2 and record exact results. Do not merge yet.

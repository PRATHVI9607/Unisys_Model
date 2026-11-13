# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** work
- **Goal:** Diagnose and improve P11/F11 startup refusals before accepting load results.
- **What changed and why:** Added a P11 inference Deployment/Service-endpoint readiness wait and a five-request sequential k6 setup warm-up. The warm-up is logged separately, stops the run on any refusal, and does not retry or discard measured VU failures. Focused harness tests passed: 20.
- **Files touched:** `eval/p11_harness.py`, `tests/test_eval_p11_harness.py`, `docs/kubeheal/PROGRESS.md`.
- **Open issues:** Existing traces are consistent with startup timing but do not identify the refusing component. Need a live rerun and readiness/NetworkPolicy/pod timestamps after owner authorizes original cluster access. F11's demo runner also needs the same explicit warm-up after this core change is merged into demo.
- **Next step:** Review and commit on work, merge into demo, add the F11 demo warm-up, then rerun E1/F11 only after authorization.

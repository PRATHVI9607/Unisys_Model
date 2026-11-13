# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** work
- **Goal:** Diagnose and improve P11/F11 startup refusals before accepting load results.
- **What changed and why:** P11 now has an explicit five-request fail-fast k6 setup warm-up as well as the Deployment/Service-endpoint readiness wait. The run logs the warm-up openly and leaves warm-up requests in aggregate metrics; it does not retry or discard measured VU failures. Regression test added. Focused P11 runner tests pass: 18. Full suite before this last runner fix: 2169 passed, 11 skipped.
- **Files touched:** `eval/p11_run.py`, `tests/test_p11_run.py`, `.ai/handoff.md`.
- **Open issues:** Existing traces are consistent with startup timing but do not identify the refusing component. Need a live rerun and readiness/NetworkPolicy/pod timestamps. F11 demo load also needs its run after readiness/warm-up; dashboard screenshot browser access is unavailable.
- **Next step:** Commit this runner fix on work, merge it to demo, then run P11 E1/F11 with readiness timestamps.

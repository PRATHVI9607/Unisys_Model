# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** work
- **Goal:** Diagnose and improve P11/F11 startup refusals before accepting load results.
- **What changed and why:** P11 now has an explicit five-second network settling delay followed by five fail-fast k6 setup requests, as well as the Deployment/Service-endpoint readiness wait. The run logs the warm-up openly and leaves warm-up requests in aggregate metrics; it does not retry or discard measured VU failures. A live attempt still had the first request refused at 14:20:42Z despite both endpoints Ready for hours. Focused runner tests pass: 18. Full suite before this last runner fix: 2169 passed, 11 skipped.
- **Files touched:** `eval/p11_run.py`, `tests/test_p11_run.py`, `.ai/handoff.md`.
- **Open issues:** Need a live rerun with the settling delay and readiness/NetworkPolicy/pod timestamps. F11 demo load also needs its run after readiness/warm-up; dashboard screenshot browser access is unavailable.
- **Next step:** Commit and merge the delay, then rerun P11 E1 and F11.

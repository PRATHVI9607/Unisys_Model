# Handoff

- **Agent:** Codex containment_security; **Date:** 2026-11-12.
- **Goal:** Add HMAC authentication to node-local containment requests and results.
- **What changed and why:** On isolated `wave/Codex-F3` (not merged), added HMAC-SHA256 signing/verification to freeze requests, Security Agent results, and operator thaw; key is injected from the existing Redis Secret. Focused tests: 299 passed, 3 skipped.
- **Files touched:** `agents/common/containment_auth.py`, Executor/Security Agent containment, Helm and plain manifests, thaw script and relevant tests, `docs/kubeheal/PROGRESS.md`.
- **Open issues:** No cluster deploy or live verification. D-5 replay mount and full stream-driven containment acceptance remain open. The shared Redis Secret key does not isolate Redis credential holders.
- **Next step:** Parent reviews this branch, then coordinates a single test-mode/live acceptance window before any deployment; merge only after the full suite is green.

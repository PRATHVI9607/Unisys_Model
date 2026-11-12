# Handoff

- **Agent:** Codex containment_security; **Date:** 2026-11-12.
- **Goal:** Prepare D-5 replay and containment HMAC hardening on isolated branch `wave/Codex-D5-Replay`; no live replay or deployment.
- **What changed and why:** Replay-origin events remain dry-run through Security Agent, Fusion, and Executor even if global mode becomes enforce. Non-target Security Agents fall back to live Falco auto-detection. Runner has a second mode check, UUID-owned collision-safe ConfigMap creation, a shared bounded deadline, ownership-checked cleanup after ambiguous create, and preserves the mounted ConfigMap with recovery steps if restoration fails. HMAC uses dedicated `kubeheal-containment-hmac`; Helm preserves its key across upgrades and fails if the existing key is missing.
- **Files touched:** `agents/fusion_agent/agent.py`, `agents/security_agent/agent.py`, `agents/security_agent/falco_client.py`, chart values/templates, plain Executor/Security Agent manifests, `scripts/d5_replay_runner.py`, focused tests, `docs/kubeheal/D5_REPLAY.md`, `docs/kubeheal/CONTAINMENT_HMAC.md`, `docs/kubeheal/PROGRESS.md`.
- **Open issues:** Focused suite passed 253 tests using fakes/templates. Not merged, built, deployed, or run on k3d. D-5 fixture is hand-written, not live Falco evidence. No cluster writes were made.
- **Next step:** Review diff and commit; root to conduct independent review before any coordinated live replay. Never push, train, change `PROJECT_SPEC.md`, or run cluster commands without coordination.

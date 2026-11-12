# Handoff

- **Agent/date:** Codex tests/demo/docs, 2026-11-12. No push or merge.
- **Goal:** Make the live demo runbook safe, exact, and honest about verification.
- **What changed and why:** Updated F2-F11 with existing resource names/commands, explicit `NOT VERIFIED` status where no live trigger exists, safe test fallbacks, and evidence paths. Corrected dashboard port-forward and agent resource names. Added the separate P11 failed-attempt note: 0/297 checks, 297/297 refused, latency `not measured`. The F4 fallback lists Secret names only without assuming the HMAC Secret name. Clarified that mode stays `test` until a reviewed enforce trigger exists.
- **Files touched:** `docs/kubeheal/DEMO_RUNBOOK.md`, `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`.
- **Open issues:** Final rehearsal evidence/screenshots are not saved. P11 E1 failed because NetworkPolicy excludes the P11 Job label; Agent2 is fixing policy on a separate branch. E2 remains paused.
- **Next step:** Review runbook diff and commit on `wave/demo-runbook`; rerun P11 only after policy update is reviewed, safely deployed, and inference requests succeed.

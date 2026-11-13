# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13
- **Branch:** demo
- **Goal:** Complete KubeHeal live acceptance and push preparation. Nothing pushed; no training or `PROJECT_SPEC.md` edits.
- **Last work commit:** `e1f7791` (`fix(eval): wait and warm inference before P11 load`).
- **What changed and why:** U6 passed twice on isolated `kubeheal-rehearsal` using vendored Helm charts and local cached images; its evidence is committed. P11 now waits for the inference Deployment and ready Service endpoints, then runs five separately logged setup warm-up requests before measured VUs. Focused P11/security-scan tests passed: 42.
- **Files touched:** U6 evidence under `docs/kubeheal/demo-evidence/F12/`; `eval/p11_harness.py`, `tests/test_eval_p11_harness.py`, `docs/kubeheal/PROGRESS.md`.
- **Open issues:** Owner authorization is pending before any further access to original `k3d-kubeheal`; its cluster and PVCs remain in place. F11 demo script warm-up remains to be added. F5-F8, F10 enforce canary/rollback, clean F11/P11 runs, original-cluster runbook rehearsal, and push prep remain. Earlier accidental command briefly restarted the original cluster, but changed no pods, releases, PVCs, or data; its mode remained test.
- **Next step:** Finish the F11 demo-side warm-up and test locally, then resume live scenarios after owner authorization. Never push.

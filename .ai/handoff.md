# KubeHeal acceptance handoff, 2026-11-13

- **Agent:** Codex
- **Branch:** demo, integrating reviewed work
- **Goal:** finish live acceptance and push preparation; nothing pushed, no training or PROJECT_SPEC.md edits.
- **What changed and why:** Final rehearsal is recorded in docs/kubeheal/demo-evidence/REHEARSAL. D-5 replay now excludes scripted F10 pods sharing the victim image label; the focused suite passed 9 tests and the rehearsal retry passed. F2 and F4 were rerun. F5-F8 and F10 have scripted live evidence; F11 and P11 E1 have clean warmed load results; F12 U6 passed twice offline on a separate cluster. P11 E3-E6 and V5-E1 remain not measured with concrete reasons.
- **Files touched:** D-5 runner/tests, DEMO_RUNBOOK.md, rehearsal/F2/F4 outputs, current evidence and acceptance docs.
- **Open issues:** Finish the merge and demo suite, update README.md/AGENTS.md/PUSH_PLAN.md, secret-scan diff against origin, verify mode test and release cluster lock. F8 SnapshotFreeze release and F9 same-input paired action remain not measured; P11 E3-E6/V5-E1 remain not measured.
- **Test status:** work full suite 2,169 passed, 11 skipped in 82.92s. Demo full suite pending merge completion.
- **Cluster:** only context k3d-kubeheal; Helm revision 17, mode test, inference /readyz HTTP 200, protected PVCs Bound. Lock held by Codex during final rehearsal.
- **Next step:** complete final push-prep checks on demo. Never push or set ALLOW_PUSH.

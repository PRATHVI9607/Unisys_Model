# Handoff

- **Agent:** Codex
- **Date:** 2026-11-13 06:38 IST
- **Goal:** Finish KubeHeal F1-F13 acceptance on `work` then `demo`; nothing pushed, no training or `PROJECT_SPEC.md` changes.
- **What changed and why:** Reviewed F3b PVC guard, F4 HMAC, F8 dashboard, P11, k6 policy, thaw HMAC docs, and demo-runbook branches. Focused suites passed. Updated `NEXT_FOR_CODEX.md` and `PROGRESS.md` with findings and the access blockers.
- **Files touched:** `docs/kubeheal/NEXT_FOR_CODEX.md`, `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`
- **Open issues:** Fresh cluster reads are blocked because sandbox access to `C:\Users\PV\.kube\config` is denied. Helm is absent from PATH and the test collector cannot stat its protected Winget path, so full suites on work and demo produce no counts. `CLUSTER_LOCK.md` still says `Codex 2026-11-13 06:17 IST`; mode/revision/tags/readiness/readyz are not freshly verified. F3b PVC guard and the thaw-doc correction remain unmerged pending a full suite. F5-F10 live acceptance, F12 U6, F13 P11, fresh F2/F3/F4 checks, demo rebuild, rehearsal, and push prep remain open.
- **Next step:** Restore authorized access to the configured `k3d-kubeheal` context and Helm, recheck cluster readiness under the existing lock, then resume the user's acceptance order. Pre-checkpoint: `work` `0dbd37e`; `demo` had merged the focused test checkpoint.

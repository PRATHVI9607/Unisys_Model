# Handoff

- **Agent/date:** Codex, 2026-11-12. Nothing pushed; no model training; mode remains `test`.
- **Goal:** Finish KubeHeal demo push prep. Claude owns F3 code and Codex owns merges into `work` and `demo`.
- **Current branches:** latest refs before this handoff refresh: `work` `104521d`, `demo` `7284a36`; the audit docs are integrated. `origin/main` is `48a59aa7195ea14f8366a4338293f095c8803daf`.
- **Suites:** work 2,158 passed, 11 skipped in 90.05s; demo 2,158 passed, 11 skipped in 66.43s. No code changed after these runs.
- **F3:** Reviewed `d0ed188`, full suite passed, merged into work and demo. Live containment through restore succeeded; Sense was scripted because Falco is absent. The escalation assertion still checks unsupported-owner behavior and no contain request.
- **Cluster:** demo image tag `b20261112215116`, Helm revision 13; last readback mode `test`. Lock was released. Check lock before any cluster touch; commit `CLUSTER LOCK <who> <start time>` before enforce/Helm upgrade, then remove and commit it. Use only `--context k3d-kubeheal`.
- **Live evidence:** F4 HMAC smoke passed signed/unsigned/tampered test-mode cases. F11 HPA reached 2 -> 8 -> 2 but the repeat had 12 refused checks and no Grafana screenshot; earlier clean HPA transcript and Prometheus/Grafana API evidence exist.
- **Audit:** P4 diff scan found one placeholder-like test token assignment, no `.env`/kubeconfig/venv/binary changes. `git diff --check` still reports whitespace in CSI comments and captured load output. Updated `PUSH_PLAN.md` lists exact feature states.
- **Remaining:** F5-F10 and F12-F13 acceptance gaps are listed in PUSH_PLAN. Run the post-cutoff rehearsal from a fresh cluster start, save evidence/fallbacks, then report only verified items. P11 unmeasured values must say `not measured`.
- **Files touched in current task:** `PUSH_PLAN.md` (feature states, scan results, and exact final verification commands), `docs/kubeheal/PROGRESS.md`, `.ai/handoff.md`.
- **Next step:** After 23:30 IST, check the lock and rehearse once from a fresh k3d start using `up.ps1 -Stage cluster` (non-destructive). Use saved F3 evidence without rerunning Claude's F3 work; do not run `down.ps1`, which deletes cluster data. Capture fallbacks and skips, then update final rehearsal status. Never push or set `ALLOW_PUSH`.

# Handoff

- **Agent:** Codex orchestrator
- **Date:** 2026-11-11
- **Status:** Paused at user request. Current checkout is `demo`; cluster `kubeheal` is running in mode `test`. Nothing pushed.
- **Implementation checkpoint:** `f4264d1` on `demo`; shared disk metric query fix is `382d137` on `work`, merged into demo. The top commit contains this pause handoff.
- **Cluster:** victim prod/dev and Health Agent use manually built `:metric-probes` images; generated chart image tags are stale. Prod victim is restored to request 100m / limit 500m. A harmless `.kubeheal-metric-probe` file remains on its PVC. Temporary snapshot-restore objects were removed.
- **Open findings:** missing-metric CI sentinel is understood; with all 15 channels observed, latest width was 0.2607 and policy recorded `human_patch` with `dry_run=true` (gate 0.15 unchanged). Startup S3Error queue drained (`XLEN=0`). Health Agent aiohttp session leak remains. Falco auto mode resolves to off; replay/install incomplete. HPA scale-out and full P10 acceptance remain.
- **WIP branches not merged:** `wave/P11` at `47e1b34` (`../Unisys_Model-wt-P11`); `wip/docs-p6d2` at `c7c9f5bf7a078702e2dd0c1d47d862df7ef1b77f` (`../Unisys_Model-wt-docs`). Work core query checkout: `../Unisys_Model-wt-metric-query` on `work`.

Resume from [NEXT_FOR_CODEX.md](../docs/kubeheal/NEXT_FOR_CODEX.md). Read it before using the cluster or merging work.

# F11 HPA evidence index

- The first attempt on 2026-11-12 failed before measurement because PowerShell `Out-String -NoNewline` flattened the JS source and k6 reported `no exported functions in script`. Cleanup removed its temporary Job, ConfigMap, and NetworkPolicy.
- The staging fix is in `6f97f88`; the later successful run is recorded in [hpa-run-2026-11-12.md](hpa-run-2026-11-12.md).
- One successful synthetic scoring load was measured. The final runbook rehearsal still needs full raw terminal screenshots and Grafana screenshots.

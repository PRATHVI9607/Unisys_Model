# F11 HPA evidence index

- The first attempt on 2026-11-12 failed before measurement because PowerShell `Out-String -NoNewline` flattened the JS source and k6 reported `no exported functions in script`. Cleanup removed its temporary Job, ConfigMap, and NetworkPolicy.
- The staging fix is in `6f97f88`; the later successful run is recorded in [hpa-run-2026-11-12.md](hpa-run-2026-11-12.md).
- The earlier successful run is in `hpa-run-2026-11-12.md`. A post-merge repeat scaled 2 -> 8 -> 2 but had 12/99,431 connection refusals; its full output and Grafana dashboard/Prometheus API evidence are in that report and `grafana-hpa-api-2026-11-12.json`.
- Grafana has no image renderer installed and browser access was unavailable, so a visual dashboard screenshot is still pending for runbook rehearsal.

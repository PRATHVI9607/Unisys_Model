# F11 k6 staging diagnostic

- **Date:** 2026-11-12
- **Machine/cluster:** not recorded in the copied console note; the target was `k3d-kubeheal`.
- **Command:** `demo/scripts/hpa_load.ps1` (32 VUs, 90 seconds, default values).
- **Result:** failed before any load measurement. k6 reported `no exported functions in script` for `/scripts/health.js`.
- **Cleanup:** the operator confirmed no temporary `kubeheal-k6-health-load` Job, ConfigMap, or NetworkPolicy remained.
- **Cause/fix:** PowerShell `Out-String -NoNewline` flattened the JavaScript source lines. Commit `6f97f88` stages the source through `kubectl create configmap --from-file` and adds a static regression check.
- **Measurements:** not measured. No HPA scale-out or Grafana result is claimed from this attempt.
- **Next:** rerun after the fix, record exact command, date, machine, k6 output, HPA samples, and dashboard screenshots here.

# F10 drift walkthrough on demo images

**Date:** 2026-11-13 (local time, Asia/Calcutta)  
**Cluster:** `k3d-kubeheal`  
**Mode:** `test` before and after the walkthrough

The bounded `demo.ps1 -Action drift -ObserveSeconds 30 -ProbeSeconds 30` scenario completed successfully. It primed live Prometheus samples, then reported 15/15 configured queries with data. The displayed sample values included CPU limit 500m, HTTP p99 latency 485.95 ms, and HTTP error rate 1.38 requests/s. These are samples from this walkthrough, not a performance baseline.

The script temporarily patched `prod/victim-app` to CPU request/limit 50m/50m. Fusion recorded incident `inc-20261113-080214-d4b35860` as a `human_patch` action with confidence 0.7316 and `dry_run=true`; no Executor Kubernetes write was enabled. The script restored CPU request/limit to 100m/500m. Readback showed `victim-app` Ready 1/1 with request 100m, limit 500m; cluster mode remained `test`.

**Status:** live drift sensing and test-mode action recording are verified. Canary-only healing and rollback after a bad p99 are **not measured**: this run intentionally stayed in `test`, and the existing scenario does not implement a canary patch/rollback trigger. No p99 rollback claim is made.

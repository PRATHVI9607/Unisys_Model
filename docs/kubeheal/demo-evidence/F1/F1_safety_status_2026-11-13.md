# F1 test safety status

**Date:** 2026-11-13  
**Cluster:** `k3d-kubeheal` (live tests remained opt-in)  
**Mode at final read:** `test`

The default full test suite passed on both maintained branches: `work` 2,166 passed, 11 skipped; `demo` 2,166 passed, 11 skipped. The live-test inventory keeps tests that can contact Kubernetes, Redis, or MinIO behind explicit opt-in flags. Those live tests were not enabled by these suite runs.

**Status:** automated test-safety coverage passed. This is not a live opt-in integration-test result. The cluster was read with the explicit `k3d-kubeheal` context, and the global mode was verified as `test` after the acceptance actions.

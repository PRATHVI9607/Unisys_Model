# F8 dashboard read-through

**Date:** 2026-11-13  
**Cluster:** `k3d-kubeheal`  
**Mode:** `test`

Dashboard API and page checks over the existing local port-forward returned HTTP 200:

| View | Result |
|---|---:|
| `/api/kill-switch` | 200 |
| `/api/approvals` | 200; 16 pending items |
| `/api/incidents` | 200; 61 incidents |
| `/api/baseline-candidates` | 200; 0 candidates |
| `/approvals` | 200 |
| `/baseline-candidates` | 200 |
| F3 incident timeline | 200; SnapshotFreeze section present |

The F3 incident detail returned `snapshot_freeze.available=true` and an empty `held` list. The dashboard therefore had no freeze target for a release action. The baseline page had no candidate target. The approvals view rendered incident links and a mode control; no approve/reject/release action was performed. F9 separately records the authenticated kill-switch toggle and ledger entries.

**Status:** dashboard data/API and page rendering are verified. A complete interactive walkthrough of every control and screenshot evidence are **not measured**: the connected browser surface was unavailable, and the currently available data has no baseline candidate or held SnapshotFreeze to act on. No claim is made that every control was exercised.

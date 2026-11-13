# F7 scripted Fusion policy evidence

**Date:** 2026-11-13
**Cluster:** `k3d-kubeheal`
**Mode:** `test`
**Inputs:** scripted policy/model events using a PVC-free run-owned target

- M2: the ambiguous prediction set `{degraded, benign}` reached `human_pending`.
- D1: inclusive boundary examples emitted `policy:cpu_cut_10x` for 500m to 50m and `policy:memory_cut_10x` for 320Mi to 32Mi.
- Rule rollback: without a fresh Security Model response, Fusion held for human review. With a fresh scripted Security Model response, Fusion queued the rule-path Executor request as dry-run.

No Kubernetes workload write was made. Three run-owned HUMAN approvals were resolved through the dashboard; the append-only ledger and stream history remain. The Security response was scripted and does not verify live Security Model scoring. Exact outcomes are in `F7_scripted_run_2026-11-13.txt` and `F7_approval_resolution_2026-11-13.txt`.

# F5 baseline promotion status

**Date:** 2026-11-13
**Cluster:** `k3d-kubeheal`
**Inputs:** scripted, PVC-free, run-owned dev and prod Deployments

The dev config change auto-promoted, and its `baseline_promoted` ledger record points to the new golden baseline. The prod config change created a pending dashboard candidate. Dashboard approval promoted it and wrote a second ledger record during a bounded enforce window with a dead-man switch. The mode returned to `test` and was read back. Exact run ID, candidate ID, ledger keys, and outcomes are in `F5_scripted_run_2026-11-13.txt`.

**Status:** live promotion workflow verified with explicitly scripted benign/certain assessments. The scores were not produced by the model, so this does not verify Health Agent model quality or its live assessment path.

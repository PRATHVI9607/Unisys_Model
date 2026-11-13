# F3 operator cleanup evidence, 2026-11-13

Context: `k3d-kubeheal`; Helm revision 15; mode was read back as `test` after both scripted windows and after cleanup.

## F3 demo-image restore rerun

The second run used Deployment `staging/f3-demo-victim-20261113` with the rebuilt victim image `b20261113071011`. Incident `inc-20261113-015540-cff4eea6` completed with `restored`. The ledger dump `99_demo_image_victim_ledger_2026-11-13.jsonl` contains the 42-step chain and the clean scan result: 5 files scanned, 0 high entropy, 0 unreadable. The restored PVC contained only the five clean seed files. Sense input was scripted from the previously model-scored hand-written D-5 event.

The cleanup helper printed and removed only the exact run-owned Deployment, original and restored PVCs, rolling and forensic snapshots, plus any resources labelled with this run's incident ID. Raw targets and output are in `100_demo_image_victim_cleanup_2026-11-13.txt`; a read-only follow-up found no remaining scratch resources in `staging`.

## Orphan freeze keys and old escalations

Before removal, `kubectl get pvc -n staging` returned no PVCs. Redis listed five `kubeheal:snapfreeze:staging:*` keys: four historical scratch keys and the current rerun's key. Each value matched the expected incident ID. The five keys were removed using Redis Lua compare-and-delete so a key with a changed owner would have been left intact. A post-check returned no staging freeze keys. No Redis stream entry, MinIO ledger object, PVC, or snapshot data was deleted by this key cleanup.

Two old `kubeheal.escalations` records referred to removed scratch workloads:

- `inc-20261112-140132-fe13751f`: freeze refused because the old Executor request had an invalid HMAC; the fail-safe containment outcome is preserved.
- `inc-20261112-140632-c8ed65b8`: the restore was kept isolated because the old entropy result was unreadable; the fail-safe outcome is preserved.

The corresponding staging resources and freeze keys were confirmed absent. A `human_resolution` entry was appended to each incident's MinIO ledger with the operator review reason. The original Redis escalation entries were retained. Their resolution records are at ledger sequences 17 and 38 respectively.

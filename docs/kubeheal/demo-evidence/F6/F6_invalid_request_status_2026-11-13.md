# F6 signed invalid-request validation

**Date:** 2026-11-13
**Cluster:** `k3d-kubeheal`
**Mode:** `test`
**Inputs:** four run-owned signed requests

The Security Agent refused all four requests before freeze/cgroup writes. Response HMACs verified and every response reported `frozen=0`:

| Scripted case | Result |
|---|---|
| Invalid namespace | `refused: bad_namespace` |
| Protected `dev` namespace label | `refused: namespace_protected` |
| Unknown action `wipe` | `refused: bad_action` |
| Missing pod UID | `refused: bad_pod_uid` |

The runner restored the previous namespace label, removed only its Redis messages/results, and confirmed mode remained `test`. Security Agent refusal logs and signed result hashes are the proof. The current implementation does not append these refusals to the shared MinIO ledger. No freeze or remediation write occurred. See `F6_signed_invalid_run_2026-11-13.txt`.

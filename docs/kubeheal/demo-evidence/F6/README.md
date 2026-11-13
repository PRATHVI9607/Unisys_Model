# F6 signed invalid-request validation

Date: 2026-11-13 local time
Context: `k3d-kubeheal`; global mode remained `test`.

The run-owned script `f6_signed_invalid_requests.py` created four HMAC-signed requests from inside the node-local Security Agent container. Every response HMAC verified. The agent refused all four before cgroup resolution or a freeze write, and every response reported `frozen=0`:

| Scripted case | Result |
|---|---|
| Invalid namespace `bad_namespace` | `refused: bad_namespace` |
| `dev` namespace temporarily labeled `kubeheal/protected=true` | `refused: namespace_protected` |
| Unknown action `wipe` | `refused: bad_action: 'wipe'` |
| Missing `pod_uid` | `refused: bad_pod_uid` |

`F6_signed_invalid_run_2026-11-13.txt` contains the run ID, request IDs, verified refusal results, and Security Agent refusal log lines. The script restores the exact prior `dev` namespace protection label and verifies the readback, removes only its own Redis request/result records, and confirms mode remains `test`.

The only Kubernetes mutation during this validation was the temporary run setup/restoration of the `dev` namespace protection label. No pod freeze or remediation write occurred. Security Agent refusals are logged but are not appended to the shared MinIO ledger by the existing implementation; the signed result hashes and component logs provide the recorded proof for this protocol check.

# Live cgroup freeze check on k3d (2026-11-12)

Machine: Windows 11, Docker Desktop, k3d cluster `kubeheal` (context `k3d-kubeheal` only), k3s v1.35.5, cgroup v2,
cgroupfs driver. Three nodes (server-0, agent-0, agent-1), each a Docker container.

**This is verified on k3d, where the nodes are Docker containers sharing the Docker Desktop VM kernel. It is NOT yet
verified on a real node.** Real hardware or a real cloud node may differ (cgroup driver, mount layout, QoS directories,
permissions, a read-only cgroup mount).

## Scope of this check (read first)

The driver called `agents.executor.freeze.request_freeze` directly inside the Executor pod, with the Executor's real
gate, ledger guard and mode watcher. It did not use the Executor's stream consumer, `parse_request`, `check_target` or
`quarantine.contain`. Request intake and the containment order (freeze, snapshot, quarantine, scale to 0) were not
exercised live. The `mode_change` ledger entries at 09:07:36Z and 09:08:07Z came from the driver's own mode watcher
starting up; the real flips are 09:08:02Z and 09:08:08Z.

## What ran

- Security Agent image `b20261112143524` (built from `demo` after the merge of V5-S5c and V5-CH4, at commit `96393fc`
  of the S5c branch), Helm release `kubeheal` revision 7 `deployed`. Later the same day the image was rebuilt as
  `b20261112150442` (revision 8) after a test follow-up and an lstat change in the container check; the freeze below ran on
  `b20261112143524`. The agent logs `containment consumer started on kubeheal.contain.req:<node>`; `POD_UID` and
  `POD_NAME` are set from the downward API.
- Scratch pod `dev/freeze-scratch` (uid `3392ad99-92e1-4504-bbc0-53446bd64dd8`, node `k3d-kubeheal-agent-0`, QoS
  Burstable, container id `c1c8c6779a8d...`), running a sleep loop. Nothing else was touched.
- Driver: `live_freeze_check_driver.py` (this folder) run INSIDE the Executor pod. It uses the Executor's own
  `RequestGate`, ledger guard and mode watcher and calls `agents.executor.freeze.request_freeze`, the same function the
  contain path calls. The thaw used `scripts/thaw_pod.py` (the admin release tool).

## Steps and real output

1. Mode `test`: `request_freeze` raised `ModeBlocked`. Ledger: `scripted_freeze_check_start`, then `request_freeze`
   outcome `blocked_by_kill_switch`. Node cgroup after: `cgroup.freeze` 0, `cgroup.events` `frozen 0`.
2. Mode set to `enforce` (09:08:02Z), request sent, mode set back to `test` (09:08:08Z, about 6 seconds later).
   `request_freeze` returned `confirmed: true`; the Security Agent result: `status frozen`, `frozen 1`, `mode_seen
   enforce`, `cgroup kubepods/burstable/pod3392ad99-92e1-4504-bbc0-53446bd64dd8`; the request took 0.02 s. Read back from
   the node (`docker exec k3d-kubeheal-agent-0 ...`): `cgroup.freeze` 1, `cgroup.events` `populated 1`, `frozen 1`.
3. In mode `test` (global mode, as left after step 2): `scripts/thaw_pod.py` printed `THAWED: status='thawed'
   frozen='0'`. Node: `cgroup.freeze` 0, `frozen 0`. The pod stayed `Running`. A thaw working in mode `test` is the
   decided behaviour.
4. Mode after the step: `test` (checked).

Ledger entries of incident `scripted-freeze-check-enforce-1` (read with `live_freeze_check_read_ledger.py`):
`000001 scripted_freeze_check_start`, `000002 intent_request_freeze` (class protective, phase about_to_do),
`000003 request_freeze` (outcome succeeded), `000004 scripted_freeze_check_result` (confirmed true, the result above).
The intent entry is written before the request is sent. Incident `scripted-freeze-check-dry-1`: `000001
scripted_freeze_check_start`, `000002 request_freeze` (blocked_by_kill_switch).

## Findings

- The thaw left no ledger entry: `scripts/thaw_pod.py` writes only to Redis and the Security Agent does not write the
  ledger. A freeze is ledgered by the Executor, a release is not. Open item: record operator thaws in the ledger.
- Anyone who holds the Redis password can publish a request or write a result hash. The Executor checks that the result
  matches the request fields, but a forged result is not detectable. Recommended hardening (with V5-P3, per-component
  Redis users): an HMAC over request and result.
- The hostPath mount is still the whole `/sys/fs/cgroup`, read-write (V5-S5). Only `kubepods` is written. Narrowing it is
  open, and the code assumes `<root>/kubepods/...`, so a narrower mount needs a chart value and a test.
- The full pytest suite used to flip the live cluster to `enforce` for a few seconds through
  `tests/test_killswitch.py::test_live_watch_follows_configmap_without_polling`. Three bursts (08:44:52Z, 09:03:08Z,
  09:04:45Z, each of four mode changes) were found in the Fusion log and the ledger (`mode_change` entries) during this
  session. The MinIO ledger since 08:30Z holds no corrective action from those windows, only `mode_change` and
  `rolling_snapshot_dry_run` entries; the Redis fallback ledger stream was empty and no baseline promotion was recorded. The test is now opt-in (`KUBEHEAL_LIVE_KILLSWITCH_TEST=1`).

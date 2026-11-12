# D-5 replay procedure

`python scripts/d5_replay_runner.py` is a one-shot k3d replay runner. Run it from the repository root after the updated Security Agent image is built and installed. It uses only the `k3d-kubeheal` context.

The runner refuses to start unless the global `kubeheal-mode` ConfigMap is already `test` and the Security Agent DaemonSet currently has `FALCO_MODE=auto`. It reads the single Running `prod` victim-app pod and rewrites the fixture namespace, pod name, pod UID, node, and container ID to that pod's current identity. It creates a temporary ConfigMap and temporarily patches a read-only replay mount plus `FALCO_MODE=replay`, `FALCO_REPLAY_PATH`, and `FALCO_REPLAY_NODE`. The node setting means only the Security Agent on the victim's node consumes the trace.

Success requires a matching `syscall_source=replay` Security event and a matching Fusion action with `dry_run=true`. The runner prints both Redis records. It does not change `kubeheal-mode`. Its `finally` block restores the original Falco environment, removes the temporary mount and volume, deletes the ConfigMap, and waits for the DaemonSet rollout. It then checks that the mode remains `test` and Falco is back to `auto`. If cleanup itself fails, it exits with the failed cleanup steps so the operator can repair them before continuing.

The fixture `tests/fixtures/falco/ransomware_pv_encrypt_new_rules.jsonl` is hand-written. It is not a Falco capture and does not verify live Falco rules or live syscall collection. The process ID and event times are synthetic; only the target pod identity is read from the cluster. The event proves replay-to-Security-event-to-Fusion flow for this trace shape. Automatic decisions remain dry runs in test mode.

This runner was tested against a fake kubectl transport. It has not been deployed or executed against k3d yet.

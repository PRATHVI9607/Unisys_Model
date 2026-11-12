# Containment message key

The Executor and Security Agent authenticate freeze requests and result hashes with HMAC-SHA256. The operator thaw script uses the same protocol. The key is stored in `kubeheal-containment-hmac`, key `key`, and is provided only to the Executor and Security Agent containers. It is separate from the Redis password, so a Redis credential holder cannot forge an authenticated containment message unless they also have access to this Secret.

The Helm chart generates a random key on first install and uses `lookup` to retain the existing Secret on upgrades. Keep the Secret in the cluster and back it up through the operator's secret-management process. Do not print its contents, add it to values files, or commit it. For the plain Kubernetes manifests, create `kubeheal-containment-hmac` with a strong random `key` before applying the Executor or Security Agent manifests.

For an existing install that used the Redis password as the containment HMAC key, the next chart upgrade creates this dedicated Secret and restarts the two consumers with it. Wait until both are Ready before sending freeze or thaw requests; in-flight messages signed with the previous key will be refused. No Redis credential is changed by this migration.

The Kubernetes Secret is namespace scoped. The application containers receive the key through a Secret reference and never read it back through the Kubernetes API. Cluster operators who can read namespace Secrets can still access the key.

## Mode-test smoke check

`python scripts/containment_hmac_smoke.py --timeout-s 60` is a bounded live protocol check for a coordinated operator to run only while `kubeheal-mode` is `test`. The runner selects a Running `dev/victim-app` pod and the Running Security Agent on the same node, checks mode before sending and after receiving the results, and invokes a short helper inside that Security Agent container. The helper gets the signing key from its existing environment and does not print or return it.

The runner sends three unique freeze requests to the existing per-node Redis stream: a valid signed request, an unsigned request, and a request whose timestamp field is changed after signing. The target identity and other validation fields remain real and valid. The valid request must return `dry_run` with `mode_seen=test`; the other two must return `refused:invalid_hmac`. It verifies the result HMAC on all three responses and removes only the three run-owned stream entries and result keys. Kubernetes access is read-only except for `exec`; the mode-test Security Agent must perform no cgroup write. Every kubectl invocation is pinned to `k3d-kubeheal` and bounded by `--timeout-s`.

The runner has offline fake-transport coverage in `tests/test_containment_hmac_smoke.py`. It has not been run against k3d. Do not invoke it during another live acceptance window or outside mode `test`.

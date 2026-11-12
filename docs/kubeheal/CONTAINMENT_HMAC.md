# Containment message key

The Executor and Security Agent authenticate freeze requests and result hashes with HMAC-SHA256. The operator thaw script uses the same protocol. The key is stored in `kubeheal-containment-hmac`, key `key`, and is provided only to the Executor and Security Agent containers. It is separate from the Redis password, so a Redis credential holder cannot forge an authenticated containment message unless they also have access to this Secret.

The Helm chart generates a random key on first install and uses `lookup` to retain the existing Secret on upgrades. Keep the Secret in the cluster and back it up through the operator's secret-management process. Do not print its contents, add it to values files, or commit it. For the plain Kubernetes manifests, create `kubeheal-containment-hmac` with a strong random `key` before applying the Executor or Security Agent manifests.

For an existing install that used the Redis password as the containment HMAC key, the next chart upgrade creates this dedicated Secret and restarts the two consumers with it. Wait until both are Ready before sending freeze or thaw requests; in-flight messages signed with the previous key will be refused. No Redis credential is changed by this migration.

The Kubernetes Secret is namespace scoped. The application containers receive the key through a Secret reference and never read it back through the Kubernetes API. Cluster operators who can read namespace Secrets can still access the key.

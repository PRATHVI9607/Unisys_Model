#!/usr/bin/env python3
"""
RBAC proof (P2 acceptance): `kubectl auth can-i` for every KubeHeal ServiceAccount.

    python scripts/rbac_check.py                # uses context k3d-kubeheal
    KUBEHEAL_CONTEXT=k3d-kubeheal python scripts/rbac_check.py

Exit code 0 only if every expectation holds. The context is always passed explicitly; this script
never touches any other cluster.
"""

import os
import subprocess
import sys

CONTEXT = os.environ.get("KUBEHEAL_CONTEXT", "k3d-kubeheal")
NS_PREFIX = "system:serviceaccount:kubeheal:"
READERS = ["health-agent", "security-agent", "fusion-agent", "dashboard",
           "health-model", "security-model", "dcm"]
WRITERS_TO_TEST = [
    "patch deployments.apps", "update deployments.apps",
    "patch statefulsets.apps", "update statefulsets.apps",
    "patch pods", "delete pods",
    "create persistentvolumeclaims", "patch persistentvolumeclaims",
    "create networkpolicies.networking.k8s.io", "delete networkpolicies.networking.k8s.io",
    "create volumesnapshots.snapshot.storage.k8s.io", "delete volumesnapshots.snapshot.storage.k8s.io",
    "patch deployments.apps/scale", "update deployments.apps/scale",
    "patch statefulsets.apps/scale", "update statefulsets.apps/scale",
]

# (service account, verb+resource, namespace or None for cluster scope, expected answer)
EXPECT = []
for sa in READERS:
    for ns in ("prod", "staging", "dev", "kube-system", "kubeheal"):
        for w in WRITERS_TO_TEST:
            EXPECT.append((sa, w, ns, False))
    EXPECT.append((sa, "get secrets", "prod", False))

# read access that agents do need
EXPECT += [
    ("health-agent", "watch deployments.apps", "prod", True),
    ("health-agent", "list services", "prod", True),
    ("health-agent", "list horizontalpodautoscalers.autoscaling", "prod", True),
    ("health-agent", "list horizontalpodautoscalers.autoscaling", "kube-system", False),
    ("health-agent", "list horizontalpodautoscalers.autoscaling", "kubeheal", False),
    ("security-agent", "list pods", None, True),
    ("security-agent", "list replicasets.apps", None, True),
    ("fusion-agent", "get namespaces", None, True),
    ("fusion-agent", "list pods", "prod", False),
    ("dashboard", "list pods", "prod", True),
    ("health-model", "list pods", "prod", False),
]

# kill switch ConfigMap: read by fusion, executor, dashboard and (V5-D5, V5-S5) the health and security agents;
# written only by the dashboard admin role
for sa in ("fusion-agent", "executor", "dashboard", "health-agent", "security-agent"):
    EXPECT.append((sa, "get configmaps/kubeheal-mode", "kubeheal", True))
    EXPECT.append((sa, "watch configmaps/kubeheal-mode", "kubeheal", True))
for sa in ("health-model", "security-model", "dcm"):
    EXPECT.append((sa, "get configmaps/kubeheal-mode", "kubeheal", False))
for sa in ("fusion-agent", "executor", "health-agent", "security-agent"):
    EXPECT.append((sa, "patch configmaps/kubeheal-mode", "kubeheal", False))
    EXPECT.append((sa, "update configmaps/kubeheal-mode", "kubeheal", False))
EXPECT.append(("dashboard", "patch configmaps/kubeheal-mode", "kubeheal", True))
EXPECT.append(("dashboard", "patch configmaps/other", "kubeheal", False))

# executor: write only the verbs the dispatched paths use (kubeheal-executor-write), only in the
# protected namespaces, never in kube-system or kubeheal. Every other tested write verb must be denied.
EXECUTOR_GRANTED = {
    "patch deployments.apps", "patch statefulsets.apps", "patch pods",
    "create persistentvolumeclaims",
    "create networkpolicies.networking.k8s.io", "delete networkpolicies.networking.k8s.io",
    "create volumesnapshots.snapshot.storage.k8s.io", "delete volumesnapshots.snapshot.storage.k8s.io",
    "patch deployments.apps/scale", "patch statefulsets.apps/scale",
}
assert EXECUTOR_GRANTED <= set(WRITERS_TO_TEST)
for ns in ("prod", "staging", "dev"):
    for w in WRITERS_TO_TEST:
        EXPECT.append(("executor", w, ns, w in EXECUTOR_GRANTED))
for ns in ("kube-system", "kubeheal", "default"):
    for w in WRITERS_TO_TEST:
        EXPECT.append(("executor", w, ns, False))
EXPECT += [
    ("executor", "get secrets", "prod", False),
    ("executor", "create clusterrolebindings.rbac.authorization.k8s.io", None, False),
    ("executor", "delete namespaces", None, False),
    ("executor", "list pods", None, True),
]


def can_i(sa: str, what: str, ns):
    cmd = ["kubectl", "--context", CONTEXT, "auth", "can-i", *what.split(),
           f"--as={NS_PREFIX}{sa}"]
    cmd += ["-n", ns] if ns else ["--all-namespaces"] if what.split()[0] in ("list", "watch") else []
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r.stdout.strip().startswith("yes")


def cluster_reachable() -> bool:
    try:
        r = subprocess.run(["kubectl", "--context", CONTEXT, "get", "--raw", "/readyz"],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def crd_installed(name: str) -> bool:
    r = subprocess.run(["kubectl", "--context", CONTEXT, "get", "crd", name],
                       capture_output=True, text=True, timeout=20)
    return r.returncode == 0


def run_checks():
    failures = []
    snapshots = crd_installed("volumesnapshots.snapshot.storage.k8s.io")
    if not snapshots:
        print("note: VolumeSnapshot CRD not installed yet (done in P10); snapshot checks skipped")
    for sa, what, ns, want in EXPECT:
        if not snapshots and "volumesnapshots" in what:
            continue
        got = can_i(sa, what, ns)
        if got != want:
            failures.append(f"{sa}: can-i {what} in {ns or 'cluster'} = {got}, expected {want}")
    return failures


if __name__ == "__main__":
    if not cluster_reachable():
        print(f"cluster context {CONTEXT} is not reachable", file=sys.stderr)
        sys.exit(2)
    bad = run_checks()
    print(f"{len(EXPECT)} checks, {len(bad)} failures")
    for b in bad:
        print("FAIL", b)
    sys.exit(1 if bad else 0)

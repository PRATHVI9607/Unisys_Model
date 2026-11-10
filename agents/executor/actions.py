"""
Kubernetes write actions - the ONLY module in KubeHeal that may call a Kubernetes write API.
=============================================================================================
P1 moves every write call here so that "no write call outside the Executor" can be checked
mechanically (tests/test_no_writes_outside_executor.py). P2 turns this package into the
Executor service with its own ServiceAccount; P7 replaces the namespace-wide quarantine with the
labelled-pod quarantine and adds the snapshot / restore paths.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

QUARANTINE_POLICY_NAME = "kubeheal-quarantine"


def quarantine_policy_manifest() -> dict:
    """Egress NetworkPolicy used as the interim containment (replaced in P7)."""
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": QUARANTINE_POLICY_NAME},
        "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                 "egress": [{"to": [{"podSelector": {}}]}]},
    }


async def contain(core_api, networking_api, namespace: str, pod: str) -> str:
    """Contain a pod: egress quarantine, then delete the pod. Returns an outcome string."""
    if not core_api or not networking_api:
        logger.warning("No kube client - containment not executed")
        return "no_kube_client"
    try:
        await networking_api.create_namespaced_network_policy(
            namespace, quarantine_policy_manifest())
    except Exception as e:
        if "already exists" not in str(e).lower() and "conflict" not in str(e).lower():
            logger.warning(f"quarantine policy: {e}")
    try:
        await core_api.delete_namespaced_pod(pod, namespace, grace_period_seconds=0)
        logger.warning(f"CONTAIN: deleted pod {namespace}/{pod}")
        return "contained"
    except Exception as e:
        logger.error(f"CONTAIN failed for {namespace}/{pod}: {e}")
        return f"contain_failed:{e}"


async def patch_to_baseline(apps_api, namespace: str, deployment: str,
                            baseline: Optional[dict]) -> str:
    """Restore a Deployment's pod template to the recorded golden baseline."""
    if not apps_api:
        logger.warning("No kube client - patch not executed")
        return "no_kube_client"
    if not baseline:
        logger.info(f"No baseline for {namespace}/{deployment}; escalating to human")
        return "no_baseline_escalated"
    try:
        body = {"spec": {"template": baseline.get("template", baseline)}}
        await apps_api.patch_namespaced_deployment(deployment, namespace, body)
        logger.info(f"PATCH: restored {namespace}/{deployment} to baseline")
        return "patched_to_baseline"
    except Exception as e:
        logger.error(f"PATCH failed for {namespace}/{deployment}: {e}")
        return f"patch_failed:{e}"

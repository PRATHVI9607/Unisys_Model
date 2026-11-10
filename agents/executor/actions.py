"""
Kubernetes write actions - the ONLY module in KubeHeal that may call a Kubernetes write API.
=============================================================================================
Every write goes through `_write(gate, ...)`, which asks the kill-switch gate immediately before the
call (S-KS-3). A blocked write raises ModeBlocked; the action function turns that into:

  * "DRY RUN: would have ..."  when nothing was written yet (mode `test` the whole time), or
  * "stopped_mode_test: ..."   when the mode flipped to `test` mid-action: the next step is not run
    and the caller escalates to a human (S-KS-5).

tests/test_no_writes_outside_executor.py proves that no write call exists outside this package and
that inside it every write method is only ever passed to `_write`, never called directly.
P7 replaces the namespace-wide quarantine with the labelled-pod quarantine and adds the snapshot
and restore paths.
"""

import logging
from typing import Awaitable, Callable, List, Optional

logger = logging.getLogger(__name__)

QUARANTINE_POLICY_NAME = "kubeheal-quarantine"


class ModeBlocked(Exception):
    """The kill-switch gate refused a write."""

    def __init__(self, step: str):
        super().__init__(step)
        self.step = step


def quarantine_policy_manifest() -> dict:
    """Egress NetworkPolicy used as the interim containment (replaced in P7)."""
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": QUARANTINE_POLICY_NAME},
        "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                 "egress": [{"to": [{"podSelector": {}}]}]},
    }


async def _write(gate, namespace: str, step: str, fn: Callable[..., Awaitable], *args, **kwargs):
    """The single choke point for Kubernetes writes. `gate.allow_write(namespace)` is evaluated
    right before the call, so a mode switch between two steps stops the second one. A missing
    gate blocks (fail safe)."""
    if gate is None or not gate.allow_write(namespace):
        if gate is not None and hasattr(gate, "record_step"):
            await gate.record_step(namespace, step, "blocked_by_kill_switch")
        raise ModeBlocked(step)
    try:
        result = await fn(*args, **kwargs)
    except Exception as exc:
        if hasattr(gate, "record_step"):
            await gate.record_step(namespace, step, f"failed: {exc}")
        raise
    if hasattr(gate, "record_step"):
        await gate.record_step(namespace, step, "succeeded")
    return result


def _blocked_outcome(what: str, planned: List[str], done: List[str], blocked: ModeBlocked) -> str:
    if not done:
        return f"DRY RUN: would have {what} ({', '.join(planned)})"
    return (f"stopped_mode_test: mode switched to test before '{blocked.step}'; "
            f"completed {done}; escalated to HUMAN")


async def contain(gate, core_api, networking_api, namespace: str, pod: str) -> str:
    """Contain a pod: egress quarantine, then delete the pod."""
    planned = ["create_quarantine_policy", "delete_pod"]
    what = f"CONTAIN {namespace}/{pod}"
    if not core_api or not networking_api:
        logger.warning("No kube client - containment not executed")
        return "no_kube_client"
    done: List[str] = []
    try:
        try:
            await _write(gate, namespace, planned[0],
                         networking_api.create_namespaced_network_policy,
                         namespace, quarantine_policy_manifest())
            done.append(planned[0])
        except ModeBlocked:
            raise
        except Exception as e:
            if "already exists" not in str(e).lower() and "conflict" not in str(e).lower():
                # Containment without isolation is not containment: stop before deleting the pod.
                logger.error(f"quarantine policy failed for {namespace}/{pod}: {e}")
                return f"contain_failed:quarantine_policy:{e}"
            done.append(planned[0])
        await _write(gate, namespace, planned[1], core_api.delete_namespaced_pod,
                     pod, namespace, grace_period_seconds=0)
        done.append(planned[1])
        logger.warning(f"CONTAIN: deleted pod {namespace}/{pod}")
        return "contained"
    except ModeBlocked as b:
        return _blocked_outcome(what, planned, done, b)
    except Exception as e:
        logger.error(f"CONTAIN failed for {namespace}/{pod}: {e}")
        return f"contain_failed:{e}"


async def patch_to_baseline(gate, apps_api, namespace: str, deployment: str,
                            baseline: Optional[dict]) -> str:
    """Restore a Deployment's pod template to the recorded golden baseline."""
    if not apps_api:
        logger.warning("No kube client - patch not executed")
        return "no_kube_client"
    if not baseline:
        logger.info(f"No baseline for {namespace}/{deployment}; escalating to human")
        return "no_baseline_escalated"
    planned = ["patch_deployment"]
    try:
        body = {"spec": {"template": baseline.get("template", baseline)}}
        await _write(gate, namespace, planned[0], apps_api.patch_namespaced_deployment,
                     deployment, namespace, body)
        logger.info(f"PATCH: restored {namespace}/{deployment} to baseline")
        return "patched_to_baseline"
    except ModeBlocked as b:
        return _blocked_outcome(f"PATCH {namespace}/{deployment}", planned, [], b)
    except Exception as e:
        logger.error(f"PATCH failed for {namespace}/{deployment}: {e}")
        return f"patch_failed:{e}"

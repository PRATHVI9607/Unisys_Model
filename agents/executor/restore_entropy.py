"""Run a read-only scan of restored PVCs before the Executor lifts quarantine."""

import asyncio
import json
import logging
import math
import re
import uuid
from typing import Dict, List, Optional

from agents.executor.actions import _write
from agents.executor.support import to_dict

logger = logging.getLogger(__name__)


def _job_name(incident_id: str) -> str:
    suffix = uuid.uuid4().hex[:8]
    base = re.sub(r"[^a-z0-9-]", "-", (incident_id or "incident").lower()).strip("-")
    return f"kubeheal-entropy-{base[:37]}-{suffix}"


SCAN_APP_LABEL = "kubeheal-restore-entropy"


async def scan_node(core_api, namespace: str, pvcs: List[str]) -> Optional[str]:
    """Node the scan Job must run on, or None for no pin.

    A ReadWriteOnce volume (and a CSI hostpath volume on k3d) can only be reached from the node where the
    pod that mounts it runs. So find a pod of the namespace that mounts each scanned PVC and take its
    `spec.nodeName`. Every scanned PVC must resolve to the same single node; if one PVC has no running
    pod, or the PVCs sit on different nodes, or the lookup fails, no pin is set (the Job is scheduled
    freely, as before). Earlier scan Jobs are not counted. Needs only `list pods` (read)."""
    try:
        listing = to_dict(await core_api.list_namespaced_pod(namespace))
    except Exception as exc:
        logger.warning("scan node lookup failed, scanning without a node pin: %s", type(exc).__name__)
        return None
    nodes_by_claim: Dict[str, set] = {claim: set() for claim in pvcs}
    for raw in listing.get("items") or []:
        pod = to_dict(raw)
        meta, spec, status = pod.get("metadata") or {}, pod.get("spec") or {}, pod.get("status") or {}
        if (meta.get("labels") or {}).get("app") == SCAN_APP_LABEL or meta.get("deletionTimestamp"):
            continue
        if status.get("phase") in ("Succeeded", "Failed") or not spec.get("nodeName"):
            continue
        for volume in spec.get("volumes") or []:
            claim = (volume.get("persistentVolumeClaim") or {}).get("claimName")
            if claim in nodes_by_claim:
                nodes_by_claim[claim].add(spec["nodeName"])
    if not pvcs or any(not nodes for nodes in nodes_by_claim.values()):
        return None
    nodes = set().union(*nodes_by_claim.values())
    if len(nodes) != 1:
        logger.warning("scanned PVCs resolve to different nodes %s, scanning without a node pin", sorted(nodes))
        return None
    return next(iter(nodes))


def job_body(name: str, incident_id: str, image: str, pvcs: List[str], timeout_s: float,
             image_pull_secrets: Optional[List[str]] = None, node_name: Optional[str] = None) -> Dict:
    mounts, volumes, roots = [], [], []
    for index, claim in enumerate(pvcs):
        volume = f"restore-volume-{index}"
        mount = f"/restore/{index}"
        volumes.append({"name": volume, "persistentVolumeClaim": {"claimName": claim, "readOnly": True}})
        mounts.append({"name": volume, "mountPath": mount, "readOnly": True})
        roots.append(mount)
    deadline = max(1, int(math.ceil(timeout_s)))
    pod_spec = {"restartPolicy": "Never", "automountServiceAccountToken": False,
                "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "scanner", "image": image,
                  "imagePullPolicy": "IfNotPresent",
                  "command": ["python", "-m", "agents.executor.entropy_probe", *roots],
                  "securityContext": {"allowPrivilegeEscalation": False,
                                      "readOnlyRootFilesystem": True,
                                      "capabilities": {"drop": ["ALL"]}},
                  # CPU and memory requests and limits: chosen default, not measured.
                  "resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {"cpu": "500m", "memory": "256Mi"}},
                  "volumeMounts": mounts}], "volumes": volumes}
    if node_name:
        pod_spec["nodeName"] = node_name
    if image_pull_secrets:
        pod_spec["imagePullSecrets"] = [{"name": secret} for secret in image_pull_secrets]
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "labels": {"app": "kubeheal-restore-entropy",
                    "kubeheal/incident": incident_id}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": deadline,
                 "ttlSecondsAfterFinished": deadline,
                 "template": {"metadata": {"labels": {"app": "kubeheal-restore-entropy",
                               "kubeheal/incident": incident_id}},
                   "spec": pod_spec}}}


async def _job_state(batch_api, namespace: str, name: str):
    job = await batch_api.read_namespaced_job(name, namespace)
    status = getattr(job, "status", None)
    if status is None and isinstance(job, dict):
        status = job.get("status", {})
    status = status or {}
    succeeded = status.get("succeeded", 0) if isinstance(status, dict) else getattr(status, "succeeded", 0)
    failed = status.get("failed", 0) if isinstance(status, dict) else getattr(status, "failed", 0)
    return "succeeded" if succeeded else "failed" if failed else None


async def _scan_result(core_api, namespace: str, name: str):
    pods = await core_api.list_namespaced_pod(namespace, label_selector=f"batch.kubernetes.io/job-name={name}")
    items = pods.get("items", []) if isinstance(pods, dict) else getattr(pods, "items", [])
    if not items:
        return None
    pod = items[0]
    metadata = pod.get("metadata", {}) if isinstance(pod, dict) else getattr(pod, "metadata", None)
    pod_name = metadata.get("name") if isinstance(metadata, dict) else getattr(metadata, "name", None)
    if not pod_name:
        return None
    raw = await core_api.read_namespaced_pod_log(pod_name, namespace, container="scanner")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    for line in reversed(str(raw).splitlines()):
        try:
            result = json.loads(line)
        except ValueError:
            continue
        if result.get("verdict") in {"clean", "high_entropy", "unknown"}:
            return result
    return None


async def check_restored_pvcs(core_api, batch_api, gate, namespace: str, incident_id: str,
                              pvcs: List[str], image: Optional[str], timeout_s: float,
                              poll_s: float, sleep=asyncio.sleep,
                              image_pull_secrets: Optional[List[str]] = None):
    """Return structured verdict. Every incomplete/error case is unknown and remains isolated."""
    if not image or not pvcs or core_api is None or batch_api is None:
        return {"clean": None, "reason": "scanner image, PVCs, or Kubernetes client unavailable"}
    name = _job_name(incident_id)
    node_name = await scan_node(core_api, namespace, pvcs)
    body = job_body(name, incident_id, image, pvcs, timeout_s, image_pull_secrets, node_name)
    try:
        await _write(gate, namespace, "create_restore_entropy_job",
                     batch_api.create_namespaced_job, namespace, body)
    except Exception as exc:
        logger.warning("restore entropy Job could not be created: %s", exc)
        return {"clean": None, "reason": f"job_create_failed: {exc}"}

    deadline = asyncio.get_running_loop().time() + timeout_s
    result = None
    try:
        while asyncio.get_running_loop().time() < deadline:
            state = await _job_state(batch_api, namespace, name)
            if state in {"succeeded", "failed"}:
                result = await _scan_result(core_api, namespace, name)
                if result is None:
                    return {"clean": None, "reason": "scanner result unavailable", "job": name}
                if state == "succeeded" and result.get("verdict") == "clean" \
                        and result.get("files_scanned", 0) > 0 and result.get("unreadable", 1) == 0:
                    return {**result, "clean": True, "job": name}
                if result.get("verdict") == "high_entropy":
                    return {**result, "clean": False, "job": name}
                return {**result, "clean": None, "job": name}
            await sleep(min(poll_s, max(0.0, deadline - asyncio.get_running_loop().time())))
        return {"clean": None, "reason": "scanner timed out", "job": name}
    except Exception as exc:
        logger.warning("restore entropy scan failed: %s", exc)
        return {"clean": None, "reason": f"scan_failed: {exc}", "job": name}
    finally:
        try:
            await _write(gate, namespace, "delete_restore_entropy_job",
                         batch_api.delete_namespaced_job, name, namespace,
                         propagation_policy="Background")
        except Exception as exc:
            # The Job TTL is the fallback cleanup path; this never changes the entropy verdict.
            logger.warning("restore entropy Job cleanup deferred to TTL: %s", exc)

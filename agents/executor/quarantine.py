"""
Ransomware step 1: quarantine and forensic snapshot (S-RR-2, S-RR-3, P7-RR-4).
================================================================================
Order of writes (each one through `_write`, so the kill switch can stop between any two):

  1. create the deny-all NetworkPolicy of this incident. It selects ONLY pods that carry both
     `kubeheal/quarantine=true` and `kubeheal/incident=<id>`, so it quarantines the labelled pod and
     nothing else in the namespace, and lifting one incident never un-quarantines another.
     (It replaces the interim policy with `podSelector: {}`.)
  2. label the target pod.
  3. on-demand forensic VolumeSnapshot of every PVC the pod mounts (never pruned).

The pod is NOT deleted: its ReplicaSet would remount the same encrypted volume. Removing the workload
is the restore path (scale to zero). Rolling snapshots of the pod's PVCs are frozen so they are not
rotated out by encrypted data.
"""

import logging
from typing import Dict, List, Optional

from agents.executor.actions import ModeBlocked, _blocked_outcome, _write
from agents.executor.config import ConfigMissing, ExecConfig
from agents.executor.snapshots import (GROUP, KIND_FORENSIC, PLURAL, VERSION, SnapshotFreeze,
                                       volume_snapshot)
from agents.executor.support import Recorder, to_dict
from agents.executor.validation import Request

logger = logging.getLogger(__name__)

QUARANTINE_LABEL = "kubeheal/quarantine"
INCIDENT_LABEL = "kubeheal/incident"


def policy_name(incident_id: str) -> str:
    return f"kubeheal-quarantine-{incident_id}"


def quarantine_policy(incident_id: str) -> Dict:
    """Deny-all in both directions (no ingress and no egress rules) for the labelled pod only."""
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": policy_name(incident_id),
                     "labels": {INCIDENT_LABEL: incident_id, "app.kubernetes.io/managed-by": "kubeheal"}},
        "spec": {"podSelector": {"matchLabels": {QUARANTINE_LABEL: "true", INCIDENT_LABEL: incident_id}},
                 "policyTypes": ["Ingress", "Egress"]},
    }


def quarantine_labels(incident_id: str) -> Dict[str, str]:
    return {QUARANTINE_LABEL: "true", INCIDENT_LABEL: incident_id}


def pod_pvc_claims(pod: Dict) -> Dict[str, str]:
    """{volume name: claim name} for the PVC volumes of a pod."""
    out = {}
    for v in ((pod.get("spec") or {}).get("volumes") or []):
        claim = (v.get("persistentVolumeClaim") or {}).get("claimName")
        if claim:
            out[v["name"]] = claim
    return out


async def workload_owns_pod(apps_api, namespace: str, pod: Dict, workload: str, kind: str) -> bool:
    """ownerReferences are the authority: Pod -> ReplicaSet -> Deployment, or Pod -> StatefulSet."""
    for ref in ((pod.get("metadata") or {}).get("ownerReferences") or []):
        if kind == "StatefulSet" and ref.get("kind") == "StatefulSet" and ref.get("name") == workload:
            return True
        if kind == "Deployment" and ref.get("kind") == "ReplicaSet":
            rs = to_dict(await apps_api.read_namespaced_replica_set(ref["name"], namespace))
            for rref in ((rs.get("metadata") or {}).get("ownerReferences") or []):
                if rref.get("kind") == "Deployment" and rref.get("name") == workload:
                    return True
    return False


def _already_exists(e: Exception) -> bool:
    s = str(e).lower()
    return "already exists" in s or "conflict" in s or getattr(e, "status", None) == 409


async def contain(gate, core_api, networking_api, apps_api, custom_api, req: Request, record: Recorder,
                  cfg: Optional[ExecConfig] = None, freeze: Optional[SnapshotFreeze] = None) -> str:
    ns, pod_name = req.namespace, req.pod
    what = f"CONTAIN {ns}/{pod_name}"
    planned = ["create_quarantine_policy", "label_pod", "forensic_snapshot"]
    if not core_api or not networking_api:
        logger.warning("No kube client - containment not executed")
        return "no_kube_client"
    cfg = cfg or ExecConfig()
    done: List[str] = []
    gaps: List[str] = []
    try:
        try:
            await _write(gate, ns, planned[0], networking_api.create_namespaced_network_policy,
                         ns, quarantine_policy(req.incident_id))
        except ModeBlocked:
            raise
        except Exception as e:
            if not _already_exists(e):
                logger.error(f"quarantine policy failed for {ns}/{pod_name}: {e}")
                await record("quarantine_policy_failed", {"error": str(e)})
                return f"contain_failed:quarantine_policy:{e}"
        done.append(planned[0])
        await record("quarantine_policy_created", {"policy": policy_name(req.incident_id)})

        pod = to_dict(await core_api.read_namespaced_pod(pod_name, ns))
        if req.deployment and apps_api is not None and not await workload_owns_pod(
                apps_api, ns, pod, req.deployment, req.kind):
            await record("ownership_mismatch", {"pod": pod_name, "workload": req.deployment})
            return (f"contain_failed:pod {pod_name} is not owned by {req.kind} {req.deployment} "
                    f"(policy {policy_name(req.incident_id)} was created and selects no pod)")

        await _write(gate, ns, planned[1], core_api.patch_namespaced_pod, pod_name, ns,
                     {"metadata": {"labels": quarantine_labels(req.incident_id)}})
        done.append(planned[1])
        await record("pod_labelled", {"pod": pod_name, "labels": quarantine_labels(req.incident_id)})

        claims = sorted(set(pod_pvc_claims(pod).values()))
        if freeze is not None:
            for c in claims:
                try:
                    await freeze.freeze(ns, c, req.incident_id)
                except Exception as e:
                    gaps.append(f"freeze {c}: {e}")
            await record("rolling_snapshots_frozen", {"pvcs": claims})
        if not claims:
            await record("forensic_snapshot_skipped", {"reason": "pod mounts no PVC"})
        else:
            try:
                klass = cfg.snapshot_class
            except ConfigMissing as e:
                gaps.append(f"forensic snapshot: {e.name} not set")
                klass = None
            for c in claims if klass else []:
                sname = f"kubeheal-forensic-{c}-{req.incident_id}"
                try:
                    await _write(gate, ns, planned[2], custom_api.create_namespaced_custom_object,
                                 GROUP, VERSION, ns, PLURAL,
                                 volume_snapshot(sname, ns, c, klass, KIND_FORENSIC,
                                                 {INCIDENT_LABEL: req.incident_id}))
                    done.append(planned[2])
                    await record("forensic_snapshot_created", {"pvc": c, "snapshot": sname})
                except ModeBlocked:
                    raise
                except Exception as e:
                    if not _already_exists(e):
                        gaps.append(f"forensic snapshot of {c}: {e}")
                        await record("forensic_snapshot_failed", {"pvc": c, "error": str(e)})
        if gaps:
            return f"contained_with_gaps:{'; '.join(gaps)}"
        return "contained"
    except ModeBlocked as b:
        await record("blocked", {"step": b.step})
        return _blocked_outcome(what, planned, done, b)
    except Exception as e:
        logger.error(f"CONTAIN failed for {ns}/{pod_name}: {e}")
        await record("contain_error", {"error": str(e)})
        return f"contain_failed:{e}"

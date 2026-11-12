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

import asyncio
import logging
import time
from typing import Dict, List, Optional

from agents.executor.actions import ModeBlocked, _blocked_outcome, _write
from agents.executor.config import ConfigMissing, ExecConfig
from agents.executor.freeze import FREEZE_LABELS, request_freeze
from agents.executor.ledger_guard import LedgerUnavailable
from agents.executor.snapshots import (GROUP, KIND_FORENSIC, PLURAL, VERSION, SnapshotFreeze,
                                       volume_snapshot)
from agents.executor.support import Recorder, poll_until, to_dict
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
    if isinstance(e, LedgerUnavailable):      # its text can contain "conflict"; it is never "already exists"
        return False
    s = str(e).lower()
    return "already exists" in s or "conflict" in s or getattr(e, "status", None) == 409


async def contain(gate, core_api, networking_api, apps_api, custom_api, req: Request, record: Recorder,
                  cfg: Optional[ExecConfig] = None, freeze: Optional[SnapshotFreeze] = None,
                  redis=None, sleep=asyncio.sleep, clock=time.monotonic) -> str:
    """Containment, in the order the owner fixed (V5-S5, D5 and Q2):

      1. freeze the pod's cgroup (request to the node-local Security Agent, bounded wait, verified answer);
      2. forensic snapshot of the pod's PVCs (and the rolling snapshots are frozen);
      3. quarantine (deny-all NetworkPolicy plus the pod label);
      4. scale the owner to zero, for an `exfiltration` containment (restore_after false) only. For
         `ransomware` the scale to zero is the first mutation of the restore request that Fusion queues right
         after the `contained` result; if no restore can be requested (T0 unknown, protected namespace), the
         pod stays frozen and quarantined and a human is told (decision recorded in PROGRESS).

    The freeze runs for the two automatic labels only (`containment_label`); a human-approved containment of
    anything else keeps the earlier behaviour (no freeze, no scale). A freeze that is NOT confirmed does not
    stop the chain (the snapshot, quarantine and scale still protect the volume and the network): it is
    reported as the gap `freeze_unconfirmed`, so the outcome is `contained_with_gaps` and Fusion requests no
    restore (a pod is never restored automatically without a confirmed freeze).
    """
    ns, pod_name = req.namespace, req.pod
    what = f"CONTAIN {ns}/{pod_name}"
    label = req.containment_label
    freezing = label in FREEZE_LABELS
    scale_after = freezing and not req.restore_after
    planned = (["request_freeze"] if freezing else []) + ["forensic_snapshot", "create_quarantine_policy",
                                                          "label_pod"] + (["scale_to_zero"] if scale_after else [])
    if not core_api or not networking_api or (req.deployment and not apps_api):
        logger.warning("No kube client - containment not executed")
        return "no_kube_client"
    cfg = cfg or ExecConfig()
    done: List[str] = []
    gaps: List[str] = []
    try:
        # Verify the target before anything is written. A wrong pod/workload pair must not leave
        # namespace state behind, even when the policy selector would currently match no pod.
        pod = to_dict(await core_api.read_namespaced_pod(pod_name, ns))
        kinds = [req.kind] if req.kind_given else ["Deployment", "StatefulSet"]
        if req.deployment and apps_api is not None and not any(
                [await workload_owns_pod(apps_api, ns, pod, req.deployment, k) for k in kinds]):
            await record("ownership_mismatch", {"pod": pod_name, "workload": req.deployment})
            return f"contain_failed:pod {pod_name} is not owned by {'/'.join(kinds)} {req.deployment}"

        # 1. freeze
        if freezing:
            if redis is None:
                gaps.append("freeze_unconfirmed:no redis for the freeze request")
                await record("freeze_unconfirmed", {"reason": "no_redis"})
            else:
                try:
                    timeout_s = cfg.freeze_timeout_s
                except ConfigMissing as e:
                    timeout_s = None
                    gaps.append(f"freeze_unconfirmed:config {e.name}")
                    await record("freeze_unconfirmed", {"reason": f"config {e.name}"})
                if timeout_s is not None:
                    outcome = await request_freeze(gate, redis, ns, req.incident_id, pod, label, timeout_s,
                                                   sleep, clock)
                    if outcome.request_id:
                        done.append("request_freeze")
                    if outcome.confirmed:
                        await record("freeze_confirmed", {"node": outcome.node, "request_id": outcome.request_id,
                                                          "cgroup": outcome.result.get("cgroup", ""),
                                                          "mode_seen": outcome.result.get("mode_seen", "")})
                    else:
                        gaps.append(f"freeze_unconfirmed:{outcome.reason}")
                        await record("freeze_unconfirmed", {"reason": outcome.reason, "node": outcome.node,
                                                            "request_id": outcome.request_id,
                                                            "result": outcome.result})
        else:
            await record("freeze_skipped", {"reason": "no automatic containment label", "label": label})

        # 2. forensic snapshot
        claims = sorted(set(pod_pvc_claims(pod).values()))
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
                    await _write(gate, ns, "forensic_snapshot", custom_api.create_namespaced_custom_object,
                                 GROUP, VERSION, ns, PLURAL,
                                 volume_snapshot(sname, ns, c, klass, KIND_FORENSIC,
                                                 {INCIDENT_LABEL: req.incident_id}))
                    done.append("forensic_snapshot")
                    await record("forensic_snapshot_created", {"pvc": c, "snapshot": sname})
                except (ModeBlocked, LedgerUnavailable):
                    raise
                except Exception as e:
                    if not _already_exists(e):
                        gaps.append(f"forensic snapshot of {c}: {e}")
                        await record("forensic_snapshot_failed", {"pvc": c, "error": str(e)})

        # 3. quarantine
        try:
            await _write(gate, ns, "create_quarantine_policy", networking_api.create_namespaced_network_policy,
                         ns, quarantine_policy(req.incident_id))
        except (ModeBlocked, LedgerUnavailable):
            raise
        except Exception as e:
            if not _already_exists(e):
                logger.error(f"quarantine policy failed for {ns}/{pod_name}: {e}")
                await record("quarantine_policy_failed", {"error": str(e)})
                return f"contain_failed:quarantine_policy:{e}"
        done.append("create_quarantine_policy")
        await record("quarantine_policy_created", {"policy": policy_name(req.incident_id)})

        await _write(gate, ns, "label_pod", core_api.patch_namespaced_pod, pod_name, ns,
                     {"metadata": {"labels": quarantine_labels(req.incident_id)}})
        done.append("label_pod")
        await record("pod_labelled", {"pod": pod_name, "labels": quarantine_labels(req.incident_id)})
        # The rolling snapshots are frozen (so nothing prunes the history) only after a gated write succeeded:
        # this is a Redis marker, and a dry run must not write even that.
        if freeze is not None:
            for c in claims:
                try:
                    await freeze.freeze(ns, c, req.incident_id)
                except Exception as e:
                    gaps.append(f"freeze {c}: {e}")
            await record("rolling_snapshots_frozen", {"pvcs": claims})

        # 4. scale to zero (exfiltration; for ransomware the restore request does it)
        if scale_after:
            gap = await _scale_to_zero(gate, apps_api, req, record, done, cfg, sleep, clock)
            if gap:
                gaps.append(gap)
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


async def _scale_to_zero(gate, apps_api, req: Request, record: Recorder, done: List[str], cfg: ExecConfig,
                         sleep, clock) -> str:
    """Remember the replica count in the annotation the restore path reads, then scale the owner to zero.
    Returns "" or the gap text. The same helpers (and the same gated writes) as the restore path."""
    from agents.executor import restore as _restore          # lazy: restore imports this module
    ns, name, kind = req.namespace, req.deployment, req.kind
    if not (name and apps_api):
        await record("scale_to_zero_skipped", {"reason": "no owning workload named"})
        return "scale_to_zero: no owning workload named"
    wl = await _restore._read_workload(apps_api, kind, ns, name)
    replicas = (wl.get("spec") or {}).get("replicas", 1)
    if replicas == 0:
        await record("scale_to_zero_skipped", {"reason": "already at zero"})
        return ""
    annotations = (wl.get("metadata") or {}).get("annotations") or {}
    if not str(annotations.get(_restore.REPLICAS_ANNOTATION, "")).isdigit():
        await _restore._patch_workload(gate, apps_api, kind, ns, name, "remember_replicas",
                                       {"metadata": {"annotations": {_restore.REPLICAS_ANNOTATION: str(replicas)}}})
        done.append("remember_replicas")
        await record("replicas_remembered", {"replicas": replicas})
    await _restore._scale_workload(gate, apps_api, kind, ns, name, "scale_to_zero", 0)
    done.append("scale_to_zero")
    await record("scaled_to_zero", {"replicas_before": replicas})
    try:
        timeout_s, poll_s = cfg.rollout_timeout_s, cfg.rollout_poll_s
    except ConfigMissing as e:
        return f"scale_to_zero: settle check skipped, config {e.name} not set"
    if not await poll_until(lambda: _restore._scaled_to(apps_api, kind, ns, name, 0), timeout_s, poll_s,
                            sleep, clock):
        await record("scale_down_timeout", {})
        return f"scale_to_zero: {kind} {name} did not settle at zero in time"
    return ""

"""
Ransomware step 2: restore from a pre-T0 snapshot (S-RR-4 .. S-RR-7, P7-RR-5, P7-RR-6).
=========================================================================================
Everything the path needs is READ before the first write, because the pods disappear once the
workload is scaled to zero: workload and replicas, the pod's owner chain, its PVC claims, the image
digests it actually ran, the source PVC specs and the candidate snapshots. Any gap ends in
`escalated:<reason>` with nothing written. T0 comes from the request (`t0_ms`); the Executor never
guesses it.

Writes (each one through `_write`, so the kill switch can stop between any two):
  1 ensure the incident's deny-all NetworkPolicy exists
  2 remember the replica count (annotation `kubeheal/original-replicas`)
  3 scale the owning Deployment or StatefulSet to zero
  4 create a NEW PVC per claim from the newest ready rolling snapshot taken strictly before T0
  5 repoint the workload to the new PVCs, pin every container image by digest, and put the
    quarantine labels in the pod template so the restored pods start isolated
  6 scale back to the remembered replica count
  7 re-check entropy of the restored volume (injected callable). Clean: remove the labels and delete
    the policy. Not clean or unknown: keep isolated and escalate.

The old PVC is never deleted or modified (it is the evidence) and stays frozen for rolling snapshots.
A retry of a restore that stopped partway fails safe: the original pod is gone, preflight cannot read it
and escalates (`pod_not_found`) before anything is written. There is no resume action; a human decides.
A StatefulSet whose volume comes from `volumeClaimTemplates` cannot be repointed by a patch (those
templates are immutable) and RBAC grants no PVC delete, so that case escalates before any write.
After a restore the golden baseline (old claimName, image tag) no longer equals the live spec; it must
be re-baselined by an operator so the drift path does not "repair" it back to the encrypted volume.
"""

import asyncio
import logging
import re
import time
from typing import Callable, Dict, List, Optional

from agents.executor.actions import ModeBlocked, _blocked_outcome, _write
from agents.executor.config import ConfigMissing, ExecConfig
from agents.executor.quarantine import (INCIDENT_LABEL, QUARANTINE_LABEL, policy_name, pod_pvc_claims,
                                        quarantine_labels, quarantine_policy, workload_owns_pod)
from agents.executor.snapshots import (GROUP, LABEL_PVC, SnapshotFreeze, list_snapshots,
                                       select_snapshot)
from agents.executor.support import Recorder, poll_until, to_dict
from agents.executor.validation import Request

logger = logging.getLogger(__name__)

REPLICAS_ANNOTATION = "kubeheal/original-replicas"
# Only the pullable `<repo>@sha256:<64 hex>` form counts. A bare `sha256:<id>` (containerd reports the
# image config id for images loaded without a registry, e.g. `k3d image import`) is not a manifest
# digest and `repo@<id>` would not pull.
_DIGEST = re.compile(r"@(sha256:[0-9a-f]{64})")
_UNITS = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60,
          "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18, "": 1}


class Escalate(Exception):
    """Preflight found something that makes the restore unsafe; nothing has been written."""


def quantity_bytes(q) -> int:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGTPE]i|[kMGTPE])?\s*", str(q))
    if not m:
        raise Escalate(f"unparsable storage quantity {q!r}")
    return int(float(m.group(1)) * _UNITS[m.group(2) or ""])


def pin_image(image: str, digest: str) -> str:
    base = image.split("@")[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        base = base[: len(base) - len(last)] + last.split(":")[0]
    return f"{base}@{digest}"


def image_digest(image_id: str) -> Optional[str]:
    m = _DIGEST.search(image_id or "")
    return m.group(1) if m else None


async def _read_workload(apps_api, kind: str, ns: str, name: str) -> Dict:
    if kind == "StatefulSet":
        return to_dict(await apps_api.read_namespaced_stateful_set(name, ns))
    return to_dict(await apps_api.read_namespaced_deployment(name, ns))


async def _patch_workload(gate, apps_api, kind: str, ns: str, name: str, step: str, body: Dict):
    if kind == "StatefulSet":
        return await _write(gate, ns, step, apps_api.patch_namespaced_stateful_set, name, ns, body)
    return await _write(gate, ns, step, apps_api.patch_namespaced_deployment, name, ns, body)


async def _scale_workload(gate, apps_api, kind: str, ns: str, name: str, step: str, replicas: int):
    body = {"spec": {"replicas": replicas}}
    if kind == "StatefulSet":
        return await _write(gate, ns, step, apps_api.patch_namespaced_stateful_set_scale, name, ns, body)
    return await _write(gate, ns, step, apps_api.patch_namespaced_deployment_scale, name, ns, body)


async def _scaled_to(apps_api, kind, ns, name, n: int) -> bool:
    """True once the workload has no replicas left (only used with n == 0)."""
    st = (await _read_workload(apps_api, kind, ns, name)).get("status") or {}
    return (st.get("replicas") or 0) == n and (st.get("readyReplicas") or 0) == n


async def _ready(apps_api, kind, ns, name, want: int) -> bool:
    d = await _read_workload(apps_api, kind, ns, name)
    st, md = d.get("status") or {}, d.get("metadata") or {}
    return ((st.get("observedGeneration") or 0) >= (md.get("generation") or 0)
            and (st.get("updatedReplicas") or 0) >= want and (st.get("readyReplicas") or 0) >= want)


def _exists(e: Exception) -> bool:
    s = str(e).lower()
    return "already exists" in s or "conflict" in s or getattr(e, "status", None) == 409


async def _preflight(core_api, apps_api, custom_api, req: Request) -> Dict:
    ns, name, kind = req.namespace, req.deployment, req.kind
    wl = await _read_workload(apps_api, kind, ns, name)
    spec = wl.get("spec") or {}
    replicas = spec.get("replicas", 1)
    if replicas == 0:
        ann = ((wl.get("metadata") or {}).get("annotations") or {}).get(REPLICAS_ANNOTATION)
        if not (ann and str(ann).isdigit() and int(ann) > 0):
            raise Escalate("replicas_unknown: workload is already at 0 and no remembered count exists")
        replicas = int(ann)

    try:
        pod = to_dict(await core_api.read_namespaced_pod(req.pod, ns))
    except Exception as e:
        if getattr(e, "status", None) == 404 or "not found" in str(e).lower():
            # After a partial run the pod is gone (scaled to zero, or replaced by the restored pods).
            # A retry must not guess; a human decides. Nothing has been written by this attempt.
            raise Escalate(
                f"pod_not_found: pod {req.pod} no longer exists. A previous restore attempt may have left "
                f"{kind} {name} scaled to zero with annotation {REPLICAS_ANNOTATION} set (or already "
                "repointed to restored PVCs); needs human review before any retry") from e
        raise
    if not await workload_owns_pod(apps_api, ns, pod, name, kind):
        raise Escalate(f"pod_not_owned: {req.pod} is not owned by {kind} {name}")

    tmpl = (spec.get("template") or {}).get("spec") or {}
    tmpl_vols = {v["name"]: (v.get("persistentVolumeClaim") or {}).get("claimName")
                 for v in tmpl.get("volumes") or []}
    claims = pod_pvc_claims(pod)
    if not claims:
        raise Escalate("no_pvc: the pod mounts no PersistentVolumeClaim, nothing to restore")
    for vol, claim in claims.items():
        if tmpl_vols.get(vol) != claim:
            raise Escalate(f"restore_unsupported_volume_claim_template: volume {vol} ({claim}) is not a "
                           "plain PVC volume of the pod template, a patch cannot repoint it")

    pod_status = pod.get("status") or {}
    images = {"containers": {}, "initContainers": {}}
    for field, status_field in (("containers", "containerStatuses"),
                                ("initContainers", "initContainerStatuses")):
        statuses = {s.get("name"): s for s in (pod_status.get(status_field) or [])}
        for c in tmpl.get(field) or []:
            digest = image_digest((statuses.get(c["name"]) or {}).get("imageID", ""))
            if not digest:
                raise Escalate(f"image_digest_unavailable: no sha256 imageID for {field} {c['name']}")
            images[field][c["name"]] = pin_image(c["image"], digest)

    t0_s = req.t0_ms / 1000.0
    plan = {}
    for vol, claim in claims.items():
        pvc = to_dict(await core_api.read_namespaced_persistent_volume_claim(claim, ns))
        pspec = pvc.get("spec") or {}
        items = await list_snapshots(custom_api, ns, f"{LABEL_PVC}={claim}")
        snap = select_snapshot(items, claim, t0_s)
        if snap is None:
            raise Escalate(f"no_snapshot_before_t0: no ready rolling snapshot of {claim} older than T0")
        want = (pspec.get("resources") or {}).get("requests", {}).get("storage")
        restore_size = (snap.get("status") or {}).get("restoreSize")
        size = want
        if want is None or (restore_size is not None and quantity_bytes(restore_size) > quantity_bytes(want)):
            size = str(restore_size) if restore_size is not None else None
        if size is None:
            raise Escalate(f"size_unknown: neither PVC {claim} nor snapshot gives a size")
        plan[vol] = {"claim": claim, "new_claim": f"{claim}-restore-{req.incident_id}",
                     "snapshot": snap["metadata"]["name"], "size": size,
                     "access_modes": pspec.get("accessModes") or ["ReadWriteOnce"],
                     "storage_class": pspec.get("storageClassName")}
    return {"replicas": replicas, "plan": plan, "images": images}


def _pvc_body(p: Dict, req: Request) -> Dict:
    spec = {"accessModes": p["access_modes"], "resources": {"requests": {"storage": p["size"]}},
            "dataSource": {"name": p["snapshot"], "kind": "VolumeSnapshot", "apiGroup": GROUP}}
    if p["storage_class"]:
        spec["storageClassName"] = p["storage_class"]
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": p["new_claim"], "labels": {INCIDENT_LABEL: req.incident_id},
                         "annotations": {"kubeheal/restored-from-snapshot": p["snapshot"],
                                         "kubeheal/restore-t0-ms": str(req.t0_ms)}},
            "spec": spec}


async def restore(gate, core_api, apps_api, networking_api, custom_api, req: Request, record: Recorder,
                  cfg: Optional[ExecConfig] = None, freeze: Optional[SnapshotFreeze] = None,
                  entropy_check: Optional[Callable] = None, sleep: Callable = asyncio.sleep,
                  clock: Callable[[], float] = time.monotonic) -> str:
    ns, name, kind = req.namespace, req.deployment, req.kind
    what = f"RESTORE {ns}/{name}"
    planned = ["ensure_quarantine_policy", "remember_replicas", "scale_to_zero", "create_restored_pvc",
               "repoint_and_pin", "scale_back", "remove_original_replicas_annotation",
               "lift_quarantine", "delete_quarantine_policy"]
    if not (core_api and apps_api and networking_api and custom_api):
        return "no_kube_client"
    cfg = cfg or ExecConfig()
    try:
        timeout_s, poll_s = cfg.rollout_timeout_s, cfg.rollout_poll_s
    except ConfigMissing as e:
        await record("preflight_failed", {"reason": f"config {e.name}"})
        return f"escalated:config_missing:{e.name}"
    try:
        pre = await _preflight(core_api, apps_api, custom_api, req)
    except Escalate as e:
        await record("preflight_failed", {"reason": str(e)})
        return f"escalated:{e}"
    except Exception as e:
        await record("preflight_failed", {"error": str(e)})
        return f"escalated:preflight_error:{e}"
    plan, replicas, images = pre["plan"], pre["replicas"], pre["images"]
    await record("preflight_ok", {"t0_ms": req.t0_ms, "replicas": replicas, "images": images,
                                  "restore": {v: {k: p[k] for k in ("claim", "new_claim", "snapshot")}
                                              for v, p in plan.items()}})

    done: List[str] = []
    try:
        try:
            await _write(gate, ns, planned[0], networking_api.create_namespaced_network_policy,
                         ns, quarantine_policy(req.incident_id))
        except ModeBlocked:
            raise
        except Exception as e:
            if not _exists(e):
                await record("quarantine_policy_failed", {"error": str(e)})
                return f"restore_failed:quarantine_policy:{e}; nothing else was changed"
        done.append(planned[0])
        await record("quarantine_policy_ensured", {"policy": policy_name(req.incident_id)})

        await _patch_workload(gate, apps_api, kind, ns, name, planned[1],
                              {"metadata": {"annotations": {REPLICAS_ANNOTATION: str(replicas)}}})
        done.append(planned[1])
        await record("replicas_remembered", {"replicas": replicas})

        await _scale_workload(gate, apps_api, kind, ns, name, planned[2], 0)
        done.append(planned[2])
        await record("scaled_to_zero", {})
        if not await poll_until(lambda: _scaled_to(apps_api, kind, ns, name, 0), timeout_s, poll_s, sleep, clock):
            await record("scale_down_timeout", {})
            return (f"restore_failed:scale to zero did not settle in time; completed {done}; "
                    f"replicas {replicas} remembered in annotation {REPLICAS_ANNOTATION}; escalated to HUMAN")

        for p in plan.values():
            if freeze is not None:
                await freeze.freeze(ns, p["new_claim"], req.incident_id)
            try:
                await _write(gate, ns, planned[3], core_api.create_namespaced_persistent_volume_claim,
                             ns, _pvc_body(p, req))
            except ModeBlocked:
                raise
            except Exception as e:
                if not _exists(e):
                    await record("restored_pvc_failed", {"pvc": p["new_claim"], "error": str(e)})
                    return (f"restore_failed:create PVC {p['new_claim']}: {e}; completed {done}; workload left "
                            f"scaled to 0 and isolated; replicas {replicas} in annotation; escalated to HUMAN")
            await record("restored_pvc_created", {"pvc": p["new_claim"], "snapshot": p["snapshot"]})
        done.append(planned[3])

        template_spec = {"volumes": [{"name": v, "persistentVolumeClaim": {"claimName": p["new_claim"]}}
                                      for v, p in plan.items()],
                         "containers": [{"name": c, "image": img}
                                        for c, img in images["containers"].items()]}
        if images["initContainers"]:
            template_spec["initContainers"] = [{"name": c, "image": img}
                                               for c, img in images["initContainers"].items()]
        await _patch_workload(gate, apps_api, kind, ns, name, planned[4], {"spec": {"template": {
            "metadata": {"labels": quarantine_labels(req.incident_id)},
            "spec": template_spec}}})
        done.append(planned[4])
        await record("repointed_and_pinned", {"volumes": {v: p["new_claim"] for v, p in plan.items()},
                                              "images": images})

        await _scale_workload(gate, apps_api, kind, ns, name, planned[5], replicas)
        done.append(planned[5])
        await record("scaled_back", {"replicas": replicas})
        if not await poll_until(lambda: _ready(apps_api, kind, ns, name, replicas), timeout_s, poll_s, sleep, clock):
            await record("ready_timeout", {})
            return (f"restored_kept_isolated:restored pods not ready in time; quarantine kept; "
                    f"completed {done}; escalated to HUMAN")

        new_claims = [p["new_claim"] for p in plan.values()]
        verdict = None
        if entropy_check is not None:
            try:
                verdict = await entropy_check(ns, name, new_claims)
            except Exception as e:
                await record("entropy_check_error", {"error": str(e)})
        detail = verdict if isinstance(verdict, dict) else {}
        clean = detail.get("clean") if detail else verdict
        await record("entropy_checked", {**detail, "clean": clean, "pvcs": new_claims})
        if clean is not True:
            why = "entropy still high on the restored volume" if clean is False else \
                "entropy result unknown (no check configured or the check failed)"
            return f"restored_kept_isolated:{why}; quarantine kept; escalated to HUMAN"

        # The restore marker is only needed to recover a workload that was already scaled to zero.
        # Remove it while quarantine is still in place, so a blocked write cannot expose the pod.
        await _patch_workload(gate, apps_api, kind, ns, name, planned[6],
                              {"metadata": {"annotations": {REPLICAS_ANNOTATION: None}}})
        done.append(planned[6])
        await record("original_replicas_annotation_removed", {})

        await _patch_workload(gate, apps_api, kind, ns, name, planned[7], {"spec": {"template": {
            "metadata": {"labels": {QUARANTINE_LABEL: None, INCIDENT_LABEL: None}}}}})
        done.append(planned[7])
        await record("quarantine_labels_removed", {})
        if not await poll_until(lambda: _ready(apps_api, kind, ns, name, replicas), timeout_s, poll_s, sleep, clock):
            return (f"restored_kept_isolated:rollout after lifting labels not ready in time; policy kept; "
                    f"completed {done}; escalated to HUMAN")
        await _write(gate, ns, planned[8], networking_api.delete_namespaced_network_policy,
                     policy_name(req.incident_id), ns)
        done.append(planned[8])
        if freeze is not None:
            for p in plan.values():
                await freeze.unfreeze(ns, p["new_claim"])
        await record("quarantine_lifted", {"policy": policy_name(req.incident_id)})
        return "restored"
    except ModeBlocked as b:
        await record("blocked", {"step": b.step})
        return _blocked_outcome(what, planned, done, b)
    except Exception as e:
        logger.error(f"restore failed for {ns}/{name}: {e}")
        await record("restore_error", {"error": str(e)})
        return (f"restore_failed:{e}; completed {done}; the workload may be scaled to 0 and is isolated; "
                f"replicas {replicas} in annotation {REPLICAS_ANNOTATION}; escalated to HUMAN")

"""
Rolling and forensic VolumeSnapshots (S-RR-1, S-RR-3, P7-RR-3).
================================================================
`SnapshotScheduler` is Executor-owned: every INTERVAL_S (300, from the plan) it snapshots each Bound
PVC in the protected namespaces (`guard.allowed_namespaces()`; this is the Executor's namespace set,
not the P6 `kubeheal/protected` label, which means "never automatic") and keeps the newest KEEP (12,
from the plan) rolling snapshots per PVC. The clock and sleep are injectable.

Safety rules:
  * Snapshots and deletions are Kubernetes writes, so they go through `_write` and the kill-switch
    gate. In `test` mode no rolling snapshot is taken, and a later restore will find none.
  * Retention touches only snapshots labelled `kubeheal/snapshot-kind=rolling` and never a forensic one.
  * A PVC of an open incident is FROZEN (`SnapshotFreeze`): no new snapshot and no pruning, otherwise
    after KEEP * INTERVAL_S the clean pre-T0 snapshots would be rotated out by encrypted ones.
  * The VolumeSnapshotClass is cluster specific, so it is required config (`SNAPSHOT_CLASS`).
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from agents.executor.actions import ModeBlocked, _write
from agents.executor.config import ConfigMissing, ExecConfig
from agents.executor.guard import allowed_namespaces
from agents.executor.support import Recorder, to_dict

logger = logging.getLogger(__name__)

GROUP, VERSION, PLURAL = "snapshot.storage.k8s.io", "v1", "volumesnapshots"
LABEL_KIND = "kubeheal/snapshot-kind"
LABEL_PVC = "kubeheal/source-pvc"
KIND_ROLLING, KIND_FORENSIC = "rolling", "forensic"
INTERVAL_S = 300      # every 5 minutes (IMPLEMENTATION_PLAN P7)
KEEP = 12             # keep 12 (IMPLEMENTATION_PLAN P7)
FREEZE_PREFIX = "kubeheal:snapfreeze"


def volume_snapshot(name: str, namespace: str, pvc: str, snapshot_class: str, kind: str,
                    extra_labels: Optional[Dict[str, str]] = None) -> Dict:
    labels = {LABEL_KIND: kind, LABEL_PVC: pvc, "app.kubernetes.io/managed-by": "kubeheal"}
    labels.update(extra_labels or {})
    return {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "VolumeSnapshot",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {"volumeSnapshotClassName": snapshot_class, "source": {"persistentVolumeClaimName": pvc}},
    }


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds from an ISO string or datetime; None if absent or unparsable."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def point_in_time(snap: Dict) -> Optional[float]:
    """When the data was captured: the CSI `status.creationTime`, not the object creation time."""
    return parse_time((snap.get("status") or {}).get("creationTime"))


def _order_time(snap: Dict) -> float:
    return (point_in_time(snap) or parse_time((snap.get("metadata") or {}).get("creationTimestamp")) or 0.0)


def select_snapshot(items: List[Dict], pvc: str, t0_s: float) -> Optional[Dict]:
    """Newest ready ROLLING snapshot of `pvc` whose capture time is strictly before T0."""
    best, best_t = None, None
    for s in items:
        labels = (s.get("metadata") or {}).get("labels") or {}
        if labels.get(LABEL_KIND) != KIND_ROLLING or labels.get(LABEL_PVC) != pvc:
            continue
        if (s.get("status") or {}).get("readyToUse") is not True:
            continue
        t = point_in_time(s)
        if t is None or not t < t0_s:
            continue
        if best_t is None or t > best_t:
            best, best_t = s, t
    return best


async def list_snapshots(custom_api, namespace: str, selector: str = "") -> List[Dict]:
    res = to_dict(await custom_api.list_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL,
                                                                  label_selector=selector))
    return list(res.get("items") or [])


class SnapshotFreeze:
    """Redis marks (not Kubernetes writes) that stop rolling snapshots of an incident's PVCs."""

    def __init__(self, redis):
        self.redis = redis

    @staticmethod
    def key(namespace: str, pvc: str) -> str:
        return f"{FREEZE_PREFIX}:{namespace}:{pvc}"

    async def freeze(self, namespace: str, pvc: str, incident_id: str) -> None:
        if self.redis is not None:
            await self.redis.set(self.key(namespace, pvc), incident_id)

    async def unfreeze(self, namespace: str, pvc: str) -> None:
        if self.redis is not None:
            await self.redis.delete(self.key(namespace, pvc))

    async def is_frozen(self, namespace: str, pvc: str) -> bool:
        return self.redis is not None and bool(await self.redis.get(self.key(namespace, pvc)))


class SnapshotScheduler:
    def __init__(self, core_api, custom_api, gate, namespaces: Optional[List[str]] = None,
                 cfg: Optional[ExecConfig] = None, clock: Callable[[], float] = time.time,
                 sleep: Callable = asyncio.sleep, is_frozen: Optional[Callable] = None,
                 record_step: Optional[Callable] = None, interval_s: int = INTERVAL_S, keep: int = KEEP):
        self.core_api, self.custom_api, self.gate = core_api, custom_api, gate
        self.namespaces = namespaces
        self.cfg, self.clock, self.sleep = cfg or ExecConfig(), clock, sleep
        self.is_frozen = is_frozen
        self.record_step = record_step
        self.record = Recorder(record_step, "snapshot-scheduler")
        self.interval_s, self.keep = interval_s, keep
        self.running = False

    def _namespaces(self) -> List[str]:
        return sorted(self.namespaces if self.namespaces is not None else allowed_namespaces())

    async def run_once(self) -> Dict[str, List[str]]:
        # Each scheduler cycle is a distinct operation in the append-only ledger.
        self.run_id = f"snapshot-{uuid.uuid4().hex}"
        self.record = Recorder(self.record_step, self.run_id)
        out: Dict[str, List[str]] = {"created": [], "deleted": [], "skipped": []}
        try:
            klass = self.cfg.snapshot_class
        except ConfigMissing as e:
            if not getattr(self, "_skip_recorded", False):      # once, not every cycle
                self._skip_recorded = True
                await self.record("snapshot_run_skipped", {"reason": f"config {e.name}"})
            out["skipped"].append(f"config:{e.name}")
            return out
        now = int(self.clock())
        for ns in self._namespaces():
            pvcs = to_dict(await self.core_api.list_namespaced_persistent_volume_claim(ns)).get("items") or []
            for p in pvcs:
                name = (p.get("metadata") or {}).get("name")
                if not name or (p.get("status") or {}).get("phase") != "Bound":
                    continue
                if self.is_frozen and await self.is_frozen(ns, name):
                    out["skipped"].append(f"{ns}/{name}:frozen")
                    continue
                snap = f"kubeheal-roll-{name}-{now}"
                try:
                    await _write(self.gate, ns, "create_rolling_snapshot",
                                 self.custom_api.create_namespaced_custom_object,
                                 GROUP, VERSION, ns, PLURAL,
                                 volume_snapshot(snap, ns, name, klass, KIND_ROLLING))
                    out["created"].append(f"{ns}/{snap}")
                    await self.record("rolling_snapshot_created", {"namespace": ns, "pvc": name, "snapshot": snap})
                except ModeBlocked:
                    out["skipped"].append(f"{ns}/{name}:DRY RUN: would have created snapshot {snap}")
                    await self.record("rolling_snapshot_dry_run", {"namespace": ns, "pvc": name, "snapshot": snap})
                    continue
                except Exception as e:
                    out["skipped"].append(f"{ns}/{name}:create failed:{e}")
                    logger.error(f"rolling snapshot of {ns}/{name} failed: {e}")
                    continue
                await self._prune(ns, name, out)
        return out

    async def _prune(self, ns: str, pvc: str, out: Dict[str, List[str]]) -> None:
        if self.is_frozen and await self.is_frozen(ns, pvc):
            return
        items = await list_snapshots(self.custom_api, ns, f"{LABEL_KIND}={KIND_ROLLING},{LABEL_PVC}={pvc}")
        items = [s for s in items
                 if ((s.get("metadata") or {}).get("labels") or {}).get(LABEL_KIND) == KIND_ROLLING]
        items.sort(key=_order_time, reverse=True)
        # Never delete the newest ready snapshot: if the snapshotter stalls and the newest KEEP are
        # all unready, the last usable restore point must survive.
        newest_ready = next((s for s in items if (s.get("status") or {}).get("readyToUse") is True), None)
        for s in items[self.keep:]:
            if s is newest_ready:
                continue
            sname = s["metadata"]["name"]
            try:
                await _write(self.gate, ns, "delete_old_rolling_snapshot",
                             self.custom_api.delete_namespaced_custom_object,
                             GROUP, VERSION, ns, PLURAL, sname)
                out["deleted"].append(f"{ns}/{sname}")
                await self.record("rolling_snapshot_pruned", {"namespace": ns, "pvc": pvc, "snapshot": sname})
            except ModeBlocked:
                return
            except Exception as e:
                logger.error(f"prune of {ns}/{sname} failed: {e}")

    async def run_forever(self) -> None:
        self.running = True
        next_due = self.clock()
        while self.running:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"snapshot run failed: {e}")
            next_due += self.interval_s
            await self.sleep(max(0.0, next_due - self.clock()))

    def stop(self) -> None:
        self.running = False

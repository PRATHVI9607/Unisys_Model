"""
Kill switch (S-KS-1 .. S-KS-6): modes `test` (dry run) and `enforce`.
=====================================================================
Source of truth: ConfigMap `kubeheal-mode` (namespace `kubeheal`, key `mode`), followed through the
Kubernetes Watch API, not polled. A namespace label `kubeheal/mode` can make ONE namespace stricter
(`test`) while the global mode is `enforce`. It can never turn enforcement on while the global mode is
`test`: the global switch is absolute.

Fail safe: anything that is not exactly `enforce` is `test`. If the mode has never been read, or the
last read failed (ConfigMap missing, API unreachable, no permission), the effective mode is `test`.
A fresh install ships the ConfigMap with `mode: test`.

The pure functions below are what the policy tests exercise. `ModeWatcher` only feeds them.
"""

import asyncio
import logging
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

MODE_CONFIGMAP = "kubeheal-mode"
MODE_NAMESPACE = "kubeheal"
MODE_KEY = "mode"
NAMESPACE_LABEL = "kubeheal/mode"
TEST, ENFORCE = "test", "enforce"


def normalize(value: Optional[str]) -> str:
    """Only the exact string `enforce` (any case, trimmed) enforces. Everything else is test."""
    return ENFORCE if isinstance(value, str) and value.strip().lower() == ENFORCE else TEST


def effective_mode(global_mode: Optional[str], ns_label: Optional[str], readable: bool) -> str:
    if not readable or global_mode is None:
        return TEST
    if normalize(global_mode) == TEST:
        return TEST
    if ns_label is not None and normalize(ns_label) == TEST:
        return TEST
    return ENFORCE


def is_dry_run(mode: str) -> bool:
    return normalize(mode) != ENFORCE


class ModeWatcher:
    def __init__(self, on_change: Optional[Callable[[str, str, str], None]] = None):
        self.global_mode: Optional[str] = None
        self.readable: bool = False
        self.ns_readable: bool = False   # namespace labels loaded and watch healthy
        self.ns_labels: Dict[str, str] = {}
        self.history: List[dict] = []
        self._on_change = on_change
        self._last_effective: Optional[str] = None
        self._tasks: List[asyncio.Task] = []
        self._running = False

    # ---- query -------------------------------------------------------
    def mode_for(self, namespace: Optional[str]) -> str:
        label = self.ns_labels.get(namespace) if namespace else None
        return effective_mode(self.global_mode, label, self.readable and self.ns_readable)

    def dry_run_for(self, namespace: Optional[str]) -> bool:
        return is_dry_run(self.mode_for(namespace))

    # ---- state updates (pure, unit tested) ----------------------------
    def apply_configmap(self, cm) -> None:
        data = (getattr(cm, "data", None) or {}) if cm is not None else {}
        if MODE_KEY not in data:
            self.mark_unreadable("ConfigMap has no 'mode' key")
            return
        self._set(data[MODE_KEY], True, "configmap")

    def apply_configmap_deleted(self) -> None:
        self.mark_unreadable("ConfigMap deleted")

    def apply_namespace(self, ns_obj, deleted: bool = False) -> None:
        name = ns_obj.metadata.name
        label = (ns_obj.metadata.labels or {}).get(NAMESPACE_LABEL)
        if deleted or label is None:
            self.ns_labels.pop(name, None)
        else:
            self.ns_labels[name] = label

    def mark_unreadable(self, reason: str) -> None:
        logger.warning(f"kill switch unreadable ({reason}): treating mode as 'test'")
        self._set(self.global_mode, False, f"unreadable: {reason}")

    def _set(self, value, readable: bool, source: str) -> None:
        self.global_mode, self.readable = value, readable
        new = effective_mode(self.global_mode, None, self.readable)
        if new != self._last_effective:
            entry = {"ts": time.time(), "from": self._last_effective, "to": new, "source": source}
            self.history.append(entry)
            logger.warning(f"KILL SWITCH mode {self._last_effective} -> {new} ({source})")
            if self._on_change:
                try:
                    self._on_change(self._last_effective, new, source)
                except Exception as e:  # never let a ledger hook break the watcher
                    logger.error(f"mode change hook failed: {e}")
            self._last_effective = new

    # ---- Watch API loops ---------------------------------------------------
    async def start(self, core_api) -> None:
        self._running = True
        self._tasks = [asyncio.create_task(self._watch_configmap(core_api)),
                       asyncio.create_task(self._watch_namespaces(core_api))]

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()

    async def _watch_configmap(self, core_api) -> None:
        from kubernetes_asyncio import watch
        selector = f"metadata.name={MODE_CONFIGMAP}"
        while self._running:
            try:
                lst = await core_api.list_namespaced_config_map(MODE_NAMESPACE, field_selector=selector)
                if lst.items:
                    self.apply_configmap(lst.items[0])
                else:
                    self.apply_configmap_deleted()
                rv = lst.metadata.resource_version
                async with watch.Watch() as w:
                    async for ev in w.stream(core_api.list_namespaced_config_map, MODE_NAMESPACE,
                                             field_selector=selector, resource_version=rv,
                                             timeout_seconds=300):
                        if ev["type"] == "DELETED":
                            self.apply_configmap_deleted()
                        elif ev["type"] in ("ADDED", "MODIFIED"):
                            self.apply_configmap(ev["object"])
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.mark_unreadable(str(e)[:120])
                await asyncio.sleep(2)

    async def _watch_namespaces(self, core_api) -> None:
        from kubernetes_asyncio import watch
        while self._running:
            try:
                lst = await core_api.list_namespace()
                self.ns_labels = {}
                for n in lst.items:
                    self.apply_namespace(n)
                self.ns_readable = True
                async with watch.Watch() as w:
                    async for ev in w.stream(core_api.list_namespace,
                                             resource_version=lst.metadata.resource_version,
                                             timeout_seconds=300):
                        self.apply_namespace(ev["object"], deleted=ev["type"] == "DELETED")
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.ns_readable = False   # stale labels could hide a `test` override: fail safe
                logger.warning(f"namespace watch error: {e}")
                await asyncio.sleep(2)

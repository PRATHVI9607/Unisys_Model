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
PROTECTED_LABEL = "kubeheal/protected"
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


def is_protected(known: bool, label: Optional[str], readable: bool) -> bool:
    """P6-D3 (S-POL-6): a namespace labelled `kubeheal/protected` never gets an automatic action.
    Fail closed: if the labels are not readable, or the namespace is not in the list the watcher has seen,
    the namespace counts as protected. A namespace without the label is not protected. A label with any
    value other than exactly `false` (any case) protects: a typo must not switch protection off."""
    if not readable or not known:
        return True
    if label is None:
        return False
    return str(label).strip().lower() != "false"


class ModeWatcher:
    def __init__(self, on_change: Optional[Callable[[str, str, str], None]] = None):
        self.global_mode: Optional[str] = None
        self.readable: bool = False
        self.ns_readable: bool = False   # namespace labels loaded and watch healthy
        self._ns_unreadable_warned = False
        self.ns_labels: Dict[str, str] = {}
        # every namespace the watcher has seen -> value of kubeheal/protected (None = no such label)
        self.ns_protect: Dict[str, Optional[str]] = {}
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

    def protected_for(self, namespace: Optional[str]) -> bool:
        """True when the namespace carries `kubeheal/protected` or its label state is unknown."""
        if not namespace:
            return True
        return is_protected(namespace in self.ns_protect, self.ns_protect.get(namespace), self.ns_readable)

    def mark_namespaces_unreadable(self, reason: str) -> None:
        """Fail closed on namespace watch errors and explain why label checks are conservative."""
        self.ns_readable = False
        if not self._ns_unreadable_warned:
            logger.warning("namespace labels have not loaded or the watch failed; mode and protected-namespace checks fail closed")
            self._ns_unreadable_warned = True
        logger.warning(f"namespace watch error: {reason}")

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
        labels = ns_obj.metadata.labels or {}
        label = labels.get(NAMESPACE_LABEL)
        if deleted or label is None:
            self.ns_labels.pop(name, None)
        else:
            self.ns_labels[name] = label
        if deleted:
            self.ns_protect.pop(name, None)
        else:
            self.ns_protect[name] = labels.get(PROTECTED_LABEL)

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
                self.ns_protect = {}       # relist: forget stale namespaces and labels
                for n in lst.items:
                    self.apply_namespace(n)
                self.ns_readable = True
                self._ns_unreadable_warned = False
                async with watch.Watch() as w:
                    async for ev in w.stream(core_api.list_namespace,
                                             resource_version=lst.metadata.resource_version,
                                             timeout_seconds=300):
                        self.apply_namespace(ev["object"], deleted=ev["type"] == "DELETED")
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.mark_namespaces_unreadable(str(e))  # stale labels could hide an override: fail safe
                await asyncio.sleep(2)

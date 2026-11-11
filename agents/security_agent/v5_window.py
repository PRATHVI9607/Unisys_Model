"""
Map normalised syscall windows onto the v5 security feature input (V5-S2)
==========================================================================
Pure functions, no I/O. `FalcoWindowTracker` windows hold NORMALISED Falco events (`falco_client._normalise`:
`syscall`, `fd_path`, `flags`, `fs_*`, `ts`, plus `seen_ms`, the arrival time). `kubeheal.features.security`
wants `{"syscall", "path", "new_path", "ts_ms"}` events whose syscall is one of its groups. This module is the
only place that translates one into the other, so the choices are visible and tested:

  * Opens become `open_w` / `open_r` from the open flags (`open_syscall`); an open without flags is a read, as in v5.
  * MAPPING CHOICE: a raw `write`, `pwrite` or `pwritev` event becomes `open_w`. v5 has no group for raw writes
    (its Falco rule hooks opens, not write()), but the rules in `k8s/falco-kubeheal-rules.yaml` still emit raw
    writes, so without this mapping `frac_write` would be 0 for every live window. One raw write event is one
    `open_w` event (no de-duplication per file), which is not what the training windows counted (one open per
    file): a train/serve skew that disappears when the rules emit opens with flags (V5-S1). Chosen, not measured.
  * A syscall outside the captured groups (mmap, msync, ...) is dropped: the training windows never held them.
  * Renames: `path` is `fs.path.source` when the rule outputs it, `new_path` is `fs.path.target` or, for a
    rename event that only carries `fd.name` (the rules in `k8s/` today), that name. The source is never
    guessed from the target, so the suffix, temp and rotation rename features are None until the rules output
    both paths (V5-S1).
  * Windows are cut like the v5 agent cuts them: at most MAX_WINDOW_EVENTS events, none older than WINDOW_S before
    the newest.
"""

from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from kubeheal.features.security import (
    CAPTURED_GROUPS,
    MAX_WINDOW_EVENTS,
    OPEN_SYSCALLS,
    SYSCALL_GROUPS,
    WINDOW_S,
    open_syscall,
    window_seconds,
)

RAW_WRITE_SYSCALLS = frozenset({"write", "pwrite", "pwritev"})
_CAPTURED = frozenset().union(*(SYSCALL_GROUPS[g] for g in CAPTURED_GROUPS))


def iso_to_ms(ts) -> Optional[int]:
    """Epoch ms of a timezone-aware ISO string, None for anything else."""
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return int(parsed.timestamp() * 1000) if parsed.tzinfo is not None else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def v5_syscall(evt: Dict) -> Optional[str]:
    """The v5 syscall name of a normalised event, None when v5 does not count it."""
    raw = (evt.get("syscall") or "").lower()
    if raw in OPEN_SYSCALLS:
        sc = open_syscall(raw, evt.get("flags") or None)
    elif raw in RAW_WRITE_SYSCALLS:
        sc = "open_w"
    else:
        sc = raw
    return sc if sc in _CAPTURED else None


def to_v5_event(evt: Dict) -> Optional[Dict]:
    """One normalised event as a v5 feature-input event, None when it is not counted or has no usable time."""
    sc = v5_syscall(evt)
    if sc is None:
        return None
    fd_path, name, source, target = (evt.get("fd_path") or "", evt.get("fs_name") or "",
                                     evt.get("fs_source") or "", evt.get("fs_target") or "")
    if sc in SYSCALL_GROUPS["rename"]:
        path, new_path = source, target or (fd_path if not source else "")
    else:
        path, new_path = fd_path or name or source, ""
    ts_ms = iso_to_ms(evt.get("ts"))
    if ts_ms is None:
        ts_ms = evt.get("seen_ms")
    if not isinstance(ts_ms, int) or isinstance(ts_ms, bool) or ts_ms <= 0:
        return None
    return {"syscall": sc, "path": path, "new_path": new_path, "ts_ms": ts_ms}


def cut_window(events: Iterable[Dict]) -> Tuple[List[Dict], int, int, float]:
    """(events, start_ms, newest_ms, window_s) of the v5 window of `events` (already v5 events, oldest first).
    ([], 0, 0, 0.0) when there are none."""
    evs = list(events)
    if not evs:
        return [], 0, 0, 0.0
    newest = max(e["ts_ms"] for e in evs)
    cutoff = newest - WINDOW_S * 1000
    evs = [e for e in evs if e["ts_ms"] >= cutoff][-MAX_WINDOW_EVENTS:]
    start = min(e["ts_ms"] for e in evs)
    return evs, start, newest, window_seconds(start, newest)


def window_from_normalised(events: Iterable[Dict]) -> Tuple[List[Dict], int, int, float]:
    """Normalised tracker window -> cut v5 window."""
    return cut_window(e for e in (to_v5_event(x) for x in events) if e is not None)


def top_syscall(events: Iterable[Dict]) -> str:
    """The most frequent observed syscall name of a normalised window ("" when empty). Observed, not a model
    attribution: the LightGBM model has none (TreeSHAP lives in `top_factors`)."""
    counts: Dict[str, int] = {}
    for e in events:
        name = (e.get("syscall") or "").lower()
        if name:
            counts[name] = counts.get(name, 0) + 1
    return max(counts, key=lambda k: (counts[k], k)) if counts else ""

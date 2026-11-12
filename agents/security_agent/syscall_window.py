"""
Syscall window tracker and Security Model input builder (P5-S2/S3)
==================================================================
`FalcoWindowTracker` keeps the rolling syscall window per PID from NORMALISED Falco events and says when
a window should trigger an entropy check. It is the same code for live Falco and for replay: both feed
`falco_client._normalise` events into `add()`.

`build_model_input` turns a window plus an entropy series into the JSON body of `POST /security/score`
(`events`, `entropy_series`, `early_signals`). It only reshapes data that was observed; it never creates
events. It does not import torch (the agent image has none); the constants below mirror the model's and
`tests/test_sense_falco_replay.py` checks they are equal.
"""

import time
from collections import OrderedDict
from datetime import datetime
from typing import Callable, Dict, List, Optional, Sequence

from agents.security_agent.falco_client import RANSOMWARE_SYSCALLS
from agents.security_agent.v5_window import v5_syscall
from kubeheal.features.security import OPEN_SYSCALLS, WINDOW_S

# models/security_model/falco_transformer_encoder.py: MAX_SEQUENCE_LENGTH
MODEL_MAX_EVENTS = 256
# models/security_model/entropy_conv1d_encoder.py: ENTROPY_WINDOW_LENGTH
MODEL_ENTROPY_LENGTH = 30

DEFAULT_BURST_THRESHOLD = 15          # pre-P5 FALCO_BURST_THRESHOLD default (ops per window)
DEFAULT_COOLDOWN_S = 5.0              # pre-P5 minimum gap between triggers for one PID


MAX_TRACKED_PIDS = 4096               # chosen default, not measured: bound on the first-seen map

# A first-seen time is kept per PID OUTSIDE the capped window, so a long attack (more events than the window
# holds) still reports the real onset as T0 instead of the start of the retained window.


def _ts_ms(ts: str) -> Optional[int]:
    """Epoch ms of a timezone-aware ISO string, None when it is not one."""
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return int(parsed.timestamp() * 1000) if parsed.tzinfo is not None else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


class Trigger:
    """A window that should start an entropy check. `first_ts` is the earliest Falco time seen for the PID,
    which may be older than every event left in the capped window ("" when no event carried a usable time)."""
    __slots__ = ("pid", "events", "reason", "first_ts")

    def __init__(self, pid: int, events: List[Dict], reason: str, first_ts: str = ""):
        self.pid, self.events, self.reason, self.first_ts = pid, events, reason, first_ts


class FalcoWindowTracker:
    def __init__(self, burst_threshold: int = DEFAULT_BURST_THRESHOLD,
                 cooldown_s: float = DEFAULT_COOLDOWN_S, max_events: int = MODEL_MAX_EVENTS,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time):
        self._wall = wall
        self.burst_threshold = burst_threshold
        self.cooldown_s = cooldown_s
        self.max_events = max_events
        self._clock = clock
        self._windows: "OrderedDict[int, List[Dict]]" = OrderedDict()
        self._last_fire: "OrderedDict[int, float]" = OrderedDict()
        self._first_seen: "OrderedDict[int, tuple]" = OrderedDict()  # pid -> (epoch ms, original ts string)
        self._instances: "OrderedDict[int, Optional[int]]" = OrderedDict()

    def discard(self, pid: int) -> None:
        """Forget one PID's bounded tracker state (also used when its starttime changes)."""
        self._windows.pop(pid, None)
        self._last_fire.pop(pid, None)
        self._first_seen.pop(pid, None)
        self._instances.pop(pid, None)

    def _ensure_pid(self, pid: int, starttime: Optional[int]) -> None:
        old = self._instances.get(pid)
        if starttime is not None and old is not None and old != starttime:
            self.discard(pid)
        if pid not in self._instances and len(self._instances) >= MAX_TRACKED_PIDS:
            oldest = next(iter(self._instances))
            self.discard(oldest)
        self._instances[pid] = starttime if starttime is not None else old
        self._instances.move_to_end(pid)

    def first_seen(self, pid: int) -> str:
        return self._first_seen.get(pid, (0, ""))[1]

    def _note_first_seen(self, pid: int, ts: str) -> None:
        ms = _ts_ms(ts) if ts else None
        if ms is None:
            return
        known = self._first_seen.get(pid)
        if known is None:
            self._first_seen[pid] = (ms, ts)
        elif ms < known[0]:
            self._first_seen[pid] = (ms, ts)
        self._first_seen.move_to_end(pid)

    def window(self, pid: int) -> List[Dict]:
        return list(self._windows.get(pid, []))

    def add(self, evt: Dict) -> Optional[Trigger]:
        """Add one normalised Falco event. Returns a Trigger when a burst (renames + writes at or above the
        threshold) or a Falco ransomware rule is seen for that PID and the cooldown has passed."""
        pid, sysc = evt.get("pid"), evt.get("syscall", "")
        if not pid or sysc not in RANSOMWARE_SYSCALLS:
            return None
        self._ensure_pid(pid, evt.get("proc_starttime"))
        w = self._windows.setdefault(pid, [])
        self._windows.move_to_end(pid)
        seen_ms = int(evt.get("seen_ms") or self._wall() * 1000)
        # An activity gap longer than WINDOW_S ends the burst: the earliest-seen time (the T0 of a later trigger)
        # must start again, or one old rename would pull T0 hours back and Fusion would pick an older snapshot.
        if w and seen_ms - w[-1]["seen_ms"] > WINDOW_S * 1000:
            self._first_seen.pop(pid, None)
        self._note_first_seen(pid, evt.get("ts", ""))
        # Keep the Falco source timestamp for Fusion's T0/restore decision. `build_model_input` deliberately
        # strips it from the Security Model's fixed event schema.
        # V5-S2: the entry also keeps what the v5 feature mapping needs (open flags, rule path fields) and the
        # arrival time, the fallback event time of an event without a Falco timestamp (agents/security_agent/v5_window.py).
        w.append({"syscall": sysc, "fd_path": evt.get("fd_path", ""), "ts": evt.get("ts", ""),
                  "flags": evt.get("flags", ""), "fs_name": evt.get("fs_name", ""),
                  "fs_source": evt.get("fs_source", ""), "fs_target": evt.get("fs_target", ""),
                  "seen_ms": seen_ms,
                  "proc_starttime": evt.get("proc_starttime")})
        cutoff_ms = w[-1]["seen_ms"] - WINDOW_S * 1000
        w[:] = [event for event in w if event["seen_ms"] >= cutoff_ms]
        if len(w) > self.max_events:
            del w[: len(w) - self.max_events]
        renames = sum(1 for e in w if e["syscall"].startswith("rename"))
        writes = sum(1 for e in w if "write" in e["syscall"] or e["syscall"] == "ftruncate"
                     or (e["syscall"] in OPEN_SYSCALLS and v5_syscall(e) == "open_w"))
        # A CRITICAL ransomware rule (the ransom-note rule) triggers on its own. The WARNING and NOTICE rules (mass rename,
        # data file activity) fire on every single matching syscall, so they only count towards the burst threshold;
        # treating each of them as a trigger would start a check with a one-event window.
        ransom_rule = ("ransom" in (evt.get("rule") or "").lower()
                       and (evt.get("priority") or "") in ("critical", "alert", "emergency"))
        if not (renames + writes >= self.burst_threshold or ransom_rule):
            return None
        now = self._clock()
        if now - self._last_fire.get(pid, float("-inf")) <= self.cooldown_s:
            return None
        self._last_fire[pid] = now
        self._last_fire.move_to_end(pid)
        return Trigger(pid, list(w), "falco_rule" if ransom_rule else "burst", self.first_seen(pid))


def build_model_input(events: Sequence[Dict], entropy_series: Sequence[float],
                      early_signals: Dict[str, bool]) -> Dict:
    """Body for the Security Model server. Keeps the most recent MODEL_MAX_EVENTS events (the server reads
    from the start of the list) and at most MODEL_ENTROPY_LENGTH entropy values."""
    evs = [{"syscall": e.get("syscall", ""), "fd_path": e.get("fd_path", "") or ""}
           for e in events][-MODEL_MAX_EVENTS:]
    return {
        "events": evs,
        "entropy_series": [float(v) for v in entropy_series][:MODEL_ENTROPY_LENGTH],
        "early_signals": {k: bool(v) for k, v in (early_signals or {}).items()},
    }

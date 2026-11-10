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
from typing import Callable, Dict, List, Optional, Sequence

from agents.security_agent.falco_client import RANSOMWARE_SYSCALLS

# models/security_model/falco_transformer_encoder.py: MAX_SEQUENCE_LENGTH
MODEL_MAX_EVENTS = 256
# models/security_model/entropy_conv1d_encoder.py: ENTROPY_WINDOW_LENGTH
MODEL_ENTROPY_LENGTH = 30

DEFAULT_BURST_THRESHOLD = 15          # pre-P5 FALCO_BURST_THRESHOLD default (ops per window)
DEFAULT_COOLDOWN_S = 5.0              # pre-P5 minimum gap between triggers for one PID


class Trigger:
    """A window that should start an entropy check."""
    __slots__ = ("pid", "events", "reason")

    def __init__(self, pid: int, events: List[Dict], reason: str):
        self.pid, self.events, self.reason = pid, events, reason


class FalcoWindowTracker:
    def __init__(self, burst_threshold: int = DEFAULT_BURST_THRESHOLD,
                 cooldown_s: float = DEFAULT_COOLDOWN_S, max_events: int = MODEL_MAX_EVENTS,
                 clock: Callable[[], float] = time.monotonic):
        self.burst_threshold = burst_threshold
        self.cooldown_s = cooldown_s
        self.max_events = max_events
        self._clock = clock
        self._windows: Dict[int, List[Dict]] = {}
        self._last_fire: Dict[int, float] = {}

    def window(self, pid: int) -> List[Dict]:
        return list(self._windows.get(pid, []))

    def add(self, evt: Dict) -> Optional[Trigger]:
        """Add one normalised Falco event. Returns a Trigger when a burst (renames + writes at or above the
        threshold) or a Falco ransomware rule is seen for that PID and the cooldown has passed."""
        pid, sysc = evt.get("pid"), evt.get("syscall", "")
        if not pid or sysc not in RANSOMWARE_SYSCALLS:
            return None
        w = self._windows.setdefault(pid, [])
        # Keep the Falco source timestamp for Fusion's T0/restore decision. `build_model_input` deliberately
        # strips it from the Security Model's fixed event schema.
        w.append({"syscall": sysc, "fd_path": evt.get("fd_path", ""), "ts": evt.get("ts", "")})
        if len(w) > self.max_events:
            del w[: len(w) - self.max_events]
        renames = sum(1 for e in w if e["syscall"].startswith("rename"))
        writes = sum(1 for e in w if "write" in e["syscall"] or e["syscall"] == "ftruncate")
        # A CRITICAL ransomware rule (the ransom-note rule) triggers on its own. The WARNING rules (mass write,
        # mass rename) fire on every single matching syscall, so they only count towards the burst threshold;
        # treating each of them as a trigger would start a check with a one-event window.
        ransom_rule = ("ransom" in (evt.get("rule") or "").lower()
                       and (evt.get("priority") or "") in ("critical", "alert", "emergency"))
        if not (renames + writes >= self.burst_threshold or ransom_rule):
            return None
        now = self._clock()
        if now - self._last_fire.get(pid, float("-inf")) <= self.cooldown_s:
            return None
        self._last_fire[pid] = now
        return Trigger(pid, list(w), "falco_rule" if ransom_rule else "burst")


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

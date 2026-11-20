"""Per-client token bucket, in memory (one dashboard replica; resets on restart)."""

from __future__ import annotations

import time

MAX_KEYS = 10_000   # shortcut: a flood of distinct clients just resets the table; upgrade to LRU if that ever matters


class Bucket:
    def __init__(self, burst: float, per_second: float) -> None:
        self.burst, self.rate = burst, per_second
        self._state: dict[str, tuple[float, float]] = {}   # key -> (tokens, last monotonic time)

    def _tokens(self, key: str) -> float:
        tokens, last = self._state.get(key, (self.burst, 0.0))
        return min(self.burst, tokens + (time.monotonic() - last) * self.rate) if last else self.burst

    def has(self, key: str) -> bool:
        return self._tokens(key) >= 1

    def take(self, key: str) -> bool:
        """Spend one token; False (nothing spent) when the client is out."""
        tokens = self._tokens(key)
        if tokens < 1:
            return False
        if len(self._state) >= MAX_KEYS:
            self._state.clear()
        self._state[key] = (tokens - 1, time.monotonic())
        return True

    def reset(self) -> None:
        self._state.clear()

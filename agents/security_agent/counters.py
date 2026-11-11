"""
Write-bytes and net-out counters for the v5 security features (V5-S3)
=====================================================================
The shipped security bundle lists `write_bytes_per_s` and `net_out_bytes_per_s`, so the agent supplies them.

PARITY SHORTCUT: v5 trained on and reads POD-level counters (the pod's cgroup v2 `io.stat` wbytes and the pod's
network namespace). This DaemonSet has no cgroup mount until the containment task (V5-S5), so the counters here
are per PROCESS: the sum of `/proc/<pid>/io` write_bytes over the pod's processes the agent knows, and the
transmitted bytes of `/proc/<pid>/net/dev` (every interface but loopback) of the pod's network namespace. A
process that exits between two samples makes the write sum drop, which counts as a reset (the counter is then
unknown). Unknown is None, never 0: a hostNetwork pod (its netns is the node's, so node egress is not the pod's),
an unreadable file, a counter that went backwards and a span between samples that is too short.

`counter_total` keeps v5's semantics: the increase between the first and last sample, rescaled so that
total / window_s is the rate over the samples' own time span.
"""

import os
from collections import deque
from typing import Deque, Iterable, Optional, Tuple

MIN_SPAN_S = 1.0          # chosen, not measured: a shorter span amplifies a few bytes into a huge rate
SAMPLE_EVERY_S = 1.0      # samples closer together than this are not added (a burst of scoring must not flush the deque)
MAX_SAMPLES = 64          # chosen, not measured


def pid_write_bytes(proc_root: str, pid: int) -> Optional[int]:
    """Cumulative write_bytes of one process from /proc/<pid>/io, None when unreadable."""
    try:
        with open(os.path.join(proc_root, str(pid), "io")) as fh:
            for line in fh:
                if line.startswith("write_bytes:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def net_tx_bytes(proc_root: str, pid: int) -> Optional[float]:
    """Bytes transmitted by the network namespace of `pid` on every interface but loopback. None for a hostNetwork
    process (its namespace is the node's) or when the table is unreadable."""
    try:
        own = os.stat(os.path.join(proc_root, str(pid), "ns", "net")).st_ino
        if own == os.stat(os.path.join(proc_root, "1", "ns", "net")).st_ino:
            return None
        with open(os.path.join(proc_root, str(pid), "net", "dev")) as fh:
            rows = fh.read().splitlines()[2:]                  # two header lines
        return float(sum(int(data.split()[8]) for name, _, data in (r.partition(":") for r in rows)
                         if name.strip() != "lo"))
    except (OSError, ValueError, IndexError):
        return None


def read_pod_counters(proc_root: str, pids: Iterable[int]) -> Tuple[Optional[float], Optional[float]]:
    """(net tx bytes, write bytes) of a pod through its known `pids`. Blocking: run it in a thread."""
    pids = sorted({int(p) for p in pids if p})
    if not pids:
        return None, None
    writes = [pid_write_bytes(proc_root, p) for p in pids]
    wb = float(sum(writes)) if all(w is not None for w in writes) else None   # a partial sum would be a fake low
    net = next((v for v in (net_tx_bytes(proc_root, p) for p in pids) if v is not None), None)
    return net, wb


class CounterSamples:
    """Samples (clock seconds, net tx, write bytes) of one pod."""

    def __init__(self, window_s: float = 60.0):
        self.window_s = window_s
        self.samples: Deque[tuple] = deque(maxlen=MAX_SAMPLES)

    def add(self, now: float, net: Optional[float], wbytes: Optional[float], force: bool = False) -> None:
        if not force and self.samples and now - self.samples[-1][0] < SAMPLE_EVERY_S:
            return
        self.samples.append((now, net, wbytes))
        while len(self.samples) > 2 and self.samples[0][0] < now - self.window_s:
            self.samples.popleft()

    def delta(self, i: int) -> Optional[float]:
        """Increase of counter i (1 = net tx, 2 = write bytes) between the first and last sample; None if unknown,
        reset, or fewer than two samples."""
        s = self.samples
        if len(s) < 2 or s[0][i] is None or s[-1][i] is None or s[-1][i] < s[0][i]:
            return None
        return s[-1][i] - s[0][i]

    def total(self, i: int, window_s: float) -> Optional[float]:
        """`delta` rescaled so that total / window_s is the rate over the samples' own time span; None when the
        span is shorter than MIN_SPAN_S."""
        d = self.delta(i)
        span = self.samples[-1][0] - self.samples[0][0] if d is not None else 0.0
        return d * window_s / span if span >= MIN_SPAN_S else None

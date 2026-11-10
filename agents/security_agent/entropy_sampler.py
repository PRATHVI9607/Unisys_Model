"""
Entropy sampler: real write entropy of a suspect process (plan P5-S1)
=====================================================================
Measures the Shannon entropy of data the suspect process has actually written, sampled over time.
The Security Model expects an entropy series of 30 values, 2 s apart (models/security_model/
entropy_conv1d_encoder.py: ENTROPY_WINDOW_LENGTH = 30, "60s @ 2s resolution").

How it finds the data (read only, no write, no signal):
  1. `<proc_root>/<pid>/fd/*` symlink targets are the files the process has open, as seen inside the
     container's mount namespace (for example `/data/file_0001.txt` on the PersistentVolume).
  2. `<proc_root>/<pid>/fdinfo/<fd>` gives the open flags (only write-capable descriptors count: O_WRONLY or
     O_RDWR) and the current file offset `pos`.
  3. The target is read through the HOST path `<proc_root>/<pid>/root/<target>` (the container's root as the
     host sees it; needs hostPID, SYS_PTRACE and DAC_READ_SEARCH, which the DaemonSet already has).
  4. The data sampled is the last `max_read_bytes` the process wrote through that descriptor, that is
     `[pos - max_read_bytes, pos)`. If `pos` is unknown the head of the file is read instead.
     Reads are bounded by `max_read_bytes` per file, and at most `max_files` files per sample.

A sample whose files yield no data is recorded as `None`. It is NOT replaced by 0.0, and the result says
how many samples were real (`valid_samples`). If the process disappears the run ends early.

Configuration (env, defaults documented here and nowhere else):
  ENTROPY_SAMPLES          30     samples per run; model window length (ENTROPY_WINDOW_LENGTH)
  ENTROPY_INTERVAL_S       2.0    seconds between samples; model window resolution
  ENTROPY_MAX_READ_BYTES   4096   per file per sample; the sample size the pre-P5 file reader used
  ENTROPY_MAX_FILES        20     files per sample; the sample count the pre-P5 file reader used
  ENTROPY_VOLUME_PREFIXES  ""     comma list of container paths to restrict sampling to (for example /data);
                                  empty means every regular file outside the excluded virtual filesystems
Both time sources are injectable (`clock`, `sleep`) so tests run without waiting.
"""

import asyncio
import logging
import math
import os
import stat
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

DEFAULT_SAMPLES = 30
DEFAULT_INTERVAL_S = 2.0
DEFAULT_MAX_READ_BYTES = 4096
DEFAULT_MAX_FILES = 20
# Container paths that are never application data.
EXCLUDED_PREFIXES = ("/proc/", "/sys/", "/dev/")

_O_ACCMODE = 0o3
_O_WRONLY = 0o1
_O_RDWR = 0o2


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 to 8.0). Empty input is 0.0 by definition; callers decide
    whether empty data counts as a sample."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


@dataclass
class SamplerConfig:
    samples: int = DEFAULT_SAMPLES
    interval_s: float = DEFAULT_INTERVAL_S
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES
    max_files: int = DEFAULT_MAX_FILES
    volume_prefixes: Tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env=None) -> "SamplerConfig":
        env = os.environ if env is None else env
        prefixes = tuple(p.strip() for p in env.get("ENTROPY_VOLUME_PREFIXES", "").split(",") if p.strip())
        return cls(
            samples=int(env.get("ENTROPY_SAMPLES", DEFAULT_SAMPLES)),
            interval_s=float(env.get("ENTROPY_INTERVAL_S", DEFAULT_INTERVAL_S)),
            max_read_bytes=int(env.get("ENTROPY_MAX_READ_BYTES", DEFAULT_MAX_READ_BYTES)),
            max_files=int(env.get("ENTROPY_MAX_FILES", DEFAULT_MAX_FILES)),
            volume_prefixes=prefixes,
        )


@dataclass
class WrittenFile:
    fd: int
    target: str          # path inside the container
    host_path: str       # path the agent reads
    pos: Optional[int]   # current offset of the descriptor, None if unknown


@dataclass
class EntropyResult:
    pid: int
    series: List[Optional[float]]                 # one entry per sample, None where no data was readable
    files: List[str] = field(default_factory=list)  # container paths seen, first appearance order
    ended_early: bool = False                     # the process went away before all samples were taken

    @property
    def valid_samples(self) -> int:
        return sum(1 for v in self.series if v is not None)

    @property
    def available(self) -> bool:
        return self.valid_samples > 0

    @property
    def mean(self) -> Optional[float]:
        vals = [v for v in self.series if v is not None]
        return sum(vals) / len(vals) if vals else None

    def model_series(self) -> List[float]:
        """Series for the Security Model: real values only. Gaps between real samples repeat the previous
        real value; leading gaps repeat the first real value. Returns [] when no sample was real (the
        caller must then treat entropy as unavailable, not as 0)."""
        vals = [v for v in self.series if v is not None]
        if not vals:
            return []
        out: List[float] = []
        last: Optional[float] = None
        for v in self.series:
            if v is not None:
                last = v
            out.append(last if last is not None else vals[0])
        return out


class ProcFdReader:
    """Lists and reads the files a process has open for writing. The OS touch points (`readlink`,
    `listdir`) are injectable for tests."""

    def __init__(self, proc_root: str = "/proc", config: Optional[SamplerConfig] = None,
                 readlink: Callable[[str], str] = os.readlink,
                 listdir: Callable[[str], List[str]] = os.listdir):
        self.proc_root = proc_root
        self.config = config or SamplerConfig()
        self._readlink = readlink
        self._listdir = listdir

    def host_path(self, pid: int, target: str) -> str:
        return f"{self.proc_root}/{pid}/root{target}"

    def process_alive(self, pid: int) -> bool:
        return os.path.isdir(f"{self.proc_root}/{pid}")

    def _wanted(self, target: str) -> bool:
        if not target.startswith("/") or target.endswith(" (deleted)"):
            return False                           # pipes, sockets, anon inodes
        if any(target.startswith(p) for p in EXCLUDED_PREFIXES):
            return False
        pfx = self.config.volume_prefixes
        return not pfx or any(target == p or target.startswith(p.rstrip("/") + "/") for p in pfx)

    def _fdinfo(self, pid: int, fd: str) -> Tuple[Optional[int], Optional[int]]:
        flags = pos = None
        try:
            with open(f"{self.proc_root}/{pid}/fdinfo/{fd}") as f:
                for line in f:
                    key, _, val = line.partition(":")
                    if key == "flags":
                        flags = int(val.strip(), 8)
                    elif key == "pos":
                        pos = int(val.strip())
        except (OSError, ValueError):
            pass
        return flags, pos

    def written_files(self, pid: int) -> List[WrittenFile]:
        """Write-capable regular-file descriptors of `pid`, one per distinct target, ordered by fd.
        Raises FileNotFoundError/ProcessLookupError if the process is gone."""
        fd_dir = f"{self.proc_root}/{pid}/fd"
        out: List[WrittenFile] = []
        seen = set()
        for name in sorted((n for n in self._listdir(fd_dir) if n.isdigit()), key=int):
            try:
                target = self._readlink(f"{fd_dir}/{name}")
            except OSError:
                continue
            if target in seen or not self._wanted(target):
                continue
            flags, pos = self._fdinfo(pid, name)
            if flags is None or (flags & _O_ACCMODE) not in (_O_WRONLY, _O_RDWR):
                continue                           # read-only descriptor, or flags unreadable
            seen.add(target)
            out.append(WrittenFile(int(name), target, self.host_path(pid, target), pos))
        return out

    def read_written(self, wf: WrittenFile) -> bytes:
        """The last `max_read_bytes` the process wrote through `wf` (or the file head if pos is unknown).

        The path is opened once with O_RDONLY | O_NONBLOCK | O_NOFOLLOW and the OPEN descriptor is checked
        with fstat: only a regular file is read. There is no stat-then-open gap, a FIFO cannot block the
        open or the read, and a symlink swapped in for the target is refused (ELOOP). Never reads more than
        the bound."""
        n = self.config.max_read_bytes
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(wf.host_path, flags)
        except OSError:
            return b""
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return b""
            if wf.pos is None:
                start, length = 0, n
            elif wf.pos <= 0:
                return b""                         # nothing written yet through this descriptor
            else:
                start = max(0, wf.pos - n)
                length = min(n, wf.pos - start)
            os.lseek(fd, start, os.SEEK_SET)
            chunks, got = [], 0
            while got < length:
                chunk = os.read(fd, length - got)
                if not chunk:
                    break
                chunks.append(chunk)
                got += len(chunk)
            return b"".join(chunks)
        except OSError:
            return b""
        finally:
            os.close(fd)


class EntropySampler:
    def __init__(self, reader: Optional[ProcFdReader] = None, config: Optional[SamplerConfig] = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep):
        self.config = config or (reader.config if reader else SamplerConfig.from_env())
        self.reader = reader or ProcFdReader(os.environ.get("PROC_ROOT", "/proc"), self.config)
        self._clock = clock
        self._sleep = sleep

    def sample_once(self, pid: int, seen_files: Optional[List[str]] = None) -> Optional[float]:
        """Mean entropy over the files `pid` is writing right now; None if there is no readable data."""
        entropies = []
        for wf in self.reader.written_files(pid)[: self.config.max_files]:
            if seen_files is not None and wf.target not in seen_files:
                seen_files.append(wf.target)
            data = self.reader.read_written(wf)
            if data:
                entropies.append(shannon_entropy(data))
        return sum(entropies) / len(entropies) if entropies else None

    async def collect(self, pid: int,
                      on_sample: Optional[Callable[["EntropyResult", int], Awaitable[None]]] = None
                      ) -> EntropyResult:
        """`samples` samples, `interval_s` apart (the sleep is shortened by the time a sample took).
        `on_sample(result, index)` is awaited after each sample (the agent uses it for an early report).
        The blocking /proc and file reads of one sample run in a worker thread (asyncio.to_thread), so a
        slow volume cannot stall the event loop that also runs the Falco consumer and the detectors."""
        cfg = self.config
        result = EntropyResult(pid=pid, series=[])
        for i in range(cfg.samples):
            t0 = self._clock()
            try:
                result.series.append(await asyncio.to_thread(self.sample_once, pid, result.files))
            except (FileNotFoundError, ProcessLookupError, PermissionError) as e:
                logger.info("entropy sampling for pid %s stopped at sample %d: %s", pid, i, e)
                result.ended_early = True
                break
            if on_sample is not None:
                await on_sample(result, i)
            if i < cfg.samples - 1:
                await self._sleep(max(0.0, cfg.interval_s - (self._clock() - t0)))
        return result

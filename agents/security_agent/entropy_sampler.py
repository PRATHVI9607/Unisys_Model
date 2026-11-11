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

V5-S2 hardening (ported from v5, adapted to the descriptor-based reader):
  * `open_in_root` opens the target with O_NOFOLLOW at EVERY path component below `<proc_root>/<pid>/root`
    (a directory chain of O_PATH descriptors, `dir_fd` relative), so a symlink planted anywhere in the path by the
    workload is refused and an absolute link cannot resolve against the agent's own root. The root itself is the
    kernel's magic link and is opened without the flag, as v5 does. Without O_PATH, O_NOFOLLOW or `dir_fd` support
    (Windows, development only) it falls back to an lstat check per component and a single open: not race free.
  * Only regular files are read, decided by `fstat` on the OPEN descriptor (a FIFO cannot block the open or the read).
  * A bounded LRU cache of entropies keyed by (device, inode, size, mtime_ns, ctime_ns, start, length): an
    unchanged file region is not read again. ctime cannot be set back by a syscall, so in-place encryption that
    restores size and mtime still misses the cache. The offset and length are in the key because the reader
    samples [pos - n, pos), not the file head. Bound: ENTROPY_CACHE_MAX.

Configuration (env, defaults documented here and nowhere else):
  ENTROPY_SAMPLES          30     samples per run; model window length (ENTROPY_WINDOW_LENGTH)
  ENTROPY_INTERVAL_S       2.0    seconds between samples; model window resolution
  ENTROPY_MAX_READ_BYTES   4096   per file per sample; the sample size the pre-P5 file reader used
  ENTROPY_MAX_FILES        20     files per sample; the sample count the pre-P5 file reader used
  ENTROPY_CACHE_MAX        512    entries of the LRU entropy cache (chosen, not measured)
  ENTROPY_VOLUME_PREFIXES  ""     comma list of container paths to restrict sampling to (for example /data);
                                  empty means every regular file outside the excluded virtual filesystems
Both time sources are injectable (`clock`, `sleep`) so tests run without waiting.
"""

import asyncio
import logging
import math
import os
import posixpath
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

DEFAULT_SAMPLES = 30
DEFAULT_INTERVAL_S = 2.0
DEFAULT_MAX_READ_BYTES = 4096
DEFAULT_MAX_FILES = 20
DEFAULT_CACHE_MAX = 512            # chosen, not measured
MAX_FILE_ENTROPIES = 8             # kubeheal.features.security.MAX_ENTROPY_SAMPLES: files per evaluation
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


_O_PATH = getattr(os, "O_PATH", 0)
_HAVE_DIR_FD = bool(_O_PATH) and hasattr(os, "O_NOFOLLOW") and os.open in getattr(os, "supports_dir_fd", set())


def split_target(target: str) -> List[str]:
    """Components of a container path. posixpath, not os.path: container paths are POSIX on every host. `normpath`
    drops "..", so the result cannot climb out of the root."""
    return [p for p in posixpath.normpath("/" + target).split("/") if p]


def open_in_root(root: str, parts: Sequence[str], flags: int) -> int:
    """Open root/parts/... with `flags`, refusing a symlink at every component below `root`. Raises OSError.

    Linux: a chain of O_PATH|O_DIRECTORY|O_NOFOLLOW descriptors, each opened relative to the previous one, then the
    last component with O_NOFOLLOW (a symlink anywhere gives ELOOP or ENOTDIR). Elsewhere: an lstat check per
    component, then one open (a development fallback, not safe against a concurrent swap)."""
    if not parts:
        raise OSError("empty path")
    if not _HAVE_DIR_FD:
        cur = root
        for i, part in enumerate(parts):
            cur = os.path.join(cur, part)
            if stat.S_ISLNK(os.lstat(cur).st_mode):
                raise OSError(f"symlink at component {i} of {'/'.join(parts)}")
        return os.open(cur, flags | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(root, _O_PATH | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))     # magic link: no O_NOFOLLOW
    try:
        for part in parts[:-1]:
            nfd = os.open(part, _O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = nfd
        return os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)


class EntropyCache:
    """Bounded LRU map: stat signature + read range -> entropy (None = the region held no data). Thread safe (the
    samples run in worker threads)."""

    def __init__(self, max_entries: int = DEFAULT_CACHE_MAX):
        self.max_entries = max(1, int(max_entries))
        self._d: "OrderedDict[tuple, Optional[float]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = self.misses = 0

    def get(self, key: tuple):
        """(found, value). A hit refreshes the entry."""
        with self._lock:
            if key in self._d:
                self._d.move_to_end(key)
                self.hits += 1
                return True, self._d[key]
            self.misses += 1
            return False, None

    def put(self, key: tuple, value: Optional[float]) -> None:
        with self._lock:
            self._d[key] = value
            self._d.move_to_end(key)
            while len(self._d) > self.max_entries:
                self._d.popitem(last=False)

    def __len__(self) -> int:
        return len(self._d)


def stat_signature(st: os.stat_result) -> tuple:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


@dataclass
class SamplerConfig:
    samples: int = DEFAULT_SAMPLES
    interval_s: float = DEFAULT_INTERVAL_S
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES
    max_files: int = DEFAULT_MAX_FILES
    volume_prefixes: Tuple[str, ...] = ()
    cache_max: int = DEFAULT_CACHE_MAX

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
            cache_max=int(env.get("ENTROPY_CACHE_MAX", DEFAULT_CACHE_MAX)),
        )


@dataclass
class WrittenFile:
    fd: int
    target: str          # path inside the container
    host_path: str       # path the agent reads
    pos: Optional[int]   # current offset of the descriptor, None if unknown


class SeenFiles(list):
    """The container paths seen, first appearance order (a plain list for callers) that also keeps the latest
    entropy of each file, oldest sampled first: the per-file values the v5 security features take."""

    def __init__(self, *a):
        super().__init__(*a)
        self.entropies: "OrderedDict[str, float]" = OrderedDict()

    def note(self, target: str, entropy: float) -> None:
        self.entropies[target] = entropy
        self.entropies.move_to_end(target)
        while len(self.entropies) > MAX_FILE_ENTROPIES:
            self.entropies.popitem(last=False)


@dataclass
class EntropyResult:
    pid: int
    series: List[Optional[float]]                 # one entry per sample, None where no data was readable
    files: List[str] = field(default_factory=SeenFiles)  # container paths seen, first appearance order
    ended_early: bool = False                     # the process went away before all samples were taken

    def file_entropies(self) -> List[float]:
        """Latest entropy per written file, at most MAX_FILE_ENTROPIES, oldest sampled first (v5 `entropy` input)."""
        ent = getattr(self.files, "entropies", None)
        return list(ent.values()) if ent else []

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
                 listdir: Callable[[str], List[str]] = os.listdir,
                 cache: Optional[EntropyCache] = None):
        self.proc_root = proc_root
        self.config = config or SamplerConfig()
        self.cache = cache if cache is not None else EntropyCache(self.config.cache_max)
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

    def _open_regular(self, wf: WrittenFile) -> Optional[int]:
        """An O_RDONLY descriptor of the target if it is a regular file, else None. Every path component below the
        container root is opened with O_NOFOLLOW (`open_in_root`); the open descriptor is checked with fstat, so
        there is no stat-then-open gap, a FIFO cannot block the open or the read (O_NONBLOCK), and a symlink
        swapped in anywhere on the path is refused."""
        root = wf.host_path[: len(wf.host_path) - len(wf.target)] if wf.host_path.endswith(wf.target) else ""
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            if not root:
                raise OSError("host path does not end with the target")
            fd = open_in_root(root, split_target(wf.target), flags)
        except OSError:
            return None
        try:
            if stat.S_ISREG(os.fstat(fd).st_mode):
                return fd
        except OSError:
            pass
        os.close(fd)
        return None

    def _range(self, wf: WrittenFile) -> Optional[Tuple[int, int]]:
        """(start, length) of the region to read: the last `max_read_bytes` written, or the head if pos is unknown;
        None when nothing was written yet through the descriptor."""
        n = self.config.max_read_bytes
        if wf.pos is None:
            return 0, n
        if wf.pos <= 0:
            return None
        start = max(0, wf.pos - n)
        return start, min(n, wf.pos - start)

    @staticmethod
    def _read_fd(fd: int, start: int, length: int) -> bytes:
        os.lseek(fd, start, os.SEEK_SET)
        chunks, got = [], 0
        while got < length:
            chunk = os.read(fd, length - got)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    def read_written(self, wf: WrittenFile) -> bytes:
        """The last `max_read_bytes` the process wrote through `wf` (or the file head if pos is unknown); b"" for
        anything that is not a readable regular file. Never reads more than the bound."""
        rng = self._range(wf)
        if rng is None:
            return b""
        fd = self._open_regular(wf)
        if fd is None:
            return b""
        try:
            return self._read_fd(fd, *rng)
        except OSError:
            return b""
        finally:
            os.close(fd)

    def written_entropy(self, wf: WrittenFile) -> Optional[float]:
        """Entropy of the region `read_written` reads, through the LRU cache; None when there is no data."""
        rng = self._range(wf)
        if rng is None:
            return None
        fd = self._open_regular(wf)
        if fd is None:
            return None
        try:
            key = (*stat_signature(os.fstat(fd)), *rng)
            found, value = self.cache.get(key)
            if found:
                return value
            data = self._read_fd(fd, *rng)
            value = shannon_entropy(data) if data else None
            self.cache.put(key, value)
            return value
        except OSError:
            return None
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
            value = self._entropy_of(wf)
            if value is not None:
                entropies.append(value)
                if hasattr(seen_files, "note"):
                    seen_files.note(wf.target, value)
        return sum(entropies) / len(entropies) if entropies else None

    def _entropy_of(self, wf: WrittenFile) -> Optional[float]:
        """Entropy of the written region, through the reader's LRU cache. A reader double that overrides
        `read_written` (tests) is read directly."""
        if type(self.reader).read_written is ProcFdReader.read_written and hasattr(self.reader, "written_entropy"):
            return self.reader.written_entropy(wf)
        data = self.reader.read_written(wf)
        return shannon_entropy(data) if data else None

    async def collect(self, pid: int,
                      on_sample: Optional[Callable[["EntropyResult", int], Awaitable[None]]] = None,
                      interval_provider: Optional[Callable[[], Awaitable[float]]] = None,
                      ) -> EntropyResult:
        """`samples` samples, `interval_s` apart (the sleep is shortened by the time a sample took).
        `on_sample(result, index)` is awaited after each sample (the agent uses it for an early report).
        `interval_provider`, when supplied, is called before every sleep so a bounded OBSERVE request can
        adjust the next interval without changing the sampler's configured base interval.
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
                interval = cfg.interval_s
                if interval_provider is not None:
                    try:
                        interval = max(0.001, float(await interval_provider()))
                    except Exception as exc:
                        logger.debug("sampling interval lookup failed; using base interval: %s", exc)
                await self._sleep(max(0.0, interval - (self._clock() - t0)))
        return result

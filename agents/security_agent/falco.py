"""Falco json_output: line parsing and a rotation/truncation-safe file tail."""

from __future__ import annotations

import ctypes
import logging
import os
from datetime import datetime

import orjson

log = logging.getLogger("kubeheal.security.falco")

READ_CHUNK = 1 << 20     # bytes per read() call, bounds memory per poll
FREE_EVERY = 8 << 20     # free the consumed prefix of the events file after this many bytes read
_FALLOC_PUNCH = 0x01 | 0x02   # FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE
_libc = ctypes.CDLL(None, use_errno=True)
_libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int64, ctypes.c_int64]


def punch_hole(fd: int, offset: int, length: int) -> bool:
    """Deallocate [offset, offset+length) of the file; size and offsets stay the same (holes read as 0)."""
    return _libc.fallocate(fd, _FALLOC_PUNCH, offset, length) == 0


_NA = (None, "", "<NA>")


def _field(fields: dict, name: str) -> str | None:
    v = fields.get(name)
    return None if v in _NA else v if type(v) is str else str(v)


def _ts_ms(obj: dict, fields: dict) -> int | None:
    if (ns := fields.get("evt.time")) is not None:     # epoch nanoseconds when the rule outputs %evt.time
        try:
            return int(ns) // 1_000_000
        except (TypeError, ValueError):
            pass
    t = obj.get("time")                                # RFC 3339 with nanoseconds: 2024-05-01T12:00:00.123456789Z
    if not isinstance(t, str):
        return None
    head, _, frac = t.rstrip("Z").partition(".")
    try:
        dt = datetime.fromisoformat(f"{head}.{(frac + '000000')[:6]}+00:00")
    except ValueError:
        return None
    return int(dt.timestamp() * 1000)


def parse_line(line: str | bytes) -> dict | None:
    """One Falco JSON line → {namespace, pod, pid, syscall, path, new_path, ts_ms}; None if unusable.

    Events without a k8s namespace/pod or without evt.type are dropped (host processes, rules whose
    output lacks %evt.type). Nothing is ever invented.
    """
    try:
        obj = orjson.loads(line)
    except orjson.JSONDecodeError:
        return None
    f = obj.get("output_fields") if type(obj) is dict else None
    if type(f) is not dict:
        return None
    ns, pod, syscall = _field(f, "k8s.ns.name"), _field(f, "k8s.pod.name"), _field(f, "evt.type")
    if not (ns and pod and syscall):
        return None
    pid = f.get("proc.pid")
    if type(pid) is not int:                           # Falco emits an int; tolerate a numeric string
        pid = int(pid) if isinstance(pid, str) and pid.isdigit() else None
    return {
        "namespace": ns,
        "pod": pod,
        "pid": pid if pid and pid > 0 else None,
        "container_id": _field(f, "container.id") or "",
        "pod_uid": _field(f, "k8s.pod.uid") or "",
        "syscall": syscall,
        # path-based calls have no fd: Falco resolves unlink/chmod paths into fs.path.name and
        # rename old/new paths into fs.path.source / fs.path.target
        "path": _field(f, "fd.name") or _field(f, "fs.path.name") or _field(f, "fs.path.source") or "",
        "new_path": _field(f, "fs.path.target") or "",
        "ts_ms": _ts_ms(obj, f),
    }


class FalcoTail:
    """Blocking tail of a JSONL file; call read_lines() from a worker thread.

    Starts at the end of the file present at startup (no replay of old history), follows rotation
    (inode change: drains the old file first) and truncation (size < offset: restarts at 0).

    Falco appends forever and nothing rotates the file (it lives on tmpfs = node RAM), so the tail
    punches a hole over everything it has consumed: storage stays bounded by the unread tail while
    Falco keeps appending at the same offset (lossless, no rename/truncate race). Needs the file
    writable; on a read-only mount it only logs that the file is not freed.
    """

    def __init__(self, path: str):
        self.path = path
        self.fh = None
        self.wfd: int | None = None    # write fd for hole punching, None when not permitted
        self.freed = 0                 # bytes [0, freed) already deallocated
        self.ino: int | None = None
        self.buf = b""
        self.started = False
        self.missing_logged = False

    def read_lines(self) -> list[bytes]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            if not self.missing_logged:
                log.warning("falco events file %s not found; waiting for it", self.path)
                self.missing_logged = True
            self.started = True        # a file that appears later is read from its beginning
            return self._drain_old() if self.fh else []
        self.missing_logged = False

        lines: list[bytes] = []
        if self.fh is not None and st.st_ino != self.ino:
            lines = self._drain_old()                       # rotated: finish the old file
        if self.fh is None:
            self.fh = open(self.path, "rb")  # held open across polls
            self.ino = os.fstat(self.fh.fileno()).st_ino
            if not self.started:
                self.fh.seek(0, os.SEEK_END)
            self.started = True
            self._open_writer()
        elif st.st_size < self.fh.tell():                   # truncated in place (copytruncate)
            self.fh.seek(0)
            self.buf, self.freed = b"", 0
        return lines + self._read()

    def _open_writer(self) -> None:
        try:
            self.wfd = os.open(self.path, os.O_WRONLY)
            if os.fstat(self.wfd).st_ino != self.ino:     # rotated between the two opens
                self._close_writer()
        except OSError as e:
            log.warning("cannot free consumed falco events in %s (%s): the file grows unbounded", self.path, e)

    def _close_writer(self) -> None:
        if self.wfd is not None:
            os.close(self.wfd)
        self.wfd, self.freed = None, 0

    def _read(self) -> list[bytes]:
        lines = self._split(self.fh.read(READ_CHUNK))
        end = self.fh.tell() & ~0xFFF                       # whole pages only
        if self.wfd is not None and end - self.freed >= FREE_EVERY:
            if punch_hole(self.wfd, self.freed, end - self.freed):
                self.freed = end
            else:
                log.warning("hole punch on %s failed (errno %d); not freeing it", self.path, ctypes.get_errno())
                self._close_writer()
        return lines

    def _split(self, data: bytes) -> list[bytes]:
        if not data:
            return []
        *lines, self.buf = (self.buf + data).split(b"\n")
        if len(self.buf) > READ_CHUNK:                      # no newline in 1 MiB: not Falco output, drop it
            self.buf = b""
        return [ln for ln in lines if ln.strip()]

    def _drain_old(self) -> list[bytes]:
        lines = []
        while data := self.fh.read(READ_CHUNK):
            lines += self._split(data)
        self.fh.close()
        self.fh, self.ino, self.buf = None, None, b""
        self._close_writer()
        return lines

    def close(self) -> None:
        if self.fh:
            self.fh.close()
            self.fh = None
        self._close_writer()

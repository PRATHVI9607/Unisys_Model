"""Syscall + file-entropy window features for the security model.

Input events are `{"syscall": str, "path": str, "new_path": str?, "ts_ms": int?}`
(Falco `evt.type` / `fd.name`; open-family calls are first classified by open_syscall()). Pure functions shared by the synthetic
generator, the lab collector and the security agent.
"""

from __future__ import annotations

import posixpath
import re

import numpy as np

SECURITY_FEATURES: list[str] = [
    "n_events", "events_per_s",
    "frac_read", "frac_write", "frac_open", "frac_rename", "frac_unlink", "frac_truncate",
    "frac_network", "frac_mmap", "frac_exec", "frac_chmod",
    "unique_paths", "unique_dirs", "files_written_per_s",
    "frac_rename_suffix_added", "frac_rename_temp_replace", "frac_rename_rotate", "rename_ext_added_ratio",
    "suspicious_ext_ratio", "ransom_note",
    "entropy_mean", "entropy_max", "entropy_p90", "entropy_high_frac", "entropy_slope", "n_entropy_samples",
    "write_bytes_per_s", "net_out_bytes_per_s",
    "frac_write_from_read", "frac_read_destroyed", "n_files_transformed",
]
# Short-horizon features (last RECENT_EVENTS events). A bundle trained before they existed still serves: the
# inference service ignores names the bundle does not list (and sends None for names it lists but we dropped).
RECENT_FEATURES: list[str] = [
    "recent_frac_write", "recent_frac_rename", "recent_frac_unlink", "recent_frac_chmod", "recent_unique_files",
    "recent_frac_rename_suffix_added", "recent_frac_rename_temp_replace", "recent_ext_added_frac",
    "recent_entropy_mean", "recent_entropy_high_frac", "recent_events_per_s",
    "recent_frac_write_from_read", "recent_frac_read_destroyed",
]
SECURITY_FEATURES += RECENT_FEATURES

OPEN_SYSCALLS = ("open", "openat", "openat2", "creat")
_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"})


def open_syscall(syscall: str, flags: str | None) -> str:
    """Open-family call → "open_w" (write intent: O_WRONLY|O_RDWR|O_CREAT|O_TRUNC, or creat) / "open_r"
    (read, also when flags are missing); any other syscall unchanged. Flags: Falco text or a number."""
    if syscall not in OPEN_SYSCALLS:
        return syscall
    if syscall == "creat":
        return "open_w"
    flags = (flags or "").strip()
    if flags.isdigit():
        n = int(flags)
        # Falco numbers are PPM-encoded (RDONLY=1, WRONLY=2, RDWR=3, CREAT=4, APPEND=8, TRUNC=256), not Linux values
        return "open_w" if n & (2 | 4 | 8 | 256) else "open_r"
    return "open_w" if _WRITE_FLAGS & set(flags.split("|")) else "open_r"


SYSCALL_GROUPS: dict[str, frozenset[str]] = {
    # read/write = per-file opens by intent (open_syscall); the live capture has no read()/write() calls
    "read": frozenset({"open_r"}),
    "write": frozenset({"open_w"}),
    "open": frozenset(OPEN_SYSCALLS),      # unclassified opens: never captured live, kept so frac_open stays a feature
    "rename": frozenset({"rename", "renameat", "renameat2"}),
    "unlink": frozenset({"unlink", "unlinkat"}),
    "truncate": frozenset({"truncate", "ftruncate"}),
    "network": frozenset({"connect", "accept", "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom",
                          "recvmsg", "socket", "bind", "listen"}),
    "mmap": frozenset({"mmap", "munmap", "mprotect"}),
    "exec": frozenset({"execve", "execveat"}),
    "chmod": frozenset({"chmod", "fchmod", "fchmodat"}),
}

# What live windows can contain: the syscall groups deploy/k8s/falco-kubeheal-rules.yaml emits, and only on data
# volumes. Network / mmap / exec and other background syscalls never reach the agent, so the synthetic
# generator drops them too (training windows must look like live ones; tests/test_features_security.py
# checks the rule file against this set).
CAPTURED_GROUPS: tuple[str, ...] = ("read", "write", "rename", "unlink", "truncate", "chmod")
MAX_ENTROPY_SAMPLES = 8   # files the agent reads per evaluation (n_entropy_samples is at most this)
# Window definition shared by the agent and the synthetic generator (train/serve parity):
# the newest <= MAX_WINDOW_EVENTS events no older than WINDOW_S before the newest one, lasting window_seconds().
MAX_WINDOW_EVENTS = 512
WINDOW_S = 60.0
RECENT_EVENTS = 64        # short horizon: an encryption burst must stand out from the setup phase before it
MIN_RECENT_S = 0.5        # floor of the recent span (recent_events_per_s)
MIN_WINDOW_S = 5.0        # floor: a burst scored early would otherwise get absurd per-second rates

HIGH_ENTROPY = 7.5  # bits/byte; compressed or encrypted content
SUSPICIOUS_EXTENSIONS = frozenset({
    ".locked", ".lock", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".cry", ".ransom",
    ".pay", ".wncry", ".wnry", ".locky", ".cerber", ".zepto", ".ryk", ".conti", ".lockbit",
    ".akira", ".clop", ".basta", ".royal", ".hive", ".djvu", ".phobos", ".dharma", ".stop",
})
_RANSOM_NOTE = re.compile(r"decrypt|recover|restore|ransom|unlock", re.IGNORECASE)
_NOTE_EXT = (".txt", ".html", ".htm", ".hta", ".rtf")


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    p = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256) / len(data)
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def window_seconds(start_ms: int, end_ms: int) -> float:
    """Length of a window whose first/last events are at start_ms/end_ms: max(span, MIN_WINDOW_S) <= WINDOW_S."""
    return min(max((end_ms - start_ms) / 1000, MIN_WINDOW_S), WINDOW_S)


def _ext(path: str) -> str:
    return posixpath.splitext(posixpath.basename(path))[1].lower()


def _is_note(path: str) -> bool:
    name = posixpath.basename(path)
    return name.lower().endswith(_NOTE_EXT) and bool(_RANSOM_NOTE.search(name))


COMPRESSION_EXT = frozenset({".gz", ".bz2", ".xz", ".zst"})
_ROT_SUFFIX = re.compile(r"\.\d{1,2}(\.(gz|bz2|xz|zst))?$")          # x.log.1, x.log.2.gz
_TEMP_NAME = re.compile(r"\.(tmp|swp|part|new|lock|dpkg-new|dpkg-old)|~|\.(?=[a-z0-9]*\d)[a-z0-9]{5,}$", re.IGNORECASE)


def _is_temp_name(path: str) -> bool:
    """Temporary-looking basename: leading ".", ".tmp"/".swp"/".part"/".new"/".lock"/".dpkg-new" anywhere, "~", or a
    mktemp-style random suffix (>= 5 alphanumerics with a digit, e.g. cfg.a1B2c3).
    shortcut: a real extension like ".sqlite3" also matches; harmless because suffix_added/rotate are checked first."""
    name = posixpath.basename(path)
    return name.startswith(".") or bool(_TEMP_NAME.search(name))


def rename_kinds(events: list[dict]) -> list[tuple[int, str, str]]:
    """Classify every rename (path → new_path) of the window: [(event index, kind, added suffix)], in order.

    kind, first match wins:
      rotate        new carries a 1-2 digit rotation suffix and both share the stem: x.log → x.log.1, x.log.1 → x.log.2.gz
      suffix_added  new = old + "." + ext (file.txt → file.txt.locked): the encryption signature
      temp_replace  old looks temporary (_is_temp_name) or new was already seen (opened, written, renamed to) earlier
                    in the window, i.e. the rename replaces an existing file
      other         anything else (a plain move; an extension swap file.txt → file.abc)
    The added suffix (with the dot) is only set for suffix_added.
    """
    out: list[tuple[int, str, str]] = []
    seen: set[str] = set()
    for i, e in enumerate(events):
        path, new = e.get("path") or "", e.get("new_path") or ""
        if e.get("syscall", "") in SYSCALL_GROUPS["rename"] and path and new:
            suffix = ""
            if path != new and _ROT_SUFFIX.search(new) and _ROT_SUFFIX.sub("", new) == _ROT_SUFFIX.sub("", path):
                kind = "rotate"
            elif new.startswith(path + ".") and len(new) > len(path) + 1:
                kind, suffix = "suffix_added", new[len(path):]
            elif _is_temp_name(path) or new in seen:
                kind = "temp_replace"
            else:
                kind = "other"
            out.append((i, kind, suffix))
            seen.add(new)
        if path:
            seen.add(path)
    return out


_KEEP_SUFFIX = re.compile(r"~|\.(tmp|temp|part|new|swp|bak|orig|old|copy|lock|dpkg-new|dpkg-old)", re.IGNORECASE)


def _derived(src: str, dst: str) -> bool:
    """dst is a transformed copy of src, not a rotation (x.log.1), compressed (x.gz) or temp/backup copy (x.tmp, x~)."""
    if _ROT_SUFFIX.search(dst) and _ROT_SUFFIX.sub("", dst) == _ROT_SUFFIX.sub("", src):
        return False
    suffix = dst[len(src):] if dst.startswith(src) else ""
    return suffix.lower() not in COMPRESSION_EXT and not _KEEP_SUFFIX.match(suffix)


def _read_origin(path: str, read: set[str]) -> str | None:
    """A file read earlier that `path` copies with an added suffix (x.docx → x.docx.locked, x.docx.id-1.[m].enc)."""
    d, name = posixpath.split(path)
    for k in (k for k, c in enumerate(name) if c == "." and k > 0):
        src = posixpath.join(d, name[:k])
        if src in read and _derived(src, path):
            return src
    return None


Transforms = tuple[list[tuple[int, str]], list[tuple[int, str, str | None]], list[tuple[int, str]]]


def transforms(events: list[dict]) -> Transforms:
    """What each event does to files opened for read earlier in the window: (reads, targets, destroys).

    reads    [(i, path)] opens for read
    targets  [(i, written path, original)] opens for write / truncates / rename targets; `original` is the file read
             earlier that this event transforms, else None: the path itself (read X, write X: in place), the rename
             source (read X, rename X → X.ext or X.other in the same directory), or the name minus an added suffix
             (read X, write X.ext: copy). Rotations, compression and temp/backup suffixes never transform.
    destroys [(i, path)] a read original overwritten in place, renamed away in its directory, or unlinked.
    Ransomware transforms the files it reads; backup tools (restic) read originals and write new content-addressed
    files elsewhere, package managers and git write fresh trees, atomic writes rename an unread temp file.
    """
    read: set[str] = set()
    reads: list[tuple[int, str]] = []
    targets: list[tuple[int, str, str | None]] = []
    destroys: list[tuple[int, str]] = []
    for i, e in enumerate(events):
        sc, path, new = e.get("syscall", ""), e.get("path") or "", e.get("new_path") or ""
        if not path:
            continue
        if sc in SYSCALL_GROUPS["read"]:
            read.add(path)
            reads.append((i, path))
        elif sc in SYSCALL_GROUPS["write"] or sc in SYSCALL_GROUPS["truncate"]:
            orig = path if path in read else _read_origin(path, read)
            targets.append((i, path, orig))
            if orig == path:
                destroys.append((i, path))
        elif sc in SYSCALL_GROUPS["rename"] and new:
            away = path in read and posixpath.dirname(path) == posixpath.dirname(new) and _derived(path, new)
            targets.append((i, new, path if away else None))
            if away:
                destroys.append((i, path))
        elif sc in SYSCALL_GROUPS["unlink"] and path in read:
            destroys.append((i, path))
    return reads, targets, destroys


def _transform_fracs(tr: Transforms, start: int, prefix: str) -> dict[str, float | None]:
    """Over events from index `start` on: share of written files that transform a read original, and share of
    files read there that are destroyed after that read. None without writes / reads."""
    reads, targets, destroys = tr
    written: dict[str, bool] = {}
    for i, p, orig in targets:
        if i >= start:
            written[p] = written.get(p, False) or orig is not None
    first: dict[str, int] = {}
    for i, p in reads:
        if i >= start:
            first.setdefault(p, i)
    gone = {p for i, p in destroys if p in first and i > first[p]}
    return {
        f"{prefix}frac_write_from_read": sum(written.values()) / len(written) if written else None,
        f"{prefix}frac_read_destroyed": len(gone) / len(first) if first else None,
    }


def _rename_fracs(kinds: list[tuple[int, str, str]], prefix: str, names: tuple[str, ...]) -> dict[str, float | None]:
    n = len(kinds)
    return {f"{prefix}{k}": (sum(x[1] == k for x in kinds) / n if n else None) for k in names}


def _ext_added(kinds: list[tuple[int, str, str]]) -> float | None:
    """Share of renames that add an extension to the original name, compression (.gz ...) and rotation excluded."""
    return sum(k == "suffix_added" and s.lower() not in COMPRESSION_EXT for _, k, s in kinds) / len(kinds) if kinds else None


def recent_features(events: list[dict], entropy: list[float], kinds: list[tuple[int, str, str]] | None = None,
                    tr: Transforms | None = None) -> dict[str, float | None]:
    """recent_* features of the last RECENT_EVENTS events (same definitions as the window features, None = unknown).

    `entropy` is the window's samples, oldest write first; the newest ones belong to the recently written files.
    shortcut: samples are matched by recency, not path (an unreadable file shifts it by one), fine for a 64-event tail.
    """
    ev = events[-RECENT_EVENTS:]
    n = len(ev)
    counts = {"write": 0, "rename": 0, "unlink": 0, "chmod": 0}
    paths: set[str] = set()
    written: set[str] = set()
    for e in ev:
        sc, path, new_path = e.get("syscall", ""), e.get("path") or "", e.get("new_path") or ""
        group = next((g for g, names in SYSCALL_GROUPS.items() if sc in names), None)
        group = "write" if group == "truncate" else group
        if group in counts:
            counts[group] += 1
        if path:
            paths.add(path)
        if group == "write" and path:
            written.add(path)
        elif group == "rename" and path and new_path:
            written.add(new_path)
    # classified over the whole window (a rename onto a file seen before the tail is still a replace)
    kinds = [k for k in (rename_kinds(events) if kinds is None else kinds) if k[0] >= len(events) - n]
    ts = [e["ts_ms"] for e in (ev[0], ev[-1]) if e.get("ts_ms") is not None] if n else []
    ent = np.asarray([x for x in entropy[-len(written):] if x is not None] if written else [], dtype=float)
    ent = ent[np.isfinite(ent)]
    return {
        **{f"recent_frac_{g}": (c / n if n else None) for g, c in counts.items()},
        "recent_unique_files": float(len(paths)) if n else None,
        **_rename_fracs(kinds, "recent_frac_rename_", ("suffix_added", "temp_replace")),
        "recent_ext_added_frac": _ext_added(kinds),
        "recent_entropy_mean": float(ent.mean()) if ent.size else None,
        "recent_entropy_high_frac": float((ent > HIGH_ENTROPY).mean()) if ent.size else None,
        "recent_events_per_s": n / max((ts[1] - ts[0]) / 1000, MIN_RECENT_S) if len(ts) == 2 else None,
        # originals read before the tail still count (the tail of a fast attack holds only its transforms)
        **_transform_fracs(transforms(events) if tr is None else tr, len(events) - n, "recent_"),
    }


def security_features(
    events: list[dict],
    entropy: list[float],
    window_s: float,
    bytes_written: float | None = None,
    net_bytes_out: float | None = None,
) -> dict[str, float | None]:
    """Features of one pod's event window, ordered by SECURITY_FEATURES."""
    rate = 1.0 / window_s if window_s and window_s > 0 else None
    n = len(events)
    groups = {g: 0 for g in SYSCALL_GROUPS}
    paths: set[str] = set()
    written: set[str] = set()
    for e in events:
        sc, path, new_path = e.get("syscall", ""), e.get("path") or "", e.get("new_path") or ""
        group = next((g for g, names in SYSCALL_GROUPS.items() if sc in names), None)
        if group:
            groups[group] += 1
        if path:
            paths.add(path)
        if group in ("write", "truncate") and path:
            written.add(path)
        elif group == "rename" and path and new_path:
            written.add(new_path)
    kinds = rename_kinds(events)
    tr = transforms(events)

    f: dict[str, float | None] = {
        "n_events": float(n),
        "events_per_s": n * rate if rate else None,
        **{f"frac_{g}": (c / n if n else None) for g, c in groups.items()},
        "unique_paths": float(len(paths)),
        "unique_dirs": float(len({posixpath.dirname(p) for p in paths})),
        "files_written_per_s": len(written) * rate if rate else None,
        **_rename_fracs(kinds, "frac_rename_", ("suffix_added", "temp_replace", "rotate")),
        "rename_ext_added_ratio": _ext_added(kinds),
        "suspicious_ext_ratio": (sum(_ext(p) in SUSPICIOUS_EXTENSIONS for p in written) / len(written)) if written else None,
        "ransom_note": float(any(_is_note(p) for p in paths | written)),
        "write_bytes_per_s": bytes_written * rate if rate and bytes_written is not None else None,
        "net_out_bytes_per_s": net_bytes_out * rate if rate and net_bytes_out is not None else None,
        **_transform_fracs(tr, 0, ""),
        "n_files_transformed": float(len({o for _, _, o in tr[1] if o})),
    }

    ent = np.asarray([x for x in entropy if x is not None], dtype=float)
    ent = ent[np.isfinite(ent)]
    has = ent.size > 0
    f.update({
        "entropy_mean": float(ent.mean()) if has else None,
        "entropy_max": float(ent.max()) if has else None,
        "entropy_p90": float(np.percentile(ent, 90)) if has else None,
        "entropy_high_frac": float((ent > HIGH_ENTROPY).mean()) if has else None,
        "entropy_slope": float(np.polyfit(np.arange(ent.size), ent, 1)[0]) if ent.size >= 2 else None,
        "n_entropy_samples": float(ent.size),
    })
    f.update(recent_features(events, entropy, kinds, tr))
    return {k: f[k] for k in SECURITY_FEATURES}

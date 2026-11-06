"""Syscall + file-entropy window features for the security model.

Input events are `{"syscall": str, "path": str, "new_path": str?, "ts_ms": int?}`
(Falco `evt.type` / `fd.name`). Pure functions shared by the synthetic
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
    "rename_ext_change_ratio", "suspicious_ext_ratio", "ransom_note",
    "entropy_mean", "entropy_max", "entropy_p90", "entropy_high_frac", "entropy_slope", "n_entropy_samples",
    "write_bytes_per_s", "net_out_bytes_per_s",
]

SYSCALL_GROUPS: dict[str, frozenset[str]] = {
    "read": frozenset({"read", "pread", "pread64", "readv", "preadv", "preadv2"}),
    "write": frozenset({"write", "pwrite", "pwrite64", "writev", "pwritev", "pwritev2"}),
    "open": frozenset({"open", "openat", "openat2", "creat"}),
    "rename": frozenset({"rename", "renameat", "renameat2"}),
    "unlink": frozenset({"unlink", "unlinkat", "rmdir"}),
    "truncate": frozenset({"truncate", "ftruncate"}),
    "network": frozenset({"connect", "accept", "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom",
                          "recvmsg", "socket", "bind", "listen"}),
    "mmap": frozenset({"mmap", "munmap", "mprotect"}),
    "exec": frozenset({"execve", "execveat"}),
    "chmod": frozenset({"chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown"}),
}

# What live windows can contain: the syscall groups deploy/k8s/falco-kubeheal-rules.yaml emits, and only on data
# volumes. Network / mmap / exec and other background syscalls never reach the agent, so the synthetic
# generator drops them too (training windows must look like live ones; tests/test_features_security.py
# checks the rule file against this set).
CAPTURED_GROUPS: tuple[str, ...] = ("read", "write", "open", "rename", "unlink", "truncate", "chmod")
MAX_ENTROPY_SAMPLES = 8   # files the agent reads per evaluation (n_entropy_samples is at most this)
# Window definition shared by the agent and the synthetic generator (train/serve parity):
# the newest <= MAX_WINDOW_EVENTS events no older than WINDOW_S before the newest one, lasting window_seconds().
MAX_WINDOW_EVENTS = 512
WINDOW_S = 60.0
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
    renames: list[tuple[str, str]] = []
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
            renames.append((path, new_path))
            written.add(new_path)

    f: dict[str, float | None] = {
        "n_events": float(n),
        "events_per_s": n * rate if rate else None,
        **{f"frac_{g}": (c / n if n else None) for g, c in groups.items()},
        "unique_paths": float(len(paths)),
        "unique_dirs": float(len({posixpath.dirname(p) for p in paths})),
        "files_written_per_s": len(written) * rate if rate else None,
        "rename_ext_change_ratio": (sum(_ext(a) != _ext(b) for a, b in renames) / len(renames)) if renames else None,
        "suspicious_ext_ratio": (sum(_ext(p) in SUSPICIOUS_EXTENSIONS for p in written) / len(written)) if written else None,
        "ransom_note": float(any(_is_note(p) for p in paths | written)),
        "write_bytes_per_s": bytes_written * rate if rate and bytes_written is not None else None,
        "net_out_bytes_per_s": net_bytes_out * rate if rate and net_bytes_out is not None else None,
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
    return {k: f[k] for k in SECURITY_FEATURES}

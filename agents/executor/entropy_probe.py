"""Read-only entropy probe used by the Executor's restored-volume Job.

Exit codes: 0 = scan completed below threshold, 10 = high-entropy file found,
11 = no trustworthy verdict (empty volume, traversal/read error, or bad input).
The caller treats every other result as unknown and keeps quarantine active.
"""

import json
import math
import os
import stat
import sys
from collections import Counter
from typing import Iterable

ENTROPY_THRESHOLD = 7.2  # Matches SecurityAgent's existing default threshold.
READ_CHUNK_BYTES = 64 * 1024


def file_entropy(path: str):
    """Return (entropy, error); never follow a symlink or accept a non-regular file."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return None, str(exc)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "not a regular file"
        counts = Counter()
        total = 0
        while True:
            chunk = os.read(fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            counts.update(chunk)
            total += len(chunk)
        if total == 0:
            return 0.0, None
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        return entropy, None
    finally:
        os.close(fd)


def scan_roots(roots: Iterable[str], threshold: float = ENTROPY_THRESHOLD):
    files = 0
    unreadable = 0
    high_entropy = 0
    errors = []

    def walk_error(exc):
        nonlocal unreadable
        unreadable += 1
        errors.append(str(exc))

    for root in roots:
        if not os.path.isdir(root):
            unreadable += 1
            errors.append(f"volume mount unavailable: {root}")
            continue
        for directory, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
            # Do not descend through symlinked directories.
            safe_dirnames = []
            for name in dirnames:
                path = os.path.join(directory, name)
                if os.path.islink(path):
                    unreadable += 1
                    errors.append(f"symlink directory skipped: {path}")
                else:
                    safe_dirnames.append(name)
            dirnames[:] = safe_dirnames
            for name in filenames:
                path = os.path.join(directory, name)
                if os.path.islink(path):
                    unreadable += 1
                    errors.append(f"symlink skipped: {path}")
                    continue
                entropy, error = file_entropy(path)
                if error:
                    unreadable += 1
                    errors.append(f"{path}: {error}")
                    continue
                files += 1
                if entropy > threshold:
                    high_entropy += 1

    if files == 0 or unreadable:
        verdict = "unknown"
    elif high_entropy:
        verdict = "high_entropy"
    else:
        verdict = "clean"
    return {"verdict": verdict, "files_scanned": files,
            "high_entropy_files": high_entropy, "unreadable": unreadable,
            "errors": errors[:20]}


def main(argv=None):
    roots = list(argv if argv is not None else sys.argv[1:])
    result = scan_roots(roots)
    print(json.dumps(result, sort_keys=True), flush=True)
    return {"clean": 0, "high_entropy": 10, "unknown": 11}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Non-destructive detection test workload for KubeHeal's security agent.

Generates the file-I/O pattern of ransomware — a burst of high-entropy writes
followed by renames with a new extension — so the security model's detection
path can be exercised end to end. It is deliberately harmless:

  * It only ever touches files it created itself in this run (tracked by path);
    it never opens, reads, modifies, or deletes any pre-existing file. (It reads
    back its own placeholder files before overwriting them, like real ransomware
    reads plaintext, so the I/O pattern is realistic.)
  * There is no cryptography and no key material; "encryption" is just
    ``os.urandom`` bytes, which read as high entropy to the detector.

Safety gate (refuses to run otherwise):
  * ``--sandbox DIR`` must be passed explicitly, and
  * DIR must already contain a ``.kubeheal-sandbox`` marker file.

The loop is bounded by ``--max-files`` and ``--duration``. ``--cleanup`` removes
everything this tool created (its generated files and the test note) and exits.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

MARKER = ".kubeheal-sandbox"
PREFIX = "khtest_"          # every generated file starts with this
PLAIN_EXT = ".dat"
ENCRYPTED_EXT = ".khlocked"
NOTE_NAME = "KUBEHEAL_TEST_NOTE.txt"
NOTE_TEXT = "KubeHeal detection test - no data was harmed\n"
PLACEHOLDER = b"benign placeholder content\n"
BLOCK = 1024                # partial-overwrite granularity


def require_sandbox(path: Path) -> None:
    """Exit unless `path` is an explicitly marked sandbox directory."""
    if not path.is_dir():
        sys.exit(f"refusing to run: {path} is not a directory")
    if not (path / MARKER).is_file():
        sys.exit(
            f"refusing to run: {path} has no {MARKER} marker.\n"
            f"This tool only runs inside a marked sandbox. Create the marker "
            f"deliberately (touch {path}/{MARKER}) if this really is a throwaway dir."
        )


def cleanup(path: Path) -> int:
    """Delete only the files this tool creates (its own prefix + note)."""
    removed = 0
    for p in list(path.glob(f"{PREFIX}*{PLAIN_EXT}")) + list(path.glob(f"{PREFIX}*{ENCRYPTED_EXT}")):
        p.unlink(missing_ok=True)
        removed += 1
    note = path / NOTE_NAME
    if note.exists():
        note.unlink()
        removed += 1
    return removed


def overwrite(data: bytes, partial: float) -> bytes:
    """High-entropy bytes over all of `data`, or over every k-th BLOCK when partial < 1 (k = 1/partial):
    the intermittent pattern that leaves files half-readable and mid-entropy."""
    step = max(1, round(1 / partial)) if partial > 0 else 1
    if step == 1:
        return os.urandom(len(data) or 4096)
    out = bytearray(data)
    for off in range(0, len(out), step * BLOCK):
        out[off:off + BLOCK] = os.urandom(len(out[off:off + BLOCK]))
    return bytes(out)


def run(path: Path, num_files: int, max_files: int, duration_s: float, rate: float, file_size: int = 864,
        rename: bool = True, partial: float = 1.0, delay_s: float = 0.0) -> int:
    """Create our own files, then high-entropy-overwrite (+ optionally rename) each one."""
    n = min(num_files, max_files)
    created = [path / f"{PREFIX}{i:04d}{PLAIN_EXT}" for i in range(n)]
    placeholder = (PLACEHOLDER * (file_size // len(PLACEHOLDER) + 1))[:max(file_size, 1)]
    for f in created:
        f.write_bytes(placeholder)
    print(f"created {len(created)} files in {path}", flush=True)
    time.sleep(delay_s)                      # quiet gap: separates the setup from the overwrite phase

    deadline = time.monotonic() + duration_s
    delay = 1.0 / rate if rate > 0 else 0.0
    touched = 0
    for src in created:                      # only files we just created
        if time.monotonic() >= deadline:
            break
        src.write_bytes(overwrite(src.read_bytes(), partial))    # read our own placeholder first, as ransomware does
        if rename:
            src.rename(src.with_name(src.stem + ENCRYPTED_EXT))
        touched += 1
        if delay:
            time.sleep(delay)
    (path / NOTE_NAME).write_text(NOTE_TEXT)
    return touched


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sandbox", required=True, help="marked sandbox dir (must contain .kubeheal-sandbox)")
    ap.add_argument("--num-files", type=int, default=100)
    ap.add_argument("--max-files", type=int, default=500, help="hard cap on files created")
    ap.add_argument("--rate", type=float, default=180.0, help="files/second")
    ap.add_argument("--duration", type=float, default=60.0, help="max seconds of the overwrite phase")
    ap.add_argument("--file-size", type=int, default=864, help="bytes per created file (max 16 MiB)")
    ap.add_argument("--no-rename", dest="rename", action="store_false", help="overwrite in place only")
    ap.add_argument("--partial", type=float, default=1.0,
                    help="fraction of each file overwritten (every 1/f-th 1 KiB block); 1 = whole file")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to wait between creating and overwriting")
    ap.add_argument("--cleanup", action="store_true", help="delete what this tool created, then exit")
    args = ap.parse_args()

    sandbox = Path(args.sandbox).resolve()
    require_sandbox(sandbox)

    if args.cleanup:
        print(f"cleaned up {cleanup(sandbox)} generated files", flush=True)
        return

    if not 0 < args.file_size <= 16 << 20 or not 0 < args.partial <= 1:
        sys.exit("refusing to run: --file-size must be in (0, 16 MiB] and --partial in (0, 1]")
    touched = run(sandbox, args.num_files, args.max_files, args.duration, args.rate, args.file_size,
                  args.rename, args.partial, args.delay)
    print(f"overwrote{'+renamed' if args.rename else ''} {touched} self-created files, wrote {NOTE_NAME}", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Non-destructive detection test workload for KubeHeal's security agent.

Generates the file-I/O pattern of ransomware — a burst of high-entropy writes
followed by renames with a new extension — so the security model's detection
path can be exercised end to end. It is deliberately harmless:

  * It only ever touches files it created itself in this run (O_EXCL|O_NOFOLLOW,
    recorded in a ledger); it never opens, reads, modifies, or deletes any pre-existing file. (It reads
    back its own placeholder files before overwriting them, like real ransomware
    reads plaintext, so the I/O pattern is realistic.)
  * There is no cryptography and no key material; "encryption" is just
    ``os.urandom`` bytes, which read as high entropy to the detector.

Safety gate (refuses to run otherwise):
  * ``--sandbox DIR`` must be passed explicitly, and
  * DIR must already contain a ``.kubeheal-sandbox`` marker file.

The loop is bounded by ``--max-files`` and ``--duration``. ``--cleanup`` removes
what this tool created and exits: only files listed in its ``.kubeheal-created`` ledger.
Every file is created O_EXCL|O_NOFOLLOW, so a planted file or symlink is skipped, never written through.
"""

from __future__ import annotations

import argparse
import os
import stat
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


LEDGER = ".kubeheal-created"    # names of the files this run created; --cleanup deletes only these


def _open(p: Path, flags: int) -> int:
    """Open without following a symlink; O_CREAT always means O_EXCL (never touch an existing file)."""
    if flags & os.O_CREAT:
        flags |= os.O_EXCL
    return os.open(p, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)


def _create(p: Path, data: bytes, ledger: int) -> None:
    os.write(ledger, p.name.encode() + b"\n")       # ledger first: a crash after create still gets cleaned
    with os.fdopen(_open(p, os.O_WRONLY | os.O_CREAT), "wb") as f:
        f.write(data)


def cleanup(path: Path) -> int:
    """Delete only regular files listed in the ledger (never a glob, never a symlink)."""
    try:
        with os.fdopen(_open(path / LEDGER, os.O_RDONLY)) as f:
            names = f.read().splitlines()
    except OSError:
        return 0
    removed = 0
    for name in names:
        if not name or name != os.path.basename(name) or name in (".", ".."):
            continue
        p = path / name
        try:
            if stat.S_ISREG(os.lstat(p).st_mode):
                p.unlink()
                removed += 1
        except FileNotFoundError:
            pass
    (path / LEDGER).unlink()
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
    placeholder = (PLACEHOLDER * (file_size // len(PLACEHOLDER) + 1))[:max(file_size, 1)]
    try:
        ledger = _open(path / LEDGER, os.O_WRONLY | os.O_CREAT)
    except FileExistsError:
        sys.exit(f"refusing to run: {path / LEDGER} exists - run --cleanup first")
    with os.fdopen(ledger, "wb", buffering=0):
        created = []
        for i in range(n):
            f = path / f"{PREFIX}{i:04d}{PLAIN_EXT}"
            try:
                _create(f, placeholder, ledger)
            except FileExistsError:
                print(f"skipped {f.name}: already exists (not ours)", flush=True)
                continue
            created.append(f)
        print(f"created {len(created)} files in {path}", flush=True)
        time.sleep(delay_s)                  # quiet gap: separates the setup from the overwrite phase

        print(f"overwrite_start_ms={time.time_ns() // 1_000_000}", flush=True)    # bench.sh: first malicious op
        deadline = time.monotonic() + duration_s
        delay = 1.0 / rate if rate > 0 else 0.0
        touched = 0
        for src in created:                  # only files we just created
            if time.monotonic() >= deadline:
                break
            try:
                with os.fdopen(_open(src, os.O_RDONLY), "rb") as f:    # read our own placeholder first, as ransomware does
                    data = f.read()
                with os.fdopen(_open(src, os.O_WRONLY | os.O_TRUNC), "wb") as f:
                    f.write(overwrite(data, partial))
                if rename:
                    dst = src.with_name(src.stem + ENCRYPTED_EXT)
                    if os.path.lexists(dst):         # shortcut: check-then-rename race, fine inside a private sandbox
                        raise FileExistsError(dst)
                    os.write(ledger, dst.name.encode() + b"\n")
                    src.rename(dst)
            except OSError as e:
                print(f"skipped {src.name}: {e}", flush=True)
                continue
            touched += 1
            if delay:
                time.sleep(delay)
        try:
            _create(path / NOTE_NAME, NOTE_TEXT.encode(), ledger)
        except FileExistsError:
            print(f"skipped {NOTE_NAME}: already exists (not ours)", flush=True)
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

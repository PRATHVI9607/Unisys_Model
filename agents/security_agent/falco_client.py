"""
Falco event client — KubeHeal v4 Security Agent.
================================================
Consumes REAL Falco syscall events. Two transports, auto-selected:

  1. gRPC Outputs API  — if `grpcio` + the generated Falco stubs
     (falco_output_pb2 / falco_output_pb2_grpc) are importable AND
     FALCO_GRPC_ADDR points at a Falco gRPC endpoint. This is Falco's
     official streaming API (unix:///run/falco/falco.sock by default).

  2. JSON output tail   — the dependency-free path used in most clusters:
     Falco is run with `json_output: true` + `file_output` to a shared file
     (or a named pipe); we tail it line-by-line. Each line is one event.

Both yield a normalised event dict:
    {syscall, pid, pod, namespace, fd_path, rule, priority, ts}

The DaemonSet mounts Falco's output; if neither transport is available the
caller falls back to the /proc write-byte tracker (still fully functional).

P5 adds a third source, REPLAY: recorded Falco JSON output (one JSON event per line, the same lines
Falco's `file_output` writes) is streamed from a file or a directory of `*.jsonl` / `*.json` files
through the same `_normalise`, so everything downstream (window tracker, model input builder, entropy
check, publish) is identical to live mode. Use it on machines where Falco cannot run (for example k3d on
Docker Desktop) and in tests. Mode selection (`resolve_falco_mode`), env:

  FALCO_MODE         auto (default) | live | replay | off
                     auto: live if the JSON events file or the gRPC unix socket exists, else off.
                     auto NEVER selects replay: recorded events must be asked for explicitly with
                     FALCO_MODE=replay, so a missing Falco cannot silently turn into canned data.
  FALCO_ENABLED      legacy flag. Used only when FALCO_MODE is unset: "true" forces live. "false" (the value
                     the current manifest sets) is treated as auto so Falco is used when it is there; set
                     FALCO_MODE=off to switch Falco input off explicitly.
  FALCO_EVENTS_PATH  JSON output file for live mode (default /var/run/falco/events.jsonl)
  FALCO_GRPC_ADDR    gRPC Outputs API address for live mode
  FALCO_REPLAY_PATH  trace file or directory for replay mode
  FALCO_REPLAY_DELAY_S  pause between replayed events, default 0 (as fast as the consumer takes them)
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Awaitable, Callable, Dict, Iterator, Optional, Tuple

logger = logging.getLogger(__name__)

# Falco "evt.type" values we care about for ransomware behaviour
RANSOMWARE_SYSCALLS = {
    "open", "openat", "write", "pwrite", "pwritev", "rename", "renameat",
    "renameat2", "ftruncate", "truncate", "unlink", "unlinkat", "mmap", "msync",
}


# Falco only puts a field into `output_fields` if the rule's output string references it. The rules in
# k8s/falco-kubeheal-rules.yaml now reference evt.type (added in the P5 merge), so their events carry the
# real syscall name. For events from older or custom rules without it, the syscall family is taken from the
# rule name (substring, lower case). The result is marked
# `syscall_inferred` and is the family the rule's condition selects (the rename rule fires on
# rename/renameat/renameat2, the write rule on write/pwrite/pwritev/ftruncate/truncate, the note rule on
# open/openat/creat), not the exact syscall.
RULE_SYSCALL_FALLBACK = (
    ("mass rename", "rename"),
    ("mass write", "write"),
    ("note dropped", "open"),
)


# Falco gRPC Outputs API: `priority` is a protobuf enum, so resp.priority is an int. The table is the
# Priority enum of falcosecurity/client-go, pkg/api/schema (EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3,
# WARNING=4, NOTICE=5, INFORMATIONAL=6, DEBUG=7), as confirmed by the project owner on 2026-11-10; the repo
# has no generated stubs to check it against. tests/test_sense_falco_replay.py pins the table. When the
# response object carries its own enum descriptor that is used first (see `priority_name`).
FALCO_PRIORITY_BY_NUMBER = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}


def priority_name(value, enum_type=None) -> str:
    """Lower-case priority NAME for a Falco priority given as a name ("Critical", "CRITICAL") or as an enum
    number (int or digit string). `enum_type` is an optional protobuf EnumDescriptor whose
    `values_by_number` wins over the fallback table. Unknown numbers give "" (never a guess)."""
    if isinstance(value, str) and not value.strip().lstrip("-").isdigit():
        return value.strip().lower()
    try:
        n = int(value)
    except (TypeError, ValueError):
        return ""
    if enum_type is not None:
        try:
            return enum_type.values_by_number[n].name.lower()
        except (KeyError, AttributeError):
            pass
    return FALCO_PRIORITY_BY_NUMBER.get(n, "")


def _event_from_grpc_response(resp) -> Optional[Dict]:
    """Falco gRPC response -> normalised event. The enum name, not str(number), goes into `priority`."""
    enum_type = None
    try:
        enum_type = resp.DESCRIPTOR.fields_by_name["priority"].enum_type
    except (AttributeError, KeyError):
        pass
    return _normalise({"rule": resp.rule,
                       "priority": priority_name(resp.priority, enum_type),
                       "time": str(resp.time),
                       "output_fields": dict(resp.output_fields)})


def _normalise(evt: Dict) -> Optional[Dict]:
    """Map a Falco JSON event → KubeHeal's normalised event."""
    of = evt.get("output_fields", evt)
    syscall = (of.get("evt.type") or of.get("syscall") or "").lower()
    inferred = False
    if not syscall:
        rule = (evt.get("rule") or "").lower()
        for needle, fallback in RULE_SYSCALL_FALLBACK:
            if needle in rule:
                syscall, inferred = fallback, True
                break
    if not syscall:
        return None
    event_time = evt.get("time")
    if not event_time:
        # Falco's `evt.time` is epoch nanoseconds. Convert that source field to an explicit UTC string;
        # downstream code never has to guess the unit of an integer timestamp.
        raw_ns = of.get("evt.time")
        try:
            ns = int(raw_ns)
            if ns > 0:
                event_time = datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat().replace(
                    "+00:00", "Z")
        except (TypeError, ValueError, OSError, OverflowError):
            pass
    return {
        "syscall_inferred": inferred,
        "syscall": syscall,
        "pid": _to_int(of.get("proc.pid") or of.get("pid")),
        "pod": of.get("k8s.pod.name") or of.get("container.name") or "",
        "namespace": of.get("k8s.ns.name") or "default",
        "fd_path": of.get("fd.name") or of.get("fd.path") or "",
        "rule": evt.get("rule", ""),
        "priority": priority_name(evt.get("priority") or ""),
        "ts": event_time or "",
    }


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


async def _tail_json(path: str) -> AsyncIterator[Dict]:
    """Async tail -f of Falco's JSON output file (one event per line)."""
    # Wait for the file to appear (Falco may start after us)
    while not os.path.exists(path):
        await asyncio.sleep(2)
    logger.info(f"Tailing Falco JSON output: {path}")
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)   # only new events
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.25)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                evt = _normalise(json.loads(line))
                if evt:
                    yield evt
            except json.JSONDecodeError:
                continue


async def _stream_grpc(addr: str) -> AsyncIterator[Dict]:
    """Falco gRPC Outputs API stream (only if stubs are present)."""
    import grpc  # noqa: F401  (presence checked by caller)
    from falco_output_pb2 import request as OutputsRequest  # type: ignore
    import falco_output_pb2_grpc as outputs_grpc            # type: ignore

    target = addr if "://" in addr else f"unix://{addr}" if addr.startswith("/") else addr
    async with grpc.aio.insecure_channel(target) as channel:
        stub = outputs_grpc.serviceStub(channel)
        logger.info(f"Falco gRPC stream connected: {target}")
        async for resp in stub.sub(OutputsRequest()):
            try:
                yield _event_from_grpc_response(resp) or {}
            except Exception:
                continue


async def falco_event_stream(grpc_addr: str = "", json_path: str = "") -> AsyncIterator[Dict]:
    """Yield normalised Falco events from gRPC (preferred) or JSON tail."""
    # Try gRPC only if grpcio + stubs import cleanly
    if grpc_addr:
        try:
            import grpc  # noqa: F401
            import falco_output_pb2  # noqa: F401
            import falco_output_pb2_grpc  # noqa: F401
            async for e in _stream_grpc(grpc_addr):
                if e:
                    yield e
            return
        except ImportError:
            logger.info("Falco gRPC stubs unavailable; using JSON tail")
        except Exception as e:
            logger.warning(f"Falco gRPC failed ({e}); using JSON tail")

    path = json_path or os.environ.get("FALCO_EVENTS_PATH", "/var/run/falco/events.jsonl")
    async for e in _tail_json(path):
        yield e


# --------------------------------------------------------------------------------------------------
# Replay (P5-S2)
# --------------------------------------------------------------------------------------------------

def iter_trace_events(path: str) -> Iterator[Dict]:
    """Yield normalised events from a recorded Falco JSON trace: a file, or every `*.jsonl` / `*.json`
    file of a directory in name order. Blank lines and lines starting with '#' are skipped. Lines that are
    not valid JSON, or that carry no usable syscall, are counted and reported in the log at the end."""
    p = Path(path)
    files = sorted(f for f in p.iterdir() if f.suffix in (".jsonl", ".json")) if p.is_dir() else [p]
    bad = unusable = 0
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    evt = _normalise(json.loads(line))
                except json.JSONDecodeError:
                    bad += 1
                    continue
                if evt:
                    yield evt
                else:
                    unusable += 1
    if bad or unusable:
        logger.warning("Falco replay %s: %d malformed line(s), %d event(s) without a syscall skipped",
                       path, bad, unusable)


async def replay_stream(path: str, delay_s: float = 0.0,
                        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> AsyncIterator[Dict]:
    """Async stream over a recorded trace; same event shape as the live transports. Finite: it ends when
    the trace ends."""
    for evt in iter_trace_events(path):
        yield evt
        await sleep(delay_s)      # also yields to the event loop when delay_s is 0


def resolve_falco_mode(env=None, exists: Callable[[str], bool] = os.path.exists) -> Tuple[str, str]:
    """(mode, reason) with mode one of live, replay, off. Pure apart from `exists`, for tests.
    Replay is reachable only with FALCO_MODE=replay, never through auto."""
    env = os.environ if env is None else env
    mode = (env.get("FALCO_MODE") or "").strip().lower()
    if not mode:
        mode = "live" if (env.get("FALCO_ENABLED") or "").strip().lower() == "true" else "auto"
    events_path = env.get("FALCO_EVENTS_PATH", "/var/run/falco/events.jsonl")
    grpc_addr = env.get("FALCO_GRPC_ADDR", "")
    replay_path = env.get("FALCO_REPLAY_PATH", "")
    if mode in ("off", "live"):
        return mode, f"FALCO_MODE/FALCO_ENABLED = {mode}"
    if mode == "replay":
        if replay_path:
            return "replay", "FALCO_MODE=replay"
        return "off", "FALCO_MODE=replay but FALCO_REPLAY_PATH is not set"
    if mode != "auto":
        return "off", f"unknown FALCO_MODE {mode!r}"
    if grpc_addr.startswith("unix://"):
        sock = grpc_addr[len("unix://"):]
    elif grpc_addr.startswith("/"):
        sock = grpc_addr
    else:
        sock = ""
    if exists(events_path):
        return "live", f"auto: Falco JSON output {events_path} exists"
    if sock and exists(sock):
        return "live", f"auto: Falco gRPC socket {sock} exists"
    return "off", ("auto: no Falco output found; using the /proc write tracker only "
                   "(set FALCO_MODE=replay and FALCO_REPLAY_PATH to replay a recorded trace)")

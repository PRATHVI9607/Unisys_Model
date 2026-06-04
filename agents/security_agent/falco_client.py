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
"""

import asyncio
import json
import logging
import os
from typing import AsyncIterator, Dict, Optional

logger = logging.getLogger(__name__)

# Falco "evt.type" values we care about for ransomware behaviour
RANSOMWARE_SYSCALLS = {
    "open", "openat", "write", "pwrite", "pwritev", "rename", "renameat",
    "renameat2", "ftruncate", "truncate", "unlink", "unlinkat", "mmap", "msync",
}


def _normalise(evt: Dict) -> Optional[Dict]:
    """Map a Falco JSON event → KubeHeal's normalised event."""
    of = evt.get("output_fields", evt)
    syscall = (of.get("evt.type") or of.get("syscall") or "").lower()
    if not syscall:
        return None
    return {
        "syscall": syscall,
        "pid": _to_int(of.get("proc.pid") or of.get("pid")),
        "pod": of.get("k8s.pod.name") or of.get("container.name") or "",
        "namespace": of.get("k8s.ns.name") or "default",
        "fd_path": of.get("fd.name") or of.get("fd.path") or "",
        "rule": evt.get("rule", ""),
        "priority": (evt.get("priority") or "").lower(),
        "ts": evt.get("time") or of.get("evt.time") or "",
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
                fields = dict(resp.output_fields)
                yield _normalise({"rule": resp.rule, "priority": str(resp.priority),
                                  "time": str(resp.time), "output_fields": fields}) or {}
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

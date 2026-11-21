# ruff: noqa: ASYNC109, ASYNC220, ASYNC221, ASYNC230, ASYNC240, ASYNC251
"""Offline CPU / RSS benchmark of one agent (not a test: pytest does not collect it).

    nice -n 19 uv run --all-extras python tests/bench_load.py security --rate 10000 --pods 50 --secs 10
    nice -n 19 uv run --all-extras python tests/bench_load.py fusion --rate 200 --secs 10
    add --uvloop to run the agent on uvloop; --idle for no events at all

The agent runs in this process; Redis (fakeredis TCP server), the Falco-file writer and the stream feeder are
separate processes, so the numbers are the agent's own: resident memory (after import, idle, peak under load)
and CPU seconds per wall second while events flow (kube is a stub, the embedded model is the real one).
"""

from __future__ import annotations

import argparse
import asyncio
import resource
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]


def rss_mb(field: str = "VmRSS") -> float:
    for ln in open("/proc/self/status"):
        if ln.startswith(field):
            return int(ln.split()[1]) / 1024
    return 0.0


def cpu() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def feeder(kind: str, path: str, rate: float, secs: float, pods: int, port: int) -> None:
    """Writer process: Falco lines into `path` (security), or SecurityEvents into the stream (fusion)."""
    import orjson
    t_end, tick = time.time() + secs, 0.01
    if kind == "security":
        out = open(path, "ab", buffering=0)
        mix = [("openat", "O_RDONLY"), ("openat", "O_WRONLY|O_CREAT"), ("openat", "O_RDONLY"), ("unlink", None),
               ("openat", "O_RDONLY"), ("renameat2", None)]
        n = 0
        while time.time() < t_end:
            t = time.time()
            batch = []
            for _ in range(int(rate * tick)):
                evt, flags = mix[n % len(mix)]
                pod = n % pods
                f = {"evt.type": evt, "fd.name": f"/data/f{n % 500}", "proc.pid": 4242, "k8s.ns.name": "prod-shop",
                     "k8s.pod.name": f"web-{pod}-x2x7q", "k8s.pod.uid": str(uuid.UUID(int=pod)), "evt.arg.flags": flags,
                     "evt.time": time.time_ns(), "container.id": ""}
                if evt == "renameat2":
                    f.update({"fd.name": None, "fs.path.source": f"/data/f{n % 500}", "fs.path.target": f"/data/g{n % 500}"})
                batch.append(orjson.dumps({"output": "x", "priority": "W", "rule": "r", "output_fields": f}))
                n += 1
            out.write(b"\n".join(batch) + b"\n")
            time.sleep(max(0.0, tick - (time.time() - t)))
    else:
        import redis

        from kubeheal.contracts import STREAM_SECURITY, SecurityEvent
        r = redis.Redis(port=port, decode_responses=True)
        n = 0
        while time.time() < t_end:
            t = time.time()
            for _ in range(int(rate * tick)):
                ev = SecurityEvent(event_id=f"s{n}", namespace="prod-shop", workload=f"web-{n % pods}", pod=f"web-{n % pods}-x",
                                   label="benign", risk=0.05, uncertain=False, features={"n_events": 10.0},
                                   pod_uid=str(uuid.UUID(int=n % pods)))
                r.xadd(STREAM_SECURITY, ev.to_fields(), maxlen=10000, approximate=True)
                n += 1
            time.sleep(max(0.0, tick - (time.time() - t)))


async def run(args) -> None:
    from bench_kill_latency import PollingRedis
    from test_agent_fusion_contract import FakeKube

    from agents.fusion_agent import agent as fa
    from agents.security_agent import agent as sa
    from agents.security_agent.falco import FalcoTail
    from kubeheal.ml.bundle import ModelBundle

    t_import = rss_mb()
    tmp = Path(tempfile.mkdtemp(prefix="kh-load-"))
    (tmp / "events.jsonl").write_bytes(b"")
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    redis_proc = subprocess.Popen([sys.executable, "-c", (
        "import socket\nfrom fakeredis import TcpFakeServer as S\n"
        f"s = S(('127.0.0.1', {port}))\ng = s.get_request\n"
        "def get_request():\n    c, a = g()\n    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)\n    return c, a\n"
        "s.get_request = get_request\ns.serve_forever()")])
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            break
        except OSError:
            time.sleep(0.05)
    r = PollingRedis.make(host="127.0.0.1", port=port, decode_responses=True)
    kube = FakeKube()
    tasks = []
    if args.agent == "security":
        sa.CGROUP_ROOT = str(tmp / "cg")
        bundle = ModelBundle.load(ROOT / "models" / "security")
        await asyncio.to_thread(bundle.predict_batch, [{}], 0.0)
        agent = sa.SecurityAgent(r, None, sa.OwnerResolver(kube, kube), proc_root=str(tmp / "proc"), protected=frozenset(),
                                 namespaces=[], bundle=bundle)
        tail = FalcoTail(str(tmp / "events.jsonl"))
        tail.read_lines()
        tasks = [asyncio.create_task(agent.tail_loop(tail)), asyncio.create_task(agent.eval_loop())]
    else:
        agent = fa.FusionAgent(r, kube, kube, kube, kube, mode="observe")
        tasks = [asyncio.create_task(agent.run())]
    await asyncio.sleep(1.0)
    t_idle0, w0 = cpu(), time.time()
    await asyncio.sleep(args.idle_s)
    idle_cpu = (cpu() - t_idle0) / (time.time() - w0)
    t_up = rss_mb()
    n_in = 0
    if not args.idle:
        feeder_proc = subprocess.Popen([sys.executable, __file__, "--feeder", args.agent, "--path", str(tmp / "events.jsonl"),
                                        "--rate", str(args.rate), "--secs", str(args.secs), "--pods", str(args.pods),
                                        "--port", str(port)])
        c0, w0 = cpu(), time.time()
        feeder_proc.wait()
        await asyncio.sleep(1.0)
        load_cpu = (cpu() - c0) / (time.time() - w0)
        if args.agent == "security":
            n_in = int(sa.EVENTS._value.get())
        else:
            n_in = int(sum(c._value.get() for c in fa.DECISIONS._metrics.values()))
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    redis_proc.kill()
    print(f"{args.agent} uvloop={args.uvloop} rate={0 if args.idle else args.rate}/s: rss after import {t_import:.0f} MB, "
          f"idle {t_up:.0f} MB, peak {rss_mb('VmHWM'):.0f} MB; idle cpu {idle_cpu * 100:.1f}%"
          + ("" if args.idle else f"; loaded cpu {load_cpu * 100:.1f}% ({n_in} events handled)"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("agent", nargs="?", choices=["security", "fusion"])
    ap.add_argument("--feeder")
    ap.add_argument("--path")
    ap.add_argument("--port", type=int)
    ap.add_argument("--rate", type=float, default=10000.0)
    ap.add_argument("--pods", type=int, default=50)
    ap.add_argument("--secs", type=float, default=10.0)
    ap.add_argument("--idle-s", type=float, default=3.0)
    ap.add_argument("--idle", action="store_true")
    ap.add_argument("--uvloop", action="store_true")
    args = ap.parse_args()
    if args.feeder:
        return feeder(args.feeder, args.path, args.rate, args.secs, args.pods, args.port)
    import logging
    logging.disable(logging.CRITICAL)
    if args.uvloop:
        import uvloop
        asyncio.run(run(args), loop_factory=uvloop.new_event_loop)
    else:
        asyncio.run(run(args))


if __name__ == "__main__":
    main()

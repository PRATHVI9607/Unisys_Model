# ruff: noqa: ASYNC109, ASYNC220, ASYNC221, ASYNC230, ASYNC240, ASYNC251
"""Offline end-to-end kill-latency benchmark (not a test: pytest does not collect it).

Replays the detection-test attack (setup creates, then read + overwrite + rename-with-suffix per file) into a
real events.jsonl at a fixed files/s from a separate process, and runs the real SecurityAgent (real FalcoTail,
embedded model + TreeSHAP, real entropy reads from a fake /proc) and the real FusionAgent (fakeredis, fake kube
with a fixed per-call latency) in one event loop. Reports the per-stage time of the event chain that ends in the
kill, from the first malicious write to the cgroup freeze.

    nice -n 19 uv run --all-extras python tests/bench_kill_latency.py --rate 180 --runs 7
    nice -n 19 uv run --all-extras python tests/bench_kill_latency.py --rate 2 --runs 5 --files 80

Stage hooks wrap SecurityAgent.{ingest,evaluate_batch,features,score}, FalcoTail.read_lines, publish_event,
FusionAgent.{process,kill,_contain} and SecurityAgent.contain: keep those names stable.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

POD, NS, PID = "web-7d9f8b6c5-x2x7q", "prod-shop", 4242
STAGES = ["evidence", "write>tail", "tail>ingest", "ingest>eval", "features", "predict+shap", "owner+publish>fusion",
          "fusion pre-freeze", "contain>agent", "freeze"]


# ── writer (own process: the workload is not in the agent's GIL) ─────────────────────────────────────────
def line(ns_time: int, evt: str, path: str, uid: str, flags: str | None = None, new: str | None = None) -> bytes:
    f = {"evt.type": evt, "fd.name": None if new else path, "proc.pid": PID, "k8s.ns.name": NS, "k8s.pod.name": POD,
         "k8s.pod.uid": uid, "evt.arg.flags": flags, "evt.time": ns_time, "container.id": ""}
    if new:
        f.update({"fs.path.source": path, "fs.path.target": new})
    import orjson
    return orjson.dumps({"output": "x", "priority": "Warning", "rule": "r", "output_fields": f}) + b"\n"


def writer(d: str, rate: float, files: int, uid: str) -> None:
    root = Path(d)
    data, events = root / "proc" / str(PID) / "root" / "data", root / "events.jsonl"
    iostat = next((root / "cg").rglob("io.stat"))
    wbytes = 0
    out = open(events, "ab", buffering=0)
    wlog = open(root / "writes.log", "ab", buffering=0)   # "ts_ms time" per event, readable while we run

    def emit(*lines_: tuple) -> None:
        nonlocal wbytes
        buf = b""
        for args in lines_:
            ns = time.time_ns()
            buf += line(ns, args[0], args[1], uid, *args[2:])
            wlog.write(f"{ns // 1_000_000} {ns / 1e9}\n".encode())
        out.write(buf)

    paths = [f"/data/khtest_{i:04d}.dat" for i in range(files)]
    for p in paths:                                         # setup: create the placeholders (fast)
        (data / p.rsplit("/", 1)[1]).write_bytes(b"benign placeholder content\n" * 32)
        emit(("openat", p, "O_WRONLY|O_CREAT"))
        time.sleep(0.0005)
    t0 = time.time()
    (root / "t0").write_text(repr(t0))
    for i, p in enumerate(paths):
        target = t0 + i / rate
        while (dt := target - time.time()) > 0:
            time.sleep(min(dt, 0.001))
        f = data / p.rsplit("/", 1)[1]
        f.read_bytes()
        emit(("openat", p, "O_RDONLY"))
        f.write_bytes(os.urandom(864))
        wbytes += 4096
        iostat.write_text(f"8:0 rbytes=0 wbytes={wbytes} rios=1 wios=1\n")
        emit(("openat", p, "O_WRONLY|O_TRUNC"))
        f.rename(f.with_name(f.name + ".khlocked"))
        emit(("renameat2", p, None, p + ".khlocked"))


class PollingRedis:
    """redis.asyncio.Redis whose blocking reads wait ~1 ms instead of returning at once: fakeredis' TCP server does
    not implement BLOCK, so without this the consumers would spin (and take the loop from everything else)."""

    @staticmethod
    def make(**kw):
        import redis.asyncio as aioredis

        class R(aioredis.Redis):
            async def xreadgroup(self, *a, **k):
                out = await super().xreadgroup(*a, **k)
                if not out and k.get("block"):
                    await asyncio.sleep(0.001)
                return out

            async def xread(self, *a, **k):
                out = await super().xread(*a, **k)
                if not out and k.get("block"):
                    await asyncio.sleep(0.001)
                return out
        return R(**kw)


# ── harness ─────────────────────────────────────────────────────────────────────────────────────────────
def tree(d: Path, uid: str) -> None:
    (d / "proc" / str(PID) / "root" / "data").mkdir(parents=True)
    (d / "proc" / str(PID) / "ns").mkdir(parents=True)
    (d / "proc" / str(PID) / "net").mkdir(parents=True)
    (d / "proc" / "1" / "ns").mkdir(parents=True)
    (d / "proc" / "1" / "ns" / "net").write_text("")
    (d / "proc" / str(PID) / "ns" / "net").write_text("")
    (d / "proc" / str(PID) / "net" / "dev").write_text("h\nh\n  eth0: 1 2 3 4 5 6 7 8 9000 10 11 12 13 14 15 16\n")
    cg = d / "cg" / "kubepods.slice" / f"kubepods-pod{uid.replace('-', '_')}.slice"
    cg.mkdir(parents=True)
    (cg / "cgroup.freeze").write_text("0")
    (cg / "io.stat").write_text("8:0 rbytes=0 wbytes=0\n")
    (d / "events.jsonl").write_bytes(b"")


async def run_once(args, quiet: bool = False) -> dict:
    from test_agent_fusion_contract import FakeKube

    from agents.fusion_agent import agent as fa
    from agents.security_agent import agent as sa
    from agents.security_agent.falco import FalcoTail
    from kubeheal.contracts import STREAM_ACTIONS, STREAM_SECURITY, ActionEvent
    from kubeheal.ml.bundle import ModelBundle

    uid = str(uuid.uuid4())
    tmp = tempfile.mkdtemp(prefix="kh-bench-")
    d = Path(tmp)
    tree(d, uid)
    sa.CGROUP_ROOT = str(d / "cg")
    if args.oracle:   # evaluate after every event: the earliest detection the model allows
        sa.BURST_EVENTS, sa.MIN_TICK_S, sa.POD_MIN_INTERVAL_S = 1, 0.0, 0.0
    import socket

    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    # fakeredis' in-process async client blocks the whole loop in XREADGROUP BLOCK: serve it from its own process
    # TCP_NODELAY on the server side: without it a MULTI/EXEC reply waits for the 40 ms delayed ACK
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
    r_sec, r_fus = (PollingRedis.make(host="127.0.0.1", port=port, decode_responses=True) for _ in range(2))
    now, M = time.time, {}   # M: per-stage stamps keyed by event id / ts_ms

    # fake kube with a fixed per-call latency
    class Kube(FakeKube):
        def __init__(self):
            super().__init__(pod_uid=uid)
            for name in [n for n in dir(FakeKube) if n.startswith(("read_", "patch_", "create_", "delete_"))]:
                setattr(self, name, self._lat(getattr(self, name), name))

        def _lat(self, fn, name):
            async def w(*a, **k):
                await asyncio.sleep(args.kube_ms / 1000)
                if name == "delete_namespaced_pod":
                    M["delete"] = now()
                k.pop("_request_timeout", None)
                return await fn(*a, **k)
            return w

    # hooks
    ing, evs, cur = {}, [], {}
    M["read_ret"] = 0.0
    orig_read = FalcoTail.read_lines

    def read_lines(self):
        out = orig_read(self)
        M["read_ret"] = now()
        return out
    FalcoTail.read_lines = read_lines
    orig_ingest = sa.SecurityAgent.ingest

    def ingest(self, ev):
        ok = orig_ingest(self, ev)
        ing[ev["ts_ms"]] = (M["read_ret"], now())
        return ok
    sa.SecurityAgent.ingest = ingest
    orig_eb = sa.SecurityAgent.evaluate_batch

    async def evaluate_batch(self, due):
        cur.clear()
        cur["start"] = now()
        await orig_eb(self, due)
    sa.SecurityAgent.evaluate_batch = evaluate_batch
    orig_feat, orig_score = sa.SecurityAgent.features, sa.SecurityAgent.score

    async def features(self, key, w):
        out = await orig_feat(self, key, w)
        cur["feat"] = now()
        return out

    async def score(self, rows):
        out = await orig_score(self, rows)
        cur["score"] = now()
        M.setdefault("scores", []).extend((cur["score"], round(r["n_events"]), p.label, round(p.risk, 2), p.uncertain)
                                          for r, p in zip(rows, out or [], strict=False))
        return out
    sa.SecurityAgent.features, sa.SecurityAgent.score = features, score
    orig_pub = sa.publish_event

    async def publish_event(r, stream, kind, event, *a, **k):
        t = now()
        await orig_pub(r, stream, kind, event, *a, **k)
        if stream == STREAM_SECURITY:
            evs.append({**cur, "eid": event.event_id, "pub0": t, "pub": now()})
    sa.publish_event = publish_event
    orig_res = sa.OwnerResolver.resolve

    async def resolve(self, ns, pod):
        t = now()
        try:
            return await orig_res(self, ns, pod)
        finally:
            cur["owner"] = cur.get("owner", 0.0) + now() - t
    sa.OwnerResolver.resolve = resolve
    orig_proc = fa.FusionAgent.process

    async def process(self, stream, msg_id, fields, deliveries):
        M.setdefault("f_in", {}).setdefault(fields.get("event_id"), now())
        await orig_proc(self, stream, msg_id, fields, deliveries)
    fa.FusionAgent.process = process
    orig_contain = fa.FusionAgent._contain

    async def _contain(self, ns, pod, uid_, event_id, action=""):
        M.setdefault("c_start", {})[event_id] = now()
        return await orig_contain(self, ns, pod, uid_, event_id, action)
    fa.FusionAgent._contain = _contain
    orig_c = sa.SecurityAgent.contain

    async def contain(self, fields):
        M.setdefault("c_in", {})[fields.get("event_id")] = now()
        out = await orig_c(self, fields)
        M.setdefault("c_done", {})[fields.get("event_id")] = now()
        return out
    sa.SecurityAgent.contain = contain

    bundle = ModelBundle.load(ROOT / "models" / "security")
    if not args.cold:   # steady state: a long-running agent has scored (and explained) windows before the attack
        bundle.predict_batch([{}], 0.0)
    sec = sa.SecurityAgent(r_sec, None, sa.OwnerResolver(Kube(), Kube()), proc_root=str(d / "proc"), protected=frozenset(),
                           namespaces=[], capture=False, bundle=bundle, contain_key="k")
    kube = Kube()
    fus = fa.FusionAgent(r_fus, kube, kube, kube, kube, mode="enforce", contain_key="k", consumer="bench")
    tail = FalcoTail(str(d / "events.jsonl"))
    tail.read_lines()   # position at the end before the workload starts
    tasks = [asyncio.create_task(fus.run()), asyncio.create_task(sec.tail_loop(tail)),
             asyncio.create_task(sec.eval_loop()), asyncio.create_task(sec.contain_loop())]
    await asyncio.sleep(0.5)   # groups created, contain_loop at the stream end
    proc = subprocess.Popen([sys.executable, __file__, "--writer", str(d), "--rate", str(args.rate),
                             "--files", str(args.files), "--uid", uid])
    result = None
    deadline = time.time() + args.max_s
    while time.time() < deadline and result is None:
        await asyncio.sleep(0.02)
        for _, f in await r_fus.xrange(STREAM_ACTIONS):
            a = ActionEvent.from_fields(f)
            if a.outcome == "pod_killed" and a.event_id and (d / "t0").exists():
                result = a
                break
    proc.kill()
    proc.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.sleep(0)
    if result is None:
        acts = [(a.decision.value, a.outcome) for a in [ActionEvent.from_fields(f) for _, f in await r_fus.xrange(STREAM_ACTIONS)]]
        sevs = [(f["label"], f["risk"], f["uncertain"], f["n_events"]) for _, f in await r_fus.xrange(STREAM_SECURITY)]
        redis_proc.kill()
        return {"error": f"no kill; actions {acts[:5]}; security events {sevs[:8]} (+{len(sevs)})"}
    t0 = float((d / "t0").read_text())
    eid = result.security_event_id
    ev = next(e for e in evs if e["eid"] == eid)
    out = {"t0": t0, "ev": ev, "M": M, "ing": ing, "eid": eid, "tmp": tmp, "uid": uid, "action": result,
           "sec_event_fields": await r_sec.xrevrange(STREAM_SECURITY, count=50)}
    redis_proc.kill()
    if args.trace:
        t0 = out["t0"]
        for t, n, label, risk, unc in M.get("scores", []):
            print(f"  eval t0{(t - t0) * 1000:+7.0f} ms  n_events={n:3d}  {label:10s} risk={risk:.2f} uncertain={unc}")
    return out


def stages(res: dict) -> dict | None:
    """Per-stage seconds of the kill chain ."""
    from kubeheal.contracts import SecurityEvent
    ev, M, t0 = res["ev"], res["M"], res["t0"]
    se = next(SecurityEvent.from_fields(f) for _, f in res["sec_event_fields"] if f["event_id"] == res["eid"])
    newest = se.window_end_ms
    read_ret, ingest = res["ing"][newest]
    wt = res["wtimes"][newest]   # last write time with this ms
    eid = res["eid"]
    s = {"evidence": wt - t0, "write>tail": read_ret - wt, "tail>ingest": ingest - read_ret,
         "ingest>eval": ev["start"] - ingest, "features": ev["feat"] - ev["start"], "predict+shap": ev["score"] - ev["feat"],
         "owner+publish>fusion": M["f_in"][eid] - ev["score"],
         "fusion pre-freeze": M["c_start"][eid] - M["f_in"][eid], "contain>agent": M["c_in"][eid] - M["c_start"][eid],
         "freeze": M["c_done"][eid] - M["c_in"][eid]}
    s["  (owner lookup)"], s["  (publish call)"] = ev.get("owner", 0.0), ev["pub"] - ev["pub0"]
    s["  (publish>fusion)"] = M["f_in"][eid] - ev["pub0"]
    s["total_freeze"] = M["c_done"][eid] - t0
    s["kill_done"] = M["delete"] - t0
    s["n_events"] = se.n_events
    return s


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--writer")
    ap.add_argument("--uid")
    ap.add_argument("--rate", type=float, default=180.0)
    ap.add_argument("--files", type=int, default=400)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--kube-ms", type=float, default=5.0, help="fixed latency of every fake kube API call")
    ap.add_argument("--max-s", type=float, default=30.0)
    ap.add_argument("--cold", action="store_true", help="first scoring happens inside the attack (builds the explainer)")
    ap.add_argument("--trace", action="store_true", help="print every evaluation of every run")
    ap.add_argument("--oracle", action="store_true", help="no scheduling limits: score after every event")
    ap.add_argument("--json", help="write the per-run stage table here")
    args = ap.parse_args()
    if args.writer:
        return writer(args.writer, args.rate, args.files, args.uid)
    import logging
    if not os.environ.get('BENCH_LOG'):
        logging.disable(logging.CRITICAL)
    else:
        logging.basicConfig(level='INFO')
    rows = []
    for i in range(args.runs):
        res = asyncio.run(run_once(args))
        if "error" in res:
            print(f"run {i}: {res['error']}")
            continue
        res["wtimes"] = {int(a): float(b) for a, b in
                         (ln.split() for ln in (Path(res["tmp"]) / "writes.log").read_text().splitlines())}
        try:
            rows.append(stages(res))
        except (KeyError, StopIteration) as e:   # writer was killed before it saved its log
            print(f"run {i}: incomplete ({e!r})")
    if not rows:
        sys.exit("no complete run")
    print(f"rate {args.rate} files/s, {len(rows)} runs, kube {args.kube_ms} ms/call (median / min / max, ms)")
    for k in [*STAGES, "  (owner lookup)", "  (publish call)", "  (publish>fusion)", "total_freeze", "kill_done"]:
        v = [r[k] * 1000 for r in rows]
        print(f"  {k:18s} {statistics.median(v):8.1f} {min(v):8.1f} {max(v):8.1f}")
    print(f"  events in the killing window: {sorted(r['n_events'] for r in rows)}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows))


if __name__ == "__main__":
    main()

"""Closed-loop load on inference /v1/health/predict_batch; reports latency percentiles and HPA replica changes.

  uv run --all-extras python deploy/scripts/loadtest_inference.py --in-cluster --hpa kubeheal-inference --duration 180 --concurrency 48
  kubectl -n kubeheal port-forward svc/kubeheal-inference 8000:8000 &
  uv run --all-extras python deploy/scripts/loadtest_inference.py --url http://127.0.0.1:8000 --duration 60       # one pod only (port-forward)

--in-cluster runs this same file inside the health-agent pod (the only clients NetworkPolicy admits, with the
Service balancing across replicas), so the HPA sees real load. The HPA exists with `inference.autoscaling.enabled`
(Helm) or overlays/production. Cluster commands go through the cluster guard (deploy/scripts/lib/guard.sh).
"""

import argparse
import asyncio
import json
import random
import statistics as st
import subprocess
import sys
import time
from pathlib import Path

IN_CLUSTER_URL = "http://kubeheal-inference.kubeheal.svc:8000"


def guard(force: str) -> None:   # cluster guard: prints the context, refuses outside minikube / k3d-kubeheal
    if subprocess.run([str(Path(__file__).resolve().parents[2] / "deploy/scripts/lib/guard.sh"), *(["--force-context", force] if force else [])]).returncode:
        sys.exit(2)


async def run_load(url: str, duration: float, concurrency: int, batch: int) -> dict:
    import aiohttp

    from kubeheal.features.health import HEALTH_FEATURES
    rng = random.Random(1)
    body = json.dumps({"items": [{"features": {f: (None if rng.random() < 0.2 else round(rng.random(), 3)) for f in HEALTH_FEATURES}}
                                 for _ in range(batch)]})
    lat: list[float] = []
    errors: dict[str, int] = {}
    end = time.monotonic() + duration

    async def worker(s: aiohttp.ClientSession) -> None:
        while time.monotonic() < end:
            t0 = time.perf_counter()
            try:
                async with s.post(f"{url}/v1/health/predict_batch", data=body, headers={"Content-Type": "application/json"}) as r:
                    await r.read()
                    key = None if r.status == 200 else f"http {r.status}"
            except (TimeoutError, aiohttp.ClientError) as e:
                key = type(e).__name__
            if key:
                errors[key] = errors.get(key, 0) + 1
            else:
                lat.append(time.perf_counter() - t0)

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30), connector=aiohttp.TCPConnector(limit=0)) as s:
        await asyncio.gather(*(worker(s) for _ in range(concurrency)))
    q = st.quantiles(lat, n=100) if len(lat) > 2 else [0.0] * 99
    return {"requests": len(lat), "errors": errors, "rows": len(lat) * batch, "duration_s": duration,
            "p50_ms": q[49] * 1000, "p95_ms": q[94] * 1000, "p99_ms": q[98] * 1000}


def read_self() -> bytes:   # the in-cluster worker runs this same file from stdin
    return Path(__file__).read_bytes()


def hpa_sample(name: str, ns: str) -> dict | None:
    r = subprocess.run(["kubectl", "-n", ns, "get", "hpa", name, "-o", "json"], capture_output=True, text=True)
    if r.returncode:
        return None
    s = json.loads(r.stdout)["status"]
    cpu = next((m["resource"]["current"].get("averageUtilization") for m in s.get("currentMetrics", [])
                if m.get("resource", {}).get("name") == "cpu"), None)
    return {"current": s.get("currentReplicas"), "desired": s.get("desiredReplicas"), "cpu_pct": cpu}


async def poll_hpa(name: str, ns: str, stop: asyncio.Event) -> list[tuple[int, dict]]:
    out, t0 = [], time.monotonic()
    while True:
        smp = await asyncio.to_thread(hpa_sample, name, ns)
        if smp and (not out or out[-1][1] != smp):
            out.append((int(time.monotonic() - t0), smp))
        if stop.is_set():
            return out
        try:
            await asyncio.wait_for(stop.wait(), 5)
        except TimeoutError:
            pass


async def in_cluster(a: argparse.Namespace, source: bytes) -> dict:
    cmd = ["kubectl", "exec", "-i", "-n", a.namespace, "deploy/kubeheal-health-agent", "--", "python", "-", "--url", IN_CLUSTER_URL,
           "--duration", str(a.duration), "--concurrency", str(a.concurrency), "--batch", str(a.batch), "--json"]
    p = await asyncio.create_subprocess_exec(*cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = await p.communicate(source)
    if p.returncode:
        sys.exit(f"in-cluster load failed: {err.decode()[-400:]}")
    return json.loads(out.decode().strip().splitlines()[-1])


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--batch", type=int, default=64, help="rows per request (one security batch is 64)")
    ap.add_argument("--hpa", default="", help="HPA name to sample, e.g. kubeheal-inference")
    ap.add_argument("--namespace", default="kubeheal")
    ap.add_argument("--in-cluster", action="store_true")
    ap.add_argument("--force-context", default="")
    ap.add_argument("--json", action="store_true", help="(worker) print the result as one JSON line")
    a = ap.parse_args()
    if a.json:
        print(json.dumps(await run_load(a.url, a.duration, a.concurrency, a.batch)))
        return
    if a.in_cluster or a.hpa:
        guard(a.force_context)
    stop, poll = asyncio.Event(), None
    if a.hpa:
        poll = asyncio.create_task(poll_hpa(a.hpa, a.namespace, stop))
        await asyncio.sleep(0)
    res = await (in_cluster(a, read_self()) if a.in_cluster else run_load(a.url, a.duration, a.concurrency, a.batch))
    if a.hpa:   # keep sampling after the load ends: scale-down is part of the proof
        await asyncio.sleep(10)
        stop.set()
    print(f"requests={res['requests']} rows={res['rows']} ({res['rows'] / a.duration:.0f} rows/s) errors={res['errors'] or 0}")
    print(f"latency per {a.batch}-row request: p50={res['p50_ms']:.1f} ms  p95={res['p95_ms']:.1f} ms  p99={res['p99_ms']:.1f} ms")
    if poll:
        tl = await poll
        for t, s in tl:
            print(f"  hpa t+{t:>3}s replicas={s['current']} desired={s['desired']} cpu={s['cpu_pct']}%")
        reps = [s["current"] for _, s in tl if s["current"] is not None]
        print(f"hpa replicas {reps[0] if reps else '?'} -> max {max(reps, default='?')} (changes: {len(tl)})")
    if res["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

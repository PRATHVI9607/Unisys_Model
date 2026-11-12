"""P10-V2: check on the k3d cluster that each of the 15 Health Agent PromQL queries returns data for the victim app.

Usage (PowerShell, repo root):
    PYTHONPATH=. .venv\\Scripts\\python.exe demo\\scripts\\verify_health_queries.py --namespace prod --seconds 120

It sends traffic to the victim Service through the API server proxy, then asks Prometheus (also through the API
server proxy) every query from agents/health_agent/metric_queries.py and prints one line per query.
Only `--context k3d-kubeheal` is used. Read-only against the cluster apart from the HTTP requests to the victim.
"""
import argparse
import json
import subprocess
import threading
import time
import urllib.parse

from agents.health_agent.metric_queries import METRIC_SPECS, build_queries

CTX = "k3d-kubeheal"
PROM = "/api/v1/namespaces/monitoring/services/monitoring-kube-prometheus-prometheus:9090/proxy/api/v1/query"


def kget(path: str) -> str:
    r = subprocess.run(["kubectl", "--context", CTX, "get", "--raw", path], capture_output=True, text=True, timeout=30)
    return r.stdout if r.returncode == 0 else ""


def traffic(namespace: str, stop: threading.Event) -> None:
    # The victim Service exposes port 8000 (the app container port), not port 80.
    base = f"/api/v1/namespaces/{namespace}/services/victim-app:8000/proxy"
    i = 0
    while not stop.is_set():
        # Exercise each app-backed channel: a real 5xx, bounded CPU work and a synced PV write.
        for p in ("/", f"/items/{i % 50}", "/health", "/fail", "/cpu?milliseconds=200", "/disk"):
            kget(base + p)
        i += 1


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="prod")
    ap.add_argument("--pod", default="victim-app")
    ap.add_argument("--seconds", type=int, default=120)
    a = ap.parse_args()

    stop = threading.Event()
    th = [threading.Thread(target=traffic, args=(a.namespace, stop), daemon=True) for _ in range(3)]
    for t in th:
        t.start()
    print(f"sending traffic to {a.namespace}/victim-app for {a.seconds}s", flush=True)
    time.sleep(a.seconds)

    queries = build_queries(a.namespace, a.pod)
    stamp = time.strftime("%Y-%m-%d %H:%M")
    ok = 0
    for spec in METRIC_SPECS:
        q = queries[spec.column]
        body = kget(PROM + "?" + urllib.parse.urlencode({"query": q}))
        try:
            res = json.loads(body)["data"]["result"]
        except Exception:
            res = []
        vals = [float(r["value"][1]) for r in res]
        has = bool(vals)
        ok += has
        sample = (max(vals) if spec.agg == "max" else sum(vals)) if has else None
        print(f"{spec.column:28s} series={len(res):2d} returned={'yes' if has else 'NO ':3s} sample={sample}")
    stop.set()
    print(f"{ok}/{len(METRIC_SPECS)} queries returned data ({stamp})")


if __name__ == "__main__":
    main()

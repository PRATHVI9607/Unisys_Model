"""Scripted check: ask for a cgroup freeze through the Executor's own request path (freeze.request_freeze with a real
RequestGate, the Executor's ledger guard and mode watcher), run INSIDE the executor pod.
Usage (stdin): python - <namespace> <pod> <incident_id> <label>
Prints one JSON line per fact. Writes only: a Redis stream entry (the request) and ledger entries."""
import asyncio
import json
import os
import sys
import time

import redis.asyncio as aioredis
from kubernetes_asyncio import client, config

from agents.executor.freeze import request_freeze
from agents.executor.main import ExecutorService, RequestGate


def say(**kw):
    print(json.dumps(kw, default=str), flush=True)


async def main(ns, pod_name, incident, label):
    try:
        config.load_incluster_config()
    except Exception:
        await config.load_kube_config()
    core = client.CoreV1Api()
    svc = ExecutorService()
    svc.core_api = core
    svc.redis = aioredis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    await svc.mode.start(core)
    for _ in range(50):
        if svc.mode.readable:
            break
        await asyncio.sleep(0.2)
    say(step="mode_seen_by_executor", mode=svc.mode.global_mode, readable=svc.mode.readable,
        dry_run_for_ns=svc.mode.dry_run_for(ns))
    pod = client.ApiClient().sanitize_for_serialization(await core.read_namespaced_pod(pod_name, ns))

    async def on_step(namespace, step, outcome):
        await svc.ledger_guard.record(incident, step, {"namespace": namespace, "outcome": outcome})

    gate = RequestGate(svc.mode, intent=svc._intent_for(lambda: incident), on_step=on_step)
    await svc.ledger_guard.record(incident, "scripted_freeze_check_start",
                                  {"namespace": ns, "pod": pod_name, "label": label, "note": "scripted step"})
    t0 = time.time()
    try:
        out = await request_freeze(gate, svc.redis, ns, incident, pod, label, 10.0)
        say(step="request_freeze", confirmed=out.confirmed, reason=out.reason, request_id=out.request_id,
            node=out.node, result=out.result, seconds=round(time.time() - t0, 2))
        await svc.ledger_guard.record(incident, "scripted_freeze_check_result",
                                      {"namespace": ns, "pod": pod_name, "confirmed": out.confirmed,
                                       "reason": out.reason, "result": out.result})
    except Exception as e:  # ModeBlocked, LedgerUnavailable
        say(step="request_freeze", raised=type(e).__name__, detail=str(e))
    await svc.mode.stop()
    await svc.redis.aclose()


asyncio.run(main(*sys.argv[1:5]))

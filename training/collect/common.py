"""Shared bits of the lab collectors: the lab namespace, JSONL output, Redis, node-memory guard.

The collectors run on a workstation against the lab cluster (kubeconfig + port-forwards made by
training/collect/run_lab.sh). They never compute model features: health records carry the features
of the health agent's own HealthEvent, security records the features the security agent captured.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from pathlib import Path

import redis.asyncio as aioredis
from kubernetes_asyncio import client
from kubernetes_asyncio.client.exceptions import ApiException

from kubeheal.contracts import PROTECTED_LABEL, TIER_LABEL
from kubeheal.features.quantity import parse_memory

log = logging.getLogger("kubeheal.lab")

NS = "kubeheal-lab"
# Every lab Deployment and pod carries this, so fusion never acts on a sample mid-measurement.
PROTECTED = {PROTECTED_LABEL: "true"}
SCENARIO_LABEL = "kubeheal.io/scenario"            # pod label: the class of a security-lab pod
SCENARIO_NAME_LABEL = "kubeheal.io/scenario-name"
PARAMS_ANNOTATION = "kubeheal.io/params"
OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "collected"


async def ensure_namespace(core: client.CoreV1Api) -> None:
    # prod tier like demo/: lab events reach the AUTO_* thresholds, so the protected label is really exercised
    body = {"metadata": {"name": NS, "labels": {TIER_LABEL: "prod", "kubeheal.io/lab": "true"}}}
    try:
        await core.create_namespace(body)
    except ApiException as e:
        if e.status != 409:
            raise


async def raw(coro) -> dict:
    """Await a kubernetes_asyncio call made with _preload_content=False → the API's JSON (camelCase)."""
    resp = await coro
    return json.loads(await resp.read())


def connect_redis(url: str) -> aioredis.Redis:
    return aioredis.from_url(url, decode_responses=True, socket_timeout=15, socket_connect_timeout=5)


class Output:
    """Append-only JSONL (one flushed line per record: a crash keeps everything already written)."""

    def __init__(self, task: str, path: Path | None = None):
        self.path = path or OUT_DIR / f"{task}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a")   # noqa: SIM115 - held for the whole run
        self.counts: Counter = Counter()
        self.started = time.monotonic()

    def write(self, rec: dict) -> None:
        self.fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self.fh.flush()
        self.counts[rec["label"]] += 1

    def progress(self) -> str:
        n = sum(self.counts.values())
        hours = max(time.monotonic() - self.started, 1) / 3600
        return f"{n} records ({n / hours:.0f}/h) {dict(self.counts)} -> {self.path}"


async def node_memory_bytes(api: client.ApiClient) -> float | None:
    """Working set of the busiest node (metrics-server), None if unavailable."""
    try:
        nodes = await client.CustomObjectsApi(api).list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
        return max(parse_memory(n["usage"]["memory"]) or 0 for n in nodes["items"])
    except (ApiException, KeyError, ValueError) as e:
        log.warning("node metrics unavailable: %s", e)
        return None


async def wait_for_memory(api: client.ApiClient, limit_bytes: float, what: str) -> None:
    """Block while the node is above the memory budget (new lab load would push it over)."""
    while (used := await node_memory_bytes(api)) is not None and used > limit_bytes:
        log.warning("node memory %.2f GiB > budget %.2f GiB: holding %s", used / 2**30, limit_bytes / 2**30, what)
        await asyncio.sleep(30)

"""Security lab collector: run labelled workloads, record the windows the security agent scored.

Launches short-lived pods in the lab namespace, each running one workload profile with randomised
parameters: ordinary benign file workloads (backups, log rotation, databases, compiles, copies,
atomic config writes), and the sandboxed, non-destructive deploy/chaos/detection-test-workload.py. The
security agent (capture mode on, see run_lab.sh) publishes every window it scores to
STREAM_CAPTURE; this collector joins those windows to the pod's profile and writes one JSONL
record per window. It never computes features itself.

Labels: a benign profile's windows are `benign`. A detection-test pod first creates plain files,
waits --delay, then overwrites them: windows that end before the overwrite starts are `benign`
(plain file creation), windows that start after it are `ransomware`, straddling windows are dropped.

    uv run python -m training.collect.security_lab --hours 1 --slots 6
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
import shlex
import time
import uuid
from datetime import datetime

from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.exceptions import ApiException
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from agents.security_agent.agent import WINDOW_S
from kubeheal.contracts import STREAM_CAPTURE, SecurityEvent
from training.collect.common import (
    NS,
    PARAMS_ANNOTATION,
    PROTECTED,
    SCENARIO_LABEL,
    SCENARIO_NAME_LABEL,
    Output,
    connect_redis,
    ensure_namespace,
    wait_for_memory,
)

log = logging.getLogger("kubeheal.lab.security")

CHAOS_IMAGE = "kubeheal/chaos:v5"
POD_DEADLINE_S = 420
TRAILING_S = 15            # windows for the last seconds arrive after the pod exits (agent evaluates every 5 s)
XREAD_RETRIES, XREAD_BACKOFF_S = 8, 2.0   # a dropped port-forward heals in seconds; ~8 min of backoff then fail loud
CATCHUP_MAX_S = 600        # the agent lags behind real time when Falco is busy; wait at most this for it
DETECTION_SHARE = 0.4      # fraction of pods running the detection-test workload
SINK_NAME, SINK_PORT = "lab-sink", 9000   # in-cluster upload target for the backup_upload profile
SINK_CODE = (
    "import socketserver\n"
    "class H(socketserver.StreamRequestHandler):\n"
    "    def handle(self):\n"
    "        while self.rfile.read(65536): pass\n"
    "socketserver.ThreadingTCPServer.allow_reuse_address = True\n"
    f"socketserver.ThreadingTCPServer(('', {SINK_PORT}), H).serve_forever()\n"
)


def _sh(script: str) -> list[str]:
    return ["sh", "-c", script]


LOOP = 'end=$(( $(date +%s) + {d} )); while [ $(date +%s) -lt $end ]; do {body}; done'


def _looped(r: random.Random, body: str, params: dict, prefix: str = "") -> tuple[list[str], dict]:
    params = params | {"duration": r.randint(60, 180)}
    return _sh(prefix + LOOP.format(d=params["duration"], body=body)), params


def _sqlite_writes(r: random.Random) -> tuple[list[str], dict]:
    p = {"duration": r.randint(60, 180), "value_bytes": r.choice([16, 128, 1024]),
         "rows": r.randint(10, 500), "sleep": r.choice([0.05, 0.5, 2.0])}
    code = (
        "import os, sqlite3, time\n"
        "db = sqlite3.connect('/data/app.db'); db.execute('pragma journal_mode=wal')\n"
        "db.execute('create table if not exists t(id integer primary key, v text)')\n"
        f"end = time.time() + {p['duration']}\n"
        "while time.time() < end:\n"
        f"    db.executemany('insert into t(v) values (?)', [(os.urandom({p['value_bytes']}).hex(),) for _ in range({p['rows']})])\n"
        f"    db.commit(); time.sleep({p['sleep']})\n"
    )
    return ["python", "-c", code], p


def _redis_snapshots(r: random.Random) -> tuple[list[str], dict]:
    p = {"requests": r.randint(2000, 50000), "value_bytes": r.choice([16, 256, 4096])}
    body = (f"redis-benchmark -q -n {p['requests']} -t set -d {p['value_bytes']} -r 100000 >/dev/null"
            " && redis-cli bgsave >/dev/null && sleep 3")
    return _looped(r, body, p, prefix="redis-server --dir /data --save '' --daemonize yes && sleep 1 && ")


# name → (image, fn(rng) -> (command, params)). Every benign command loops until DURATION seconds pass.
def _benign_profiles() -> dict:
    def busybox(body: str, **params):
        def make(r: random.Random):
            p = {k: v(r) for k, v in params.items()}
            return _looped(r, body.format(**p), p)
        return "busybox:1.37", make

    return {
        "tar_gzip_backup": busybox(
            "mkdir -p /data/src && for i in $(seq {files}); do head -c {kb}k /dev/urandom > /data/src/f$i.bin;"
            " seq 1 2000 > /data/src/t$i.txt; done; tar czf /data/backup.tgz.tmp -C /data src"
            " && mv /data/backup.tgz.tmp /data/backup-$(date +%s).tgz; rm -f $(ls -t /data/backup-*.tgz | tail -n +3);"
            " sleep {pause}",
            files=lambda r: r.randint(5, 60), kb=lambda r: r.choice([4, 64, 512]), pause=lambda r: r.randint(1, 8)),
        "log_rotation": busybox(
            "for i in $(seq {lines}); do echo \"$(date) INFO request id=$i status=200 path=/api/v1/items\""
            " >> /data/app.log; done; mv /data/app.log /data/app.log.1 && gzip -f /data/app.log.1; sleep {pause}",
            lines=lambda r: r.randint(200, 5000), pause=lambda r: r.randint(1, 5)),
        "atomic_config_writes": busybox(
            "for i in $(seq {n}); do echo \"{{\\\"version\\\": $i, \\\"replicas\\\": $((i % 7))}}\" > /data/conf.json.tmp"
            " && mv /data/conf.json.tmp /data/conf.json; done; sleep {pause}",
            n=lambda r: r.randint(20, 400), pause=lambda r: r.randint(1, 5)),
        "large_copy": busybox(
            "head -c {mb}M /dev/urandom > /data/blob && cp /data/blob /data/blob.copy && md5sum /data/blob.copy"
            " && rm /data/blob.copy; sleep {pause}",
            mb=lambda r: r.randint(1, 64), pause=lambda r: r.randint(2, 10)),
        "archive_extract": busybox(
            "mkdir -p /data/pkg /data/out && for i in $(seq {files}); do seq 1 {lines} > /data/pkg/m$i.txt; done;"
            " tar czf /data/pkg.tgz -C /data pkg && rm -rf /data/out/* && tar xzf /data/pkg.tgz -C /data/out; sleep {pause}",
            files=lambda r: r.randint(10, 200), lines=lambda r: r.randint(10, 3000), pause=lambda r: r.randint(1, 5)),
        "sqlite_writes": ("python:3.13-slim", _sqlite_writes),
        "python_compile": ("python:3.13-slim", lambda r: _looped(r, (
            "rm -rf /data/py && mkdir /data/py && cp -r /usr/local/lib/python3.13/json"
            " /usr/local/lib/python3.13/email /usr/local/lib/python3.13/http /data/py/"
            " && python -m compileall -q -f /data/py; sleep 2"), {})),
        "redis_snapshots": ("redis:7-alpine", _redis_snapshots),
        # benign high egress: compressed (high-entropy) backups shipped to an in-cluster sink
        "backup_upload": busybox(
            "mkdir -p /data/src && for i in $(seq {files}); do seq 1 3000 > /data/src/t$i.txt; done;"
            " head -c {mb}M /dev/urandom > /data/src/blob.bin; tar czf /data/backup.tgz -C /data src"
            f" && nc -w 3 {SINK_NAME} {SINK_PORT} < /data/backup.tgz; sleep {{pause}}",
            files=lambda r: r.randint(5, 80), mb=lambda r: r.randint(1, 48), pause=lambda r: r.randint(1, 10)),
    }


BENIGN = _benign_profiles()


def detection_profile(r: random.Random) -> tuple[list[str], dict]:
    p = {"num_files": r.randint(20, 400), "rate": r.choice([5, 20, 60, 180, 400]),
         "file_size": r.choice([512, 4096, 65536, 1 << 20]), "rename": r.random() < 0.7,
         "partial": r.choice([1.0, 1.0, 0.5, 0.25, 0.1]), "delay": r.randint(int(WINDOW_S) + 5, int(WINDOW_S) + 20),
         "duration": 90}
    p["file_size"] = min(p["file_size"], (256 << 20) // p["num_files"])     # stay under the emptyDir limit
    args = ["--sandbox", "/data", "--num-files", p["num_files"], "--max-files", p["num_files"], "--rate", p["rate"],
            "--file-size", p["file_size"], "--partial", p["partial"], "--delay", p["delay"], "--duration", p["duration"]]
    args += [] if p["rename"] else ["--no-rename"]
    cmd = "touch /data/.kubeheal-sandbox && exec python /app/detection-test-workload.py " + shlex.join(map(str, args))
    return _sh(cmd), p


def pod_manifest(name: str, scenario: str, label: str, image: str, command: list[str], params: dict) -> dict:
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NS,
                     "labels": PROTECTED | {SCENARIO_LABEL: label, SCENARIO_NAME_LABEL: scenario, "kubeheal.io/lab": "true"},
                     "annotations": {PARAMS_ANNOTATION: json.dumps(params)}},
        "spec": {
            "restartPolicy": "Never", "activeDeadlineSeconds": POD_DEADLINE_S,
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "work", "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
                "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            }],
            "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "512Mi"}}],
        },
    }


def sink_manifests() -> tuple[dict, dict]:
    """A pod that reads and discards uploads, and its Service. No scenario label: its windows are ignored."""
    labels = PROTECTED | {"app": SINK_NAME, "kubeheal.io/lab": "true"}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": SINK_NAME, "namespace": NS, "labels": labels},
           "spec": {"automountServiceAccountToken": False, "containers": [{
               "name": "sink", "image": "python:3.13-slim", "command": ["python", "-c", SINK_CODE],
               "ports": [{"containerPort": SINK_PORT}],
               "resources": {"requests": {"cpu": "20m", "memory": "32Mi"}, "limits": {"cpu": "500m", "memory": "64Mi"}},
               "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
           }]}}
    svc = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": SINK_NAME, "namespace": NS},
           "spec": {"selector": {"app": SINK_NAME}, "ports": [{"port": SINK_PORT, "targetPort": SINK_PORT}]}}
    return pod, svc


async def ensure_sink(core: client.CoreV1Api) -> None:
    pod, svc = sink_manifests()
    for create, body in ((core.create_namespaced_pod, pod), (core.create_namespaced_service, svc)):
        try:
            await create(NS, body)
        except ApiException as e:
            if e.status != 409:
                raise


def overwrite_start_ms(log_text: str, delay_s: float) -> int | None:
    """Wall-clock ms when the detection workload began overwriting: its 'created N files' line + delay."""
    for line in log_text.splitlines():
        ts, _, msg = line.partition(" ")
        if msg.startswith("created "):
            return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000 + delay_s * 1000)
    return None


def label_window(ev: SecurityEvent, profile_label: str, overwrite_ms: int | None) -> str | None:
    if profile_label == "benign":
        return "benign"
    if overwrite_ms is None:                       # never reached the overwrite phase: no clean label
        return None
    if ev.window_end_ms <= overwrite_ms:
        return "benign"
    if ev.window_start_ms >= overwrite_ms:
        return profile_label
    return None


class Lab:
    def __init__(self, args, core: client.CoreV1Api, api: client.ApiClient, redis, out: Output):
        self.args, self.core, self.api, self.redis, self.out = args, core, api, redis, out
        self.rng = random.Random(args.seed)
        self.pending: dict[str, list[SecurityEvent]] = {}   # pod name → captured windows awaiting its label
        self.dropped = 0
        self.late = 0          # lab windows that arrived after their pod's sample was closed (lost)
        self.watermark_ms = 0  # newest window end the agent has captured (any pod): how far it has caught up
        self.abort = False     # capture reader died: samples can no longer be labelled, slots stop

    async def read_capture(self) -> None:
        last, failures = "$", 0
        while True:
            try:
                batches = await self.redis.xread({STREAM_CAPTURE: last}, block=2000, count=500) or []
                failures = 0
            except (RedisConnectionError, RedisTimeoutError, ConnectionError, TimeoutError) as e:
                failures += 1
                if failures > XREAD_RETRIES:
                    raise
                delay = min(XREAD_BACKOFF_S * 2 ** (failures - 1), 120)
                log.warning("capture read failed (%s); retry %d/%d in %.0fs", e, failures, XREAD_RETRIES, delay)
                await asyncio.sleep(delay)
                continue
            for _, entries in batches:
                for entry_id, fields in entries:
                    last = entry_id
                    try:
                        ev = SecurityEvent.from_fields(fields)
                    except ValueError as e:
                        log.warning("bad capture entry %s: %s", entry_id, e)
                        continue
                    self.watermark_ms = max(self.watermark_ms, ev.window_end_ms)
                    if ev.namespace == NS and ev.pod in self.pending:
                        self.pending[ev.pod].append(ev)
                    elif ev.namespace == NS and ev.pod.startswith("sec-"):
                        self.late += 1

    async def run_one(self) -> None:
        detection = self.rng.random() < DETECTION_SHARE
        if detection:
            scenario, label, image = "detection_test", "ransomware", CHAOS_IMAGE
            command, params = detection_profile(self.rng)
        else:
            scenario = self.rng.choice(sorted(BENIGN))
            label = "benign"
            image, make = BENIGN[scenario]
            command, params = make(self.rng)
        name = f"sec-{scenario.replace('_', '-')}-{uuid.uuid4().hex[:6]}"
        self.pending[name] = []
        try:
            await self.core.create_namespaced_pod(NS, pod_manifest(name, scenario, label, image, command, params))
            phase = await self.wait_done(name)
            await self.caught_up(time.time() * 1000)
            overwrite_ms = None
            if detection:
                text = await self.core.read_namespaced_pod_log(name, NS, timestamps=True)
                overwrite_ms = overwrite_start_ms(text, params["delay"])
            for ev in self.pending.get(name, []):
                lab = label_window(ev, label, overwrite_ms)
                if lab is None:
                    self.dropped += 1
                    continue
                self.out.write({
                    "source": "security_lab", "scenario": scenario, "params": params, "group": name,
                    "label": lab, "label_reasons": [f"profile:{label}" + ("" if lab == label else ":setup_phase")],
                    "pod_phase": phase, "features": ev.features, "n_events": ev.n_events,
                    "window_start_ms": ev.window_start_ms, "window_end_ms": ev.window_end_ms,
                    "model_version": ev.model_version, "model_label": ev.label, "model_risk": ev.risk,
                })
        finally:
            self.pending.pop(name, None)
            try:
                await self.core.delete_namespaced_pod(name, NS, grace_period_seconds=0)
            except ApiException as e:
                if e.status != 404:
                    log.warning("could not delete %s: %s", name, e.reason)

    async def caught_up(self, done_ms: float) -> None:
        """Wait until the agent has scored events up to the pod's end (bounded), then the trailing grace."""
        deadline = time.monotonic() + CATCHUP_MAX_S
        while self.watermark_ms < done_ms and time.monotonic() < deadline:   # noqa: ASYNC110 - bounded poll
            await asyncio.sleep(2)
        await asyncio.sleep(TRAILING_S)

    async def wait_done(self, name: str) -> str:
        deadline = time.monotonic() + POD_DEADLINE_S + 60
        while time.monotonic() < deadline:
            pod = await self.core.read_namespaced_pod(name, NS)
            if pod.status.phase in ("Succeeded", "Failed"):
                return pod.status.phase
            await asyncio.sleep(5)
        return "Timeout"

    async def slot(self, until: float) -> None:
        while time.monotonic() < until and not self.abort:
            await wait_for_memory(self.api, self.args.max_node_mem_gib * 2**30, "security slot")
            try:
                await self.run_one()
            except Exception:                      # one bad sample must not end a multi-hour slot
                log.exception("security sample failed")
                await asyncio.sleep(10)


async def run(args) -> None:
    await config.load_kube_config()
    async with client.ApiClient() as api:
        core = client.CoreV1Api(api)
        await ensure_namespace(core)
        await ensure_sink(core)
        redis = connect_redis(args.redis)
        out = Output("security")
        lab = Lab(args, core, api, redis, out)
        reader = asyncio.create_task(lab.read_capture())

        def reader_done(t: asyncio.Task) -> None:
            if not t.cancelled() and t.exception():
                log.error("capture reader died, stopping the run: %r", t.exception())
                lab.abort = True
        reader.add_done_callback(reader_done)
        until = time.monotonic() + args.hours * 3600

        async def report():
            while True:
                await asyncio.sleep(60)
                log.info("%s; dropped %d straddling/unlabelled windows, %d late (lost); agent lag %.0fs", out.progress(),
                         lab.dropped, lab.late, time.time() - lab.watermark_ms / 1000)
        reporter = asyncio.create_task(report())
        try:
            await asyncio.gather(*(lab.slot(until) for _ in range(args.slots)))
        finally:
            reader.cancel()
            reporter.cancel()
            await redis.aclose()
            log.info("done: %s", out.progress())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=float, required=True)
    ap.add_argument("--slots", type=int, default=6, help="lab pods running in parallel")
    ap.add_argument("--redis", default="redis://localhost:16379/0")
    ap.add_argument("--max-node-mem-gib", type=float, default=6.0, help="pause new pods above this")
    ap.add_argument("--seed", default=None, help="RNG seed (default: random, so resumed runs add new samples)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

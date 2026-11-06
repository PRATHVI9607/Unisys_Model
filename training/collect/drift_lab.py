"""Collect real health-model training data in the lab namespace (never production).

Parity by construction: this collector never computes a feature. Each lab Deployment ("slot",
podinfo with its own load generator) gets a randomised base spec; then, repeatedly:

1. apply a scenario (one or several spec changes with random magnitudes) at t0;
2. wait until the health agent has assessed exactly that spec (Redis key_spec hash == the applied
   spec's hash) and take the HealthEvent it published for this workload after t0: its features are
   the record's features;
3. label from the OBSERVED impact (`impact_label`): the event's post-change metric window plus pod
   status polled during that window and the p99 of the minute before t0;
4. restore the base spec and wait for the agent to record it (the agent assesses the restore too when
   it had promoted the change to baseline; that event becomes a `revert` sample, labelled the same
   way) and for the rollout to recover. Before each change the previous rollout is given PRE_SETTLE_S to
   leave the pre-change p99 window.

Every few samples a slot is recreated with a new random base spec (= a new run / group).

Labels:
  critical     security-posture change (privileged, hostPath, hostNetwork/hostPID, added
               capabilities, runAsUser 0) — explicit policy, whatever the metrics say;
               scaled to zero; ready ratio < 0.5; rollout not complete when the agent assessed;
               a pod waiting in ImagePullBackOff / ErrImagePull / CrashLoopBackOff /
               CreateContainer*Error / RunContainerError; any container restart or OOMKill;
               5xx ratio > 5 %
  degradation  p99 >= 2x the pre-change p99 (and >= +10 ms: podinfo's first histogram bucket is
               5 ms, so smaller moves are bucket noise); CPU throttling > 25 %; memory > 90 % of limit
  benign       otherwise

    uv run python -m training.collect.drift_lab --hours 1 --slots 4      # (run_lab.sh does this)
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import logging
import random
import statistics
import time
import uuid
from datetime import datetime

import aiohttp
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.exceptions import ApiException

from agents.health_agent.agent import ASSESS_DELAY_S, rollout_complete
from agents.health_agent.prometheus import fetch_window
from kubeheal.contracts import STREAM_HEALTH, HealthEvent, key_spec
from kubeheal.features.health import canonical_spec, spec_hash
from kubeheal.features.quantity import parse_cpu, parse_memory
from training.collect.common import (
    NS,
    PROTECTED,
    Output,
    connect_redis,
    ensure_namespace,
    raw,
    wait_for_memory,
)

log = logging.getLogger("kubeheal.lab.drift")

IMAGE = "ghcr.io/stefanprodan/podinfo"
TAGS = ["6.9.0", "6.10.0", "6.12.0", "6.13.0", "6.14.1"]          # pre-pulled by run_lab.sh
PATHS = ["/", "/api/info", "/version", "/env", "/headers", "/status/200", "/delay/0"]
BAD_WAITING = {"ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "CreateContainerConfigError",
               "CreateContainerError", "RunContainerError", "InvalidImageName"}
POSTURE_OPS = {"privileged", "host_path", "host_network", "host_pid", "cap_add", "run_as_root"}
P99_MIN_DELTA_S = 0.01
SYNC_GRACE_S = 180          # past ASSESS_DELAY_S, how long to wait for the agent (inference retries are 60 s)
POLL_S = 10
# The pre-change p99 is the mean over [t0-60, t0] of 1m-rate samples, so it reads data back to t0-120: wait until
# that span is clear of the previous rollout (usually the revert of the last scenario), plus a scrape/termination
# margin, or its slowdown leaks into "before" and under-labels degradation.
PRE_SETTLE_S = 150


# ── lab objects ──────────────────────────────────────────────────────────────
def variant(rng: random.Random) -> dict:
    """A random healthy base: resources, replicas, memory ballast, podinfo version."""
    mem = rng.choice([64, 96, 128, 256])
    return {"replicas": rng.choice([1, 1, 2, 2, 3]), "cpu_m": rng.choice([100, 200, 300, 500]),
            "cpu_req_m": rng.choice([5, 10, 25]), "mem_mi": mem, "mem_req_mi": rng.choice([16, 32]),
            "stress_mb": rng.choice([s for s in (0, 0, 8, 16, 32) if s <= mem * 0.3]), "tag": rng.choice(TAGS)}


def deployment(name: str, v: dict) -> dict:
    labels = {"app": name, "kubeheal.io/scrape": "true", **PROTECTED}
    cmd = ["./podinfo", "--port=9898", "--level=info"] + ([f"--stress-memory={v['stress_mb']}"] if v["stress_mb"] else [])
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NS, "labels": {"app": name, **PROTECTED}},
        "spec": {
            "replicas": v["replicas"],
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 100,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "terminationGracePeriodSeconds": 5,
                    "containers": [{
                        "name": "app", "image": f"{IMAGE}:{v['tag']}", "command": cmd,
                        "ports": [{"containerPort": 9898, "name": "http"}],
                        "env": [{"name": "PODINFO_UI_MESSAGE", "value": f"lab {name}"}],
                        "resources": {"requests": {"cpu": f"{v['cpu_req_m']}m", "memory": f"{v['mem_req_mi']}Mi"},
                                      "limits": {"cpu": f"{v['cpu_m']}m", "memory": f"{v['mem_mi']}Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "livenessProbe": {"httpGet": {"path": "/healthz", "port": 9898}, "periodSeconds": 10},
                        "readinessProbe": {"httpGet": {"path": "/readyz", "port": 9898}, "periodSeconds": 3},
                        "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                    }],
                    "volumes": [{"name": "data", "emptyDir": {}}],
                },
            },
        },
    }


def service(name: str) -> dict:
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": NS},
            "spec": {"selector": {"app": name}, "ports": [{"name": "http", "port": 9898, "targetPort": 9898}]}}


def load_profile(rng: random.Random) -> dict:
    return {"loops": rng.choice([1, 2, 3, 4]), "sleep_ms": rng.choice([30, 60, 120, 250, 500]),
            "paths": rng.sample(PATHS, rng.randint(1, 4))}


def loadgen_pod(profiles: dict[str, dict]) -> dict:
    """One pod, one busybox container per slot (per-deployment load, without a pod each)."""
    def script(name: str, p: dict) -> str:
        gets = "; ".join(f"wget -q -T 3 -O /dev/null http://{name}.{NS}.svc:9898{path} 2>/dev/null" for path in p["paths"])
        return (f"for i in $(seq {p['loops']}); do (while true; do {gets}; usleep {p['sleep_ms'] * 1000}; done) & done; "
                "wait")
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "lab-loadgen", "namespace": NS, "labels": {"app": "lab-loadgen", **PROTECTED}},
        "spec": {
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "terminationGracePeriodSeconds": 1,
            "containers": [{
                "name": name, "image": "busybox:1.37.0", "command": ["sh", "-c", script(name, p)],
                "resources": {"requests": {"cpu": "5m", "memory": "4Mi"}, "limits": {"cpu": "100m", "memory": "16Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            } for name, p in profiles.items()],
        },
    }


# ── scenarios ────────────────────────────────────────────────────────────────
def _ratio(rng, *choices):
    return lambda r: rng.choice(choices)


def _probe(r: random.Random) -> dict:
    kind = r.choice(["readinessProbe", "livenessProbe"])
    return r.choice([{"op": "probe", "probe": kind, "path": r.choice(["/nope", "/healthz/x", "/readyz/missing"])},
                     {"op": "probe", "probe": kind, "port": r.choice([9899, 8080, 1234])}])


# family → op generator. Magnitudes span harmless to breaking; labels come from impact.
FAMILIES: dict[str, object] = {
    "cpu_limit_down": lambda r: {"op": "cpu_limit", "ratio": r.choice([0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9])},
    # Absolute targets: whether a cut throttles depends on the millicores left, not the ratio (base 100-500m).
    "cpu_throttle": lambda r: {"op": "cpu_limit", "m": r.choice([5, 8, 10, 12, 15, 18, 22])},
    "cpu_limit_up": lambda r: {"op": "cpu_limit", "ratio": r.choice([1.25, 1.5, 2, 3, 4])},
    "cpu_request": lambda r: {"op": "cpu_request", "ratio": r.choice([0.5, 2, 4])},
    "mem_limit_down": lambda r: {"op": "mem_limit", "ratio": r.choice([0.1, 0.2, 0.3, 0.4, 0.5, 0.7, 0.85])},
    # podinfo's working set is ~21-30 Mi: 30-34 Mi presses it toward > 90 % without (mostly) OOM-killing it.
    "mem_pressure": lambda r: {"op": "mem_limit", "mi": r.choice([30, 32, 34])},
    "mem_limit_up": lambda r: {"op": "mem_limit", "ratio": r.choice([1.25, 1.5, 2, 4])},
    "replicas_up": lambda r: {"op": "replicas", "delta": r.randint(1, 3)},
    "replicas_down": lambda r: {"op": "replicas", "delta": -r.randint(1, 2)},
    "replicas_zero": lambda r: {"op": "replicas", "n": 0},
    "image_valid": lambda r: {"op": "image", "tag": r.choice(TAGS)},
    "image_missing": lambda r: {"op": "image", "tag": f"0.0.{r.randint(1, 999)}-missing"},
    "probe_break": _probe,
    "probe_tweak": lambda r: {"op": "probe", "probe": r.choice(["readinessProbe", "livenessProbe"]),
                              "period": r.choice([2, 5, 15, 30])},
    "probe_remove": lambda r: {"op": "probe_remove", "probe": r.choice(["readinessProbe", "livenessProbe"])},
    "env": lambda r: {"op": "env_set", "name": r.choice(["PODINFO_UI_MESSAGE", "PODINFO_UI_COLOR", "LOG_FORMAT",
                                                         "FEATURE_X", "CACHE_TTL"]),
                      "value": r.choice(["on", "off", "#34577c", "json", str(r.randint(1, 9999))])},
    "args_break": lambda r: {"op": "args_add", "args": [r.choice(["--no-such-flag", "--port=9899", "--port=x"])]},
    "args_stress": lambda r: {"op": "args_add", "args": [r.choice(["--stress-cpu=1", f"--stress-memory={r.choice([16, 32, 64, 128])}"])]},
    "volume_mount_remove": lambda r: {"op": "volume_mount_remove"},
    "meta": lambda r: {"op": r.choice(["template_label", "template_annotation"]),
                       "key": r.choice(["team", "version", "lab.io/rev", "owner"]), "value": f"v{r.randint(1, 999)}"},
    "posture": lambda r: r.choice([{"op": "privileged"}, {"op": "host_path"}, {"op": "host_network"},
                                   {"op": "host_pid"}, {"op": "run_as_root"},
                                   {"op": "cap_add", "caps": [r.choice(["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "NET_RAW"])]}]),
}

# The scenario mix, in one place. Weighted toward subtle slowdowns: in the 2026-10-17 lab run only ~5 % of
# samples were degradation, and nearly all came from CPU limits left under ~20m (throttle > 25 %) or
# --stress-cpu; memory pressure > 90 % without an OOM kill was rare. Benign and critical stay well represented.
WEIGHTS: dict[str, int] = {
    "cpu_limit_down": 6, "cpu_throttle": 18, "cpu_limit_up": 4, "cpu_request": 3,
    "mem_limit_down": 6, "mem_pressure": 6, "mem_limit_up": 4,
    "replicas_up": 4, "replicas_down": 3, "replicas_zero": 2,
    "image_valid": 5, "image_missing": 3,
    "probe_break": 4, "probe_tweak": 3, "probe_remove": 2,
    "env": 5, "args_break": 3, "args_stress": 7, "volume_mount_remove": 2, "meta": 5, "posture": 5,
}


def op_name(op: dict) -> str:
    extra = [str(v if not isinstance(v, list) else ",".join(v)) for k, v in op.items() if k not in ("op", "probe")]
    return "_".join([op["op"], *([op["probe"].removesuffix("Probe")] if "probe" in op else []), *extra])


def pick_ops(rng: random.Random, base: dict) -> tuple[str, list[dict]]:
    """(family, ops): one change, or 2-3 changes of different families ("combined")."""
    names, weights = list(WEIGHTS), list(WEIGHTS.values())
    k = rng.choices([1, 2, 3], weights=[70, 22, 8])[0]
    while True:
        fams = list(dict.fromkeys(rng.choices(names, weights, k=k)))
        ops = [FAMILIES[f](rng) for f in fams]
        if len({o["op"] for o in ops}) == len(ops) and apply_ops(base, ops) != base:
            return (fams[0] if len(fams) == 1 else "combined"), ops


def apply_ops(spec: dict, ops: list[dict]) -> dict:
    """Pure: the canonical DeploymentSpec with the ops applied (container 0 is the app)."""
    new = copy.deepcopy(spec)
    pod = new["template"]["spec"]
    c = pod["containers"][0]
    res = c.setdefault("resources", {})
    lim, req = res.setdefault("limits", {}), res.setdefault("requests", {})
    sc = c.setdefault("securityContext", {})
    for op in ops:
        match op["op"]:
            case "cpu_limit":
                m = op.get("m") or max(1, round(parse_cpu(lim["cpu"]) * 1000 * op["ratio"]))
                lim["cpu"] = f"{m}m"
                if parse_cpu(req.get("cpu", 0)) * 1000 > m:
                    req["cpu"] = f"{m}m"
            case "cpu_request":
                req["cpu"] = f"{min(max(1, round(parse_cpu(req['cpu']) * 1000 * op['ratio'])), round(parse_cpu(lim['cpu']) * 1000))}m"
            case "mem_limit":
                mi = op.get("mi") or max(8, round(parse_memory(lim["memory"]) / 2**20 * op["ratio"]))
                lim["memory"] = f"{mi}Mi"
                if parse_memory(req.get("memory", 0)) > mi * 2**20:
                    req["memory"] = f"{mi}Mi"
            case "replicas":
                new["replicas"] = op["n"] if "n" in op else max(1, new.get("replicas", 1) + op["delta"])
            case "image":
                c["image"] = f"{IMAGE}:{op['tag']}"
            case "probe":
                p = c.setdefault(op["probe"], {"httpGet": {"path": "/healthz", "port": 9898}})
                if "path" in op:
                    p["httpGet"]["path"] = op["path"]
                if "port" in op:
                    p["httpGet"]["port"] = op["port"]
                if "period" in op:
                    p["periodSeconds"] = op["period"]
            case "probe_remove":
                c.pop(op["probe"], None)
            case "env_set":
                env = c.setdefault("env", [])
                env[:] = [e for e in env if e["name"] != op["name"]] + [{"name": op["name"], "value": op["value"]}]
            case "args_add":
                c["command"] = [*c["command"], *op["args"]]
            case "volume_mount_remove":
                c.pop("volumeMounts", None)
            case "template_label" | "template_annotation":
                key = "labels" if op["op"] == "template_label" else "annotations"
                new["template"].setdefault("metadata", {}).setdefault(key, {})[op["key"]] = op["value"]
            case "privileged":
                sc.update(privileged=True, allowPrivilegeEscalation=True)
            case "cap_add":
                sc.setdefault("capabilities", {})["add"] = op["caps"]
                if "SYS_ADMIN" in op["caps"]:     # the API rejects SYS_ADMIN with allowPrivilegeEscalation=false
                    sc["allowPrivilegeEscalation"] = True
            case "run_as_root":
                pod["securityContext"].update(runAsNonRoot=False, runAsUser=0)
            case "host_network":
                pod["hostNetwork"] = True
            case "host_pid":
                pod["hostPID"] = True
            case "host_path":
                pod.setdefault("volumes", []).append({"name": "host", "hostPath": {"path": "/tmp/kubeheal-lab",
                                                                                   "type": "DirectoryOrCreate"}})
                c.setdefault("volumeMounts", []).append({"name": "host", "mountPath": "/host", "readOnly": True})
            case other:
                raise ValueError(f"unknown op {other}")
    return new


def settle_wait_s(dep: dict, now: float) -> float:
    """Seconds until the last completed rollout is PRE_SETTLE_S old (0 when none is recorded or it is older)."""
    for c in (dep.get("status") or {}).get("conditions") or []:
        if c.get("type") == "Progressing" and c.get("reason") == "NewReplicaSetAvailable" and c.get("lastUpdateTime"):
            return max(0.0, datetime.fromisoformat(c["lastUpdateTime"]).timestamp() + PRE_SETTLE_S - now)
    return 0.0


# ── labels ───────────────────────────────────────────────────────────────────
def impact_label(features: dict, obs: dict, pre_p99: float | None, ops: list[dict]) -> tuple[str, list[str]]:
    """(label, reasons) from the agent's post-change window features + pod observations; see module doc."""
    def over(name: str, t: float) -> bool:
        return (v := features.get(name)) is not None and v > t

    crit = [f"policy:security_posture:{o['op']}" for o in ops if o["op"] in POSTURE_OPS]
    if obs.get("desired") == 0:
        crit.append("scaled_to_zero")
    if (rr := features.get("ready_ratio")) is not None and rr < 0.5:
        crit.append("ready_ratio<0.5")
    if obs.get("stuck"):
        crit.append("rollout_stuck")
    crit += [f"pod_waiting:{r}" for r in sorted(obs.get("waiting", ()))]
    if obs.get("oom"):
        crit.append("oom_killed")
    if obs.get("restarts", 0) > 0:
        crit.append("container_restarts")
    if over("error_ratio", 0.05):
        crit.append("error_ratio>5%")
    if crit:
        return "critical", crit
    deg = []
    p99 = features.get("latency_p99_mean_s")
    if p99 is not None and pre_p99 and p99 >= 2 * pre_p99 and p99 - pre_p99 >= P99_MIN_DELTA_S:
        deg.append("p99>=2x_pre")
    if over("cpu_throttle_mean", 0.25):
        deg.append("cpu_throttle>25%")
    if over("mem_util_max", 0.9):
        deg.append("mem_util>0.9")
    return ("degradation", deg) if deg else ("benign", [])


def observe_pods(pods: list[dict], before: dict[str, int], obs: dict) -> None:
    """Fold one pod listing into obs: waiting reasons, OOM kills, restarts since t0 (per pod uid)."""
    for p in pods:
        uid = p["metadata"]["uid"]
        for cs in (p.get("status") or {}).get("containerStatuses") or []:
            st, last = cs.get("state") or {}, cs.get("lastState") or {}
            if (reason := (st.get("waiting") or {}).get("reason")) in BAD_WAITING:
                obs["waiting"].add(reason)
            if "OOMKilled" in ((st.get("terminated") or {}).get("reason"), (last.get("terminated") or {}).get("reason")):
                obs["oom"] = True
            obs["restarts"] = max(obs["restarts"], cs.get("restartCount", 0) - before.get(uid, 0))


# ── collection ───────────────────────────────────────────────────────────────
class DriftLab:
    def __init__(self, args, api: client.ApiClient, redis, session: aiohttp.ClientSession, out: Output):
        self.args, self.redis, self.session, self.out = args, redis, session, out
        self.api, self.apps, self.core = api, client.AppsV1Api(api), client.CoreV1Api(api)
        self.deadline = time.time() + args.hours * 3600

    def done(self) -> bool:
        return time.time() >= self.deadline

    async def setup(self, names: list[str], rng: random.Random) -> None:
        await ensure_namespace(self.core)
        for name in names:
            try:
                await self.core.create_namespaced_service(NS, service(name))
            except ApiException as e:
                if e.status != 409:
                    raise
        try:
            await self.core.delete_namespaced_pod("lab-loadgen", NS, grace_period_seconds=0)
            while True:
                await self.core.read_namespaced_pod("lab-loadgen", NS)
                await asyncio.sleep(2)
        except ApiException as e:
            if e.status != 404:
                raise
        await self.core.create_namespaced_pod(NS, loadgen_pod({n: load_profile(rng) for n in names}))

    async def read_spec(self, name: str) -> tuple[dict, dict]:
        dep = await raw(self.apps.read_namespaced_deployment(name, NS, _preload_content=False))
        return dep, canonical_spec(dep)

    async def set_spec(self, name: str, spec: dict) -> str:
        patch = [{"op": "replace", "path": "/spec/template", "value": spec["template"]},
                 {"op": "replace", "path": "/spec/replicas", "value": spec.get("replicas", 1)}]
        dep = await raw(self.apps.patch_namespaced_deployment(
            name, NS, patch, _content_type="application/json-patch+json", _preload_content=False))
        return spec_hash(canonical_spec(dep))

    async def pods(self, name: str) -> list[dict]:
        return (await raw(self.core.list_namespaced_pod(NS, label_selector=f"app={name}",
                                                        _preload_content=False)))["items"]

    async def agent_spec_hash(self, name: str) -> str | None:
        blob = await self.redis.get(key_spec(NS, name))
        return spec_hash(json.loads(blob)) if blob else None

    async def wait_rollout(self, name: str, limit_s: float) -> bool:
        end = time.time() + limit_s
        while time.time() < end:
            if rollout_complete((await self.read_spec(name))[0]):
                return True
            await asyncio.sleep(3)
        return False

    async def new_base(self, name: str, rng: random.Random) -> tuple[dict, dict]:
        """(Re)create the slot with a random base spec and wait until the agent has first-sighted it."""
        try:
            await self.apps.delete_namespaced_deployment(name, NS, propagation_policy="Foreground")
            while True:
                await self.apps.read_namespaced_deployment(name, NS)
                await asyncio.sleep(2)
        except ApiException as e:
            if e.status != 404:
                raise
        v = variant(rng)
        await self.apps.create_namespaced_deployment(NS, deployment(name, v))
        if not await self.wait_rollout(name, 180):
            raise RuntimeError(f"{name}: base rollout did not complete")
        base = (await self.read_spec(name))[1]
        want = spec_hash(base)
        await asyncio.sleep(ASSESS_DELAY_S)      # the agent first-sights it ASSESS_DELAY_S after it appeared
        end = time.time() + SYNC_GRACE_S
        while await self.agent_spec_hash(name) != want:   # first sight stores it as spec + baseline
            if time.time() > end:
                raise RuntimeError(f"{name}: health agent never stored the base spec")
            await asyncio.sleep(POLL_S)
        return v, base

    async def observe(self, name: str, t0: float, want: str, before: dict[str, int]) -> tuple[dict, HealthEvent | None]:
        """Poll pods until the agent has assessed `want`; then its event for this workload since t0."""
        obs = {"waiting": set(), "oom": False, "restarts": 0}
        end = t0 + ASSESS_DELAY_S + SYNC_GRACE_S
        while True:
            observe_pods(await self.pods(name), before, obs)
            if time.time() >= t0 + ASSESS_DELAY_S and await self.agent_spec_hash(name) == want:
                break
            if time.time() > end:
                raise RuntimeError(f"{name}: health agent did not assess the change within {end - t0:.0f}s")
            await asyncio.sleep(POLL_S)
        dep, spec = await self.read_spec(name)
        obs |= {"stuck": not rollout_complete(dep) and spec.get("replicas", 1) > 0,
                "desired": spec.get("replicas", 1), "waiting": sorted(obs["waiting"])}
        for _id, fields in await self.redis.xrevrange(STREAM_HEALTH, count=1000):
            if fields.get("namespace") == NS and fields.get("workload") == name:
                ev = HealthEvent.from_fields(fields)
                return obs, (ev if ev.timestamp_ms >= t0 * 1000 else None)
        return obs, None

    async def pre_p99(self, name: str, t0: float) -> float | None:
        w = await fetch_window(self.session, self.args.prometheus, NS, name, t0 - 60, t0)
        return statistics.fmean(w["latency_p99_s"]) if w.get("latency_p99_s") else None

    async def change(self, name: str, spec: dict, ops: list[dict], meta: dict) -> dict | None:
        """Apply spec, observe, and write the labelled record if the agent published an event."""
        before = {p["metadata"]["uid"]: max([cs.get("restartCount", 0) for cs in (p.get("status") or {})
                                             .get("containerStatuses") or []] or [0]) for p in await self.pods(name)}
        if (wait := settle_wait_s((await self.read_spec(name))[0], time.time())) > 0:
            await asyncio.sleep(wait)
        pre = await self.pre_p99(name, time.time())
        t0 = time.time()
        want = await self.set_spec(name, spec)
        obs, ev = await self.observe(name, t0, want, before)
        if ev is None:
            log.info("%s %s: no event (agent treated it as a baseline restore)", name, meta["scenario"])
            return None
        label, reasons = impact_label(ev.features, obs, pre, ops)
        rec = {"id": ev.event_id, "source": "lab", "task": "health", **meta, "label": label,
               "label_reasons": reasons, "features": ev.features, "changed_fields": ev.changed_fields,
               "agent": {"label": ev.label, "risk": ev.risk, "uncertain": ev.uncertain,
                         "model_version": ev.model_version},
               "obs": obs, "pre_p99_s": pre, "t_change_ms": int(t0 * 1000), "t_event_ms": ev.timestamp_ms}
        self.out.write(rec)
        log.info("%s %-40s -> %-11s %s (agent: %s %.2f)", name, meta["scenario"][:40], label, reasons,
                 ev.label, ev.risk)
        return rec

    async def slot(self, i: int) -> None:
        name = f"lab-{i:02d}"
        rng = random.Random(f"{self.args.seed}-{name}-{time.time_ns()}")
        await asyncio.sleep(i * 7)          # stagger slots: spreads API / agent / Prometheus load
        while not self.done():
            try:
                v, base = await self.new_base(name, rng)
                run_id = uuid.uuid4().hex[:12]
                for _ in range(self.args.samples_per_base):
                    if self.done():
                        break
                    await wait_for_memory(self.api, self.args.max_node_mem_gib * 2**30, name)
                    family, ops = pick_ops(rng, base)
                    scenario = "+".join(op_name(o) for o in ops)
                    meta = {"run_id": run_id, "group": run_id, "slot": name, "family": family,
                            "scenario": scenario, "params": {"ops": ops, "base": v}, "revert": False}
                    try:
                        await self.change(name, apply_ops(base, ops), ops, meta)
                    except ApiException as e:
                        if e.status != 422:
                            raise
                        log.info("%s %s rejected by the API (invalid spec): %s", name, scenario, e.reason)
                        continue
                    # Restore; the agent assesses it only when it had promoted the change to baseline.
                    await self.change(name, base, [], meta | {"family": "revert", "scenario": f"revert:{scenario}",
                                                              "revert": True})
                    if not await self.wait_rollout(name, 120):
                        raise RuntimeError(f"{name}: did not recover after restoring the base spec")
            except Exception:
                log.exception("%s: slot error; recreating it in 30s", name)
                await asyncio.sleep(30)

    async def progress(self) -> None:
        while not self.done():
            await asyncio.sleep(300)
            log.info("health progress: %s", self.out.progress())


async def run(args) -> None:
    await config.load_kube_config()
    out = Output("health")
    async with client.ApiClient() as api, aiohttp.ClientSession() as session:
        redis = connect_redis(args.redis)
        lab = DriftLab(args, api, redis, session, out)
        names = [f"lab-{i:02d}" for i in range(args.slots)]
        await lab.setup(names, random.Random(args.seed))
        tasks = [asyncio.create_task(lab.slot(i)) for i in range(args.slots)]
        prog = asyncio.create_task(lab.progress())
        await asyncio.gather(*tasks)
        prog.cancel()
        log.info("health done: %s", out.progress())
        await redis.aclose()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=float, required=True)
    ap.add_argument("--slots", type=int, default=20, help="lab Deployments measured in parallel")
    ap.add_argument("--samples-per-base", type=int, default=8, help="scenarios per random base spec (one run)")
    ap.add_argument("--redis", default="redis://localhost:16379/0")
    ap.add_argument("--prometheus", default="http://localhost:19090")
    ap.add_argument("--max-node-mem-gib", type=float, default=6.0, help="pause new samples above this")
    ap.add_argument("--seed", default="kubeheal")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

"""Shared fakes for the V5-D4 Health Agent tests: a fake clock, the in-memory Redis, a Kubernetes API (Deployment
reads and lists, pod lists), a Prometheus window and the inference service. Nothing here touches a network."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents.health_agent import agent as ha
from agents.health_agent.agent import HealthAgent
from fake_redis import FakeRedis
from kubeheal.contracts import Factor, Prediction
from kubeheal.features.health import RAW_METRICS

WALL0 = 1_760_000_000.0
KEY = ("prod", "victim-app")


class Clock:
    """One number the test advances: `mono` for deadlines, `wall` for epoch seconds."""

    def __init__(self):
        self.t = 1000.0

    def mono(self):
        return self.t

    def wall(self):
        return WALL0 + self.t

    def advance(self, seconds):
        self.t += seconds


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def dep(cpu="500m", image="img:1", name="victim-app", ns="prod", generation=1, rolled_out=True, replicas=1,
        annotations=None, extra_status=None):
    """An API-shaped Deployment (what a watch event's raw_object and a list item are)."""
    status = ({"observedGeneration": generation, "replicas": replicas, "updatedReplicas": replicas,
               "availableReplicas": replicas} if rolled_out else {})
    status.update(extra_status or {})
    return {
        "metadata": {"name": name, "namespace": ns, "generation": generation, "resourceVersion": "1",
                     "annotations": dict(annotations or {})},
        "spec": {"replicas": replicas, "selector": {"matchLabels": {"app": name}},
                 "template": {"metadata": {"labels": {"app": name}},
                              "spec": {"containers": [{"name": "app", "image": image,
                                                       "resources": {"limits": {"cpu": cpu}}}]}}},
        "status": status,
    }


def failing_pod(created_wall, name="victim-app", reason="ImagePullBackOff"):
    return {"metadata": {"creationTimestamp": iso(created_wall),
                         "labels": {"app": name, "pod-template-hash": "abc"},
                         "ownerReferences": [{"kind": "ReplicaSet", "name": f"{name}-abc"}]},
            "status": {"containerStatuses": [{"name": "app", "state": {"waiting": {"reason": reason}}}]}}


def full_window(value=0.2):
    return {name: [value, value, value, value] for name in RAW_METRICS}


def prediction(label="degradation", risk=0.6, pset=None, uncertain=False, version="test-bundle-1"):
    return Prediction(model_version=version, label=label, risk=risk,
                      probabilities={"benign": 0.1, "degradation": 0.6, "critical": 0.3},
                      prediction_set=pset if pset is not None else [label], uncertain=uncertain,
                      top_factors=[Factor(feature="cpu_limit_ratio", value=0.1, contribution=0.5)])


class Resp:
    def __init__(self, body):
        self.body = body

    async def read(self):
        return json.dumps(self.body).encode()


class FakeCore:
    def __init__(self):
        self.pods = []
        self.pod_calls = []
        self.fail = None          # an exception the pod list raises

    async def list_namespaced_pod(self, namespace, **kw):
        self.pod_calls.append((namespace, kw))
        if self.fail is not None:
            raise self.fail
        return Resp({"items": self.pods})

    async def list_namespaced_service(self, *a, **k):
        raise RuntimeError("no services in the fake")          # blast radius falls back to "unknown"


class FakeApps:
    def __init__(self):
        self.live = {}            # (namespace, name) -> Deployment dict returned by a live read
        self.reads = []
        self.items = []           # what a list returns
        self.list_calls = []
        self.list_rv = "10"
        self.read_error = None

    async def read_namespaced_deployment(self, name, namespace, **kw):
        self.reads.append((namespace, name, kw))
        if self.read_error is not None:
            raise self.read_error
        return Resp(self.live[(namespace, name)])

    async def list_namespaced_deployment(self, namespace, **kw):
        self.list_calls.append((namespace, kw))
        rv, self.list_rv = self.list_rv, str(int(self.list_rv) + 10)
        return Resp({"items": list(self.items), "metadata": {"resourceVersion": rv}})


class FakeAutoscaling:
    def __init__(self, targets=()):
        self.targets = list(targets)
        self.calls = []
        self.error = None

    async def list_namespaced_horizontal_pod_autoscaler(self, namespace, **kw):
        self.calls.append(namespace)
        if self.error is not None:
            raise self.error
        return Resp({"items": [{"metadata": {"namespace": ns}, "spec": {"scaleTargetRef": {"kind": "Deployment",
                                                                                              "name": name}}}
                               for ns, name in self.targets if ns == namespace]})


class Env:
    """An agent wired to the fakes, plus the recorded calls."""

    def __init__(self, **kw):
        self.clock = Clock()
        self.agent = HealthAgent(redis_url="redis://unused", observe_base_s=60, delay_s=60,
                                 clock=self.clock.mono, wall=self.clock.wall, **kw)
        self.redis = self.agent.redis = FakeRedis()
        self.core = self.agent.core_api = FakeCore()
        self.apps = self.agent.apps_api = FakeApps()
        self.agent.autoscaling_api = FakeAutoscaling()
        self.windows = []         # (start, end) of each metric query
        self.window = full_window()
        self.window_error = None
        self.gate = None          # optional asyncio.Event the window fake waits on
        self.active = 0
        self.max_active = 0
        self.predictions = []     # feature dicts sent to the inference service
        self.result = prediction()    # None = the service does not answer
        env = self

        async def fake_window(session, url, ns, name, start, end, *a, **k):
            env.windows.append((ns, name, start, end))
            env.active += 1
            env.max_active = max(env.max_active, env.active)
            try:
                if env.gate is not None:
                    await env.gate.wait()
                if env.window_error is not None:
                    raise env.window_error
                return dict(env.window)
            finally:
                env.active -= 1

        async def fake_predict(session, url, features, timeout=None):
            env.predictions.append(dict(features))
            return env.result

        self.agent._fetch_window = fake_window
        self.agent._predict = fake_predict

    @property
    def events(self):
        return [f for s, f in self.redis.added if s == ha.HEALTH_STREAM]

    async def send(self, etype, d):
        await self.agent.handle_deployment_event(etype, d)

    async def tick(self, advance=0.0):
        self.clock.advance(advance)
        await self.agent.tick()
        await self.agent.drain()

    async def baseline_then_change(self, **change):
        """First sight records the golden baseline; a changed spec then goes on the debounce."""
        await self.send("ADDED", dep())
        await self.send("MODIFIED", dep(**change))

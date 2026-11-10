"""
Fake Kubernetes clients for the P7 remediation tests (no cluster, no network).

All fakes append every WRITE to one shared `log` as (api, method, name_or_ns, ...) so tests can assert
exact order and that a dry run wrote nothing. Deployments and StatefulSets really apply JSON Patch
(including `test` ops) and strategic-merge style dict patches, so an invalid patch fails the test.
"""
import copy
import re
from datetime import datetime, timedelta, timezone

DIGEST = "sha256:" + "ab" * 32


class Exists(Exception):
    status = 409

    def __init__(self, what):
        super().__init__(f"{what} already exists")


class Clock:
    """Monotonic fake clock; `sleep` advances it and remembers every requested delay."""

    def __init__(self, start=1_000_000.0):
        self.now, self.sleeps = start, []

    def __call__(self):
        return self.now

    async def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


class Gate:
    """allow_write answers True for the first `allow` calls (None = always), then False."""

    def __init__(self, allow=None):
        self.allow, self.calls = allow, 0

    def allow_write(self, ns):
        self.calls += 1
        return self.allow is None or self.calls <= self.allow


class ToggleGate:
    def __init__(self):
        self.on = True

    def allow_write(self, ns):
        return self.on


class Mode:
    """Stand-in for ModeWatcher used by ExecutorService."""

    def __init__(self, dry=False):
        self.dry = dry

    def dry_run_for(self, ns):
        return self.dry


class Redis:
    def __init__(self, store=None):
        self.store, self.added, self.acked = dict(store or {}), [], []

    async def get(self, k):
        return self.store.get(k)

    async def set(self, k, v, nx=False, ex=None):
        if nx and k in self.store:
            return None
        self.store[k] = v
        return True

    async def delete(self, k):
        self.store.pop(k, None)

    async def xadd(self, s, f):
        self.added.append((s, f))

    async def xack(self, s, g, i):
        self.acked.append(i)

    def stream(self, name):
        return [f for s, f in self.added if s == name]


# ---- patch helpers ---------------------------------------------------------------------------------
def _walk(doc, parts):
    for p in parts[:-1]:
        doc = doc[int(p)] if isinstance(doc, list) else doc[p]
    return doc


def json_patch(doc, ops):
    doc = copy.deepcopy(doc)
    for o in ops:
        parts = [x.replace("~1", "/").replace("~0", "~") for x in o["path"].split("/")[1:]]
        parent, last = _walk(doc, parts), parts[-1]
        key = int(last) if isinstance(parent, list) else last
        if o["op"] == "test":
            assert parent[key] == o["value"], f"JSON Patch test failed at {o['path']}"
        elif o["op"] == "remove":
            del parent[key]
        elif o["op"] == "replace":
            assert key in parent or (isinstance(parent, list) and key < len(parent)), o["path"]
            parent[key] = o["value"]
        elif o["op"] == "add":
            parent[key] = o["value"]
    return doc


def merge_patch(doc, patch):
    """Strategic-merge-like: dicts merge, None deletes, name-keyed lists merge by name."""
    for k, v in patch.items():
        if v is None:
            doc.pop(k, None)
        elif isinstance(v, dict):
            merge_patch(doc.setdefault(k, {}), v)
        elif isinstance(v, list) and v and isinstance(v[0], dict) and "name" in v[0]:
            cur = doc.setdefault(k, [])
            for item in v:
                for existing in cur:
                    if existing.get("name") == item["name"]:
                        merge_patch(existing, item)
                        break
                else:
                    cur.append(copy.deepcopy(item))
        else:
            doc[k] = copy.deepcopy(v)
    return doc


# ---- objects -----------------------------------------------------------------------------------------
def deployment_obj(name="web", cpu="500m", memory="256Mi", replicas=2, claim=None, volume="data",
                   max_surge="25%", max_unavail="25%", image="reg:5000/app:1.0"):
    spec = {
        "replicas": replicas,
        "selector": {"matchLabels": {"app": name}},
        "strategy": {"type": "RollingUpdate",
                     "rollingUpdate": {"maxUnavailable": max_unavail, "maxSurge": max_surge}},
        "template": {"metadata": {"labels": {"app": name, "app.kubernetes.io/name": name}},
                     "spec": {"containers": [{"name": "app", "image": image,
                                              "resources": {"limits": {"cpu": cpu, "memory": memory}}}]}},
    }
    if claim:
        spec["template"]["spec"]["volumes"] = [{"name": volume, "persistentVolumeClaim": {"claimName": claim}}]
    return {"metadata": {"name": name, "generation": 1, "annotations": {}}, "spec": spec,
            "status": {"observedGeneration": 1, "replicas": replicas, "updatedReplicas": replicas,
                       "readyReplicas": replicas, "availableReplicas": replicas}}


def golden_record(dep):
    from agents.health_agent.baseline import make_record
    return make_record(dep["spec"])


def snapshot_obj(name, pvc, taken_s, kind="rolling", ready=True, ns="prod", size="1Gi"):
    ts = datetime.fromtimestamp(taken_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"metadata": {"name": name, "namespace": ns, "creationTimestamp": ts,
                         "labels": {"kubeheal/snapshot-kind": kind, "kubeheal/source-pvc": pvc}},
            "status": {"readyToUse": ready, "creationTime": ts, "restoreSize": size}}


# ---- APIs ----------------------------------------------------------------------------------------------
class Cluster:
    """One shared log plus the four API facades."""

    def __init__(self):
        self.log = []
        self.workloads = {}      # (kind, name) -> object
        self.pods = {}
        self.pvcs = {}
        self.replica_sets = {}
        self.snapshots = {}      # name -> object
        self.snapshot_clock = lambda: 10_000_000.0     # stamps creationTimestamp of created snapshots
        self.policies = {}
        self.stuck_rollout = False
        self.stuck_scale_down = False
        self.apps = FakeApps(self)
        self.core = FakeCore(self)
        self.net = FakeNet(self)
        self.custom = FakeCustom(self)

    def writes(self, method=None):
        return [e for e in self.log if method is None or e[1] == method]


def _converge(obj, replicas=None, stuck=False):
    st = obj["status"]
    if replicas is not None:
        obj["spec"]["replicas"] = replicas
    want = obj["spec"]["replicas"]
    if stuck:
        st["readyReplicas"] = 0
        st["availableReplicas"] = 0
        return
    st.update({"observedGeneration": obj["metadata"]["generation"], "replicas": want,
               "updatedReplicas": want, "readyReplicas": want, "availableReplicas": want})


class FakeApps:
    def __init__(self, c):
        self.c = c

    def _get(self, kind, name):
        return self.c.workloads[(kind, name)]

    async def read_namespaced_deployment(self, name, ns):
        return copy.deepcopy(self._get("Deployment", name))

    async def read_namespaced_stateful_set(self, name, ns):
        return copy.deepcopy(self._get("StatefulSet", name))

    async def read_namespaced_replica_set(self, name, ns):
        return copy.deepcopy(self.c.replica_sets[name])

    def _patch(self, kind, name, ns, body):
        obj = self._get(kind, name)
        self.c.log.append(("apps", f"patch_{kind}", name, body))
        if isinstance(body, list):
            new = json_patch(obj, body)
            obj.clear()
            obj.update(new)
        else:
            merge_patch(obj, copy.deepcopy(body))
        obj["metadata"]["generation"] += 1
        _converge(obj, stuck=self.c.stuck_rollout)

    async def patch_namespaced_deployment(self, name, ns, body):
        self._patch("Deployment", name, ns, body)

    async def patch_namespaced_stateful_set(self, name, ns, body):
        self._patch("StatefulSet", name, ns, body)

    def _scale(self, kind, name, body):
        obj = self._get(kind, name)
        self.c.log.append(("apps", f"scale_{kind}", name, body["spec"]["replicas"]))
        n = body["spec"]["replicas"]
        obj["spec"]["replicas"] = n
        if n == 0 and self.c.stuck_scale_down:
            return
        _converge(obj)

    async def patch_namespaced_deployment_scale(self, name, ns, body):
        self._scale("Deployment", name, body)

    async def patch_namespaced_stateful_set_scale(self, name, ns, body):
        self._scale("StatefulSet", name, body)


class FakeCore:
    def __init__(self, c):
        self.c = c

    async def read_namespaced_pod(self, name, ns):
        return copy.deepcopy(self.c.pods[name])

    async def patch_namespaced_pod(self, name, ns, body):
        self.c.log.append(("core", "patch_pod", name, body))
        merge_patch(self.c.pods[name], copy.deepcopy(body))

    async def read_namespaced_persistent_volume_claim(self, name, ns):
        return copy.deepcopy(self.c.pvcs[name])

    async def list_namespaced_persistent_volume_claim(self, ns):
        return {"items": [copy.deepcopy(p) for p in self.c.pvcs.values()
                          if p["metadata"].get("namespace", ns) == ns]}

    async def create_namespaced_persistent_volume_claim(self, ns, body):
        name = body["metadata"]["name"]
        self.c.log.append(("core", "create_pvc", name, body))
        if name in self.c.pvcs:
            raise Exists(name)
        self.c.pvcs[name] = copy.deepcopy(body)


class FakeNet:
    def __init__(self, c):
        self.c = c

    async def create_namespaced_network_policy(self, ns, body):
        name = body["metadata"]["name"]
        self.c.log.append(("net", "create_policy", name, body))
        if name in self.c.policies:
            raise Exists(name)
        self.c.policies[name] = body

    async def delete_namespaced_network_policy(self, name, ns):
        self.c.log.append(("net", "delete_policy", name))
        self.c.policies.pop(name, None)


def _selector_ok(obj, selector):
    labels = obj["metadata"].get("labels") or {}
    for term in filter(None, selector.split(",")):
        k, v = term.split("=")
        if labels.get(k) != v:
            return False
    return True


class FakeCustom:
    def __init__(self, c):
        self.c = c

    async def create_namespaced_custom_object(self, group, version, ns, plural, body):
        assert (group, version, plural) == ("snapshot.storage.k8s.io", "v1", "volumesnapshots")
        name = body["metadata"]["name"]
        self.c.log.append(("custom", "create_snapshot", name, body))
        if name in self.c.snapshots:
            raise Exists(name)
        obj = copy.deepcopy(body)
        obj["metadata"]["creationTimestamp"] = datetime.fromtimestamp(
            self.c.snapshot_clock(), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.c.snapshots[name] = obj

    async def list_namespaced_custom_object(self, group, version, ns, plural, label_selector=""):
        return {"items": [copy.deepcopy(s) for s in self.c.snapshots.values()
                          if _selector_ok(s, label_selector or "")]}

    async def delete_namespaced_custom_object(self, group, version, ns, plural, name):
        self.c.log.append(("custom", "delete_snapshot", name))
        self.c.snapshots.pop(name)


def add_db_workload(c, name="db", kind="Deployment", claim="db-data", replicas=1, pod=None, vct=False,
                    digest=DIGEST, image="reg:5000/db:1.0"):
    """A workload with one PVC volume, its RS (for Deployments), one running pod and the PVC."""
    pod = pod or f"{name}-abc-1"
    dep = deployment_obj(name=name, replicas=replicas, claim=None if vct else claim, image=image)
    if vct:
        dep["spec"]["volumeClaimTemplates"] = [{"metadata": {"name": "data"}}]
    c.workloads[(kind, name)] = dep
    owner = ([{"kind": "StatefulSet", "name": name}] if kind == "StatefulSet"
             else [{"kind": "ReplicaSet", "name": f"{name}-abc"}])
    if kind == "Deployment":
        c.replica_sets[f"{name}-abc"] = {"metadata": {"name": f"{name}-abc",
                                                      "ownerReferences": [{"kind": "Deployment", "name": name}]}}
    c.pods[pod] = {"metadata": {"name": pod, "labels": {"app": name}, "ownerReferences": owner},
                   "spec": {"volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": claim}}]},
                   "status": {"containerStatuses": [
                       {"name": "app", "imageID": (f"docker.io/reg/db@{digest}" if digest else "")}]}}
    c.pvcs[claim] = {"metadata": {"name": claim, "namespace": "prod"},
                     "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "local-path",
                              "resources": {"requests": {"storage": "1Gi"}}},
                     "status": {"phase": "Bound"}}
    return pod

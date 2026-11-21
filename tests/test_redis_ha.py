"""Redis HA: manifests (production overlay == Helm redis.ha.enabled), Sentinel client wiring, failover recovery."""

import shutil
import subprocess
from pathlib import Path

import fakeredis
import pytest
import redis.asyncio as aioredis
import yaml

from agents.fusion_agent import agent as fa
from kubeheal import redis_client as rc

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/kubeheal"
needs_tools = pytest.mark.skipif(not (shutil.which("helm") and shutil.which("kubectl")), reason="helm/kubectl not on PATH")


def render(*cmd: str) -> dict:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(r.stdout) if d}


@pytest.fixture(scope="module", params=["kustomize", "helm"])
def prod(request):
    if request.param == "kustomize":
        return render("kubectl", "kustomize", str(ROOT / "deploy/k8s/overlays/production"))
    return render("helm", "template", "k", str(CHART), "-n", "kubeheal", "-f", str(CHART / "values-production.yaml"))


@needs_tools
def test_three_redis_three_sentinels_quorum_pdb_anti_affinity(prod):
    for name in ("redis", "redis-sentinel"):
        sts = prod[("StatefulSet", name)]
        assert sts["spec"]["replicas"] == 3 and sts["spec"]["template"]["spec"]["priorityClassName"] == "kubeheal-security"
        term = sts["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"][0]
        assert term["podAffinityTerm"]["topologyKey"] == "kubernetes.io/hostname"
        assert prod[("PodDisruptionBudget", name)]["spec"]["minAvailable"] == 2
    assert prod[("StatefulSet", "redis")]["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"] == "1Gi"
    assert "sentinel monitor kubeheal $master 6379 2" in prod[("StatefulSet", "redis-sentinel")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert ("Deployment", "redis") not in prod and ("Service", "redis-master") not in prod
    assert {("NetworkPolicy", n) for n in ("redis-agents-only", "redis-peers", "redis-sentinel-clients")} <= prod.keys()


@needs_tools
def test_acl_users_and_replication_auth(prod):
    script = prod[("StatefulSet", "redis")]["spec"]["template"]["spec"]["containers"][0]["args"][0]
    for user in ("default", "health", "security", "fusion", "dashboard"):
        assert f"user {user} on >" in script
    assert "user replicator on >$REPLICATOR_PASSWORD" in script and "+psync +replconf" in script
    assert "masteruser replicator" in script and "masterauth $REPLICATOR_PASSWORD" in script
    assert "min-replicas-to-write 1" in script and "min-replicas-max-lag 10" in script


@needs_tools
def test_agents_get_sentinel_env(prod):
    for kind, name in (("Deployment", "kubeheal-fusion-agent"), ("Deployment", "kubeheal-health-agent"),
                       ("DaemonSet", "kubeheal-security-agent")):
        env = {e["name"]: e for e in prod[(kind, name)]["spec"]["template"]["spec"]["containers"][0]["env"]}
        hosts = env["REDIS_SENTINELS"]["value"].split(",")
        assert len(hosts) == 3 and all(h.endswith(".redis-sentinel.kubeheal.svc:26379") for h in hosts)
        assert "REDIS_URL" in env   # still supplies the component's ACL user and password


@needs_tools
def test_sentinel_is_authenticated_and_clients_are_limited(prod):
    sts = prod[("StatefulSet", "redis-sentinel")]["spec"]["template"]["spec"]["containers"][0]
    script = sts["args"][0]
    assert "user default on >$SENTINEL_PASSWORD" in script and "sentinel|get-master-addr-by-name" in script
    default_line = next(ln for ln in script.splitlines() if ln.strip().startswith("user default on"))
    assert "+@all" not in default_line and "-@all" in default_line      # clients may only look up the primary
    assert "sentinel sentinel-user peer" in script and "user peer on >$REDISCLI_AUTH" in script
    assert "env -u REDISCLI_AUTH" not in script and "--user peer" in str(sts["readinessProbe"])
    redis = prod[("StatefulSet", "redis")]["spec"]["template"]["spec"]["containers"][0]
    assert "user replicator on >$REPLICATOR_PASSWORD" in redis["args"][0] and "masterauth $REPLICATOR_PASSWORD" in redis["args"][0]
    for c, key in ((sts, "SENTINEL_PASSWORD"), (redis, "REPLICATOR_PASSWORD")):
        ref = {e["name"]: e for e in c["env"]}[key]["valueFrom"]["secretKeyRef"]
        assert ref["name"] == "kubeheal-redis-ha"
    for kind, name in (("Deployment", "kubeheal-fusion-agent"), ("Deployment", "kubeheal-health-agent"),
                       ("Deployment", "kubeheal-dashboard"), ("DaemonSet", "kubeheal-security-agent")):
        if (kind, name) not in prod:   # kustomize production drops the dashboard
            continue
        env = {e["name"]: e for e in prod[(kind, name)]["spec"]["template"]["spec"]["containers"][0]["env"]}
        assert env["REDIS_SENTINEL_PASSWORD"]["valueFrom"]["secretKeyRef"] == {"name": "kubeheal-redis-ha", "key": "sentinel-password"}, name
    job = prod[("Job", "kubeheal-redis-secret")]["spec"]["template"]["spec"]["containers"][0]["command"][2]
    assert 'create(api, "kubeheal-redis-ha", {"replicator-password"' in job and "sentinel-password" in job


@needs_tools
def test_dev_stays_single_redis():
    dev = render("kubectl", "kustomize", str(ROOT / "deploy/k8s"))
    assert ("Deployment", "redis") in dev and not [k for k in dev if "sentinel" in k[1] or k[0] == "StatefulSet"]


# ── client ────────────────────────────────────────────────────────────────────────────────────

class FakeSentinel:
    calls: list = []

    def __init__(self, nodes, sentinel_kwargs=None, **kw):
        FakeSentinel.calls.append((nodes, sentinel_kwargs, kw))

    def master_for(self, name):
        return ("master", name)


def test_sentinel_client_uses_component_credentials(monkeypatch):
    monkeypatch.setattr(rc, "Sentinel", FakeSentinel)
    monkeypatch.setattr(rc, "_sentinels", {})
    monkeypatch.setenv("REDIS_SENTINELS", "s0.x:26379, s1.x:26380")
    monkeypatch.setenv("REDIS_SENTINEL_PASSWORD", "sp")
    got = rc.redis_client("redis://fusion:p%40ss@redis-master.kubeheal.svc:6379/0", 10, 5)
    assert got == ("master", "kubeheal")
    nodes, skw, kw = FakeSentinel.calls[-1]
    assert nodes == [("s0.x", 26379), ("s1.x", 26380)] and skw["password"] == "sp"
    assert (kw["username"], kw["password"], kw["db"], kw["socket_timeout"]) == ("fusion", "p@ss", 0, 10)
    monkeypatch.setenv("REDIS_SENTINEL_MASTER", "m2")
    assert rc.redis_client("redis://fusion:p@h/0", 10, 5) == ("master", "m2")


def test_plain_url_without_sentinels(monkeypatch):
    monkeypatch.delenv("REDIS_SENTINELS", raising=False)
    assert isinstance(rc.redis_client("redis://u:p@h:6379/0", 1, 1), aioredis.Redis)


# ── failover: a primary switch looks like ReadOnlyError / ConnectionError to the loops ──────────

@pytest.mark.parametrize("exc", [aioredis.ReadOnlyError("READONLY"), aioredis.ConnectionError("primary gone")])
async def test_fusion_consume_survives_primary_switch(monkeypatch, exc):
    monkeypatch.setattr(fa, "RETRY_S", 0)
    agent = fa.FusionAgent(fakeredis.FakeAsyncRedis(decode_responses=True), None, None, None, None)
    polls = []

    async def poll_once(**_):
        polls.append(1)
        if len(polls) == 1:
            raise exc            # the write hit the demoted primary
        if len(polls) == 4:
            raise KeyboardInterrupt   # stop the loop; only reachable if polling resumed after the error

    monkeypatch.setattr(agent, "poll_once", poll_once)
    with pytest.raises(KeyboardInterrupt):
        await agent.consume(fa.STREAMS)
    assert len(polls) == 4

"""V5-D5 (owner decision D3): golden baseline promotion.

Automatic in dev and staging, a candidate that waits for approval in prod and an unknown tier; every promotion is a
ledger entry that keeps the previous baseline, written BEFORE the key is overwritten. Offline: the fake Kubernetes
API, Redis, Prometheus window and inference service of tests/health_helpers.py and the in-memory ledger."""
import asyncio
import json
import logging

import pytest
from kubernetes_asyncio.client.exceptions import ApiException  # noqa: F401  (kept for parity with the other tests)

from health_helpers import Env, dep, failing_pod, prediction
from agents.common.ledger import InMemoryLedgerStore, Ledger
from agents.health_agent import baseline as bl
from agents.health_agent.agent import HealthAgent

BENIGN = dict(label="benign", risk=0.05, pset=["benign"])


class FailingStore(InMemoryLedgerStore):
    def put_if_absent(self, key, data):
        raise OSError("minio down")


def run(coro):
    return asyncio.run(coro)


def key_of(ns):
    return (ns, "victim-app")


def run_env(fn, **kw):
    async def go():
        env = Env(**kw)
        try:
            await fn(env)
        finally:
            await env.agent.stop()
    run(go())


def entries(ledger, step=None, ns="dev"):
    prefix = f"incidents/{bl.ledger_incident_id(ns, 'victim-app')}/"
    out = []
    for k in sorted(ledger.store.objects):
        if k.startswith(prefix):
            rec = json.loads(ledger.store.objects[k])
            if step is None or rec["step"] == step:
                out.append(rec)
    return out


async def golden_text(env, ns):
    return env.redis.store[bl.baseline_key(*key_of(ns))]


async def golden_image(env, ns):
    rec = json.loads(env.redis.store[bl.baseline_key(*key_of(ns))])
    return rec["spec"]["template"]["spec"]["containers"][0]["image"]


async def drift(env, ns, assess=True, **change):
    """First sight records the golden baseline (img:1); the changed spec is then assessed after the delay."""
    await env.send("ADDED", dep(ns=ns))
    await env.send("MODIFIED", dep(ns=ns, **change))
    if assess:
        await env.tick(60)


def verdict(**over):
    v = {"label": "benign", "prediction_set": ["benign"], "uncertain": False, "risk": 0.05,
         "model_version": "test-bundle-1", "event_id": "health-test", "reasons": [],
         "changed_fields": ["template.spec.containers[0].image"], "since_wall": 0.0, "missing_metrics": [],
         "golden_sha256": ""}
    v.update(over)
    return v


async def vd(env, ns, **over):
    """A clean verdict bound to the CURRENT golden baseline of the workload."""
    return verdict(golden_sha256=bl.raw_digest(await golden_text(env, ns)), **over)


# ---- promotion matrix by tier ---------------------------------------------------------------------------------
@pytest.mark.parametrize("ns", ["dev", "staging"])
def test_dev_and_staging_promote_automatically(ns):
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, ns, image="img:2")
        assert await golden_image(env, ns) == "img:2"
        assert bl.baseline_key(*key_of(ns)) in env.redis.store
        assert await bl.get_candidate(env.redis, *key_of(ns)) is None
        [promo] = entries(env.agent.ledger, "baseline_promoted", ns)
        assert promo["payload"]["kind"] == "auto" and promo["payload"]["approver"] == "health-agent"
        assert key_of(ns) not in env.agent._drifted          # the live spec is the baseline now
    run_env(go, ledger=Ledger())


@pytest.mark.parametrize("ns", ["prod", "demo"])      # "demo" has no tier mapping: unknown, treated like prod
def test_prod_and_unknown_tier_store_a_candidate_and_leave_the_baseline(ns):
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, ns, image="img:2")
        assert await golden_image(env, ns) == "img:1"
        cand = await bl.get_candidate(env.redis, *key_of(ns))
        assert cand["status"] == "pending" and cand["spec"]["template"]["spec"]["containers"][0]["image"] == "img:2"
        assert entries(env.agent.ledger, "baseline_promoted", ns) == []
        assert len(entries(env.agent.ledger, "baseline_candidate_created", ns)) == 1
    run_env(go, ledger=Ledger())


def test_candidate_schema():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "prod", image="img:2")
        cand = await bl.get_candidate(env.redis, "prod", "victim-app")
        assert set(cand) == {"schema", "candidate_id", "namespace", "deployment", "tier", "spec_hash",
                             "golden_sha256", "spec", "template", "changed_fields", "assessment", "created_at",
                             "status"}
        assert cand["schema"] == 1 and cand["tier"] == "prod"
        assert cand["changed_fields"] == ["template.spec.containers[0].image"]
        assert cand["golden_sha256"] == bl.raw_digest(await golden_text(env, "prod"))
        assert cand["assessment"]["prediction_set"] == ["benign"] and cand["assessment"]["rollout_complete"] is True
        assert "kubeheal:baseline-candidate:prod:victim-app" in env.redis.store
        assert [c["candidate_id"] for c in await bl.list_candidates(env.redis)] == [cand["candidate_id"]]
    run_env(go, ledger=Ledger())


# ---- what blocks a promotion --------------------------------------------------------------------------------
@pytest.mark.parametrize("pred", [
    dict(label="benign", risk=0.2, pset=["benign", "degradation"], uncertain=True),   # not certain
    dict(label="degradation", risk=0.6, pset=["degradation"]),                          # certain but not benign
    dict(label="benign", risk=0.05, pset=[]),                                           # empty set
    dict(label="benign", risk=0.05, pset=["degradation"]),                              # set is not {benign}
])
def test_only_a_certain_benign_set_promotes(pred):
    async def go(env):
        env.result = prediction(**pred)
        await drift(env, "dev", image="img:2")
        assert len(env.events) == 1
        assert await golden_image(env, "dev") == "img:1"
        assert entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


def test_a_window_without_metrics_is_never_certain():
    async def go(env):
        env.result = prediction(**BENIGN)
        env.window = {}                                    # Prometheus has nothing: the published set is empty
        await drift(env, "dev", image="img:2")
        assert env.events[0]["health_prediction_set"] == "[]"
        assert await golden_image(env, "dev") == "img:1"
    run_env(go, ledger=Ledger())


def test_an_incomplete_rollout_promotes_only_when_it_completes():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2", rolled_out=False)
        assert len(env.events) == 1 and await golden_image(env, "dev") == "img:1"
        assert key_of("dev") in env.agent.tracking
        await env.send("MODIFIED", dep(ns="dev", image="img:2", generation=1))     # status-only: rollout done
        await env.tick(2)
        assert await golden_image(env, "dev") == "img:2"
        assert len(entries(env.agent.ledger, "baseline_promoted")) == 1
    run_env(go, ledger=Ledger())


def test_failure_reasons_block_a_promotion():
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        await env.send("MODIFIED", dep(ns="dev", image="img:2"))
        env.core.pods = [failing_pod(env.clock.wall())]
        await env.tick(60)
        assert json.loads(env.events[0]["failure_reasons_json"]) == ["ImagePullBackOff"]
        assert await golden_image(env, "dev") == "img:1" and entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


def test_failure_reasons_that_appear_after_the_verdict_block_the_promotion():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2", rolled_out=False)
        env.core.pods = [failing_pod(env.clock.wall())]
        await env.tick(2)
        await env.tick(2)                                  # confirmed on two polls: a follow-up event
        assert len(env.events) == 2
        await env.send("MODIFIED", dep(ns="dev", image="img:2", generation=1))     # then the rollout completes
        env.core.pods = []
        await env.tick(2)
        await env.tick(2)
        assert await golden_image(env, "dev") == "img:1" and entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


def test_a_posture_violation_blocks_a_promotion():
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        await env.send("MODIFIED", dep(ns="dev", cpu="50m"))        # the 10x cpu cut rule
        await env.tick(0)
        assert "policy:cpu_cut_10x" in json.loads(env.events[0]["failure_reasons_json"])
        assert env.events[0]["health_label"] == "benign"
        assert await golden_image(env, "dev") == "img:1"
        assert entries(env.agent.ledger) == []
        # the final recheck also refuses a verdict that carried no reasons while the posture is violated
        env.agent._vetoed.clear()                                    # (the published event vetoed this spec)
        env.agent._cooloff_until.clear()
        out = await env.agent._maybe_promote(key_of("dev"), env.agent.seen_hash[key_of("dev")], await vd(env, "dev"))
        assert out == "failure_reasons"
        assert entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


def test_a_spec_equal_to_the_baseline_has_nothing_to_promote():
    async def go(env):
        await env.send("ADDED", dep(ns="dev"))
        out = await env.agent._maybe_promote(key_of("dev"), env.agent.seen_hash[key_of("dev")], await vd(env, "dev"))
        assert out == "nothing_to_promote" and entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


# ---- superseded specs ---------------------------------------------------------------------------------------
def test_a_superseded_spec_is_never_promoted():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", assess=False, image="img:2", rolled_out=False)
        old_hash = env.agent.seen_hash[key_of("dev")]
        await env.send("MODIFIED", dep(ns="dev", image="img:3"))                  # a newer spec arrives
        assert await env.agent._maybe_promote(key_of("dev"), old_hash, await vd(env, "dev")) == "superseded"
        # an assessment of a different spec in flight also blocks (the current hash is the newest one)
        env.agent.assessing[key_of("dev")] = "some-other-hash"
        new_hash = env.agent.seen_hash[key_of("dev")]
        assert await env.agent._maybe_promote(key_of("dev"), new_hash, await vd(env, "dev")) == "superseded"
        env.agent.assessing.pop(key_of("dev"))
        assert await golden_image(env, "dev") == "img:1" and entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


def test_a_spec_superseded_during_the_ledger_write_aborts_the_promotion():
    class SupersedingLedger(Ledger):
        agent = None

        def append(self, incident_id, step, payload):
            entry = super().append(incident_id, step, payload)
            if step == "baseline_promoted":
                self.agent.seen_hash[key_of("dev")] = "a-newer-hash"            # a newer spec arrived meanwhile
            return entry

    async def go(env):
        env.agent.ledger.agent = env.agent
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2")
        assert await golden_image(env, "dev") == "img:1"                         # CAS never ran
        assert len(entries(env.agent.ledger, "baseline_promoted")) == 1          # ledger first, then aborted
        [abort] = entries(env.agent.ledger, "baseline_promotion_aborted")
        assert "superseded" in abort["payload"]["reason"]
    run_env(go, ledger=SupersedingLedger())


# ---- ledger rules -------------------------------------------------------------------------------------------
def test_a_failing_ledger_fails_closed_and_the_baseline_is_unchanged(caplog):
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        before = await golden_text(env, "dev")
        with caplog.at_level(logging.ERROR):
            await env.send("MODIFIED", dep(ns="dev", image="img:2"))
            await env.tick(60)
        assert await golden_text(env, "dev") == before
        assert "ledger write failed" in caplog.text
        assert len(env.events) == 1                                              # the event itself still published
    run_env(go, ledger=Ledger(FailingStore()))


def test_the_ledger_entry_keeps_the_previous_baseline_and_is_written_first():
    class OrderLedger(Ledger):
        seen_golden_at_append = None
        env = None

        def append(self, incident_id, step, payload):
            if step == "baseline_promoted":
                OrderLedger.seen_golden_at_append = self.env.redis.store[bl.baseline_key("dev", "victim-app")]
            return super().append(incident_id, step, payload)

    async def go(env):
        env.agent.ledger.env = env
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        old_text = await golden_text(env, "dev")
        await env.send("MODIFIED", dep(ns="dev", image="img:2"))
        await env.tick(60)
        assert OrderLedger.seen_golden_at_append == old_text                    # still the old baseline at append time
        [promo] = entries(env.agent.ledger, "baseline_promoted")
        p = promo["payload"]
        assert p["previous"] == json.loads(old_text)
        assert p["previous_text_sha256"] == bl.raw_digest(old_text)
        assert p["previous"]["spec"]["template"]["spec"]["containers"][0]["image"] == "img:1"
        assert p["new"]["spec"]["template"]["spec"]["containers"][0]["image"] == "img:2"
        assert p["changed_fields"] == ["template.spec.containers[0].image"]
        assert p["evidence"]["prediction_set"] == ["benign"] and p["evidence"]["failure_reasons"] == []
        new = json.loads(await golden_text(env, "dev"))
        assert new["promotion"]["ledger_key"] in env.agent.ledger.store.objects     # the pointer resolves
        assert new["promotion"]["kind"] == "auto"
        # a second promotion points back at the first one
        await env.send("MODIFIED", dep(ns="dev", image="img:3"))
        await env.tick(60)
        second = entries(env.agent.ledger, "baseline_promoted")[1]["payload"]
        assert second["previous_promotion"]["ledger_key"] == new["promotion"]["ledger_key"]
        assert second["previous"]["spec"]["template"]["spec"]["containers"][0]["image"] == "img:2"
    run_env(go, ledger=OrderLedger())


def test_a_lost_compare_and_set_does_not_overwrite_a_newer_baseline():
    async def go(env):
        await env.send("ADDED", dep(ns="dev"))
        stale = await golden_text(env, "dev")
        env.redis.store[bl.baseline_key("dev", "victim-app")] = json.dumps(bl.make_record(dep(image="img:9")["spec"]))
        res = await bl.promote_baseline(env.redis, env.agent.ledger, "dev", "victim-app",
                                        new_spec=dep(image="img:2")["spec"], spec_hash="h", golden_raw=stale,
                                        kind="auto", actor="health-agent")
        assert res["status"] == "conflict"
        assert await golden_image(env, "dev") == "img:9"
        assert len(entries(env.agent.ledger, "baseline_promotion_aborted")) == 1
    run_env(go, ledger=Ledger())


# ---- no ledger, switched off -----------------------------------------------------------------------------------
def test_without_a_ledger_automatic_promotion_is_disabled_and_candidates_are_still_stored(caplog, monkeypatch):
    monkeypatch.delenv("LEDGER_BACKEND", raising=False)

    async def go(env):
        assert env.agent.ledger is None
        with caplog.at_level(logging.WARNING):
            env.agent.log_promotion_config()
        assert "DISABLED, no ledger is configured" in caplog.text
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2")
        assert await golden_image(env, "dev") == "img:1"                         # no promotion without a ledger
        await drift(env, "prod", image="img:2")
        cand = await bl.get_candidate(env.redis, "prod", "victim-app")
        assert cand["status"] == "pending"
        # approval needs the ledger
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", None, cand["candidate_id"])
        assert res["status"] == "no_ledger"
        assert await golden_image(env, "prod") == "img:1"
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is not None
    run_env(go)


def test_promotion_switch(monkeypatch):
    assert bl.promotion_enabled_from_env({}) is True
    assert bl.promotion_enabled_from_env({"HEALTH_BASELINE_PROMOTION": "on"}) is True
    for off in ("off", "OFF", "false", "0", "no", "disabled"):
        assert bl.promotion_enabled_from_env({"HEALTH_BASELINE_PROMOTION": off}) is False
    monkeypatch.setenv("HEALTH_BASELINE_PROMOTION", "off")
    assert HealthAgent(redis_url="redis://unused", ledger=Ledger()).auto_promotion is False


def test_switched_off_dev_does_not_promote_but_prod_still_gets_a_candidate():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2")
        assert await golden_image(env, "dev") == "img:1" and entries(env.agent.ledger) == []
        await drift(env, "prod", image="img:2")
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is not None
    run_env(go, ledger=Ledger(), auto_promotion=False)


def test_the_ledger_is_built_from_the_environment_only_when_configured(monkeypatch):
    monkeypatch.delenv("LEDGER_BACKEND", raising=False)
    assert HealthAgent(redis_url="redis://unused").ledger is None
    monkeypatch.setenv("LEDGER_BACKEND", "memory")
    assert isinstance(HealthAgent(redis_url="redis://unused").ledger, Ledger)
    monkeypatch.setenv("LEDGER_BACKEND", "minio")                  # no credentials: invalid, so no ledger
    assert HealthAgent(redis_url="redis://unused").ledger is None


# ---- candidates: approve, reject, drop -----------------------------------------------------------------------------
async def prod_candidate(env):
    env.result = prediction(**BENIGN)
    await drift(env, "prod", image="img:2")
    return await bl.get_candidate(env.redis, "prod", "victim-app")


def test_approving_a_candidate_promotes_it_through_the_ledger():
    async def go(env):
        cand = await prod_candidate(env)
        old_text = await golden_text(env, "prod")
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", " alice ", env.agent.ledger,
                                         candidate_id=cand["candidate_id"], reason="reviewed")
        assert res["status"] == "promoted"
        assert await golden_image(env, "prod") == "img:2"
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        [promo] = entries(env.agent.ledger, "baseline_promoted", "prod")
        p = promo["payload"]
        assert p["kind"] == "approved" and p["approver"] == "alice" and p["reason"] == "reviewed"
        assert p["candidate_id"] == cand["candidate_id"] and p["previous"] == json.loads(old_text)
        assert json.loads(await golden_text(env, "prod"))["promotion"]["approver"] == "alice"
    run_env(go, ledger=Ledger())


def test_approval_checks_the_candidate_id_and_the_approver():
    async def go(env):
        cand = await prod_candidate(env)
        cid, led = cand["candidate_id"], env.agent.ledger
        assert (await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", led, "not-it"))["status"] == "id_mismatch"
        assert (await bl.approve_promotion(env.redis, "prod", "other", "alice", led, cid))["status"] == "not_found"
        for bad in ({"approver": "  "}, {"approver": "Health-Agent"}, {"approver": "x" * 129},
                    {"reason": "r" * 513}, {"candidate_id": ""}, {"candidate_id": None}, {"namespace": "a:b"},
                    {"namespace": "Prod"}, {"deployment": "victim-app:x"}, {"deployment": "-bad"}):
            args = {"namespace": "prod", "deployment": "victim-app", "approver": "alice", "candidate_id": cid,
                    "reason": ""}
            args.update(bad)
            for fn in (bl.approve_promotion, bl.reject_promotion):
                with pytest.raises(ValueError):
                    await fn(env.redis, args["namespace"], args["deployment"], args["approver"], led,
                             args["candidate_id"], args["reason"])
        with pytest.raises(TypeError):                              # candidate_id has no default
            await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", led)
        with pytest.raises(TypeError):
            await bl.reject_promotion(env.redis, "prod", "victim-app", "alice", led)
        assert (await bl.approve_promotion(env.redis, "prod", "victim-app", "a" * 128, led, "not-it"))["status"] == "id_mismatch"
        assert await golden_image(env, "prod") == "img:1" and await bl.get_candidate(env.redis, "prod", "victim-app")
    run_env(go, ledger=Ledger())


def test_approval_with_a_failing_ledger_changes_nothing():
    async def go(env):
        cand = await prod_candidate(env)
        before = await golden_text(env, "prod")
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", Ledger(FailingStore()),
                                         cand["candidate_id"])
        assert res["status"] == "ledger_failed"
        assert await golden_text(env, "prod") == before
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is not None
    run_env(go, ledger=Ledger())


def test_a_candidate_is_stale_when_the_golden_baseline_moved():
    async def go(env):
        cand = await prod_candidate(env)
        env.redis.store[bl.baseline_key("prod", "victim-app")] = json.dumps(bl.make_record(dep(image="img:7")["spec"]))
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger,
                                         cand["candidate_id"])
        assert res["status"] == "stale"
        assert await golden_image(env, "prod") == "img:7"
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        assert len(entries(env.agent.ledger, "baseline_candidate_superseded", "prod")) == 1
    run_env(go, ledger=Ledger())


def test_rejecting_a_candidate_is_ledgered_and_remembered():
    async def go(env):
        cand = await prod_candidate(env)
        res = await bl.reject_promotion(env.redis, "prod", "victim-app", "bob", env.agent.ledger,
                                        candidate_id=cand["candidate_id"], reason="not intended")
        assert res["status"] == "rejected"
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        assert await golden_image(env, "prod") == "img:1"
        [rej] = entries(env.agent.ledger, "baseline_candidate_rejected", "prod")
        assert rej["payload"]["approver"] == "bob" and rej["payload"]["reason"] == "not intended"
        # the same spec is not proposed again
        key = key_of("prod")
        out = await env.agent._maybe_promote(key, env.agent.seen_hash[key], await vd(env, "prod"))
        assert out == "candidate_rejected_before" and await bl.get_candidate(env.redis, *key) is None
        # a changed spec clears the remembered rejection and can get a new candidate
        await env.send("MODIFIED", dep(ns="prod", image="img:3"))
        await env.tick(60)
        assert (await bl.get_candidate(env.redis, *key))["spec"]["template"]["spec"]["containers"][0]["image"] == "img:3"
        assert bl.rejected_key(*key) not in env.redis.store
    run_env(go, ledger=Ledger())


def test_rejection_with_a_failing_ledger_keeps_the_candidate_pending():
    async def go(env):
        cid = (await prod_candidate(env))["candidate_id"]
        res = await bl.reject_promotion(env.redis, "prod", "victim-app", "bob", Ledger(FailingStore()), cid)
        assert res["status"] == "ledger_failed"
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is not None
        assert (await bl.reject_promotion(env.redis, "prod", "victim-app", "bob", None, cid))["status"] == "no_ledger"
    run_env(go, ledger=Ledger())


def test_a_candidate_is_dropped_when_the_live_spec_changes_again():
    async def go(env):
        await prod_candidate(env)
        await env.send("MODIFIED", dep(ns="prod", image="img:3", rolled_out=False))     # a newer spec, not yet certain
        await env.agent.drain()
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        [dropped] = entries(env.agent.ledger, "baseline_candidate_superseded", "prod")
        assert "changed again" in dropped["payload"]["reason"]
        assert await golden_image(env, "prod") == "img:1"
    run_env(go, ledger=Ledger())


def test_a_candidate_is_dropped_when_the_workload_is_deleted_or_returns_to_the_baseline():
    async def go(env):
        await prod_candidate(env)
        await env.send("DELETED", dep(ns="prod", image="img:2"))
        await env.agent.drain()
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        assert "deleted" in entries(env.agent.ledger, "baseline_candidate_superseded", "prod")[0]["payload"]["reason"]
    run_env(go, ledger=Ledger())


def test_a_candidate_is_dropped_when_the_spec_returns_to_the_baseline():
    async def go(env):
        await prod_candidate(env)
        await env.send("MODIFIED", dep(ns="prod"))                    # back to img:1, the golden spec
        await env.agent.drain()
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        assert len(entries(env.agent.ledger, "baseline_candidate_superseded", "prod")) == 1
    run_env(go, ledger=Ledger())


def test_a_candidate_written_while_a_newer_spec_arrives_is_removed():
    async def go(env):
        env.result = prediction(**BENIGN)
        real_set = env.redis.set

        async def racing_set(k, v, **kw):
            res = await real_set(k, v, **kw)
            if k == bl.candidate_key("prod", "victim-app"):
                env.agent.seen_hash[key_of("prod")] = "a-newer-hash"        # the newer spec lands during the write
            return res

        env.redis.set = racing_set
        await drift(env, "prod", image="img:2")
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is None
        assert len(entries(env.agent.ledger, "baseline_candidate_superseded", "prod")) == 1
        assert await golden_image(env, "prod") == "img:1"
    run_env(go, ledger=Ledger())


def test_the_same_assessment_does_not_rewrite_the_candidate():
    async def go(env):
        cand = await prod_candidate(env)
        key = key_of("prod")
        out = await env.agent._maybe_promote(key, env.agent.seen_hash[key], await vd(env, "prod"))
        assert out == "candidate_unchanged"
        assert (await bl.get_candidate(env.redis, *key)) == cand
        assert len(entries(env.agent.ledger, "baseline_candidate_created", "prod")) == 1
    run_env(go, ledger=Ledger())


# ---- the first baseline is still SET NX -----------------------------------------------------------------------
def test_the_first_baseline_is_still_set_nx():
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        first = await golden_text(env, "dev")
        golden, created = await bl.get_or_set_baseline(env.redis, "dev", "victim-app", dep(image="img:5")["spec"])
        assert created is False and await golden_text(env, "dev") == first
        assert golden["spec"]["template"]["spec"]["containers"][0]["image"] == "img:1"
    run_env(go, ledger=Ledger())


def test_persistent_drift_that_is_not_certain_benign_never_replaces_the_baseline():
    async def go(env):
        env.result = prediction(label="degradation", risk=0.6, pset=["degradation"])
        await drift(env, "dev", image="img:2")
        await env.send("MODIFIED", dep(ns="dev", image="img:2", annotations={"x": "y"}))
        await env.tick(300)
        assert await golden_image(env, "dev") == "img:1" and entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


# ---- scripts/baseline_tool.py ----------------------------------------------------------------------------------
class SyncRedis:
    def __init__(self, store):
        self.store = store

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v

    def delete(self, k):
        return int(self.store.pop(k, None) is not None)

    def scan_iter(self, pattern):
        prefix = pattern.rstrip("*")
        return iter([k for k in list(self.store) if k.startswith(prefix)])


def test_baseline_tool_restore_candidates_and_reset(tmp_path, monkeypatch, capsys):
    import redis as redis_lib
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import baseline_tool

    async def go(env):
        cand = await prod_candidate(env)
        old_text = await golden_text(env, "prod")
        await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger, cand["candidate_id"])
        [promo] = entries(env.agent.ledger, "baseline_promoted", "prod")
        entry_file = tmp_path / "entry.json"
        entry_file.write_text(json.dumps(promo))
        other = tmp_path / "other.json"
        other.write_text(json.dumps({**promo, "payload": {**promo["payload"], "deployment": "someone-else"}}))
        store = {k: v for k, v in env.redis.store.items()}
        monkeypatch.setattr(redis_lib.Redis, "from_url", staticmethod(lambda *a, **k: SyncRedis(store)))
        key = bl.baseline_key("prod", "victim-app")
        assert baseline_tool.main(["restore", "prod", "victim-app", str(other)]) == 1       # wrong workload
        assert json.loads(store[key])["spec"]["template"]["spec"]["containers"][0]["image"] == "img:2"
        assert baseline_tool.main(["restore", "prod", "victim-app", str(entry_file)]) == 0
        assert json.loads(store[key]) == json.loads(old_text)                                # the previous record
        store[bl.candidate_key("prod", "victim-app")] = json.dumps(cand)
        assert baseline_tool.main(["candidates"]) == 0
        assert cand["candidate_id"] in capsys.readouterr().out
        assert baseline_tool.main(["reset", "prod", "victim-app"]) == 0
        assert key not in store
    run_env(go, ledger=Ledger())


# =====================================================================================================================
# Review fixes (D1 to D8, L1, T-c, restore): guards around a promotion
# =====================================================================================================================
from kubeheal.features.health import RAW_METRICS            # noqa: E402

from agents.health_agent.agent import PROMOTIONS             # noqa: E402

DEV = key_of("dev")
PROD = key_of("prod")


def outcomes():
    """Promotion outcome counters (cumulative in the process), as {label: count}."""
    return {s.labels["outcome"]: s.value for m in PROMOTIONS.collect() for s in m.samples
            if s.name.endswith("_total")}


def grew(before, label):
    return outcomes().get(label, 0) > before.get(label, 0)


async def no_candidate_or_promotion(env, ns):
    assert await golden_image(env, ns) == "img:1"
    assert await bl.get_candidate(env.redis, ns, "victim-app") is None
    assert entries(env.agent.ledger, "baseline_promoted", ns) == []


# ---- D1: a later assessment replaces the tracker's verdict -----------------------------------------------------------
def test_a_later_worse_score_of_the_same_spec_replaces_the_tracked_verdict():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2", rolled_out=False)
        assert env.agent.tracking[DEV].verdict["label"] == "benign"
        env.apps.live[DEV] = dep(ns="dev", image="img:2", rolled_out=False)
        env.result = prediction(label="degradation", risk=0.6, pset=["degradation"])
        await env.agent.observe_sample(DEV)                       # an OBSERVE re-score of the same spec
        assert env.agent.tracking[DEV].verdict["label"] == "degradation"
        env.agent._vetoed.clear()                                 # (isolate D1 from the veto)
        env.agent._cooloff_until.clear()
        env.redis.store.pop(bl.cooloff_key(*DEV), None)
        await env.send("MODIFIED", dep(ns="dev", image="img:2", generation=1))      # the rollout completes
        await env.tick(2)
        await no_candidate_or_promotion(env, "dev")
    run_env(go, ledger=Ledger())


def test_a_later_assessment_without_a_score_clears_the_tracked_verdict():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2", rolled_out=False)
        assert env.agent.tracking[DEV].verdict is not None
        env.apps.live[DEV] = dep(ns="dev", image="img:2", rolled_out=False)
        env.result = None
        await env.agent.observe_sample(DEV)
        assert env.agent.tracking[DEV].verdict is None
        await env.send("MODIFIED", dep(ns="dev", image="img:2", generation=1))
        await env.tick(2)
        await no_candidate_or_promotion(env, "dev")
    run_env(go, ledger=Ledger())


# ---- D2: lost failure evidence is not "no failure" -------------------------------------------------------------------
@pytest.mark.parametrize("ns", ["dev", "prod"])
@pytest.mark.parametrize("breakage", ["403", "timeout", "no_client", "match_expressions"])
def test_failure_evidence_that_cannot_be_read_blocks_promotion_and_candidate(ns, breakage):
    async def go(env):
        before = outcomes()
        env.result = prediction(**BENIGN)
        first, second = dep(ns=ns), dep(ns=ns, image="img:2")
        if breakage == "403":
            env.core.fail = ApiException(status=403, reason="Forbidden")
        elif breakage == "timeout":
            env.core.fail = asyncio.TimeoutError()
        elif breakage == "no_client":
            env.agent.core_api = None
        else:
            for d in (first, second):
                d["spec"]["selector"] = {"matchExpressions": [{"key": "app", "operator": "In", "values": ["victim-app"]}]}
        await env.send("ADDED", first)
        await env.send("MODIFIED", second)
        await env.tick(60)
        assert len(env.events) == 1                               # event publishing keeps its behavior
        assert json.loads(env.events[0]["failure_reasons_json"]) == []
        await no_candidate_or_promotion(env, ns)
        assert grew(before, "evidence_unavailable")
    run_env(go, ledger=Ledger())


# ---- D3: missing metric series ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("ns", ["dev", "prod"])
def test_missing_metric_series_block_promotion_and_candidate(ns, caplog):
    async def go(env):
        env.result = prediction(**BENIGN)
        env.window = {k: v for k, v in env.window.items() if k != list(RAW_METRICS)[-1]}   # one series missing
        with caplog.at_level(logging.INFO):
            await drift(env, ns, image="img:2")
        assert env.events[0]["health_prediction_set"] == '["benign"]'     # the model still said certain benign
        assert json.loads(env.events[0]["metrics_missing_json"]) == [list(RAW_METRICS)[-1]]
        await no_candidate_or_promotion(env, ns)
        assert "metric series missing" in caplog.text
    run_env(go, ledger=Ledger())


# ---- D4: coordination with the Executor, Fusion and the cool-off -----------------------------------------------------
def block_rollback(env, ns, state="pending"):
    env.redis.store[f"kubeheal:rollback:{ns}:victim-app"] = json.dumps({"state": state, "incident_id": "i1"})


def block_lock(env, ns):
    env.redis.store[f"kubeheal:incident-lock:{ns}:victim-app"] = "token"


def block_incident(env, ns, state="queued", name="victim-app", namespace=None):
    env.redis.hashes["kubeheal:fusion:incident:i1"] = {"namespace": namespace or ns, "deployment": name,
                                                       "opened": "1", "action_state": state}


def block_cooloff(env, ns):
    env.redis.store[bl.cooloff_key(ns, "victim-app")] = "1"


@pytest.mark.parametrize("ns", ["dev", "prod"])
@pytest.mark.parametrize("block", [block_rollback, block_lock, block_incident, block_cooloff,
                                   lambda e, n: block_incident(e, n, state="human_pending")])
def test_something_else_acting_on_the_workload_blocks_promotion_and_candidate(ns, block):
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns=ns))
        block(env, ns)
        await env.send("MODIFIED", dep(ns=ns, image="img:2"))
        await env.tick(60)
        assert len(env.events) == 1
        await no_candidate_or_promotion(env, ns)
    run_env(go, ledger=Ledger())


@pytest.mark.parametrize("harmless", [
    lambda e, n: block_rollback(e, n, state="done"),
    lambda e, n: block_incident(e, n, state=""),
    lambda e, n: block_incident(e, n, name="other-app"),
    lambda e, n: block_incident(e, n, namespace="elsewhere"),
])
def test_unrelated_coordination_state_does_not_block(harmless):
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        harmless(env, "dev")
        await env.send("MODIFIED", dep(ns="dev", image="img:2"))
        await env.tick(60)
        assert await golden_image(env, "dev") == "img:2"
    run_env(go, ledger=Ledger())


@pytest.mark.parametrize("ns", ["dev", "prod"])
def test_a_redis_error_while_reading_coordination_state_refuses(ns):
    async def go(env):
        env.result = prediction(**BENIGN)
        real_get = env.redis.get

        async def flaky(k):
            if k.startswith("kubeheal:rollback:"):
                raise ConnectionError("redis down")
            return await real_get(k)

        await env.send("ADDED", dep(ns=ns))
        env.redis.get = flaky
        await env.send("MODIFIED", dep(ns=ns, image="img:2"))
        await env.tick(60)
        await no_candidate_or_promotion(env, ns)
    run_env(go, ledger=Ledger())


def test_a_non_benign_event_sets_the_cooloff_marker_and_a_clean_one_does_not():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2")                    # clean: promoted, no cool-off
        assert bl.cooloff_key(*DEV) not in env.redis.store and DEV not in env.agent._cooloff_until
        env.result = prediction(label="degradation", risk=0.6, pset=["degradation"])
        await env.send("MODIFIED", dep(ns="dev", image="img:3"))
        await env.tick(60)
        assert env.redis.store[bl.cooloff_key(*DEV)] == "1"
        assert env.redis.expiry[bl.cooloff_key(*DEV)] - env.redis.now == 300       # the default, chosen not measured
        assert env.agent._cooloff_until[DEV] > env.clock.t
    run_env(go, ledger=Ledger())


def test_an_uncertain_event_and_a_no_score_notice_also_set_the_cooloff_marker():
    async def go(env):
        env.result = prediction(label="benign", risk=0.2, pset=["benign", "degradation"], uncertain=True)
        await drift(env, "dev", image="img:2")
        assert bl.cooloff_key(*DEV) in env.redis.store
        env.redis.store.pop(bl.cooloff_key(*DEV))
        env.agent._cooloff_until.clear()
        env.result = None                                         # inference down: the no-score notice
        await env.send("MODIFIED", dep(ns="dev", image="img:3"))
        await env.tick(60)
        assert bl.cooloff_key(*DEV) in env.redis.store
    run_env(go, ledger=Ledger())


def test_the_cooloff_blocks_a_clean_spec_until_it_has_passed(monkeypatch):
    async def go(env):
        env.result = prediction(label="degradation", risk=0.6, pset=["degradation"])
        await drift(env, "dev", image="img:2")                    # harmful: cool-off starts
        env.result = prediction(**BENIGN)
        await env.send("MODIFIED", dep(ns="dev", image="img:3"))
        await env.tick(60)                                        # clean, but inside the cool-off
        assert await golden_image(env, "dev") == "img:1"
        env.redis.advance(301)
        env.clock.advance(301)
        env.apps.live[DEV] = dep(ns="dev", image="img:3")
        await env.agent.observe_sample(DEV)                       # the same clean spec, scored again later
        assert await golden_image(env, "dev") == "img:3"
    run_env(go, ledger=Ledger())


def test_approval_is_blocked_while_something_else_acts_on_the_workload():
    async def go(env):
        cand = await prod_candidate(env)
        block_lock(env, "prod")
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger,
                                         cand["candidate_id"])
        assert res["status"] == "blocked" and "lock" in res["reason"]
        assert await golden_image(env, "prod") == "img:1" and await bl.get_candidate(env.redis, "prod", "victim-app")
        env.redis.store.pop("kubeheal:incident-lock:prod:victim-app")
        block_rollback(env, "prod")
        assert (await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger,
                                           cand["candidate_id"]))["status"] == "blocked"
        env.redis.store.pop("kubeheal:rollback:prod:victim-app")
        assert (await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger,
                                           cand["candidate_id"]))["status"] == "promoted"
    run_env(go, ledger=Ledger())


def test_cooloff_and_soak_settings_come_from_the_environment(monkeypatch):
    assert HealthAgent(redis_url="redis://unused", ledger=None).cooloff_s == 300
    assert HealthAgent(redis_url="redis://unused", ledger=None).min_soak_s == 0
    monkeypatch.setenv("HEALTH_PROMOTION_COOLOFF_S", "42")
    monkeypatch.setenv("HEALTH_PROMOTION_MIN_SOAK_S", "120")
    monkeypatch.setenv("HEALTH_PROMOTION_REQUIRE_SECURITY", "on")
    a = HealthAgent(redis_url="redis://unused", ledger=None)
    assert (a.cooloff_s, a.min_soak_s, a.require_security) == (42, 120, True)
    monkeypatch.setenv("HEALTH_PROMOTION_COOLOFF_S", "0")
    with pytest.raises(ValueError):
        HealthAgent(redis_url="redis://unused", ledger=None)


# ---- D5: a harmful verdict vetoes its spec ---------------------------------------------------------------------------
@pytest.mark.parametrize("ns", ["dev", "prod"])
def test_a_harmful_verdict_vetoes_the_spec_even_if_a_later_rescore_says_benign(ns):
    async def go(env):
        key = key_of(ns)
        env.result = prediction(label="degradation", risk=0.6, pset=["degradation"])
        await drift(env, ns, image="img:2")
        h = env.agent.seen_hash[key]
        assert env.redis.store[bl.veto_key(*key)] == h and env.redis.expiry[bl.veto_key(*key)] - env.redis.now == 86400
        assert h in env.agent._vetoed[key]
        # a later OBSERVE re-score says certain benign, the cool-off has passed: still no promotion or candidate
        env.redis.advance(301)
        env.clock.advance(301)
        env.result = prediction(**BENIGN)
        env.apps.live[key] = dep(ns=ns, image="img:2")
        await env.agent.observe_sample(key)
        await no_candidate_or_promotion(env, ns)
        # the veto survives a restart (memory gone): Redis still holds it
        env.agent._vetoed.clear()
        await env.agent.observe_sample(key)
        await no_candidate_or_promotion(env, ns)
        # a NEW spec hash is not vetoed by the old one
        await env.send("MODIFIED", dep(ns=ns, image="img:3"))
        await env.tick(60)
        if ns == "dev":
            assert await golden_image(env, ns) == "img:3"
        else:
            assert (await bl.get_candidate(env.redis, *key))["spec"]["template"]["spec"]["containers"][0]["image"] == "img:3"
    run_env(go, ledger=Ledger())


# ---- D6: the verdict is bound to the golden it was assessed against -------------------------------------------------
def test_a_verdict_for_another_golden_is_refused():
    async def go(env):
        await env.send("ADDED", dep(ns="dev"))
        await env.send("MODIFIED", dep(ns="dev", image="img:2"))
        h = env.agent.seen_hash[DEV]
        out = await env.agent._maybe_promote(DEV, h, verdict(golden_sha256="not-the-golden"))
        assert out == "golden_moved" and await golden_image(env, "dev") == "img:1"
    run_env(go, ledger=Ledger())


def test_a_golden_that_moved_while_the_rollout_finished_blocks_the_followup_promotion():
    async def go(env):
        before = outcomes()
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2", rolled_out=False)
        env.redis.store[bl.baseline_key(*DEV)] = json.dumps(bl.make_record(dep(image="img:7")["spec"]))   # the tool
        await env.send("MODIFIED", dep(ns="dev", image="img:2", generation=1))
        await env.tick(2)
        assert await golden_image(env, "dev") == "img:7" and entries(env.agent.ledger) == []
        assert grew(before, "golden_moved")
    run_env(go, ledger=Ledger())


# ---- soak ------------------------------------------------------------------------------------------------------------
def test_the_optional_soak_time_delays_the_promotion_until_it_has_passed():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2")                    # assessed 60 s after the change
        assert await golden_image(env, "dev") == "img:1"
        assert DEV in env.agent._promote_retry
        await env.tick(39)
        assert await golden_image(env, "dev") == "img:1"
        await env.tick(1)                                         # 100 s after the change
        assert await golden_image(env, "dev") == "img:2"
        assert DEV not in env.agent._promote_retry
    run_env(go, ledger=Ledger(), min_soak_s=100)


def test_a_new_assessment_cancels_a_pending_soak_retry():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", image="img:2")
        assert DEV in env.agent._promote_retry
        env.apps.live[DEV] = dep(ns="dev", image="img:2")
        env.result = prediction(label="degradation", risk=0.6, pset=["degradation"])
        await env.agent.observe_sample(DEV)
        assert DEV not in env.agent._promote_retry
        await env.tick(100)
        assert await golden_image(env, "dev") == "img:1"
    run_env(go, ledger=Ledger(), min_soak_s=100)


# ---- D8: security gate ---------------------------------------------------------------------------------------------
def set_security(env, risk="0.5", scored="true", age_s=0.0, ahead_s=60.0, key=DEV):
    ts = int((env.clock.wall() + ahead_s - age_s) * 1000)       # ahead_s: the assessment happens that much later
    env.redis.hashes[f"kubeheal:security:score:{key[0]}:{key[1]}"] = {"sec_risk": risk, "model_scored": scored,
                                                                       "ts_ms": str(ts)}


@pytest.mark.parametrize("ns", ["dev", "prod"])
@pytest.mark.parametrize("fields", [dict(risk="0.5"), dict(risk="0.4"), dict(risk="0.1", scored="false"),
                                    dict(risk="nan"), dict(risk="x")])
def test_a_fresh_high_or_unscored_security_score_blocks(ns, fields):
    async def go(env):
        before = outcomes()
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns=ns))
        await env.send("MODIFIED", dep(ns=ns, image="img:2"))
        set_security(env, key=key_of(ns), **fields)
        await env.tick(60)
        await no_candidate_or_promotion(env, ns)
        assert grew(before, "security_blocked")
    run_env(go, ledger=Ledger())


def test_a_fresh_low_security_score_allows_the_promotion():
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        await env.send("MODIFIED", dep(ns="dev", image="img:2"))
        set_security(env, risk="0.1")
        await env.tick(60)
        assert await golden_image(env, "dev") == "img:2"
    run_env(go, ledger=Ledger())


@pytest.mark.parametrize("stale", [True, False])
@pytest.mark.parametrize("require", [True, False])
def test_a_missing_or_stale_security_score_blocks_only_when_required(stale, require):
    async def go(env):
        env.result = prediction(**BENIGN)
        await env.send("ADDED", dep(ns="dev"))
        await env.send("MODIFIED", dep(ns="dev", image="img:2"))
        if stale:
            set_security(env, risk="0.9", age_s=3600)             # an hour old: stale, not evidence
        await env.tick(60)
        assert await golden_image(env, "dev") == ("img:1" if require else "img:2")
    run_env(go, ledger=Ledger(), require_security=require)


def test_security_blocker_unit():
    async def go(env):
        now = 1_000_000.0
        key = "kubeheal:security:score:dev:victim-app"

        async def verdict_for(fields, require=False, fresh_s=30.0):
            env.redis.hashes.pop(key, None)
            if fields is not None:
                env.redis.hashes[key] = fields
            return await bl.security_blocker(env.redis, "dev", "victim-app", now_ms=now, fresh_s=fresh_s, require=require)

        fresh = {"sec_risk": "0.39", "model_scored": "true", "ts_ms": str(int(now))}
        assert await verdict_for(fresh) is None
        assert "0.4" in await verdict_for({**fresh, "sec_risk": "0.4"})
        assert await verdict_for({**fresh, "ts_ms": str(int(now - 31_000))}) is None            # stale
        assert await verdict_for({**fresh, "ts_ms": str(int(now - 31_000))}, require=True)
        assert await verdict_for(None) is None and await verdict_for(None, require=True)
        assert await verdict_for({**fresh, "ts_ms": "junk"}) == "the security score hash is malformed"
        assert bl.RAW_SEC_RISK_CEILING == 0.4
    run_env(go, ledger=Ledger())


# ---- L1 and T-c ------------------------------------------------------------------------------------------------------
def test_a_failing_abort_entry_is_logged_as_an_error_and_the_payloads_say_not_applied(caplog):
    class AbortFails(Ledger):
        agent = None

        def append(self, incident_id, step, payload):
            if step == "baseline_promotion_aborted":
                raise OSError("ledger down")
            entry = super().append(incident_id, step, payload)
            if step == "baseline_promoted":
                self.agent.seen_hash[DEV] = "a-newer-hash"
            return entry

    async def go(env):
        env.agent.ledger.agent = env.agent
        env.result = prediction(**BENIGN)
        with caplog.at_level(logging.ERROR):
            await drift(env, "dev", image="img:2")
        assert await golden_image(env, "dev") == "img:1"
        assert "abort entry" in caplog.text and "NOT applied" in caplog.text
        [promo] = entries(env.agent.ledger, "baseline_promoted")
        assert promo["payload"]["applied"] is False
        assert "promotion" not in json.loads(await golden_text(env, "dev"))       # the golden does not point to it
    run_env(go, ledger=AbortFails())


def test_the_lua_script_and_its_python_mirror_agree():
    lua = bl.PROMOTE_BASELINE_LUA
    assert "redis.call('GET', KEYS[1]) == ARGV[1]" in lua and "redis.call('SET', KEYS[1], ARGV[2])" in lua
    assert "kubeheal:promote_baseline" in lua                  # the marker the mirror in tests/health_helpers.py keys on

    async def go(env):
        key = "kubeheal:baseline:dev:x"
        env.redis.store[key] = "old"
        assert await env.redis.eval(lua, 1, key, "other", "new") == 0 and env.redis.store[key] == "old"
        assert await env.redis.eval(lua, 1, key, "old", "new") == 1 and env.redis.store[key] == "new"
    run_env(go, ledger=Ledger())


# ---- scripts/baseline_tool.py restore rules --------------------------------------------------------------------------
def test_baseline_tool_restore_refuses_a_stale_or_altered_entry_unless_forced(tmp_path, monkeypatch, capsys):
    import sys
    from pathlib import Path
    import redis as redis_lib
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import baseline_tool

    async def go(env):
        cand = await prod_candidate(env)
        old_text = await golden_text(env, "prod")
        await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger, cand["candidate_id"])
        [promo] = entries(env.agent.ledger, "baseline_promoted", "prod")
        good = tmp_path / "good.json"
        good.write_text(json.dumps(promo))
        altered = json.loads(json.dumps(promo))
        altered["payload"]["previous"]["spec"]["template"]["spec"]["containers"][0]["image"] = "evil"
        bad = tmp_path / "altered.json"
        bad.write_text(json.dumps(altered))
        store = dict(env.redis.store)
        monkeypatch.setattr(redis_lib.Redis, "from_url", staticmethod(lambda *a, **k: SyncRedis(store)))
        key = bl.baseline_key("prod", "victim-app")
        promoted_text = store[key]

        assert baseline_tool.main(["restore", "prod", "victim-app", str(bad)]) == 1            # entry altered
        assert "current golden digest: " + bl.raw_digest(promoted_text) in capsys.readouterr().out
        assert store[key] == promoted_text

        # the golden moved on (a later promotion or the tool): the entry is no longer the latest promotion
        moved = json.loads(promoted_text)
        moved["promotion"]["ledger_key"] = "incidents/baseline.prod.victim-app/000099-baseline_promoted.json"
        store[key] = json.dumps(moved, sort_keys=True)
        assert baseline_tool.main(["restore", "prod", "victim-app", str(good)]) == 1
        assert "not by" in capsys.readouterr().err and store[key] == json.dumps(moved, sort_keys=True)
        assert baseline_tool.main(["restore", "prod", "victim-app", str(good), "--force"]) == 0
        assert json.loads(store[key]) == json.loads(old_text)

        # no current golden (after reset): refused without --force
        store.pop(key)
        assert baseline_tool.main(["restore", "prod", "victim-app", str(good)]) == 1
        assert "no current golden record" in capsys.readouterr().err and key not in store
        # the clean case: the entry IS the promotion that wrote the current golden
        store[key] = promoted_text
        assert baseline_tool.main(["restore", "prod", "victim-app", str(good)]) == 0
        assert json.loads(store[key]) == json.loads(old_text)
    run_env(go, ledger=Ledger())

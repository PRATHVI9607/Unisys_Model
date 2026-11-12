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
         "changed_fields": ["template.spec.containers[0].image"], "since_wall": 0.0}
    v.update(over)
    return v


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
        out = await env.agent._maybe_promote(key_of("dev"), env.agent.seen_hash[key_of("dev")], verdict())
        assert out == "failure_reasons"
        assert entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


def test_a_spec_equal_to_the_baseline_has_nothing_to_promote():
    async def go(env):
        await env.send("ADDED", dep(ns="dev"))
        out = await env.agent._maybe_promote(key_of("dev"), env.agent.seen_hash[key_of("dev")], verdict())
        assert out == "nothing_to_promote" and entries(env.agent.ledger) == []
    run_env(go, ledger=Ledger())


# ---- superseded specs ---------------------------------------------------------------------------------------
def test_a_superseded_spec_is_never_promoted():
    async def go(env):
        env.result = prediction(**BENIGN)
        await drift(env, "dev", assess=False, image="img:2", rolled_out=False)
        old_hash = env.agent.seen_hash[key_of("dev")]
        await env.send("MODIFIED", dep(ns="dev", image="img:3"))                  # a newer spec arrives
        assert await env.agent._maybe_promote(key_of("dev"), old_hash, verdict()) == "superseded"
        # an assessment of a different spec in flight also blocks (the current hash is the newest one)
        env.agent.assessing[key_of("dev")] = "some-other-hash"
        new_hash = env.agent.seen_hash[key_of("dev")]
        assert await env.agent._maybe_promote(key_of("dev"), new_hash, verdict()) == "superseded"
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
        assert (await bl.get_candidate(env.redis, "prod", "victim-app"))["status"] == "pending"
        # approval needs the ledger
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", None)
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
        assert (await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger,
                                           candidate_id="not-it"))["status"] == "id_mismatch"
        assert (await bl.approve_promotion(env.redis, "prod", "other", "alice", env.agent.ledger))["status"] == "not_found"
        with pytest.raises(ValueError):
            await bl.approve_promotion(env.redis, "prod", "victim-app", "  ", env.agent.ledger)
        assert await golden_image(env, "prod") == "img:1" and await bl.get_candidate(env.redis, "prod", "victim-app")
        assert cand["candidate_id"]
    run_env(go, ledger=Ledger())


def test_approval_with_a_failing_ledger_changes_nothing():
    async def go(env):
        await prod_candidate(env)
        before = await golden_text(env, "prod")
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", Ledger(FailingStore()))
        assert res["status"] == "ledger_failed"
        assert await golden_text(env, "prod") == before
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is not None
    run_env(go, ledger=Ledger())


def test_a_candidate_is_stale_when_the_golden_baseline_moved():
    async def go(env):
        await prod_candidate(env)
        env.redis.store[bl.baseline_key("prod", "victim-app")] = json.dumps(bl.make_record(dep(image="img:7")["spec"]))
        res = await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger)
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
        out = await env.agent._maybe_promote(key, env.agent.seen_hash[key], verdict())
        assert out == "candidate_rejected_before" and await bl.get_candidate(env.redis, *key) is None
        # a changed spec clears the remembered rejection and can get a new candidate
        await env.send("MODIFIED", dep(ns="prod", image="img:3"))
        await env.tick(60)
        assert (await bl.get_candidate(env.redis, *key))["spec"]["template"]["spec"]["containers"][0]["image"] == "img:3"
        assert bl.rejected_key(*key) not in env.redis.store
    run_env(go, ledger=Ledger())


def test_rejection_with_a_failing_ledger_keeps_the_candidate_pending():
    async def go(env):
        await prod_candidate(env)
        res = await bl.reject_promotion(env.redis, "prod", "victim-app", "bob", Ledger(FailingStore()))
        assert res["status"] == "ledger_failed"
        assert await bl.get_candidate(env.redis, "prod", "victim-app") is not None
        assert (await bl.reject_promotion(env.redis, "prod", "victim-app", "bob", None))["status"] == "no_ledger"
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
        out = await env.agent._maybe_promote(key, env.agent.seen_hash[key], verdict())
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
        await bl.approve_promotion(env.redis, "prod", "victim-app", "alice", env.agent.ledger)
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

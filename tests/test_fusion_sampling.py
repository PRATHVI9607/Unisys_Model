"""P6-D2: OBSERVE triples sampling for that pod for a bounded period (agents/common/sampling.py contract)."""
import json

from fusion_helpers import NOW_MS, ledger_steps, make_agent, run, sec_event
from agents.common import sampling
from agents.fusion_agent import agent as fusion
from agents.fusion_agent.config import FusionConfig

NOW = 1_000_000_000          # ms, only used as a number for the reader
OBSERVE_EV = dict(sec_risk="0.50", namespace_tier="staging")       # 0.50 x 1.00: the OBSERVE band


def observe(a, **kw):
    run(a._decide("prod:payments", None, sec_event(**{**OBSERVE_EV, **kw})))


async def aobserve(a, **kw):
    await a._decide("prod:payments", None, sec_event(**{**OBSERVE_EV, **kw}))


def test_observe_writes_a_request_for_the_pod_and_the_workload():
    a = make_agent()
    observe(a)
    assert set(a.redis.store) >= {"kubeheal:sampling:prod:workload:payments",
                                  "kubeheal:sampling:prod:pod:payments-abc-1"}
    data = json.loads(a.redis.store["kubeheal:sampling:prod:pod:payments-abc-1"])
    assert data["factor"] == 3 and data["requested_by"] == "fusion" and data["incident_id"].startswith("inc-")
    assert data["until_ms"] > 0
    step = next(r["payload"] for r in ledger_steps(a) if r["step"] == "observe_requested")
    assert step["factor"] == 3 and step["period_s"] == a.cfg.observe_period_s and len(step["keys"]) == 2


def test_the_factor_is_3_and_the_reader_triples_the_rate():
    async def go():
        a = make_agent()
        await aobserve(a)
        now_ms = int(a.redis.now * 1000)
        assert await sampling.sampling_factor(a.redis, "prod", "payments", "payments-abc-1", now_ms) == 3
        assert await sampling.sampling_factor(a.redis, "prod", "payments", None, now_ms) == 3
        assert await sampling.sampling_factor(a.redis, "prod", None, "payments-abc-1", now_ms) == 3
        assert await sampling.sampling_factor(a.redis, "prod", "other", "other-1", now_ms) == 1
        assert await sampling.sampling_factor(a.redis, "dev", "payments", "payments-abc-1", now_ms) == 1
        assert sampling.scaled_interval(30.0, 3) == 10.0 and sampling.scaled_interval(30.0, 1) == 30.0
    run(go())


def test_the_request_expires_after_the_bounded_period():
    async def go():
        a = make_agent(cfg=FusionConfig(observe_period_s=120))
        await aobserve(a)
        t = lambda: int(a.redis.now * 1000)  # noqa: E731
        assert await sampling.sampling_factor(a.redis, "prod", "payments", "payments-abc-1", t()) == 3
        a.redis.advance(119)
        assert await sampling.sampling_factor(a.redis, "prod", "payments", "payments-abc-1", t()) == 3
        a.redis.advance(2)                                   # the Redis TTL is the bound
        assert await sampling.sampling_factor(a.redis, "prod", "payments", "payments-abc-1", t()) == 1
    run(go())


def test_the_reader_also_checks_until_ms_when_the_key_stays_past_its_ttl():
    async def go():
        a = make_agent()
        await a.redis.set(sampling.pod_key("prod", "p"), json.dumps({"factor": 3, "until_ms": 5000}))
        assert await sampling.sampling_factor(a.redis, "prod", None, "p", now_ms=4999) == 3
        assert await sampling.sampling_factor(a.redis, "prod", None, "p", now_ms=5000) == 1
    run(go())


def test_a_repeated_observe_does_not_extend_the_period():
    async def go():
        a = make_agent(cfg=FusionConfig(observe_period_s=100))
        await aobserve(a)
        first = a.redis.store["kubeheal:sampling:prod:pod:payments-abc-1"]
        a.redis.advance(60)
        await aobserve(a, event_id="sec-2", pid_target="43")          # another OBSERVE while active
        assert a.redis.store["kubeheal:sampling:prod:pod:payments-abc-1"] == first
        step = [r["payload"] for r in ledger_steps(a) if r["step"] == "observe_requested"][-1]
        assert step["already_active"] is True
        a.redis.advance(41)                                    # 101 s after the first: expired
        await aobserve(a, event_id="sec-3", pid_target="44")
        assert a.redis.store["kubeheal:sampling:prod:pod:payments-abc-1"] != first
    run(go())


def test_other_decisions_do_not_request_more_sampling():
    a = make_agent()
    run(a._decide("prod:payments", None, sec_event(sec_risk="0.10")))
    run(a._decide("prod:payments", None, sec_event(event_id="s2", pid_target="2", sec_risk="0.70",
                                                   namespace_tier="staging")))
    assert not any(k.startswith(sampling.SAMPLING_PREFIX) for k in a.redis.store)


def test_observe_happens_in_test_mode_too():
    a = make_agent(enforce=False)
    observe(a)
    assert "kubeheal:sampling:prod:pod:payments-abc-1" in a.redis.store     # Sense/Score/Decide always run


def test_unreadable_or_garbage_request_means_factor_one():
    async def go():
        a = make_agent()
        await a.redis.set(sampling.workload_key("prod", "w"), "not json")
        assert await sampling.sampling_factor(a.redis, "prod", "w") == 1

        class Broken:
            async def get(self, k):
                raise RuntimeError("down")
        assert await sampling.sampling_factor(Broken(), "prod", "w") == 1
    run(go())


def test_the_contract_is_documented_in_the_module():
    doc = sampling.__doc__
    assert "kubeheal:sampling" in doc and "Health Agent" in doc and "Security Agent" in doc
    assert sampling.OBSERVE_FACTOR == 3

"""Property tests: stream contracts round-trip through Redis fields; HMACs reject every tampering."""

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agents.common import CONTAIN_SIGNED, approval_sign, approval_verify, contain_sign, contain_verify
from kubeheal.contracts import ActionEvent, Decision, Factor, HealthEvent, SecurityEvent

P = settings(max_examples=200, deadline=None, database=None)
txt = st.text(max_size=30)                       # any unicode: newlines, quotes, NULs
num = st.floats(-1e9, 1e9, allow_nan=False, allow_infinity=False)
risk = st.floats(0, 1)
ms = st.integers(0, 2**42)
factor = st.builds(Factor, feature=txt, value=st.none() | num, contribution=num)
common = dict(
    event_id=txt, namespace=txt, workload=txt, pod=txt, timestamp_ms=ms, model_version=txt, label=txt, risk=risk,
    uncertain=st.booleans(), probabilities=st.dictionaries(txt, risk, max_size=4), top_factors=st.lists(factor, max_size=3),
    features=st.dictionaries(txt, st.none() | num, max_size=5))
health = st.builds(HealthEvent, **common, spec_changed=st.booleans(), changed_fields=st.lists(txt, max_size=4),
                   has_baseline=st.booleans(), failure_reasons=st.lists(txt, max_size=3))
security = st.builds(SecurityEvent, **common, pod_uid=txt, window_start_ms=ms, window_end_ms=ms, n_events=st.integers(0, 10**6))
action = st.builds(ActionEvent, event_id=txt, namespace=txt, workload=txt, pod=txt, decision=st.sampled_from(Decision),
                   mode=st.sampled_from(["observe", "enforce"]), outcome=txt, score=risk, compound_score=risk, rationale=txt,
                   summary=txt, health_event_id=txt, security_event_id=txt, containment=txt, approved_by=txt, timestamp_ms=ms)


@P
@given(st.one_of(health, security, action))
def test_event_fields_roundtrip(ev):
    f = ev.to_fields()
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in f.items())
    assert type(ev).from_fields(f) == ev
    assert type(ev).from_fields({k.encode(): v.encode() for k, v in f.items()}) == ev   # redis without decode_responses


@P
@given(health, st.dictionaries(st.sampled_from(["risk", "timestamp_ms", "label", "features", "top_factors", "spec_changed"]),
                               st.text(max_size=12), max_size=3))
def test_from_fields_with_garbage_values_raises_only_validation_errors(ev, bad):
    f = ev.to_fields() | bad
    try:
        HealthEvent.from_fields(f)
    except ValueError:   # pydantic ValidationError and json.JSONDecodeError are both ValueErrors
        pass


# ── HMAC ─────────────────────────────────────────────────────────────────────────────────────────
key = st.text(min_size=1, max_size=40)
no_pipe = st.text(alphabet=st.characters(blacklist_characters="|", blacklist_categories=("Cs",)), max_size=20)
contain = st.fixed_dictionaries({f: no_pipe for f in CONTAIN_SIGNED})


@P
@given(key, contain)
def test_contain_roundtrip_and_any_signed_field_change_fails(k, c):
    c = {**c, "sig": contain_sign(k, c)}
    assert contain_verify(k, c)
    assert not contain_verify(k + "x", c)
    for f in CONTAIN_SIGNED:
        assert not contain_verify(k, {**c, f: c[f] + "x"})
        assert not contain_verify(k, {**c, f: "x" + c[f]})
    assert contain_verify(k, {**c, "extra": "unsigned"})   # unsigned fields are not covered, by design


@P
@given(key, contain, st.text(max_size=80) | st.integers() | st.none() | st.binary(max_size=10))
def test_contain_verify_never_raises_on_hostile_sig(k, c, sig):
    assert contain_verify(k, {**c, "sig": sig}) is False or sig == contain_sign(k, c)
    c.pop("pod", None)
    assert contain_verify(k, c) is False    # missing field


def test_contain_verify_non_ascii_signature_and_surrogates():
    c = dict.fromkeys(CONTAIN_SIGNED, "a")
    assert contain_verify("k", {**c, "sig": "é" * 64}) is False
    assert contain_verify("k", {**c, "pod": "\ud800", "sig": "00"}) is False
    assert contain_verify("k", {}) is False


@pytest.mark.xfail(strict=True, reason="BUG agents/common.py contain_sign: fields are joined with '|' without escaping, so "
                   "(namespace='a|b', pod='c') and (namespace='a', pod='b|c') sign identically. Not reachable with DNS-label names")
def test_contain_sign_is_unambiguous_for_pipes():
    base = {"pod_uid": "u", "event_id": "e", "ts_ms": "1"}
    assert contain_sign("k", {**base, "namespace": "a|b", "pod": "c"}) != contain_sign("k", {**base, "namespace": "a", "pod": "b|c"})


scalar = st.text(max_size=12) | st.integers(-10**6, 10**6) | st.booleans() | st.none()
rec = st.dictionaries(st.text(min_size=1, max_size=8).filter(lambda s: s not in ("sig", "requested")),
                      scalar | st.lists(scalar, max_size=3) | st.dictionaries(st.text(max_size=4), scalar, max_size=3),
                      min_size=1, max_size=6)


@P
@given(key, rec, st.data())
def test_approval_roundtrip_and_any_field_change_fails(k, r, data):
    signed = {**r, "sig": approval_sign(k, r)}
    assert approval_verify(k, signed)
    assert approval_verify(k, {**signed, "requested": {"decision": "approve", "actor": "x"}})   # dashboard-owned, unsigned
    assert not approval_verify(k + "x", signed)
    name = data.draw(st.sampled_from(sorted(r)))
    other = data.draw(scalar | st.lists(scalar, max_size=2))
    tampered = {**signed, name: other}
    if tampered[name] != r[name] or type(tampered[name]) is not type(r[name]):
        # json.dumps differs unless the values are equal as JSON (1 vs True differ too)
        if json.dumps(other) != json.dumps(r[name]):
            assert not approval_verify(k, tampered)
    assert not approval_verify(k, {**signed, "injected": 1})
    assert not approval_verify(k, {kk: v for kk, v in signed.items() if kk != name})


@P
@given(key, rec, st.text(max_size=70) | st.integers() | st.none() | st.lists(st.integers(), max_size=2))
def test_approval_verify_never_raises_on_hostile_sig(k, r, sig):
    approval_verify(k, {**r, "sig": sig})
    assert approval_verify(k, {**r, "sig": "ü" * 64}) is False


def test_approval_verify_unserialisable_record_is_false():
    assert approval_verify("k", {"a": object(), "sig": "x"}) is False
    assert approval_verify("k", {1: "a", "b": 2, "sig": "x"}) is False   # mixed-type keys cannot be sorted

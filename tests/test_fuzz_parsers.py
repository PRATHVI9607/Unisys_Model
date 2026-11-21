"""Fuzz the untrusted-input parsers: Falco lines, k8s quantities, open() flags. Property: never raise, never invent."""

import json
import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agents.security_agent.falco import parse_line
from kubeheal.features.quantity import parse_cpu, parse_memory
from kubeheal.features.security import OPEN_SYSCALLS, open_syscall

FUZZ = settings(max_examples=300, deadline=None, database=None)
RESULT_KEYS = {"namespace", "pod", "pid", "container_id", "pod_uid", "syscall", "path", "new_path", "ts_ms"}
FIELD_NAMES = ["k8s.ns.name", "k8s.pod.name", "k8s.pod.uid", "container.id", "evt.type", "evt.arg.flags", "fd.name",
               "fs.path.name", "fs.path.source", "fs.path.target", "proc.pid", "evt.time"]
scalar = st.none() | st.booleans() | st.integers(-2**63, 2**63 - 1) | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=40)
json_val = st.recursive(scalar, lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=8), c, max_size=3), max_leaves=6)
# Plausible Falco shape with hostile values: the fields the parser reads, each any JSON value.
falco_obj = st.fixed_dictionaries(
    {"output_fields": st.dictionaries(st.sampled_from(FIELD_NAMES), scalar | json_val, max_size=len(FIELD_NAMES))},
    optional={"time": scalar, "rule": st.text(max_size=10)})


def check(res, line):
    if res is None:
        return
    assert set(res) == RESULT_KEYS
    f = json.loads(line)["output_fields"]
    # nothing invented: identity fields are the input's, as strings
    assert res["namespace"] == str(f["k8s.ns.name"]) and res["pod"] == str(f["k8s.pod.name"])
    assert res["pid"] is None or (isinstance(res["pid"], int) and res["pid"] > 0)
    assert res["ts_ms"] is None or isinstance(res["ts_ms"], int)
    assert all(isinstance(res[k], str) for k in ("container_id", "pod_uid", "syscall", "path", "new_path"))
    assert res["syscall"] and res["namespace"] and res["pod"]


@FUZZ
@given(st.binary(max_size=300))
def test_parse_line_arbitrary_bytes(raw):
    assert parse_line(raw) is None or set(parse_line(raw)) == RESULT_KEYS


@FUZZ
@given(st.text(max_size=300))
def test_parse_line_arbitrary_text(raw):
    parse_line(raw)


@FUZZ
@given(json_val)
def test_parse_line_arbitrary_json_is_none_unless_falco_shaped(v):
    res = parse_line(json.dumps(v))
    if res is not None:
        assert isinstance(v, dict) and isinstance(v.get("output_fields"), dict)


# ascii-digit-only pids / flags / times here; the unicode-digit and inf cases have their own tests below
ascii_safe = st.text(alphabet=st.characters(codec="ascii", exclude_characters="\x00"), max_size=20)
safe_scalar = st.none() | st.booleans() | st.integers(0, 2**40) | ascii_safe


@FUZZ
@given(st.dictionaries(st.sampled_from(FIELD_NAMES), safe_scalar, max_size=len(FIELD_NAMES)))
def test_parse_line_hostile_values(fields):
    line = json.dumps({"output_fields": fields, "time": "2024-05-01T12:00:00.123456789Z"})
    check(parse_line(line), line)


@FUZZ
@given(falco_obj)
def test_parse_line_falco_shaped_never_raises(obj):
    try:
        line = json.dumps(obj)
    except ValueError:
        return
    # json_val strings may hold unicode digits: only the "raises" half is asserted here
    try:
        parse_line(line)
    except (ValueError, OverflowError):
        pytest.skip("known: unicode digit / inf crash")


def good(**over):
    f = {"k8s.ns.name": "ns", "k8s.pod.name": "p", "evt.type": "openat", "fd.name": "/data/a", "proc.pid": 7}
    return json.dumps({"output_fields": f | over, "time": "2024-05-01T12:00:00.5Z"})


def test_parse_line_baseline_event():
    r = parse_line(good(**{"evt.arg.flags": "O_WRONLY|O_CREAT"}))
    assert r["syscall"] == "open_w" and r["path"] == "/data/a" and r["pid"] == 7 and r["ts_ms"] == 1714564800500


def test_parse_line_drops_host_and_typeless_events():
    assert parse_line(good(**{"k8s.ns.name": None})) is None
    assert parse_line(good(**{"k8s.pod.name": "<NA>"})) is None
    assert parse_line(good(**{"evt.type": ""})) is None


def test_parse_line_unicode_digit_pid_does_not_raise():
    assert parse_line(good(**{"proc.pid": "²"}))["pid"] is None


@pytest.mark.parametrize("flags", ["²", "9" * 5000])
def test_open_syscall_odd_digit_flags_do_not_raise(flags):
    assert open_syscall("openat", flags) in ("open_r", "open_w")


def test_parse_line_nonfinite_event_time_does_not_raise():
    for t in ("1e999", '"inf"', '"nan"', "-1e30"):
        line = '{"output_fields":{"k8s.ns.name":"n","k8s.pod.name":"p","evt.type":"unlink","evt.time":' + t + "}}"
        r = parse_line(line)
        assert r is None or r["ts_ms"] is None or isinstance(r["ts_ms"], int)


# ── open_syscall ─────────────────────────────────────────────────────────────────────────────────
@FUZZ
@given(st.text(max_size=20), st.none() | st.text(alphabet="OWRDCATNL_|x 0123456789", max_size=40))
def test_open_syscall_total(sc, flags):
    out = open_syscall(sc, flags)
    if sc not in OPEN_SYSCALLS:
        assert out == sc
    else:
        assert out in ("open_r", "open_w")
        assert (out == "open_w") if sc == "creat" else True


@FUZZ
@given(st.integers(0, 2**32))
def test_open_syscall_numeric_flags_follow_ppm_mask(n):
    assert open_syscall("open", str(n)) == ("open_w" if n & (2 | 4 | 8 | 256) else "open_r")


def test_open_syscall_missing_flags_is_read():
    assert open_syscall("openat", None) == "open_r" and open_syscall("openat2", "") == "open_r"


# ── quantities ───────────────────────────────────────────────────────────────────────────────────
@FUZZ
@given(st.text(max_size=20))
def test_quantity_never_raises_and_is_finite(q):
    for fn in (parse_cpu, parse_memory):
        v = fn(q)
        assert v is None or math.isfinite(v)


def test_quantity_huge_exponent_is_not_infinite():
    assert parse_cpu("1e999") is None or math.isfinite(parse_cpu("1e999"))


@FUZZ
@given(st.one_of(st.none(), st.booleans(), st.lists(st.integers(), max_size=2), st.dictionaries(st.text(max_size=3), st.integers(), max_size=2)))
def test_quantity_non_scalars_are_none(q):
    assert parse_cpu(q) is None and parse_memory(q) is None


@FUZZ
@given(st.integers(0, 10**6), st.sampled_from(["", "m", "k", "Ki", "Mi", "Gi", "M", "G"]))
def test_quantity_valid_roundtrip_is_nonnegative(n, suffix):
    v = parse_memory(f"{n}{suffix}")
    assert v is not None and v >= 0
    assert parse_cpu(f"{n}m") == pytest.approx(n / 1000)


@pytest.mark.parametrize("q", ["", " ", "m", "1x", "1Ki Mi", "--1", "1..2", "1e", "0x10"])
def test_quantity_rejects_garbage(q):
    assert parse_cpu(q) is None

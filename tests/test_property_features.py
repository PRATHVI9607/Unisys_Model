"""Property tests for the shared feature code: security windows, canonical specs, spec hashing and diffing."""

import math

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from kubeheal.features.health import canonical_spec, changed_paths, spec_hash
from kubeheal.features.security import (
    RECENT_EVENTS,
    RECENT_FEATURES,
    SECURITY_FEATURES,
    SYSCALL_GROUPS,
    recent_features,
    security_features,
)

P = settings(max_examples=200, deadline=None, database=None)
SYSCALLS = sorted({s for g in SYSCALL_GROUPS.values() for s in g} | {"open_r", "open_w", "futex", "", "weird☃"})
PATHS = st.sampled_from(["/data/a.txt", "/data/b.txt", "/data/a.txt.locked", "/data/sub/c.db", "/data/.tmp123",
                         "/data/README_decrypt.txt", "/data/x.log.1", "/data/x.log.2.gz", "/", "", "no-slash", "/d/é.enc"])
event = st.fixed_dictionaries(
    {"syscall": st.sampled_from(SYSCALLS)},
    optional={"path": PATHS | st.none(), "new_path": PATHS | st.none(), "ts_ms": st.integers(0, 2**41) | st.none()})
events = st.lists(event, max_size=120)
entropy = st.lists(st.none() | st.floats(0, 8) | st.just(float("nan")) | st.just(float("inf")), max_size=12)
WIN = st.floats(5.0, 60.0)
FRACS = [f for f in SECURITY_FEATURES if "frac" in f or f.endswith("_ratio")]


def finite_or_none(f):
    assert list(f) == SECURITY_FEATURES
    for k, v in f.items():
        assert v is None or (isinstance(v, float) and math.isfinite(v)), (k, v)


@P
@given(events, entropy, WIN)
def test_security_features_total_finite_and_sane(evs, ent, win):
    f = security_features(evs, ent, win)
    finite_or_none(f)
    assert f["n_events"] == len(evs)
    for k in FRACS:
        assert f[k] is None or 0.0 <= f[k] <= 1.0, (k, f[k])
    assert f["unique_dirs"] <= f["unique_paths"] <= 2 * len(evs)
    assert f["ransom_note"] in (0.0, 1.0)
    assert f["n_entropy_samples"] <= len(ent)
    if f["entropy_mean"] is not None:
        assert 0 <= f["entropy_mean"] <= 8 and f["entropy_max"] >= f["entropy_mean"] - 1e-9
    assert f["n_files_transformed"] <= len(evs)
    if evs:
        assert f["events_per_s"] == pytest.approx(len(evs) / win)


@P
@given(events, entropy)
def test_security_features_none_never_zero(evs, ent):
    # unknown stays None: no window length, no byte counters, no entropy samples, no events
    f = security_features(evs, [], 0.0)
    assert f["events_per_s"] is None and f["files_written_per_s"] is None
    assert f["write_bytes_per_s"] is None and f["net_out_bytes_per_s"] is None
    assert f["entropy_mean"] is None and f["entropy_slope"] is None and f["recent_entropy_mean"] is None
    g = security_features(evs, ent, 30.0, bytes_written=None, net_bytes_out=None)
    assert g["write_bytes_per_s"] is None and g["net_out_bytes_per_s"] is None
    if not evs:
        assert all(g[k] is None for k in FRACS if k.startswith("frac_") or k.startswith("recent_frac_"))
        assert g["recent_unique_files"] is None and g["recent_events_per_s"] is None


@P
@given(events, st.floats(5, 60), st.floats(0, 1e12), st.floats(0, 1e12))
def test_byte_rates_scale_with_window(evs, win, w, n):
    f = security_features(evs, [], win, bytes_written=w, net_bytes_out=n)
    assert f["write_bytes_per_s"] == pytest.approx(w / win) and f["net_out_bytes_per_s"] == pytest.approx(n / win)


# Features that are counts / sets over the window, so they must not depend on the order of events that happened
# at the same instant (ordering-sensitive ones: rename kinds, transforms, rename-from-read tracking).
UNORDERED = ["n_events", "events_per_s", "unique_paths", "unique_dirs", "files_written_per_s", "suspicious_ext_ratio",
             "ransom_note", "frac_read", "frac_write", "frac_open", "frac_rename", "frac_unlink", "frac_truncate",
             "frac_network", "frac_mmap", "frac_exec", "frac_chmod", "recent_frac_write", "recent_frac_rename",
             "recent_frac_unlink", "recent_frac_chmod", "recent_unique_files", "recent_events_per_s"]


@P
@given(st.lists(event, max_size=RECENT_EVENTS), st.integers(0, 2**41), st.randoms(use_true_random=False))
def test_identical_timestamp_permutation_keeps_unordered_features(evs, ts, rnd):
    same = [{**e, "ts_ms": ts} for e in evs]
    shuffled = same[:]
    rnd.shuffle(shuffled)
    a, b = security_features(same, [], 30.0), security_features(shuffled, [], 30.0)
    assert {k: a[k] for k in UNORDERED} == {k: b[k] for k in UNORDERED}


@P
@given(events, entropy)
def test_recent_features_cover_only_the_tail(evs, ent):
    r = recent_features(evs, ent)
    assert list(r) == RECENT_FEATURES and all(v is None or math.isfinite(v) for v in r.values())
    if len(evs) > RECENT_EVENTS:   # old events cannot change tail counts
        r2 = recent_features(evs[-RECENT_EVENTS:], ent)
        for k in ("recent_frac_write", "recent_frac_rename", "recent_frac_unlink", "recent_frac_chmod", "recent_unique_files"):
            assert r[k] == r2[k]


# ── canonical spec / hash / diff ─────────────────────────────────────────────────────────────────
# camelCase keys only: that is what the API returns. Snake_case keys can collide after camel-casing.
KEY = st.from_regex(r"[a-z][a-zA-Z0-9]{0,6}", fullmatch=True)
LEAF = st.text(max_size=8) | st.integers(2, 10**6)
EMPTY = st.sampled_from([None, {}, []])
spec_val = st.recursive(LEAF | EMPTY, lambda c: st.lists(c, max_size=3) | st.dictionaries(KEY, c, max_size=4), max_leaves=12)
spec = st.dictionaries(KEY, spec_val, max_size=5).map(lambda d: {"template": {"spec": {"containers": [d]}}})


def shuffle_keys(v, rnd):
    if isinstance(v, dict):
        items = list(v.items())
        rnd.shuffle(items)
        return {k: shuffle_keys(x, rnd) for k, x in items}
    return [shuffle_keys(x, rnd) for x in v] if isinstance(v, list) else v


@P
@given(spec, st.randoms(use_true_random=False))
def test_spec_hash_stable_under_key_order(s, rnd):
    t = shuffle_keys(s, rnd)
    assert spec_hash(s) == spec_hash(t) and canonical_spec(s) == canonical_spec(t)


def has_empty(v):
    if isinstance(v, dict):
        return any(x is None or x in ({}, []) or has_empty(x) for x in v.values())
    return isinstance(v, list) and any(x is None or x in ({}, []) or has_empty(x) for x in v)


@P
@given(spec)
def test_canonical_spec_idempotent_and_drops_empties(s):
    c = canonical_spec(s)
    assert canonical_spec(c) == c
    assert not has_empty(c)
    assert spec_hash(c) == spec_hash(s)


@P
@given(spec, spec)
def test_changed_paths_empty_iff_hash_equal(a, b):
    assert (changed_paths(canonical_spec(a), canonical_spec(b)) == []) == (spec_hash(a) == spec_hash(b))
    assert changed_paths(canonical_spec(a), canonical_spec(a)) == []


@P
@given(spec, spec, st.integers(1, 10))
def test_changed_paths_respects_limit_and_is_symmetric_in_emptiness(a, b, limit):
    ca, cb = canonical_spec(a), canonical_spec(b)
    assert len(changed_paths(ca, cb, limit)) <= limit
    assert bool(changed_paths(ca, cb)) == bool(changed_paths(cb, ca))


@P
@given(spec, KEY, EMPTY)
def test_adding_empty_values_does_not_change_hash(s, k, empty):
    if k not in s:
        assert spec_hash({**s, k: empty}) == spec_hash(s)


def test_spec_hash_accepts_deployment_wrapper_and_spec_alike():
    inner = {"template": {"spec": {"containers": [{"name": "a", "image": "x:1"}]}}, "replicas": 2}
    assert spec_hash(inner) == spec_hash({"spec": inner})


def test_spec_hash_stable_when_snake_and_camel_keys_collide():
    a = {"template": {"x_y": 1, "xY": 2}}
    b = {"template": {"xY": 2, "x_y": 1}}
    assert spec_hash(a) == spec_hash(b)


def test_hash_changes_on_any_leaf_change():
    base = {"template": {"spec": {"containers": [{"name": "a", "image": "x:1", "resources": {"limits": {"cpu": "1"}}}]}}}
    h = spec_hash(base)
    for path_val in ("x:2", "y:1", ""):
        mod = {"template": {"spec": {"containers": [{"name": "a", "image": path_val, "resources": {"limits": {"cpu": "1"}}}]}}}
        assert (spec_hash(mod) == h) is (path_val == "x:1")

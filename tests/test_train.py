import json
from types import SimpleNamespace

import lightgbm as lgb
import numpy as np

from kubeheal.features.health import HEALTH_FEATURES
from training import train
from training.train import missing_dropout


def test_missing_dropout_blanks_each_group_and_keeps_labels():
    x = np.ones((10, len(HEALTH_FEATURES)))
    y = np.arange(10) % 3
    g = np.array([f"g{i}" for i in range(10)])
    x2, y2, g2, f2, counts = missing_dropout(x, y, g, np.full(10, "fam"), HEALTH_FEATURES, seed=1)
    assert counts == dict.fromkeys(train.MISSING_GROUPS, 10) and len(x2) == len(y2) == len(g2) == len(f2) == 40
    assert (x2[:10] == 1).all()
    for i, feats in enumerate(train.MISSING_GROUPS.values()):
        copies, cols = x2[10 * (i + 1):10 * (i + 2)], [HEALTH_FEATURES.index(f) for f in feats]
        assert np.isnan(copies[:, cols]).all() and not np.isnan(np.delete(copies, cols, axis=1)).any()
    assert (y2[10:] == np.tile(y, 3)).all() and (g2[10:] == np.tile(g, 3)).all() and (f2 == "fam").all()   # stays with its run


def test_missing_dropout_tolerates_dropped_features():
    names = [f for f in HEALTH_FEATURES if f not in ("latency_trend", "cpu_limit_ratio")]
    x2 = missing_dropout(np.ones((4, len(names))), np.zeros(4, int), np.arange(4), np.full(4, ""), names, seed=1)[0]
    assert x2.shape == (16, len(names))


def test_heldout_family_tests_real_rows_only():
    rng = np.random.default_rng(0)
    x = rng.normal(size=(60, 2))
    y = np.arange(60) % 2
    fam = np.array(["a", "b"] * 30)
    x2, y2, f2 = np.vstack([x, x]), np.concatenate([y, y]), np.concatenate([fam, fam])   # copies inherit the family
    orig = np.arange(120) < 60
    out = train.heldout_families(x2, y2, f2, ["m0", "m1"], ["l0", "l1"], 1, 5, orig)
    assert {k: v["n"] for k, v in out["per_family"].items()} == {"a": 30, "b": 30}   # copies are not tested on


def test_heldout_family_holds_out_every_row_involving_it():
    rng = np.random.default_rng(0)
    x = rng.normal(size=(90, 2))
    y = np.arange(90) % 2
    fam = np.array(["a", "b", "a|b"] * 30)    # a|b = a combined change or a revert touching both families
    out = train.heldout_families(x, y, fam, ["m0", "m1"], ["l0", "l1"], 1, 5, np.ones(90, bool))
    assert {k: v["n"] for k, v in out["per_family"].items()} == {"a": 30, "b": 30}   # tested: only-that-family rows


def test_gate_floors_ceilings_and_regression():
    report = {"cv": {"macro_f1": 0.9, "false_kill_rate": 0.04}}
    gates = {"cv.macro_f1": (">=", 0.8), "cv.false_kill_rate": ("<=", 0.05), "missing.x": (">=", 0.1)}
    out, fails = train.gate(report, gates, {"cv": {"macro_f1": 0.95, "false_kill_rate": 0.0}}, 0.02, False)
    assert out["cv.macro_f1"] == {"value": 0.9, "op": ">=", "threshold": 0.8, "baseline": 0.95}
    assert len(fails) == 3 and "missing.x = None" in fails[2] and all("regressed" in f for f in fails[:2])
    assert len(train.gate(report, gates, None, 0.02, False)[1]) == 1                  # no baseline: thresholds only
    assert train.gate(report, {"cv.macro_f1": (">=", 0.8)}, {"cv": {"macro_f1": 0.95}}, 0.02, True)[1] == []


def test_new_only_with_legacy_does_not_keyerror(monkeypatch):
    from kubeheal.features.health import HEALTH_FEATURES
    from training.datasets import collected

    feats = dict.fromkeys(HEALTH_FEATURES)
    recs = [{"features": feats, "label": "benign", "group": "lab:a", "family": "f", "assess_delay_s": 5},
            {"features": feats, "label": "benign", "group": "legacy:b", "family": ""}]   # legacy rows lack the key
    monkeypatch.setattr(collected, "health_rows", lambda path: (recs, {"sources": {}, "synthetic": False}))
    args = SimpleNamespace(collected=True, with_legacy=True, new_only=True, data="x", n_scenarios=0, seed=1, drop_features=[])
    assert train.load("health", args)[4]["rows"] == 1


def test_synth_db_one_open_per_file_and_no_invisible_entropy():
    from collections import Counter

    from training.synth_security import generate

    recs = generate(600, seed=3)
    for r in recs:
        if r["scenario"] == "db_workload":
            c = Counter((e["syscall"], e["path"]) for e in r["events"])
            assert max(c.values()) == 1
        if r["scenario"] in ("recon", "maintenance_script"):   # their only write is the /tmp drop, outside the root
            assert r["entropy"] == []
    assert {"db_workload", "recon", "maintenance_script"} <= {r["scenario"] for r in recs}


def _compact_run(monkeypatch, tmp_path, gate_floor):
    """Run `main --compact --task security` on a tiny separable dataset and a 2-candidate grid."""
    from kubeheal.contracts import SECURITY_LABELS
    from kubeheal.features.security import SECURITY_FEATURES

    rng = np.random.default_rng(0)
    n, k = 400, len(SECURITY_LABELS)
    y = np.arange(n) % k
    x = rng.normal(size=(n, len(SECURITY_FEATURES)))
    x[np.arange(n), y] += 6.0                                  # class c separable on feature c
    groups = np.array([f"lab:g{i // 4}" for i in range(n)])
    data = {"rows": n, "groups": n // 4, "sha256": "0" * 64, "synthetic": False}
    monkeypatch.setattr(train, "load", lambda task, args: (x, y, groups, np.array([f"f{(i // 4) % 3}" for i in range(n)]), data))
    monkeypatch.setattr(train, "COMPACT_GRID", [{"num_leaves": 31, "min_data_in_leaf": 5, "learning_rate": 0.05},
                                                 {"num_leaves": 7, "min_data_in_leaf": 5, "learning_rate": 0.3}])
    monkeypatch.setattr(train, "LIVE_NONE", {"security": []})
    monkeypatch.setattr(train, "ROOT", tmp_path)
    gates = [f"{p}={v}" for p, v in [("cv5_grouped.macro_f1", gate_floor), ("cv5_grouped_lab.per_class.ransomware.recall", 0.0),
                                     ("cv5_grouped_lab.false_kill_rate", 1.0), ("heldout_family.pooled.per_class.ransomware.recall", 0.0)]]
    argv = ["--task", "security", "--compact", "--out", str(tmp_path / "out"), "--n-scenarios", "0",
            *[a for g in gates for a in ("--gate", g)]]
    return train.main(argv), tmp_path / "out"


def test_compact_writes_smallest_passing_candidate_and_records_table(monkeypatch, tmp_path):
    rc, out = _compact_run(monkeypatch, tmp_path, 0.5)
    meta = json.loads((out / "meta.json").read_text())
    c = meta["metrics"]["compact"]
    assert rc == 0 and len(c["candidates"]) == 2 and all(r["gates_pass"] for r in c["candidates"])
    fastest = min(c["candidates"], key=lambda r: (round(r["predict_explain_ms"], 2), -r["macro_f1"]))
    assert c["candidates"][c["chosen"]] == fastest
    assert lgb.Booster(model_file=str(out / "model.txt")).num_trees() == fastest["trees"]


def test_compact_gate_failure_writes_nothing(monkeypatch, tmp_path):
    rc, out = _compact_run(monkeypatch, tmp_path, 1.01)   # unreachable floor: no candidate passes
    assert rc == 1 and not out.exists()

from types import SimpleNamespace

import numpy as np

from kubeheal.features.health import HEALTH_FEATURES, METRIC_FEATURES
from training import train
from training.train import metric_dropout


def test_metric_dropout_blanks_only_metrics_and_keeps_labels():
    x = np.ones((10, len(HEALTH_FEATURES)))
    y = np.arange(10) % 3
    g = np.array([f"g{i}" for i in range(10)])
    x2, y2, g2, f2 = metric_dropout(x, y, g, np.full(10, "fam"), HEALTH_FEATURES, seed=1)
    assert len(x2) == len(y2) == len(g2) == len(f2) == 20 and (x2[:10] == 1).all()
    cols = [HEALTH_FEATURES.index(f) for f in METRIC_FEATURES]
    copies = x2[10:]
    assert np.isnan(copies[:, cols]).all() and not np.isnan(np.delete(copies, cols, axis=1)).any()
    assert (y2[10:] == y).all() and (g2[10:] == g).all() and (f2[10:] == "fam").all()   # copy stays with its source run and family


def test_heldout_family_tests_real_rows_only():
    rng = np.random.default_rng(0)
    x = rng.normal(size=(60, 2))
    y = np.arange(60) % 2
    fam = np.array(["a", "b"] * 30)
    x2, y2, f2 = np.vstack([x, x]), np.concatenate([y, y]), np.concatenate([fam, fam])   # copies inherit the family
    orig = np.arange(120) < 60
    out = train.heldout_families(x2, y2, f2, ["m0", "m1"], ["l0", "l1"], 1, 5, orig)
    assert {k: v["n"] for k, v in out["per_family"].items()} == {"a": 30, "b": 30}   # copies are not tested on


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

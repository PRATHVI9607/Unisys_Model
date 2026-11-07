"""Collected lab data → training rows, and train.py --collected end to end on a tiny fake lab set."""

import json
import random

import pytest

from kubeheal.contracts import HEALTH_LABELS
from kubeheal.features.health import HEALTH_FEATURES
from kubeheal.ml.bundle import ModelBundle
from training import train
from training.datasets import collected


def fake_health(path, n=120):
    r = random.Random(0)
    with open(path, "w") as fh:
        for i in range(n):
            label = HEALTH_LABELS[i % 3]
            feats = {f: r.random() for f in HEALTH_FEATURES} | {"spec_changed": 1.0, "ready_ratio": [1, 0.8, 0.1][i % 3]}
            fh.write(json.dumps({"group": f"run{i % 40}", "family": f"fam{i % 4}", "label": label,
                                 "features": feats, "label_reasons": []}) + "\n")
        fh.write('{"torn')                          # collector killed mid-line


def test_security_family_splits_detection_variants():
    det = {"scenario": "detection_test", "params": {"rename": False, "partial": 0.5}}
    assert collected.family("security", det) == "detection_test:inplace_partial"
    assert collected.family("security", {"scenario": "log_rotation"}) == "log_rotation"


def test_security_rows_take_only_unobservable_classes_from_synthetic(tmp_path, monkeypatch):
    monkeypatch.setattr(collected, "COLLECTED", tmp_path)
    (tmp_path / "security.jsonl").write_text(json.dumps(
        {"group": "sec-x", "scenario": "log_rotation", "label": "benign",
         "features": {"n_events": 3, "write_bytes_per_s": 0.0}}) + "\n")
    rows, meta = collected.security_rows(60, 1)
    assert {r["label"] for r in rows if r["source"] == "synthetic"} <= set(collected.SYNTH_ONLY)
    assert {r["label"] for r in rows if r["source"] == "synthetic_hard_negative"} == {"benign"}
    assert meta["class_source"]["benign"] == ["lab", "synthetic_hard_negative"]
    assert meta["class_source"]["exfiltration"] == ["synthetic"]
    assert meta["synthetic_fraction_by_class"]["exfiltration"] == 1.0 and 0 < meta["synthetic_fraction_by_class"]["benign"] < 1


def test_train_collected_health_reports_heldout_families(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(collected, "COLLECTED", tmp_path)
    fake_health(tmp_path / "health.jsonl")
    out = tmp_path / "bundle"
    assert train.main(["--task", "health", "--collected", "--min-macro-f1", "0", "--out", str(out)]) == 0
    meta = ModelBundle.load(out).meta
    assert meta["data"]["rows"] == 120 and meta["data"]["legacy_csv"] is False
    held = meta["metrics"]["heldout_family"]
    assert set(held["per_family"]) == {"fam0", "fam1", "fam2", "fam3"} and held["pooled"]["n"] == 120


def test_train_collected_rejects_stale_feature_names(tmp_path, monkeypatch):
    monkeypatch.setattr(collected, "COLLECTED", tmp_path)
    (tmp_path / "health.jsonl").write_text(json.dumps(
        {"group": "g", "family": "f", "label": "benign", "features": {"old_name": 1.0}}) + "\n")
    with pytest.raises(ValueError, match="old_name"):
        train.main(["--task", "health", "--collected"])


def test_security_rows_refuse_pre_telemetry_data(tmp_path, monkeypatch):
    monkeypatch.setattr(collected, "COLLECTED", tmp_path)
    (tmp_path / "security.jsonl").write_text(json.dumps(
        {"group": "g", "scenario": "log_rotation", "label": "benign", "features": {"write_bytes_per_s": None}}) + "\n")
    with pytest.raises(ValueError, match="byte telemetry"):
        collected.security_rows(60, 1)


def test_relabel_health_uses_robust_pre_p99():
    def rec(pre, p99, label="benign", revert=False, run="r1"):
        return {"run_id": run, "slot": "lab-00", "revert": revert, "pre_p99_s": pre, "label": label,
                "label_reasons": [], "features": {"latency_p99_mean_s": p99}}

    recs = [rec(0.005, 0.005), rec(0.005, 0.005), rec(None, 0.005),
            rec(0.05, 0.03),                        # inflated pre hid a 6x slowdown
            rec(0.005, 0.03, "critical"),           # never touched
            rec(0.2, 0.03, revert=True),            # revert: its own pre (the changed spec) is the right baseline
            rec(0.005, 0.012)]                      # 2.4x but only +7 ms: below P99_MIN_DELTA_S
    assert collected.relabel_health(recs) == 1
    assert [r["label"] for r in recs] == ["benign"] * 3 + ["degradation", "critical", "benign", "benign"]
    assert recs[3]["relabeled"] == collected.ROBUST_P99 and recs[3]["label_reasons"] == [collected.ROBUST_P99]
    assert recs[3]["robust_pre_p99_s"] == 0.005
    assert collected.relabel_health(recs) == 0      # idempotent: export → reload does not double count

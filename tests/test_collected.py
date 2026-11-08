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
            if i % 10 == 0:
                feats["replicas_ratio"] = None      # scaled up from 0 replicas, as in the lab's replicas_zero reverts
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
    rows, meta = collected.security_rows(150, 1)
    assert {r["label"] for r in rows if r["source"] == "synthetic"} <= set(collected.SYNTH_ONLY)
    assert {r["label"] for r in rows if r["source"] == "synthetic_hard_negative"} == {"benign"}
    assert {r["label"] for r in rows if r["source"] == "synthetic_hard_positive"} == {"ransomware"}   # slow attacks
    assert meta["class_source"]["benign"] == ["lab", "synthetic_hard_negative"]
    assert meta["class_source"]["exfiltration"] == ["synthetic"]
    assert meta["synthetic_fraction_by_class"]["exfiltration"] == 1.0 and 0 < meta["synthetic_fraction_by_class"]["benign"] < 1


def test_train_collected_health_reports_heldout_families(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(collected, "COLLECTED", tmp_path)
    fake_health(tmp_path / "health.jsonl")
    out = tmp_path / "bundle"
    gates = [a for p in train.GATES["health"] for a in ("--gate", f"{p}=0")]
    assert train.main(["--task", "health", "--collected", *gates, "--out", str(out)]) == 0
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


def test_train_gate_failure_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(collected, "COLLECTED", tmp_path)
    fake_health(tmp_path / "health.jsonl")
    out = tmp_path / "bundle"
    assert train.main(["--task", "health", "--collected", "--gate", "heldout_family.pooled.macro_f1=1.1",
                       "--out", str(out)]) == 1
    assert not out.exists()


def health_rec(ops, replicas=1, label="benign", revert=False):
    return {"revert": revert, "label": label, "label_reasons": [], "obs": {"stuck": False, "desired": replicas},
            "params": {"ops": ops, "base": {"replicas": replicas}}, "family": "x", "features": {}, "pre_p99_s": None}


def test_relabel_readiness_stuck_only_for_one_replica_forward_breaks():
    brk = {"op": "probe", "probe": "readinessProbe", "path": "/nope"}
    recs = [health_rec([brk]),                                                  # the replicas=1 bug: relabel
            health_rec([brk], replicas=2),                                      # 2 replicas: recorded right
            health_rec([brk], revert=True),                                     # restoring the base: fine
            health_rec([{"op": "probe", "probe": "readinessProbe", "period": 5}]),   # tweak, not a break
            health_rec([{"op": "probe", "probe": "livenessProbe", "port": 1234}]),   # liveness: restarts decide
            health_rec([{"op": "probe", "probe": "readinessProbe", "port": 1234}], label="degradation")]
    assert collected.relabel_readiness_stuck(recs) == 2
    assert [r["label"] for r in recs] == ["critical", "benign", "benign", "benign", "benign", "critical"]
    assert recs[0]["obs"]["stuck"] and recs[0]["label_reasons"] == ["rollout_stuck"]
    assert recs[0]["relabeled"] == collected.READINESS_STUCK
    assert collected.relabel_readiness_stuck(recs) == 0      # idempotent: stuck is now True


def test_heldout_key_derives_health_families_from_ops():
    rec = health_rec([{"op": "cpu_limit", "m": 8}, {"op": "image", "tag": "0.0.1-missing"}, {"op": "privileged"}])
    assert collected.heldout_key("health", rec) == "cpu_throttle|image_missing|posture"
    assert collected.heldout_key("health", health_rec([{"op": "args_add", "args": ["--stress-cpu=1"]}],
                                                      revert=True)) == "args_stress"   # a revert: its forward family
    assert collected.heldout_key("health", {"family": "fam0"}) == "fam0"                # no params: recorded family

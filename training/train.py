"""Train, evaluate and promote a KubeHeal model bundle.

    uv run python -m training.train --task health
    uv run python -m training.train --task security

Splits are by group (scenario run), stratified on each group's most severe
label, so no run lands on two sides:

- test (10 % of groups): held out, reported only;
- val (10 %): early stopping for the final model, trained on the other 80 %;
- 5-fold grouped cross-validation over all non-test groups gives the
  out-of-fold probabilities used both for the CV report and for split-
  conformal calibration. With few groups (health has 48 runs, only 9 with a
  harmful label) a single 10 % calib split is one or two runs, which badly
  under-covers; out-of-fold scores of ~40 unseen runs are far more stable.

Promotion gate: the bundle is written to models/<task>/ only when the grouped
CV macro-F1 (the steadier estimate; for health over rows with a real spec
change, the only inputs the agent sends) clears --min-macro-f1. Otherwise,
or if the metric is missing, the script exits non-zero and nothing is written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.model_selection import GroupKFold

from kubeheal import __version__
from kubeheal.contracts import HEALTH_CLASS_RISK, HEALTH_LABELS, SECURITY_CLASS_RISK, SECURITY_LABELS
from kubeheal.features.health import HEALTH_FEATURES, health_features
from kubeheal.features.security import SECURITY_FEATURES, security_features
from kubeheal.ml.bundle import ModelBundle
from kubeheal.ml.conformal import calibrate, prediction_sets

ROOT = Path(__file__).resolve().parents[1]
# Measured over seeds 1/2/7: health 0.57-0.64 (spec-changed rows), security see meta.json; gates leave seed margin.
DEFAULT_MIN_MACRO_F1 = {"health": 0.55, "security": 0.80}


def load(task: str, args) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict]:
    """Feature matrix, label indices, groups, scenario families ("" = not held out) and data provenance."""
    full, labels = (HEALTH_FEATURES, HEALTH_LABELS) if task == "health" else (SECURITY_FEATURES, SECURITY_LABELS)
    names = [f for f in full if f not in args.drop_features]   # the bundle's feature list; rows carry all of `full`
    if args.collected:
        from training.datasets import collected

        recs, data = (collected.health_rows(args.data if args.with_legacy else None) if task == "health"
                      else collected.security_rows(args.n_scenarios, args.seed))
        if task == "health" and args.new_only:   # rows from the 120 s window era carry no assess_delay_s
            recs = [r for r in recs if r.get("assess_delay_s") is not None]
        rows = [r["features"] for r in recs]
        source = data.pop("sources")
        # Recorded by the agents of the day: a renamed/added feature would otherwise train as an all-NaN column.
        stale = next((set(r) ^ set(full) for r in rows if set(r) != set(full)), None)
        if stale:
            raise ValueError(f"collected {task} features differ from {task} features: {sorted(stale)}")
    elif task == "health":
        from training.datasets.health import load_records

        recs = load_records(args.data)
        rows = [health_features(r["old"], r["new"], r["window"]) for r in recs]
        source, data = str(Path(args.data).resolve().relative_to(ROOT)), {"synthetic": False}
    else:
        from training.synth_security import generate

        recs = generate(args.n_scenarios, args.seed)
        rows = [security_features(r["events"], r["entropy"], r["window_s"], r["bytes_written"], r["net_bytes_out"])
                for r in recs]
        source, data = f"training/synth_security.py n_scenarios={args.n_scenarios} seed={args.seed}", {"synthetic": True}
    x = np.array([[np.nan if r.get(f) is None else r[f] for f in names] for r in rows], dtype=float)
    y = np.array([labels.index(r["label"]) for r in recs])
    groups = np.array([r["group"] for r in recs])
    families = np.array([r.get("family", "") if args.collected else "" for r in recs])
    sha = hashlib.sha256(x.tobytes() + y.tobytes()).hexdigest()
    data = {"source": source, "rows": len(y), "groups": len(set(groups)), **data, "sha256": sha}
    return x, y, groups, families, data


def metric_dropout(x, y, groups, families, names, seed, frac=1.0):
    """Health: copies of a random `frac` of rows with every metric feature unknown (Prometheus down / no app metrics).

    The copy keeps its label, group and family (so grouped CV and held-out-family splits keep it with its source), so the model learns what the spec change alone predicts (uncertain unless the spec is
    decisive) rather than an arbitrary extrapolation for all-missing metrics.
    """
    from kubeheal.features.health import METRIC_FEATURES

    pick = np.flatnonzero(np.random.default_rng(seed).random(len(y)) < frac)
    xs = x[pick].copy()
    xs[:, [names.index(f) for f in METRIC_FEATURES]] = np.nan
    return (np.vstack([x, xs]), np.concatenate([y, y[pick]]), np.concatenate([groups, groups[pick]]),
            np.concatenate([families, families[pick]]))


def heldout_families(x, y, families, names, labels, seed, rounds, orig) -> dict:
    """Leave-one-scenario-family-out: train on every other row, test on the family never seen in training."""
    k = len(labels)
    per, ys, ps = {}, [], []
    for fam in sorted(set(families) - {""}):
        te = (families == fam) & orig   # test on real rows only; every row of the family (copies too) leaves training
        probs = fit(x[families != fam], y[families != fam], names, k, seed, rounds).predict(x[te])
        present = sorted(set(y[te]))
        per[fam] = {"n": int(te.sum()), "labels": {labels[i]: int((y[te] == i).sum()) for i in present},
                    "accuracy": round(float((probs.argmax(1) == y[te]).mean()), 4),
                    "macro_f1_present": round(float(f1_score(y[te], probs.argmax(1), labels=present,
                                                             average="macro", zero_division=0)), 4)}
        ys.append(y[te])
        ps.append(probs)
    pooled = scores(np.concatenate(ys), np.concatenate(ps), labels) if ys else None
    return {"note": "each lab family held out in turn (model never saw it); pooled = all held-out predictions",
            "pooled": pooled, "per_family": per}


def split_groups(groups: np.ndarray, y: np.ndarray, seed: int) -> dict[str, np.ndarray]:
    """80/10/10 train/val/test by group, stratified on each group's most severe label."""
    rng = np.random.default_rng(seed)
    uniq = np.unique(groups)
    severity = np.array([y[groups == g].max() for g in uniq])
    parts: dict[str, list] = {"train": [], "val": [], "test": []}
    for s in np.unique(severity):
        stratum = rng.permutation(uniq[severity == s])
        cuts = (np.array([0.8, 0.9]) * len(stratum)).round().astype(int)
        for name, g in zip(parts, np.split(stratum, cuts), strict=True):
            parts[name].extend(g)
    return {name: np.isin(groups, g) for name, g in parts.items()}


def class_weights(y: np.ndarray, k: int) -> np.ndarray:
    counts = np.bincount(y, minlength=k).astype(float)
    return (len(y) / (k * np.maximum(counts, 1)))[y]


def fit(x, y, names, k, seed, rounds, valid=None) -> lgb.Booster:
    params = {"objective": "multiclass", "num_class": k, "learning_rate": 0.05, "num_leaves": 15,
              "min_data_in_leaf": 20, "feature_fraction": 0.8, "bagging_fraction": 0.8, "bagging_freq": 1,
              "lambda_l2": 1.0, "seed": seed, "deterministic": True, "force_row_wise": True, "verbose": -1,
              "num_threads": int(os.environ.get("KUBEHEAL_TRAIN_THREADS", 4))}   # more add contention on a few k rows
    dtrain = lgb.Dataset(x, y, weight=class_weights(y, k), feature_name=names)
    if valid is None:
        return lgb.train(params, dtrain, num_boost_round=rounds)
    dval = lgb.Dataset(valid[0], valid[1], weight=class_weights(valid[1], k), reference=dtrain)
    return lgb.train(params, dtrain, num_boost_round=rounds, valid_sets=[dval],
                     callbacks=[lgb.early_stopping(50, verbose=False)])


def scores(y: np.ndarray, probs: np.ndarray, labels: list[str], q: float | None = None) -> dict:
    pred = probs.argmax(1)
    k = len(labels)
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=range(k), zero_division=0)
    out = {
        "n": len(y),
        "per_class": {lbl: {"precision": round(p[i], 4), "recall": round(r[i], 4), "f1": round(f[i], 4),
                            "support": int(s[i])} for i, lbl in enumerate(labels)},
        "macro_f1": round(float(f1_score(y, pred, labels=range(k), average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y, pred, labels=range(k), average="weighted", zero_division=0)), 4),
        "accuracy": round(float((pred == y).mean()), 4),
        "confusion_matrix": confusion_matrix(y, pred, labels=range(k)).tolist(),
    }
    if q is not None:
        sets = prediction_sets(probs, q)
        out["coverage"] = round(float(sets[np.arange(len(y)), y].mean()), 4)
        out["mean_set_size"] = round(float(sets.sum(1).mean()), 4)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--task", choices=["health", "security"], required=True)
    ap.add_argument("--data", default=str(ROOT / "training/data/health_drift.csv"), help="health legacy CSV")
    ap.add_argument("--collected", action="store_true",
                    help="train on lab data (training/datasets/collected.py); security adds synthetic rows only "
                         "for the classes the lab cannot produce")
    ap.add_argument("--with-legacy", action="store_true", help="health --collected: also the legacy CSV (--data)")
    ap.add_argument("--new-only", action="store_true", help="health --collected: drop rows without assess_delay_s")
    ap.add_argument("--drop-features", type=lambda v: [f for f in v.split(",") if f], default=[],
                    help="comma-separated features left out of the bundle (the agents still compute them)")
    ap.add_argument("--n-scenarios", type=int, default=3000, help="security synthetic scenario instances")
    ap.add_argument("--out", help="bundle dir (default models/<task>)")
    ap.add_argument("--alpha", type=float, default=0.1, help="conformal miscoverage")
    ap.add_argument("--min-macro-f1", type=float, help="promotion gate on grouped-CV macro-F1 (default per task)")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)
    task = args.task
    labels, risk = (HEALTH_LABELS, HEALTH_CLASS_RISK) if task == "health" else (SECURITY_LABELS, SECURITY_CLASS_RISK)
    names = [f for f in (HEALTH_FEATURES if task == "health" else SECURITY_FEATURES) if f not in args.drop_features]
    k = len(labels)
    gate = args.min_macro_f1 if args.min_macro_f1 is not None else DEFAULT_MIN_MACRO_F1[task]

    x, y, groups, families, data = load(task, args)
    if task == "health" and args.collected:
        x, y, groups, families = metric_dropout(x, y, groups, families, names, args.seed)
        data["metric_dropout_rows"] = len(y) - data["rows"]
        data["sha256"] = hashlib.sha256(x.tobytes() + y.tobytes()).hexdigest()
    print(f"{task}: {data['rows']} rows, {data['groups']} groups, class counts {np.bincount(y, minlength=k).tolist()}")
    orig = np.arange(len(y)) < data["rows"]   # metric_dropout copies are appended after the real rows: fit-only
    m = split_groups(groups, y, args.seed)
    for name, mask in m.items():
        if len(set(y[mask])) < k:
            print(f"warning: {name} split lacks some classes ({sorted(set(y[mask]))})", file=sys.stderr)

    booster = fit(x[m["train"]], y[m["train"]], names, k, args.seed, 2000, valid=(x[m["val"]], y[m["val"]]))
    rounds = booster.best_iteration or booster.current_iteration()

    # Health is only ever asked about real spec changes (the agent skips no-op updates), so conformal
    # calibration and the gate use that population; unchanged "pre" rows would make both look better.
    serving = x[:, names.index("spec_changed")] == 1 if task == "health" else np.ones(len(y), bool)
    real = orig & serving
    dev = ~m["test"]
    oof = np.zeros((len(y), k))
    for tr, te in GroupKFold(n_splits=5).split(x[dev], y[dev], groups[dev]):
        tr, te = np.flatnonzero(dev)[tr], np.flatnonzero(dev)[te]
        oof[te] = fit(x[tr], y[tr], names, k, args.seed, rounds).predict(x[te])
    q = calibrate(oof[dev & real], y[dev & real], args.alpha)

    test_probs = booster.predict(x[m["test"]])
    report = {
        "split": {n: {"rows": int(v.sum()), "groups": len(set(groups[v]))} for n, v in m.items()},
        "best_iteration": rounds,
        "conformal": {"alpha": args.alpha, "q": round(q, 6),
                      "calibrated_on": "5-fold grouped out-of-fold probabilities, non-test groups, real serving rows"},
        "cv5_grouped": scores(y[dev & orig], oof[dev & orig], labels, q),
        "test": scores(y[m["test"] & orig], test_probs[orig[m["test"]]], labels, q),
    }
    if families.any():
        report["heldout_family"] = heldout_families(x, y, families, names, labels, args.seed, rounds, orig)
    if task == "health":
        report["cv5_grouped_spec_changed"] = scores(y[dev & real], oof[dev & real], labels, q)
        report["test_spec_changed"] = scores(y[m["test"] & real], booster.predict(x[m["test"] & real]), labels, q)
    if not orig.all():
        report["metric_dropout_copies"] = {"note": "fit-only rows, not in calibration or the gate; own metrics",
                                           "cv5_grouped": scores(y[dev & ~orig], oof[dev & ~orig], labels, q)}

    bundle = ModelBundle(booster, {
        "task": task, "version": f"{task}-{__version__}-{data['sha256'][:8]}", "labels": labels,
        "class_risk": risk, "features": names, "alpha": args.alpha, "conformal_q": q, "metrics": report,
        "data": data, "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
    })
    lat = []
    for row in x[m["test"]][:300]:
        t0 = time.perf_counter()
        bundle.predict({f: (None if np.isnan(v) else float(v)) for f, v in zip(names, row, strict=True)})
        lat.append((time.perf_counter() - t0) * 1000)
    report["latency_ms"] = {"p50": round(float(np.percentile(lat, 50)), 3), "p99": round(float(np.percentile(lat, 99)), 3),
                            "note": "single-row bundle.predict incl. TreeSHAP, num_threads=1"}
    print(json.dumps(report, indent=2))

    gate_key = "cv5_grouped_spec_changed" if task == "health" else "cv5_grouped"
    macro = report.get(gate_key, {}).get("macro_f1")
    if macro is None or macro < gate:
        print(f"FAIL: {gate_key} macro-F1 {macro} < gate {gate}; bundle NOT written", file=sys.stderr)
        return 1
    out = Path(args.out or ROOT / "models" / task)
    bundle.save(out)
    print(f"PASS: {gate_key} macro-F1 {macro} >= {gate}; wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

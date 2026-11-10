# Conformal quantiles: which file the servers use (F9)

Values below are copied from files in the repo. Nothing was recomputed.

| Model | `*_conformal.json` (loaded by the server) | `*_report.json` `conformal_q` (training-time) |
|---|---|---|
| Health | q = 0.5468633584181468, alpha = 0.1 (`models/health_model/checkpoints/health_conformal.json`) | 0.7302716440994654 |
| Security | q = 0.08265669266382854, alpha = 0.1 (`models/security_model/checkpoints/security_conformal.json`) | 0.08182301419121879 |

## Decision

- The servers load `<checkpoint dir>/health_conformal.json` and `security_conformal.json`
  (`services/*/main.py`, `_load_model`). The `conformal_q` field in `*_report.json` is the value the
  training run recorded and is **not read at serve time**.
- `tests/test_model_servers_fail_closed.py::test_server_uses_the_conformal_json_next_to_the_checkpoint`
  asserts that the server's loaded q equals the value in `*_conformal.json`.
- Both files are written by `models/train_*_model.py`. `models/calibrate_conformal.py` rewrites only
  `*_conformal.json`, at a chosen coverage. The two values differ, so the JSON was written by a
  different run than the report (probably `calibrate_conformal.py`). That was not verified.

## What the serve-time interval really is

`ci_width = 1 - max softmax probability` per request, and `interval(risk, ci_width)` returns
`risk +/- ci_width / 2`. The calibrated `q` is **not used** to build the interval or the width. The
Fusion gate (width <= 0.15, spec S-POL-6) therefore tests a per-sample confidence gap, not a
split-conformal interval. The score responses now include `conformal_q` so the loaded value is visible.

## Open item (not fixed in P1)

Using `q` properly (flag a prediction uncertain when `1 - max_prob > q`, or build a calibrated set)
changes behaviour and needs a recalibration on held-out data. That is scheduled with the model
hardening phase (P12), which needs the user's go before any training or recalibration runs.

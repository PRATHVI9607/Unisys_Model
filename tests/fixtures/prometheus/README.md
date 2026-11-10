# Prometheus window fixtures

Hand-built and synthetic. They were NOT captured from a running Prometheus. Each file describes, per
Health Model metric column, which of the 60 steps (index 0..59, 5 s apart) a fake Prometheus returns:

- `points`: list of `[step_index, value]` (values are simple ramps, only meant to be distinguishable)
- `absent`: the query returns an empty result
- `nan_only`: the query returns the string "NaN" for every step (what `histogram_quantile` gives with no traffic)

`tests/test_sense_health_window.py` turns a fixture into `query_range` JSON bodies. Files:
`window_full.json`, `window_short.json`, `window_missing.json`.

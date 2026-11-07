import numpy as np
import pytest

from kubeheal.features.security import (
    MIN_RECENT_S,
    RECENT_EVENTS,
    RECENT_FEATURES,
    SECURITY_FEATURES,
    security_features,
    shannon_entropy,
)
from training.synth_security import generate


def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
    assert shannon_entropy(b"abab") == pytest.approx(1.0)


def test_ransomware_like_window():
    events = [
        {"syscall": "open_r", "path": "/data/a.docx"},
        {"syscall": "open_w", "path": "/data/a.docx"},
        {"syscall": "ftruncate", "path": "/data/a.docx"},
        {"syscall": "rename", "path": "/data/a.docx", "new_path": "/data/a.docx.locked"},
        {"syscall": "open_w", "path": "/data/b.txt"},
        {"syscall": "rename", "path": "/data/b.txt", "new_path": "/data/b.txt.x7f3q"},
        {"syscall": "open_w", "path": "/data/README_DECRYPT.txt"},
        {"syscall": "sendto", "path": ""},
    ]
    f = security_features(events, [7.99, 7.98, 4.5], window_s=4.0, bytes_written=4000.0)
    assert list(f) == SECURITY_FEATURES
    assert f["n_events"] == 8 and f["events_per_s"] == 2.0
    assert f["frac_rename"] == 0.25 and f["frac_write"] == 0.375 and f["frac_truncate"] == 0.125 and f["frac_network"] == 0.125
    assert f["rename_ext_change_ratio"] == 1.0
    # written: a.docx, b.txt, README, a.docx.locked, b.txt.x7f3q → one known ransomware extension
    assert f["suspicious_ext_ratio"] == pytest.approx(1 / 5)
    assert f["files_written_per_s"] == pytest.approx(5 / 4)
    assert f["ransom_note"] == 1.0
    assert f["entropy_high_frac"] == pytest.approx(2 / 3) and f["entropy_max"] == 7.99
    assert f["write_bytes_per_s"] == 1000.0 and f["net_out_bytes_per_s"] is None


def test_missing_data_is_none_not_zero():
    f = security_features([], [], window_s=0)
    assert f["n_events"] == 0.0 and f["n_entropy_samples"] == 0.0
    for k in ("events_per_s", "frac_read", "entropy_mean", "entropy_slope", "rename_ext_change_ratio",
              "suspicious_ext_ratio", "files_written_per_s", "write_bytes_per_s"):
        assert f[k] is None, k


def test_benign_log_rotation_is_not_a_note_or_ransom_ext():
    events = [{"syscall": "rename", "path": "/var/log/app.log", "new_path": "/var/log/app.log.1"},
              {"syscall": "write", "path": "/var/log/app.log"}]
    f = security_features(events, [], window_s=10)
    assert f["ransom_note"] == 0.0 and f["suspicious_ext_ratio"] == 0.0
    assert f["rename_ext_change_ratio"] == 1.0   # benign renames change extensions too; the model must cope


def test_synthetic_generator_matches_agent_window_definition():
    recs = generate(200, seed=3)
    assert {r["label"] for r in recs} == {"benign", "suspicious", "ransomware", "exfiltration"}
    assert all(1 <= len(r["events"]) <= 512 and 5 <= r["window_s"] <= 60 for r in recs)
    assert any(not r["entropy"] for r in recs)
    lengths = np.array([len(r["events"]) for r in recs])
    assert lengths.min() < 60 and lengths.max() > 350
    # no label-revealing token: ransomware often has no known ransomware extension at all
    ransom = [security_features(r["events"], r["entropy"], r["window_s"]) for r in recs if r["label"] == "ransomware"]
    assert any(not f["suspicious_ext_ratio"] for f in ransom)


def test_training_windows_only_hold_what_falco_captures():
    """Train/serve parity: synthetic windows contain only syscalls the KubeHeal Falco rule emits."""
    import re
    from pathlib import Path

    from kubeheal.features.security import CAPTURED_GROUPS, MAX_ENTROPY_SAMPLES, SYSCALL_GROUPS, open_syscall

    rules = Path(__file__).parents[1].joinpath("deploy/k8s/falco-kubeheal-rules.yaml").read_text()
    emitted = set(re.search(r"evt\.type in \(([^)]*)\)", rules).group(1).replace("\n", " ").replace(" ", "").split(","))
    captured = set().union(*(SYSCALL_GROUPS[g] for g in CAPTURED_GROUPS))
    # what the agent sees: opens become open_r/open_w, so the rule's list must map onto the captured set exactly
    assert {open_syscall(e, "O_RDONLY") for e in emitted} | {open_syscall(e, "O_WRONLY") for e in emitted} == captured
    assert not {"read", "write", "pread", "pwrite"} & emitted           # read()/write() are never hooked
    recs = generate(200, seed=3)
    assert all(e["syscall"] in captured for r in recs for e in r["events"])
    assert all(len(r["entropy"]) <= MAX_ENTROPY_SAMPLES for r in recs)


def test_synthetic_byte_counters_separate_the_synthetic_only_classes():
    """Pod-wide counters as the agent measures them: sometimes None, never negative, class-typical rates."""
    recs = generate(1500, seed=5)
    for key in ("bytes_written", "net_bytes_out"):
        vals = [r[key] for r in recs]
        assert 0.1 < sum(v is None for v in vals) / len(vals) < 0.4
        assert all(v is None or v >= 0 for v in vals)

    def median_rate(key, **match):
        rates = [r[key] / r["window_s"] for r in recs if r[key] is not None
                 and all(r[k] == v for k, v in match.items())]
        return float(np.median(rates))
    benign_net = median_rate("net_bytes_out", label="benign")
    assert median_rate("net_bytes_out", label="exfiltration") > 20 * benign_net
    assert median_rate("net_bytes_out", scenario="backup_upload") > 20 * benign_net    # benign hard negative
    assert median_rate("bytes_written", label="ransomware") > 10 * median_rate("bytes_written", label="benign")
    assert median_rate("bytes_written", scenario="backup_compress") > median_rate("bytes_written", label="suspicious")
    assert median_rate("bytes_written", label="exfiltration") < median_rate("bytes_written", label="ransomware")


# ── recent_* (last RECENT_EVENTS events) ─────────────────────────────────────
def _ev(i, syscall="open_w", path=None, **kw):
    return {"syscall": syscall, "path": path or f"/data/f{i}", "ts_ms": 1_000_000 + i * 100, **kw}


def test_recent_features_unknown_are_none_not_zero():
    f = security_features([], [], window_s=0)
    assert all(f[k] is None for k in RECENT_FEATURES)
    f = security_features([{"syscall": "open_r", "path": "/data/a"}], [], window_s=5)   # no ts, no writes
    assert f["recent_frac_write"] == 0.0 and f["recent_unique_files"] == 1.0
    for k in ("recent_ext_change_frac", "recent_entropy_mean", "recent_entropy_high_frac", "recent_events_per_s"):
        assert f[k] is None, k


def test_recent_features_cover_only_the_last_64_events():
    setup = [_ev(i, "open_r") for i in range(400)]                       # long quiet setup phase
    burst = [_ev(400 + i, "rename", f"/data/b{i}.txt", new_path=f"/data/b{i}.txt.locked") for i in range(RECENT_EVENTS)]
    f = security_features(setup + burst, [4.0] * 8, window_s=60)
    assert f["frac_rename"] < 0.2 and f["recent_frac_rename"] == 1.0     # window dilutes it, recent does not
    assert f["recent_unique_files"] == RECENT_EVENTS and f["recent_ext_change_frac"] == 1.0
    assert f["recent_frac_write"] == 0.0


def test_recent_rate_span_is_floored():
    burst = [{"syscall": "open_w", "path": f"/d/{i}", "ts_ms": 5000 + i} for i in range(10)]   # 9 ms span
    assert security_features(burst, [], 5)["recent_events_per_s"] == pytest.approx(10 / MIN_RECENT_S)
    slow = [_ev(i * 10) for i in range(11)]                                                  # 10 s span
    assert security_features(slow, [], 5)["recent_events_per_s"] == pytest.approx(1.1)


def test_recent_entropy_uses_the_newest_samples_of_recently_written_files():
    # 2 files written recently; 8 samples oldest first: only the last 2 (encrypted) count
    events = [_ev(i, "open_r") for i in range(100)] + [_ev(100), _ev(101, "ftruncate")]
    f = security_features(events, [3.0] * 6 + [7.9, 7.95], window_s=10)
    assert f["recent_entropy_mean"] == pytest.approx(7.925) and f["recent_entropy_high_frac"] == 1.0
    assert f["entropy_high_frac"] == pytest.approx(2 / 8)


def test_synthetic_windows_carry_recent_features_in_attack_order():
    recs = generate(150, seed=5)
    rows = [(r["label"], security_features(r["events"], r["entropy"], r["window_s"], r["bytes_written"],
                                           r["net_bytes_out"])) for r in recs]
    assert all(set(RECENT_FEATURES) <= set(f) for _, f in rows)
    assert all(f["recent_frac_write"] is not None for _, f in rows)
    # ransomware: the tail is mostly write/rename work; benign windows' tails are not
    ran = np.mean([f["recent_frac_write"] + f["recent_frac_rename"] for lbl, f in rows if lbl == "ransomware"])
    ben = np.mean([f["recent_frac_write"] + f["recent_frac_rename"] for lbl, f in rows if lbl == "benign"])
    assert ran > ben

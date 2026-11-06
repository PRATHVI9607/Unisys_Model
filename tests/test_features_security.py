import numpy as np
import pytest

from kubeheal.features.security import SECURITY_FEATURES, security_features, shannon_entropy
from training.synth_security import generate


def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
    assert shannon_entropy(b"abab") == pytest.approx(1.0)


def test_ransomware_like_window():
    events = [
        {"syscall": "openat", "path": "/data/a.docx"},
        {"syscall": "read", "path": "/data/a.docx"},
        {"syscall": "write", "path": "/data/a.docx"},
        {"syscall": "rename", "path": "/data/a.docx", "new_path": "/data/a.docx.locked"},
        {"syscall": "write", "path": "/data/b.txt"},
        {"syscall": "rename", "path": "/data/b.txt", "new_path": "/data/b.txt.x7f3q"},
        {"syscall": "write", "path": "/data/README_DECRYPT.txt"},
        {"syscall": "sendto", "path": ""},
    ]
    f = security_features(events, [7.99, 7.98, 4.5], window_s=4.0, bytes_written=4000.0)
    assert list(f) == SECURITY_FEATURES
    assert f["n_events"] == 8 and f["events_per_s"] == 2.0
    assert f["frac_rename"] == 0.25 and f["frac_write"] == 0.375 and f["frac_network"] == 0.125
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

    from kubeheal.features.security import CAPTURED_GROUPS, MAX_ENTROPY_SAMPLES, SYSCALL_GROUPS

    rules = Path(__file__).parents[1].joinpath("deploy/k8s/falco-kubeheal-rules.yaml").read_text()
    emitted = set(re.search(r"evt\.type in \(([^)]*)\)", rules).group(1).replace("\n", " ").replace(" ", "").split(","))
    captured = set().union(*(SYSCALL_GROUPS[g] for g in CAPTURED_GROUPS))
    assert emitted <= captured                                           # every live event is counted
    assert all(emitted & SYSCALL_GROUPS[g] for g in CAPTURED_GROUPS)     # every captured group can occur live
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

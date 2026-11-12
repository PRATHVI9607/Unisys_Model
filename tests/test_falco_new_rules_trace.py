"""V5-S1: the hand-written trace shaped like the new Falco rules (NOT a real capture, see tests/fixtures/falco/README.md)
replayed through falco_client, FalcoWindowTracker and the v5 feature path, and scored with the shipped bundle."""
from pathlib import Path

import pytest

from agents.security_agent import falco_client as fc
from agents.security_agent.syscall_window import FalcoWindowTracker
from agents.security_agent.v5_window import window_from_normalised
from kubeheal.features.security import security_features

TRACE = Path(__file__).parent / "fixtures" / "falco" / "ransomware_pv_encrypt_new_rules.jsonl"
PID = 4242


def replay():
    """(all events, window of PID from the tracker, triggers). The clock is held, then moved past the cooldown
    before the ransom note so that the CRITICAL rule can fire its own trigger."""
    now = {"t": 0.0}
    tracker = FalcoWindowTracker(clock=lambda: now["t"])
    events = list(fc.iter_trace_events(str(TRACE)))
    triggers = []
    for e in events:
        if e["priority"] == "critical":
            now["t"] = 10.0
        tr = tracker.add(e)
        if tr:
            triggers.append(tr)
    return events, tracker.window(PID), triggers


def test_replay_carries_open_flags_and_both_rename_paths():
    events, _, _ = replay()
    assert len(events) == 37
    opens = [e for e in events if e["syscall"] == "openat"]
    renames = [e for e in events if e["syscall"] == "renameat2"]
    assert len(opens) == 25 and len(renames) == 12
    assert all(e["flags"] for e in opens)
    assert sum("O_WRONLY" in e["flags"] for e in opens) == 13          # 12 rewrites and the note
    for e in renames:
        assert e["fs_source"].startswith("/data/") and e["fs_target"] == e["fs_source"] + ".locked"
        assert e["fd_path"] == "" and e["flags"] == ""                  # null fields stay empty, never "<NA>"
    assert events[-1]["priority"] == "critical" and events[-1]["fd_path"] == "/data/DECRYPT_FILES.txt"
    assert all(e["pod_uid"] and e["container_id"] and e["syscall_inferred"] is False for e in events)


def test_tracker_triggers_on_the_burst_and_again_on_the_note():
    _, _, triggers = replay()
    assert [t.reason for t in triggers] == ["burst", "falco_rule"]
    assert all(t.pid == PID for t in triggers)


def test_v5_events_have_open_w_and_renames_with_both_paths():
    _, window, _ = replay()
    v5, _start, _end, window_s = window_from_normalised(window)
    by = {}
    for e in v5:
        by.setdefault(e["syscall"], []).append(e)
    assert len(by["open_w"]) == 13 and len(by["open_r"]) == 12
    assert len(by["renameat2"]) == 12
    for e in by["renameat2"]:
        assert e["path"].startswith("/data/") and e["new_path"] == e["path"] + ".locked"
    assert window_s > 0


def test_features_have_rename_and_suffix_style_values():
    _, window, _ = replay()
    v5, _start, _end, window_s = window_from_normalised(window)
    f = security_features(v5, [], window_s)
    for name in ("frac_rename", "frac_write", "frac_rename_suffix_added", "rename_ext_added_ratio",
                 "suspicious_ext_ratio", "ransom_note", "recent_frac_rename_suffix_added"):
        assert f[name] is not None, name
    assert f["frac_rename_suffix_added"] > 0 and f["rename_ext_added_ratio"] > 0 and f["ransom_note"] > 0


def test_the_shipped_bundle_scores_the_new_rules_trace_as_not_benign():
    """Real LightGBM bundle through the bundle API (as tests/test_security_v5.py does), no entropy (a replayed pid has
    no readable files). Hand-written trace, so this shows what the model does with the fields the new rules emit,
    not how a live attack scores."""
    pytest.importorskip("lightgbm")
    from kubeheal.ml.bundle import ModelBundle
    _, window, _ = replay()
    v5, _start, _end, window_s = window_from_normalised(window)
    bundle = ModelBundle.load_default("security")
    pred = bundle.predict(bundle.restrict(security_features(v5, [], window_s)))
    assert pred.label != "benign", (pred.label, pred.risk, pred.probabilities)
    assert pred.risk >= 0.5, (pred.label, pred.risk, pred.probabilities)


def test_a_null_or_na_fd_name_never_becomes_a_path():
    for value in (None, "<NA>", ""):
        evt = fc._normalise({"rule": "KubeHeal Ransomware Mass Rename",
                             "output_fields": {"evt.type": "rename", "fd.name": value, "fs.path.source": "/data/a",
                                               "fs.path.target": "/data/a.locked", "proc.pid": 1}})
        assert evt["fd_path"] == "" and evt["fs_source"] == "/data/a" and evt["fs_target"] == "/data/a.locked"
    unlink = fc._normalise({"output_fields": {"evt.type": "unlink", "fd.name": "<NA>", "fs.path.name": "/data/x",
                                              "proc.pid": 1}})
    assert unlink["fd_path"] == "" and unlink["fs_name"] == "/data/x"

import numpy as np
import pytest

from kubeheal.features.security import (
    MIN_RECENT_S,
    RECENT_EVENTS,
    RECENT_FEATURES,
    SECURITY_FEATURES,
    rename_kinds,
    security_features,
    shannon_entropy,
)


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
    assert f["rename_ext_added_ratio"] == 1.0 and f["frac_rename_suffix_added"] == 1.0
    # written: a.docx, b.txt, README, a.docx.locked, b.txt.x7f3q → one known ransomware extension
    assert f["suspicious_ext_ratio"] == pytest.approx(1 / 5)
    assert f["files_written_per_s"] == pytest.approx(5 / 4)
    assert f["ransom_note"] == 1.0
    assert f["entropy_high_frac"] == pytest.approx(2 / 3) and f["entropy_max"] == 7.99
    assert f["write_bytes_per_s"] == 1000.0 and f["net_out_bytes_per_s"] is None


def test_missing_data_is_none_not_zero():
    f = security_features([], [], window_s=0)
    assert f["n_events"] == 0.0 and f["n_entropy_samples"] == 0.0
    for k in ("events_per_s", "frac_read", "entropy_mean", "entropy_slope", "rename_ext_added_ratio",
              "suspicious_ext_ratio", "files_written_per_s", "write_bytes_per_s"):
        assert f[k] is None, k


def test_benign_log_rotation_is_not_a_note_or_ransom_ext():
    events = [{"syscall": "rename", "path": "/var/log/app.log", "new_path": "/var/log/app.log.1"},
              {"syscall": "write", "path": "/var/log/app.log"}]
    f = security_features(events, [], window_s=10)
    assert f["ransom_note"] == 0.0 and f["suspicious_ext_ratio"] == 0.0
    assert f["frac_rename_rotate"] == 1.0 and f["rename_ext_added_ratio"] == 0.0   # rotation is not an encryption suffix








# ── recent_* (last RECENT_EVENTS events) ─────────────────────────────────────
def _ev(i, syscall="open_w", path=None, **kw):
    return {"syscall": syscall, "path": path or f"/data/f{i}", "ts_ms": 1_000_000 + i * 100, **kw}


def test_recent_features_unknown_are_none_not_zero():
    f = security_features([], [], window_s=0)
    assert all(f[k] is None for k in RECENT_FEATURES)
    f = security_features([{"syscall": "open_r", "path": "/data/a"}], [], window_s=5)   # no ts, no writes
    assert f["recent_frac_write"] == 0.0 and f["recent_unique_files"] == 1.0
    for k in ("recent_ext_added_frac", "recent_frac_rename_suffix_added", "recent_entropy_mean", "recent_entropy_high_frac", "recent_events_per_s"):
        assert f[k] is None, k


def test_recent_features_cover_only_the_last_64_events():
    setup = [_ev(i, "open_r") for i in range(400)]                       # long quiet setup phase
    burst = [_ev(400 + i, "rename", f"/data/b{i}.txt", new_path=f"/data/b{i}.txt.locked") for i in range(RECENT_EVENTS)]
    f = security_features(setup + burst, [4.0] * 8, window_s=60)
    assert f["frac_rename"] < 0.2 and f["recent_frac_rename"] == 1.0     # window dilutes it, recent does not
    assert f["recent_unique_files"] == RECENT_EVENTS and f["recent_ext_added_frac"] == 1.0 and f["recent_frac_rename_suffix_added"] == 1.0
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






# ── rename classification ────────────────────────────────────────────────────
def _kinds(*pairs, before=()):
    ev = [{"syscall": "open_w", "path": p} for p in before]
    ev += [{"syscall": "rename", "path": a, "new_path": b} for a, b in pairs]
    return [k for _, k, _ in rename_kinds(ev)]


def test_rename_classifier():
    assert _kinds(("/d/file.txt", "/d/file.txt.locked")) == ["suffix_added"]
    assert _kinds(("/d/.cfg.tmp123", "/d/cfg")) == ["temp_replace"]
    assert _kinds(("/d/cfg~", "/d/cfg"), ("/d/a.dpkg-new", "/d/a"), ("/d/x.k3Jd9Z", "/d/x")) == ["temp_replace"] * 3
    assert _kinds(("/d/new", "/d/cfg"), before=["/d/cfg"]) == ["temp_replace"]          # onto a file seen earlier
    assert _kinds(("/d/new", "/d/cfg")) == ["other"]                                     # not seen: plain move
    assert _kinds(("/d/x.log", "/d/x.log.1"), ("/d/x.log.1.gz", "/d/x.log.2.gz")) == ["rotate", "rotate"]
    assert _kinds(("/d/x", "/d/y")) == ["other"]
    assert _kinds(("/d/a", "/d/b"), ("/d/c", "/d/b")) == ["other", "temp_replace"]      # target of an earlier rename
    assert _kinds(("/d/f.tmp", "/d/f.tmp.locked")) == ["suffix_added"]                   # suffix wins over temp-looking


def test_rename_features_split_encryption_from_benign_renames():
    enc = [{"syscall": "rename", "path": f"/d/f{i}.txt", "new_path": f"/d/f{i}.txt.q8x2k"} for i in range(4)]
    f = security_features(enc, [], 5)
    assert f["frac_rename_suffix_added"] == f["rename_ext_added_ratio"] == f["recent_ext_added_frac"] == 1.0
    assert f["frac_rename_temp_replace"] == f["frac_rename_rotate"] == 0.0
    gz = [{"syscall": "rename", "path": "/d/a.log", "new_path": "/d/a.log.gz"}]     # compression is not encryption
    f = security_features(gz, [], 5)
    assert f["frac_rename_suffix_added"] == 1.0 and f["rename_ext_added_ratio"] == 0.0
    atomic = [{"syscall": "rename", "path": f"/d/.c.tmp{i}", "new_path": "/d/c"} for i in range(3)]
    f = security_features(atomic, [], 5)
    assert f["frac_rename_temp_replace"] == f["recent_frac_rename_temp_replace"] == 1.0
    assert f["rename_ext_added_ratio"] == 0.0 and f["recent_frac_rename_suffix_added"] == 0.0


def test_rename_features_none_without_renames():
    f = security_features([{"syscall": "open_w", "path": "/d/a"}], [], 5)
    for k in ("frac_rename_suffix_added", "frac_rename_temp_replace", "frac_rename_rotate", "rename_ext_added_ratio",
              "recent_frac_rename_suffix_added", "recent_frac_rename_temp_replace", "recent_ext_added_frac"):
        assert f[k] is None, k


def test_recent_rename_kind_sees_the_whole_window():
    ev = [{"syscall": "open_w", "path": "/d/cfg"}] + [_ev(i, "open_r") for i in range(100)]
    ev.append({"syscall": "rename", "path": "/d/new", "new_path": "/d/cfg"})        # target written 100 events ago
    f = security_features(ev, [], 5)
    assert f["recent_frac_rename_temp_replace"] == 1.0




# ── transforms of read originals ─────────────────────────────────────────────
TRANSFORM = ("frac_write_from_read", "frac_read_destroyed", "n_files_transformed")


def _e(sc, p, new=None):
    return {"syscall": sc, "path": p} | ({"new_path": new} if new else {})


def _tf(events):
    f = security_features(events, [], 5)
    return tuple(f[k] for k in TRANSFORM)


def _detection(n=6, mode="rename", setup=True):
    """deploy/chaos/detection-test-workload.py: create, then read + O_TRUNC write (+ rename/swap) each file."""
    ev = [_e("open_w", f"/data/f{i}.dat") for i in range(n)] if setup else []
    for i in range(n):
        x = f"/data/f{i}.dat"
        ev += [_e("open_r", x), _e("open_w", x)]
        if mode == "rename":
            ev.append(_e("rename", x, x + ".khlocked"))
        elif mode == "swap":
            ev.append(_e("rename", x, f"/data/f{i}.khlocked"))
        elif mode == "copy":              # write x.enc, delete the original
            ev[-1] = _e("open_w", x + ".enc")
            ev.append(_e("unlink", x))
    return ev


@pytest.mark.parametrize("mode", ["rename", "inplace", "swap", "copy"])
def test_ransomware_transforms_every_file_it_reads(mode):
    w, d, n = _tf(_detection(mode=mode, setup=False))
    assert w == 1.0 and d == 1.0 and n == 6.0


def test_setup_phase_dilutes_the_window_but_not_the_read_side_or_the_tail():
    ev = [_e("open_w", f"/data/s{i}.dat") for i in range(200)] + _detection(n=20)
    f = security_features(ev, [], 5)
    assert f["frac_write_from_read"] < 0.3 and f["frac_read_destroyed"] == 1.0
    assert f["recent_frac_write_from_read"] == 1.0 and f["recent_frac_read_destroyed"] > 0.9


def test_slow_attack_is_evident_after_two_files():
    ev = [_e("open_w", f"/data/f{i}.dat") for i in range(100)] + _detection(n=2, setup=False)
    f = security_features(ev, [], 60)
    assert f["n_files_transformed"] == 2.0 and f["frac_read_destroyed"] == f["recent_frac_read_destroyed"] == 1.0


def test_partial_attack_reads_more_than_it_transforms():
    ev = _detection(n=4, setup=False) + [_e("open_r", f"/data/g{i}") for i in range(4)]
    assert _tf(ev)[1] == 0.5


def test_restic_backup_reads_originals_and_writes_new_repo_files():
    ev = [_e("open_r", "/data/repo/config"), _e("open_r", "/data/repo/keys/1f2e")]
    for i in range(30):
        ev.append(_e("open_r", f"/data/src/f{i}.txt"))
        if i % 5 == 0:
            h = f"{i:02x}a9c3e1b7"
            ev += [_e("open_w", f"/data/repo/data/{h[:2]}/.{h}-tmp"), _e("rename", f"/data/repo/data/{h[:2]}/.{h}-tmp",
                                                                       f"/data/repo/data/{h[:2]}/{h}")]
    ev += [_e("open_w", "/data/repo/snapshots/77ab"), _e("open_w", "/data/repo/locks/88cd"),
           _e("unlink", "/data/repo/locks/88cd"),
           _e("open_r", "/data/repo/index/55"), _e("open_w", "/data/cache/x/index/55")]   # cache copy: other dir
    assert _tf(ev) == (0.0, 0.0, 0.0)


def test_restic_prune_deletes_packs_it_read_but_transforms_none():
    ev = []
    for i in range(10):
        ev += [_e("open_r", f"/data/repo/data/0{i}/old{i}"), _e("open_w", f"/data/repo/data/1{i}/new{i}")]
    ev += [_e("unlink", f"/data/repo/data/0{i}/old{i}") for i in range(10)]
    w, d, n = _tf(ev)
    assert w == 0.0 and n == 0.0 and d == 1.0


def test_package_installs_and_git_write_fresh_trees():
    npm = [_e("open_r", "/data/app/package.json"), _e("open_r", "/data/npmcache/content-v2/sha512/ab/cd/ef01")]
    npm += [_e("open_w", f"/data/app/node_modules/express/lib/f{i}.js") for i in range(40)]
    npm += [_e("open_w", "/data/app/node_modules/.staging/x-1"),
            _e("rename", "/data/app/node_modules/.staging/x-1", "/data/app/node_modules/x"),
            _e("open_w", "/data/app/package.json")]                                # rewrites its manifest
    w, d, n = _tf(npm)
    assert w < 0.05 and n == 1.0
    pip = [_e("open_r", "/data/pipcache/wheels/a/requests-2.32.whl")]
    pip += [_e("open_w", f"/data/venv/lib/site-packages/requests/m{i}.py") for i in range(30)]
    pip += [_e("open_r", "/data/venv/lib/site-packages/requests/m1.py"),
            _e("open_w", "/data/venv/lib/site-packages/requests/__pycache__/m1.cpython-313.pyc.4711"),
            _e("rename", "/data/venv/lib/site-packages/requests/__pycache__/m1.cpython-313.pyc.4711",
               "/data/venv/lib/site-packages/requests/__pycache__/m1.cpython-313.pyc")]
    assert _tf(pip) == (0.0, 0.0, 0.0)
    git = [_e("open_r", "/data/repo/.git/index"), _e("open_r", "/data/repo/.git/objects/pack/p.pack")]
    git += [x for i in range(20) for x in (_e("unlink", f"/data/repo/src/f{i}.go"), _e("open_w", f"/data/repo/src/f{i}.go"))]
    git += [_e("open_w", "/data/repo/.git/index.lock"), _e("rename", "/data/repo/.git/index.lock", "/data/repo/.git/index")]
    assert _tf(git) == (0.0, 0.0, 0.0)


def test_logrotate_gzip_and_atomic_config_writes_do_not_transform():
    rot = [_e("rename", "/data/app.log", "/data/app.log.1"), _e("open_w", "/data/app.log"),
           _e("open_r", "/data/app.log.1"), _e("open_w", "/data/app.log.1.gz"), _e("unlink", "/data/app.log.1"),
           _e("rename", "/data/app.log.1.gz", "/data/app.log.2.gz")]
    w, d, n = _tf(rot)
    assert w == 0.0 and n == 0.0 and d == 1.0          # gzip removes what it read: destroyed, not transformed
    conf = [_e("open_r", "/data/conf.json")]
    for tmp in ("/data/conf.json.tmp", "/data/.conf.json.swp", "/data/conf.json~", "/data/conf.json.new"):
        conf += [_e("open_w", tmp), _e("rename", tmp, "/data/conf.json")]
    assert _tf(conf) == (0.0, 0.0, 0.0)
    moved = [_e("open_r", "/data/in/a.csv"), _e("rename", "/data/in/a.csv", "/data/done/a.csv")]   # queue move
    assert _tf(moved) == (0.0, 0.0, 0.0)


def test_transform_features_none_without_reads_or_writes():
    f = security_features([], [], 5)
    assert f["frac_write_from_read"] is None and f["frac_read_destroyed"] is None and f["n_files_transformed"] == 0.0
    assert f["recent_frac_write_from_read"] is None and f["recent_frac_read_destroyed"] is None
    f = security_features([_e("open_w", "/d/a")], [], 5)
    assert f["frac_write_from_read"] == 0.0 and f["frac_read_destroyed"] is None



"""V5-I3: no dashboard module requires a field that V5 removed. A grep-style test lists the modules that may
still READ a removed field (always through `.get`, always optional), and an AST check forbids a subscript
read (`x["field_attribution_json"]`) of any of them anywhere in dashboard/."""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard"

# Removed or legacy fields (V5): the LightGBM stack publishes prediction sets and TreeSHAP top factors instead.
REMOVED = ("field_attribution_json", "ci_width", "embedding", "top_field", "top_syscall", "top_metric")

# file (relative to dashboard/) -> the tokens it may still mention, and why. Anything else is a failure.
ALLOWED_LEGACY_READERS = {
    # reads them with .get for older incidents and shows them only as legacy; never required
    "incident_view.py": {"field_attribution_json", "ci_width", "top_field", "top_syscall", "top_metric"},
    # renders the optional `legacy` dict of the incident view
    "pages.py": {"ci_width", "top_metric"},
    # stream and Redis event path: field_attribution_json goes through _tolerant_json / .get
    "fastapi_app.py": {"field_attribution_json", "top_syscall"},   # top_syscall: _g(...) with a default
    # _exec_request: top_field is only the fallback for an older incident without `patch_fields`
    "admin_routes.py": {"top_field"},
}


def _files():
    for p in sorted(DASH.rglob("*")):
        if p.suffix in (".py", ".html", ".js", ".css") and "__pycache__" not in p.parts:
            yield p


def _mentioned(path):
    text = path.read_text(encoding="utf-8")
    return {t for t in REMOVED if re.search(re.escape(t), text)}


def test_only_the_listed_modules_mention_a_removed_field():
    found = {}
    for p in _files():
        hit = _mentioned(p)
        if hit:
            found[str(p.relative_to(DASH)).replace("\\", "/")] = hit
    unexpected = {f: sorted(t - ALLOWED_LEGACY_READERS.get(f, set())) for f, t in found.items()
                  if t - ALLOWED_LEGACY_READERS.get(f, set())}
    assert not unexpected, f"dashboard files read removed fields without being listed: {unexpected}"


def test_the_allow_list_has_no_stale_entries():
    for name, tokens in ALLOWED_LEGACY_READERS.items():
        path = DASH / name
        assert path.exists(), name
        assert tokens <= _mentioned(path), f"{name} no longer mentions {sorted(tokens - _mentioned(path))}"


def test_embeddings_are_never_read_by_the_dashboard():
    for p in _files():
        text = p.read_text(encoding="utf-8")
        assert "embedding" not in text and "_b64" not in text, p.name


@pytest.mark.parametrize("path", [p for p in sorted(DASH.glob("*.py"))], ids=lambda p: p.name)
def test_no_removed_field_is_read_with_a_subscript(path):
    """`event["field_attribution_json"]` raises KeyError for a new event: only `.get(...)` is allowed."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, (str, bytes)):
                text = key.value.decode() if isinstance(key.value, bytes) else key.value
                if any(t in text for t in REMOVED):
                    bad.append((node.lineno, text))
    assert not bad, f"{path.name} reads a removed field with a subscript: {bad}"


def test_detector_catches_a_required_read(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('def a(e):\n    return e["health_ci_width"]\n')
    tree = ast.parse(f.read_text())
    hits = [n for n in ast.walk(tree) if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
            and "ci_width" in n.slice.value]
    assert hits


# ------------------------------------------------------------------ the event paths of fastapi_app

@pytest.mark.parametrize("junk", [None, "", "{}", b"{}", "not json", b"\xff\xfe", "[1]", "5", '"x"'])
def test_stream_path_json_helper_never_raises(junk):
    from dashboard.fastapi_app import _tolerant_json
    assert _tolerant_json(junk, {}) == {}
    assert _tolerant_json(junk, None) is None


def test_tolerant_json_reads_an_object():
    from dashboard.fastapi_app import _tolerant_json
    assert _tolerant_json(b'{"a": 1}', {}) == {"a": 1}
    assert _tolerant_json('{"a": 1}', None) == {"a": 1}


@pytest.mark.parametrize("kind", ["health", "security"])
def test_normalize_v4_works_without_any_removed_field(kind):
    from dashboard.fastapi_app import _normalize_v4
    d = {"health_risk": "0.2", "sec_risk": "0.3", "health_label": "benign", "sec_label": "benign"}
    _normalize_v4(d, kind)
    assert d["risk_score"] in (0.2, 0.3)
    if kind == "health":
        assert d["explainability"] == {}


@pytest.mark.parametrize("junk", ["", "garbage", "[1,2]", "null"])
def test_normalize_v4_tolerates_a_malformed_legacy_attribution(junk):
    from dashboard.fastapi_app import _normalize_v4
    d = {"health_risk": "0.2", "field_attribution_json": junk}
    _normalize_v4(d, "health")
    assert d["explainability"] in ({}, [1, 2], None)


def test_event_details_model_has_no_required_removed_field():
    from dashboard.fastapi_app import EventDetails
    EventDetails.model_validate({"event_id": "e1"})        # no ci width, no explainability, no embeddings

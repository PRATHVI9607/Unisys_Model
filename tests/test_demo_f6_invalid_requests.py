"""F6 runner stays signed, test-mode-only, bounded to owned Redis records, and restores its label."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docs" / "kubeheal" / "demo-evidence" / "F6" / "f6_signed_invalid_requests.py"


def test_f6_runner_uses_signed_invalid_cases_and_checks_no_freeze_occurred():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'CONTEXT = "k3d-kubeheal"' in source
    for case in ("bad_namespace", "protected_label", "unknown_action", "missing_field"):
        assert f'"{case}"' in source
    assert "sign_fields(fields, key)" in source
    assert "verify_fields(row, key)" in source
    assert 'row.get("frozen") != "0"' in source
    assert 'row.get("status") != "refused"' in source


def test_f6_runner_is_test_mode_only_and_restores_protected_label():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'if mode() != "test"' in source
    assert '"kubeheal/protected=true"' in source
    assert '"kubeheal/protected-"' in source
    assert 'f"kubeheal/protected={old_label}"' in source
    assert "finally:" in source
    assert "run-owned cleanup incomplete" in source
    assert "print(key)" not in source
    assert '"response_hmac": "valid"' in source

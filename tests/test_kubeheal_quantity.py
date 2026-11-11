import pytest

from kubeheal.features.quantity import parse_cpu, parse_memory


@pytest.mark.parametrize("q,expected", [("500m", 0.5), ("2", 2.0), (1, 1.0), ("0.25", 0.25), ("100u", 1e-4), ("1e3m", 1.0)])
def test_parse_cpu(q, expected):
    assert parse_cpu(q) == pytest.approx(expected)


@pytest.mark.parametrize("q,expected", [
    ("256Mi", 256 * 2**20), ("1Gi", 2**30), ("1G", 1e9), ("128974848", 128974848),
    ("129e6", 129e6), ("500k", 5e5), ("1E", 1e18), (" 64Ki ", 64 * 1024),
])
def test_parse_memory(q, expected):
    assert parse_memory(q) == pytest.approx(expected)


@pytest.mark.parametrize("q", [None, "", "abc", "12Qi", "1.2.3", True])
def test_unparsable_is_none(q):
    assert parse_cpu(q) is None and parse_memory(q) is None

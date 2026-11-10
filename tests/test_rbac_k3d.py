"""P2 acceptance on the real cluster: skipped automatically when k3d-kubeheal is not reachable."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rbac_check  # noqa: E402


@pytest.mark.skipif(not rbac_check.cluster_reachable(), reason="k3d-kubeheal cluster not reachable")
def test_rbac_matrix():
    failures = rbac_check.run_checks()
    assert not failures, "\n".join(failures)

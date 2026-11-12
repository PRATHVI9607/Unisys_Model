"""P2 acceptance on the real cluster. Opt in explicitly; default test runs stay offline."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rbac_check  # noqa: E402


@pytest.mark.skipif(os.environ.get("KUBEHEAL_LIVE_RBAC_TEST") != "1",
                    reason="live cluster test; opt in with KUBEHEAL_LIVE_RBAC_TEST=1")
def test_rbac_matrix():
    if not rbac_check.cluster_reachable():
        pytest.skip("k3d-kubeheal cluster not reachable")
    failures = rbac_check.run_checks()
    assert not failures, "\n".join(failures)

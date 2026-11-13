"""F3b: the drift path never rewrites a PVC claim.

After a ransomware restore the Deployment points at the restored PVC and its images are pinned by digest, while
the golden baseline still holds the old claim name and the image tags, so the Health Agent sees drift. A drift
patch built from that diff would put the old (encrypted, forensic) PVC back. The Executor refuses before any
write: a patch may not change which PVC a volume claims."""
import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from agents.executor import drift
from test_remediation_drift import CPU, Scenario

CLAIM = "template.spec.volumes[0].persistentVolumeClaim.claimName"
IMAGE = "template.spec.containers[0].image"


def _volumes(claim):
    return [{"name": "data", "persistentVolumeClaim": {"claimName": claim}}]


def restored_scenario():
    """Golden claims `data-old`; live (after a restore) claims `data-restore-inc-1`; CPU drift is unrelated."""
    s = Scenario()
    s.golden["spec"]["template"]["spec"]["volumes"] = _volumes("data-old")
    live = s.c.workloads[("Deployment", "web")]
    live["spec"]["template"]["spec"]["volumes"] = _volumes("data-restore-inc-1")
    s.live_before = copy.deepcopy(drift.drift_view(live["spec"]))
    return s


def test_a_patch_that_would_put_the_old_pvc_back_escalates_before_any_write():
    s = restored_scenario()
    out = s.go(patch_fields=[CLAIM])
    assert out.startswith("escalated:patch_changes_volume_claim")
    assert s.c.writes() == [] and "rollback_point_saved" not in s.steps()


def test_a_patch_of_other_fields_still_runs_when_the_claims_differ_from_the_baseline():
    s = restored_scenario()
    assert s.go(field=CPU, patch_fields=[CPU]) == "patched_kept"
    live = s.live_spec()["template"]["spec"]
    assert live["volumes"] == _volumes("data-restore-inc-1")                 # the restored claim was left alone
    assert live["containers"][0]["resources"]["limits"]["cpu"] == "500m"


def test_mixed_candidates_escalate_rather_than_patch_the_part_that_is_allowed():
    s = restored_scenario()
    out = s.go(patch_fields=[CPU, CLAIM])
    assert out.startswith("escalated:patch_changes_volume_claim") and s.c.writes() == []


@pytest.mark.parametrize("live_vols,target_vols", [
    (_volumes("a"), _volumes("b")),                                           # claim changed
    (_volumes("a"), []),                                                      # claimed volume dropped
    ([], _volumes("a")),                                                      # claimed volume added
    (_volumes("a"), [{"name": "data", "emptyDir": {}}]),                      # claim replaced by another source
])
def test_any_change_of_the_claimed_volumes_is_refused(live_vols, target_vols):
    raw = {"selector": {"matchLabels": {"app": "web"}}}
    live_view = {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"volumes": live_vols}}}
    target = {"template": {"metadata": {"labels": {"app": "web"}}, "spec": {"volumes": target_vols}}}
    with pytest.raises(drift.PlanError, match="patch_changes_volume_claim"):
        drift.validate_patch_target(raw, live_view, target)


def test_an_unchanged_claim_and_a_non_claim_volume_change_are_allowed():
    raw = {"selector": {"matchLabels": {"app": "web"}}}
    cfg_a = {"name": "seed", "configMap": {"name": "a"}}
    cfg_b = {"name": "seed", "configMap": {"name": "b"}}
    live_view = {"template": {"metadata": {"labels": {"app": "web"}},
                              "spec": {"volumes": _volumes("a") + [cfg_a]}}}
    target = {"template": {"metadata": {"labels": {"app": "web"}},
                           "spec": {"volumes": _volumes("a") + [cfg_b]}}}
    drift.validate_patch_target(raw, live_view, target)                      # no error

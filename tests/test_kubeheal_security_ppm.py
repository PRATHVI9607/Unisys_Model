import pytest

from kubeheal.correlation import _is_config_cause
from kubeheal.features.security import open_syscall


@pytest.mark.parametrize("flags,want", [("1", "open_r"), ("2", "open_w"), ("3", "open_w"), ("5", "open_w"),
                                        ("9", "open_w"), ("257", "open_w"), ("O_RDONLY|O_CLOEXEC", "open_r")])
def test_open_syscall_ppm_flags(flags, want):
    assert open_syscall("openat", flags) == want


def test_config_cause_exact_segment():
    assert not _is_config_cause("spec.template.spec.containers[0].imagePullPolicy")
    assert _is_config_cause("spec.template.spec.containers[0].image")
    assert _is_config_cause("spec.template.spec.containers[0].resources.limits.cpu")

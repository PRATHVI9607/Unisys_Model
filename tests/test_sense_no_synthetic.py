"""P5-S4: live agent code fabricates no syscall events and reads no hard-coded fake data paths."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE_DIRS = ["agents/security_agent", "agents/health_agent"]

FORBIDDEN = [
    (re.compile(r"synth_events|def\s+synth"), "synthetic syscall fabrication"),
    (re.compile(r"/data/test_|test_\{i\}"), "hard-coded fake data files"),
    (re.compile(r"/data/file_\{i\}|/var/log/app_\{i\}"), "fabricated event paths"),
    (re.compile(r"random\.(choice|sample|random|uniform|randint)"), "randomised signal generation"),
    (re.compile(r"^\s*import random\b", re.M), "random import in a live path"),
]


def _live_files():
    for d in LIVE_DIRS:
        for p in (ROOT / d).rglob("*.py"):
            if "__pycache__" not in p.parts:
                yield p


def test_live_agent_code_has_no_fabrication():
    offenders = []
    for p in _live_files():
        src = p.read_text(encoding="utf-8")
        for rx, why in FORBIDDEN:
            if rx.search(src):
                offenders.append(f"{p.relative_to(ROOT)}: {why}")
    assert not offenders, offenders


def test_synth_events_is_gone_from_the_agent_module():
    from agents.security_agent import agent
    assert not hasattr(agent, "synth_events")


def test_security_agent_still_has_no_kubernetes_write_or_kill_call():
    """Complements tests/test_no_writes_outside_executor.py for the new modules of this phase."""
    for name in ("entropy_sampler.py", "syscall_window.py", "falco_client.py", "agent.py"):
        src = (ROOT / "agents/security_agent" / name).read_text(encoding="utf-8")
        for needle in ("os.kill", "os.killpg", "create_namespaced", "patch_namespaced",
                       "delete_namespaced", "replace_namespaced", "os.remove", "os.unlink"):
            assert needle not in src, (name, needle)

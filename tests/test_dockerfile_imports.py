"""Every agent image must contain what its entry package imports at module level.

A cluster install (V5 Task 4, 2026-11-12) found the Executor image crash-looping with `No module named 'kubeheal'`:
agents/executor/drift.py had started to import kubeheal.posture, and Dockerfile.executor copied only agents/. No unit
test can see that, because the tests run in a full checkout. This test follows the imports of each image's entry
package (transitively, through repo modules) and requires (a) a COPY line for every top-level repo directory it
reaches and (b) an installed package for every module-level third-party import. Imports inside a function are lazy and
optional and are not required (they are the guarded optional imports, for example the gRPC stubs of the Falco client).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_dockerfiles_security import ROOT, _imports_of, _module_file   # noqa: E402

# image Dockerfile -> the entry package directories (relative to the repo root)
IMAGES = {
    "Dockerfile.security": ["agents/security_agent"],
    "Dockerfile.health": ["agents/health_agent"],
    "Dockerfile.fusion": ["agents/fusion_agent"],
    "Dockerfile.executor": ["agents/executor"],
    "Dockerfile.dashboard": ["dashboard"],
}


# Files an image deliberately does not copy. The Health Agent image copies two torch-free modules of models/health_model
# one by one and leaves the package __init__ (it imports the torch encoder) out: models/ is a PEP 420 namespace package
# there (see the comment in dockerfiles/Dockerfile.health).
DELIBERATELY_NOT_COPIED = {"Dockerfile.health": {"models/health_model/__init__.py"}}


def reachable(entry_dirs):
    queue = [p for d in entry_dirs for p in sorted((ROOT / d).glob("*.py"))]
    seen, external = set(), set()
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        for name, module_level in _imports_of(path):
            top = name.split(".")[0]
            target = _module_file(name)
            if target is not None:
                queue.append(target)
                for parent in range(1, name.count(".") + 1):
                    init = _module_file(".".join(name.split(".")[:parent]))
                    if init is not None:
                        queue.append(init)
            elif (ROOT / top).is_dir() or _module_file(top) is not None:
                continue
            elif top not in sys.stdlib_module_names and module_level:
                external.add(top)
    return seen, external


def is_copied(rel: str, text: str) -> bool:
    """True when a COPY line covers the file: the file itself or any ancestor directory, to the same place."""
    parts = rel.split("/")
    candidates = [f"COPY {rel} /app/{rel}"]
    for i in range(1, len(parts)):
        d = "/".join(parts[:i])
        candidates.append(f"COPY {d}/ /app/{d}/")
    return any(c in text for c in candidates)


@pytest.mark.parametrize("image", sorted(IMAGES))
def test_the_image_copies_every_repo_file_its_entry_imports(image):
    text = (ROOT / "dockerfiles" / image).read_text(encoding="utf-8")
    seen, _external = reachable(IMAGES[image])
    missing = sorted(rel for rel in (p.relative_to(ROOT).as_posix() for p in seen)
                     if not is_copied(rel, text) and rel not in DELIBERATELY_NOT_COPIED.get(image, set()))
    assert not missing, f"{image}: imported but not copied: {missing}"


@pytest.mark.parametrize("image", sorted(IMAGES))
def test_the_image_installs_every_third_party_package_its_entry_imports(image):
    text = (ROOT / "dockerfiles" / image).read_text(encoding="utf-8").lower().replace("_", "-")
    _seen, external = reachable(IMAGES[image])
    for name in sorted(external):
        assert name.lower().replace("_", "-") in text, f"{image}: {name} is imported but not installed"

from pathlib import Path


def test_security_dockerfile_copies_every_top_level_agent_package():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "dockerfiles" / "Dockerfile.security").read_text(encoding="utf-8")
    assert "COPY agents/ /app/agents/" in dockerfile
    assert "COPY kubeheal/ /app/kubeheal/" in dockerfile


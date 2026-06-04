"""Contract: the v4 fields the agents PUBLISH must cover what Fusion READS.
Guards against the v3↔v4 schema drift that silently broke the pipeline."""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

HEALTH_SRC = (ROOT/"agents/health_agent/agent.py").read_text()
SEC_SRC    = (ROOT/"agents/security_agent/agent.py").read_text()
FUSION_SRC = (ROOT/"agents/fusion_agent/agent.py").read_text()

def published_keys(src, stream):
    # keys inside the payload dict the agent xadds (quoted "key":)
    return set(re.findall(r'"([a-z0-9_]+)":', src))

def test_health_publishes_fusion_fields():
    pub = published_keys(HEALTH_SRC, "health")
    for need in ["health_risk","health_label","health_ci_width","top_field",
                 "namespace_tier","health_embedding_b64","event_id"]:
        assert need in pub, f"health agent must publish {need}"

def test_security_publishes_fusion_fields():
    pub = published_keys(SEC_SRC, "security")
    for need in ["sec_risk","sec_label","sec_ci_width","top_syscall",
                 "namespace_tier","security_embedding_b64","event_id"]:
        assert need in pub, f"security agent must publish {need}"

def test_no_stale_v3_endpoints():
    # no agent should reference the removed v3 monolith service
    for src in (HEALTH_SRC, SEC_SRC, FUSION_SRC):
        assert "dit-sec-server" not in src

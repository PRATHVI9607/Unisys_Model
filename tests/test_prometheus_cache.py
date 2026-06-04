import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def test_metric_columns_count():
    from models.health_model.metric_bilstm_encoder import METRIC_COLUMNS, NUM_METRICS, INPUT_SEQUENCE_LENGTH
    assert NUM_METRICS==15 and len(METRIC_COLUMNS)==15 and INPUT_SEQUENCE_LENGTH==60

def test_cache_dict_exists():
    from agents.health_agent import prometheus_client as pc
    assert isinstance(pc._prometheus_cache, dict)

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import torch

def test_yaml_gat_shapes():
    from models.health_model.yaml_gat_encoder import YAMLGATEncoder, yaml_diff_to_graph
    old={'spec':{'template':{'spec':{'containers':[{'name':'a','resources':{'limits':{'cpu':'500m'}}}]}}}}
    new={'spec':{'template':{'spec':{'containers':[{'name':'a','resources':{'limits':{'cpu':'50m'}}}]}}}}
    g=yaml_diff_to_graph(old,new); emb,imp=YAMLGATEncoder()(g)
    assert emb.shape[-1]==128 and abs(float(imp.sum())-1.0)<1e-3

def test_bilstm_shape():
    from models.health_model.metric_bilstm_encoder import MetricBiLSTMEncoder
    assert MetricBiLSTMEncoder()(torch.zeros(2,60,15)).shape==(2,64)

def test_conv1d_shape():
    from models.security_model.entropy_conv1d_encoder import EntropyConv1DEncoder
    assert EntropyConv1DEncoder()(torch.rand(2,30)).shape==(2,64)

def test_security_model_predict():
    from models.security_model.security_model import SecurityModel
    r=SecurityModel().predict([{'syscall':'write','fd_path':'/d/f'}]*20,[7.5]*10)
    assert 0.0<=r['risk_score']<=1.0 and len(r['security_embedding'])==64

def test_dcm_correlate_range():
    from models.dcm.cross_modal_attention import CrossModalAttention
    s=CrossModalAttention().correlate([0.1]*128,[0.2]*64); assert 0.0<=s<=1.0

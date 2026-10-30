import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(ROOT / 'agent'))

from app import db, main  # noqa: E402

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'events.db')
    models = tmp_path / 'models'
    models.mkdir()
    shutil.copy2(BACKEND / 'models' / 'model.joblib', models / 'model.joblib')
    monkeypatch.setattr(main, 'MODEL_DIR', models)
    monkeypatch.setattr(main, 'FIREWALL_MODE', 'SIMULATE_BLOCK')
    main.training_state = {'state': 'idle', 'error': None, 'started_at': None, 'finished_at': None, 'metrics': None, 'traffic_source': None}
    with TestClient(main.app) as instance:
        yield instance

@pytest.fixture
def configured_policy(client):
    network = client.post('/api/v1/access-policy/networks', json={'label':'Office network','cidr':'10.0.0.0/24','kind':'office'})
    service = client.post('/api/v1/access-policy/resources', json={'name':'Internal service','destination_cidr':'192.168.1.50/32','protocol':'TCP','ports':'22,443'})
    assert network.status_code == 201 and service.status_code == 201

@pytest.fixture
def flow():
    return {'agent_id':'unit-test', 'traffic_source':'capture', 'src_ip':'8.8.8.8', 'dst_ip':'192.168.1.50', 'src_port':51425, 'dst_port':443, 'protocol':'TCP', 'flow_duration':12., 'packet_count':40, 'byte_count':28000, 'iat_mean':.3, 'average_packet_size':700., 'syn_count':1, 'ack_count':30, 'syn_ack_ratio':1/30}

@pytest.fixture
def normal_prediction(monkeypatch):
    result = {'classification':'Normal','attack_type':'Normal','confidence':.05,'anomaly_score':.1,'detection_source':'supervised','probabilities':{'Normal':.95}}
    monkeypatch.setattr(main.model, 'predict', lambda _: result.copy())
    return result

@pytest.fixture
def malicious_prediction(monkeypatch):
    result = {'classification':'Malicious','attack_type':'DDoS_SYN_Flood','confidence':.92,'anomaly_score':.2,'detection_source':'supervised','probabilities':{'Normal':.08,'DDoS_SYN_Flood':.92}}
    monkeypatch.setattr(main.model, 'predict', lambda _: result.copy())
    return result

@pytest.fixture
def anomaly_prediction(monkeypatch):
    result = {'classification':'Malicious','attack_type':'Unknown_Anomaly','confidence':.82,'anomaly_score':.82,'detection_source':'anomaly','probabilities':{'Normal':.8}}
    monkeypatch.setattr(main.model, 'predict', lambda _: result.copy())
    return result

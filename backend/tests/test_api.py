import io
import time
from pathlib import Path

import pytest
from scapy.all import IP, TCP, wrpcap

from app import db, main


def post(client, flow):
    response = client.post('/api/v1/flows/process', json=flow)
    assert response.status_code == 200, response.text
    return response.json()

def test_health_and_real_model(client, flow):
    health = client.get('/health').json()
    assert health['status'] == 'ok' and health['model_loaded'] and health['firewall_mode'] == 'SIMULATE_BLOCK'
    info = client.get('/api/v1/model/info').json()
    assert info['metrics']['source'] == 'synthetic' and info['metrics']['test_rows'] == 6000
    prediction = post(client, flow)
    assert prediction['classification'] in {'Normal', 'Malicious', 'Policy_Denied'}
    assert 0 <= prediction['confidence'] <= 1

def test_short_benign_shape_regression(client):
    # One loopback-shaped case, not a real-world accuracy measurement.
    short = {'flow_duration':.0017,'packet_count':14,'byte_count':1232,'iat_mean':.00013,'average_packet_size':88,'syn_count':2,'ack_count':12,'syn_ack_ratio':2/12}
    prediction = main.model.predict(short)
    assert prediction['classification'] == 'Normal'

def test_validation_rejects_bad_flows(client, flow):
    assert client.post('/api/v1/flows/process', json={**flow, 'src_ip':'not-an-ip'}).status_code == 422
    assert client.post('/api/v1/flows/process', json={**flow, 'packet_count':-1}).status_code == 422
    assert client.post('/api/v1/flows/process', json={**flow, 'traffic_source':'pcap'}).status_code == 422

def test_new_policy_starts_without_unconfigured_scopes(client, flow, normal_prediction):
    policy = client.get('/api/v1/access-policy').json()
    assert policy['settings']['mode'] == 'monitor'
    assert policy['trusted_networks'] == [] and policy['resources'] == []
    result = post(client, flow)
    assert result['policy_action'] == 'allow' and result['action'] == 'ALLOWED'


def test_only_exact_legacy_starter_scopes_are_removed(client):
    with db.connect() as conn:
        conn.execute("INSERT INTO trusted_networks(label,cidr,kind,enabled,source,created_at) VALUES ('Example office','10.0.0.0/24','office',1,'example',0)")
        conn.execute("INSERT INTO protected_resources(name,destination_cidr,protocol,ports,enabled,source,created_at) VALUES ('Example internal service','192.168.1.50/32','TCP','[\"22\",\"443\"]',1,'example',0)")
        conn.execute("INSERT INTO trusted_networks(label,cidr,kind,enabled,source,created_at) VALUES ('Branch network','10.10.0.0/24','office',1,'manual',0)")
        conn.execute("INSERT INTO protected_resources(name,destination_cidr,protocol,ports,enabled,source,created_at) VALUES ('Customer service','192.168.5.5/32','TCP','[\"443\"]',1,'manual',0)")
        conn.execute("UPDATE policy_settings SET mode='enforce' WHERE id=1")
    db.init_db()
    policy = client.get('/api/v1/access-policy').json()
    assert [n['label'] for n in policy['trusted_networks']] == ['Branch network']
    assert [r['name'] for r in policy['resources']] == ['Customer service']
    assert policy['settings']['mode'] == 'enforce'


def test_monitor_records_policy_separately(client, flow, normal_prediction, configured_policy):
    result = post(client, flow)
    assert result['classification'] == 'Normal' and result['policy_action'] == 'monitor'
    assert result['action'] == 'POLICY_MONITORED'
    assert client.get('/api/v1/blocklist').json() == []
    s = client.get('/api/v1/summary?source=capture').json()
    assert s['policyMonitored'] == 1 and s['totalAlerts'] == 0

def test_policy_deny_is_not_ml_or_global_block(client, flow, normal_prediction, configured_policy):
    response = client.put('/api/v1/access-policy/settings', json={'enabled':True,'mode':'enforce','egress_enabled':False,'egress_cidrs':[]})
    assert response.status_code == 200
    result = post(client, flow)
    assert result['classification'] == 'Policy_Denied' and result['detection_source'] == 'access_policy'
    assert result['action'] == 'POLICY_DENY_RECORDED' and result['policy_action'] == 'deny'
    assert client.get('/api/v1/blocklist').json() == []
    s = client.get('/api/v1/summary').json()
    assert s['policyOnly'] == 1 and s['mlAlerts'] == 0

def test_trusted_source_still_gets_ml_inspected(client, flow, malicious_prediction, configured_policy):
    result = post(client, {**flow, 'src_ip':'10.0.0.23'})
    assert result['trusted_source'] is True and result['policy_action'] == 'allow'
    assert result['classification'] == 'Malicious' and result['action'] == 'BLOCKED_SIMULATED'
    block = client.get('/api/v1/blocklist').json()[0]
    assert block['traffic_source'] == 'capture' and block['enforceable'] is True

def test_alert_only_never_adds_block(client, flow, malicious_prediction, monkeypatch):
    monkeypatch.setattr(main, 'FIREWALL_MODE', 'ALERT_ONLY')
    assert post(client, flow)['action'] == 'ALERT_ONLY'
    assert client.get('/api/v1/blocklist').json() == []

def test_sources_and_heartbeats_are_separate(client, flow, malicious_prediction):
    post(client, flow)
    post(client, {**flow, 'traffic_source':'synthetic', 'src_ip':'1.1.1.1'})
    post(client, {**flow, 'traffic_source':'unknown', 'src_ip':'9.9.9.9'})
    assert client.post('/api/v1/agents/heartbeat', json={'agent_id':'demo','traffic_source':'synthetic'}).status_code == 200
    assert client.post('/api/v1/agents/heartbeat', json={'agent_id':'real','traffic_source':'capture','interface':'eth0'}).status_code == 200
    all_summary = client.get('/api/v1/summary').json(); real = client.get('/api/v1/summary?source=capture').json()
    assert all_summary['totalEvents'] == 3 and all_summary['activeAgents'] == 2
    assert real['totalEvents'] == 1 and real['activeAgents'] == 1
    assert len(client.get('/api/v1/alerts?source=synthetic').json()) == 1
    blocks = {item['ip']:item for item in client.get('/api/v1/blocklist').json()}
    assert blocks['8.8.8.8']['enforceable'] and not blocks['1.1.1.1']['enforceable'] and not blocks['9.9.9.9']['enforceable']
    assert client.get('/api/v1/summary?source=bad').status_code == 422

def test_synthetic_cannot_override_active_capture_block(client, flow, malicious_prediction):
    post(client, flow)
    post(client, {**flow, 'traffic_source':'synthetic'})
    blocks = client.get('/api/v1/blocklist').json()
    assert len(blocks) == 1 and blocks[0]['traffic_source'] == 'capture' and blocks[0]['enforceable']

def test_manual_blocks_reject_local_addresses_and_can_be_removed(client):
    assert client.post('/api/v1/blocklist', json={'ip':'127.0.0.1'}).status_code == 422
    assert client.post('/api/v1/blocklist', json={'ip':'1.1.1.1','reason':'Test'}).status_code == 200
    block = client.get('/api/v1/blocklist?source=synthetic').json()[0]
    assert block['source'] == 'manual' and block['enforceable']
    assert client.delete('/api/v1/blocklist/1.1.1.1').status_code == 200
    assert client.delete('/api/v1/blocklist/1.1.1.1').status_code == 404

def test_policy_validates_narrow_scopes(client):
    assert client.post('/api/v1/access-policy/networks', json={'label':'Too wide','cidr':'0.0.0.0/0','kind':'office'}).status_code == 422
    assert client.post('/api/v1/access-policy/networks', json={'label':'Office','cidr':'10.1.2.0/24','kind':'office'}).status_code == 201
    assert client.post('/api/v1/access-policy/resources', json={'name':'Public','destination_cidr':'8.8.8.0/24','protocol':'TCP','ports':'443'}).status_code == 422
    result = client.post('/api/v1/access-policy/resources', json={'name':'Database','destination_cidr':'10.2.3.4/32','protocol':'TCP','ports':'5432, 8000-8002'})
    assert result.status_code == 201
    assert client.post('/api/v1/access-policy/resources', json={'name':'Bad port','destination_cidr':'10.2.3.4/32','ports':'70000'}).status_code == 422
    assert client.put('/api/v1/access-policy/settings', json={'enabled':True,'mode':'enforce','egress_enabled':True,'egress_cidrs':[]}).status_code == 422
    assert client.put('/api/v1/access-policy/settings', json={'enabled':True,'mode':'monitor','egress_enabled':True,'egress_cidrs':['192.168.4.0/24']}).status_code == 200

def test_network_toggle_and_delete(client):
    created = client.post('/api/v1/access-policy/networks', json={'label':'VPN','cidr':'10.5.0.0/24','kind':'vpn'}).json()['id']
    assert client.patch(f'/api/v1/access-policy/networks/{created}', json={'enabled':False}).status_code == 200
    assert [n for n in client.get('/api/v1/access-policy').json()['trusted_networks'] if n['id'] == created][0]['enabled'] is False
    assert client.delete(f'/api/v1/access-policy/networks/{created}').status_code == 200
    assert client.delete(f'/api/v1/access-policy/networks/{created}').status_code == 404

def test_offline_pcap_does_not_create_block(client, tmp_path, malicious_prediction):
    path = tmp_path / 'flow.pcap'; wrpcap(str(path), [IP(src='8.8.8.8',dst='192.168.1.50')/TCP(sport=51234,dport=443,flags='S')])
    response = client.post('/api/v1/pcap/analyze', files={'file':('flow.pcap',path.read_bytes(),'application/octet-stream')})
    assert response.status_code == 200, response.text
    assert response.json()['total_flows'] == 1 and response.json()['malicious_flows'] == 1
    assert response.json()['response'] == 'offline_no_firewall_changes'
    assert client.get('/api/v1/blocklist').json() == []
    assert client.get('/api/v1/summary?source=pcap').json()['totalEvents'] == 1
    assert client.get('/api/v1/events?source=pcap').json()[0]['action'] == 'OFFLINE_ANALYSIS'

def test_pcap_limits_and_bad_uploads(client, monkeypatch):
    assert client.post('/api/v1/pcap/analyze', files={'file':('bad.txt',b'no','text/plain')}).status_code == 400
    assert client.post('/api/v1/pcap/analyze', files={'file':('bad.pcap',b'not a pcap','application/octet-stream')}).status_code == 400
    monkeypatch.setattr(main, 'MAX_PCAP_BYTES', 5)
    assert client.post('/api/v1/pcap/analyze', files={'file':('big.pcap',b'123456','application/octet-stream')}).status_code == 413

def test_anomaly_review_is_source_scoped_and_reversible(client, flow, anomaly_prediction):
    first = post(client, flow)
    assert first['detection_source'] == 'anomaly' and first['pattern_id']
    pid = first['pattern_id']
    assert len(client.get('/api/v1/patterns?source=capture').json()) == 1
    assert client.post(f'/api/v1/patterns/{pid}/approve', json={'label':'Normal'}).status_code == 422
    assert client.post(f'/api/v1/patterns/{pid}/approve', json={'label':'Analyst review'}).status_code == 200
    learned = post(client, flow)
    assert learned['detection_source'] == 'learned_pattern' and learned['attack_type'] == 'Analyst_review'
    synthetic = post(client, {**flow, 'traffic_source':'synthetic'})
    assert synthetic['detection_source'] == 'anomaly'
    assert client.get('/api/v1/summary?source=capture').json()['feedbackExamples'] == 1
    assert client.post(f'/api/v1/patterns/{pid}/reject').status_code == 200
    assert client.get('/api/v1/rules?source=capture').json()[0]['enabled'] is False
    assert client.get('/api/v1/summary?source=capture').json()['feedbackExamples'] == 0

def test_export_is_source_scoped(client, flow, malicious_prediction):
    post(client, flow); post(client, {**flow, 'traffic_source':'synthetic', 'src_ip':'1.1.1.1'})
    response = client.get('/api/v1/alerts/export.csv?source=synthetic')
    assert response.status_code == 200 and 'text/csv' in response.headers['content-type']
    assert '1.1.1.1' in response.text and '8.8.8.8' not in response.text

def test_csv_export_neutralizes_spreadsheet_formulas(client, flow, malicious_prediction):
    post(client, {**flow, 'agent_id':'=1+1'})
    response = client.get('/api/v1/alerts/export.csv')
    assert response.status_code == 200
    assert "'=1+1" in response.text


def test_model_candidate_activate_rollback(client, flow, anomaly_prediction):
    assert client.post('/api/v1/model/retrain?source=capture').status_code == 400
    pid = post(client, flow)['pattern_id']
    client.post(f'/api/v1/patterns/{pid}/approve', json={'label':'Analyst review'})
    assert client.post('/api/v1/model/retrain?source=capture').status_code == 202
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = client.get('/api/v1/model/retrain/status').json()
        if state['state'] != 'running': break
        time.sleep(.2)
    assert state['state'] == 'ready', state
    assert state['metrics']['source'] == 'synthetic baseline + capture feedback'
    candidate_info = client.get('/api/v1/model/info').json()
    assert candidate_info['candidate_available'] and candidate_info['candidate_metrics']['test_rows'] > 0
    assert client.post('/api/v1/model/activate').status_code == 200
    assert client.get('/api/v1/model/info').json()['rollback_available']
    assert client.post('/api/v1/model/rollback').status_code == 200
    assert client.get('/api/v1/model/info').json()['metrics']['source'] == 'synthetic'

def test_api_key_guards_mutations_only(client, flow, monkeypatch):
    monkeypatch.setattr(main, 'API_KEY', 'test-key')
    assert client.get('/api/v1/summary').status_code == 200
    assert client.post('/api/v1/flows/process', json=flow).status_code == 401
    assert client.post('/api/v1/agents/heartbeat', headers={'X-API-Key':'test-key'}, json={'agent_id':'test','traffic_source':'capture'}).status_code == 200

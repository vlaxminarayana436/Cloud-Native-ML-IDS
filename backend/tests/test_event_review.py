import csv
import io

from app import db, main
from app.features import BASE_FEATURES


def submit(client, flow):
    response = client.post('/api/v1/flows/process', json=flow)
    assert response.status_code == 200, response.text
    return response.json()


def normal_result():
    return {'classification': 'Normal', 'attack_type': 'Normal', 'confidence': .05,
            'anomaly_score': .1, 'detection_source': 'supervised', 'probabilities': {'Normal': .95}}


def test_flow_reviews_are_separate_from_detection_rules_and_training(client, flow, anomaly_prediction, monkeypatch):
    monkeypatch.setattr(main, 'FIREWALL_MODE', 'ALERT_ONLY')
    flagged = submit(client, flow)
    monkeypatch.setattr(main.model, 'predict', lambda _: normal_result())
    normal = submit(client, {**flow, 'src_ip': '1.1.1.1'})
    synthetic = submit(client, {**flow, 'traffic_source': 'synthetic'})
    flagged_id, normal_id, synthetic_id = flagged['event_id'], normal['event_id'], synthetic['event_id']

    pending = client.get('/api/v1/reviews?source=capture&detection=alerts&status=unreviewed').json()
    assert [item['id'] for item in pending['items']] == [flagged_id]
    assert pending['items'][0]['review'] is None
    assert pending['summary'] == {'total': 2, 'unreviewed': 2, 'benign': 0, 'malicious': 0, 'unsure': 0}

    saved = client.put(f'/api/v1/events/{flagged_id}/review', json={'label': 'benign', 'note': '  Confirmed using context  '})
    assert saved.status_code == 200
    assert saved.json()['review']['note'] == 'Confirmed using context'
    assert client.put(f'/api/v1/events/{normal_id}/review', json={'label': 'unsure'}).status_code == 200
    assert client.put(f'/api/v1/events/{synthetic_id}/review', json={'label': 'malicious'}).status_code == 200
    capture = client.get('/api/v1/reviews?source=capture&detection=all&status=all').json()
    assert capture['summary'] == {'total': 2, 'unreviewed': 0, 'benign': 1, 'malicious': 0, 'unsure': 1}
    by_id = {item['id']: item for item in capture['items']}
    assert by_id[flagged_id]['classification'] == 'Malicious'
    assert by_id[flagged_id]['detection_source'] == 'anomaly'
    assert by_id[flagged_id]['action'] == 'ALERT_ONLY'
    assert by_id[flagged_id]['review']['label'] == 'benign'
    assert by_id[normal_id]['classification'] == 'Normal' and by_id[normal_id]['review']['label'] == 'unsure'
    assert client.get('/api/v1/reviews?source=capture&detection=normal&status=unsure').json()['items'][0]['id'] == normal_id
    assert client.get('/api/v1/reviews?source=capture&detection=all&status=malicious').json()['items'] == []
    assert client.get('/api/v1/reviews?source=synthetic&detection=all&status=reviewed').json()['items'][0]['id'] == synthetic_id

    # These assessments are not learned-pattern approvals, retraining examples,
    # model predictions, or firewall entries.
    assert client.get('/api/v1/rules').json() == []
    assert client.get('/api/v1/blocklist').json() == []
    assert client.get('/api/v1/summary').json()['feedbackExamples'] == 0
    assert client.post('/api/v1/model/retrain').status_code == 400
    assert all(pattern['status'] == 'pending' for pattern in client.get('/api/v1/patterns').json())
    monkeypatch.setattr(main.model, 'predict', lambda _: anomaly_prediction.copy())
    repeated = submit(client, flow)
    assert repeated['classification'] == 'Malicious' and repeated['detection_source'] == 'anomaly'
    assert repeated['action'] == 'ALERT_ONLY'  # The benign assessment did not suppress later alerts.

    # Existing databases can be initialized again, and corrected/cleared labels persist.
    db.init_db()
    assert client.get('/api/v1/reviews?source=capture&detection=all&status=benign').json()['items'][0]['id'] == flagged_id
    assert client.put(f'/api/v1/events/{flagged_id}/review', json={'label': 'malicious', 'note': 'changed'}).status_code == 200
    assert client.get('/api/v1/reviews?source=capture&detection=all&status=malicious').json()['items'][0]['review']['note'] == 'changed'
    assert client.delete(f'/api/v1/events/{flagged_id}/review').status_code == 200
    assert client.delete(f'/api/v1/events/{flagged_id}/review').status_code == 404
    assert flagged_id in [item['id'] for item in client.get('/api/v1/reviews?source=capture&detection=all&status=unreviewed').json()['items']]


def test_existing_database_upgrades_without_losing_events(client, flow, normal_prediction):
    event_id = submit(client, flow)['event_id']
    # Simulate a pre-review database and then start the new schema migration.
    with db.connect() as conn:
        conn.execute('DROP TABLE event_reviews')
    db.init_db()
    db.init_db()  # Startup is idempotent.
    records = client.get('/api/v1/reviews?source=capture&detection=all&status=unreviewed').json()['items']
    assert [item['id'] for item in records] == [event_id]
    assert client.put(f'/api/v1/events/{event_id}/review', json={'label': 'unsure'}).status_code == 200
    assert client.get('/api/v1/events?source=capture').json()[0]['classification'] == 'Normal'


def test_review_validation_and_optional_mutation_key(client, flow, normal_prediction, monkeypatch):
    event_id = submit(client, flow)['event_id']
    url = f'/api/v1/events/{event_id}/review'
    assert client.put(url, json={'label': 'Normal'}).status_code == 422
    assert client.put(url, json={'label': 'benign', 'note': 'x' * 501}).status_code == 422
    assert client.put('/api/v1/events/999999/review', json={'label': 'unsure'}).status_code == 404
    for query in ('source=invalid', 'detection=bad', 'status=bad', 'before_id=0', 'limit=101'):
        assert client.get('/api/v1/reviews?' + query).status_code == 422

    monkeypatch.setattr(main, 'API_KEY', 'review-test-key')
    assert client.put(url, json={'label': 'benign'}).status_code == 401
    assert client.put(url, json={'label': 'benign'}, headers={'X-API-Key': 'wrong'}).status_code == 401
    assert client.get('/api/v1/reviews?detection=all&status=all').status_code == 200
    assert client.put(url, json={'label': 'benign'}, headers={'X-API-Key': 'review-test-key'}).status_code == 200
    assert client.delete(url).status_code == 401
    assert client.delete(url, headers={'X-API-Key': 'review-test-key'}).status_code == 200


def test_review_pagination_is_stable_when_new_flows_arrive(client, flow, normal_prediction):
    ids = [submit(client, flow)['event_id'] for _ in range(5)]
    first = client.get('/api/v1/reviews?source=capture&detection=normal&status=all&limit=2').json()
    assert [item['id'] for item in first['items']] == ids[::-1][:2]
    assert first['has_more'] and first['next_before_id'] == ids[-2]
    newest = submit(client, flow)['event_id']
    second = client.get(f"/api/v1/reviews?source=capture&detection=normal&status=all&limit=2&before_id={first['next_before_id']}").json()
    assert [item['id'] for item in second['items']] == ids[::-1][2:4]
    third = client.get(f"/api/v1/reviews?source=capture&detection=normal&status=all&limit=2&before_id={second['next_before_id']}").json()
    assert [item['id'] for item in third['items']] == [ids[0]]
    assert not third['has_more'] and third['next_before_id'] is None
    assert newest not in [item['id'] for item in first['items'] + second['items'] + third['items']]
    assert third['summary']['total'] == 6  # Summary covers the full source, not this page.


def test_feature_export_is_allowlisted_and_respects_filters(client, flow, anomaly_prediction, monkeypatch):
    monkeypatch.setattr(main, 'FIREWALL_MODE', 'ALERT_ONLY')
    private = {**flow, 'agent_id': '=private-host.example', 'protocol': 'private-host.example'}
    event_id = submit(client, private)['event_id']
    submit(client, {**flow, 'traffic_source': 'synthetic'})
    assert client.put(f'/api/v1/events/{event_id}/review', json={'label': 'benign', 'note': '@private-note.example'}).status_code == 200
    response = client.get('/api/v1/reviews/export.csv?source=capture&detection=all&status=reviewed')
    assert response.status_code == 200 and response.headers['x-export-truncated'] == 'false'
    assert 'text/csv' in response.headers['content-type']
    text = response.text
    for secret in ('8.8.8.8', '192.168.1.50', 'private-host.example', 'PRIVATE-HOST.EXAMPLE', 'private-note.example', 'unit-test'):
        assert secret not in text
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 1
    assert list(rows[0]) == ['traffic_source', 'prediction', 'detector', 'protocol', 'from_port_443', 'to_port_443', 'anomaly_score', *BASE_FEATURES, 'analyst_label']
    assert rows[0]['traffic_source'] == 'capture' and rows[0]['protocol'] == 'OTHER'
    assert rows[0]['prediction'] == 'Malicious' and rows[0]['analyst_label'] == 'benign'
    assert rows[0]['from_port_443'] == 'False' and rows[0]['to_port_443'] == 'True'
    assert float(rows[0]['packet_count']) == flow['packet_count']
    assert list(csv.DictReader(io.StringIO(client.get('/api/v1/reviews/export.csv?source=synthetic&detection=all&status=reviewed').text))) == []


def test_feature_export_caps_records_and_reports_truncation(client, flow, normal_prediction):
    event_id = submit(client, flow)['event_id']
    with db.connect() as conn:
        record = dict(conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone())
        record.pop('id')
        columns = list(record)
        query = f"INSERT INTO events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})"
        conn.executemany(query, [tuple(record.values())] * 1000)
    response = client.get('/api/v1/reviews/export.csv?source=capture&detection=all&status=all')
    assert response.headers['x-export-truncated'] == 'true'
    assert len(list(csv.DictReader(io.StringIO(response.text)))) == 1000

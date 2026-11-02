from fastapi.testclient import TestClient
import os, sys

# Ensure project root is on sys.path so tests can import backend package
tests_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(tests_dir, '..', '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend.main import app

client = TestClient(app)


def test_openapi_available():
    r = client.get('/openapi.json')
    assert r.status_code == 200


def test_token_with_bad_credentials():
    r = client.post('/token', data={'username': 'no-such-user', 'password': 'wrong'})
    assert r.status_code in (400, 401)


def test_scans_requires_auth():
    r = client.get('/scans')
    assert r.status_code == 401


def test_stats_requires_auth():
    r = client.get('/stats')
    assert r.status_code == 401


def test_log_anomaly_endpoint_detects_sqli():
    from backend.auth import create_user, authenticate_user
    create_user('audit-user', 'secret123', is_admin=False, role='user')
    login = client.post('/token', data={'username': 'audit-user', 'password': 'secret123'})
    token = login.json()['access_token']

    r = client.post('/analyze-logs', json={'logs': ['SELECT * FROM users WHERE id = 1 OR 1=1', 'normal request']}, headers={'Authorization': f'Bearer {token}'})
    assert r.status_code == 200
    payload = r.json()['result']
    assert payload['overall_score'] >= 25
    assert len(payload['detections']) >= 1


def test_me_and_alerts_endpoints_for_authorized_user():
    from backend.auth import create_user
    create_user('enterprise-user', 'P@ssw0rd!', is_admin=False, role='user')
    login = client.post('/token', data={'username': 'enterprise-user', 'password': 'P@ssw0rd!'})
    token = login.json()['access_token']

    me = client.get('/me', headers={'Authorization': f'Bearer {token}'})
    assert me.status_code == 200
    assert me.json()['user']['username'] == 'enterprise-user'

    alerts = client.get('/alerts', headers={'Authorization': f'Bearer {token}'})
    assert alerts.status_code == 200
    assert 'alerts' in alerts.json()

import os, sys
import types

# Ensure project root is on sys.path so tests can import backend package
tests_dir = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(tests_dir, '..', '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import socket
import requests

from backend import scanner
from backend import ssl_audit


class DummyPortScanner:
    def __init__(self):
        self._hosts = []

    def scan(self, hosts=None, arguments=None):
        # simulate a scan that finds no hosts
        return {}

    def all_hosts(self):
        return []

    def scanstats(self):
        return {'uphosts': 0, 'downhosts': 0}


def test_run_nmap_scan_returns_scanstats_when_no_hosts(monkeypatch):
    # monkeypatch nmap.PortScanner to return our dummy
    dummy = DummyPortScanner()
    monkeypatch.setattr(scanner, 'nmap', types.SimpleNamespace(PortScanner=lambda: dummy))

    res = scanner.run_nmap_scan('192.0.2.1')
    assert isinstance(res, dict)
    assert 'scanstats' in res


class DummyResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def test_check_http_security_headers_detects_missing(monkeypatch):
    # simulate requests.get returning headers that are missing the security headers
    headers = {'Server': 'nginx/1.18'}
    monkeypatch.setattr(requests, 'get', lambda url, timeout, verify: DummyResponse(200, headers))

    out = ssl_audit.check_http_security_headers('example.com')
    assert isinstance(out, dict)
    assert 'missing_headers' in out
    # expected missing headers should include at least the standard ones
    assert 'X-Frame-Options' in out['missing_headers']
    assert 'Strict-Transport-Security' in out['missing_headers']


def test_run_ssl_audit_handles_socket_error(monkeypatch):
    # make socket.create_connection raise an exception
    def raise_conn(addr, timeout):
        raise socket.timeout('timed out')

    monkeypatch.setattr(socket, 'create_connection', raise_conn)

    out = ssl_audit.run_ssl_audit('example.com')
    assert isinstance(out, dict)
    # cert should indicate invalid due to socket timeout
    assert 'cert' in out
    assert out['cert'].get('valid') is False

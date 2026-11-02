"""NVD CVE lookup helper (MVP) with a simple persistent file cache.
Uses the NVD REST API to search CVEs by keyword (product + version). Caches results in .cache/cve_cache.json to avoid repeated API calls.
"""
import requests
import time
import json
from pathlib import Path

CACHE_FILE = Path(__file__).resolve().parent / '.cache' / 'cve_cache.json'
CACHE = {}
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CACHE_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


def _ensure_cache_loaded():
    global CACHE
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if CACHE_FILE.exists():
            raw = json.loads(CACHE_FILE.read_text(encoding='utf-8'))
            # raw: { key: { 'ts': epoch, 'cves': [...] } }
            now = time.time()
            for k, v in raw.items():
                if now - v.get('ts', 0) < CACHE_TTL_SECONDS:
                    CACHE[k] = v.get('cves', [])
    except Exception:
        CACHE = {}


def _persist_cache():
    try:
        out = {}
        now = time.time()
        for k, v in CACHE.items():
            out[k] = {'ts': now, 'cves': v}
        CACHE_FILE.write_text(json.dumps(out), encoding='utf-8')
    except Exception:
        pass


def find_cves_for_service(product: str, version: str, max_results: int = 5):
    _ensure_cache_loaded()
    key = f"{product}:{version}"
    if key in CACHE:
        return CACHE[key]

    query = f"{product} {version}" if version else product
    params = {'keywordSearch': query, 'resultsPerPage': max_results}
    try:
        resp = requests.get(NVD_API_BASE, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get('vulnerabilities') or []
            cves = []
            for it in items[:max_results]:
                cve = it.get('cve') or {}
                cve_id = cve.get('id')
                desc = ''
                descriptions = cve.get('descriptions') or []
                if descriptions:
                    desc = descriptions[0].get('value')
                cves.append({'id': cve_id, 'description': desc})
            CACHE[key] = cves
            # persist cache
            _persist_cache()
            # NVD rate limits: be polite
            time.sleep(0.6)
            return cves
        else:
            return []
    except Exception:
        return []

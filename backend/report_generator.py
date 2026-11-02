"""HTML -> PDF report generator using Jinja2 and WeasyPrint.
Generates a polished HTML report from a Jinja2 template and converts it to PDF with WeasyPrint.
"""
import json
import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML, CSS

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / 'templates'
STRINGS_DIR = TEMPLATES_DIR

RECOMMENDATIONS = [
    'Close or restrict access to high-risk ports (21, 23, 445) and use secure alternatives.',
    'Ensure TLS 1.2+ is used, renew or fix certificates when expired.',
    'Add security headers: HSTS, Content-Security-Policy, X-Frame-Options.',
    'Perform authenticated scans and deeper web application scans (OWASP ZAP) for web apps.'
]


def _format_timestamp(ts: int) -> str:
    try:
        return datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(ts)


def _load_strings(lang: str) -> dict:
    p = STRINGS_DIR / f'strings_{lang}.json'
    if not p.exists():
        p = STRINGS_DIR / 'strings_en.json'
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return {}


try:
    from .cve_lookup import find_cves_for_service
except ImportError:  # pragma: no cover - supports running as a top-level module
    from cve_lookup import find_cves_for_service


def _prepare_nmap_hosts(nmap_res: dict) -> list:
    hosts = []
    if not isinstance(nmap_res, dict):
        return hosts
    # Collect unique (product, version) pairs to lookup
    lookup_cache = {}
    for host, h in nmap_res.items():
        ports = []
        for p in h.get('ports', []):
            port_copy = dict(p)
            product = (p.get('product') or '').strip()
            version = (p.get('version') or '').strip()
            cves = []
            if product:
                key = f"{product}:{version}"
                if key in lookup_cache:
                    cves = lookup_cache[key]
                else:
                    try:
                        cves = find_cves_for_service(product, version)
                    except Exception:
                        cves = []
                    lookup_cache[key] = cves
            port_copy['cves'] = cves
            ports.append(port_copy)
        hosts.append({
            'host': host,
            'state': h.get('state'),
            'ports': ports
        })
    return hosts


def generate_pdf(scan_record: dict, lang: str = 'en') -> bytes:
    """Render HTML template and convert to PDF bytes.
    scan_record: {id, target, timestamp, result}
    """
    strings = _load_strings(lang)
    target = scan_record.get('target', 'unknown')
    timestamp = _format_timestamp(scan_record.get('timestamp', int(datetime.datetime.utcnow().timestamp())))
    result = scan_record.get('result') or {}

    nmap_res = result.get('nmap') if isinstance(result, dict) else result
    ssl_res = result.get('ssl_audit') if isinstance(result, dict) else {}

    # compute counts
    high = medium = low = 0
    if isinstance(nmap_res, dict):
        for _, h in nmap_res.items():
            for p in h.get('ports', []):
                r = p.get('risk')
                if r == 'high':
                    high += 1
                elif r == 'medium':
                    medium += 1
                else:
                    low += 1

    total = high + medium + low if (high + medium + low) > 0 else 1
    score = max(0, 100 - (10 * high) - (5 * medium))

    # prepare template context
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template('report.html')

    # Load mapping rules and evaluate matches
    mapping_path = TEMPLATES_DIR / 'bsi_gdpr_mapping.json'
    matched_rules = []
    try:
        mapping = json.loads(mapping_path.read_text(encoding='utf-8'))
    except Exception:
        mapping = []

    # helper checks
    def check_tls_deprecated(ssl):
        # Use tls probe results to determine deprecated versions support
        try:
            tls = ssl.get('tls') if isinstance(ssl, dict) else None
            if not tls:
                return False
            supported = tls.get('supported_versions') or []
            # if any TLSv1 or TLSv1.1 present, mark deprecated
            for v in supported:
                if v in ('TLSv1', 'TLSv1.1'):
                    return True
            return False
        except Exception:
            return False

    def check_open_high_port(nmap_res):
        if not isinstance(nmap_res, dict):
            return False
        for _, h in nmap_res.items():
            for p in h.get('ports', []):
                if p.get('risk') == 'high':
                    return True
        return False

    def check_no_hsts_or_http(ssl):
        # if headers report status_code and Strict-Transport-Security missing -> flag
        headers = ssl.get('headers') if isinstance(ssl, dict) else None
        if not headers:
            return True
        missing = headers.get('missing_headers') or []
        # if Strict-Transport-Security missing or status_code indicates non-HTTPS
        if 'Strict-Transport-Security' in missing:
            return True
        # if status_code present and not a redirect to https, signal
        if headers.get('status_code') and headers.get('status_code') < 300 and not headers.get('header_values', {}).get('Strict-Transport-Security'):
            return True
        return False

    def check_cert_expired(ssl):
        cert = ssl.get('cert') if isinstance(ssl, dict) else None
        if not cert:
            return False
        if isinstance(cert, dict):
            if cert.get('valid') is False:
                return True
            days = cert.get('days_left')
            if days is not None and days < 0:
                return True
        return False

    # evaluate mapping rules
    for rule in mapping:
        check = rule.get('check')
        matched = False
        evidence = None
        if check == 'tls_deprecated':
            matched = check_tls_deprecated(ssl_res)
        elif check == 'open_high_port':
            matched = check_open_high_port(nmap_res)
            if matched:
                # list offending ports
                ports = []
                for _, h in (nmap_res or {}).items():
                    for p in h.get('ports', []):
                        if p.get('risk') == 'high':
                            ports.append(f"{p.get('port')}/{p.get('protocol')}")
                evidence = { 'ports': ports }
        elif check == 'no_hsts_or_http':
            matched = check_no_hsts_or_http(ssl_res)
            if matched:
                evidence = { 'headers': (ssl_res or {}).get('headers') }
        elif check == 'cert_expired':
            matched = check_cert_expired(ssl_res)
            if matched:
                evidence = { 'cert': (ssl_res or {}).get('cert') }

        if matched:
            matched_rules.append({
                'id': rule.get('id'),
                'type': rule.get('type'),
                'title': rule.get(f'title_{lang}', rule.get('title_en')),
                'description': rule.get(f'description_{lang}', rule.get('description_en')),
                'severity': rule.get('severity'),
                'recommendation': rule.get(f'recommendation_{lang}', rule.get('recommendation_en')),
                'evidence': evidence
            })

    context = {
        'lang': lang,
        'strings': strings,
        'target': target,
        'timestamp': timestamp,
        'score': score,
        'high': high,
        'medium': medium,
        'low': low,
        'nmap_hosts': _prepare_nmap_hosts(nmap_res),
        'ssl': ssl_res,
        'recommendations': RECOMMENDATIONS,
        'matched_rules': matched_rules,
        'gen_time': datetime.datetime.utcnow().isoformat() + ' UTC'
    }

    html = template.render(**context)

    # Use WeasyPrint to render HTML -> PDF
    css = CSS(string='@page { size: A4; margin: 20mm }')
    pdf = HTML(string=html, base_url=str(TEMPLATES_DIR)).write_pdf(stylesheets=[css])
    return pdf

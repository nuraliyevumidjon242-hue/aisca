"""SSL and HTTP security headers audit utilities (MVP).
"""
import socket
import ssl
import datetime
import requests
import urllib.parse


def check_ssl_certificate(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        # connect to port 443
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get('notAfter')
        if not_after:
            try:
                expires = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            except Exception:
                # fallback: return raw string
                return {"valid": True, "notAfter": not_after}
            days_left = (expires - datetime.datetime.utcnow()).days
            return {"valid": True, "notAfter": not_after, "days_left": days_left}
        else:
            return {"valid": True, "info": cert}

    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_http_security_headers(target: str) -> dict:
    # Determine base host/url
    if target.startswith('http://') or target.startswith('https://'):
        urls_to_try = [target]
        if target.startswith('https://'):
            urls_to_try.append('http://' + target[8:])
    else:
        urls_to_try = ['https://' + target, 'http://' + target]

    last_error = None
    for url in urls_to_try:
        ssl_verified = True
        try:
            try:
                resp = requests.get(url, timeout=4, verify=True)
            except requests.exceptions.SSLError:
                ssl_verified = False
                resp = requests.get(url, timeout=4, verify=False)

            headers = resp.headers
            missing = []
            for h in ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']:
                if h not in headers:
                    missing.append(h)
            header_values = {
                k: headers.get(k)
                for k in ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security', 'Server', 'Content-Type']
                if k in headers
            }
            return {
                "url": url,
                "status_code": resp.status_code,
                "ssl_verified": ssl_verified,
                "missing_headers": missing,
                "header_values": header_values
            }
        except Exception as e:
            last_error = str(e)
            continue

    return {"error": last_error or "Could not reach target over HTTP or HTTPS"}


try:
    from .ssl_versions import probe_tls_versions
except ImportError:  # pragma: no cover - supports running as a top-level module
    from ssl_versions import probe_tls_versions


def run_ssl_audit(target: str) -> dict:
    # normalize hostname
    parsed = urllib.parse.urlparse(target if target.startswith('http') else ('https://' + target))
    hostname = parsed.hostname or target
    cert = check_ssl_certificate(hostname)
    headers = check_http_security_headers(target)
    # probe TLS versions (best-effort)
    try:
        versions = probe_tls_versions(hostname)
    except Exception as e:
        versions = { 'error': str(e) }
    return {"host": hostname, "cert": cert, "headers": headers, "tls": versions}

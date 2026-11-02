"""Probe supported TLS versions by attempting connections with specific TLS context versions.
This is a best-effort probe: some servers may block or limit ciphers; the probe tries common TLS versions.
"""
import socket
import ssl

TLS_VERSIONS = [
    ('TLSv1', ssl.TLSVersion.TLSv1),
    ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
    ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
    ('TLSv1.3', ssl.TLSVersion.TLSv1_3),
]


def probe_tls_versions(hostname: str, port: int = 443, timeout: float = 1.5) -> dict:
    supported = []
    for name, ver in TLS_VERSIONS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # restrict to single version by setting both min and max
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # if handshake succeeds, mark supported
                    supported.append(name)
        except Exception:
            # handshake failed for this version
            continue
    return { 'supported_versions': supported }

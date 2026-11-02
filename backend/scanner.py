"""Simple wrapper around nmap (python-nmap).
This is an MVP implementation: it runs a service/version scan and classifies a few ports as high/medium/low risk.
"""
import nmap

HIGH_RISK_PORTS = {21, 23, 445}
MEDIUM_RISK_PORTS = {22, 80, 443}


def run_nmap_scan(target: str) -> dict:
    nm = nmap.PortScanner()
    # -sT TCP connect scan (does not require raw sockets), -sV version detection, -Pn no ping, -T4 faster
    nm.scan(hosts=target, arguments='-sT -sV -Pn -T4 --host-timeout 25s --max-retries 1')
    results = {}

    for host in nm.all_hosts():
        host_entry = {
            "host": host,
            "state": nm[host].state(),
            "addresses": nm[host].get('addresses', {}),
            "ports": []
        }

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                svc = nm[host][proto][port]
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "name": svc.get('name'),
                    "product": svc.get('product'),
                    "version": svc.get('version'),
                    "extrainfo": svc.get('extrainfo'),
                    "state": svc.get('state')
                }

                if port in HIGH_RISK_PORTS:
                    risk = "high"
                elif port in MEDIUM_RISK_PORTS:
                    risk = "medium"
                else:
                    risk = "low"

                port_info["risk"] = risk
                host_entry["ports"].append(port_info)

        results[host] = host_entry

    # If no hosts found (e.g., the target is a single IP and not returned by all_hosts), attempt to return basic info
    if not results and nm.all_hosts() == []:
        # try to at least return the scan summary/scanstats
        try:
            stats = nm.scanstats()
            return {"scanstats": stats}
        except Exception:
            return {"error": "no results from nmap"}

    return results

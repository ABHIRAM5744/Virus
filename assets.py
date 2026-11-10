"""Real monitoring of YOUR OWN websites/servers (set ASSETS=https://mysite.com,https://api.mysite.com in .env).

Each asset is checked every 60 s: DNS, HTTP status + latency, TLS certificate expiry, security headers, and whether its IP
appears on live threat lists. run_scan() does a TCP connect scan, restricted to configured assets only.
"""
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

import geo
import intel

SCAN_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]
RISKY = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
         9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
SEC_HEADERS = {"strict-transport-security": "HSTS", "content-security-policy": "CSP", "x-content-type-options": "X-Content-Type-Options",
               "x-frame-options": "X-Frame-Options"}


def parse_assets(raw):
    out = []
    for i, item in enumerate([x.strip() for x in (raw or "").split(",") if x.strip()]):
        url = item if "://" in item else "https://" + item
        u = urlparse(url)
        if not u.hostname:
            continue
        out.append({"id": f"asset-{i + 1}", "name": u.hostname, "url": url, "host": u.hostname, "https": u.scheme == "https",
                    "port": u.port or (443 if u.scheme == "https" else 80)})
    return out


def tls_days_left(host, port, timeout=8):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
    return int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)


class AssetMonitor:
    def __init__(self, engine, assets):
        self.engine = engine
        self.assets = assets
        self.state = {a["id"]: {"up": None, "alerted": {}} for a in assets}

    def start(self):
        for a in self.assets:
            ip = None
            try:
                ip = socket.gethostbyname(a["host"])
            except Exception:
                pass
            g = geo.lookup(ip) if ip else None
            h = geo.home()
            lat, lon = (g["lat"], g["lon"]) if g else (h["lat"] + 1.5, h["lon"] + 1.5)
            self.engine.register_node(a["id"], a["host"], "asset", lat, lon, (g or {}).get("city") or "unknown", meta={"url": a["url"], "ip": ip},
                                      scan_target=a["host"])
            threading.Thread(target=self._loop, args=(a,), daemon=True, name=f"asset-{a['host']}").start()

    def _once_per(self, a, key, seconds):
        st = self.state[a["id"]]["alerted"]
        if time.time() - st.get(key, 0) < seconds:
            return False
        st[key] = time.time()
        return True

    def _loop(self, a):
        while True:
            try:
                self.check(a)
            except Exception as e:  # noqa: BLE001
                print("asset check error:", a["host"], e)
            time.sleep(60)

    def check(self, a):
        eng, nid, st = self.engine, a["id"], self.state[a["id"]]
        meta, status, problems = {}, "ok", []
        try:
            ip = socket.gethostbyname(a["host"])
        except Exception as e:  # noqa: BLE001
            ip = None
            problems.append(("dns", "high", f"DNS resolution failed for {a['host']}: {e}"))
        meta["ip"] = ip
        up, code, ms = False, None, None
        if ip:
            t0 = time.time()
            try:
                r = requests.get(a["url"], timeout=10, allow_redirects=True, headers={"User-Agent": "VIRUS-VoiceSOC-monitor/2.0"})
                ms = int((time.time() - t0) * 1000); code = r.status_code; up = code < 500
                missing = [n for k, n in SEC_HEADERS.items() if k not in {h.lower() for h in r.headers}]
                meta.update(http_status=code, latency_ms=ms, missing_security_headers=missing)
                if code >= 500:
                    problems.append(("5xx", "high", f"{a['host']} returned HTTP {code}"))
                if ms > 2500:
                    problems.append(("slow", "medium", f"{a['host']} is slow: {ms} ms"))
                if missing and a["https"] and self._once_per(a, "headers", 3600):
                    eng.submit({"source": "asset-monitor", "type": "weak_headers", "severity": "low", "mitre": ("T1190", "Exploit Public-Facing Application"),
                                "ip": None, "target": nid, "direction": "in", "tags": missing,
                                "title": f"{a['host']} is missing security headers: {', '.join(missing)}",
                                "detail": "Missing HTTP security headers make clickjacking, XSS and downgrade attacks easier."})
            except Exception as e:  # noqa: BLE001
                problems.append(("down", "critical", f"{a['host']} is unreachable: {str(e)[:100]}"))
        if a["https"] and ip:
            try:
                d = tls_days_left(a["host"], a["port"]); meta["tls_days_left"] = d
                if d < 14:
                    problems.append(("tls", "critical" if d < 3 else "high", f"TLS certificate for {a['host']} expires in {d} days"))
            except Exception as e:  # noqa: BLE001
                problems.append(("tlserr", "high", f"TLS handshake problem on {a['host']}: {str(e)[:100]}"))
        if ip and intel.tags_for(ip) and self._once_per(a, "rep", 6 * 3600):
            problems.append(("reputation", "high", f"IP {ip} of {a['host']} appears on threat lists: {', '.join(intel.tags_for(ip))}"))
        for key, sev, text in problems:
            if self._once_per(a, key, 600 if key in ("down", "5xx", "slow") else 6 * 3600):
                eng.submit({"source": "asset-monitor", "type": f"asset_{key}", "severity": sev, "mitre": ("T1499", "Endpoint Denial of Service") if key in ("down", "5xx", "slow") else ("T1557", "Adversary-in-the-Middle"),
                            "ip": None, "target": nid, "direction": "in", "tags": [key], "title": text, "detail": f"Live check at {time.strftime('%H:%M:%S')}. {text}."})
        sevs = [p[1] for p in problems]
        status = "compromised" if "critical" in sevs else "warn" if sevs else "ok"
        if up and st["up"] is False:
            eng.submit({"source": "asset-monitor", "type": "asset_recovered", "severity": "info", "mitre": ("T1499", "Endpoint Denial of Service"),
                        "ip": None, "target": nid, "direction": "in", "tags": [], "title": f"{a['host']} recovered ({code}, {ms} ms)", "detail": "Service is reachable again."})
        st["up"] = up
        eng.set_meta(nid, **meta)
        eng.set_status(nid, status)

    # ---- real TCP connect scan, restricted to configured assets
    def scan(self, node_id):
        a = next((x for x in self.assets if x["id"] == node_id), None)
        if not a:
            return {"error": "scan is only allowed on your configured assets"}
        host = a["host"]
        try:
            ip = socket.gethostbyname(host)
        except Exception as e:  # noqa: BLE001
            return {"error": f"dns: {e}"}

        def probe(p):
            try:
                with socket.create_connection((ip, p), timeout=1.5):
                    return p
            except Exception:
                return None
        with ThreadPoolExecutor(24) as ex:
            open_ports = sorted(p for p in ex.map(probe, SCAN_PORTS) if p)
        risky = {p: RISKY[p] for p in open_ports if p in RISKY}
        for p, name in risky.items():
            self.engine.submit({"source": "scan", "type": "exposed_service", "severity": "high", "mitre": ("T1133", "External Remote Services"),
                                "ip": None, "target": node_id, "direction": "in", "tags": [name], "title": f"{name} (port {p}) is exposed to the internet on {host}",
                                "detail": f"TCP connect scan found {name} reachable on {ip}:{p}. Restrict it with a firewall or VPN."})
        return {"node": node_id, "host": host, "ip": ip, "open_ports": open_ports, "exposed_risky_services": risky, "ports_checked": len(SCAN_PORTS)}

"""Real telemetry from the machine running VIRUS: live network connections, listening ports, SSH auth failures.

Outbound connections are geolocated and checked against the live threat lists. A hit becomes a CRITICAL event.
"""
import os
import re
import subprocess
import platform
import socket
import threading
import time
from collections import Counter

import geo
import intel

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def _netstat_connections():
    cmd = ["netstat", "-ano"] if platform.system() == "Windows" else ["netstat", "-an"]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    conns = []
    ep = re.compile(r"(\d+\.\d+\.\d+\.\d+)[.:](\d+)")
    for line in out.splitlines():
        m = re.search(r"\b(ESTABLISHED|LISTEN|LISTENING|SYN_SENT)\b", line)
        eps = ep.findall(line)
        if not m or len(eps) < 1:
            continue
        status = "LISTEN" if m.group(1).startswith("LISTEN") else m.group(1)
        l = eps[0]; r = eps[1] if len(eps) > 1 else ("0.0.0.0", "0")
        conns.append({"pid": None, "status": status, "lip": l[0], "lport": int(l[1]), "rip": r[0], "rport": int(r[1])})
    return conns


def get_connections():
    if psutil:
        try:
            out = []
            for c in psutil.net_connections(kind="inet"):
                out.append({"pid": c.pid, "status": c.status, "lip": c.laddr.ip if c.laddr else "", "lport": c.laddr.port if c.laddr else 0,
                            "rip": c.raddr.ip if c.raddr else "", "rport": c.raddr.port if c.raddr else 0})
            return out
        except Exception:
            pass  # macOS without root, etc.
    return _netstat_connections()


def _pname(pid):
    if not pid or not psutil:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except Exception:
        return "unknown"


class HostMonitor:
    def __init__(self, engine):
        self.engine = engine
        self.seen_remote = {}
        self.baseline_ports = None
        self.first = True

    def start(self):
        threading.Thread(target=self._net_loop, daemon=True, name="hostmon").start()
        threading.Thread(target=self._auth_loop, daemon=True, name="authlog").start()

    def _net_loop(self):
        while True:
            try:
                self._net_tick()
            except Exception as e:  # noqa: BLE001
                print("hostmon error:", e)
            time.sleep(5)

    def _net_tick(self):
        conns = get_connections()
        est = [c for c in conns if c["status"] in ("ESTABLISHED", "SYN_SENT") and geo.is_public(c["rip"])]
        listening = sorted({c["lport"] for c in conns if c["status"] == "LISTEN" and c["lip"] in ("0.0.0.0", "::", "")})
        procs = Counter(_pname(c["pid"]) for c in est)
        self.engine.set_meta("hq", connections=len(est), unique_remote_ips=len({c["rip"] for c in est}),
                             listening_ports=listening[:25], top_processes=[p for p, _ in procs.most_common(4)])
        if self.baseline_ports is None:
            self.baseline_ports = set(listening)
        for p in set(listening) - self.baseline_ports:
            self.baseline_ports.add(p)
            self.engine.submit({"source": "host", "type": "new_listener", "severity": "medium", "mitre": ("T1571", "Non-Standard Port"),
                                "ip": None, "target": "hq", "direction": "in", "tags": ["listening"],
                                "title": f"New service listening on all interfaces: port {p}",
                                "detail": f"A process started listening on 0.0.0.0:{p}. Verify it is expected."})
        now = time.time(); budget = 8 if self.first else 5
        for c in est:
            ip = c["rip"]
            tags = intel.tags_for(ip)
            if ip in self.seen_remote and now - self.seen_remote[ip] < 1800:
                continue
            if not tags:
                if budget <= 0:
                    continue
                budget -= 1
            self.seen_remote[ip] = now
            proc = _pname(c["pid"])
            if tags:
                self.engine.submit({"source": "host", "type": "c2_connection", "severity": "critical", "mitre": ("T1071", "Application Layer Protocol"),
                                    "ip": ip, "target": "hq", "direction": "out", "actionable": True, "tags": tags,
                                    "title": f"{proc} connected to known-malicious IP ({'/'.join(tags[:2])})",
                                    "detail": f"{proc} (pid {c['pid']}) has an open connection to {ip}:{c['rport']}, which is on live threat lists: {', '.join(tags)}."})
            else:
                self.engine.submit({"source": "host", "type": "outbound", "severity": "info", "mitre": ("T1071", "Application Layer Protocol"),
                                    "ip": ip, "target": "hq", "direction": "out", "tags": [],
                                    "title": f"{proc} → {{city}}:{c['rport']}",
                                    "detail": f"Outbound connection from {proc} to {ip}:{c['rport']} ({{org}}). Not on any threat list."})
        self.first = False

    # ---- Linux/BSD auth log: real SSH brute force against this machine
    def _auth_loop(self):
        path = next((p for p in ("/var/log/auth.log", "/var/log/secure") if os.path.exists(p) and os.access(p, os.R_OK)), None)
        if not path:
            return
        pat = re.compile(r"(?:Failed password for (?:invalid user )?(\S+)|Invalid user (\S+)) from (\d+\.\d+\.\d+\.\d+)")
        with open(path, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            window = {}
            while True:
                line = f.readline()
                if line:
                    m = pat.search(line)
                    if m:
                        ip = m.group(3); user = m.group(1) or m.group(2)
                        w = window.setdefault(ip, {"n": 0, "users": set(), "t": time.time()})
                        w["n"] += 1; w["users"].add(user)
                    continue
                now = time.time()
                for ip, w in list(window.items()):
                    if now - w["t"] > 20:
                        window.pop(ip)
                        sev = "high" if w["n"] >= 5 else "medium"
                        self.engine.submit({"source": "auth.log", "type": "ssh_bruteforce", "severity": sev, "mitre": ("T1110", "Brute Force"),
                                            "ip": ip, "target": "hq", "direction": "in", "actionable": True, "tags": intel.tags_for(ip),
                                            "title": f"SSH brute force: {w['n']} failed logins from {{city}}",
                                            "detail": f"{w['n']} failed SSH logins from {ip} in {int(now - w['t'])}s. Usernames tried: {', '.join(sorted(w['users']))[:80]}."})
                time.sleep(1.5)

"""Optional TCP honeypot. Set HONEYPOT_PORTS=2222,8080,2323 to enable.

It only accepts connections, sends a banner, records the first bytes and closes. It never executes anything.
Real internet scanners hit exposed ports within minutes (use a VPS or port-forward).
"""
import re
import socket
import threading

import intel

BANNERS = {22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", 2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
           21: b"220 FTP service ready\r\n", 23: b"login: ", 2323: b"login: ", 25: b"220 mail ESMTP\r\n"}
PATTERNS = [(re.compile(rb"(\.\./|/etc/passwd|/bin/sh|cmd\.exe)", re.I), "path traversal / shell probe", "high", ("T1190", "Exploit Public-Facing Application")),
            (re.compile(rb"(union\s+select|or\s+1=1|sleep\()", re.I), "SQL injection probe", "high", ("T1190", "Exploit Public-Facing Application")),
            (re.compile(rb"\$\{jndi:", re.I), "Log4Shell probe", "critical", ("T1190", "Exploit Public-Facing Application")),
            (re.compile(rb"^(GET|POST|HEAD|PUT) ", re.I), "HTTP probe", "medium", ("T1595", "Active Scanning")),
            (re.compile(rb"^SSH-"), "SSH client handshake", "medium", ("T1110", "Brute Force"))]


def start(engine, ports):
    for p in ports:
        threading.Thread(target=_serve, args=(engine, p), daemon=True, name=f"honeypot-{p}").start()


def _serve(engine, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port)); s.listen(20)
    except OSError as e:
        print(f"honeypot: cannot bind {port}: {e}")
        return
    print(f"honeypot listening on :{port}")
    while True:
        try:
            c, addr = s.accept()
        except OSError:
            return
        threading.Thread(target=_handle, args=(engine, c, addr, port), daemon=True).start()


def _handle(engine, c, addr, port):
    data = b""
    try:
        c.settimeout(4)
        if port in BANNERS:
            c.sendall(BANNERS[port])
        data = c.recv(600)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass
    kind, sev, mitre = "connection / port scan", "medium", ("T1046", "Network Service Discovery")
    for rx, k, sv, mt in PATTERNS:
        if rx.search(data or b""):
            kind, sev, mitre = k, sv, mt
            break
    snippet = re.sub(r"[^\x20-\x7e]", ".", (data or b"")[:100].decode("latin1"))
    ip = addr[0]
    engine.submit({"source": "honeypot", "type": "honeypot_hit", "severity": sev, "mitre": mitre, "ip": ip, "target": "honeypot", "direction": "in",
                   "actionable": True, "tags": intel.tags_for(ip),
                   "title": f"Honeypot :{port} hit from {{city}} - {kind}",
                   "detail": f"{ip}:{addr[1]} connected to honeypot port {port}. First bytes: {snippet!r}"})

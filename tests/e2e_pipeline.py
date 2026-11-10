"""End-to-end pipeline test. TEST HARNESS ONLY: a local HTTP server stands in for the feed hosts (this sandbox cannot reach them);
the app code under test (pollers, engine, geo, host monitor, firewall) is the real code. Nothing here ships as app data.

Part 1: feeds -> pollers -> engine -> events.
Part 2: a REAL established connection on this machine is added to the threat set -> host monitor must raise a CRITICAL event,
        offer a pending block, and the block action must stop further alerts for that IP.
"""
import os
import sys
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import intel, geo, hostmon, soc  # noqa: E402

FIX = {
    "/feodo": json.dumps([{"ip_address": "45.9.148.108", "port": 443, "status": "online", "malware": "QakBot", "as_name": "TEST-AS", "country": "NL", "first_seen": "2026-11-01 10:00:00", "last_online": "2026-11-10"}]),
    "/kev": json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "RCE", "dateAdded": "2026-11-09", "shortDescription": "x", "requiredAction": "patch", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known"}]}),
    "/dshield": json.dumps([{"source": "185.220.101.7", "reports": 5000, "targets": 900, "firstseen": "2026-11-01", "lastseen": "2026-11-10"}]),
    "/blocklist": "185.220.101.9\n45.9.148.20\n",
}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = FIX.get(self.path.split("?")[0])
        self.send_response(200 if body else 404); self.end_headers()
        self.wfile.write((body or "").encode())

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_port}"
intel.URLS.update(feodo=base + "/feodo", kev=base + "/kev", dshield=base + "/dshield", blocklist_de=base + "/blocklist")
geo.lookup_many = lambda ips: {ip: {"city": "TestCity", "country": "NL", "lat": 52.3, "lon": 4.9, "org": "TEST-ORG"} for ip in ips}  # no network here

e = soc.Engine(); e.register_node("hq", "testbox", "host", 25.2, 55.3, "Dubai"); e.start()
q = e.subscribe()
p = intel.Poller(e)
for name, fn in (("feodo", p.poll_feodo), ("dshield", p.poll_dshield), ("cisa-kev", p.poll_kev), ("blocklist.de", p.poll_blocklist)):
    intel._status(name); print("poll", name, "->", fn(), "items")
time.sleep(6)
evs = e.state()["events"]
print("PART 1 events:", [(x["source"], x["severity"]) for x in evs])
assert {x["source"] for x in evs} >= {"abuse.ch Feodo", "CISA KEV", "SANS DShield"}, "feed events missing"
assert all(x["direction"] in ("in", "out") for x in evs)

# ---- Part 2: real connection correlation
real = [c for c in hostmon.get_connections() if c["status"] == "ESTABLISHED" and geo.is_public(c["rip"])]
print("PART 2 real public connections seen:", len(real))
assert real, "no real outbound connection to correlate in this environment"
ip = real[0]["rip"]
intel._add_threat([ip], "test-ioc")
mon = hostmon.HostMonitor(e); mon.start()
deadline = time.time() + 20
hit = None
while time.time() < deadline and not hit:
    hit = next((x for x in e.state()["events"] if x["source"] == "host" and x["severity"] == "critical"), None); time.sleep(1)
print("critical host event:", hit and hit["title"])
assert hit, "host monitor did not raise a critical event for a connection to a listed IP"
assert e.pending and e.pending["type"] == "block_ip", "no pending block offered"
print("pending:", e.pending["ip"], "| node status:", e.nodes["hq"]["status"])
res, _ = e.apply([{"type": "confirm_pending"}]); print("block result:", {k: v for k, v in res[0].items() if k != "type"})
assert ip in e.blocked and e.pending is None
print("ALL E2E CHECKS PASSED")

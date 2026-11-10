"""Global attack layer: feeds that describe attacks happening ELSEWHERE on the internet (not only against this machine).

Keyless (work out of the box):
  * FireHOL typed attacker lists (SSH/mail/web/VoIP brute force, scanners, bots) - hosted on GitHub, refreshed ~every 10-30 min
  * Phishing.Database "new today" phishing URLs (resolved to hosting IP and geolocated)
  * ransomware.live recent victims (country-level)
Optional keys (free to create; panel shows "needs KEY" until set):
  * CLOUDFLARE_API_TOKEN  -> Cloudflare Radar: real origin->target country attack flows (L3 + L7)
  * OTX_API_KEY           -> AlienVault OTX pulses (fresh IOCs from the community)
  * ABUSECH_AUTH_KEY      -> abuse.ch ThreatFox IOCs (also used for URLhaus/Feodo when they require it)
  * ABUSEIPDB_API_KEY     -> AbuseIPDB blacklist (>=90% confidence)
  * GREYNOISE_API_KEY     -> GreyNoise enrichment in IP look-ups
Parsers are pure functions (tests/test_globalfeeds.py).
"""
import os
import re
import threading
import time

import requests

import geo
import intel

UA = intel.UA

FIREHOL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{}.ipset"
# file, label, type, MITRE, severity
FIREHOL_SETS = [
    ("blocklist_de_ssh", "SSH brute-force", "ssh_bruteforce", ("T1110", "Brute Force"), "medium"),
    ("blocklist_de_apache", "web-server attack", "web_attack", ("T1190", "Exploit Public-Facing Application"), "high"),
    ("blocklist_de_mail", "mail-server attack", "mail_attack", ("T1110", "Brute Force"), "medium"),
    ("blocklist_de_imap", "IMAP/POP3 brute-force", "mail_attack", ("T1110", "Brute Force"), "medium"),
    ("blocklist_de_sip", "VoIP/SIP attack", "sip_attack", ("T1110", "Brute Force"), "medium"),
    ("blocklist_de_ftp", "FTP brute-force", "ftp_bruteforce", ("T1110", "Brute Force"), "medium"),
    ("blocklist_de_bots", "attack bot", "attack_bot", ("T1595", "Active Scanning"), "medium"),
    ("blocklist_de_bruteforce", "login brute-force", "bruteforce", ("T1110", "Brute Force"), "medium"),
    ("greensnow", "internet scanner / attacker", "scanner", ("T1595", "Active Scanning"), "medium"),
    ("bruteforceblocker", "brute-force attacker", "bruteforce", ("T1110", "Brute Force"), "high"),
    ("botscout_1d", "spam / abuse bot", "attack_bot", ("T1595", "Active Scanning"), "low"),
]
PHISH_NEW = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt"
RANSOMWARE = "https://api.ransomware.live/v2/recentvictims"

KEYS = {
    "cloudflare-radar": "CLOUDFLARE_API_TOKEN",
    "otx": "OTX_API_KEY",
    "threatfox": "ABUSECH_AUTH_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
}


# ------------------------------------------------------------------ pure parsers
def parse_radar_attacks(j):
    """Cloudflare Radar attacks/top/attacks -> [{from, to, from_name, to_name, pct}] (tolerates key-name variants)."""
    res = (j or {}).get("result") or {}
    rows = None
    for k, v in res.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            rows = v
            break
    out = []
    for r in rows or []:
        o = r.get("originCountryAlpha2") or r.get("origin_country_alpha2")
        t = r.get("targetCountryAlpha2") or r.get("target_country_alpha2")
        try:
            val = float(r.get("value"))
        except (TypeError, ValueError):
            continue
        if o and t:
            out.append({"from": o.upper(), "to": t.upper(), "from_name": r.get("originCountryName") or o, "to_name": r.get("targetCountryName") or t, "pct": val})
    return out


def parse_radar_locations(j):
    """Cloudflare Radar attacks/top/locations/origin -> [{cc, name, pct}]"""
    res = (j or {}).get("result") or {}
    rows = None
    for k, v in res.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            rows = v
            break
    out = []
    for r in rows or []:
        cc = r.get("originCountryAlpha2") or r.get("targetCountryAlpha2") or r.get("clientCountryAlpha2")
        name = r.get("originCountryName") or r.get("targetCountryName") or r.get("clientCountryName") or cc
        try:
            out.append({"cc": cc.upper(), "name": name, "pct": float(r.get("value"))})
        except (TypeError, ValueError, AttributeError):
            continue
    return out


def parse_threatfox(j):
    """ThreatFox get_iocs -> [{ip, port, malware, threat, conf, first}] for ip:port IOCs."""
    out = []
    for r in (j or {}).get("data") or []:
        if not isinstance(r, dict) or r.get("ioc_type") != "ip:port":
            continue
        ip, _, port = str(r.get("ioc", "")).rpartition(":")
        ip = geo.norm_ip(ip)
        if ip:
            out.append({"ip": ip, "port": port, "malware": r.get("malware_printable") or "unknown", "threat": r.get("threat_type") or "",
                        "conf": r.get("confidence_level") or 0, "first": r.get("first_seen") or ""})
    return out


def parse_abuseipdb(j):
    out = []
    for r in (j or {}).get("data") or []:
        ip = geo.norm_ip(r.get("ipAddress", ""))
        if ip:
            out.append({"ip": ip, "score": r.get("abuseConfidenceScore", 0), "cc": r.get("countryCode"), "last": r.get("lastReportedAt", "")})
    return out


def parse_otx(j):
    """OTX pulses -> [{id, name, ips[], tags[], adversary, tlp}]"""
    out = []
    for p in (j or {}).get("results") or []:
        ips = [geo.norm_ip(i.get("indicator", "")) for i in p.get("indicators") or [] if i.get("type") == "IPv4"]
        ips = [i for i in ips if i]
        out.append({"id": p.get("id"), "name": p.get("name") or "OTX pulse", "ips": ips[:5], "tags": (p.get("tags") or [])[:4],
                    "adversary": p.get("adversary") or "", "n_ind": len(p.get("indicators") or [])})
    return out


def parse_ransomware(j):
    """ransomware.live recentvictims -> [{victim, group, cc, date}]"""
    out = []
    rows = j if isinstance(j, list) else (j or {}).get("data") or []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cc = (r.get("country") or "").strip().upper()
        if len(cc) == 2:
            out.append({"victim": r.get("victim") or r.get("post_title") or "undisclosed", "group": r.get("group") or "unknown", "cc": cc,
                        "date": r.get("discovered") or r.get("attackdate") or ""})
    return out


# ------------------------------------------------------------------ pollers
class GlobalFeeds:
    def __init__(self, engine):
        self.engine = engine
        self.seen = {}

    def run(self, name, interval, fn, key_env=None):
        s = intel._status(name)
        if key_env and not os.getenv(key_env):
            s.update(ok=None, needs_key=key_env, last_error=f"needs {key_env} (free) - see README")
            return
        s["scope"] = "global"

        def loop():
            time.sleep(2.0)
            while True:
                try:
                    n = fn()
                    s.update(ok=True, last_ok=time.time(), last_error=None, items=n if n is not None else s["items"], polls=s["polls"] + 1)
                except Exception as e:  # noqa: BLE001
                    s.update(ok=False, last_error=str(e)[:160], polls=s["polls"] + 1)
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True, name=f"gfeed-{name}").start()

    def start(self):
        self.run("firehol-attackers", 900, self.poll_firehol)
        self.run("phishing-db", 900, self.poll_phishing)
        self.run("ransomware.live", 900, self.poll_ransomware)
        self.run("cloudflare-radar", 1800, self.poll_radar, KEYS["cloudflare-radar"])
        self.run("otx", 900, self.poll_otx, KEYS["otx"])
        self.run("threatfox", 600, self.poll_threatfox, KEYS["threatfox"])
        self.run("abuseipdb", 3600, self.poll_abuseipdb, KEYS["abuseipdb"])

    def _new(self, key, items, keyfn, first_limit, cap):
        seen = self.seen.setdefault(key, None)
        cur = {keyfn(i) for i in items}
        if seen is None:
            self.seen[key] = cur
            return items[:first_limit]
        fresh = [i for i in items if keyfn(i) not in seen]
        self.seen[key] = cur
        return fresh[:cap]

    # -- FireHOL typed attacker lists (keyless)
    def poll_firehol(self):
        total, batch = 0, []
        for fname, label, typ, mitre, sev in FIREHOL_SETS:
            try:
                ips = intel.parse_ip_lines(intel._fetch(FIREHOL.format(fname), 40))
            except Exception as e:  # noqa: BLE001
                intel._status("firehol-attackers", last_error=f"{fname}: {str(e)[:80]}")
                continue
            total += len(ips)
            intel._add_threat(ips, fname.replace("_", "-"))
            for ip in self._new(fname, ips, lambda x: x, 5, 12):
                batch.append({"source": "FireHOL " + fname.replace("blocklist_de_", "bl.de/"), "type": typ, "severity": sev, "mitre": mitre, "ip": ip,
                              "tags": [fname], "title": f"{label.capitalize()} from {{city}}",
                              "detail": f"{ip} is currently listed for {label} (FireHOL / {fname}). Observed by honeypots and sensors across the internet."})
        if total == 0:
            raise RuntimeError("no FireHOL list reachable")
        self.engine.submit_global(batch)
        return total

    # -- Phishing.Database new-today (keyless)
    def poll_phishing(self):
        urls = intel.parse_urls(intel._fetch(PHISH_NEW, 40))
        batch = []
        for u in self._new("phish", urls, lambda x: x, 12, 15):
            host = intel.host_of(u)
            ip = intel.resolve(host) if host else None
            if ip and geo.is_public(ip):
                batch.append({"source": "Phishing.Database", "type": "phishing_site", "severity": "medium", "mitre": ("T1566", "Phishing"), "ip": ip,
                              "tags": ["phishing"], "title": f"Phishing site hosted in {{city}}: {host}", "detail": f"New phishing URL today: {u[:140]} (hosting IP {ip})."})
        self.engine.submit_global(batch)
        return len(urls)

    # -- ransomware.live (keyless, country level)
    def poll_ransomware(self):
        r = requests.get(RANSOMWARE, headers=UA, timeout=25)
        r.raise_for_status()
        rows = parse_ransomware(r.json())
        batch = []
        for v in self._new("ransom", rows, lambda x: (x["victim"], x["group"]), 6, 10):
            batch.append({"source": "ransomware.live", "type": "ransomware_victim", "severity": "high", "mitre": ("T1486", "Data Encrypted for Impact"), "cc": v["cc"],
                          "tags": ["ransomware", v["group"]], "title": f"Ransomware victim posted by {v['group']} ({v['cc']})",
                          "detail": f"{v['victim']} listed on the {v['group']} leak site {v['date']}."})
        self.engine.submit_global(batch)
        return len(rows)

    # -- Cloudflare Radar (key): real country->country attack flows
    def poll_radar(self):
        tok = os.getenv(KEYS["cloudflare-radar"])
        h = dict(UA, Authorization=f"Bearer {tok}")
        flows, errs = [], []
        for layer in ("layer7", "layer3"):
            try:
                r = requests.get(f"https://api.cloudflare.com/client/v4/radar/attacks/{layer}/top/attacks", headers=h,
                                 params={"dateRange": "1d", "limit": 10, "format": "json"}, timeout=25)
                r.raise_for_status()
                for f in parse_radar_attacks(r.json()):
                    a, b = geo.country_xy(f["from"]), geo.country_xy(f["to"])
                    if a and b:
                        flows.append(dict(f, layer=layer.upper().replace("LAYER", "L"), from_xy=a[:2], to_xy=b[:2]))
            except Exception as e:  # noqa: BLE001
                errs.append(f"{layer}: {str(e)[:70]}")
        if not flows:
            raise RuntimeError("; ".join(errs) or "empty Radar response")
        self.engine.set_flows(flows, {"source": "Cloudflare Radar", "window": "last 24h", "note": "aggregate share of attack traffic, not individual attacks", "ts": time.time()})
        return len(flows)

    # -- AlienVault OTX (key)
    def poll_otx(self):
        r = requests.get("https://otx.alienvault.com/api/v1/pulses/activity", headers=dict(UA, **{"X-OTX-API-KEY": os.getenv(KEYS["otx"])}),
                         params={"limit": 20}, timeout=30)
        r.raise_for_status()
        pulses = parse_otx(r.json())
        batch = []
        for p in self._new("otx", pulses, lambda x: x["id"], 6, 10):
            for ip in p["ips"][:2]:
                batch.append({"source": "AlienVault OTX", "type": "threat_pulse", "severity": "high", "mitre": ("T1583", "Acquire Infrastructure"), "ip": ip,
                              "tags": ["otx"] + p["tags"], "title": f"OTX pulse: {p['name'][:70]}", "detail": f"{ip} appears in a fresh community pulse ({p['n_ind']} indicators). {p['adversary']}"})
        self.engine.submit_global(batch)
        return len(pulses)

    # -- abuse.ch ThreatFox (key)
    def poll_threatfox(self):
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 1}, headers=dict(UA, **{"Auth-Key": os.getenv(KEYS["threatfox"])}), timeout=40)
        r.raise_for_status()
        rows = parse_threatfox(r.json())
        intel._add_threat([x["ip"] for x in rows], "threatfox")
        batch = [{"source": "abuse.ch ThreatFox", "type": "malware_c2", "severity": "high", "mitre": ("T1071", "Application Layer Protocol"), "ip": x["ip"],
                  "tags": ["threatfox", x["malware"]], "title": f"{x['malware']} C2 in {{city}} ({x['ip']}:{x['port']})",
                  "detail": f"ThreatFox IOC, {x['threat']}, confidence {x['conf']}%, first seen {x['first']}."} for x in self._new("tf", rows, lambda x: x["ip"], 8, 15)]
        self.engine.submit_global(batch)
        return len(rows)

    # -- AbuseIPDB blacklist (key)
    def poll_abuseipdb(self):
        r = requests.get("https://api.abuseipdb.com/api/v2/blacklist", headers=dict(UA, Key=os.getenv(KEYS["abuseipdb"]), Accept="application/json"),
                         params={"confidenceMinimum": 90, "limit": 500}, timeout=30)
        r.raise_for_status()
        rows = parse_abuseipdb(r.json())
        intel._add_threat([x["ip"] for x in rows], "abuseipdb")
        batch = [{"source": "AbuseIPDB", "type": "reported_attacker", "severity": "high", "mitre": ("T1595", "Active Scanning"), "ip": x["ip"], "tags": ["abuseipdb"],
                  "title": f"AbuseIPDB {x['score']}% abusive IP in {{city}}", "detail": f"{x['ip']} confidence of abuse {x['score']}%, last reported {x['last']}."}
                 for x in self._new("abuseipdb", rows, lambda x: x["ip"], 8, 15)]
        self.engine.submit_global(batch)
        return len(rows)


def greynoise(ip):
    """Optional enrichment used by intel.lookup_ip."""
    k = os.getenv("GREYNOISE_API_KEY")
    if not k:
        return None
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=dict(UA, key=k), timeout=10)
        if r.status_code in (200, 404):
            j = r.json()
            return {"noise": j.get("noise"), "riot": j.get("riot"), "classification": j.get("classification"), "name": j.get("name")}
    except Exception:
        return None
    return None

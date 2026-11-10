"""Live threat-intelligence feeds. Every item that reaches the dashboard comes from one of these public sources.

Parsers are pure functions (see tests/test_parsers.py); pollers fetch, parse and submit candidates to the engine.
Run `python check_sources.py` to verify every source from your own network.
"""
import os
import re
import csv
import io
import json
import socket
import threading
import time
from urllib.parse import urlparse

import requests

import geo

UA = {"User-Agent": "VIRUS-VoiceSOC/2.0 (security research)"}

URLS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "blocklist_de": "https://api.blocklist.de/getlast.php?time=3600",
    "blocklist_all": "https://lists.blocklist.de/lists/all.txt",
    "dshield": "https://isc.sans.edu/api/topips/records/25?json",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "et_compromised": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "tor_exit": "https://check.torproject.org/torbulkexitlist",
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
}

SOURCES = {}          # name -> status dict (shown in the UI)
THREAT = {}           # ip -> set(tags)   (used to correlate host/asset/honeypot traffic)
_tlock = threading.Lock()


# ------------------------------------------------------------------ status helpers
def _status(name, **kw):
    s = SOURCES.setdefault(name, {"name": name, "ok": None, "last_ok": None, "last_error": None, "items": 0, "polls": 0})
    s.update(kw)
    return s


def _fetch(url, timeout=25):
    h = dict(UA)
    if ".abuse.ch" in url and os.getenv("ABUSECH_AUTH_KEY"):
        h["Auth-Key"] = os.getenv("ABUSECH_AUTH_KEY")     # abuse.ch now asks for a free Auth-Key
    r = requests.get(url, headers=h, timeout=timeout)
    r.raise_for_status()
    return r.text


def tags_for(ip):
    with _tlock:
        return sorted(THREAT.get(ip, ()))


def _add_threat(ips, tag):
    with _tlock:
        for ip in ips:
            THREAT.setdefault(ip, set()).add(tag)


def threat_size():
    with _tlock:
        return len(THREAT)


# ------------------------------------------------------------------ pure parsers
def parse_ip_lines(text):
    out = []
    for line in (text or "").splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        ip = geo.norm_ip(line.split()[0].split(",")[0])
        if ip:
            out.append(ip)
    return out


def parse_ipsum(text, min_level=3):
    """IPsum lines are 'ip<TAB>number_of_blocklists'. Level >= 3 has very few false positives."""
    out = []
    for line in (text or "").splitlines():
        if not line or line[0] == "#":
            continue
        p = line.split()
        if len(p) >= 2 and p[1].isdigit() and int(p[1]) >= min_level:
            ip = geo.norm_ip(p[0])
            if ip:
                out.append(ip)
    return out


def parse_feodo(text):
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("blocklist") or data.get("data") or next((v for v in data.values() if isinstance(v, list)), [])
    rows = []
    for d in data:
        ip = geo.norm_ip(str(d.get("ip_address") or d.get("ip") or ""))
        if ip:
            rows.append({"ip": ip, "port": d.get("port"), "status": (d.get("status") or "").lower(), "malware": d.get("malware") or "unknown",
                         "country": d.get("country"), "as_name": d.get("as_name"), "first_seen": d.get("first_seen"),
                         "last_online": d.get("last_online")})
    rows.sort(key=lambda r: (r["last_online"] or r["first_seen"] or ""), reverse=True)
    return rows


def parse_dshield(text):
    data = json.loads(text)
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [])
    rows = []
    for d in data:
        raw = d.get("source") or d.get("ip") or d.get("ipv4") or ""
        ip = geo.norm_ip(str(raw))
        if ip:
            def num(k):
                try:
                    return int(str(d.get(k) or 0).replace(",", ""))
                except ValueError:
                    return 0
            rows.append({"ip": ip, "reports": num("reports") or num("count"), "targets": num("targets"),
                         "first": d.get("firstseen"), "last": d.get("lastseen")})
    return rows


def parse_kev(text):
    data = json.loads(text)
    rows = []
    for v in data.get("vulnerabilities", []):
        rows.append({"cve": v.get("cveID"), "vendor": v.get("vendorProject"), "product": v.get("product"), "name": v.get("vulnerabilityName"),
                     "added": v.get("dateAdded"), "desc": v.get("shortDescription"), "action": v.get("requiredAction"),
                     "due": v.get("dueDate"), "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known"})
    rows.sort(key=lambda r: r["added"] or "", reverse=True)
    return rows


def parse_urls(text):
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("http"):
            out.append(line)
    return out


def parse_urlhaus(text):
    lines = [l for l in text.splitlines() if l.strip()]
    header = None
    rows = []
    for l in lines:
        if l.startswith("#"):
            if "url" in l and "dateadded" in l:
                header = [h.strip() for h in l.lstrip("# ").split(",")]
            continue
        rows.append(l)
    out = []
    for rec in csv.reader(io.StringIO("\n".join(rows))):
        d = dict(zip(header, rec)) if header and len(rec) >= len(header) else {"url": rec[2] if len(rec) > 2 else "", "threat": rec[5] if len(rec) > 5 else ""}
        if d.get("url", "").startswith("http") and d.get("url_status", "online") == "online":
            out.append({"url": d["url"], "threat": d.get("threat", "malware_download"), "tags": d.get("tags", "")})
    return out


def host_of(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def resolve(host, timeout=4):
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host or ""):
        return host
    res = []

    def _go():
        try:
            res.append(socket.gethostbyname(host))
        except OSError:
            pass  # dead phishing/malware domains are normal; don't spam the logs

    t = threading.Thread(target=_go, daemon=True)
    t.start(); t.join(timeout)
    return res[0] if res else None


# ------------------------------------------------------------------ pollers
class Poller:
    def __init__(self, engine):
        self.engine = engine
        self.seen = {"feodo": set(), "blocklist": set(), "dshield": set(), "kev": set(), "phish": set(), "urlhaus": set()}
        self.first = {k: True for k in self.seen}

    def run(self, name, interval, fn):
        def loop():
            time.sleep(1.0)
            while True:
                s = _status(name)
                try:
                    n = fn()
                    s.update(ok=True, last_ok=time.time(), last_error=None, items=n if n is not None else s["items"], polls=s["polls"] + 1)
                except Exception as e:  # noqa: BLE001
                    s.update(ok=False, last_error=str(e)[:160], polls=s["polls"] + 1)
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True, name=f"poll-{name}").start()

    def start(self):
        for n in ("feodo", "blocklist.de", "dshield", "cisa-kev", "openphish", "urlhaus", "threat-sets"):
            _status(n)
        self.run("threat-sets", 3 * 3600, self.poll_threat_sets)
        self.run("feodo", 300, self.poll_feodo)
        self.run("blocklist.de", 60, self.poll_blocklist)
        self.run("dshield", 900, self.poll_dshield)
        self.run("cisa-kev", 1800, self.poll_kev)
        self.run("openphish", 600, self.poll_openphish)
        self.run("urlhaus", 600, self.poll_urlhaus)

    # -- helpers
    def _fresh(self, key, items, keyfn, first_limit):
        """Return items not seen before. On the first poll only emit `first_limit` of them (the rest just seed the set)."""
        seen = self.seen[key]
        new = [i for i in items if keyfn(i) not in seen]
        for i in items:
            seen.add(keyfn(i))
        if self.first[key]:
            self.first[key] = False
            return new[:first_limit]
        return new

    # -- correlation sets
    def poll_threat_sets(self):
        total = 0
        for key, tag in (("et_compromised", "et-compromised"), ("blocklist_all", "blocklist.de"), ("tor_exit", "tor-exit"), ("ipsum", "ipsum")):
            try:
                text = _fetch(URLS[key], 60)
                ips = parse_ipsum(text) if key == "ipsum" else parse_ip_lines(text)
                _add_threat(ips, tag); total += len(ips)
            except Exception as e:  # noqa: BLE001
                _status("threat-sets", last_error=f"{key}: {str(e)[:100]}")
        if total == 0:
            raise RuntimeError("no correlation list could be downloaded")
        return threat_size()

    # -- abuse.ch Feodo Tracker: botnet C2 servers
    def poll_feodo(self):
        rows = parse_feodo(_fetch(URLS["feodo"]))
        _add_threat([r["ip"] for r in rows], "feodo-c2")
        online = [r for r in rows if r["status"] in ("online", "")]
        for r in self._fresh("feodo", online, lambda r: r["ip"], 6):
            self.engine.submit({
                "source": "abuse.ch Feodo", "type": "botnet_c2", "severity": "high", "mitre": ("T1071", "Application Layer Protocol"),
                "ip": r["ip"], "target": "hq", "direction": "in", "tags": ["feodo-c2", str(r["malware"])],
                "title": f"Active {r['malware']} botnet C2 ({r['ip']}:{r['port']})",
                "detail": f"Listed on abuse.ch Feodo Tracker as online. Malware: {r['malware']}. AS: {r['as_name']}. Last online {r['last_online']}. "
                          "Global threat intel; not necessarily communicating with you."})
        return len(rows)

    # -- blocklist.de: IPs that attacked honeypots/fail2ban nodes in the last hour
    def poll_blocklist(self):
        ips = parse_ip_lines(_fetch(URLS["blocklist_de"]))
        _add_threat(ips, "blocklist.de")
        for ip in self._fresh("blocklist", ips, lambda x: x, 20)[:60]:
            self.engine.submit({
                "source": "blocklist.de", "type": "reported_attacker", "severity": "medium", "mitre": ("T1595", "Active Scanning"),
                "ip": ip, "target": "hq", "direction": "in", "tags": ["blocklist.de"],
                "title": "Attacker reported in the last hour from {city}",
                "detail": f"{ip} attacked honeypot / fail2ban sensors worldwide within the last hour (blocklist.de). Global intel, not targeting you specifically."})
        return len(ips)

    # -- SANS ISC DShield: top attacking sources
    def poll_dshield(self):
        rows = parse_dshield(_fetch(URLS["dshield"]))
        _add_threat([r["ip"] for r in rows], "dshield")
        for r in self._fresh("dshield", rows, lambda r: r["ip"], 6):
            sev = "high" if r["targets"] >= 500 else "medium"
            self.engine.submit({
                "source": "SANS DShield", "type": "top_attacker", "severity": sev, "mitre": ("T1046", "Network Service Discovery"),
                "ip": r["ip"], "target": "hq", "direction": "in", "tags": ["dshield"],
                "title": f"DShield top attacker: {r['reports']:,} reports, {r['targets']:,} targets",
                "detail": f"SANS Internet Storm Center ranks {r['ip']} among today's most active scanners. First seen {r['first']}, last {r['last']}."})
        return len(rows)

    # -- CISA Known Exploited Vulnerabilities
    def poll_kev(self):
        rows = parse_kev(_fetch(URLS["kev"], 40))
        for r in self._fresh("kev", rows, lambda r: r["cve"], 5):
            self.engine.submit({
                "source": "CISA KEV", "type": "kev", "severity": "critical" if r["ransomware"] else "high",
                "mitre": ("T1190", "Exploit Public-Facing Application"), "ip": None, "target": "hq", "direction": "in",
                "tags": [r["cve"]] + (["ransomware"] if r["ransomware"] else []),
                "title": f"CISA KEV: {r['cve']} {r['vendor']} {r['product']}",
                "detail": f"{r['name']}. {r['desc']} Required action: {r['action']} Due {r['due']}. Added {r['added']}."
                          + (" Known ransomware campaign use." if r["ransomware"] else "")})
        return len(rows)

    # -- OpenPhish live phishing URLs
    def poll_openphish(self):
        urls = parse_urls(_fetch(URLS["openphish"]))
        for u in self._fresh("phish", urls, lambda u: u, 6)[:8]:
            host = host_of(u)
            ip = resolve(host)
            self.engine.submit({
                "source": "OpenPhish", "type": "phishing", "severity": "medium", "mitre": ("T1566", "Phishing"),
                "ip": ip, "target": "hq", "direction": "in", "tags": ["phishing"],
                "title": f"Live phishing site: {host}",
                "detail": f"OpenPhish lists {host} (resolves to {ip}) as an active phishing page: {u[:140]}"})
        return len(urls)

    # -- URLhaus malware distribution URLs
    def poll_urlhaus(self):
        rows = parse_urlhaus(_fetch(URLS["urlhaus"]))
        for r in self._fresh("urlhaus", rows, lambda r: r["url"], 5)[:6]:
            host = host_of(r["url"]); ip = resolve(host)
            self.engine.submit({
                "source": "abuse.ch URLhaus", "type": "malware_url", "severity": "high", "mitre": ("T1105", "Ingress Tool Transfer"),
                "ip": ip, "target": "hq", "direction": "in", "tags": ["malware-url", r["threat"]],
                "title": f"Malware distribution host: {host}",
                "detail": f"URLhaus lists an online malware URL on {host} ({ip}). Threat: {r['threat']} {r['tags']}"})
        return len(rows)


# ------------------------------------------------------------------ on-demand IP lookup (used by the voice assistant)
def lookup_ip(ip):
    ip = geo.norm_ip(ip)
    if not ip:
        return {"error": "invalid ip"}
    out = {"ip": ip, "public": geo.is_public(ip), "threat_lists": tags_for(ip)}
    g = geo.lookup(ip)
    if g:
        out["geo"] = {k: g.get(k) for k in ("city", "country", "org")}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", headers=UA, timeout=10)
        if r.status_code == 200:
            j = r.json()
            out["shodan"] = {"open_ports": j.get("ports", [])[:15], "known_vulns": j.get("vulns", [])[:10], "tags": j.get("tags", []), "hostnames": j.get("hostnames", [])[:3]}
        elif r.status_code == 404:
            out["shodan"] = "no data"
    except Exception as e:  # noqa: BLE001
        out["shodan_error"] = str(e)[:80]
    try:
        import globalfeeds
        gn = globalfeeds.greynoise(ip)
        if gn:
            out["greynoise"] = gn
    except Exception:  # noqa: BLE001
        pass
    return out

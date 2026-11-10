"""Analyst toolbox. Every tool returns a plain dict. Network tools only touch PUBLIC hosts (SSRF guard) and never scan ports of third parties."""
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

import geo
import intel

UA = {"User-Agent": "VIRUS-VoiceSOC/2.0 (security research)"}
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$", re.I)


class ToolError(Exception):
    pass


def clean_host(s):
    s = (s or "").strip()
    if "://" in s:
        s = urlparse(s).hostname or ""
    s = s.split("/")[0].split(":")[0].strip().lower().rstrip(".")
    if not (HOST_RE.match(s) or geo.norm_ip(s)):
        raise ToolError("enter a valid domain or IP")
    return s


def public_ips(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ToolError(f"{host} does not resolve")
    ips = sorted({i[4][0] for i in infos})
    if not ips or not all(ipaddress.ip_address(i).is_global for i in ips):
        raise ToolError("refusing to contact private / local addresses")
    return ips


# ------------------------------------------------------------------ pure helpers (unit-tested)
def grade_headers(h):
    h = {k.lower(): v for k, v in h.items()}
    checks = [
        ("strict-transport-security", 20, "HSTS forces HTTPS"), ("content-security-policy", 25, "CSP limits script injection (XSS)"),
        ("x-frame-options", 10, "clickjacking protection"), ("x-content-type-options", 10, "stops MIME sniffing"),
        ("referrer-policy", 10, "limits referrer leakage"), ("permissions-policy", 10, "restricts browser features"),
    ]
    res, score = [], 0
    for name, pts, why in checks:
        ok = name in h or (name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""))
        score += pts if ok else 0
        res.append({"header": name, "present": ok, "why": why})
    leak = [k for k in ("server", "x-powered-by") if k in h and re.search(r"\d", h[k])]
    score += 15 if not leak else 0
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
    return {"score": score, "grade": grade, "checks": res, "version_leak": {k: h[k] for k in leak}}


def url_heuristics(url):
    u = urlparse(url if "://" in url else "http://" + url)
    host, flags = (u.hostname or "").lower(), []
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        flags.append("host is a raw IP address")
    if "@" in (u.netloc or ""):
        flags.append("'@' in the address hides the real host")
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("punycode (look-alike characters possible)")
    if host.count(".") >= 4:
        flags.append("very deep sub-domain nesting")
    if len(url) > 120:
        flags.append("unusually long URL")
    if re.search(r"\.(zip|mov|top|xyz|click|gq|cf|tk|ml|ga|work|support)$", host):
        flags.append("high-abuse TLD")
    if re.search(r"(login|verify|secure|account|update|wallet|bank|password)", host):
        flags.append("credential-bait words in the host name")
    if u.scheme == "http":
        flags.append("no HTTPS")
    return {"host": host, "flags": flags, "heuristic_score": min(100, 18 * len(flags))}


def subnet(cidr):
    n = ipaddress.ip_network(cidr.strip(), strict=False)
    hosts = n.num_addresses - (2 if n.version == 4 and n.prefixlen < 31 else 0)
    return {"network": str(n.network_address), "prefix": n.prefixlen, "netmask": str(n.netmask), "broadcast": str(n.broadcast_address) if n.version == 4 else None,
            "first_host": str(n.network_address + (1 if n.version == 4 and n.prefixlen < 31 else 0)), "usable_hosts": max(hosts, 0), "private": n.is_private, "version": n.version}


def hash_kind(h):
    h = h.strip().lower()
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(h)) if re.fullmatch(r"[0-9a-f]+", h) else None


# ------------------------------------------------------------------ tools
def t_ip(q):
    ip = geo.norm_ip(q)
    if not ip:
        raise ToolError("enter a valid IP address")
    r = intel.lookup_ip(ip)
    lists = r.get("threat_lists") or []
    r["verdict"] = "LISTED on live threat feeds: " + ", ".join(lists) if lists else "not on any loaded threat list"
    return r


def doh(name, typ):
    r = requests.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": typ}, headers=dict(UA, accept="application/dns-json"), timeout=10)
    r.raise_for_status()
    return [a.get("data") for a in r.json().get("Answer", []) if a.get("data")]


def t_dns(q):
    d = clean_host(q)
    out = {"domain": d}
    for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            out[t] = doh(d, t)
        except Exception as e:  # noqa: BLE001
            out[t] = f"error: {str(e)[:60]}"
    txt = " ".join(x for x in out.get("TXT", []) if isinstance(x, str))
    try:
        dm = " ".join(doh("_dmarc." + d, "TXT"))
    except Exception:  # noqa: BLE001
        dm = ""
    out["email_security"] = {"spf": "present" if "v=spf1" in txt else "MISSING (spoofing easier)", "dmarc": ("present: " + dm[:80]) if "v=DMARC1" in dm else "MISSING (spoofing easier)"}
    return out


def t_whois(q):
    d = clean_host(q)
    r = requests.get(f"https://rdap.org/domain/{d}", headers=UA, timeout=15)
    if r.status_code == 404:
        raise ToolError("domain not found in RDAP")
    r.raise_for_status()
    j = r.json()
    ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    registrar = None
    for e in j.get("entities", []):
        if "registrar" in e.get("roles", []):
            for item in (e.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn":
                    registrar = item[3]
    out = {"domain": j.get("ldhName", d), "registrar": registrar, "registered": ev.get("registration"), "expires": ev.get("expiration"), "last_changed": ev.get("last changed"),
           "status": j.get("status", []), "nameservers": [n.get("ldhName") for n in j.get("nameservers", [])]}
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(ev["registration"].replace("Z", "+00:00"))).days
        out["age_days"] = age
        out["verdict"] = "NEWLY REGISTERED (<30 days): common for phishing infrastructure" if age < 30 else "established domain"
    except Exception:  # noqa: BLE001
        pass
    return out


def t_tls(q):
    host = clean_host(q)
    public_ips(host)
    ctx, verified = ssl.create_default_context(), True
    try:
        s = socket.create_connection((host, 443), timeout=8)
        ss = ctx.wrap_socket(s, server_hostname=host)
    except ssl.SSLCertVerificationError as e:
        verified = f"FAILED: {e.verify_message}"
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((host, 443), timeout=8)
        ss = ctx.wrap_socket(s, server_hostname=host)
    with ss:
        cert = ss.getpeercert()
        out = {"host": host, "chain_verified": verified, "protocol": ss.version(), "cipher": ss.cipher()[0]}
        if cert:
            na = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            flat = lambda t: {k: v for rdn in t for k, v in rdn}  # noqa: E731
            out.update(subject=flat(cert["subject"]).get("commonName"), issuer=flat(cert["issuer"]).get("organizationName"), expires=na.isoformat(),
                       days_left=(na - datetime.now(timezone.utc)).days, san=[v for k, v in cert.get("subjectAltName", ())][:12])
            out["verdict"] = "EXPIRED" if out["days_left"] < 0 else "expires soon" if out["days_left"] < 14 else "valid"
        else:
            out["note"] = "certificate details unavailable for an unverified chain"
    return out


def t_headers(q):
    host = clean_host(q)
    url, hops = f"https://{host}", []
    for _ in range(4):
        h = urlparse(url).hostname
        public_ips(h)
        r = requests.get(url, headers=UA, timeout=10, allow_redirects=False, stream=True)
        hops.append(f"{r.status_code} {url}")
        if r.is_redirect and r.headers.get("location"):
            url = requests.compat.urljoin(url, r.headers["location"]); r.close(); continue
        break
    out = grade_headers(dict(r.headers)); r.close()
    out.update(final_url=url, hops=hops)
    return out


def t_cve(q):
    q = q.strip()
    p = {"cveId": q.upper()} if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", q) else {"keywordSearch": q, "resultsPerPage": 5}
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=p, headers=UA, timeout=25)
    r.raise_for_status()
    try:
        kev = {k["cve"] for k in intel.parse_kev(intel._fetch(intel.URLS["kev"], 30))}
    except Exception:  # noqa: BLE001
        kev = set()
    items = []
    for v in r.json().get("vulnerabilities", []):
        c = v["cve"]
        m = (c.get("metrics") or {})
        sc = None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if m.get(k):
                sc = m[k][0]["cvssData"]; break
        items.append({"id": c["id"], "published": c.get("published"), "cvss": sc and sc.get("baseScore"), "severity": sc and sc.get("baseSeverity"),
                      "exploited_in_the_wild (CISA KEV)": c["id"] in kev, "description": next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")[:400]})
    if not items:
        raise ToolError("no CVE found")
    return {"results": items}


def t_url(q):
    out = url_heuristics(q)
    host, hits = out["host"], []
    try:
        for name, key in (("OpenPhish", "openphish"), ("URLhaus", "urlhaus")):
            text = intel._fetch(intel.URLS[key], 30)
            urls = intel.parse_urls(text) if key == "openphish" else intel.parse_urlhaus(text)
            urls = [u if isinstance(u, str) else u.get("url", "") for u in urls]
            if any(q.strip() == u or (host and intel.host_of(u) == host) for u in urls):
                hits.append(name)
    except Exception as e:  # noqa: BLE001
        out["feed_error"] = str(e)[:80]
    ip = intel.resolve(host) if host else None
    if ip:
        out["resolves_to"] = ip
        if intel.tags_for(ip):
            hits.append("IP on: " + ", ".join(intel.tags_for(ip)))
    out["live_feed_hits"] = hits
    out["verdict"] = "MALICIOUS - listed on live feeds" if hits else ("suspicious" if out["heuristic_score"] >= 36 else "no indicators found (not proof of safety)")
    return out


def t_hash(q):
    h = q.strip().lower()
    kind = hash_kind(h)
    if not kind:
        raise ToolError("not a valid MD5 / SHA-1 / SHA-256 / SHA-512 hash")
    out = {"hash": h, "type": kind, "virustotal": f"https://www.virustotal.com/gui/file/{h}"}
    key = os.getenv("ABUSECH_AUTH_KEY")
    if not key:
        out["note"] = "set ABUSECH_AUTH_KEY (free) to query MalwareBazaar live"
        return out
    r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": h}, headers=dict(UA, **{"Auth-Key": key}), timeout=25)
    r.raise_for_status()
    j = r.json()
    if j.get("query_status") == "ok":
        d = j["data"][0]
        out.update(verdict="KNOWN MALWARE", family=d.get("signature"), file_type=d.get("file_type"), first_seen=d.get("first_seen"), tags=d.get("tags"))
    else:
        out["verdict"] = "not in MalwareBazaar (" + str(j.get("query_status")) + ")"
    return out


def t_subnet(q):
    try:
        return subnet(q)
    except ValueError:
        raise ToolError("enter a CIDR like 10.0.0.0/24")


TOOLS = {"ip": t_ip, "dns": t_dns, "whois": t_whois, "tls": t_tls, "headers": t_headers, "cve": t_cve, "url": t_url, "hash": t_hash, "subnet": t_subnet}


def run(name, q):
    fn = TOOLS.get(name)
    if not fn:
        return {"ok": False, "error": "unknown tool"}
    t0 = time.time()
    try:
        return {"ok": True, "tool": name, "result": fn(q or ""), "ms": int((time.time() - t0) * 1000)}
    except ToolError as e:
        return {"ok": False, "error": str(e)}
    except requests.RequestException as e:
        return {"ok": False, "error": f"network: {str(e)[:120]}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:120]}"}

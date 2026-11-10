"""IP geolocation with a persistent cache. Primary: ip-api.com batch (100 IPs/request). Fallback: ipwho.is."""
import os
import json
import time
import threading
import ipaddress
import requests

UA = {"User-Agent": "VIRUS-VoiceSOC/2.0"}
_cache = {}
_lock = threading.Lock()
_last_batch = 0.0
_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".geo_cache.json")
_home = None


def _load():
    try:
        with open(_CACHE_FILE) as f:
            _cache.update(json.load(f))
    except Exception:
        pass


def _save():
    try:
        with open(_CACHE_FILE, "w") as f:
            json.dump(dict(list(_cache.items())[-5000:]), f)
    except Exception:
        pass


_load()


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def norm_ip(s):
    """Normalise zero-padded octets (SANS ISC style 001.002.003.004) and strip junk."""
    s = (s or "").strip().strip("[]")
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        s = ".".join(str(int(p)) for p in parts)
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return ""


def _fmt_ipapi(j):
    if j.get("status") != "success":
        return None
    return {"ip": j.get("query"), "country": j.get("country"), "cc": j.get("countryCode"), "city": j.get("city") or j.get("country"),
            "lat": j.get("lat"), "lon": j.get("lon"), "org": j.get("org") or j.get("as")}


def _ipwho(ip):
    try:
        r = requests.get(f"https://ipwho.is/{ip}", headers=UA, timeout=8)
        j = r.json()
        if not j.get("success"):
            return None
        return {"ip": ip, "country": j.get("country"), "cc": j.get("country_code"), "city": j.get("city") or j.get("country"),
                "lat": j.get("latitude"), "lon": j.get("longitude"), "org": (j.get("connection") or {}).get("org")}
    except Exception:
        return None


def _batch(ips):
    global _last_batch
    wait = 4.2 - (time.time() - _last_batch)  # free tier: 15 batch requests / minute
    if wait > 0:
        time.sleep(wait)
    _last_batch = time.time()
    try:
        r = requests.post("http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,org,as,query",
                          json=[{"query": ip} for ip in ips], headers=UA, timeout=15)
        if r.status_code == 200:
            return {j.get("query"): _fmt_ipapi(j) for j in r.json()}
    except Exception:
        pass
    return None


def lookup_many(ips):
    """Return {ip: geo|None} for public IPs. Cached; failures are cached briefly as None."""
    ips = [i for i in dict.fromkeys(ips) if is_public(i)]
    out, need = {}, []
    with _lock:
        for i in ips:
            if i in _cache:
                out[i] = _cache[i]
            else:
                need.append(i)
    for k in range(0, len(need), 100):
        chunk = need[k:k + 100]
        res = _batch(chunk)
        if res is None:  # batch endpoint down -> per-IP fallback (bounded)
            res = {ip: _ipwho(ip) for ip in chunk[:15]}
        with _lock:
            for ip in chunk:
                g = res.get(ip)
                if g:
                    _cache[ip] = g
                out[ip] = g
    if need:
        _save()
    return out


def lookup(ip):
    return lookup_many([ip]).get(ip)


def home():
    """Where this SOC sits: env override, else geolocate our public IP."""
    global _home
    if _home:
        return _home
    lat, lon = os.getenv("HOME_LAT"), os.getenv("HOME_LON")
    if lat and lon:
        _home = {"ip": None, "city": os.getenv("HOME_CITY", "Home"), "lat": float(lat), "lon": float(lon), "source": "env"}
        return _home
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            ip = requests.get(url, headers=UA, timeout=6).text.strip()
            g = lookup(ip)
            if g:
                _home = dict(g, ip=ip, source="public-ip")
                return _home
        except Exception:
            continue
    _home = {"ip": None, "city": "Dubai (default - set HOME_LAT/HOME_LON)", "lat": 25.2048, "lon": 55.2708, "source": "fallback"}
    return _home


_countries = None


def country_xy(cc):
    """Offline ISO-2 -> (lat, lon, name) for aggregate (country-level) data such as Cloudflare Radar. None if unknown."""
    global _countries
    if _countries is None:
        try:
            with open(os.path.join(os.path.dirname(__file__), "data", "countries.json"), encoding="utf-8") as f:
                _countries = json.load(f)
        except Exception:
            _countries = {}
    r = _countries.get((cc or "").upper())
    return (r[0], r[1], r[2]) if r else None

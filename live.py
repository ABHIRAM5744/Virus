"""Real-time world objects drawn on the globe: satellites (Celestrak TLEs, propagated in the browser with SGP4), aircraft (OpenSky ADS-B)
and earthquakes (USGS). Parsers are pure (tests/test_live.py); results are cached so many browser tabs do not hammer the providers."""
import threading
import time

import requests

UA = {"User-Agent": "VIRUS-VoiceSOC/2.0 (security research)"}
_cache, _lock = {}, threading.Lock()

CELESTRAK = "https://celestrak.org/NORAD/elements/gp.php?GROUP={}&FORMAT=tle"
# group -> max satellites to plot (starlink is thousands: sample it)
GROUPS = {"stations": 40, "gps-ops": 32, "weather": 20, "science": 20, "starlink": 90}


def parse_tle(text, group=""):
    lines = [l.rstrip() for l in (text or "").splitlines() if l.strip()]
    out = []
    for i in range(0, len(lines) - 2):
        if lines[i + 1].startswith("1 ") and lines[i + 2].startswith("2 "):
            out.append({"n": lines[i].strip(), "g": group, "l1": lines[i + 1], "l2": lines[i + 2]})
    return out


def parse_opensky(j, limit=1500):
    out = []
    for s in (j or {}).get("states") or []:
        try:
            lon, lat, alt, ground = s[5], s[6], s[7], s[8]
            if lon is None or lat is None or ground:
                continue
            out.append([s[0], (s[1] or "").strip(), round(lat, 3), round(lon, 3), int(alt or 0), int(s[10] or 0), int(s[9] or 0), s[2]])
        except (IndexError, TypeError, ValueError):
            continue
    if len(out) > limit:
        step = len(out) / limit
        out = [out[int(i * step)] for i in range(limit)]
    return out


def parse_quakes(j):
    out = []
    for f in (j or {}).get("features") or []:
        try:
            p, c = f["properties"], f["geometry"]["coordinates"]
            out.append({"id": f.get("id"), "mag": p.get("mag"), "place": p.get("place"), "time": p.get("time"), "lon": c[0], "lat": c[1], "depth": c[2], "url": p.get("url")})
        except (KeyError, TypeError, IndexError):
            continue
    return out


def _cached(key, ttl, fn):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    try:
        val = fn()
    except Exception:
        if hit:                      # serve stale data rather than nothing
            return dict(hit[1], stale=True)
        raise
    with _lock:
        _cache[key] = (time.time(), val)
    return val


def satellites():
    def fetch():
        sats, errs = [], []
        for g, cap in GROUPS.items():
            try:
                r = requests.get(CELESTRAK.format(g), headers=UA, timeout=25)
                r.raise_for_status()
                rows = parse_tle(r.text, g)
                if len(rows) > cap:
                    step = len(rows) / cap
                    rows = [rows[int(i * step)] for i in range(cap)]
                sats += rows
            except Exception as e:  # noqa: BLE001
                errs.append(f"{g}: {str(e)[:60]}")
        if not sats:   # fallback: ISS only
            r = requests.get("https://tle.ivanstanojevic.de/tle/25544", headers=UA, timeout=20)
            r.raise_for_status()
            j = r.json()
            sats = [{"n": j["name"], "g": "stations", "l1": j["line1"], "l2": j["line2"]}]
            errs.append("celestrak unreachable, ISS only")
        return {"sats": sats, "errors": errs, "source": "celestrak.org", "fetched": time.time()}
    return _cached("sats", 6 * 3600, fetch)


def aircraft():
    def fetch():
        r = requests.get("https://opensky-network.org/api/states/all", headers=UA, timeout=25)
        r.raise_for_status()
        return {"planes": parse_opensky(r.json()), "source": "opensky-network.org (ADS-B)", "fetched": time.time()}
    return _cached("planes", 40, fetch)


def quakes():
    def fetch():
        r = requests.get("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson", headers=UA, timeout=25)
        r.raise_for_status()
        return {"quakes": parse_quakes(r.json()), "source": "USGS (M2.5+ last 24h)", "fetched": time.time()}
    return _cached("quakes", 180, fetch)

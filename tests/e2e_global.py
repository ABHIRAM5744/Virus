"""Real FireHOL data -> GlobalFeeds -> Engine global sightings. Geolocation is stubbed ONLY if ip-api is unreachable (sandbox)."""
import os, sys, time, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import geo, soc, globalfeeds

if geo.lookup("8.8.8.8") is None:
    print("(ip-api unreachable here: using deterministic stub geolocation)")
    geo.lookup_many = lambda ips: {ip: {"lat": random.uniform(-50, 60), "lon": random.uniform(-150, 150), "country": "Testland", "city": "T", "org": "x"} for ip in ips}
e = soc.Engine(); e.register_node("hq", "HQ", "server", 25.2, 55.3, "Dubai")
gf = globalfeeds.GlobalFeeds(e)
n = gf.poll_firehol()
time.sleep(1.5)
st = e.stats()
print("list size", n, "| sightings", len(e.gevents), "| sources", st["global_by_source"])
assert n > 1000 and len(e.gevents) >= 20
assert all(x["scope"] == "global" and x["src"]["lat"] is not None for x in e.gevents)
assert not e.events, "global sightings must not become attacks on our node"
e.set_flows([{"from": "RU", "to": "US", "pct": 5.0}], {"source": "test"}); assert e.state()["flows"]
print("E2E GLOBAL PASSED")

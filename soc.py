"""SOC engine: receives REAL events from intel feeds, host monitor, asset monitor and honeypot; geolocates, paces and publishes them.

No event in this module is generated. Everything arrives through submit().
"""
import queue
import threading
import time
import uuid
from datetime import datetime, timezone

import firewall
import geo
import intel

SEV_W = {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 12}
SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _now():
    return datetime.now(timezone.utc)


class Engine:
    def __init__(self):
        self.lock = threading.RLock()
        self.nodes = {}
        self.events = []
        self.blocked = {}          # ip -> firewall result
        self.blocked_hits = 0
        self.total = 0
        self.by_source = {}
        self.pending = None
        self.subs = []
        self.history = []
        self.actions_log = []
        self.recent = {}           # dedupe key -> ts
        self.gevents = []          # global sightings (attacks seen elsewhere on the internet)
        self.gtotal = 0
        self.gby_source = {}
        self.flows = []            # aggregate country->country attack flows (Cloudflare Radar)
        self.flows_meta = {}
        self.q = queue.Queue(800)
        self.asset_monitor = None
        self._started = False

    # ------------------------------------------------------------ pubsub
    def subscribe(self):
        q = queue.Queue(maxsize=300)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, msg):
        with self.lock:
            subs = list(self.subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass

    # ------------------------------------------------------------ nodes
    def register_node(self, nid, name, kind, lat, lon, city, meta=None, scan_target=None):
        with self.lock:
            n = self.nodes.get(nid) or {"id": nid, "status": "ok", "since": time.time()}
            n.update(name=name, kind=kind, lat=lat, lon=lon, city=city, scan_target=scan_target)
            n.setdefault("meta", {}).update(meta or {})
            self.nodes[nid] = n
            nd = dict(n)
        self.publish({"kind": "node", "node": nd})

    def set_meta(self, nid, **kw):
        with self.lock:
            n = self.nodes.get(nid)
            if not n:
                return
            n["meta"].update(kw)
            nd = dict(n)
        self.publish({"kind": "node", "node": nd})

    def set_status(self, nid, status):
        with self.lock:
            n = self.nodes.get(nid)
            if not n or n["status"] == status:
                return
            n["status"] = status
            n["since"] = time.time()
            nd = dict(n)
            stats = self.stats()
        self.publish({"kind": "node", "node": nd})
        self.publish({"kind": "stats", "stats": stats})

    # ------------------------------------------------------------ lifecycle
    def start(self):
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._worker, daemon=True, name="pacer").start()
        threading.Thread(target=self._housekeeping, daemon=True, name="house").start()

    def _housekeeping(self):
        while True:
            time.sleep(20)
            now = time.time()
            with self.lock:
                for k in [k for k, t in self.recent.items() if now - t > 600]:
                    self.recent.pop(k, None)
                if self.pending and now - self.pending.get("ts", now) > 300:
                    self.pending = None
                    self.publish({"kind": "pending", "pending": None})
                expire = [n["id"] for n in self.nodes.values() if n["kind"] == "host" and n["status"] in ("warn", "compromised") and now - n["since"] > 600]
            for nid in expire:
                self.set_status(nid, "ok")

    # ------------------------------------------------------------ intake
    def submit(self, c):
        """c: dict(source,type,title,severity,mitre,ip|None,target,direction,tags,detail,actionable)"""
        if c["severity"] in ("high", "critical"):
            threading.Thread(target=self._process, args=([c],), daemon=True).start()   # no pacing for important events
            return
        try:
            self.q.put_nowait(c)
        except queue.Full:
            pass

    def submit_global(self, items):
        """Global-scope sightings: attacks / malicious infrastructure observed anywhere. They are drawn on the globe where they
        originate; they are NOT drawn as attacks on our node. items: dicts with source,type,title,detail,severity,tags,mitre and
        either `ip` (geolocated online) or `cc` (ISO-2 country, offline)."""
        if items:
            threading.Thread(target=self._process_global, args=(list(items),), daemon=True).start()

    def _process_global(self, items):
        ips = [c["ip"] for c in items if c.get("ip") and geo.is_public(c["ip"])]
        geos = geo.lookup_many(ips) if ips else {}
        out = []
        for c in items:
            try:
                ip, g, cc = c.get("ip"), None, c.get("cc")
                if ip:
                    g = geos.get(ip)
                    if not g:
                        continue
                    lat, lon, country, city, org = g.get("lat"), g.get("lon"), g.get("country"), g.get("city"), g.get("org")
                else:
                    xy = geo.country_xy(cc)
                    if not xy:
                        continue
                    lat, lon, country, city, org = xy[0], xy[1], xy[2], None, None
                if lat is None or lon is None:
                    continue
                key = ("g", c["type"], ip or c["title"], cc)
                with self.lock:
                    if time.time() - self.recent.get(key, 0) < 3600:
                        continue
                    self.recent[key] = time.time()
                out.append({"id": uuid.uuid4().hex[:8], "ts": _now().isoformat(timespec="seconds"), "epoch": time.time(), "scope": "global",
                            "type": c["type"], "title": c["title"].replace("{city}", city or country or "unknown"), "detail": c.get("detail", ""),
                            "severity": c.get("severity", "medium"), "source": c["source"], "tags": c.get("tags", []),
                            "mitre": {"id": c["mitre"][0], "name": c["mitre"][1]} if c.get("mitre") else None,
                            "src": {"ip": ip, "city": city, "country": country, "lat": lat, "lon": lon, "org": org}})
            except Exception as e:  # noqa: BLE001
                print("global process error:", e)
        if not out:
            return
        with self.lock:
            self.gevents.extend(out)
            self.gevents = self.gevents[-600:]
            self.gtotal += len(out)
            for e in out:
                self.gby_source[e["source"]] = self.gby_source.get(e["source"], 0) + 1
            stats = self.stats()
        self.publish({"kind": "global", "items": out})
        self.publish({"kind": "stats", "stats": stats})

    def set_flows(self, flows, meta):
        """flows: [{from,to,from_name,to_name,from_xy,to_xy,pct,layer}] aggregate country-to-country attack traffic."""
        with self.lock:
            self.flows, self.flows_meta = flows, meta
        self.publish({"kind": "flows", "flows": flows, "meta": meta})

    def _worker(self):
        while True:
            batch = [self.q.get()]
            time.sleep(0.2)
            while len(batch) < 40:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            self._process(batch, paced=True)

    def _process(self, batch, paced=False):
        ips = [c["ip"] for c in batch if c.get("ip")]
        geos = geo.lookup_many(ips) if ips else {}
        h = geo.home()
        for c in batch:
            try:
                ip = c.get("ip")
                src = None
                if ip:
                    if ip in self.blocked:
                        with self.lock:
                            self.blocked_hits += 1
                        self.publish({"kind": "stats", "stats": self.stats()})
                        continue
                    g = geos.get(ip) if geo.is_public(ip) else {"city": "Local network", "country": "LAN", "lat": h["lat"] + 0.4, "lon": h["lon"] + 0.4, "org": "private address"}
                    src = {"ip": ip, "city": (g or {}).get("city") or "unknown", "country": (g or {}).get("country"),
                           "lat": (g or {}).get("lat"), "lon": (g or {}).get("lon"), "org": (g or {}).get("org")}
                key = (c["type"], ip, c["target"], c["title"][:40])
                with self.lock:
                    if time.time() - self.recent.get(key, 0) < 300:
                        continue
                    self.recent[key] = time.time()
                title = c["title"].replace("{city}", (src or {}).get("city") or "unknown")
                detail = c["detail"].replace("{org}", (src or {}).get("org") or "unknown org")
                self._emit(c, title, detail, src)
            except Exception as e:  # noqa: BLE001
                print("process error:", e)
            if paced:
                time.sleep(1.6)

    def _emit(self, c, title, detail, src):
        sev, target = c["severity"], self.nodes.get(c["target"]) or self.nodes.get("hq")
        if not target:
            return
        ev = {"id": uuid.uuid4().hex[:8], "ts": _now().isoformat(timespec="seconds"), "epoch": time.time(), "type": c["type"], "title": title,
              "severity": sev, "mitre": {"id": c["mitre"][0], "name": c["mitre"][1]}, "src": src, "direction": c.get("direction", "in"),
              "target": {"id": target["id"], "name": target["name"], "city": target["city"]}, "detail": detail, "source": c["source"],
              "tags": c.get("tags", [])}
        node_msg = None
        with self.lock:
            self.total += 1
            self.by_source[c["source"]] = self.by_source.get(c["source"], 0) + 1
            self.events.append(ev)
            self.events = self.events[-300:]
            real_target = c["source"] in ("host", "auth.log", "honeypot", "asset-monitor", "scan")
            if real_target and sev == "critical" and target["status"] != "compromised":
                target["status"] = "compromised"; target["since"] = time.time(); node_msg = dict(target)
            elif real_target and sev == "high" and target["status"] == "ok":
                target["status"] = "warn"; target["since"] = time.time(); node_msg = dict(target)
            if c.get("actionable") and src and src.get("ip") and geo.is_public(src["ip"]) and src["ip"] not in self.blocked and SEV_ORDER.index(sev) >= 2:
                cur = self.pending
                if cur is None or sev == "critical":
                    self.pending = {"type": "block_ip", "ip": src["ip"], "city": src["city"], "event_id": ev["id"], "node": target["id"],
                                    "severity": sev, "title": title, "ts": time.time(), "direction": ev["direction"]}
            pending, stats = self.pending, self.stats()
        self.publish({"kind": "event", "event": ev})
        if node_msg:
            self.publish({"kind": "node", "node": node_msg})
        self.publish({"kind": "pending", "pending": pending})
        self.publish({"kind": "stats", "stats": stats})

    # ------------------------------------------------------------ stats / state
    def stats(self):
        now = time.time()
        with self.lock:
            recent = [e for e in self.events if now - e["epoch"] < 300 and e["severity"] != "info"]
            crit = sum(1 for n in self.nodes.values() if n["status"] == "compromised")
            warn = sum(1 for n in self.nodes.values() if n["status"] == "warn")
            risk = 6 + 0.55 * sum(SEV_W[e["severity"]] for e in recent) + 12 * crit + 4 * warn
            sev_counts = {s: 0 for s in SEV_ORDER}
            for e in self.events:
                sev_counts[e["severity"]] += 1
            src = list(intel.SOURCES.values())
            g_recent = [e for e in self.gevents if now - e["epoch"] < 3600]
            origins = {}
            for e in g_recent:
                k = e["src"].get("country") or "?"
                origins[k] = origins.get(k, 0) + 1
            return {"global_total": self.gtotal, "global_1h": len(g_recent), "global_by_source": dict(self.gby_source),
                    "top_origins": sorted(origins.items(), key=lambda kv: -kv[1])[:8], "risk": int(max(4, min(100, risk))), "total": self.total, "blocked_ips": sorted(self.blocked), "blocked_hits": self.blocked_hits,
                    "critical_nodes": crit, "warn_nodes": warn, "by_severity": sev_counts, "by_source": dict(self.by_source),
                    "sources_ok": sum(1 for s in src if s.get("ok")), "sources_total": len(src), "intel_ips": intel.threat_size()}

    def state(self):
        with self.lock:
            return {"nodes": list(self.nodes.values()), "events": self.events[-60:], "stats": self.stats(), "pending": self.pending,
                    "sources": list(intel.SOURCES.values()), "global_events": self.gevents[-150:], "flows": self.flows, "flows_meta": self.flows_meta}

    def snapshot_for_llm(self):
        with self.lock:
            return {
                "stats": {k: v for k, v in self.stats().items() if k in ("risk", "total", "blocked_ips", "critical_nodes", "by_severity", "by_source", "intel_ips")},
                "nodes": [{"id": n["id"], "name": n["name"], "kind": n["kind"], "city": n["city"], "status": n["status"], "meta": n["meta"]} for n in self.nodes.values()],
                "recent_events": [{"id": e["id"], "title": e["title"], "severity": e["severity"], "source": e["source"], "target": e["target"]["id"],
                                   "src_ip": (e["src"] or {}).get("ip"), "src_city": (e["src"] or {}).get("city"), "tags": e["tags"]} for e in self.events[-10:]],
                "pending_action": self.pending,
                "data_sources": [{"name": s["name"], "ok": s["ok"]} for s in intel.SOURCES.values()],
            }

    # ------------------------------------------------------------ actions
    def resolve_node(self, q):
        q = (q or "").lower().strip()
        if not q:
            return None
        with self.lock:
            if q in self.nodes:
                return self.nodes[q]
            for n in self.nodes.values():
                if q in n["id"].lower() or q in n["name"].lower() or n["name"].lower() in q or q in n["kind"]:
                    return n
        return None

    def _block(self, ip):
        res = firewall.block(ip)
        if res.get("ok"):
            with self.lock:
                self.blocked[ip] = res
                if self.pending and self.pending.get("ip") == ip:
                    self.pending = None
                pend, stats = self.pending, self.stats()
            self.publish({"kind": "pending", "pending": pend})
            self.publish({"kind": "stats", "stats": stats})
        return res

    def apply(self, actions):
        """Execute actions from the assistant/UI. Returns (results, client_actions)."""
        results, client = [], []
        for a in (actions or [])[:5]:
            t = a.get("type")
            try:
                if t == "block_ip":
                    ip = a.get("ip") or (self.pending or {}).get("ip")
                    res = self._block(ip) if ip else {"ok": False, "error": "no ip"}
                    results.append(dict(res, type=t, ip=ip))
                elif t == "confirm_pending":
                    p = self.pending
                    if not p:
                        results.append({"type": t, "ok": False, "error": "nothing pending"})
                        continue
                    results.append(dict(self._block(p["ip"]), type="block_ip", ip=p["ip"]))
                elif t == "deny_pending":
                    with self.lock:
                        self.pending = None
                    self.publish({"kind": "pending", "pending": None})
                    results.append({"type": t, "ok": True})
                elif t in ("ack_node", "release_node", "isolate_node"):
                    node = self.resolve_node(a.get("node")) or (self.nodes.get((self.pending or {}).get("node")))
                    if not node:
                        results.append({"type": t, "ok": False, "error": "unknown node"})
                        continue
                    self.set_status(node["id"], "ok")
                    results.append({"type": "ack_node", "ok": True, "node": node["id"]})
                elif t == "lookup_ip":
                    r = intel.lookup_ip(a.get("ip", ""))
                    results.append({"type": t, "ok": "error" not in r, "result": r})
                elif t == "run_tool":
                    import tools
                    r = tools.run(str(a.get("tool", "")), str(a.get("input", ""))[:300])
                    results.append({"type": t, "ok": r.get("ok", False), "result": r.get("result", r)})
                elif t in ("set_view", "toggle_layer"):
                    client.append(dict(a)); results.append({"type": t, "ok": True})
                elif t == "run_scan":
                    node = self.resolve_node(a.get("node"))
                    if not node or not self.asset_monitor:
                        results.append({"type": t, "ok": False, "error": "scan works only on assets you configured in ASSETS"})
                        continue
                    r = self.asset_monitor.scan(node["id"])
                    results.append({"type": t, "ok": "error" not in r, "result": r})
                    client.append({"type": "focus_node", "node": node["id"]})
                elif t == "focus_node":
                    node = self.resolve_node(a.get("node"))
                    if node:
                        client.append({"type": t, "node": node["id"]})
                        results.append({"type": t, "ok": True, "node": node["id"]})
                    else:
                        results.append({"type": t, "ok": False})
                elif t in ("filter_severity", "open_report", "toggle_rotation"):
                    client.append(a)
                    results.append({"type": t, "ok": True})
                else:
                    results.append({"type": t, "ok": False, "error": "unknown action"})
            except Exception as e:  # noqa: BLE001
                results.append({"type": t, "ok": False, "error": str(e)[:120]})
        with self.lock:
            self.actions_log += [r for r in results if r.get("ok")]
            self.actions_log = self.actions_log[-50:]
        return results, client

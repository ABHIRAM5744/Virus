"""VIRUS Voice SOC - multilingual voice-driven security operations centre (live data).

mic -> Gnani Prisma STT -> LLM router (Groq / Gemini / Claude) -> SOC actions -> Gnani Timbre TTS
"""
import os
import json
import time
import base64
import queue
import re
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

load_dotenv()

import assets  # noqa: E402
import geo  # noqa: E402
import gnani  # noqa: E402
import honeypot  # noqa: E402
import hostmon  # noqa: E402
import intel  # noqa: E402
import llm  # noqa: E402
import soc  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
engine = soc.Engine()


@app.before_request
def _password_gate():
    """Optional site-wide login when deployed publicly: set APP_PASSWORD (any username works)."""
    import hmac
    pw = os.getenv("APP_PASSWORD")
    if not pw or request.path in ("/api/health", "/api/ingest"):  # health check for Render; ingest has its own token
        return None
    a = request.authorization
    if a and a.password and hmac.compare_digest(a.password.encode(), pw.encode()):
        return None
    return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="VIRUS SOC"'})

LANG_NAMES = {
    "en-IN": "English", "hi-IN": "Hindi", "hi-en": "Hinglish (Hindi written in Latin script mixed with English)",
    "ta-IN": "Tamil", "te-IN": "Telugu", "kn-IN": "Kannada", "ml-IN": "Malayalam", "mr-IN": "Marathi",
    "bn-IN": "Bengali", "gu-IN": "Gujarati", "pa-IN": "Punjabi",
}

ASSISTANT_PROMPT = """You are VIRUS, a calm, sharp voice assistant inside a Security Operations Centre.
The analyst speaks to you; your reply is read aloud by a text-to-speech engine.

LIVE SOC SNAPSHOT (real data: public threat feeds, this machine's network connections, the analyst's own monitored assets, honeypot):
{snapshot}

Reply with ONE JSON object and nothing else:
{{"reply": "<spoken answer>", "lang": "<code>", "actions": [ ... ]}}

Rules for "reply":
- Same language as the analyst. If they speak Hindi/Tamil/etc. answer in that language in its NATIVE script. For Hinglish answer in Hinglish (Latin script).
- At most 2 short sentences (under 45 words). No markdown, no emojis, no bullet points.
- Write numbers as spoken words in that language (not digits). Do not read full IP addresses; say the city or organisation instead.
- Only state facts present in the snapshot or in tool results. If data is missing, say so. Never invent events, IPs or numbers.
"lang" is one of: en-IN hi-IN hi-en ta-IN te-IN kn-IN ml-IN mr-IN bn-IN gu-IN pa-IN. Pick the language you replied in.

Allowed actions (use only when the analyst asks, or confirms a pending action):
- {{"type":"block_ip","ip":"<ip>"}}            block an attacker IP at the firewall (dry-run unless ENABLE_FIREWALL=1)
- {{"type":"confirm_pending"}}                  analyst said yes / haan / ho / aamam / sari to the pending_action question
- {{"type":"deny_pending"}}                     analyst said no / nahi to the pending_action question
- {{"type":"ack_node","node":"<node id>"}}     acknowledge and clear a node's alert state
- {{"type":"focus_node","node":"<node id>"}}   rotate the 3D globe to a node
- {{"type":"lookup_ip","ip":"<ip>"}}           live reputation + geolocation + open-ports lookup of an IP (use ips from the snapshot)
- {{"type":"run_scan","node":"<node id>"}}     real TCP scan, works only for kind=asset nodes
- {{"type":"run_tool","tool":"dns|whois|tls|headers|cve|url|hash|subnet|ip","input":"<domain / url / CVE id / hash / cidr / ip>"}}  live security tool (DNS+SPF/DMARC, WHOIS, TLS cert, HTTP header grade, CVE+CISA-KEV, URL check, hash lookup, subnet calc)
- {{"type":"set_view","view":"realistic|tactical|flat"}}   switch the globe look (realistic 3D earth, tactical HUD, flat 2D map)
- {{"type":"toggle_layer","layer":"satellites|aircraft|quakes|clouds|daynight|sightings|flows","on":true}}
- {{"type":"filter_severity","level":"info|low|medium|high|critical"}}
- {{"type":"open_report"}}                      generate the full incident report
For lookup_ip, run_scan and run_tool you will receive the results and then give the spoken answer; put a short placeholder reply for now.
If the analyst only asks a question, return "actions": []. Never invent node ids or IPs; use the snapshot.
"""


def clean_reply(text):
    return re.sub(r"[*_`#>]", "", text or "").strip()


# ----------------------------------------------------------------------------- offline fallback
def heuristic(text, snap):
    t = (text or "").lower()
    words = set(re.findall(r"\w+", t))
    pend = snap.get("pending_action")
    acts, reply = [], None
    yes = bool(words & {"yes", "yeah", "haan", "han", "karo", "confirm", "approve", "aamam", "sari", "ho"}) or "go ahead" in t or "kar do" in t
    no = bool(words & {"no", "nahi", "nahin", "mat", "cancel", "deny", "vendam"})
    if pend and ("block" in words or yes) and not no:
        acts, reply = [{"type": "confirm_pending"}], "Blocking the attacker."
    elif pend and no:
        acts, reply = [{"type": "deny_pending"}], "Okay, I will leave it as is."
    elif "report" in words and ("generate" in words or "incident" in words or "full" in words):
        acts, reply = [{"type": "open_report"}], "Generating the incident report now."
    else:
        s = snap["stats"]
        reply = (f"Threat level is {s['risk']} percent with {s['total']} live events so far. "
                 f"{s['critical_nodes']} nodes are in critical state.")
    return {"reply": reply, "lang": "en-IN", "actions": acts}


INFO_ACTIONS = {"lookup_ip", "run_scan", "run_tool"}


def _llm_json(system, messages, max_tokens=500):
    raw, provider = llm.chat("fast", system, messages, max_tokens=max_tokens, json_mode=True, timeout=20)
    return llm.parse_json(raw), provider


# ----------------------------------------------------------------------------- core assistant
def run_assistant(text, ui_lang="auto"):
    snap = engine.snapshot_for_llm()
    system = ASSISTANT_PROMPT.format(snapshot=json.dumps(snap, ensure_ascii=False, default=str))
    if ui_lang in LANG_NAMES:
        system += f"\nThe analyst selected {LANG_NAMES[ui_lang]}; reply in it unless they clearly speak another language.\n"
    messages = engine.history[-8:] + [{"role": "user", "content": text}]
    provider, err = None, None
    try:
        data, provider = _llm_json(system, messages)
    except Exception as e:  # noqa: BLE001
        err = str(e)
        data, provider = heuristic(text, snap), "offline-fallback"
    actions = [a for a in (data.get("actions") if isinstance(data.get("actions"), list) else []) if isinstance(a, dict)]
    results, client = engine.apply(actions)
    # tool loop: lookups/scans return data the spoken answer must be based on
    if any(r["type"] in INFO_ACTIONS for r in results) and provider != "offline-fallback":
        try:
            tool_msg = "TOOL RESULTS (real, live): " + json.dumps([r for r in results if r["type"] in INFO_ACTIONS], ensure_ascii=False, default=str)[:3500]
            data2, provider = _llm_json(system, messages + [
                {"role": "assistant", "content": json.dumps(data, ensure_ascii=False)},
                {"role": "user", "content": tool_msg + "\nNow give the final spoken answer in the analyst's language, using only these results. Return the same JSON format with \"actions\": []."}])
            data["reply"], data["lang"] = data2.get("reply", data.get("reply")), data2.get("lang", data.get("lang"))
        except Exception as e:  # noqa: BLE001
            err = (err or "") + f" tool-pass: {e}"
    reply = clean_reply(data.get("reply")) or "Understood."
    lang = data.get("lang") if data.get("lang") in gnani.TTS_LANGS else (ui_lang if ui_lang in gnani.TTS_LANGS else "auto")
    engine.history += [{"role": "user", "content": text}, {"role": "assistant", "content": json.dumps({"reply": reply, "lang": lang, "actions": actions}, ensure_ascii=False)}]
    engine.history = engine.history[-16:]
    return {"reply": reply, "lang": lang, "results": results, "client_actions": client, "provider": provider, "llm_error": err}


def speak(text, lang):
    try:
        wav = gnani.tts(text, lang)
        return {"audio_b64": base64.b64encode(wav).decode(), "audio_mime": "audio/wav"}
    except Exception as e:  # noqa: BLE001
        return {"tts_error": str(e)}


# ----------------------------------------------------------------------------- routes
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({
        "gnani": gnani.configured(),
        "llm": llm.configured(),
        "llm_stats": llm.STATS,
        "llm_status": llm.status(),
        "uptime_events": engine.total,
        "sources": list(intel.SOURCES.values()),
        "intel_ips": intel.threat_size(),
        "firewall_enforcing": os.getenv("ENABLE_FIREWALL") == "1",
    })


@app.get("/api/state")
def state():
    return jsonify(engine.state())


@app.get("/api/stream")
def stream():
    q = engine.subscribe()

    def gen():
        try:
            yield "retry: 2000\n\n"
            while True:
                try:
                    msg = q.get(timeout=15)
                except queue.Empty:
                    yield ": ping\n\n"
                    continue
                yield f"data: {json.dumps(msg)}\n\n"
        finally:
            engine.unsubscribe(q)

    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/voice")
def voice():
    f = request.files.get("audio")
    if not f:
        return jsonify({"error": "no audio"}), 400
    ui_lang = request.form.get("lang", "auto")
    t0 = time.time()
    try:
        stt = gnani.stt(f.read(), ui_lang, f.filename or "speech.wav", f.mimetype or "audio/wav")
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Speech recognition failed - {e}"}), 502
    if not stt["text"]:
        return jsonify({"error": "I could not hear anything. Try again closer to the mic.", "empty": True}), 200
    t1 = time.time()
    # if Prisma detected a language and the UI is on auto, hint the assistant with it
    hint = stt.get("lang") if ui_lang == "auto" else ui_lang
    out = run_assistant(stt["text"], hint or "auto")
    t2 = time.time()
    out.update(speak(out["reply"], out["lang"]))
    t3 = time.time()
    out.update({"transcript": stt["text"], "detected_lang": stt.get("lang"), "stt_note": stt.get("note"),
                "timings": {"stt": round(t1 - t0, 2), "llm": round(t2 - t1, 2), "tts": round(t3 - t2, 2)}})
    return jsonify(out)


@app.get("/api/live/<kind>")
def live_data(kind):
    import live
    fn = {"satellites": live.satellites, "aircraft": live.aircraft, "quakes": live.quakes}.get(kind)
    if not fn:
        return jsonify({"error": "unknown"}), 404
    try:
        return jsonify(fn())
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"{kind} source unreachable: {str(e)[:120]}"}), 502


@app.post("/api/tool")
def run_tool():
    import tools
    d = request.get_json(silent=True) or {}
    return jsonify(tools.run(d.get("tool", ""), str(d.get("input", ""))[:300]))


@app.post("/api/tool/explain")
def explain_tool():
    d = request.get_json(silent=True) or {}
    data = json.dumps(d.get("result", {}))[:3500]
    system = "You are VIRUS, a SOC analyst assistant. Explain tool output to a junior analyst: verdict first, then 2-4 short bullets of what matters and the next action. No fluff."
    try:
        text, prov = llm.chat("fast", system, [{"role": "user", "content": f"Tool: {d.get('tool')}\nInput: {d.get('input')}\nOutput JSON: {data}"}], max_tokens=350, timeout=25)
        return jsonify({"text": text, "provider": prov})
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"AI unavailable: {str(e)[:100]}"}), 502


@app.post("/api/chat")
def chat():
    d = request.get_json(force=True, silent=True) or {}
    text = (d.get("text") or "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400
    t1 = time.time()
    out = run_assistant(text, d.get("lang", "auto"))
    t2 = time.time()
    if d.get("speak", True):
        out.update(speak(out["reply"], out["lang"]))
    out.update({"transcript": text, "timings": {"llm": round(t2 - t1, 2), "tts": round(time.time() - t2, 2)}})
    return jsonify(out)


@app.post("/api/tts")
def tts_route():
    d = request.get_json(force=True, silent=True) or {}
    return jsonify(speak(d.get("text", ""), d.get("lang", "auto")))


@app.post("/api/narrate")
def narrate():
    """Spoken alert for a new high/critical event, ending with the pending question."""
    d = request.get_json(force=True, silent=True) or {}
    ui_lang = d.get("lang", "en-IN")
    ev = next((e for e in reversed(engine.events) if e["id"] == d.get("event_id")), None)
    if not ev:
        return jsonify({"error": "unknown event"}), 404
    pend = engine.pending
    lang = ui_lang if ui_lang in LANG_NAMES else "en-IN"
    prompt = (
        f"Write a spoken SOC alert in {LANG_NAMES[lang]} (native script unless Hinglish). Max 35 words, numbers as words, "
        "no IP digits. Say the severity, what happened, which node, and the city of origin."
        + (" End by asking if the analyst wants the attacker blocked." if pend and pend.get("event_id") == ev["id"] else "")
        + ' Return JSON: {"reply": "..."}\nEvent: ' + json.dumps(ev, ensure_ascii=False)
    )
    try:
        raw, prov = llm.chat("fast", "You write short spoken security alerts.", [{"role": "user", "content": prompt}],
                             max_tokens=200, json_mode=True, timeout=15)
        text = clean_reply(llm.parse_json(raw)["reply"])
    except Exception:  # noqa: BLE001
        prov = "template"
        text = (f"{ev['severity'].capitalize()} alert. {ev['title']} on {ev['target']['name']}"
                + (f", from {ev['src']['city']}." if ev["src"] else ".")
                + (" Shall I block the attacker?" if pend and pend.get("event_id") == ev["id"] else ""))
    out = {"reply": text, "lang": lang, "provider": prov}
    out.update(speak(text, lang))
    return jsonify(out)


@app.post("/api/action")
def action():
    d = request.get_json(force=True, silent=True) or {}
    results, client = engine.apply([d])
    return jsonify({"results": results, "client_actions": client})


@app.post("/api/ingest")
def ingest():
    """Push your own real alerts (Wazuh, Suricata, Fail2ban, CloudTrail...) into the SOC."""
    d = request.get_json(force=True, silent=True) or {}
    token = os.getenv("INGEST_TOKEN")
    if token and request.headers.get("X-Ingest-Token") != token:
        return jsonify({"error": "unauthorized"}), 401
    sev = d.get("severity", "medium")
    engine.submit({"source": str(d.get("source", "ingest"))[:30], "type": str(d.get("type", "external"))[:30], "severity": sev if sev in soc.SEV_W else "medium",
                   "mitre": (str(d.get("mitre_id", "T0000")), str(d.get("mitre_name", "Unmapped"))), "ip": geo.norm_ip(d.get("src_ip", "")) or None,
                   "target": (engine.resolve_node(d.get("target", "")) or {}).get("id", "hq"), "direction": "in", "actionable": True,
                   "tags": list(d.get("tags", []))[:6], "title": str(d.get("title", "External alert"))[:140], "detail": str(d.get("detail", ""))[:400]})
    return jsonify({"ok": True})


@app.post("/api/council")
def council():
    """Ask Groq, Gemini and Claude independently for a verdict on one event, then take a vote."""
    d = request.get_json(force=True, silent=True) or {}
    ev = next((e for e in reversed(engine.events) if e["id"] == d.get("event_id")), None)
    if not ev:
        return jsonify({"error": "unknown event"}), 404
    snap = engine.snapshot_for_llm()
    system = ("You are a senior SOC analyst giving an independent second opinion. Reply with JSON only: "
              '{"verdict":"block|isolate|escalate|monitor","confidence":0-100,"reason":"<max 25 words>"}')
    user = f"Event: {json.dumps(ev)}\nContext: {json.dumps(snap['stats'])}"
    conf = llm.configured()

    def ask(name):
        if not conf[name]:
            return {"provider": name, "error": "no key configured"}
        t0 = time.time()
        try:
            j = llm.parse_json(llm.call(name, system, [{"role": "user", "content": user}], 200, True, 25))
            model = llm.STATS[name]["model"]
            v = str(j.get("verdict", "monitor")).lower()
            v = v if v in ("block", "isolate", "escalate", "monitor") else "monitor"
            return {"provider": name, "model": model, "verdict": v, "confidence": int(j.get("confidence", 50)),
                    "reason": str(j.get("reason", ""))[:200], "ms": int((time.time() - t0) * 1000)}
        except Exception as e:  # noqa: BLE001
            return {"provider": name, "error": str(e)[:140]}

    voters = [p for p in llm.PROVIDERS if conf[p]] or ["groq"]
    with ThreadPoolExecutor(len(voters)) as ex:
        votes = list(ex.map(ask, voters))
    rank = {"isolate": 3, "block": 2, "escalate": 1, "monitor": 0}
    tally = {}
    for v in votes:
        if "verdict" in v:
            tally[v["verdict"]] = tally.get(v["verdict"], 0) + 1
    consensus = max(tally, key=lambda k: (tally[k], rank[k])) if tally else None
    return jsonify({"event_id": ev["id"], "votes": votes, "consensus": consensus, "tally": tally})


@app.post("/api/report")
def report():
    d = request.get_json(force=True, silent=True) or {}
    lang = d.get("lang", "en-IN")
    snap = engine.snapshot_for_llm()
    evs = engine.events[-30:]
    brief = [{"time": e["ts"][11:19], "sev": e["severity"], "title": e["title"], "target": e["target"]["name"],
              "source": e["source"], "from": (e["src"] or {}).get("city"), "mitre": f"{e['mitre']['id']} {e['mitre']['name']}"} for e in evs]
    system = ("You are a principal incident responder writing a concise incident report for a SOC manager. "
              "Use Markdown with these sections: ## Executive Summary, ## Timeline, ## Affected Assets, ## MITRE ATT&CK Mapping, "
              "## Actions Taken, ## Recommendations. Use bullet lists, no tables. Under 350 words. "
              "Base every statement on the supplied data only (public threat feeds, this host's connections, monitored assets, honeypot). "
              "Say clearly when an event is global threat intel rather than something that targeted this organisation. Do not invent facts.")
    user = (f"Stats: {json.dumps(snap['stats'])}\nNodes: {json.dumps(snap['nodes'])}\n"
            f"Events: {json.dumps(brief)}\nActions taken: {json.dumps(engine.actions_log[-15:])}\n"
            f"Write the report in {LANG_NAMES.get(lang, 'English')}.")
    try:
        md, prov = llm.chat("deep", system, [{"role": "user", "content": user}], max_tokens=1400, timeout=60)
    except Exception as e:  # noqa: BLE001
        s = snap["stats"]
        prov = "template"
        md = (f"## Executive Summary\nThreat level {s['risk']}%. {s['total']} live events, {len(s['blocked_ips'])} IPs blocked, "
              f"{s['critical_nodes']} nodes in critical state.\n\n## Timeline\n"
              + "\n".join(f"- {b['time']} [{b['sev']}] {b['title']} on {b['target']}" for b in brief[-10:])
              + f"\n\n_LLM unavailable ({str(e)[:80]}); template report shown._")
    return jsonify({"markdown": md, "provider": prov})


def watch_ips(target):
    """IP or domain -> all its public IPv4 addresses (a CDN site has several)."""
    import socket as _s
    target = (target or "").strip().lower()
    if geo.norm_ip(target):
        return [geo.norm_ip(target)] if geo.is_public(target) else []
    try:
        return sorted({i[4][0] for i in _s.getaddrinfo(target, None, _s.AF_INET) if geo.is_public(i[4][0])})
    except Exception:  # noqa: BLE001
        return []


@app.post("/api/watch")
def watch():
    """Analyst watchlist: any REAL connection from this machine to a watched IP/domain raises a critical alert."""
    t = ((request.get_json(force=True, silent=True) or {}).get("target") or "").strip()
    ips = watch_ips(t)
    if not ips:
        return jsonify({"ok": False, "error": f"could not resolve a public IP for '{t}'"}), 400
    intel._add_threat(ips, "watchlist")
    return jsonify({"ok": True, "target": t, "ips": ips})


def boot():
    """Wire every real data source into the engine."""
    llm.warmup()  # discover which models each key can use, in the background
    import socket as _s
    h = geo.home()
    engine.register_node("hq", _s.gethostname(), "host", h["lat"], h["lon"], h.get("city") or "Home",
                         meta={"public_ip": h.get("ip"), "location_source": h.get("source")})
    mon = None
    if os.getenv("ASSETS"):
        mon = assets.AssetMonitor(engine, assets.parse_assets(os.getenv("ASSETS")))
        engine.asset_monitor = mon
    ports = [int(p) for p in os.getenv("HONEYPOT_PORTS", "").split(",") if p.strip().isdigit()]
    if ports:
        engine.register_node("honeypot", "Honeypot", "honeypot", h["lat"] - 3, h["lon"] + 3, h.get("city") or "Home", meta={"ports": ports})
    engine.start()
    intel.Poller(engine).start()
    import globalfeeds
    globalfeeds.GlobalFeeds(engine).start()
    hostmon.HostMonitor(engine).start()
    for w in [x.strip() for x in os.getenv("WATCH", "").split(",") if x.strip()]:
        intel._add_threat(watch_ips(w), "watchlist")
    if mon:
        mon.start()
    if ports:
        honeypot.start(engine, ports)


boot_lock = None
if __name__ == "__main__":
    boot()
    port = int(os.getenv("PORT", "5000"))
    print(f"\n  VIRUS Voice SOC (live data) -> http://localhost:{port}\n  Gnani: {gnani.configured()}  LLMs: {llm.configured()}  "
          f"Assets: {os.getenv('ASSETS') or 'none'}  Honeypot: {os.getenv('HONEYPOT_PORTS') or 'off'}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)

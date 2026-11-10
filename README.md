# VIRUS Voice SOC (live data)

    mic -> Gnani Prisma STT -> Groq / Gemini / Claude (with real lookup + scan tools) -> Gnani Timbre TTS
    live feeds + this machine + your assets + honeypot -> engine -> 3D globe

## Run
    Windows: double-click start.bat   (Mac/Linux: ./run.sh)
    python check_sources.py     # run once on YOUR network: tells you which live feeds respond
    open http://localhost:5000  # must be localhost for the microphone

Keys are in `.env` (server-side only). Rotate them after the hackathon.

## Where every event comes from (nothing is generated)
| Source | What it is | Refresh |
|---|---|---|
| abuse.ch Feodo | online botnet C2 servers | 5 min |
| blocklist.de | IPs that attacked honeypots worldwide in the last hour | 1 min |
| SANS ISC DShield | today's top attacking IPs | 15 min |
| CISA KEV | newly added actively-exploited CVEs | 30 min |
| OpenPhish, URLhaus | live phishing / malware-distribution hosts | 10 min |
| Host monitor | EVERY real connection on this machine, checked against 17k+ IPsum/ET/Tor/Feodo threat IPs; new listening ports; SSH auth failures | 5 s |
| Asset monitor | real uptime, latency, TLS expiry, security headers of YOUR sites (`ASSETS=`), plus TCP scan of those assets only | 60 s |
| Honeypot | optional listeners that log real inbound scanners (`HONEYPOT_PORTS=`) | live |
| `POST /api/ingest` | your own SIEM / Wazuh / Suricata alerts | live |

Global-intel events say so in their text: they are NOT claimed to be attacks on you. Only host, asset and honeypot events change node status.

## Configure (.env)
    ASSETS=https://yoursite.com,https://api.yoursite.com   # real monitored nodes on the globe
    HONEYPOT_PORTS=2222,8080                               # run on a public VPS to catch real scanners
    WATCH=example.com                                      # watchlist: any real connection to it raises a CRITICAL alert
    HOME_LAT=25.2  HOME_LON=55.27  HOME_CITY=Dubai         # otherwise located from your public IP
    ENABLE_FIREWALL=1                                      # REAL OS blocking (run as admin/root). Default is dry-run
    INGEST_TOKEN=...                                       # protect /api/ingest

## Live demo that triggers a REAL detection
1. Set `WATCH=example.com` (or `curl -X POST localhost:5000/api/watch -H 'Content-Type: application/json' -d '{"target":"example.com"}'`).
2. Open example.com in your browser. The host monitor sees the real connection -> CRITICAL alert, spoken aloud.
3. Say "haan, block karo" -> with ENABLE_FIREWALL=1 the IP is blocked at the OS firewall.
4. Say "look up the top attacker" -> live geo + reputation + Shodan InternetDB open ports.

## AI providers (auto-discovery, no hard-coded model names)
The app asks each provider which models YOUR key can use, picks the best, and moves to the next model/provider on any error.
Hover a provider pill in the top bar to see the model in use or why it was rejected.

    python check_llm.py          # run on your machine: lists usable models per key and tests them

| Provider | .env key | Notes |
|---|---|---|
| Groq | GROQ_API_KEY | free tier; models discovered from /openai/v1/models |
| Gemini | GEMINI_API_KEY | free tier; 2.5 models are now limited to old accounts, 3.x are used automatically |
| Claude | ANTHROPIC_API_KEY | needs a real `sk-ant-...` key from console.anthropic.com (or set ANTHROPIC_BASE_URL for a compatible relay) |
| FREE (OpenRouter) | OPENROUTER_API_KEY | free `:free` models, no card: https://openrouter.ai/keys |

Pin a model with GROQ_MODEL / GEMINI_MODEL / CLAUDE_MODEL / OPENROUTER_MODEL. Test: `python tests/test_llm.py`.

## Tests
    python tests/test_parsers.py        # feed parsers
    python tests/e2e_pipeline.py        # feeds -> engine -> events; real connection -> critical -> block


## Global live attacks (what is NOT only about your machine)
The globe now has two layers. **Local** = things touching your nodes (arcs to your node). **Global** = attacks seen worldwide, drawn as purple pulses where they originate (never as fake attacks on you); filter with the `local / global` chips. The *Global Attack Pulse* panel shows sightings, top origin countries and (with a Cloudflare key) real origin -> target attack flows.

Works with no keys: FireHOL typed attacker lists (SSH/web/mail/VoIP brute force, scanners, bots), Phishing.Database, ransomware.live, plus all the earlier feeds.

Free keys that unlock more (put them in `.env`, restart; the panel chips show `needs KEY` until set):
| Variable | Where (free) | Unlocks |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | dash.cloudflare.com > My Profile > API Tokens (permission: Radar read) | country-to-country L3/L7 attack flows |
| `OTX_API_KEY` | otx.alienvault.com > Settings | fresh community threat pulses |
| `ABUSECH_AUTH_KEY` | auth.abuse.ch | ThreatFox C2 IOCs (+ URLhaus/Feodo if they require it) |
| `ABUSEIPDB_API_KEY` | abuseipdb.com > API | 90%+ confidence blacklist |
| `GREYNOISE_API_KEY` | viz.greynoise.io | internet-noise classification in IP look-ups |

Run `python check_sources.py` on your own network to verify every source; `python tests/e2e_global.py` for the global pipeline.

## Realistic 3D, live world objects, toolbox
* **Views** (top-centre): *Realistic 3D* (NASA-based earth, clouds, night lights, ocean glint, atmosphere, real-time day/night from the UTC sun position), *Tactical* (wireframe HUD) and *Flat map* (normal 2D map with the same live data + terminator). Layer chips toggle each data layer; choices are remembered. Voice: "switch to flat map", "show satellites".
* **3D models**: your host/HQ, monitored assets and honeypot are low-poly 3D models whose LEDs follow node status; the ISS and stations are modelled; aircraft are instanced airliners.
* **Real-time objects**: satellites (Celestrak TLE, SGP4 propagated in the browser, so the ISS position is live), aircraft (OpenSky ADS-B), earthquakes (USGS M2.5+, 24 h). Orbit altitude is visually compressed. OpenSky is rate-limited for anonymous use; failures show as "unavailable" in the status box, never fake data.
* **Toolbox** (header button): IP intel, DNS + SPF/DMARC, WHOIS/RDAP, TLS cert, HTTP header grade, CVE (NVD + CISA KEV), URL check, hash lookup, subnet calculator, each with "Explain with AI". The voice assistant can run them too ("check DNS for example.com"). SNAP saves a PNG of the globe.
